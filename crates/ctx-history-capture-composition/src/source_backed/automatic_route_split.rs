//! One-way warm migration from released collapsed automatic route identities.
//!
//! Resolver roles are intentionally not a persistence schema.  This module
//! recognizes only the six released families whose automatic identity changed,
//! and makes the old identity a bounded predecessor of one role-specific
//! successor for exactly one atomic publication.

use super::*;

const WITNESS_MAGIC: &[u8] = b"ctx-auto-route-split\0";
const WITNESS_VERSION: u8 = 1;
pub const MAX_AUTOMATIC_ROUTE_SPLIT_WITNESS_BYTES: usize = 312;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SplitWitness {
    cohort: [u8; 32],
    role: ProviderRouteRole,
}

#[derive(Debug, Clone, Default)]
pub struct AutomaticRouteSplitPlan {
    required_routes: BTreeSet<SourceRouteIdentity>,
}

/// Returns the released collapsed identity when this current automatic route
/// belongs to one of the six one-way split cohorts.  Watch admission uses the
/// predecessor identity only to widen pending maintenance; publication still
/// performs the full cohort and witness validation above.
pub(crate) fn automatic_route_split_legacy_route(
    route: &SourceBackedRoute,
) -> Option<SourceRouteIdentity> {
    (route.metadata.selection == Some(SourceBackedRouteSelection::Automatic)).then_some(())?;
    route
        .metadata
        .source
        .route_provenance
        .automatic_route_role()?;
    split_cohort(
        route.metadata.source.provider,
        route.metadata.certified_source_format,
    )?;
    legacy_automatic_source_backed_route_identity(&route.metadata.source).ok()
}

impl AutomaticRouteSplitPlan {
    pub fn requires_exhaustive_publication(&self) -> bool {
        !self.required_routes.is_empty()
    }

    pub fn required_routes(&self) -> &BTreeSet<SourceRouteIdentity> {
        &self.required_routes
    }
}

/// Classifies and installs every active collapsed-route migration.
///
/// A malformed tagged witness is an error rather than an invitation to start
/// over.  Untagged route controls remain provider-owned controls from older
/// releases and therefore mean that the base has no split witness yet.
pub fn prepare_automatic_route_splits(
    registry: &mut SourceBackedProviderRegistry,
    base_routes: &BTreeSet<SourceRouteIdentity>,
    base_route_controls: &BTreeMap<SourceRouteIdentity, Vec<u8>>,
    scope: &SourceBackedRefreshScope,
    demand: SourceBackedReconciliationDemand,
) -> SourceBackedCoordinatorResult<AutomaticRouteSplitPlan> {
    let mut cohorts = BTreeMap::<SourceRouteIdentity, CohortMembers>::new();
    for (index, route) in registry.routes.iter().enumerate() {
        let Some(role) = route
            .metadata
            .source
            .route_provenance
            .automatic_route_role()
        else {
            continue;
        };
        let Some(cohort) = split_cohort(
            route.metadata.source.provider,
            route.metadata.certified_source_format,
        ) else {
            continue;
        };
        // Unsupported, unavailable, and registration-failed candidates retain
        // their resolver provenance even though normal registry construction
        // deliberately withholds executable selection and route identity.
        // Derive their current identity here so a witnessed cohort cannot
        // retire its predecessor while one known role is unaccounted for.
        let route_identity = route.metadata.route_identity.clone().map_or_else(
            || automatic_source_backed_route_identity(&route.metadata.source),
            Ok,
        )?;
        let legacy = legacy_automatic_source_backed_route_identity(&route.metadata.source)?;
        if !base_routes.contains(&legacy) {
            continue;
        }
        let members = cohorts
            .entry(legacy)
            .or_insert_with(|| CohortMembers::new(cohort));
        if members.cohort != cohort {
            return Err(split_error(
                route.metadata.source.provider,
                "automatic split cohort has conflicting static policy",
            ));
        }
        if members
            .members
            .iter()
            .any(|member| member.route == route_identity || member.role == *role)
        {
            return Err(split_error(
                route.metadata.source.provider,
                "automatic split cohort contains duplicate role ownership",
            ));
        }
        members.members.push(CohortMember {
            index,
            route: route_identity,
            role: role.clone(),
        });
    }

    let mut plan = AutomaticRouteSplitPlan::default();
    let mut bridge_keep = BTreeSet::new();
    let mut bridge_members = BTreeSet::new();
    for (legacy, mut members) in cohorts {
        members.members.sort_by_key(|member| member.index);
        let role_routes = members
            .members
            .iter()
            .map(|member| member.route.clone())
            .collect::<BTreeSet<_>>();
        if !base_routes.is_disjoint(&role_routes) {
            return Err(split_error(
                CaptureProvider::Unknown,
                "base generation contains both collapsed and role-specific automatic routes",
            ));
        }
        require_exhaustive_split(scope, demand)?;
        let witness = match base_route_controls.get(&legacy) {
            Some(control) if control.starts_with(WITNESS_MAGIC) => Some(decode_witness(control)?),
            _ => None,
        };
        let Some(witness) = witness else {
            let winner_index = select_released_bridge_winner(registry, &members.members)?;
            let winner = members
                .members
                .iter()
                .find(|member| member.index == winner_index)
                .ok_or_else(|| {
                    split_error(
                        CaptureProvider::Unknown,
                        "collapsed automatic route has no successor",
                    )
                })?;
            let route = registry.routes.get_mut(winner_index).ok_or_else(|| {
                split_error(
                    CaptureProvider::Unknown,
                    "automatic split winner was not registered",
                )
            })?;
            route.metadata.route_identity = Some(legacy.clone());
            route.automatic_split_bridge_control = Some(encode_witness(&SplitWitness {
                cohort: members.cohort,
                role: winner.role.clone(),
            })?);
            bridge_keep.insert(winner.index);
            bridge_members.extend(members.members.iter().map(|member| member.index));
            plan.required_routes.insert(legacy);
            continue;
        };
        if witness.cohort != members.cohort {
            return Err(split_error(
                CaptureProvider::Unknown,
                "automatic split witness belongs to a stale cohort policy",
            ));
        }
        let owner = members
            .members
            .iter()
            .find(|member| member.role == witness.role)
            .ok_or_else(|| {
                split_error(
                    CaptureProvider::Unknown,
                    "automatic split witness names a role absent from the current cohort",
                )
            })?;
        validate_witnessed_cohort(registry, &members.members, owner.index)?;
        let owner_route = registry.routes.get_mut(owner.index).ok_or_else(|| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split owner was not registered",
            )
        })?;
        owner_route.base_route_aliases = BTreeSet::from([legacy.clone()]);
        plan.required_routes.extend(role_routes.clone());
        registry.register_automatic_split_cohort_barrier(legacy, &owner.route, role_routes)?;
    }

    if !bridge_members.is_empty() {
        let mut index = 0usize;
        registry.routes.retain(|_| {
            let current = index;
            index = index.saturating_add(1);
            !bridge_members.contains(&current) || bridge_keep.contains(&current)
        });
    }
    Ok(plan)
}

/// Replays the released collapsed-identity registry conflict rule over the
/// role-specific candidates without changing their current identities.
/// Executable authority replaces an earlier non-executable candidate; the
/// first executable then remains the winner. If none is executable, the first
/// candidate retains the exact sorted/deduplicated missing-path union.
fn select_released_bridge_winner(
    registry: &mut SourceBackedProviderRegistry,
    members: &[CohortMember],
) -> SourceBackedCoordinatorResult<usize> {
    // A released unsupported observation had no route identity and therefore
    // did not participate in collapsed-identity conflict resolution. It is
    // still a cohort member for witnessed retirement validation, but cannot
    // become the bridge owner.
    let candidates = members
        .iter()
        .filter(|member| {
            registry
                .routes
                .get(member.index)
                .is_some_and(|route| route.metadata.route_identity.is_some())
        })
        .map(|member| member.index)
        .collect::<Vec<_>>();
    let Some(first) = candidates.first().copied() else {
        return Err(split_error(
            CaptureProvider::Unknown,
            "collapsed automatic route has no successor",
        ));
    };
    let mut winner_index = first;
    for candidate_index in candidates.into_iter().skip(1) {
        let winner_executable = registry
            .routes
            .get(winner_index)
            .is_some_and(|route| route.driver.is_some());
        if winner_executable {
            continue;
        }
        let candidate_route = registry.routes.get(candidate_index).ok_or_else(|| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split candidate was not registered",
            )
        })?;
        if candidate_route.driver.is_some() {
            winner_index = candidate_index;
            continue;
        }
        let mut missing = candidate_route.certified_missing_paths.clone();
        let winner = registry.routes.get_mut(winner_index).ok_or_else(|| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split winner was not registered",
            )
        })?;
        winner.certified_missing_paths.append(&mut missing);
        winner.certified_missing_paths.sort();
        winner.certified_missing_paths.dedup();
    }
    Ok(winner_index)
}

#[derive(Debug, Clone)]
struct CohortMembers {
    cohort: [u8; 32],
    members: Vec<CohortMember>,
}

impl CohortMembers {
    fn new(cohort: [u8; 32]) -> Self {
        Self {
            cohort,
            members: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CohortMember {
    index: usize,
    route: SourceRouteIdentity,
    role: ProviderRouteRole,
}

fn validate_witnessed_cohort(
    registry: &SourceBackedProviderRegistry,
    members: &[CohortMember],
    owner_index: usize,
) -> SourceBackedCoordinatorResult<()> {
    for member in members {
        let route = registry.routes.get(member.index).ok_or_else(|| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split cohort member was not registered",
            )
        })?;
        let owner = member.index == owner_index;
        let certified_missing = !route.certified_missing_paths.is_empty();
        if route.metadata.source.status == ProviderSourceStatus::Missing
            && !owner
            && certified_missing
        {
            continue;
        }
        if owner && route.metadata.source.status == ProviderSourceStatus::Missing {
            return Err(split_error(
                route.metadata.source.provider,
                "automatic split witness owner is missing",
            ));
        }
        if route.driver.is_none()
            || !matches!(
                route.metadata.source.status,
                ProviderSourceStatus::Available | ProviderSourceStatus::Empty
            )
        {
            return Err(split_error(
                route.metadata.source.provider,
                "automatic split cohort is unavailable or unsupported",
            ));
        }
    }
    Ok(())
}

fn require_exhaustive_split(
    scope: &SourceBackedRefreshScope,
    demand: SourceBackedReconciliationDemand,
) -> SourceBackedCoordinatorResult<()> {
    if *scope == SourceBackedRefreshScope::All
        && demand == SourceBackedReconciliationDemand::Exhaustive
    {
        Ok(())
    } else {
        Err(split_error(
            CaptureProvider::Unknown,
            "automatic route split requires all routes and exhaustive reconciliation",
        ))
    }
}

fn split_cohort(provider: CaptureProvider, certified_format: &str) -> Option<[u8; 32]> {
    let revision = match (provider, certified_format) {
        (CaptureProvider::OpenClaw, "openclaw_session_jsonl_tree") => {
            b"openclaw-jsonl.v1".as_slice()
        }
        (CaptureProvider::Warp, "warp_sqlite") => b"warp.v1".as_slice(),
        (CaptureProvider::Cline, "cline_task_directory_json") => b"cline-task-json.v1".as_slice(),
        (CaptureProvider::Antigravity, "antigravity_cli_transcript_jsonl_tree") => {
            b"antigravity.v1".as_slice()
        }
        (CaptureProvider::CodeBuddy, "codebuddy_history_json") => b"codebuddy.v1".as_slice(),
        (CaptureProvider::RooCode, "roo_task_directory_json") => {
            b"roo-code-task-json.v1".as_slice()
        }
        _ => return None,
    };
    let mut digest = Sha256::new();
    digest.update(b"ctx-auto-route-split-cohort.v1\0");
    for value in [
        provider.as_str().as_bytes(),
        certified_format.as_bytes(),
        revision,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    Some(digest.finalize().into())
}

fn encode_witness(witness: &SplitWitness) -> SourceBackedCoordinatorResult<Vec<u8>> {
    let role = witness.role.as_bytes();
    let role_len = u16::try_from(role.len()).map_err(|_| {
        split_error(
            CaptureProvider::Unknown,
            "automatic split witness role is too large",
        )
    })?;
    let mut encoded = Vec::with_capacity(WITNESS_MAGIC.len() + 1 + 32 + 2 + role.len());
    encoded.extend_from_slice(WITNESS_MAGIC);
    encoded.push(WITNESS_VERSION);
    encoded.extend_from_slice(&witness.cohort);
    encoded.extend_from_slice(&role_len.to_be_bytes());
    encoded.extend_from_slice(role);
    if encoded.len() > MAX_AUTOMATIC_ROUTE_SPLIT_WITNESS_BYTES {
        return Err(split_error(
            CaptureProvider::Unknown,
            "automatic split witness exceeds its bounded contract",
        ));
    }
    Ok(encoded)
}

fn decode_witness(value: &[u8]) -> SourceBackedCoordinatorResult<SplitWitness> {
    if value.len() > MAX_AUTOMATIC_ROUTE_SPLIT_WITNESS_BYTES {
        return Err(split_error(
            CaptureProvider::Unknown,
            "automatic split witness exceeds its bounded contract",
        ));
    }
    let minimum = WITNESS_MAGIC.len() + 1 + 32 + 2;
    if value.len() < minimum || !value.starts_with(WITNESS_MAGIC) {
        return Err(split_error(
            CaptureProvider::Unknown,
            "automatic split witness is malformed",
        ));
    }
    let version = value[WITNESS_MAGIC.len()];
    if version != WITNESS_VERSION {
        return Err(split_error(
            CaptureProvider::Unknown,
            "automatic split witness version is unsupported",
        ));
    }
    let cohort_start = WITNESS_MAGIC.len() + 1;
    let cohort_end = cohort_start + 32;
    let mut cohort = [0; 32];
    cohort.copy_from_slice(&value[cohort_start..cohort_end]);
    let role_len =
        u16::from_be_bytes(value[cohort_end..cohort_end + 2].try_into().map_err(|_| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split witness is malformed",
            )
        })?) as usize;
    let role = value
        .get(cohort_end + 2..)
        .filter(|role| role.len() == role_len)
        .ok_or_else(|| {
            split_error(
                CaptureProvider::Unknown,
                "automatic split witness is malformed",
            )
        })?;
    let role = ProviderRouteRole::try_from_encoded(role).map_err(|_| {
        split_error(
            CaptureProvider::Unknown,
            "automatic split witness role is malformed",
        )
    })?;
    Ok(SplitWitness { cohort, role })
}

fn split_error(
    provider: CaptureProvider,
    detail: impl Into<String>,
) -> SourceBackedCoordinatorError {
    SourceBackedCoordinatorError::InvalidRoute {
        provider,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ctx_history_capture_model::ProviderSourceRouteProvenance;

    use super::*;
    use crate::ProviderCatalogSupport;

    fn source_with_role(
        provider: CaptureProvider,
        source_format: &'static str,
        path: impl Into<PathBuf>,
        role: ProviderRouteRole,
        status: ProviderSourceStatus,
    ) -> ProviderSource {
        ProviderSource {
            provider,
            path: path.into(),
            exists: status != ProviderSourceStatus::Missing,
            source_format,
            source_kind: ProviderSourceKind::NativeHistory,
            import_support: ProviderImportSupport::Native,
            catalog_support: ProviderCatalogSupport::None,
            status,
            unsupported_reason: None,
            route_provenance: ProviderSourceRouteProvenance::Automatic { route_role: role },
        }
    }

    fn source(role: &'static str) -> ProviderSource {
        source_with_role(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
            format!("/fixture/{role}"),
            ProviderRouteRole::from_static(role),
            ProviderSourceStatus::Available,
        )
    }

    fn executable_route(source: ProviderSource) -> SourceBackedRoute {
        SourceBackedRoute::automatic(
            source,
            SourceBackedSelectorAuthority::DiscoveredWinner,
            SourceBackedRouteDriver::new(|_| Ok(()), |_| true, |_| true),
        )
        .unwrap()
    }

    fn route(role: &'static str) -> SourceBackedRoute {
        executable_route(source(role))
    }

    fn missing_route(source: ProviderSource) -> SourceBackedRoute {
        SourceBackedRoute::certified_missing(
            source,
            SourceBackedSelectorAuthority::DiscoveredWinner,
        )
        .unwrap()
    }

    fn route_id(route: &SourceBackedRoute) -> SourceRouteIdentity {
        route.metadata.route_identity.clone().unwrap()
    }

    fn fail_before_scan(mut route: SourceBackedRoute) -> SourceBackedRoute {
        let original = route.driver.take().unwrap();
        let owns = std::sync::Arc::clone(&original.owns_source);
        route.driver = Some(SourceBackedRouteDriver::new_fallible(
            |_| {
                Err(SourceBackedRouteError::new(
                    SourceBackedRouteErrorKind::Unavailable,
                    "injected split cohort failure",
                ))
            },
            move |source| owns(source),
            |_| Ok(false),
        ));
        route
    }

    #[test]
    fn cold_roled_routes_remain_direct_and_unroled_legacy_hash_is_stable() {
        let roled = route("surface-cli");
        let current = route_id(&roled);
        let legacy = legacy_automatic_source_backed_route_identity(&roled.metadata.source).unwrap();
        assert_ne!(current, legacy);
        let mut registry = SourceBackedProviderRegistry::new();
        registry.register(roled);
        let plan = prepare_automatic_route_splits(
            &mut registry,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        assert!(!plan.requires_exhaustive_publication());
        assert_eq!(route_id(registry.routes.first().unwrap()), current);
        assert!(registry
            .watch_catalog()
            .has_automatic_split_legacy_route(&legacy));
    }

    #[test]
    fn first_warm_publication_bridges_the_first_winner_and_writes_a_witness() {
        let first = route("surface-cli");
        let second = route("surface-ide");
        let legacy = legacy_automatic_source_backed_route_identity(&first.metadata.source).unwrap();
        let mut registry = SourceBackedProviderRegistry::new();
        registry.register(first);
        registry.register(second);
        let plan = prepare_automatic_route_splits(
            &mut registry,
            &BTreeSet::from([legacy.clone()]),
            &BTreeMap::new(),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        assert!(plan.requires_exhaustive_publication());
        assert_eq!(registry.routes.len(), 1);
        let bridge = registry.routes.first().unwrap();
        assert_eq!(route_id(bridge), legacy);
        let witness =
            decode_witness(bridge.automatic_split_bridge_control.as_deref().unwrap()).unwrap();
        assert_eq!(witness.role, ProviderRouteRole::from_static("surface-cli"));
    }

    #[test]
    fn bridge_conflicts_replace_missing_with_first_executable_for_fixed_and_dynamic_roles() {
        let cases = [
            (
                CaptureProvider::Antigravity,
                "antigravity_cli_transcript_jsonl_tree",
                ProviderRouteRole::from_dynamic([b"surface".as_slice(), b"cli".as_slice()])
                    .unwrap(),
                ProviderRouteRole::from_dynamic([b"surface".as_slice(), b"ide".as_slice()])
                    .unwrap(),
            ),
            (
                CaptureProvider::OpenClaw,
                "openclaw_session_jsonl_tree",
                ProviderRouteRole::from_dynamic([b"agent".as_slice(), b"missing".as_slice()])
                    .unwrap(),
                ProviderRouteRole::from_dynamic([b"agent".as_slice(), b"available".as_slice()])
                    .unwrap(),
            ),
        ];
        for (provider, format, missing_role, available_role) in cases {
            let missing_source = source_with_role(
                provider,
                format,
                format!("/fixture/{}/missing", provider.as_str()),
                missing_role,
                ProviderSourceStatus::Missing,
            );
            let available_path = PathBuf::from(format!("/fixture/{}/available", provider.as_str()));
            let available_source = source_with_role(
                provider,
                format,
                available_path.clone(),
                available_role.clone(),
                ProviderSourceStatus::Available,
            );
            let legacy = legacy_automatic_source_backed_route_identity(&available_source).unwrap();
            let mut registry = SourceBackedProviderRegistry::new();
            registry.register(missing_route(missing_source));
            registry.register(executable_route(available_source));
            prepare_automatic_route_splits(
                &mut registry,
                &BTreeSet::from([legacy.clone()]),
                &BTreeMap::new(),
                &SourceBackedRefreshScope::All,
                SourceBackedReconciliationDemand::Exhaustive,
            )
            .unwrap();
            let [bridge] = registry.routes.as_ref() else {
                panic!("one released bridge route expected");
            };
            assert!(bridge.driver.is_some());
            assert_eq!(bridge.metadata.source.path, available_path);
            assert!(bridge.certified_missing_paths.is_empty());
            let witness =
                decode_witness(bridge.automatic_split_bridge_control.as_deref().unwrap()).unwrap();
            assert_eq!(witness.role, available_role);
        }
    }

    #[test]
    fn all_missing_bridge_candidates_merge_paths_like_the_released_registry() {
        let first_path = PathBuf::from("/fixture/missing-z");
        let second_path = PathBuf::from("/fixture/missing-a");
        let first = source_with_role(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
            first_path.clone(),
            ProviderRouteRole::from_static("missing-z"),
            ProviderSourceStatus::Missing,
        );
        let second = source_with_role(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
            second_path.clone(),
            ProviderRouteRole::from_static("missing-a"),
            ProviderSourceStatus::Missing,
        );
        let legacy = legacy_automatic_source_backed_route_identity(&first).unwrap();
        let mut registry = SourceBackedProviderRegistry::new();
        registry.register(missing_route(first));
        registry.register(missing_route(second));
        prepare_automatic_route_splits(
            &mut registry,
            &BTreeSet::from([legacy]),
            &BTreeMap::new(),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        let [bridge] = registry.routes.as_ref() else {
            panic!("one merged missing bridge expected");
        };
        assert_eq!(
            bridge.certified_missing_paths,
            vec![second_path, first_path]
        );
    }

    #[test]
    fn witnessed_successor_alone_receives_the_legacy_alias_and_retirement_barrier() {
        let first = route("surface-cli");
        let second = route("surface-ide");
        let legacy = legacy_automatic_source_backed_route_identity(&first.metadata.source).unwrap();
        let cohort = split_cohort(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
        )
        .unwrap();
        let witness = encode_witness(&SplitWitness {
            cohort,
            role: ProviderRouteRole::from_static("surface-ide"),
        })
        .unwrap();
        let first_id = route_id(&first);
        let second_id = route_id(&second);
        let mut registry = SourceBackedProviderRegistry::new();
        registry.register(first);
        registry.register(second);
        prepare_automatic_route_splits(
            &mut registry,
            &BTreeSet::from([legacy.clone()]),
            &BTreeMap::from([(legacy.clone(), witness)]),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        let first = registry
            .routes
            .iter()
            .find(|route| route_id(route) == first_id)
            .unwrap();
        let second = registry
            .routes
            .iter()
            .find(|route| route_id(route) == second_id)
            .unwrap();
        assert!(first.base_route_aliases.is_empty());
        assert_eq!(second.base_route_aliases, BTreeSet::from([legacy.clone()]));
        assert_eq!(registry.automatic_split_cohort_barriers.len(), 1);
        assert_eq!(
            registry.automatic_split_cohort_barriers[0].cohort,
            BTreeSet::from([first_id, second_id])
        );
    }

    #[test]
    fn every_roled_nonowner_blocks_retirement_except_certified_missing() {
        let owner_role = ProviderRouteRole::from_static("surface-cli");
        let owner_source = source_with_role(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
            "/fixture/owner",
            owner_role.clone(),
            ProviderSourceStatus::Available,
        );
        let legacy = legacy_automatic_source_backed_route_identity(&owner_source).unwrap();
        let witness = encode_witness(&SplitWitness {
            cohort: split_cohort(
                CaptureProvider::Antigravity,
                "antigravity_cli_transcript_jsonl_tree",
            )
            .unwrap(),
            role: owner_role,
        })
        .unwrap();

        for (name, status) in [
            ("unavailable", ProviderSourceStatus::Unknown),
            ("unsupported", ProviderSourceStatus::Unsupported),
            ("registration-failed", ProviderSourceStatus::Available),
        ] {
            let blocked = source_with_role(
                CaptureProvider::Antigravity,
                "antigravity_cli_transcript_jsonl_tree",
                format!("/fixture/{name}"),
                ProviderRouteRole::from_static(name),
                status,
            );
            let mut registry = SourceBackedProviderRegistry::new();
            registry.register(executable_route(owner_source.clone()));
            registry.register(SourceBackedRoute::unsupported(
                blocked,
                format!("injected {name} candidate"),
            ));
            let error = prepare_automatic_route_splits(
                &mut registry,
                &BTreeSet::from([legacy.clone()]),
                &BTreeMap::from([(legacy.clone(), witness.clone())]),
                &SourceBackedRefreshScope::All,
                SourceBackedReconciliationDemand::Exhaustive,
            )
            .expect_err("known unusable nonowner must block retirement");
            assert!(error.to_string().contains("unavailable or unsupported"));
        }

        let missing = source_with_role(
            CaptureProvider::Antigravity,
            "antigravity_cli_transcript_jsonl_tree",
            "/fixture/certified-missing",
            ProviderRouteRole::from_static("certified-missing"),
            ProviderSourceStatus::Missing,
        );
        let missing_id = automatic_source_backed_route_identity(&missing).unwrap();
        let mut registry = SourceBackedProviderRegistry::new();
        registry.register(executable_route(owner_source));
        registry.register(missing_route(missing));
        prepare_automatic_route_splits(
            &mut registry,
            &BTreeSet::from([legacy.clone()]),
            &BTreeMap::from([(legacy, witness)]),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        assert_eq!(registry.automatic_split_cohort_barriers.len(), 1);
        assert!(registry.automatic_split_cohort_barriers[0]
            .cohort
            .contains(&missing_id));
    }

    #[test]
    fn malformed_stale_mixed_and_partial_split_states_fail_closed() {
        let fixture = route("surface-cli");
        let legacy =
            legacy_automatic_source_backed_route_identity(&fixture.metadata.source).unwrap();
        let current = route_id(&fixture);
        let attempt = |base: BTreeSet<SourceRouteIdentity>,
                       controls: BTreeMap<SourceRouteIdentity, Vec<u8>>,
                       scope: SourceBackedRefreshScope,
                       demand| {
            let mut registry = SourceBackedProviderRegistry::new();
            registry.register(route("surface-cli"));
            prepare_automatic_route_splits(&mut registry, &base, &controls, &scope, demand)
        };
        assert!(attempt(
            BTreeSet::from([legacy.clone()]),
            BTreeMap::from([(legacy.clone(), WITNESS_MAGIC.to_vec())]),
            SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .is_err());
        assert!(attempt(
            BTreeSet::from([legacy.clone(), current]),
            BTreeMap::new(),
            SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .is_err());
        assert!(attempt(
            BTreeSet::from([legacy.clone()]),
            BTreeMap::new(),
            SourceBackedRefreshScope::exact([legacy.clone()]),
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .is_err());
        assert!(attempt(
            BTreeSet::from([legacy]),
            BTreeMap::new(),
            SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Incremental,
        )
        .is_err());
    }

    #[test]
    fn split_cohorts_are_limited_to_the_six_roled_certified_formats() {
        for (provider, format) in [
            (CaptureProvider::OpenClaw, "openclaw_session_jsonl_tree"),
            (CaptureProvider::Warp, "warp_sqlite"),
            (CaptureProvider::Cline, "cline_task_directory_json"),
            (
                CaptureProvider::Antigravity,
                "antigravity_cli_transcript_jsonl_tree",
            ),
            (CaptureProvider::CodeBuddy, "codebuddy_history_json"),
            (CaptureProvider::RooCode, "roo_task_directory_json"),
        ] {
            assert!(
                split_cohort(provider, format).is_some(),
                "{provider:?} {format}"
            );
        }
        assert!(split_cohort(CaptureProvider::OpenClaw, "openclaw_agent_sqlite").is_none());
        assert!(split_cohort(CaptureProvider::Cline, "cline_sdk_session_store").is_none());
        assert!(split_cohort(CaptureProvider::RooCode, "roo_task_json").is_none());
    }

    #[test]
    fn split_witness_enforces_the_role_and_control_byte_bounds() {
        let component = vec![b'r'; 247];
        let role = ProviderRouteRole::from_dynamic([component.as_slice()]).unwrap();
        assert_eq!(role.as_bytes().len(), 256);
        let encoded = encode_witness(&SplitWitness {
            cohort: [7; 32],
            role,
        })
        .unwrap();
        assert_eq!(encoded.len(), MAX_AUTOMATIC_ROUTE_SPLIT_WITNESS_BYTES);
        assert!(decode_witness(&encoded).is_ok());
        assert!(decode_witness(&vec![0; MAX_AUTOMATIC_ROUTE_SPLIT_WITNESS_BYTES + 1]).is_err());
    }

    #[test]
    fn two_publication_bridge_keeps_the_legacy_route_then_retires_it_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let index_root = temp.path().join("index");
        let initial_current = route("surface-cli");
        let legacy =
            legacy_automatic_source_backed_route_identity(&initial_current.metadata.source)
                .unwrap();
        let mut released = initial_current.clone();
        released.metadata.route_identity = Some(legacy.clone());
        let mut released_registry = SourceBackedProviderRegistry::new();
        released_registry.register(released);
        let initial = refresh_source_backed_generation(
            &index_root,
            &released_registry,
            WriterOptions::default(),
        )
        .unwrap();
        assert!(initial.commit.manifest().source_route(&legacy).is_some());

        let mut bridge_registry = SourceBackedProviderRegistry::new();
        bridge_registry.register(route("surface-cli"));
        bridge_registry.register(route("surface-ide"));
        prepare_automatic_route_splits(
            &mut bridge_registry,
            &BTreeSet::from([legacy.clone()]),
            &BTreeMap::new(),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        let bridge = SourceBackedRefreshExecutor::new(bridge_registry, WriterOptions::default())
            .refresh(&index_root, |_| Ok(()))
            .unwrap();
        assert!(bridge.commit.manifest().source_route(&legacy).is_some());
        assert!(bridge.route_controls.contains_key(&legacy));

        let first = route("surface-cli");
        let second = route("surface-ide");
        let first_id = route_id(&first);
        let second_id = route_id(&second);
        let mut successor_registry = SourceBackedProviderRegistry::new();
        successor_registry.register(first);
        successor_registry.register(second);
        prepare_automatic_route_splits(
            &mut successor_registry,
            &BTreeSet::from([legacy.clone()]),
            &bridge.route_controls,
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        let successor =
            SourceBackedRefreshExecutor::new(successor_registry, WriterOptions::default())
                .with_base_route_controls(bridge.route_controls)
                .refresh(&index_root, |_| Ok(()))
                .unwrap();
        assert!(successor.commit.manifest().source_route(&legacy).is_none());
        assert!(successor
            .commit
            .manifest()
            .source_route(&first_id)
            .is_some());
        assert!(successor
            .commit
            .manifest()
            .source_route(&second_id)
            .is_some());
        assert!(!successor.route_controls.contains_key(&legacy));
    }

    #[test]
    fn failed_witnessed_cohort_keeps_the_bridge_generation_active() {
        let temp = tempfile::tempdir().unwrap();
        let index_root = temp.path().join("index");
        let current = route("surface-cli");
        let legacy =
            legacy_automatic_source_backed_route_identity(&current.metadata.source).unwrap();
        let mut released = current.clone();
        released.metadata.route_identity = Some(legacy.clone());
        let mut initial_registry = SourceBackedProviderRegistry::new();
        initial_registry.register(released);
        refresh_source_backed_generation(&index_root, &initial_registry, WriterOptions::default())
            .unwrap();

        let mut bridge_registry = SourceBackedProviderRegistry::new();
        bridge_registry.register(route("surface-cli"));
        bridge_registry.register(route("surface-ide"));
        prepare_automatic_route_splits(
            &mut bridge_registry,
            &BTreeSet::from([legacy.clone()]),
            &BTreeMap::new(),
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        let bridge = SourceBackedRefreshExecutor::new(bridge_registry, WriterOptions::default())
            .refresh(&index_root, |_| Ok(()))
            .unwrap();

        let mut failed_registry = SourceBackedProviderRegistry::new();
        failed_registry.register(route("surface-cli"));
        failed_registry.register(fail_before_scan(route("surface-ide")));
        prepare_automatic_route_splits(
            &mut failed_registry,
            &BTreeSet::from([legacy.clone()]),
            &bridge.route_controls,
            &SourceBackedRefreshScope::All,
            SourceBackedReconciliationDemand::Exhaustive,
        )
        .unwrap();
        assert!(
            SourceBackedRefreshExecutor::new(failed_registry, WriterOptions::default())
                .with_base_route_controls(bridge.route_controls)
                .refresh(&index_root, |_| Ok(()))
                .is_err()
        );
        let retained = ctx_history_index::VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(retained.generation_id(), bridge.commit.generation_id);
        assert!(retained.manifest().source_route(&legacy).is_some());
    }
}
