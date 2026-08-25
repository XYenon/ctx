use super::*;

/// Derives the stable catalog lineage for an exact provider source request.
///
/// This is the released explicit-source v1 identity contract. Automatic
/// routes that represent the same certified format and physical path must use
/// this lineage too, so route selection does not fork source, session, event,
/// cursor, or replay-checkpoint identity.
pub fn explicit_source_catalog_lineage(
    provider: CaptureProvider,
    certified_source_format: &str,
    path: &Path,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ctx.explicit-source-request-lineage.v1\0");
    digest.update(provider.as_str().as_bytes());
    digest.update([0]);
    digest.update(certified_source_format.as_bytes());
    digest.update([0]);
    digest.update(path.as_os_str().as_encoded_bytes());
    digest.finalize().into()
}

#[cfg(test)]
#[test]
fn exact_source_catalog_lineage_preserves_released_v1_identity() {
    let lineage = explicit_source_catalog_lineage(
        CaptureProvider::NanoClaw,
        "nanoclaw_project",
        Path::new("/fixture/nanoclaw"),
    );
    let encoded = lineage
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(
        encoded,
        "5213b19342d779063b64336dd7fff3a678de719fadb60240a1e1061798687e56"
    );
    assert_ne!(
        lineage,
        explicit_source_catalog_lineage(
            CaptureProvider::NanoClaw,
            "nanoclaw_project",
            Path::new("/fixture/nanoclaw-other"),
        )
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceBackedAutomaticUnavailableReason {
    SourceStatus(ProviderSourceStatus),
    UnsafeRootOverlap {
        detail: String,
    },
    UnsupportedFormat {
        detail: &'static str,
    },
    SelectorAuthorityUnavailable {
        detail: &'static str,
    },
    RegistrationRejected {
        kind: SourceBackedRouteErrorKind,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceBackedAutomaticRegistryIssue {
    Discovery(DiscoveryIssue),
    Unavailable {
        source: ProviderSource,
        reason: SourceBackedAutomaticUnavailableReason,
    },
}

#[derive(Debug, Clone)]
pub struct SourceBackedAutomaticRegistryBuild {
    pub registry: SourceBackedProviderRegistry,
    pub issues: Vec<SourceBackedAutomaticRegistryIssue>,
    pub discovery_duration: Duration,
}

impl SourceBackedAutomaticRegistryBuild {
    pub fn executable_route_count(&self) -> usize {
        self.registry.executable_route_count()
    }

    pub fn unsupported_route_count(&self) -> usize {
        self.registry.unsupported_route_count()
    }

    pub fn into_parts(
        self,
    ) -> (
        SourceBackedProviderRegistry,
        Vec<SourceBackedAutomaticRegistryIssue>,
    ) {
        (self.registry, self.issues)
    }

    pub fn into_refresh_executor(
        self,
        writer_options: WriterOptions,
    ) -> (
        SourceBackedRefreshExecutor,
        Vec<SourceBackedAutomaticRegistryIssue>,
    ) {
        (
            SourceBackedRefreshExecutor::with_discovery_duration(
                self.registry,
                writer_options,
                self.discovery_duration,
            ),
            self.issues,
        )
    }
}

/// Discovers and registers every automatic source-backed route capture can
/// construct without daemon-side provider branching.
///
/// Normal provider absence and selector/discovery limitations are returned as
/// typed issues. A detected format whose adapter seam is unavailable is also
/// retained as a typed unsupported route, so refresh and hydration cannot
/// silently claim it.
pub fn build_automatic_source_backed_registry_with_probes(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
) -> SourceBackedAutomaticRegistryBuild {
    let discovery_started = Instant::now();
    let discovery = discovery.clone().with_data_root(data_root);
    let report =
        ctx_history_source_discovery::discover_provider_sources_with_context(probes, &discovery);
    let mut build = build_automatic_source_backed_registry_from_report_with_probes(
        probes, &discovery, data_root, report,
    );
    build.discovery_duration = discovery_started.elapsed();
    build
}

/// Registers automatic routes from one already-completed discovery report.
///
/// Callers that must validate source roots before their first persistent write
/// can pass the same report through registration instead of traversing every
/// provider tree a second time.
pub fn build_automatic_source_backed_registry_from_report_with_probes(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    report: DiscoveryReport,
) -> SourceBackedAutomaticRegistryBuild {
    build_automatic_source_backed_registry_from_report_with_probes_and_root_identities(
        probes,
        discovery,
        data_root,
        report,
        &BTreeMap::new(),
    )
}

#[doc(hidden)]
pub fn build_automatic_source_backed_registry_from_report_with_probes_and_root_identities(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    report: DiscoveryReport,
    provider_root_identities: &BTreeMap<String, ProviderRootSourceIdentity>,
) -> SourceBackedAutomaticRegistryBuild {
    build_automatic_source_backed_registry_from_parts_with_probes(
        probes,
        discovery,
        data_root,
        report.sources,
        report.issues,
        provider_root_identities,
    )
}

fn build_automatic_source_backed_registry_from_parts_with_probes(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    sources: Vec<ProviderSource>,
    discovery_issues: Vec<DiscoveryIssue>,
    provider_root_identities: &BTreeMap<String, ProviderRootSourceIdentity>,
) -> SourceBackedAutomaticRegistryBuild {
    let canonical_automatic =
        ctx_history_source_discovery::discover_canonical_automatic_provider_sources_with_context(
            probes, discovery,
        );
    let provider_root_identities = normalized_provider_root_identities(
        discovery,
        &sources,
        &canonical_automatic.sources,
        data_root,
        provider_root_identities,
    );
    let mut registry = SourceBackedProviderRegistry::new();
    let mut issues = discovery_issues
        .into_iter()
        .map(SourceBackedAutomaticRegistryIssue::Discovery)
        .collect::<Vec<_>>();
    let mut compound_provider_registered = HashSet::new();
    let mut codex_session_tree_sources = Vec::new();
    let mut released_configured_codex_session_tree_sources =
        BTreeMap::<String, Vec<ProviderSource>>::new();

    // A configured home is explicit desired state. Register those routes
    // before inferred routes so a retained released identity cannot make an
    // old automatic location win merely because discovery returned it first.
    let (configured_sources, automatic_sources): (Vec<_>, Vec<_>) = sources
        .into_iter()
        .partition(|source| configured_provider_root_for_source(discovery, source).is_some());
    for source in configured_sources.into_iter().chain(automatic_sources) {
        let configured_root = configured_provider_root_for_source(discovery, &source);
        let configured_route_role = configured_root
            .and_then(|_| source.route_provenance.route_role())
            .cloned();
        let configured_source_identity = configured_root.map(|root| {
            provider_root_identities
                .get(&root.id)
                .copied()
                .unwrap_or_else(|| default_provider_root_source_identity(discovery, root))
        });
        if let Err(error) =
            validate_provider_source_roots_outside_data_root(data_root, std::iter::once(&source))
        {
            let reason = SourceBackedAutomaticUnavailableReason::UnsafeRootOverlap {
                detail: error.to_string(),
            };
            registry.register(SourceBackedRoute::unsupported(
                source.clone(),
                automatic_unavailable_detail(&reason),
            ));
            issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
            continue;
        }
        if source.import_support == ProviderImportSupport::Explicit {
            continue;
        }
        if source.import_support == ProviderImportSupport::Unsupported
            || source.source_kind == ProviderSourceKind::DetectionOnly
            || source.status == ProviderSourceStatus::Unsupported
            || (source.unsupported_reason.is_some()
                && source.status != ProviderSourceStatus::Empty
                && !(configured_root.is_some() && source.status == ProviderSourceStatus::Unknown))
        {
            let detail = source
                .unsupported_reason
                .unwrap_or("the detected provider format is not supported for automatic refresh");
            retain_unsupported_automatic_format(&mut registry, &mut issues, source, detail);
            continue;
        }
        if source.status == ProviderSourceStatus::Unknown {
            let reason = SourceBackedAutomaticUnavailableReason::SourceStatus(source.status);
            let mut route = if configured_root.is_some() {
                SourceBackedRoute::unavailable_explicit(
                    source.clone(),
                    automatic_unavailable_detail(&reason),
                )
                .unwrap_or_else(|_| {
                    SourceBackedRoute::unsupported(
                        source.clone(),
                        automatic_unavailable_detail(&reason),
                    )
                })
            } else {
                SourceBackedRoute::unsupported(
                    source.clone(),
                    automatic_unavailable_detail(&reason),
                )
            };
            if let (Some(configured_root), Some(route_role)) =
                (configured_root, configured_route_role.as_ref())
            {
                let source_root_lineage = configured_source_identity
                    .and_then(|identity| identity.lineage(configured_root));
                if let Err(error) =
                    route.apply_provider_root_route_identity(source_root_lineage, route_role)
                {
                    let reason = automatic_registration_rejected(error);
                    registry.register(SourceBackedRoute::unsupported(
                        source.clone(),
                        automatic_unavailable_detail(&reason),
                    ));
                    issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { reason, source });
                    continue;
                }
            }
            registry.register(route);
            issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { reason, source });
            continue;
        }

        let Some(format_route) = landed_format_route(source.provider, source.source_format) else {
            retain_unsupported_automatic_format(
                &mut registry,
                &mut issues,
                source,
                "the discovered provider format has no landed source-backed route",
            );
            continue;
        };
        if !format_route.automatic {
            retain_unsupported_automatic_format(
                &mut registry,
                &mut issues,
                source,
                "the discovered provider format is not registered for automatic refresh",
            );
            continue;
        }
        if let Some(reason) = format_route.unsupported_reason {
            retain_unsupported_automatic_format(&mut registry, &mut issues, source, reason);
            continue;
        }

        if source.status == ProviderSourceStatus::Missing {
            let route = if configured_root.is_some() {
                SourceBackedRoute::certified_explicit_missing(
                    source.clone(),
                    SourceBackedSelectorAuthority::ExplicitPath,
                )
            } else {
                SourceBackedRoute::certified_missing(
                    source.clone(),
                    format_route.selector_authority,
                )
            };
            let route = route.and_then(|mut route| {
                if let (Some(configured_root), Some(route_role)) =
                    (configured_root, configured_route_role.as_ref())
                {
                    let source_root_lineage = configured_source_identity
                        .and_then(|identity| identity.lineage(configured_root));
                    route.apply_provider_root_route_identity(source_root_lineage, route_role)?;
                }
                Ok(route)
            });
            match route {
                Ok(route) => registry.register(route),
                Err(error) => {
                    let reason = automatic_registration_rejected(error);
                    registry.register(SourceBackedRoute::unsupported(
                        source.clone(),
                        automatic_unavailable_detail(&reason),
                    ));
                    issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
                }
            }
            continue;
        }

        if !matches!(
            source.status,
            ProviderSourceStatus::Available | ProviderSourceStatus::Empty
        ) {
            let reason = SourceBackedAutomaticUnavailableReason::SourceStatus(source.status);
            registry.register(SourceBackedRoute::unsupported(
                source.clone(),
                automatic_unavailable_detail(&reason),
            ));
            issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
            continue;
        }

        let mut source = source;
        if source.status == ProviderSourceStatus::Empty {
            // Resolver diagnostics explain why a present root is empty; they do
            // not make its landed adapter unsupported.
            source.unsupported_reason = None;
        }
        if let Some(configured_root) = configured_root {
            let Some(route_role) = configured_route_role.as_ref() else {
                retain_unsupported_automatic_format(
                    &mut registry,
                    &mut issues,
                    source,
                    "the configured provider source has no explicit route role",
                );
                continue;
            };
            if source.provider == CaptureProvider::Codex
                && source.source_format == "codex_session_jsonl_tree"
                && configured_source_identity == Some(ProviderRootSourceIdentity::Released)
            {
                released_configured_codex_session_tree_sources
                    .entry(configured_root.id.clone())
                    .or_default()
                    .push(source);
                continue;
            }
            let source_root_lineage =
                configured_source_identity.and_then(|identity| identity.lineage(configured_root));
            let registration = match (source.provider, source.source_format) {
                (CaptureProvider::Claude, "claude_projects_jsonl_tree") => {
                    register_configured_claude_source_backed_route(
                        &mut registry,
                        source.clone(),
                        SourceBackedRouteSelection::ExplicitManual,
                        source_root_lineage,
                        route_role,
                    )
                }
                (CaptureProvider::Codex, "codex_session_jsonl_tree") => {
                    register_configured_codex_session_tree_route(
                        &mut registry,
                        source.clone(),
                        SourceBackedRouteSelection::ExplicitManual,
                        source_root_lineage,
                        route_role,
                    )
                }
                (CaptureProvider::Codex, "codex_history_jsonl") => {
                    register_configured_codex_prompt_history_source_backed_route(
                        &mut registry,
                        source.clone(),
                        SourceBackedRouteSelection::ExplicitManual,
                        source_root_lineage,
                        route_role,
                    )
                }
                (CaptureProvider::Crush, "crush_sqlite")
                | (CaptureProvider::Goose, "goose_sessions_sqlite")
                | (CaptureProvider::AstrBot, "astrbot_data_v4_sqlite")
                | (CaptureProvider::Lingma, "lingma_sqlite")
                | (CaptureProvider::Warp, "warp_sqlite") => register_configured_compound_route(
                    &mut registry,
                    discovery,
                    source.clone(),
                    data_root,
                    source_root_lineage,
                    route_role,
                ),
                _ => register_configured_landed_source_backed_route(
                    &mut registry,
                    source.clone(),
                    data_root,
                    source_root_lineage,
                    route_role,
                ),
            };
            match registration {
                Ok(()) => {}
                Err(error) => {
                    let reason = automatic_registration_rejected(error);
                    registry.register(SourceBackedRoute::unsupported(
                        source.clone(),
                        automatic_unavailable_detail(&reason),
                    ));
                    issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
                }
            }
            continue;
        }
        if source.provider == CaptureProvider::Codex
            && source.source_format == "codex_session_jsonl_tree"
        {
            codex_session_tree_sources.push(source);
            continue;
        }

        let compound_provider = matches!(
            format_route.constructor,
            SourceBackedRouteConstructor::FiniteInventory
                | SourceBackedRouteConstructor::DiscoveryContext
        );
        if compound_provider && compound_provider_registered.contains(&source.provider) {
            continue;
        }

        match register_discovered_automatic_route(
            &mut registry,
            probes,
            discovery,
            data_root,
            format_route,
            source.clone(),
        ) {
            Ok(()) => {
                if compound_provider {
                    compound_provider_registered.insert(source.provider);
                }
            }
            Err(reason) => {
                if compound_provider {
                    compound_provider_registered.insert(source.provider);
                }
                registry.register(SourceBackedRoute::unsupported(
                    source.clone(),
                    automatic_unavailable_detail(&reason),
                ));
                issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
            }
        }
    }

    for sources in released_configured_codex_session_tree_sources.into_values() {
        let source = sources.first().cloned();
        let route_role = source
            .as_ref()
            .and_then(|source| source.route_provenance.route_role())
            .cloned();
        let registration = route_role.as_ref().map_or_else(
            || {
                Err(invalid_route(
                    CaptureProvider::Codex,
                    "configured Codex session routes have no explicit route role",
                ))
            },
            |route_role| {
                register_configured_codex_session_tree_routes(
                    &mut registry,
                    sources,
                    SourceBackedRouteSelection::ExplicitManual,
                    None,
                    route_role,
                )
            },
        );
        if let (Some(source), Err(error)) = (source, registration) {
            let reason = automatic_registration_rejected(error);
            registry.register(SourceBackedRoute::unsupported(
                source.clone(),
                automatic_unavailable_detail(&reason),
            ));
            issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
        }
    }

    if !codex_session_tree_sources.is_empty() {
        codex_session_tree_sources.sort_by(|left, right| {
            codex_automatic_session_root_rank(&left.path)
                .cmp(&codex_automatic_session_root_rank(&right.path))
                .then_with(|| left.path.cmp(&right.path))
        });
        codex_session_tree_sources.dedup_by(|left, right| left.path == right.path);
        let source = codex_session_tree_sources.first().cloned();
        let registration = register_codex_session_tree_routes(
            &mut registry,
            codex_session_tree_sources,
            SourceBackedRouteSelection::Automatic,
        );
        if let (Some(source), Err(error)) = (source, registration) {
            let reason = automatic_registration_rejected(error);
            registry.register(SourceBackedRoute::unsupported(
                source.clone(),
                automatic_unavailable_detail(&reason),
            ));
            issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
        }
    }

    let definitions = discovery.configured_provider_roots().to_vec();
    let applied_roots = definitions
        .iter()
        .map(|definition| {
            let routes = registry
                .routes
                .iter()
                .filter(|route| {
                    configured_provider_root_for_source(discovery, &route.metadata.source)
                        .is_some_and(|root| root.id == definition.id)
                })
                .filter_map(|route| route.metadata.route_identity.clone())
                .collect::<Vec<_>>();
            AppliedProviderRoot::with_source_identity(
                definition.clone(),
                provider_root_identities
                    .get(&definition.id)
                    .copied()
                    .unwrap_or_else(|| {
                        default_provider_root_source_identity(discovery, definition)
                    }),
                routes,
            )
            .map_err(SourceBackedCoordinatorError::Index)
        })
        .collect::<SourceBackedCoordinatorResult<Vec<_>>>();
    match applied_roots {
        Ok(applied_roots) => {
            if let Err(error) = registry.set_applied_provider_roots(
                discovery.automatic_provider_discovery_enabled(),
                provider_source_config_digest(
                    discovery.automatic_provider_discovery_enabled(),
                    &definitions,
                ),
                applied_roots,
            ) {
                if let Some(source) = registry
                    .routes
                    .first()
                    .map(|route| route.metadata.source.clone())
                {
                    issues.push(SourceBackedAutomaticRegistryIssue::Unavailable {
                        source,
                        reason: SourceBackedAutomaticUnavailableReason::RegistrationRejected {
                            kind: SourceBackedRouteErrorKind::Internal,
                            detail: error.to_string(),
                        },
                    });
                }
            }
        }
        Err(error) => {
            if let Some(source) = registry
                .routes
                .first()
                .map(|route| route.metadata.source.clone())
            {
                issues.push(SourceBackedAutomaticRegistryIssue::Unavailable {
                    source,
                    reason: SourceBackedAutomaticUnavailableReason::RegistrationRejected {
                        kind: SourceBackedRouteErrorKind::Internal,
                        detail: error.to_string(),
                    },
                });
            }
        }
    }

    SourceBackedAutomaticRegistryBuild {
        registry,
        issues,
        discovery_duration: Duration::ZERO,
    }
}

fn normalized_provider_root_identities(
    discovery: &DiscoveryContext,
    configured_sources: &[ProviderSource],
    canonical_automatic_sources: &[ProviderSource],
    data_root: &Path,
    retained: &BTreeMap<String, ProviderRootSourceIdentity>,
) -> BTreeMap<String, ProviderRootSourceIdentity> {
    // Composition may run after the discovery report crossed an I/O boundary,
    // so the canonical automatic view is deliberately revalidated before it
    // can grant a *new* Released owner. Any TOCTOU change (including a root
    // becoming unavailable) fails this gate and remains NamedV1. A previously
    // published Released owner is kept ahead of this gate; refresh retention
    // then protects its exact prior route membership while the source is
    // unreadable.
    let mut released_owner = BTreeMap::<String, String>::new();
    let mut identities = BTreeMap::new();
    for root in discovery.configured_provider_roots() {
        let provider = root.provider.as_str().to_owned();
        let identity = match retained.get(&root.id).copied() {
            Some(ProviderRootSourceIdentity::Released)
                if !released_owner.contains_key(&provider) =>
            {
                released_owner.insert(provider, root.id.clone());
                ProviderRootSourceIdentity::Released
            }
            Some(_) => ProviderRootSourceIdentity::NamedV1,
            None if !released_owner.contains_key(&provider)
                && configured_root_matches_canonical_automatic_routes(
                    root,
                    configured_sources,
                    canonical_automatic_sources,
                    data_root,
                ) =>
            {
                released_owner.insert(provider, root.id.clone());
                ProviderRootSourceIdentity::Released
            }
            None => ProviderRootSourceIdentity::NamedV1,
        };
        identities.insert(root.id.clone(), identity);
    }
    identities
}

fn default_provider_root_source_identity(
    _discovery: &DiscoveryContext,
    _root: &ProviderRootDefinition,
) -> ProviderRootSourceIdentity {
    ProviderRootSourceIdentity::NamedV1
}

fn configured_root_matches_canonical_automatic_routes(
    root: &ProviderRootDefinition,
    configured_sources: &[ProviderSource],
    canonical_automatic_sources: &[ProviderSource],
    data_root: &Path,
) -> bool {
    let routes = configured_sources
        .iter()
        .filter(|source| provider_source_belongs_to_configured_root(root, source))
        .collect::<Vec<_>>();
    !routes.is_empty()
        && routes.iter().all(|source| {
            matches!(
                source.status,
                ProviderSourceStatus::Available | ProviderSourceStatus::Empty
            ) && validate_provider_source_roots_outside_data_root(data_root, [*source]).is_ok()
                && canonical_automatic_sources.iter().any(|automatic| {
                    automatic.provider == source.provider
                        && automatic.source_format == source.source_format
                        && matches!(
                            automatic.status,
                            ProviderSourceStatus::Available | ProviderSourceStatus::Empty
                        )
                        && provider_paths_equivalent(&automatic.path, &source.path)
                })
        })
}

fn configured_provider_root_for_source<'a>(
    discovery: &'a DiscoveryContext,
    source: &ProviderSource,
) -> Option<&'a ctx_history_capture_model::ProviderRootDefinition> {
    discovery
        .configured_provider_roots()
        .iter()
        .find(|root| provider_source_belongs_to_configured_root(root, source))
}

fn register_configured_landed_source_backed_route(
    registry: &mut SourceBackedProviderRegistry,
    source: ProviderSource,
    data_root: &Path,
    source_root_lineage: Option<[u8; 32]>,
    route_role: &ProviderRouteRole,
) -> SourceBackedCoordinatorResult<()> {
    register_landed_source_backed_route_with_data_root_and_lineage(
        registry,
        source.clone(),
        SourceBackedRouteSelection::ExplicitManual,
        data_root,
        source_root_lineage,
    )?;
    apply_configured_route_identity(registry, &source, source_root_lineage, route_role)
}

fn apply_configured_route_identity(
    registry: &mut SourceBackedProviderRegistry,
    source: &ProviderSource,
    source_root_lineage: Option<[u8; 32]>,
    route_role: &ProviderRouteRole,
) -> SourceBackedCoordinatorResult<()> {
    let route = registry.routes.last_mut().ok_or_else(|| {
        invalid_route(
            source.provider,
            "landed configured registration produced no executable route",
        )
    })?;
    route.apply_provider_root_route_identity(source_root_lineage, route_role)
}

fn register_configured_compound_route(
    registry: &mut SourceBackedProviderRegistry,
    discovery: &DiscoveryContext,
    source: ProviderSource,
    data_root: &Path,
    source_root_lineage: Option<[u8; 32]>,
    route_role: &ProviderRouteRole,
) -> SourceBackedCoordinatorResult<()> {
    // Configured roots are direct authority.  The selector keys below are
    // derived from the stable root lineage and static route role, never the
    // filesystem location, so a valid named root remains executable when its
    // installed-client automatic selector is presently unavailable.
    let configured_key = configured_compound_selector_key(source_root_lineage, route_role)?;
    match source.provider {
        CaptureProvider::Warp => {
            register_warp_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                configured_surface_key(source_root_lineage, route_role),
                source_root_lineage,
            )?;
        }
        CaptureProvider::Goose => {
            let platform_root = source.path.parent().and_then(Path::parent).ok_or_else(|| {
                invalid_route(
                    source.provider,
                    "configured Goose database has no exact platform-root parent",
                )
            })?;
            register_goose_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                platform_root,
                Vec::new(),
                source_root_lineage,
            )?;
        }
        CaptureProvider::Crush => {
            let inventory = Arc::new(ConfiguredCrushInventorySource {
                database: CrushProjectDatabaseV0::new(configured_key.clone(), source.path.clone())
                    .map_err(|error| invalid_route(source.provider, error.to_string()))?,
                authority_key: configured_key.clone(),
                revision: route_role.as_bytes().to_vec(),
            });
            register_crush_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                inventory,
                source_root_lineage,
            )?;
        }
        CaptureProvider::AstrBot => {
            register_astrbot_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                discovery.clone(),
                source_root_lineage,
            )?;
        }
        CaptureProvider::Lingma => {
            register_lingma_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                configured_key.clone(),
                vec![(source.path.clone(), configured_key)],
                source_root_lineage,
            )?;
        }
        _ => unreachable!("configured compound route is filtered by its caller"),
    }
    apply_configured_route_identity(registry, &source, source_root_lineage, route_role)
}

const CONFIGURED_COMPOUND_SELECTOR_DOMAIN: &str = "ctx.configured-root-compound-selector.v1";

fn configured_compound_selector_key(
    source_root_lineage: Option<[u8; 32]>,
    route_role: &ProviderRouteRole,
) -> SourceBackedCoordinatorResult<TypedKey> {
    let mut components = vec![
        TypedKey::utf8(CONFIGURED_COMPOUND_SELECTOR_DOMAIN)
            .map_err(|error| invalid_route(CaptureProvider::Unknown, error.to_string()))?,
        TypedKey::bytes(route_role.as_bytes().to_vec())
            .map_err(|error| invalid_route(CaptureProvider::Unknown, error.to_string()))?,
    ];
    if let Some(lineage) = source_root_lineage {
        components.push(
            TypedKey::bytes(lineage.to_vec())
                .map_err(|error| invalid_route(CaptureProvider::Unknown, error.to_string()))?,
        );
    }
    TypedKey::composite(components)
        .map_err(|error| invalid_route(CaptureProvider::Unknown, error.to_string()))
}

fn configured_surface_key(
    source_root_lineage: Option<[u8; 32]>,
    route_role: &ProviderRouteRole,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ctx.configured-root-warp-surface.v1\0");
    digest.update(route_role.as_bytes());
    if let Some(lineage) = source_root_lineage {
        digest.update(lineage);
    }
    format!("ctx-configured-root:{:x}", digest.finalize())
}

#[derive(Debug, Clone)]
struct ConfiguredCrushInventorySource {
    authority_key: TypedKey,
    revision: Vec<u8>,
    database: CrushProjectDatabaseV0,
}

impl CrushProjectInventorySourceV0 for ConfiguredCrushInventorySource {
    fn observe(
        &self,
    ) -> ctx_history_providers_sqlite_inventory::CrushSourceBackedResultV0<
        CrushProjectInventoryObservationV0,
    > {
        CrushProjectInventoryObservationV0::new(
            self.authority_key.clone(),
            self.revision.clone(),
            vec![self.database.clone()],
        )
    }
}

#[cfg(test)]
pub(in crate::source_backed) fn build_automatic_source_backed_registry_from_parts(
    discovery: &DiscoveryContext,
    data_root: &Path,
    sources: Vec<ProviderSource>,
    discovery_issues: Vec<DiscoveryIssue>,
) -> SourceBackedAutomaticRegistryBuild {
    build_automatic_source_backed_registry_from_parts_with_probes(
        &crate::test_provider_probes(),
        discovery,
        data_root,
        sources,
        discovery_issues,
        &BTreeMap::new(),
    )
}

fn codex_automatic_session_root_rank(root: &Path) -> u8 {
    match root.file_name().and_then(std::ffi::OsStr::to_str) {
        Some("sessions") => 0,
        Some("archived_sessions") => 1,
        _ => 2,
    }
}

fn retain_unsupported_automatic_format(
    registry: &mut SourceBackedProviderRegistry,
    issues: &mut Vec<SourceBackedAutomaticRegistryIssue>,
    source: ProviderSource,
    detail: &'static str,
) {
    registry.register(SourceBackedRoute::unsupported(source.clone(), detail));
    issues.push(SourceBackedAutomaticRegistryIssue::Unavailable {
        source,
        reason: SourceBackedAutomaticUnavailableReason::UnsupportedFormat { detail },
    });
}

fn automatic_unavailable_detail(reason: &SourceBackedAutomaticUnavailableReason) -> String {
    match reason {
        SourceBackedAutomaticUnavailableReason::SourceStatus(status) => {
            format!("provider source status is {}", status.as_str())
        }
        SourceBackedAutomaticUnavailableReason::UnsafeRootOverlap { detail }
        | SourceBackedAutomaticUnavailableReason::RegistrationRejected { detail, .. } => {
            detail.clone()
        }
        SourceBackedAutomaticUnavailableReason::UnsupportedFormat { detail }
        | SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable { detail } => {
            (*detail).to_owned()
        }
    }
}

fn register_discovered_automatic_route(
    registry: &mut SourceBackedProviderRegistry,
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    format_route: &'static SourceBackedProviderRouteMetadata,
    source: ProviderSource,
) -> Result<(), SourceBackedAutomaticUnavailableReason> {
    let result = match (format_route.constructor, source.provider) {
        (SourceBackedRouteConstructor::NamedSurface, CaptureProvider::Warp) => {
            let selected =
                resolve_warp_discovery_authority(probes, discovery, &source).map_err(|error| {
                    SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                        detail: warp_discovery_unavailable_detail(error),
                    }
                })?;
            register_warp_source_backed_route(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                selected.surface_key().as_str(),
                None,
            )
        }
        (SourceBackedRouteConstructor::SelectedWithRetainedRoutes, CaptureProvider::Goose) => {
            let platform_root = goose_platform_root(discovery, &source.path).ok_or(
                SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                    detail: "Goose discovery selected a database without its exact platform root",
                },
            )?;
            register_goose_source_backed_route(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                platform_root,
                Vec::new(),
                None,
            )
        }
        (SourceBackedRouteConstructor::FiniteInventory, CaptureProvider::Crush) => {
            let inventory_source = discovered_crush_inventory_source(probes, discovery, &source)?;
            register_crush_source_backed_route(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                inventory_source,
                None,
            )
        }
        (SourceBackedRouteConstructor::FiniteInventory, CaptureProvider::Lingma) => {
            let selector = LingmaInventorySelector::new(discovery.clone(), *probes);
            let registration =
                ctx_history_providers_sqlite_inventory::registration::discovered_lingma_registration::<
                    crate::provider::source_backed::family::document::CaptureDocumentLifecycle,
                    crate::provider::source_backed::family::document::CaptureDocumentSpool,
                    _,
                >(
                    source,
                    SourceBackedRouteSelection::Automatic,
                    data_root,
                    move || selector.observe(),
                )
                .map_err(|error| match error {
                    ctx_history_providers_sqlite_inventory::registration::LingmaRegistrationError::SelectorAuthorityUnavailable(detail) => {
                        SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable { detail }
                    }
                    ctx_history_providers_sqlite_inventory::registration::LingmaRegistrationError::RegistrationRejected(detail) => {
                        SourceBackedAutomaticUnavailableReason::RegistrationRejected {
                            kind: SourceBackedRouteErrorKind::Unsupported,
                            detail,
                        }
                    }
                })?;
            crate::provider::source_backed::family::document::install_sqlite_inventory_registration(
                registry,
                registration,
            )
        }
        (SourceBackedRouteConstructor::DiscoveryContext, CaptureProvider::AstrBot) => {
            register_astrbot_source_backed_route(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                discovery.clone(),
                None,
            )
        }
        (SourceBackedRouteConstructor::CatalogLineage, CaptureProvider::NanoClaw) => {
            let lineage = explicit_source_catalog_lineage(
                source.provider,
                format_route.certified_source_format,
                &source.path,
            );
            register_nanoclaw_source_backed_route_with_selection(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                lineage,
                &[],
            )
        }
        (SourceBackedRouteConstructor::ExactCwd, CaptureProvider::Shelley) => {
            let exact_cwd = discovery.cwd().ok_or(
                SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                    detail: "Shelley automatic registration requires the exact discovery CWD",
                },
            )?;
            register_shelley_source_backed_route(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                exact_cwd,
            )
        }
        (SourceBackedRouteConstructor::ProviderSource, CaptureProvider::OpenHands) => {
            let current_root = resolve_openhands_conversations_root(discovery).ok_or(
                SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                    detail: "OpenHands automatic registration requires its exact current conversation root",
                },
            )?;
            register_openhands_automatic_route(registry, source, &current_root)
        }
        (SourceBackedRouteConstructor::ProviderSource, _) => {
            register_landed_source_backed_route_with_data_root(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
            )
        }
        _ => Err(invalid_route(
            source.provider,
            "the landed route constructor does not match its provider registration callback",
        )),
    };
    result.map_err(automatic_registration_rejected)
}

fn automatic_registration_rejected(
    error: SourceBackedCoordinatorError,
) -> SourceBackedAutomaticUnavailableReason {
    let kind = match &error {
        SourceBackedCoordinatorError::RouteScan { source, .. }
        | SourceBackedCoordinatorError::RouteRegistration { source, .. }
        | SourceBackedCoordinatorError::Progress(source)
        | SourceBackedCoordinatorError::CoreEmission(source) => source.kind,
        SourceBackedCoordinatorError::UnavailableRoute { .. } => {
            SourceBackedRouteErrorKind::Unavailable
        }
        SourceBackedCoordinatorError::InvalidRoute { .. }
        | SourceBackedCoordinatorError::InvalidRefreshScope { .. } => {
            SourceBackedRouteErrorKind::Unsupported
        }
        _ => SourceBackedRouteErrorKind::Internal,
    };
    SourceBackedAutomaticUnavailableReason::RegistrationRejected {
        kind,
        detail: error.to_string(),
    }
}

fn goose_platform_root(discovery: &DiscoveryContext, database: &Path) -> Option<PathBuf> {
    if let Some(root) = discovery
        .env("GOOSE_PATH_ROOT")
        .filter(|value| !value.is_empty())
    {
        let root = PathBuf::from(root);
        if root.is_absolute() && database == root.join("data/sessions/sessions.db") {
            return Some(root);
        }
    }
    let root = match discovery.platform() {
        DiscoveryPlatform::Linux | DiscoveryPlatform::MacOS => {
            match discovery.env("XDG_DATA_HOME") {
                Some(value) if !value.is_empty() && Path::new(value).is_absolute() => {
                    PathBuf::from(value).join("goose")
                }
                _ => discovery.home().join(".local/share/goose"),
            }
        }
        DiscoveryPlatform::Windows => discovery
            .platform_dirs()
            .data
            .as_ref()?
            .join("Block/goose/data"),
        DiscoveryPlatform::OtherUnix => {
            let value = discovery
                .env("XDG_DATA_HOME")
                .filter(|value| !value.is_empty() && Path::new(value).is_absolute())?;
            PathBuf::from(value).join("goose")
        }
    };
    (database == root.join("sessions/sessions.db")).then_some(root)
}

const fn warp_discovery_unavailable_detail(error: WarpDiscoveryUnavailable) -> &'static str {
    match error {
        WarpDiscoveryUnavailable::UnsupportedPlatform { .. } => {
            "Warp installed-surface authority is unavailable on this platform"
        }
        WarpDiscoveryUnavailable::WindowsLocalDataRootUnavailable => {
            "Warp installed-surface authority has no Windows local-data root"
        }
        WarpDiscoveryUnavailable::ProviderSpecUnavailable => {
            "Warp provider discovery specification is unavailable"
        }
        WarpDiscoveryUnavailable::SourceCandidateRejected { .. } => {
            "Warp installed-surface discovery rejected the selected source within fixed bounds"
        }
        WarpDiscoveryUnavailable::SourceNotSelected => {
            "Warp source is absent from authoritative installed-surface discovery"
        }
    }
}

#[derive(Debug, Clone)]
struct DiscoveredCrushInventorySource {
    selector: CrushProjectInventorySelector,
    spec: &'static ProviderSourceSpec,
}

impl CrushProjectInventorySourceV0 for DiscoveredCrushInventorySource {
    fn observe(
        &self,
    ) -> ctx_history_providers_sqlite_inventory::CrushSourceBackedResultV0<
        CrushProjectInventoryObservationV0,
    > {
        self.selector
            .observe(self.spec)
            .map_err(crush_selector_adapter_error)
            .and_then(crush_adapter_inventory)
    }
}

fn discovered_crush_inventory_source(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    selected_source: &ProviderSource,
) -> Result<Arc<DiscoveredCrushInventorySource>, SourceBackedAutomaticUnavailableReason> {
    let spec = provider_source_spec(CaptureProvider::Crush).ok_or(
        SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
            detail: "Crush provider discovery specification is unavailable",
        },
    )?;
    let source = Arc::new(DiscoveredCrushInventorySource {
        selector: CrushProjectInventorySelector::new(discovery.clone(), *probes),
        spec,
    });
    let opening = source.selector.observe(spec).map_err(|error| {
        SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
            detail: error.detail(),
        }
    })?;
    if !opening
        .databases()
        .iter()
        .any(|database| database.database_path() == selected_source.path)
    {
        return Err(
            SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                detail:
                    "Crush selected database is absent from its authoritative project inventory",
            },
        );
    }
    crush_adapter_inventory(opening).map_err(|error| {
        SourceBackedAutomaticUnavailableReason::RegistrationRejected {
            kind: SourceBackedRouteErrorKind::Unsupported,
            detail: error.to_string(),
        }
    })?;
    Ok(source)
}

fn crush_adapter_inventory(
    inventory: CrushDiscoveredProjectInventory,
) -> ctx_history_providers_sqlite_inventory::CrushSourceBackedResultV0<
    CrushProjectInventoryObservationV0,
> {
    let authority_key = inventory
        .authority_key()
        .map_err(crush_selector_adapter_error)?;
    let databases = inventory
        .databases()
        .iter()
        .map(|database| {
            let project_key = database
                .selector_key()
                .typed_key()
                .map_err(crush_selector_adapter_error)?;
            CrushProjectDatabaseV0::new(project_key, database.database_path())
        })
        .collect::<ctx_history_providers_sqlite_inventory::CrushSourceBackedResultV0<Vec<_>>>()?;
    CrushProjectInventoryObservationV0::new(authority_key, inventory.revision().to_vec(), databases)
}

fn crush_selector_adapter_error(
    error: CrushProjectInventorySelectorError,
) -> ctx_history_providers_sqlite_inventory::CrushSourceBackedErrorV0 {
    ctx_history_providers_sqlite_inventory::CaptureError::InvalidPayload(error.to_string()).into()
}
