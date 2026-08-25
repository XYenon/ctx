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
    build_automatic_source_backed_registry_from_report_with_probes_and_retained_roots(
        probes,
        discovery,
        data_root,
        report,
        &BTreeMap::new(),
    )
}

#[doc(hidden)]
pub fn build_automatic_source_backed_registry_from_report_with_probes_and_retained_roots(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    report: DiscoveryReport,
    retained_provider_roots: &BTreeMap<String, RetainedProviderRootAuthority>,
) -> SourceBackedAutomaticRegistryBuild {
    build_automatic_source_backed_registry_from_parts_with_probes(
        probes,
        discovery,
        data_root,
        report.sources,
        report.issues,
        retained_provider_roots,
    )
}

fn build_automatic_source_backed_registry_from_parts_with_probes(
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    sources: Vec<ProviderSource>,
    discovery_issues: Vec<DiscoveryIssue>,
    retained_provider_roots: &BTreeMap<String, RetainedProviderRootAuthority>,
) -> SourceBackedAutomaticRegistryBuild {
    let canonical_automatic =
        ctx_history_source_discovery::discover_canonical_automatic_provider_sources_with_context(
            probes, discovery,
        );
    let canonical_automatic_sources = canonical_automatic.sources;
    let provider_root_registrations = normalized_provider_root_registrations(
        discovery,
        &sources,
        &canonical_automatic_sources,
        data_root,
        retained_provider_roots,
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
            provider_root_registrations
                .get(&root.id)
                .map(|registration| registration.source_identity)
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
            if configured_source_identity == Some(ProviderRootSourceIdentity::Released)
                && released_root_uses_automatic_registration(source.provider)
            {
                // A missing moved Released root cannot reconstruct current
                // connector routes. Leave its applied membership empty so the
                // refresh merge restores the exact prior route set instead of
                // minting a configured-path identity for the missing scan path.
                let reason = SourceBackedAutomaticUnavailableReason::SourceStatus(source.status);
                issues.push(SourceBackedAutomaticRegistryIssue::Unavailable { source, reason });
                continue;
            }
            let route = if configured_root.is_some() {
                let reason = SourceBackedAutomaticUnavailableReason::SourceStatus(source.status);
                SourceBackedRoute::unavailable_explicit(
                    source.clone(),
                    automatic_unavailable_detail(&reason),
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
                Ok(route) => {
                    registry.register(route);
                    if configured_root.is_some() {
                        let reason = SourceBackedAutomaticUnavailableReason::SourceStatus(
                            ProviderSourceStatus::Missing,
                        );
                        issues.push(SourceBackedAutomaticRegistryIssue::Unavailable {
                            source,
                            reason,
                        });
                    }
                }
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
            if configured_source_identity == Some(ProviderRootSourceIdentity::Released)
                && released_root_uses_automatic_registration(source.provider)
            {
                let identity_root = provider_root_registrations
                    .get(&configured_root.id)
                    .and_then(|registration| registration.released_identity_root.as_deref());
                let compound_provider = matches!(
                    format_route.constructor,
                    SourceBackedRouteConstructor::FiniteInventory
                        | SourceBackedRouteConstructor::DiscoveryContext
                );
                let registration = identity_root.map_or_else(
                    || {
                        Err(SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                            detail: "released provider root has no immutable automatic identity root",
                        })
                    },
                    |identity_root| {
                        register_released_provider_root_route(
                            &mut registry,
                            probes,
                            discovery,
                            data_root,
                            configured_root,
                            source.clone(),
                            identity_root,
                        )
                        .map_err(automatic_registration_rejected)
                    },
                );
                match registration {
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
                        issues.push(SourceBackedAutomaticRegistryIssue::Unavailable {
                            source,
                            reason,
                        });
                    }
                }
                continue;
            }
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
                    configured_root,
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
        let coexistence_lineage = released_root_automatic_coexistence_lineage(
            &registry,
            discovery,
            &provider_root_registrations,
            &source,
        );
        if compound_provider
            && compound_provider_registered.contains(&source.provider)
            && coexistence_lineage.is_none()
        {
            continue;
        }
        match register_discovered_automatic_route(
            &mut registry,
            probes,
            discovery,
            data_root,
            format_route,
            source.clone(),
            coexistence_lineage,
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
            let registration = provider_root_registrations.get(&definition.id);
            let source_identity = registration
                .map(|registration| registration.source_identity)
                .unwrap_or_else(|| default_provider_root_source_identity(discovery, definition));
            match registration.and_then(|registration| registration.retained_authority.as_ref()) {
                Some(authority) => AppliedProviderRoot::with_retained_authority(
                    definition.clone(),
                    authority.clone(),
                    routes,
                ),
                None => AppliedProviderRoot::with_source_identity(
                    definition.clone(),
                    source_identity,
                    routes,
                ),
            }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderRootRegistration {
    source_identity: ProviderRootSourceIdentity,
    released_identity_root: Option<PathBuf>,
    retained_authority: Option<RetainedProviderRootAuthority>,
}

fn normalized_provider_root_registrations(
    discovery: &DiscoveryContext,
    configured_sources: &[ProviderSource],
    canonical_automatic_sources: &[ProviderSource],
    data_root: &Path,
    retained: &BTreeMap<String, RetainedProviderRootAuthority>,
) -> BTreeMap<String, ProviderRootRegistration> {
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
        let retained_root = retained.get(&root.id);
        let identity = match retained_root.map(RetainedProviderRootAuthority::source_identity) {
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
        let released_identity_root = match identity {
            ProviderRootSourceIdentity::Released => retained_root
                .and_then(RetainedProviderRootAuthority::connector_binding)
                .and_then(|binding| binding.identity_root().map(Path::to_path_buf))
                .or_else(|| {
                    (retained_root.is_none()
                        && configured_root_matches_canonical_automatic_routes(
                            root,
                            configured_sources,
                            canonical_automatic_sources,
                            data_root,
                        ))
                    .then(|| root.path.clone())
                }),
            ProviderRootSourceIdentity::NamedV1 => None,
        };
        identities.insert(
            root.id.clone(),
            ProviderRootRegistration {
                source_identity: identity,
                released_identity_root,
                retained_authority: retained_root
                    .filter(|authority| authority.source_identity() == identity)
                    .cloned(),
            },
        );
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
                && matched_canonical_automatic_source(source, canonical_automatic_sources).is_some()
        })
}

fn matched_canonical_automatic_source<'a>(
    configured: &ProviderSource,
    canonical_automatic_sources: &'a [ProviderSource],
) -> Option<&'a ProviderSource> {
    canonical_automatic_sources.iter().find(|automatic| {
        automatic.provider == configured.provider
            && automatic.source_format == configured.source_format
            && matches!(
                automatic.status,
                ProviderSourceStatus::Available | ProviderSourceStatus::Empty
            )
            && provider_paths_equivalent(&automatic.path, &configured.path)
    })
}

fn register_released_provider_root_route(
    registry: &mut SourceBackedProviderRegistry,
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    configured_root: &ProviderRootDefinition,
    configured_source: ProviderSource,
    identity_root: &Path,
) -> SourceBackedCoordinatorResult<()> {
    let mut identity_source =
        released_identity_source(configured_root, &configured_source, identity_root)?;
    let mut scan_source = configured_source.clone();
    scan_source.route_provenance = identity_source.route_provenance.clone();
    let mut scoped = SourceBackedProviderRegistry::new();
    match configured_source.provider {
        CaptureProvider::OpenClaw => {
            register_landed_source_backed_route_with_data_root_and_lineage(
                &mut scoped,
                scan_source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                None,
            )?;
        }
        CaptureProvider::Hermes => register_hermes_released_source_backed_route(
            &mut scoped,
            scan_source,
            data_root,
            &identity_source.path,
        )?,
        CaptureProvider::Warp => {
            let selected =
                resolve_warp_released_identity_authority(probes, discovery, &identity_source.path)
                    .map_err(|error| {
                        invalid_route(configured_source.provider, error.to_string())
                    })?;
            identity_source.route_provenance = selected.source().route_provenance.clone();
            scan_source.route_provenance = identity_source.route_provenance.clone();
            register_warp_source_backed_route(
                &mut scoped,
                scan_source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                selected.surface_key().as_str(),
                None,
            )?;
        }
        CaptureProvider::Goose => {
            let identity_platform_root = goose_platform_root(discovery, &identity_source.path)
                .ok_or_else(|| {
                    invalid_route(
                        configured_source.provider,
                        "released Goose identity has no exact automatic platform root",
                    )
                })?;
            let scan_platform_root = rebase_goose_platform_root(
                &identity_source.path,
                &identity_platform_root,
                &scan_source.path,
            )
            .or_else(|| scan_source.path.parent().map(Path::to_path_buf))
            .ok_or_else(|| {
                invalid_route(
                    configured_source.provider,
                    "configured Goose database has no attachment-context parent",
                )
            })?;
            register_goose_source_backed_route(
                &mut scoped,
                scan_source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                scan_platform_root,
                Vec::new(),
                None,
            )?;
        }
        CaptureProvider::Crush => {
            let released = resolve_crush_released_project_inventory(
                probes,
                discovery,
                &identity_source.path,
                &scan_source.path,
            )
            .map_err(|error| invalid_route(configured_source.provider, error.to_string()))?;
            let databases = released
                .databases()
                .iter()
                .map(|(key, path)| {
                    CrushProjectDatabaseV0::new(key.clone(), path.clone()).map_err(|error| {
                        invalid_route(configured_source.provider, error.to_string())
                    })
                })
                .collect::<SourceBackedCoordinatorResult<Vec<_>>>()?;
            let inventory = Arc::new(ReleasedCrushInventorySource {
                authority_key: released.authority_key().clone(),
                revision: released.revision().to_vec(),
                databases,
            });
            register_crush_source_backed_route(
                &mut scoped,
                scan_source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                inventory,
                None,
            )?;
        }
        CaptureProvider::Lingma => {
            let identity = resolve_lingma_released_identity_authority(
                probes,
                discovery,
                &identity_source.path,
            )
            .map_err(|error| invalid_route(configured_source.provider, error.to_string()))?;
            let inventory = LingmaInventorySelector::new(discovery.clone(), *probes)
                .observe()
                .map_err(|error| invalid_route(configured_source.provider, error.to_string()))?;
            let authority_key = inventory
                .authority_key()
                .map_err(|error| invalid_route(configured_source.provider, error.to_string()))?;
            let mut databases = inventory
                .databases()
                .iter()
                .filter(|database| {
                    database.path() != identity_source.path
                        && database.path() != configured_source.path
                })
                .map(|database| {
                    database
                        .catalog_lineage()
                        .typed_key()
                        .map(|lineage| (database.path().to_path_buf(), lineage))
                        .map_err(|error| {
                            invalid_route(configured_source.provider, error.to_string())
                        })
                })
                .collect::<SourceBackedCoordinatorResult<Vec<_>>>()?;
            databases.push((
                configured_source.path.clone(),
                identity.typed_key().map_err(|error| {
                    invalid_route(configured_source.provider, error.to_string())
                })?,
            ));
            register_lingma_source_backed_route(
                &mut scoped,
                scan_source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                authority_key,
                databases,
                None,
            )?;
        }
        CaptureProvider::AstrBot => register_astrbot_released_source_backed_route(
            &mut scoped,
            scan_source,
            identity_source.clone(),
            discovery.home(),
            data_root,
        )?,
        provider => {
            return Err(invalid_route(
                provider,
                "provider has no released automatic connector reconstruction",
            ));
        }
    }
    if scoped.routes.len() != 1 {
        return Err(invalid_route(
            configured_source.provider,
            format!(
                "released automatic registration produced {} routes instead of one",
                scoped.routes.len()
            ),
        ));
    }
    let mut route = scoped
        .routes
        .pop()
        .expect("one released route was validated");
    let mut configured_source = configured_source;
    if let ProviderSourceRouteProvenance::ConfiguredRoot {
        automatic_route_role,
        ..
    } = &mut configured_source.route_provenance
    {
        *automatic_route_role = identity_source
            .route_provenance
            .automatic_route_role()
            .cloned();
    }
    route.apply_released_automatic_identity(&identity_source, configured_source)?;
    registry.register(route);
    Ok(())
}

fn released_identity_source(
    configured_root: &ProviderRootDefinition,
    configured_source: &ProviderSource,
    identity_root: &Path,
) -> SourceBackedCoordinatorResult<ProviderSource> {
    let relative = configured_source
        .path
        .strip_prefix(&configured_root.path)
        .map_err(|_| {
            invalid_route(
                configured_source.provider,
                "configured source is outside its provider root",
            )
        })?;
    let mut identity_source = configured_source.clone();
    identity_source.path = identity_root.join(relative);
    identity_source.route_provenance = ProviderSourceRouteProvenance::Unroled;
    if configured_source.provider == CaptureProvider::OpenClaw {
        let mut components = relative.components();
        let agents = components.next();
        let agent_id = components.next().map(|component| component.as_os_str());
        if agents.map(|component| component.as_os_str()) != Some(std::ffi::OsStr::new("agents"))
            || agent_id.is_none()
        {
            return Err(invalid_route(
                configured_source.provider,
                "released OpenClaw source has no bounded automatic agent identity",
            ));
        }
        let route_role = ProviderRouteRole::from_dynamic([
            b"agent".as_slice(),
            agent_id.expect("agent id was validated").as_encoded_bytes(),
        ])
        .map_err(|error| invalid_route(configured_source.provider, error.to_string()))?;
        identity_source.route_provenance = ProviderSourceRouteProvenance::Automatic { route_role };
    }
    Ok(identity_source)
}

fn rebase_goose_platform_root(
    identity_database: &Path,
    identity_platform_root: &Path,
    scan_database: &Path,
) -> Option<PathBuf> {
    let suffix = identity_database
        .strip_prefix(identity_platform_root)
        .ok()?;
    if suffix.as_os_str().is_empty() || !scan_database.ends_with(suffix) {
        return None;
    }
    scan_database
        .ancestors()
        .nth(suffix.components().count())
        .map(Path::to_path_buf)
}

fn released_root_automatic_coexistence_lineage(
    registry: &SourceBackedProviderRegistry,
    discovery: &DiscoveryContext,
    provider_root_registrations: &BTreeMap<String, ProviderRootRegistration>,
    automatic: &ProviderSource,
) -> Option<[u8; 32]> {
    let ordinary_route = automatic_source_backed_route_identity(automatic).ok()?;
    let adopted = registry.routes.iter().find(|route| {
        route.metadata.route_identity.as_ref() == Some(&ordinary_route)
            && !provider_paths_equivalent(&route.metadata.source.path, &automatic.path)
    })?;
    let (root_id, _) = adopted.metadata.source.route_provenance.configured_root()?;
    if provider_root_registrations
        .get(root_id)
        .map(|registration| registration.source_identity)
        != Some(ProviderRootSourceIdentity::Released)
    {
        return None;
    }
    let root = discovery
        .configured_provider_roots()
        .iter()
        .find(|root| root.id == root_id && root.provider == automatic.provider)?;
    Some(automatic_provider_root_coexistence_source_lineage(root))
}

const fn released_root_uses_automatic_registration(provider: CaptureProvider) -> bool {
    matches!(
        provider,
        CaptureProvider::OpenClaw
            | CaptureProvider::Hermes
            | CaptureProvider::Crush
            | CaptureProvider::Goose
            | CaptureProvider::AstrBot
            | CaptureProvider::Lingma
            | CaptureProvider::Warp
    )
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
    configured_root: &ProviderRootDefinition,
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
            let platform_root = source.path.parent().ok_or_else(|| {
                invalid_route(
                    source.provider,
                    "configured Goose database has no attachment-context parent",
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
            let root_local_discovery = discovery
                .clone()
                .with_automatic_provider_discovery(false)
                .with_configured_provider_roots(vec![configured_root.clone()]);
            register_astrbot_source_backed_route(
                registry,
                source.clone(),
                SourceBackedRouteSelection::ExplicitManual,
                data_root,
                root_local_discovery,
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

#[derive(Debug, Clone)]
struct ReleasedCrushInventorySource {
    authority_key: TypedKey,
    revision: Vec<u8>,
    databases: Vec<CrushProjectDatabaseV0>,
}

impl CrushProjectInventorySourceV0 for ReleasedCrushInventorySource {
    fn observe(
        &self,
    ) -> ctx_history_providers_sqlite_inventory::CrushSourceBackedResultV0<
        CrushProjectInventoryObservationV0,
    > {
        CrushProjectInventoryObservationV0::new(
            self.authority_key.clone(),
            self.revision.clone(),
            self.databases.clone(),
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
    source_root_lineage: Option<[u8; 32]>,
) -> Result<(), SourceBackedAutomaticUnavailableReason> {
    let Some(source_root_lineage) = source_root_lineage else {
        return register_discovered_automatic_route_scoped(
            registry,
            probes,
            discovery,
            data_root,
            format_route,
            source,
            None,
        );
    };
    let provider = source.provider;
    let mut scoped = SourceBackedProviderRegistry::new();
    register_discovered_automatic_route_scoped(
        &mut scoped,
        probes,
        discovery,
        data_root,
        format_route,
        source,
        Some(source_root_lineage),
    )?;
    if scoped.routes.len() != 1 {
        return Err(
            SourceBackedAutomaticUnavailableReason::RegistrationRejected {
                kind: SourceBackedRouteErrorKind::Internal,
                detail: format!(
                    "{} automatic coexistence registration produced {} routes instead of one",
                    provider.as_str(),
                    scoped.routes.len()
                ),
            },
        );
    }
    let mut route = scoped.routes.pop().expect("one scoped route was validated");
    route
        .apply_automatic_coexistence_identity(source_root_lineage)
        .map_err(automatic_registration_rejected)?;
    registry.register(route);
    Ok(())
}

fn register_discovered_automatic_route_scoped(
    registry: &mut SourceBackedProviderRegistry,
    probes: &StaticProviderProbeCatalog,
    discovery: &DiscoveryContext,
    data_root: &Path,
    format_route: &'static SourceBackedProviderRouteMetadata,
    source: ProviderSource,
    source_root_lineage: Option<[u8; 32]>,
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
                source_root_lineage,
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
                source_root_lineage,
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
                source_root_lineage,
            )
        }
        (SourceBackedRouteConstructor::FiniteInventory, CaptureProvider::Lingma) => {
            let selector = LingmaInventorySelector::new(discovery.clone(), *probes);
            let registration =
                ctx_history_providers_sqlite_inventory::registration::discovered_lingma_registration_scoped::<
                    crate::provider::source_backed::family::document::CaptureDocumentLifecycle,
                    crate::provider::source_backed::family::document::CaptureDocumentSpool,
                    _,
                >(
                    source,
                    SourceBackedRouteSelection::Automatic,
                    data_root,
                    move || selector.observe(),
                    source_root_lineage.map_or(
                        ctx_history_core::SourceAnchorScope::Unqualified,
                        ctx_history_core::SourceAnchorScope::Lineage,
                    ),
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
                discovery.clone().with_configured_provider_roots(Vec::new()),
                source_root_lineage,
            )
        }
        (SourceBackedRouteConstructor::CatalogLineage, CaptureProvider::NanoClaw) => {
            if source_root_lineage.is_some() {
                return Err(
                    SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                        detail:
                            "NanoClaw automatic coexistence requires a scoped catalog connector",
                    },
                );
            }
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
            if source_root_lineage.is_some() {
                return Err(
                    SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                        detail:
                            "Shelley automatic coexistence requires a scoped exact-CWD connector",
                    },
                );
            }
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
            if source_root_lineage.is_some() {
                return Err(SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                    detail: "OpenHands automatic coexistence requires a scoped current-root connector",
                });
            }
            let current_root = resolve_openhands_conversations_root(discovery).ok_or(
                SourceBackedAutomaticUnavailableReason::SelectorAuthorityUnavailable {
                    detail: "OpenHands automatic registration requires its exact current conversation root",
                },
            )?;
            register_openhands_automatic_route(registry, source, &current_root)
        }
        (SourceBackedRouteConstructor::ProviderSource, _) => {
            register_landed_source_backed_route_with_data_root_and_lineage(
                registry,
                source,
                SourceBackedRouteSelection::Automatic,
                data_root,
                source_root_lineage,
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
