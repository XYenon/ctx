use super::*;

#[derive(Debug, Clone)]
pub(super) struct ReleasedProviderRootRoute {
    pub(super) route_identity: SourceRouteIdentity,
    pub(super) exact_source_token: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReleasedCompoundRootSource {
    pub(super) definition: ProviderRootDefinition,
    pub(super) source: ProviderSource,
    pub(super) identity_root: PathBuf,
}

pub(super) fn released_compound_inventory_coverage(
    provider: CaptureProvider,
    discovery: &DiscoveryContext,
    available: &[ReleasedCompoundRootSource],
    registrations: &BTreeMap<String, ProviderRootRegistration>,
) -> SqliteInventoryCoverage {
    if !matches!(provider, CaptureProvider::Crush | CaptureProvider::Lingma) {
        return SqliteInventoryCoverage::Complete;
    }
    let configured_released = discovery
        .configured_provider_roots()
        .iter()
        .filter(|root| {
            root.provider == provider
                && registrations.get(&root.id).is_some_and(|registration| {
                    registration.source_identity == ProviderRootSourceIdentity::Released
                })
        })
        .count();
    let available_released = available
        .iter()
        .filter(|root| root.source.provider == provider)
        .count();
    if discovery.automatic_provider_discovery_enabled() && available_released == configured_released
    {
        SqliteInventoryCoverage::Complete
    } else {
        SqliteInventoryCoverage::SelectedSubset
    }
}

pub(super) fn released_compound_root_sources(
    discovery: &DiscoveryContext,
    sources: &[ProviderSource],
    registrations: &BTreeMap<String, ProviderRootRegistration>,
) -> Vec<ReleasedCompoundRootSource> {
    sources
        .iter()
        .filter(|source| {
            matches!(
                source.provider,
                CaptureProvider::Crush | CaptureProvider::Lingma
            ) && matches!(
                source.status,
                ProviderSourceStatus::Available | ProviderSourceStatus::Empty
            )
        })
        .filter_map(|source| {
            let definition = configured_provider_root_for_source(discovery, source)?;
            let registration = registrations.get(&definition.id)?;
            if registration.source_identity != ProviderRootSourceIdentity::Released {
                return None;
            }
            Some(ReleasedCompoundRootSource {
                definition: definition.clone(),
                source: source.clone(),
                identity_root: registration.released_identity_root.clone()?,
            })
        })
        .collect()
}

pub(super) fn applied_provider_roots(
    discovery: &DiscoveryContext,
    registry: &SourceBackedProviderRegistry,
    registrations: &BTreeMap<String, ProviderRootRegistration>,
    released_routes: &BTreeMap<String, Vec<ReleasedProviderRootRoute>>,
) -> SourceBackedCoordinatorResult<Vec<AppliedProviderRoot>> {
    discovery
        .configured_provider_roots()
        .iter()
        .map(|definition| {
            let mut routes = registry
                .routes
                .iter()
                .filter(|route| {
                    configured_provider_root_for_source(discovery, &route.metadata.source)
                        .is_some_and(|root| root.id == definition.id)
                })
                .filter_map(|route| route.metadata.route_identity.clone())
                .collect::<BTreeSet<_>>();
            let mut exact = BTreeMap::<SourceRouteIdentity, Vec<String>>::new();
            for receipt in released_routes.get(&definition.id).into_iter().flatten() {
                routes.insert(receipt.route_identity.clone());
                if let Some(token) = &receipt.exact_source_token {
                    exact
                        .entry(receipt.route_identity.clone())
                        .or_default()
                        .push(token.clone());
                }
            }
            let registration = registrations.get(&definition.id);
            let source_identity = registration
                .map(|registration| registration.source_identity)
                .unwrap_or_else(|| default_provider_root_source_identity(discovery, definition));
            let root = match registration.and_then(|value| value.retained_authority.as_ref()) {
                Some(authority) => AppliedProviderRoot::with_retained_authority(
                    definition.clone(),
                    authority.clone(),
                    routes.iter().cloned().collect(),
                ),
                None => AppliedProviderRoot::with_source_identity(
                    definition.clone(),
                    source_identity,
                    routes.into_iter().collect(),
                ),
            }
            .map_err(SourceBackedCoordinatorError::Index)?;
            root.with_exact_source_memberships(
                exact
                    .into_iter()
                    .map(|(route, sources)| {
                        AppliedProviderRootSourceMembership::exact(route, sources)
                    })
                    .collect::<ctx_history_index::Result<Vec<_>>>()?,
            )
            .map_err(SourceBackedCoordinatorError::Index)
        })
        .collect()
}
