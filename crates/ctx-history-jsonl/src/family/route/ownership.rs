use super::*;

pub(super) fn base_sources_for_route<R: JsonlFamilyRuntime>(
    adapter: &dyn JsonlFamilyAdapter<Runtime = R>,
    sink: &SourceBackedGenerationSink<'_, R::Lifecycle>,
) -> SourceBackedRouteResult<Vec<CertifiedSource>> {
    Ok(sink
        .base_route_sources()
        .map_err(route_internal)?
        .into_values()
        .filter(|source| adapter.owns(source.observation().source()))
        .collect())
}
