//! Generation-level provider lifecycle qualification.

use std::{fs, path::PathBuf};

use ctx_history_capture_composition::*;
use ctx_history_capture_model::{
    ProviderRootDefinition, ProviderRouteRole, ProviderSourceRouteProvenance, SourceRouteIdentity,
};
use ctx_history_core::{CaptureProvider, CoreRecord, LiteralFactKind, SourceAnchor, SourceKey};
use ctx_history_index::VerifiedIndex;
use tempfile::tempdir;

#[path = "provider_lifecycle/codex_child_independence.rs"]
mod codex_child_independence;
#[path = "provider_lifecycle/sqlite_selected.rs"]
mod sqlite_selected;

fn has_literal_fact(record: &CoreRecord, kind: LiteralFactKind, value: &str) -> bool {
    record
        .content
        .activity
        .iter()
        .flat_map(|activity| activity.facts.iter())
        .any(|fact| fact.kind == kind && fact.value == value)
}

fn fixture_provider_source_at(
    provider: CaptureProvider,
    source_format: &'static str,
    import_support: ProviderImportSupport,
    path: impl Into<PathBuf>,
) -> ProviderSource {
    ProviderSource {
        provider,
        path: path.into(),
        exists: true,
        source_format,
        source_kind: ProviderSourceKind::NativeHistory,
        import_support,
        catalog_support: ProviderCatalogSupport::None,
        status: ProviderSourceStatus::Available,
        unsupported_reason: None,
        route_provenance: Default::default(),
    }
}

fn test_provider_probes() -> StaticProviderProbeCatalog {
    use ctx_history_source_discovery::{CursorProbeFragment, CursorTranscriptProbeOutcome};

    fn cursor(_: &std::path::Path) -> CursorTranscriptProbeOutcome {
        CursorTranscriptProbeOutcome::NotFound
    }

    StaticProviderProbeCatalog::new(CursorProbeFragment::new(cursor))
}

mod provider_sources {
    use std::path::PathBuf;

    use ctx_history_core::CaptureProvider;

    pub(crate) fn provider_source_for_path(
        provider: CaptureProvider,
        path: PathBuf,
    ) -> ctx_history_capture_composition::ProviderSource {
        ctx_history_source_discovery::provider_source_for_path(
            &super::test_provider_probes(),
            provider,
            path,
        )
    }
}

mod test_support_paths {
    use std::{fs, io};

    pub(crate) fn tempdir() -> io::Result<tempfile::TempDir> {
        let temp_root = fs::canonicalize(std::env::temp_dir())?;
        tempfile::Builder::new()
            .prefix("ctx-history-capture-provider-lifecycle-")
            .tempdir_in(temp_root)
    }
}

mod provider {
    pub(crate) mod codex {
        pub(crate) use ctx_history_provider_codex::codex::*;
    }

    pub(crate) mod source_backed {
        pub(crate) mod family {
            pub(crate) mod jsonl {
                pub(crate) use ctx_history_provider_runtime::{
                    set_after_jsonl_append_observation_route_binding_hook,
                    set_after_jsonl_semantic_preflight_hook, set_after_standard_zstd_snapshot_hook,
                    set_before_jsonl_terminal_physical_revalidation_hook,
                };
            }
        }
    }
}
