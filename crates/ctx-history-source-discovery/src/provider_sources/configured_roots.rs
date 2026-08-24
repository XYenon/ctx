use std::path::{Path, PathBuf};

use ctx_history_capture_model::{
    ProviderRootDefinition, ProviderRouteRole, ProviderSourceRouteProvenance,
};
use ctx_history_core::CaptureProvider;

use super::{
    context::DiscoveryContext,
    reasons::path_presence_unknown_reason,
    resolvers::{
        issue, path_presence, push_source_candidate, source_from_parts_with_data_root, PathPresence,
    },
    selectors::encoded_path_within_limit,
    types::{DiscoveryIssueKind, DiscoveryReport, ProviderSourceKind, ProviderSourceSpec},
    StaticProviderProbeCatalog,
};

const CONFIGURED_ROOT_SYMLINK_REASON: &str =
    "the selected history path uses a symlink component; use a trusted real provider root";
const CONFIGURED_ROOT_PATH_LIMIT_REASON: &str =
    "the selected provider history path exceeds the discovery path limit";

/// Filesystem kind required by a configured-root capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredRootPathKind {
    Directory,
    File,
}

/// Frozen expansion strategy for one enabled configured-root capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredRootExpander {
    ClaudeHomeV1,
    CodexHomeV1,
}

/// Support state and complete expansion metadata for one landed provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredRootCapabilityState {
    Enabled {
        expected_path_kind: ConfiguredRootPathKind,
        expander: ConfiguredRootExpander,
    },
    NotYetEnabled,
}

impl ConfiguredRootCapabilityState {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    pub const fn expected_path_kind(self) -> Option<ConfiguredRootPathKind> {
        match self {
            Self::Enabled {
                expected_path_kind, ..
            } => Some(expected_path_kind),
            Self::NotYetEnabled => None,
        }
    }

    pub const fn expander(self) -> Option<ConfiguredRootExpander> {
        match self {
            Self::Enabled { expander, .. } => Some(expander),
            Self::NotYetEnabled => None,
        }
    }
}

/// Provider-neutral configured-root capability row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredRootCapability {
    pub provider: CaptureProvider,
    pub state: ConfiguredRootCapabilityState,
}

const ENABLED_DIRECTORY_CLAUDE: ConfiguredRootCapabilityState =
    ConfiguredRootCapabilityState::Enabled {
        expected_path_kind: ConfiguredRootPathKind::Directory,
        expander: ConfiguredRootExpander::ClaudeHomeV1,
    };
const ENABLED_DIRECTORY_CODEX: ConfiguredRootCapabilityState =
    ConfiguredRootCapabilityState::Enabled {
        expected_path_kind: ConfiguredRootPathKind::Directory,
        expander: ConfiguredRootExpander::CodexHomeV1,
    };
const NOT_YET_ENABLED: ConfiguredRootCapabilityState = ConfiguredRootCapabilityState::NotYetEnabled;

// Keep this table in the exact landed provider-spec order. Later provider
// cohorts enable rows here without introducing a second support allowlist.
const CONFIGURED_ROOT_CAPABILITIES: &[ConfiguredRootCapability] = &[
    ConfiguredRootCapability {
        provider: CaptureProvider::Codex,
        state: ENABLED_DIRECTORY_CODEX,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::GrokBuild,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::DeepSeekHarness,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Pi,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Claude,
        state: ENABLED_DIRECTORY_CLAUDE,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::OpenCode,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Kilo,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::MiMoCode,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::KiroCli,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Crush,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Goose,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Antigravity,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Gemini,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Tabnine,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Cursor,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Zed,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::CopilotCli,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::FactoryAiDroid,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::QwenCode,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::KimiCodeCli,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Auggie,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Junie,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Firebender,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::ForgeCode,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::DeepAgents,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::MistralVibe,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Mux,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::RovoDev,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::OpenClaw,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Hermes,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::NanoClaw,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::AstrBot,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Shelley,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Continue,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::OpenHands,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Cline,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::RooCode,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Lingma,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Qoder,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::Warp,
        state: NOT_YET_ENABLED,
    },
    ConfiguredRootCapability {
        provider: CaptureProvider::CodeBuddy,
        state: NOT_YET_ENABLED,
    },
];

pub fn configured_root_capabilities() -> &'static [ConfiguredRootCapability] {
    CONFIGURED_ROOT_CAPABILITIES
}

pub fn configured_root_capability(
    provider: CaptureProvider,
) -> Option<&'static ConfiguredRootCapability> {
    CONFIGURED_ROOT_CAPABILITIES
        .iter()
        .find(|capability| capability.provider == provider)
}

#[derive(Debug, Clone)]
struct ConfiguredRouteExpansion {
    relative_path: &'static [&'static str],
    source_format: &'static str,
    route_role: ProviderRouteRole,
}

const CLAUDE_ROUTES: &[ConfiguredRouteExpansion] = &[ConfiguredRouteExpansion {
    relative_path: &["projects"],
    source_format: "claude_projects_jsonl_tree",
    route_role: ProviderRouteRole::from_static("claude-projects"),
}];

const CODEX_ROUTES: &[ConfiguredRouteExpansion] = &[
    ConfiguredRouteExpansion {
        relative_path: &["sessions"],
        source_format: "codex_session_jsonl_tree",
        route_role: ProviderRouteRole::from_static("codex-sessions"),
    },
    ConfiguredRouteExpansion {
        relative_path: &["archived_sessions"],
        source_format: "codex_session_jsonl_tree",
        route_role: ProviderRouteRole::from_static("codex-archived-sessions"),
    },
    ConfiguredRouteExpansion {
        relative_path: &["history.jsonl"],
        source_format: "codex_history_jsonl",
        route_role: ProviderRouteRole::from_static("codex-prompt-history"),
    },
];

pub(super) fn expand_configured_roots_for_provider(
    probes: &StaticProviderProbeCatalog,
    context: &DiscoveryContext,
    spec: &ProviderSourceSpec,
) -> DiscoveryReport {
    let Some(expander) = configured_root_capability(spec.provider)
        .and_then(|capability| capability.state.expander())
    else {
        return DiscoveryReport::default();
    };
    let expansions = match expander {
        ConfiguredRootExpander::ClaudeHomeV1 => CLAUDE_ROUTES,
        ConfiguredRootExpander::CodexHomeV1 => CODEX_ROUTES,
    };
    let mut report = DiscoveryReport::default();
    for root in context
        .configured_provider_roots()
        .iter()
        .filter(|root| root.provider == spec.provider)
    {
        for expansion in expansions {
            add_configured_source(
                probes,
                context.data_root(),
                &mut report,
                spec,
                root,
                expansion,
            );
        }
    }
    report
}

fn add_configured_source(
    probes: &StaticProviderProbeCatalog,
    data_root: Option<&Path>,
    report: &mut DiscoveryReport,
    spec: &ProviderSourceSpec,
    root: &ProviderRootDefinition,
    expansion: &ConfiguredRouteExpansion,
) {
    let path = expansion
        .relative_path
        .iter()
        .fold(root.path.clone(), |path, component| path.join(component));
    if !encoded_path_within_limit(&path) {
        push_issue_once(
            report,
            spec,
            None,
            DiscoveryIssueKind::SelectorUnreconstructible,
            CONFIGURED_ROOT_PATH_LIMIT_REASON,
        );
        return;
    }
    match path_presence(&path) {
        PathPresence::Unknown(kind) => push_issue_once(
            report,
            spec,
            Some(path.clone()),
            DiscoveryIssueKind::SelectorUnreconstructible,
            path_presence_unknown_reason(kind),
        ),
        PathPresence::Unsupported => {
            push_issue_once(
                report,
                spec,
                Some(path),
                DiscoveryIssueKind::SelectorUnreconstructible,
                CONFIGURED_ROOT_SYMLINK_REASON,
            );
            return;
        }
        PathPresence::Missing | PathPresence::Present => {}
    }
    let mut source = source_from_parts_with_data_root(
        probes,
        data_root,
        spec,
        path,
        expansion.source_format,
        ProviderSourceKind::NativeHistory,
    );
    source.route_provenance = ProviderSourceRouteProvenance::ConfiguredRoot {
        root_id: root.id.clone(),
        root_path: root.path.clone(),
        route_role: expansion.route_role.clone(),
    };
    if !push_source_candidate(&mut report.sources, source) {
        push_issue_once(
            report,
            spec,
            None,
            DiscoveryIssueKind::SelectorUnreconstructible,
            CONFIGURED_ROOT_PATH_LIMIT_REASON,
        );
    }
}

fn push_issue_once(
    report: &mut DiscoveryReport,
    spec: &ProviderSourceSpec,
    path: Option<PathBuf>,
    kind: DiscoveryIssueKind,
    reason: &'static str,
) {
    if !report
        .issues
        .iter()
        .any(|existing| existing.kind == kind && existing.reason == reason)
    {
        report.issues.push(issue(spec.provider, path, kind, reason));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::provider_sources::provider_source_specs;

    #[test]
    fn capability_table_is_exhaustive_for_all_41_landed_providers() {
        assert_eq!(configured_root_capabilities().len(), 41);
        let providers = configured_root_capabilities()
            .iter()
            .map(|capability| capability.provider)
            .collect::<HashSet<_>>();
        assert_eq!(providers.len(), configured_root_capabilities().len());
        assert_eq!(
            providers,
            provider_source_specs()
                .iter()
                .map(|spec| spec.provider)
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn foundation_enables_only_directory_claude_and_codex_homes() {
        let enabled = configured_root_capabilities()
            .iter()
            .filter(|capability| capability.state.is_enabled())
            .collect::<Vec<_>>();
        assert_eq!(enabled.len(), 2);
        assert_eq!(
            configured_root_capability(CaptureProvider::Claude).map(|row| row.state),
            Some(ENABLED_DIRECTORY_CLAUDE)
        );
        assert_eq!(
            configured_root_capability(CaptureProvider::Codex).map(|row| row.state),
            Some(ENABLED_DIRECTORY_CODEX)
        );
        assert!(configured_root_capabilities().iter().all(|capability| {
            matches!(
                capability.provider,
                CaptureProvider::Claude | CaptureProvider::Codex
            ) || capability.state == ConfiguredRootCapabilityState::NotYetEnabled
        }));
    }

    #[test]
    fn released_route_roles_remain_exact_bytes() {
        assert_eq!(CLAUDE_ROUTES[0].route_role.as_bytes(), b"claude-projects");
        assert_eq!(CODEX_ROUTES[0].route_role.as_bytes(), b"codex-sessions");
        assert_eq!(
            CODEX_ROUTES[1].route_role.as_bytes(),
            b"codex-archived-sessions"
        );
        assert_eq!(
            CODEX_ROUTES[2].route_role.as_bytes(),
            b"codex-prompt-history"
        );
    }
}
