use std::{fs, path::Path};

use ctx_history_capture_model::{ProviderRootDefinition, ProviderRootSourceIdentity};
use rusqlite::Connection;

use super::*;

struct ProviderFixture {
    context: DiscoveryContext,
    root: ProviderRootDefinition,
    marker: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct RouteBytes {
    route: String,
    selection: SourceBackedRouteSelection,
    selector_authority: SourceBackedSelectorAuthority,
    provider: CaptureProvider,
    source_format: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct PublicationBytes {
    sources: Vec<u8>,
    aggregates: Vec<u8>,
    source_routes: Vec<u8>,
    route_controls: Vec<u8>,
    records: Vec<Vec<u8>>,
}

fn copy_fixture(relative: &str, destination: &Path) {
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::copy(
        crate::test_support_paths::capture_repo_root()
            .join("tests/fixtures/provider-history")
            .join(relative),
        destination,
    )
    .unwrap();
}

fn create_hermes_fixture(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(path)
        .unwrap()
        .execute_batch(
            "create table sessions (
                 id text primary key,
                 source text not null,
                 parent_session_id text,
                 started_at real not null,
                 ended_at real,
                 message_count integer default 0,
                 cwd text,
                 git_branch text,
                 git_repo_root text
             );
             create table messages (
                 id integer primary key,
                 session_id text not null,
                 role text not null,
                 content text,
                 timestamp real not null,
                 active integer not null default 1,
                 compacted integer not null default 0
             );
             insert into sessions
                 (id, source, parent_session_id, started_at, message_count, cwd)
                 values ('hermes-equivalence', 'acp', null, 1782259200.0, 1, '/repo');
             insert into messages (id, session_id, role, content, timestamp)
                 values (1, 'hermes-equivalence', 'user',
                         'hermes released equivalence oracle', 1782259201.0);",
        )
        .unwrap();
}

fn provider_fixture(root: &Path, provider: CaptureProvider) -> ProviderFixture {
    let home = root.join("home");
    let cwd = root.join("cwd");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    let mut context = DiscoveryContext::new(
        &home,
        &cwd,
        DiscoveryPlatform::Linux,
        crate::DiscoveryPlatformDirs::default(),
    );
    let (path, marker) = match provider {
        CaptureProvider::OpenClaw => {
            let state = root.join("openclaw-state");
            let sessions = state.join("agents/alpha/sessions");
            fs::create_dir_all(&sessions).unwrap();
            fs::write(
                state.join("openclaw.json"),
                b"{agents:{list:[{id:'alpha'}]}}",
            )
            .unwrap();
            fs::write(
                sessions.join("equivalence.jsonl"),
                concat!(
                    "{\"type\":\"message\",\"id\":\"openclaw-equivalence\",",
                    "\"timestamp\":\"2026-06-24T12:00:00Z\",",
                    "\"message\":{\"role\":\"user\",",
                    "\"content\":\"openclaw released equivalence oracle\"}}\n"
                ),
            )
            .unwrap();
            context = context.with_env("OPENCLAW_STATE_DIR", state.as_os_str());
            (state, "openclaw released equivalence oracle")
        }
        CaptureProvider::Hermes => {
            let database = home.join(".hermes/state.db");
            create_hermes_fixture(&database);
            (database, "hermes released equivalence oracle")
        }
        CaptureProvider::Crush => {
            let database = cwd.join(".crush/crush.db");
            fs::create_dir_all(cwd.join(".git")).unwrap();
            copy_fixture("crush/v1/crush.db", &database);
            (database, "crush sqlite search oracle request")
        }
        CaptureProvider::Goose => {
            let goose_root = root.join("goose-root");
            let database = goose_root.join("data/sessions/sessions.db");
            copy_fixture("goose/v15/sessions.db", &database);
            context = context.with_env("GOOSE_PATH_ROOT", goose_root.as_os_str());
            (database, "goose sqlite search oracle request")
        }
        CaptureProvider::AstrBot => {
            let database = home.join(".astrbot/data/data_v4.db");
            copy_fixture("astrbot/v1/data/data_v4.db", &database);
            (database, "ASTRBOT_ORACLE_USER_TEXT")
        }
        CaptureProvider::Lingma => {
            let database = home.join(".lingma/vscode/sharedClientCache/cache/db/local.db");
            copy_fixture("lingma/v1/local.db", &database);
            (database, "lingma oracle prompt")
        }
        CaptureProvider::Warp => {
            let state = root.join("xdg-state");
            let database = state.join("warp-terminal/warp.sqlite");
            copy_fixture("warp/v1/warp.sqlite", &database);
            context = context.with_env("XDG_STATE_HOME", state.as_os_str());
            (database, "warp sqlite oracle prompt")
        }
        _ => unreachable!("released-root equivalence fixture is provider-scoped"),
    };
    ProviderFixture {
        context,
        root: ProviderRootDefinition {
            id: format!("released-{}", provider.as_str()),
            provider,
            path,
            group: Some("released".to_owned()),
            kind: None,
        },
        marker,
    }
}

fn build_provider_registry(
    context: &DiscoveryContext,
    data_root: &Path,
    provider: CaptureProvider,
) -> SourceBackedAutomaticRegistryBuild {
    let report = ctx_history_source_discovery::discover_provider_sources_for_provider_with_context(
        &crate::test_provider_probes(),
        context,
        provider,
    );
    let build = build_automatic_source_backed_registry_from_parts(
        context,
        data_root,
        report.sources,
        report.issues,
    );
    assert!(build.issues.is_empty(), "{provider}: {:?}", build.issues);
    build
}

fn route_bytes(registry: &SourceBackedProviderRegistry) -> Vec<RouteBytes> {
    let mut routes = registry
        .routes()
        .filter_map(|metadata| {
            Some(RouteBytes {
                route: metadata.route_identity.as_ref()?.as_str().to_owned(),
                selection: metadata.selection?,
                selector_authority: metadata.selector_authority,
                provider: metadata.source.provider,
                source_format: metadata.source.source_format,
            })
        })
        .collect::<Vec<_>>();
    routes.sort_by(|left, right| left.route.cmp(&right.route));
    routes
}

fn publication_bytes(
    index_root: &Path,
    registry: &SourceBackedProviderRegistry,
    marker: &str,
) -> PublicationBytes {
    let receipt = refresh_source_backed_generation(
        index_root,
        registry,
        source_backed_refresh_writer_options(),
    )
    .unwrap();
    assert!(
        receipt.failed_routes.is_empty(),
        "{:?}",
        receipt.failed_routes
    );
    assert!(!receipt.sources.is_empty());
    let manifest = receipt.commit.manifest();
    let sources = serde_json::to_vec(&manifest.sources).unwrap();
    let aggregates = serde_json::to_vec(&manifest.core_record_aggregates).unwrap();
    let source_routes = serde_json::to_vec(manifest.source_routes()).unwrap();
    let route_controls = serde_json::to_vec(&receipt.route_controls).unwrap();
    let index = VerifiedIndex::open(index_root).unwrap();
    let mut records = index
        .search_event_candidates(marker, 32)
        .unwrap()
        .into_iter()
        .filter_map(|candidate| {
            index
                .core_record_by_id(candidate.event.event_id.as_uuid())
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|record| serde_json::to_vec(&record).unwrap())
        .collect::<Vec<_>>();
    records.sort();
    assert!(!records.is_empty(), "no records matched {marker:?}");
    PublicationBytes {
        sources,
        aggregates,
        source_routes,
        route_controls,
        records,
    }
}

#[test]
fn matching_released_roots_reproduce_automatic_authority_and_record_bytes() {
    for provider in [
        CaptureProvider::OpenClaw,
        CaptureProvider::Hermes,
        CaptureProvider::Crush,
        CaptureProvider::Goose,
        CaptureProvider::AstrBot,
        CaptureProvider::Lingma,
        CaptureProvider::Warp,
    ] {
        let temp = tempdir().unwrap();
        let fixture = provider_fixture(temp.path(), provider);
        let automatic = build_provider_registry(
            &fixture.context,
            &temp.path().join("automatic-data"),
            provider,
        );
        assert_eq!(automatic.executable_route_count(), 1, "{provider}");
        let automatic_routes = route_bytes(&automatic.registry);
        let automatic_publication = publication_bytes(
            &temp.path().join("automatic-index"),
            &automatic.registry,
            fixture.marker,
        );

        for automatic_enabled in [true, false] {
            let context = fixture
                .context
                .clone()
                .with_automatic_provider_discovery(automatic_enabled)
                .with_configured_provider_roots(vec![fixture.root.clone()]);
            let configured = build_provider_registry(
                &context,
                &temp
                    .path()
                    .join(format!("configured-data-{automatic_enabled}")),
                provider,
            );
            assert_eq!(configured.executable_route_count(), 1, "{provider}");
            let (_, _, applied) = configured.registry.applied_provider_roots().unwrap();
            assert_eq!(applied.len(), 1, "{provider}");
            assert_eq!(
                applied[0].source_identity(),
                ProviderRootSourceIdentity::Released,
                "{provider} automatic={automatic_enabled}"
            );
            assert_eq!(
                serde_json::to_vec(&applied[0].source_identity()).unwrap(),
                b"\"released\"",
                "{provider} automatic={automatic_enabled}"
            );
            assert_eq!(
                route_bytes(&configured.registry),
                automatic_routes,
                "{provider} automatic={automatic_enabled} route authority"
            );
            assert_eq!(
                publication_bytes(
                    &temp
                        .path()
                        .join(format!("configured-index-{automatic_enabled}")),
                    &configured.registry,
                    fixture.marker,
                ),
                automatic_publication,
                "{provider} automatic={automatic_enabled} source/session/event bytes"
            );
        }
    }
}
