use super::*;
use ctx_history_capture::ProviderRootDefinition;
use ctx_history_index::AppliedProviderRoot;

fn write_crush(path: &Path, index: usize, marker: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "create table sessions (
                id text primary key, parent_session_id text, title text,
                prompt_tokens integer, completion_tokens integer, cost real,
                created_at integer, updated_at integer, summary_message_id text
             );
             create table messages (
                id text primary key, session_id text not null, role text not null,
                parts text not null, created_at integer, updated_at integer,
                provider text, model text, is_summary_message integer not null default 0
             );",
        )
        .unwrap();
    insert_crush(path, index, marker);
}

fn insert_crush(path: &Path, index: usize, marker: &str) {
    let connection = Connection::open(path).unwrap();
    let session = format!("lifecycle-session-{index}");
    connection
        .execute(
            "insert into sessions values (?1, null, 'fixture', 1, 1, 0, 1000, 1000, null)",
            [&session],
        )
        .unwrap();
    connection
        .execute(
            "insert into messages values (?1, ?2, 'assistant', ?3, 1001, 1001, 'fixture', 'model', 0)",
            rusqlite::params![
                format!("lifecycle-message-{index}"),
                session,
                json!([{"type":"text","data":{"text":marker}}]).to_string(),
            ],
        )
        .unwrap();
}

fn write_lingma(path: &Path, index: usize, marker: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(path)
        .unwrap()
        .execute_batch(
            "create table chat_record (
                session_id text not null, request_id text, chat_prompt text not null,
                summary text, error_result text, gmt_create integer, extra text
             );",
        )
        .unwrap();
    insert_lingma(path, index, marker);
}

fn insert_lingma(path: &Path, index: usize, marker: &str) {
    Connection::open(path)
        .unwrap()
        .execute(
            "insert into chat_record values (?1, ?2, ?3, null, null, 1780000000, '{}')",
            rusqlite::params![
                format!("lifecycle-session-{index}"),
                format!("lifecycle-request-{index}"),
                marker,
            ],
        )
        .unwrap();
}

fn fixture(
    root: &Path,
    provider: CaptureProvider,
) -> (DiscoveryContext, Vec<ProviderRootDefinition>, Vec<PathBuf>) {
    let home = root.join("home");
    let cwd = root.join("cwd");
    let config = root.join("config");
    fs::create_dir_all(&cwd).unwrap();
    let paths = match provider {
        CaptureProvider::Crush => {
            let projects = (0..3)
                .map(|index| {
                    let project = root.join(format!("project-{index}"));
                    let data = root.join(format!("crush-data-{index}"));
                    fs::create_dir_all(&project).unwrap();
                    write_crush(
                        &data.join("crush.db"),
                        index,
                        &format!("lifecycleinitial{index}"),
                    );
                    json!({"path": project, "data_dir": data})
                })
                .collect::<Vec<_>>();
            let registry = home.join(".local/share/crush/projects.json");
            fs::create_dir_all(registry.parent().unwrap()).unwrap();
            fs::write(
                registry,
                serde_json::to_vec(&json!({"projects": projects})).unwrap(),
            )
            .unwrap();
            (0..3)
                .map(|index| root.join(format!("crush-data-{index}/crush.db")))
                .collect::<Vec<_>>()
        }
        CaptureProvider::Lingma => {
            let storage = (0..3)
                .map(|index| root.join(format!("lingma-storage-{index}")))
                .collect::<Vec<_>>();
            for (index, storage) in storage.iter().enumerate() {
                write_lingma(
                    &storage.join("sharedClientCache/cache/db/local.db"),
                    index,
                    &format!("lifecycleinitial{index}"),
                );
                let settings = if index == 0 {
                    config.join("Code/User/settings.json")
                } else {
                    config.join(format!("Code/User/profiles/profile-{index}/settings.json"))
                };
                fs::create_dir_all(settings.parent().unwrap()).unwrap();
                fs::write(
                    settings,
                    serde_json::to_vec(&json!({"QoderCN.LocalMachineStoragePath": storage}))
                        .unwrap(),
                )
                .unwrap();
            }
            storage
                .into_iter()
                .map(|path| path.join("sharedClientCache/cache/db/local.db"))
                .collect()
        }
        _ => unreachable!(),
    };
    let roots = paths[..2]
        .iter()
        .enumerate()
        .map(|(index, path)| ProviderRootDefinition {
            id: ["alpha", "beta"][index].to_owned(),
            provider,
            path: path.clone(),
            group: Some(format!("{}-group", ["alpha", "beta"][index])),
            kind: None,
        })
        .collect();
    (
        DiscoveryContext::new(
            &home,
            &cwd,
            DiscoveryPlatform::Linux,
            DiscoveryPlatformDirs {
                config: Some(config),
                ..DiscoveryPlatformDirs::default()
            },
        ),
        roots,
        paths,
    )
}

fn refresh(
    base: &DiscoveryContext,
    provider: CaptureProvider,
    roots: &[ProviderRootDefinition],
    automatic: bool,
    data_root: &Path,
    index_root: &Path,
) {
    let discovery = base
        .clone()
        .with_automatic_provider_discovery(automatic)
        .with_configured_provider_roots(roots.to_vec());
    let report = ctx_history_capture::discover_provider_sources_for_provider_with_context(
        &discovery, provider,
    );
    let mut progress = |_: CaptureSourceBackedDetailedRefreshProgress| Ok(());
    refresh_all_provider_sources(
        &discovery,
        report,
        StdDuration::ZERO,
        data_root,
        index_root,
        None,
        SourceBackedRefreshScope::All,
        &mut progress,
    )
    .unwrap();
}

fn stable_record_bytes(index: &VerifiedIndex, marker: &str) -> (String, Vec<u8>) {
    let hits = index.search_event_candidates(marker, 8).unwrap();
    assert_eq!(hits.len(), 1, "{marker}");
    let hit = &hits[0];
    let record = index
        .core_record_by_id(hit.event.event_id.as_uuid())
        .unwrap()
        .unwrap();
    (
        ctx_history_index::source_token(&hit.event.source),
        serde_json::to_vec(&record).unwrap(),
    )
}

fn assert_root_filter(index: &VerifiedIndex, id: &str, expected: usize) {
    let allowed = index
        .manifest()
        .provider_root_source_tokens(&[id.to_owned()], &[])
        .unwrap();
    let hits = index
        .search_event_candidates_with_filters(
            match id {
                "alpha" => "lifecycleinitial0",
                "beta" => "lifecycleinitial1",
                _ => unreachable!(),
            },
            &EventSearchFilters {
                allowed_source_keys: Some(allowed),
                ..EventSearchFilters::default()
            },
            16,
        )
        .unwrap();
    assert_eq!(hits.len(), expected, "root {id}");
}

fn initial_count(index: &VerifiedIndex) -> usize {
    (0..3)
        .map(|index_value| {
            index
                .search_event_candidates(&format!("lifecycleinitial{index_value}"), 8)
                .unwrap()
                .len()
        })
        .sum()
}

fn certificate_bytes(index: &VerifiedIndex, token: &str) -> Vec<u8> {
    let source = index
        .manifest()
        .sources
        .iter()
        .find(|source| ctx_history_index::source_token(source.observation().source()) == token)
        .unwrap();
    serde_json::to_vec(source).unwrap()
}

#[test]
fn shared_compound_route_survives_warm_policy_moves_absence_and_alias_removal() {
    for provider in [CaptureProvider::Crush, CaptureProvider::Lingma] {
        let temp = tempfile::tempdir().unwrap();
        let fixture_root = fs::canonicalize(temp.path()).unwrap();
        let data_root = fixture_root.join("data");
        let index_root = source_backed_index_root(&data_root);
        ctx_history_platform::platform_security::establish_private_data_root(&data_root).unwrap();
        let (base, mut roots, paths) = fixture(&fixture_root, provider);

        refresh(&base, provider, &roots, true, &data_root, &index_root);
        let initial = VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(initial_count(&initial), 3);
        let initial_alpha = stable_record_bytes(&initial, "lifecycleinitial0");
        let initial_automatic = stable_record_bytes(&initial, "lifecycleinitial2");
        let initial_automatic_certificate = certificate_bytes(&initial, &initial_automatic.0);
        let route = initial.manifest().provider_roots()[0].routes()[0].clone();
        drop(initial);

        match provider {
            CaptureProvider::Crush => {
                insert_crush(&paths[1], 20, "configuredoffrecord");
                insert_crush(&paths[2], 30, "automaticnewrecord");
            }
            CaptureProvider::Lingma => {
                insert_lingma(&paths[1], 20, "configuredoffrecord");
                insert_lingma(&paths[2], 30, "automaticnewrecord");
            }
            _ => unreachable!(),
        }
        refresh(&base, provider, &roots, false, &data_root, &index_root);
        let automatic_off = VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(initial_count(&automatic_off), 3);
        assert_eq!(
            automatic_off
                .search_event_candidates("configuredoffrecord", 8)
                .unwrap()
                .len(),
            1
        );
        assert!(automatic_off
            .search_event_candidates("automaticnewrecord", 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            stable_record_bytes(&automatic_off, "lifecycleinitial2"),
            initial_automatic
        );
        assert_eq!(
            certificate_bytes(&automatic_off, &initial_automatic.0),
            initial_automatic_certificate
        );
        drop(automatic_off);
        refresh(&base, provider, &roots, false, &data_root, &index_root);
        assert!(VerifiedIndex::open(&index_root)
            .unwrap()
            .search_event_candidates("automaticnewrecord", 8)
            .unwrap()
            .is_empty());

        refresh(&base, provider, &roots, true, &data_root, &index_root);
        assert_eq!(
            VerifiedIndex::open(&index_root)
                .unwrap()
                .search_event_candidates("automaticnewrecord", 8)
                .unwrap()
                .len(),
            1
        );

        for step in 1..=2 {
            let moved = fixture_root.join(format!("move-{step}/history.db"));
            fs::create_dir_all(moved.parent().unwrap()).unwrap();
            fs::rename(&roots[0].path, &moved).unwrap();
            roots[0].path = moved;
            refresh(&base, provider, &roots, true, &data_root, &index_root);
            let moved_index = VerifiedIndex::open(&index_root).unwrap();
            assert_eq!(
                moved_index.manifest().provider_roots()[0].routes(),
                &[route.clone()]
            );
            assert_eq!(
                stable_record_bytes(&moved_index, "lifecycleinitial0"),
                initial_alpha
            );
            let encoded = serde_json::to_vec(&moved_index.manifest().provider_roots()[0]).unwrap();
            let restarted: AppliedProviderRoot = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(restarted.exact_source_memberships().len(), 1);
        }

        let absent = fixture_root.join("temporarily-absent.db");
        fs::rename(&roots[0].path, &absent).unwrap();
        match provider {
            CaptureProvider::Crush => insert_crush(&roots[1].path, 40, "remainingpeeradvanced"),
            CaptureProvider::Lingma => insert_lingma(&roots[1].path, 40, "remainingpeeradvanced"),
            _ => unreachable!(),
        }
        refresh(&base, provider, &roots, true, &data_root, &index_root);
        let missing = VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(
            missing
                .search_event_candidates("remainingpeeradvanced", 8)
                .unwrap()
                .len(),
            1
        );
        let alpha = missing
            .manifest()
            .provider_roots()
            .iter()
            .find(|root| root.definition().id == "alpha")
            .unwrap();
        assert_eq!(alpha.routes(), &[route.clone()]);
        assert_eq!(alpha.exact_source_memberships().len(), 1);
        assert_eq!(
            alpha.exact_source_memberships()[0].source_tokens(),
            &[initial_alpha.0.clone()]
        );
        assert_eq!(
            stable_record_bytes(&missing, "lifecycleinitial0"),
            initial_alpha
        );
        assert_root_filter(&missing, "alpha", 1);
        drop(missing);

        fs::rename(&absent, &roots[0].path).unwrap();
        refresh(&base, provider, &roots, true, &data_root, &index_root);
        let reappeared = VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(
            stable_record_bytes(&reappeared, "lifecycleinitial0"),
            initial_alpha
        );
        assert_root_filter(&reappeared, "alpha", 1);
        drop(reappeared);

        match provider {
            CaptureProvider::Crush => {
                insert_crush(&roots[0].path, 50, "removedaliasnewrecord");
                insert_crush(&roots[1].path, 60, "remainingafterremoval");
            }
            CaptureProvider::Lingma => {
                insert_lingma(&roots[0].path, 50, "removedaliasnewrecord");
                insert_lingma(&roots[1].path, 60, "remainingafterremoval");
            }
            _ => unreachable!(),
        }
        refresh(&base, provider, &roots[1..], false, &data_root, &index_root);
        let removed = VerifiedIndex::open(&index_root).unwrap();
        assert_eq!(removed.manifest().provider_roots().len(), 1);
        assert!(matches!(
            removed
                .manifest()
                .provider_root_source_tokens(&["alpha".to_owned()], &[]),
            Err(ctx_history_index::IndexError::UnknownProviderRootSelector(id)) if id == "alpha"
        ));
        assert_eq!(
            removed.manifest().provider_roots()[0].definition().id,
            "beta"
        );
        assert_eq!(removed.manifest().provider_roots()[0].routes(), &[route]);
        assert_root_filter(&removed, "beta", 1);
        assert_eq!(
            stable_record_bytes(&removed, "lifecycleinitial0"),
            initial_alpha
        );
        assert!(removed
            .search_event_candidates("removedaliasnewrecord", 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            removed
                .search_event_candidates("remainingafterremoval", 8)
                .unwrap()
                .len(),
            1
        );
    }
}
