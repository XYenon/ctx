use super::*;

#[test]
fn moving_a_named_claude_home_preserves_route_and_source_identity() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = fs::canonicalize(temp.path()).unwrap();
    let data_root = fixture.join("data");
    let index_root = source_backed_index_root(&data_root);
    ctx_history_platform::platform_security::establish_private_data_root(&data_root).unwrap();
    let (_, _, discovery) = discovery_fixture(&fixture);
    let first_home = fixture.join("claude-work-old");
    let first_projects = first_home.join("projects");
    let session = first_projects.join("project/session.jsonl");
    fs::create_dir_all(session.parent().unwrap()).unwrap();
    fs::write(
        &session,
        format!(
            "{}\n",
            json!({
                "type": "user",
                "uuid": "moved-message",
                "sessionId": "019fb700-0000-7000-8000-000000000715",
                "message": {"role": "user", "content": "moved claude"}
            })
        ),
    )
    .unwrap();
    let definition = |path| ctx_history_capture::ProviderRootDefinition {
        id: "work".to_owned(),
        provider: CaptureProvider::Claude,
        path,
        group: Some("work".to_owned()),
        kind: None,
    };
    let first_discovery = discovery
        .clone()
        .with_automatic_provider_discovery(false)
        .with_configured_provider_roots(vec![definition(first_home.clone())]);
    let mut progress = |_: CaptureSourceBackedDetailedRefreshProgress| Ok(());
    refresh_all_provider_sources(
        &first_discovery,
        DiscoveryReport {
            sources: vec![configured_provider_source_for_path(
                CaptureProvider::Claude,
                first_projects,
                "work",
                first_home.clone(),
                "claude-projects",
            )],
            issues: Vec::new(),
        },
        StdDuration::ZERO,
        &data_root,
        &index_root,
        None,
        SourceBackedRefreshScope::All,
        &mut progress,
    )
    .unwrap();
    let first = VerifiedIndex::open(&index_root).unwrap();
    let first_route = first.manifest().provider_roots()[0].routes()[0].clone();
    let first_source = first.manifest().sources[0].observation().source().clone();
    drop(first);

    let second_home = fixture.join("claude-work-new");
    fs::rename(&first_home, &second_home).unwrap();
    let second_projects = second_home.join("projects");
    let second_discovery = discovery
        .with_automatic_provider_discovery(false)
        .with_configured_provider_roots(vec![definition(second_home.clone())]);
    let mut progress = |_: CaptureSourceBackedDetailedRefreshProgress| Ok(());
    refresh_all_provider_sources(
        &second_discovery,
        DiscoveryReport {
            sources: vec![configured_provider_source_for_path(
                CaptureProvider::Claude,
                second_projects,
                "work",
                second_home.clone(),
                "claude-projects",
            )],
            issues: Vec::new(),
        },
        StdDuration::ZERO,
        &data_root,
        &index_root,
        None,
        SourceBackedRefreshScope::All,
        &mut progress,
    )
    .unwrap();

    let moved = VerifiedIndex::open(&index_root).unwrap();
    assert_eq!(moved.manifest().source_routes().len(), 1);
    assert_eq!(
        moved.manifest().provider_roots()[0].routes(),
        &[first_route]
    );
    assert_eq!(
        moved.manifest().provider_roots()[0].definition().path,
        second_home
    );
    assert_eq!(
        moved.manifest().provider_roots()[0].source_identity(),
        ProviderRootSourceIdentity::NamedV1
    );
    assert!(moved.manifest().sources[0]
        .observation()
        .source()
        .exact_descriptor_eq(&first_source));
}

#[test]
fn moving_a_named_codex_home_preserves_route_and_source_identity() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = fs::canonicalize(temp.path()).unwrap();
    let data_root = fixture.join("data");
    let index_root = source_backed_index_root(&data_root);
    ctx_history_platform::platform_security::establish_private_data_root(&data_root).unwrap();
    let (_, _, discovery) = discovery_fixture(&fixture);
    let first_home = fixture.join("codex-work-old");
    let first_sessions = first_home.join("sessions");
    let session = first_sessions.join("rollout.jsonl");
    fs::create_dir_all(&first_sessions).unwrap();
    fs::write(
        &session,
        format!(
            "{}\n{}\n",
            json!({
                "timestamp": "2026-08-17T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": "019fb700-0000-7000-8000-000000000716",
                    "timestamp": "2026-08-17T00:00:00Z",
                    "cwd": "/repo/moved-codex",
                    "originator": "codex_cli_rs",
                    "cli_version": "1.0.0",
                    "source": "cli",
                    "model_provider": "openai"
                }
            }),
            json!({
                "timestamp": "2026-08-17T00:00:01Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "moved codex"}]
                }
            })
        ),
    )
    .unwrap();
    let definition = |path| ctx_history_capture::ProviderRootDefinition {
        id: "work".to_owned(),
        provider: CaptureProvider::Codex,
        path,
        group: Some("work".to_owned()),
        kind: None,
    };
    let first_discovery = discovery
        .clone()
        .with_automatic_provider_discovery(false)
        .with_configured_provider_roots(vec![definition(first_home.clone())]);
    let mut progress = |_: CaptureSourceBackedDetailedRefreshProgress| Ok(());
    refresh_all_provider_sources(
        &first_discovery,
        DiscoveryReport {
            sources: vec![configured_provider_source_for_path(
                CaptureProvider::Codex,
                first_sessions,
                "work",
                first_home.clone(),
                "codex-sessions",
            )],
            issues: Vec::new(),
        },
        StdDuration::ZERO,
        &data_root,
        &index_root,
        None,
        SourceBackedRefreshScope::All,
        &mut progress,
    )
    .unwrap();
    let first = VerifiedIndex::open(&index_root).unwrap();
    let first_route = first.manifest().provider_roots()[0].routes()[0].clone();
    let first_source = first.manifest().sources[0].observation().source().clone();
    drop(first);

    let second_home = fixture.join("codex-work-new");
    fs::rename(&first_home, &second_home).unwrap();
    let second_sessions = second_home.join("sessions");
    let second_discovery = discovery
        .with_automatic_provider_discovery(false)
        .with_configured_provider_roots(vec![definition(second_home.clone())]);
    let mut progress = |_: CaptureSourceBackedDetailedRefreshProgress| Ok(());
    refresh_all_provider_sources(
        &second_discovery,
        DiscoveryReport {
            sources: vec![configured_provider_source_for_path(
                CaptureProvider::Codex,
                second_sessions,
                "work",
                second_home.clone(),
                "codex-sessions",
            )],
            issues: Vec::new(),
        },
        StdDuration::ZERO,
        &data_root,
        &index_root,
        None,
        SourceBackedRefreshScope::All,
        &mut progress,
    )
    .unwrap();

    let moved = VerifiedIndex::open(&index_root).unwrap();
    assert_eq!(moved.manifest().source_routes().len(), 1);
    assert_eq!(
        moved.manifest().provider_roots()[0].routes(),
        &[first_route]
    );
    assert_eq!(
        moved.manifest().provider_roots()[0].definition().path,
        second_home
    );
    assert!(moved.manifest().sources[0]
        .observation()
        .source()
        .exact_descriptor_eq(&first_source));
}
