use super::*;
use ctx_history_capture_model::ProviderRootSourceIdentity;
use std::collections::BTreeMap;

fn configured_source(
    mut source: ProviderSource,
    root: &ProviderRootDefinition,
    route_role: &'static str,
) -> ProviderSource {
    source.route_provenance = ProviderSourceRouteProvenance::ConfiguredRoot {
        root_id: root.id.clone(),
        root_path: root.path.clone(),
        route_role: ProviderRouteRole::from_static(route_role),
        automatic_route_role: None,
    };
    source
}

#[test]
fn configured_compound_roots_register_from_arbitrary_paths_without_automatic_authority() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cwd = temp.path().join("cwd");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    let cases = [
        (
            CaptureProvider::Crush,
            "crush_sqlite",
            "crush-project-database",
        ),
        (
            CaptureProvider::Goose,
            "goose_sessions_sqlite",
            "goose-sessions-database",
        ),
        (
            CaptureProvider::AstrBot,
            "astrbot_data_v4_sqlite",
            "astrbot-instance-database",
        ),
        (
            CaptureProvider::Lingma,
            "lingma_sqlite",
            "lingma-client-profile-database",
        ),
        (
            CaptureProvider::Warp,
            "warp_sqlite",
            "warp-surface-database",
        ),
    ];
    let roots = cases
        .iter()
        .map(|(provider, _, _)| ProviderRootDefinition {
            id: format!("configured-{}", provider.as_str()),
            provider: *provider,
            path: temp.path().join(format!("arbitrary-{}", provider.as_str())),
            group: None,
            kind: None,
        })
        .collect::<Vec<_>>();
    let context = DiscoveryContext::new(
        &home,
        &cwd,
        DiscoveryPlatform::Linux,
        DiscoveryPlatformDirs::default(),
    )
    .with_automatic_provider_discovery(false)
    .with_configured_provider_roots(roots.clone());
    let sources = cases
        .iter()
        .zip(&roots)
        .map(|((provider, format, role), root)| {
            configured_source(
                fixture_provider_source_at(
                    *provider,
                    format,
                    ProviderImportSupport::Native,
                    root.path.join("not-selected-by-automatic.sqlite"),
                ),
                root,
                role,
            )
        })
        .collect();
    let build = build_automatic_source_backed_registry_from_report_with_probes_and_retained_roots(
        &test_provider_probes(),
        &context,
        &temp.path().join("ctx-data"),
        DiscoveryReport {
            sources,
            issues: Vec::new(),
        },
        &BTreeMap::new(),
    );

    assert!(build.issues.is_empty(), "{:?}", build.issues);
    assert_eq!(build.executable_route_count(), cases.len());
    assert!(build
        .registry
        .applied_provider_roots()
        .unwrap()
        .2
        .iter()
        .all(|root| root.source_identity() == ProviderRootSourceIdentity::NamedV1));
}

#[test]
fn only_one_noncompound_root_per_provider_owns_the_released_namespace() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let cwd = temp.path().join("cwd");
    let first = temp.path().join("claude-first");
    let second = temp.path().join("claude-second");
    for path in [&home, &cwd, &first, &second] {
        fs::create_dir_all(path).unwrap();
    }
    let roots = [(&first, "first"), (&second, "second")]
        .into_iter()
        .map(|(path, id)| ProviderRootDefinition {
            id: id.to_owned(),
            provider: CaptureProvider::Claude,
            path: path.to_path_buf(),
            group: None,
            kind: None,
        })
        .collect::<Vec<_>>();
    let context = DiscoveryContext::new(
        &home,
        &cwd,
        DiscoveryPlatform::Linux,
        DiscoveryPlatformDirs::default(),
    )
    .with_configured_provider_roots(roots.clone());
    let report = DiscoveryReport {
        sources: roots
            .iter()
            .map(|root| {
                configured_source(
                    provider_sources::provider_source_for_path(
                        CaptureProvider::Claude,
                        root.path.join("projects"),
                    ),
                    root,
                    "claude-projects",
                )
            })
            .collect(),
        issues: Vec::new(),
    };
    let retained = roots
        .iter()
        .map(|root| {
            (
                root.id.clone(),
                AppliedProviderRoot::with_source_identity(
                    root.clone(),
                    ProviderRootSourceIdentity::Released,
                    Vec::new(),
                )
                .unwrap()
                .retained_authority()
                .unwrap(),
            )
        })
        .collect();
    let build = build_automatic_source_backed_registry_from_report_with_probes_and_retained_roots(
        &test_provider_probes(),
        &context,
        &temp.path().join("ctx-data"),
        report,
        &retained,
    );
    let applied = &build.registry.applied_provider_roots().unwrap().2;

    assert_eq!(
        applied
            .iter()
            .filter(|root| root.source_identity() == ProviderRootSourceIdentity::Released)
            .count(),
        1
    );
    assert_eq!(
        applied[0].source_identity(),
        ProviderRootSourceIdentity::Released
    );
    assert_eq!(
        applied[1].source_identity(),
        ProviderRootSourceIdentity::NamedV1
    );
}
