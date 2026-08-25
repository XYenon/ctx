use super::*;
use ctx_history_capture_model::{
    ProviderRootDefinition, ProviderRootKind, ProviderRootSourceIdentity,
};
use ctx_history_core::CaptureProvider;

#[test]
fn source_route_snapshot_and_generation_wire_contract_remain_stable() {
    let route_identity = SourceRouteIdentity::from_sha256("ab".repeat(32)).unwrap();
    let snapshot = SourceRouteSnapshot::present(route_identity, Vec::new()).unwrap();

    assert_eq!(
        serde_json::to_string(&snapshot).unwrap(),
        format!(
            "{{\"route_identity\":\"{}\",\"sources\":[],\"missing\":null}}",
            "ab".repeat(32)
        )
    );

    let manifest = GenerationManifest::from_parts(Vec::new(), vec![snapshot]).unwrap();
    assert_eq!(
        serde_json::to_string(&manifest).unwrap(),
        "{\"manifest_version\":10,\"identity_version\":1,\"core_record_version\":3,\"core_record_contract_fingerprint\":\"ebb5c9b638de184824a6ce141ebf9b70941fb293fc113d29e2851565bad4371e\",\"lexical_schema_version\":22,\"lexical_analyzer_version\":2,\"policy_schema_hash\":\"98a522ab684f09534a71628117e182f3559d7094880609a74e81041d00361475\",\"indexed_documents\":0,\"certified_source_bytes\":0,\"sources\":[],\"core_record_aggregates\":[],\"source_routes\":[{\"route_identity\":\"abababababababababababababababababababababababababababababababab\",\"sources\":[],\"missing\":null}],\"automatic_provider_discovery\":true,\"provider_root_config_digest\":\"4bfe780cf41a834d4bd7c58d54498cc96b6a5a1d6b20c37f212af31aaa674064\",\"provider_roots\":[]}",
    );
    assert_eq!(
        manifest.generation_id().unwrap(),
        "b609445527280817f04d9c768192bdb546ea009e309eab6dddde6a1f095a49ec"
    );
}

#[test]
fn released_provider_root_retains_immutable_connector_authority_across_moves() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original-hermes-home");
    let moved = ProviderRootDefinition {
        id: "hermes".to_owned(),
        provider: CaptureProvider::Hermes,
        path: temp.path().join("moved-hermes-home"),
        group: None,
        kind: None,
    };
    let applied = AppliedProviderRoot::with_source_identity_and_connector_binding(
        moved.clone(),
        ProviderRootSourceIdentity::Released,
        Some(ProviderRootConnectorBinding::released_rooted_v1(
            original.clone(),
        )),
        Vec::new(),
    )
    .unwrap();
    let manifest = GenerationManifest::from_parts_with_record_aggregates_and_provider_roots(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
        provider_source_config_digest(true, std::slice::from_ref(&moved)),
        vec![applied],
    )
    .unwrap();

    let retained = &manifest.provider_roots()[0];
    assert_eq!(retained.definition().path, moved.path);
    assert_eq!(
        retained
            .connector_binding()
            .unwrap()
            .identity_root()
            .unwrap(),
        original
    );

    let mut moved_again = moved;
    moved_again.path = temp.path().join("moved-again-hermes-home");
    let reconstructed = AppliedProviderRoot::with_retained_authority(
        moved_again.clone(),
        retained.retained_authority().unwrap(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(reconstructed.definition(), &moved_again);
    assert_eq!(
        reconstructed
            .connector_binding()
            .unwrap()
            .identity_root()
            .unwrap(),
        original
    );
}

#[test]
fn provider_root_connector_binding_matches_released_identity_contract() {
    let temp = tempfile::tempdir().unwrap();
    let definition = ProviderRootDefinition {
        id: "codex".to_owned(),
        provider: CaptureProvider::Codex,
        path: temp.path().join("codex-home"),
        group: None,
        kind: None,
    };
    let binding = ProviderRootConnectorBinding::released_path_independent_v1();
    assert_eq!(
        serde_json::to_string(&binding).unwrap(),
        "{\"kind\":\"released_path_independent_v1\"}"
    );
    assert_eq!(
        serde_json::to_string(&ProviderRootConnectorBinding::released_rooted_v1(
            definition.path.clone()
        ))
        .unwrap(),
        format!(
            "{{\"kind\":\"released_rooted_v1\",\"identity_root\":{}}}",
            serde_json::to_string(&definition.path).unwrap()
        )
    );

    assert!(matches!(
        AppliedProviderRoot::with_source_identity_and_connector_binding(
            definition.clone(),
            ProviderRootSourceIdentity::NamedV1,
            Some(binding),
            Vec::new(),
        ),
        Err(IndexError::InvalidProviderRoots(_))
    ));
    assert!(matches!(
        AppliedProviderRoot::with_source_identity_and_connector_binding(
            definition.clone(),
            ProviderRootSourceIdentity::Released,
            None,
            Vec::new(),
        ),
        Err(IndexError::InvalidProviderRoots(_))
    ));
    assert!(matches!(
        AppliedProviderRoot::with_source_identity_and_connector_binding(
            definition.clone(),
            ProviderRootSourceIdentity::Released,
            Some(ProviderRootConnectorBinding::released_rooted_v1(
                temp.path().join("wrong-rooted-codex-home"),
            )),
            Vec::new(),
        ),
        Err(IndexError::InvalidProviderRoots(_))
    ));

    let hermes = ProviderRootDefinition {
        id: "hermes".to_owned(),
        provider: CaptureProvider::Hermes,
        path: temp.path().join("hermes-home"),
        group: None,
        kind: None,
    };
    assert!(matches!(
        AppliedProviderRoot::with_source_identity_and_connector_binding(
            hermes,
            ProviderRootSourceIdentity::Released,
            Some(ProviderRootConnectorBinding::released_rooted_v1(
                "relative-home",
            )),
            Vec::new(),
        ),
        Err(IndexError::InvalidProviderRoots(_))
    ));

    let released = AppliedProviderRoot::with_source_identity(
        definition,
        ProviderRootSourceIdentity::Released,
        Vec::new(),
    )
    .unwrap();
    assert!(released
        .connector_binding()
        .unwrap()
        .identity_root()
        .is_none());
}

#[test]
fn provider_root_aliases_are_bounded_and_generation_local() {
    let temp = tempfile::tempdir().unwrap();
    let route_identity = SourceRouteIdentity::from_sha256("cd".repeat(32)).unwrap();
    let definition = ProviderRootDefinition {
        id: "personal".to_owned(),
        provider: CaptureProvider::Claude,
        path: temp.path().join("claude-personal"),
        group: Some("personal".to_owned()),
        kind: None,
    };
    let manifest = GenerationManifest::from_parts_with_record_aggregates_and_provider_roots(
        Vec::new(),
        Vec::new(),
        vec![SourceRouteSnapshot::present(route_identity.clone(), Vec::new()).unwrap()],
        true,
        provider_source_config_digest(true, std::slice::from_ref(&definition)),
        vec![AppliedProviderRoot::new(definition, vec![route_identity]).unwrap()],
    )
    .unwrap();

    assert_eq!(manifest.provider_roots().len(), 1);
    assert_eq!(
        manifest
            .provider_root_source_tokens(&["personal".to_owned()], &[])
            .unwrap(),
        Vec::<String>::new()
    );
    assert!(matches!(
        manifest.provider_root_source_tokens(&["work".to_owned()], &[]),
        Err(IndexError::UnknownProviderRootSelector(selector)) if selector == "work"
    ));
    assert!(matches!(
        manifest.provider_root_source_tokens(&[], &["work".to_owned()]),
        Err(IndexError::UnknownProviderRootGroup(group)) if group == "work"
    ));
}

#[test]
fn provider_root_manifest_validation_is_provider_generic() {
    let temp = tempfile::tempdir().unwrap();
    let definition = ProviderRootDefinition {
        id: "future-provider".to_owned(),
        provider: CaptureProvider::Cursor,
        path: temp.path().join("cursor-root"),
        group: None,
        kind: None,
    };

    let applied = AppliedProviderRoot::new(definition.clone(), Vec::new()).unwrap();
    assert_eq!(applied.definition(), &definition);
    assert_eq!(
        applied.source_identity(),
        ProviderRootSourceIdentity::NamedV1
    );
}

#[test]
fn provider_root_manifest_validates_openhands_kind_at_the_persisted_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let invalid = ProviderRootDefinition {
        id: "openhands".to_owned(),
        provider: CaptureProvider::OpenHands,
        path: temp.path().join("openhands"),
        group: None,
        kind: None,
    };
    assert!(matches!(
        AppliedProviderRoot::new(invalid, Vec::new()),
        Err(IndexError::InvalidProviderRoots(_))
    ));

    let invalid_old_provider = ProviderRootDefinition {
        id: "claude".to_owned(),
        provider: CaptureProvider::Claude,
        path: temp.path().join("claude"),
        group: None,
        kind: Some(ProviderRootKind::OpenHandsLegacyPersistence),
    };
    assert!(matches!(
        AppliedProviderRoot::new(invalid_old_provider, Vec::new()),
        Err(IndexError::InvalidProviderRoots(_))
    ));
}

#[test]
fn provider_root_manifest_rejects_openhands_ancestor_overlap_at_the_index_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let current = ProviderRootDefinition {
        id: "current".to_owned(),
        provider: CaptureProvider::OpenHands,
        path: temp.path().join("openhands"),
        group: None,
        kind: Some(ProviderRootKind::OpenHandsCurrentConversations),
    };
    let legacy = ProviderRootDefinition {
        id: "legacy".to_owned(),
        provider: CaptureProvider::OpenHands,
        path: current.path.join("legacy-persistence"),
        group: None,
        kind: Some(ProviderRootKind::OpenHandsLegacyPersistence),
    };
    let definitions = vec![current.clone(), legacy.clone()];

    assert!(matches!(
        GenerationManifest::from_parts_with_record_aggregates_and_provider_roots(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            true,
            provider_source_config_digest(true, &definitions),
            vec![
                AppliedProviderRoot::new(current, Vec::new()).unwrap(),
                AppliedProviderRoot::new(legacy, Vec::new()).unwrap(),
            ],
        ),
        Err(IndexError::InvalidProviderRoots(detail)) if detail.contains("overlapping legacy/current")
    ));
}

#[test]
fn provider_root_manifest_prunes_unretained_routes_and_rejects_shared_routes() {
    let temp = tempfile::tempdir().unwrap();
    let route_identity = SourceRouteIdentity::from_sha256("ef".repeat(32)).unwrap();
    let definition = |id: &str| ProviderRootDefinition {
        id: id.to_owned(),
        provider: CaptureProvider::Codex,
        path: temp.path().join(format!("codex-{id}")),
        group: None,
        kind: None,
    };
    let first = definition("first");
    let pruned = GenerationManifest::from_parts_with_record_aggregates_and_provider_roots(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
        provider_source_config_digest(true, std::slice::from_ref(&first)),
        vec![AppliedProviderRoot::new(first, vec![route_identity.clone()]).unwrap()],
    )
    .unwrap();
    assert!(pruned.provider_roots()[0].routes().is_empty());

    let mut persisted = serde_json::to_value(&pruned).unwrap();
    persisted["provider_roots"][0]["routes"] = serde_json::json!([route_identity.as_str()]);
    let dangling: GenerationManifest = serde_json::from_value(persisted).unwrap();
    assert!(matches!(
        dangling.validate_contract(),
        Err(IndexError::ProviderRootRouteNotRetained { .. })
    ));

    let definitions = vec![definition("first"), definition("second")];
    assert!(matches!(
        GenerationManifest::from_parts_with_record_aggregates_and_provider_roots(
            Vec::new(),
            Vec::new(),
            vec![SourceRouteSnapshot::present(route_identity.clone(), Vec::new()).unwrap()],
            true,
            provider_source_config_digest(true, &definitions),
            definitions
                .into_iter()
                .map(|root| AppliedProviderRoot::new(root, vec![route_identity.clone()]).unwrap())
                .collect(),
        ),
        Err(IndexError::SourceRouteOwnedByMultipleProviderRoots { .. })
    ));
}

#[test]
fn malformed_deserialized_route_identity_reaches_complete_manifest_validation() {
    let route_identity = SourceRouteIdentity::from_sha256("ab".repeat(32)).unwrap();
    let manifest = GenerationManifest::from_parts(
        Vec::new(),
        vec![SourceRouteSnapshot::present(route_identity, Vec::new()).unwrap()],
    )
    .unwrap();
    let mut persisted = serde_json::to_value(manifest).unwrap();
    persisted["source_routes"][0]["route_identity"] = serde_json::json!("AB".repeat(32));
    let loaded: GenerationManifest = serde_json::from_value(persisted).unwrap();

    assert!(matches!(
        loaded.validate_contract(),
        Err(IndexError::InvalidSourceRouteIdentity)
    ));
}
