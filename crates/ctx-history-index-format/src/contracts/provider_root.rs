use ctx_history_capture_model::{
    ProviderRootDefinition, ProviderRootSourceIdentity, SourceRouteIdentity,
    MAX_PROVIDER_ROOT_SELECTOR_BYTES,
};
use serde::{Deserialize, Serialize};

use super::{IndexError, Result};

const MAX_PROVIDER_ROOT_CONNECTOR_PATH_BYTES: usize = 16 * 1024;

/// Immutable automatic-discovery authority retained by a released root.
///
/// The configured definition records the root's current scan path. This
/// binding records the original automatic root used for released identity so
/// later path moves can reconstruct the same connector without reopening the
/// old location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRootConnectorBinding {
    ReleasedV1 { identity_root: std::path::PathBuf },
}

impl ProviderRootConnectorBinding {
    pub fn released_v1(identity_root: impl Into<std::path::PathBuf>) -> Self {
        Self::ReleasedV1 {
            identity_root: identity_root.into(),
        }
    }

    pub fn identity_root(&self) -> &std::path::Path {
        match self {
            Self::ReleasedV1 { identity_root } => identity_root,
        }
    }

    fn validate_contract(&self) -> Result<()> {
        let path = self.identity_root();
        let Some(text) = path.to_str() else {
            return Err(IndexError::InvalidProviderRoots(
                "released connector identity root is not UTF-8".to_owned(),
            ));
        };
        if !path.is_absolute()
            || text.len() > MAX_PROVIDER_ROOT_CONNECTOR_PATH_BYTES
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(IndexError::InvalidProviderRoots(
                "released connector identity root is not a bounded normalized absolute path"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Generation-authoritative expansion of one configured provider home.
///
/// Search resolves the human-facing id and group to exact physical route
/// identities from the same pinned generation. Group and path remain aliases;
/// the stable root id namespaces independently named homes so filesystem moves
/// do not rotate source, session, or event identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedProviderRoot {
    pub(super) definition: ProviderRootDefinition,
    source_identity: ProviderRootSourceIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connector_binding: Option<ProviderRootConnectorBinding>,
    pub(super) routes: Vec<SourceRouteIdentity>,
}

impl AppliedProviderRoot {
    pub fn new(
        definition: ProviderRootDefinition,
        routes: Vec<SourceRouteIdentity>,
    ) -> Result<Self> {
        Self::with_source_identity(definition, ProviderRootSourceIdentity::NamedV1, routes)
    }

    pub fn with_source_identity(
        definition: ProviderRootDefinition,
        source_identity: ProviderRootSourceIdentity,
        routes: Vec<SourceRouteIdentity>,
    ) -> Result<Self> {
        let connector_binding = (source_identity == ProviderRootSourceIdentity::Released)
            .then(|| ProviderRootConnectorBinding::released_v1(definition.path.clone()));
        Self::with_source_identity_and_connector_binding(
            definition,
            source_identity,
            connector_binding,
            routes,
        )
    }

    pub fn with_source_identity_and_connector_binding(
        definition: ProviderRootDefinition,
        source_identity: ProviderRootSourceIdentity,
        connector_binding: Option<ProviderRootConnectorBinding>,
        mut routes: Vec<SourceRouteIdentity>,
    ) -> Result<Self> {
        routes.sort();
        let root = Self {
            definition,
            source_identity,
            connector_binding,
            routes,
        };
        root.validate_contract()?;
        Ok(root)
    }

    pub fn definition(&self) -> &ProviderRootDefinition {
        &self.definition
    }

    pub fn source_identity(&self) -> ProviderRootSourceIdentity {
        self.source_identity
    }

    pub fn connector_binding(&self) -> Option<&ProviderRootConnectorBinding> {
        self.connector_binding.as_ref()
    }

    pub fn routes(&self) -> &[SourceRouteIdentity] {
        &self.routes
    }

    pub(super) fn validate_contract(&self) -> Result<()> {
        validate_provider_root_definition(&self.definition)?;
        match (self.source_identity, &self.connector_binding) {
            (ProviderRootSourceIdentity::Released, Some(binding)) => {
                binding.validate_contract()?;
            }
            (ProviderRootSourceIdentity::Released, None) => {
                return Err(IndexError::InvalidProviderRoots(format!(
                    "released root {} has no connector binding",
                    self.definition.id
                )));
            }
            (ProviderRootSourceIdentity::NamedV1, None) => {}
            (ProviderRootSourceIdentity::NamedV1, Some(_)) => {
                return Err(IndexError::InvalidProviderRoots(format!(
                    "named root {} carries a released connector binding",
                    self.definition.id
                )));
            }
        }
        if self.routes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(IndexError::InvalidProviderRoots(format!(
                "root {} routes are not strictly sorted and unique",
                self.definition.id
            )));
        }
        for route in &self.routes {
            route.validate().map_err(IndexError::from)?;
        }
        Ok(())
    }
}

fn validate_provider_root_definition(root: &ProviderRootDefinition) -> Result<()> {
    let valid_selector = |value: &str| {
        !value.is_empty()
            && value.len() <= MAX_PROVIDER_ROOT_SELECTOR_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    if !valid_selector(&root.id) {
        return Err(IndexError::InvalidProviderRoots(format!(
            "root id {:?} is invalid",
            root.id
        )));
    }
    if !root.has_valid_kind() {
        return Err(IndexError::InvalidProviderRoots(format!(
            "root {} has an invalid provider/kind combination",
            root.id
        )));
    }
    if root
        .group
        .as_deref()
        .is_some_and(|group| !valid_selector(group))
    {
        return Err(IndexError::InvalidProviderRoots(format!(
            "root {} has invalid group",
            root.id
        )));
    }
    if !root.path.is_absolute()
        || root.path.to_str().is_none()
        || root.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(IndexError::InvalidProviderRoots(format!(
            "root {} path is not normalized absolute UTF-8",
            root.id
        )));
    }
    Ok(())
}
