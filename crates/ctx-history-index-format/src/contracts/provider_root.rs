use ctx_history_capture_model::{
    ProviderRootConnectorBinding, ProviderRootDefinition, ProviderRootSourceIdentity,
    RetainedProviderRootAuthority, SourceRouteIdentity, MAX_PROVIDER_ROOT_SELECTOR_BYTES,
};
use serde::{Deserialize, Serialize};

use super::{is_sha256_hex, IndexError, Result};

const MAX_PROVIDER_ROOT_CONNECTOR_PATH_BYTES: usize = 16 * 1024;

fn validate_connector_binding(binding: &ProviderRootConnectorBinding) -> Result<()> {
    let Some(path) = binding.identity_root() else {
        return Ok(());
    };
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
            "released connector identity root is not a bounded normalized absolute path".to_owned(),
        ));
    }
    Ok(())
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
    exact_source_memberships: Vec<AppliedProviderRootSourceMembership>,
}

/// Exact query membership for one lifecycle-associated provider-root route.
/// A route without an entry uses whole-route membership; an entry may be empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedProviderRootSourceMembership {
    route_identity: SourceRouteIdentity,
    source_tokens: Vec<String>,
}

impl AppliedProviderRootSourceMembership {
    pub fn exact(
        route_identity: SourceRouteIdentity,
        mut source_tokens: Vec<String>,
    ) -> Result<Self> {
        source_tokens.sort();
        let membership = Self {
            route_identity,
            source_tokens,
        };
        membership.validate_contract()?;
        Ok(membership)
    }

    pub fn route_identity(&self) -> &SourceRouteIdentity {
        &self.route_identity
    }

    pub fn source_tokens(&self) -> &[String] {
        &self.source_tokens
    }

    fn validate_contract(&self) -> Result<()> {
        self.route_identity.validate().map_err(IndexError::from)?;
        if self.source_tokens.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(IndexError::InvalidProviderRoots(format!(
                "route {} exact source membership is not strictly sorted and unique",
                self.route_identity.as_str()
            )));
        }
        self.source_tokens.iter().try_for_each(|source| {
            if is_sha256_hex(source) {
                Ok(())
            } else {
                Err(IndexError::InvalidProviderRoots(format!(
                    "route {} exact source membership has an invalid source token",
                    self.route_identity.as_str()
                )))
            }
        })
    }
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
        let connector_binding =
            (source_identity == ProviderRootSourceIdentity::Released).then(|| {
                if released_connector_is_path_independent(definition.provider) {
                    ProviderRootConnectorBinding::released_path_independent_v1()
                } else {
                    ProviderRootConnectorBinding::released_rooted_v1(definition.path.clone())
                }
            });
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
            exact_source_memberships: Vec::new(),
        };
        root.validate_contract()?;
        Ok(root)
    }

    pub fn with_retained_authority(
        definition: ProviderRootDefinition,
        authority: RetainedProviderRootAuthority,
        routes: Vec<SourceRouteIdentity>,
    ) -> Result<Self> {
        Self::with_source_identity_and_connector_binding(
            definition,
            authority.source_identity(),
            authority.connector_binding().cloned(),
            routes,
        )
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

    pub fn retained_authority(&self) -> Result<RetainedProviderRootAuthority> {
        match self.source_identity {
            ProviderRootSourceIdentity::NamedV1 => Ok(RetainedProviderRootAuthority::named_v1()),
            ProviderRootSourceIdentity::Released => self
                .connector_binding
                .clone()
                .map(RetainedProviderRootAuthority::released)
                .ok_or_else(|| {
                    IndexError::InvalidProviderRoots(format!(
                        "released root {} has no connector binding",
                        self.definition.id
                    ))
                }),
        }
    }

    pub fn routes(&self) -> &[SourceRouteIdentity] {
        &self.routes
    }

    pub fn with_exact_source_memberships(
        mut self,
        mut exact_source_memberships: Vec<AppliedProviderRootSourceMembership>,
    ) -> Result<Self> {
        exact_source_memberships
            .sort_by(|left, right| left.route_identity.cmp(&right.route_identity));
        self.exact_source_memberships = exact_source_memberships;
        self.validate_contract()?;
        Ok(self)
    }

    pub fn exact_source_memberships(&self) -> &[AppliedProviderRootSourceMembership] {
        &self.exact_source_memberships
    }

    pub fn exact_source_tokens_for_route(&self, route: &SourceRouteIdentity) -> Option<&[String]> {
        self.exact_source_memberships
            .binary_search_by(|membership| membership.route_identity.cmp(route))
            .ok()
            .and_then(|index| self.exact_source_memberships.get(index))
            .map(AppliedProviderRootSourceMembership::source_tokens)
    }

    pub(super) fn validate_contract(&self) -> Result<()> {
        validate_provider_root_definition(&self.definition)?;
        match (self.source_identity, &self.connector_binding) {
            (ProviderRootSourceIdentity::Released, Some(binding)) => {
                validate_connector_binding(binding)?;
                if released_connector_is_path_independent(self.definition.provider)
                    != binding.identity_root().is_none()
                {
                    return Err(IndexError::InvalidProviderRoots(format!(
                        "released root {} carries the wrong connector binding kind",
                        self.definition.id
                    )));
                }
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
        if self
            .exact_source_memberships
            .windows(2)
            .any(|pair| pair[0].route_identity >= pair[1].route_identity)
        {
            return Err(IndexError::InvalidProviderRoots(format!(
                "root {} exact source memberships are not strictly sorted and unique",
                self.definition.id
            )));
        }
        for membership in &self.exact_source_memberships {
            membership.validate_contract()?;
            if self
                .routes
                .binary_search(&membership.route_identity)
                .is_err()
            {
                return Err(IndexError::InvalidProviderRoots(format!(
                    "root {} has exact source membership for an unassociated route",
                    self.definition.id
                )));
            }
        }
        Ok(())
    }
}

const fn released_connector_is_path_independent(
    provider: ctx_history_core::CaptureProvider,
) -> bool {
    matches!(
        provider,
        ctx_history_core::CaptureProvider::Codex | ctx_history_core::CaptureProvider::Claude
    )
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
