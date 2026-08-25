use std::path::PathBuf;

use ctx_history_core::CaptureProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_CONFIGURED_PROVIDER_ROOTS: usize = 64;
pub const MAX_PROVIDER_ROOT_SELECTOR_BYTES: usize = 64;

/// Exact persisted OpenHands history layout selected by a configured root.
///
/// This is deliberately not a provider-general selector: OpenHands has two
/// incompatible native history layouts whose paths alone do not establish the
/// intended contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderRootKind {
    #[serde(rename = "current-conversations")]
    OpenHandsCurrentConversations,
    #[serde(rename = "legacy-persistence")]
    OpenHandsLegacyPersistence,
}

impl ProviderRootKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenHandsCurrentConversations => "current-conversations",
            Self::OpenHandsLegacyPersistence => "legacy-persistence",
        }
    }
}

impl std::fmt::Display for ProviderRootKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ProviderRootKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "current-conversations" => Ok(Self::OpenHandsCurrentConversations),
            "legacy-persistence" => Ok(Self::OpenHandsLegacyPersistence),
            _ => Err("expected current-conversations or legacy-persistence"),
        }
    }
}

/// Source-identity namespace applied to one configured provider home.
///
/// Released homes retain the identity contract used by automatic discovery
/// before named roots existed. Independently named homes use a logical
/// provider/root-id namespace so duplicate native session IDs remain distinct
/// without tying public identities to a machine-specific filesystem path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRootSourceIdentity {
    Released,
    #[default]
    NamedV1,
}

impl ProviderRootSourceIdentity {
    pub fn lineage(self, root: &ProviderRootDefinition) -> Option<[u8; 32]> {
        match self {
            Self::Released => None,
            Self::NamedV1 => {
                let mut digest = Sha256::new();
                digest.update(b"ctx-provider-root-source-identity-v1\0");
                digest.update(root.provider.as_str().as_bytes());
                digest.update([0]);
                digest.update((root.id.len() as u64).to_be_bytes());
                digest.update(root.id.as_bytes());
                Some(digest.finalize().into())
            }
        }
    }
}

/// Canonical desired/applied identity for one user-named provider home.
///
/// A provider adapter expands the home into physical routes. Human group
/// membership stays here rather than being copied into every Core record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRootDefinition {
    pub id: String,
    pub provider: CaptureProvider,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ProviderRootKind>,
}

impl ProviderRootDefinition {
    /// Validates the narrow provider/kind pairing at every persisted boundary.
    pub const fn has_valid_kind(&self) -> bool {
        match self.provider {
            CaptureProvider::OpenHands => self.kind.is_some(),
            _ => self.kind.is_none(),
        }
    }

    /// OpenHands legacy persistence recursively owns its configured directory.
    /// A current-conversations root nested within it would select the same
    /// history, while disjoint roots remain independently valid.
    pub fn openhands_selected_histories_overlap(&self, other: &Self) -> bool {
        let (legacy, current) = match (self.provider, self.kind, other.provider, other.kind) {
            (
                CaptureProvider::OpenHands,
                Some(ProviderRootKind::OpenHandsLegacyPersistence),
                CaptureProvider::OpenHands,
                Some(ProviderRootKind::OpenHandsCurrentConversations),
            ) => (self, other),
            (
                CaptureProvider::OpenHands,
                Some(ProviderRootKind::OpenHandsCurrentConversations),
                CaptureProvider::OpenHands,
                Some(ProviderRootKind::OpenHandsLegacyPersistence),
            ) => (other, self),
            _ => return false,
        };
        current.path.starts_with(&legacy.path)
    }
}

pub fn provider_source_config_digest(
    automatic_discovery: bool,
    roots: &[ProviderRootDefinition],
) -> String {
    let mut canonical = roots.to_vec();
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    let mut digest = Sha256::new();
    digest.update(b"ctx-provider-source-config-v1\0");
    digest.update([u8::from(automatic_discovery)]);
    match serde_json::to_vec(&canonical) {
        Ok(encoded) => digest.update(encoded),
        Err(_) => {
            // PathBuf's JSON representation rejects non-Unicode paths. Public
            // discovery-context constructors can still receive one before
            // config/manifest validation returns its typed error, so digesting
            // that untrusted definition must remain total and collision-safe.
            digest.update(b"native-path-fallback-v1\0");
            digest.update((canonical.len() as u64).to_be_bytes());
            for root in canonical {
                for value in [root.id.as_bytes(), root.provider.as_str().as_bytes()] {
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
                let path = root.path.as_os_str().as_encoded_bytes();
                digest.update((path.len() as u64).to_be_bytes());
                digest.update(path);
                match root.group {
                    Some(group) => {
                        digest.update([1]);
                        digest.update((group.len() as u64).to_be_bytes());
                        digest.update(group.as_bytes());
                    }
                    None => digest.update([0]),
                }
                match root.kind {
                    Some(kind) => {
                        digest.update([1]);
                        let kind = kind.as_str().as_bytes();
                        digest.update((kind.len() as u64).to_be_bytes());
                        digest.update(kind);
                    }
                    None => digest.update([0]),
                }
            }
        }
    }
    format!("{:x}", digest.finalize())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    use super::*;

    #[test]
    fn digest_is_total_and_distinct_for_non_unicode_public_api_paths() {
        let root = |byte| ProviderRootDefinition {
            id: "fixture".to_owned(),
            provider: CaptureProvider::Claude,
            path: PathBuf::from(OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', byte])),
            group: None,
            kind: None,
        };

        assert_ne!(
            provider_source_config_digest(true, &[root(0xfe)]),
            provider_source_config_digest(true, &[root(0xff)])
        );
        assert_ne!(
            provider_source_config_digest(true, &[root(0xfe)]),
            provider_source_config_digest(false, &[root(0xfe)])
        );
    }

    #[test]
    fn named_source_identity_is_logical_and_path_independent() {
        let mut root = ProviderRootDefinition {
            id: "personal".to_owned(),
            provider: CaptureProvider::Claude,
            path: PathBuf::from("/old/claude"),
            group: None,
            kind: None,
        };
        let original = ProviderRootSourceIdentity::NamedV1.lineage(&root);
        root.path = PathBuf::from("/new/claude");
        assert_eq!(original, ProviderRootSourceIdentity::NamedV1.lineage(&root));
        root.id = "work".to_owned();
        assert_ne!(original, ProviderRootSourceIdentity::NamedV1.lineage(&root));
        assert_eq!(ProviderRootSourceIdentity::Released.lineage(&root), None);
    }

    #[test]
    fn openhands_kind_has_exact_wire_spellings_and_changes_config_digest_only() {
        let mut root = ProviderRootDefinition {
            id: "work".to_owned(),
            provider: CaptureProvider::OpenHands,
            path: PathBuf::from("/history/openhands"),
            group: None,
            kind: Some(ProviderRootKind::OpenHandsCurrentConversations),
        };
        assert_eq!(
            serde_json::to_string(&root).unwrap(),
            r#"{"id":"work","provider":"openhands","path":"/history/openhands","kind":"current-conversations"}"#
        );
        assert_eq!(
            "legacy-persistence".parse(),
            Ok(ProviderRootKind::OpenHandsLegacyPersistence)
        );
        assert!("Current-Conversations".parse::<ProviderRootKind>().is_err());
        let current_digest = provider_source_config_digest(true, std::slice::from_ref(&root));
        let lineage = ProviderRootSourceIdentity::NamedV1.lineage(&root);
        root.kind = Some(ProviderRootKind::OpenHandsLegacyPersistence);
        assert_ne!(
            current_digest,
            provider_source_config_digest(true, std::slice::from_ref(&root))
        );
        assert_eq!(lineage, ProviderRootSourceIdentity::NamedV1.lineage(&root));
    }

    #[test]
    fn old_provider_json_and_digest_remain_byte_compatible() {
        let root = ProviderRootDefinition {
            id: "work".to_owned(),
            provider: CaptureProvider::Claude,
            path: PathBuf::from("/history/claude"),
            group: Some("team".to_owned()),
            kind: None,
        };
        assert_eq!(
            serde_json::to_string(&root).unwrap(),
            r#"{"id":"work","provider":"claude","path":"/history/claude","group":"team"}"#
        );
        assert_eq!(
            provider_source_config_digest(true, std::slice::from_ref(&root)),
            "3ed4b8cc54b28c0c87bde2fb771ee2b60d57fd27c84833b6e245b262f3c24bcd"
        );
    }
}
