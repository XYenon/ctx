use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use ctx_history_capture::{
    configured_root_capabilities, configured_root_capability, ConfiguredRootPathKind,
    MAX_PROVIDER_ROOT_SELECTOR_BYTES,
};
use ctx_history_core::CaptureProvider;

pub(super) fn validate_provider_root_support(provider: CaptureProvider) -> Result<()> {
    if configured_root_capability(provider).is_some_and(|capability| capability.state.is_enabled())
    {
        return Ok(());
    }
    let mut enabled = configured_root_capabilities()
        .iter()
        .filter(|capability| capability.state.is_enabled())
        .map(|capability| capability.provider.as_str())
        .collect::<Vec<_>>();
    enabled.sort_unstable();
    let enabled = enabled.join(" and ");
    bail!(
        "configured provider homes currently support only {enabled}, not {}",
        provider.as_str()
    )
}

pub(super) fn validate_provider_root_existing_kind(
    provider: CaptureProvider,
    path: &Path,
) -> Result<()> {
    let capability = configured_root_capability(provider)
        .filter(|capability| capability.state.is_enabled())
        .ok_or_else(|| anyhow::anyhow!("configured provider root capability is not enabled"))?;
    let expected = capability
        .state
        .expected_path_kind()
        .ok_or_else(|| anyhow::anyhow!("configured provider root path kind is unavailable"))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect provider home {}", path.display()))?;
    let valid_kind = match expected {
        ConfiguredRootPathKind::Directory => metadata.is_dir(),
        ConfiguredRootPathKind::File => metadata.is_file(),
    };
    if metadata.file_type().is_symlink() || !valid_kind {
        let kind = match expected {
            ConfiguredRootPathKind::Directory => "directory",
            ConfiguredRootPathKind::File => "file",
        };
        bail!(
            "provider home must be an existing non-symlink {kind}: {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn validate_root_selector(kind: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_PROVIDER_ROOT_SELECTOR_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        return Ok(());
    }
    bail!(
        "{kind} `{value}` must be 1..={MAX_PROVIDER_ROOT_SELECTOR_BYTES} ASCII letters, digits, hyphens, or underscores"
    )
}

pub(super) fn validate_provider_root_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.to_str().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!(
            "configured provider home must be a normalized absolute UTF-8 path: {}",
            path.display()
        );
    }
    Ok(())
}
