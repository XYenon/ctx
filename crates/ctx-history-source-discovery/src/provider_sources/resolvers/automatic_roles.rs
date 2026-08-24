use ctx_history_capture_model::{
    ProviderRouteRole, ProviderRouteRoleError, ProviderSourceRouteProvenance,
};
use sha2::{Digest, Sha256};

const NATIVE_ROLE_ID_DIGEST_DOMAIN: &[u8] = b"ctx.provider-route-native-id.v1\0";

pub(super) const AUTOMATIC_ROUTE_ROLE_UNAVAILABLE_REASON: &str =
    "the provider's stable automatic route role exceeds discovery limits; use an exact --path";

pub(super) fn automatic_route_provenance<I, B>(
    components: I,
) -> Result<ProviderSourceRouteProvenance, ProviderRouteRoleError>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    ProviderRouteRole::from_dynamic(components)
        .map(|route_role| ProviderSourceRouteProvenance::Automatic { route_role })
}

/// Frames a provider-native identifier directly whenever the complete role is
/// bounded and hashes only an identifier that makes that role too large. The
/// marker keeps inline and digest forms in disjoint namespaces, while the
/// fixed digest preserves the source list for valid platform directory names.
pub(super) fn automatic_route_provenance_with_native_id(
    prefix: &[&[u8]],
    native_id: &[u8],
    suffix: &[&[u8]],
) -> Result<ProviderSourceRouteProvenance, ProviderRouteRoleError> {
    let mut components = Vec::with_capacity(prefix.len().saturating_add(suffix.len() + 2));
    components.extend(prefix.iter().map(|component| component.to_vec()));
    components.push(b"native-id".to_vec());
    components.push(native_id.to_vec());
    components.extend(suffix.iter().map(|component| component.to_vec()));
    match automatic_route_provenance(components) {
        Ok(route_provenance) => Ok(route_provenance),
        Err(_) => {
            let mut digest = Sha256::new();
            digest.update(NATIVE_ROLE_ID_DIGEST_DOMAIN);
            digest.update((native_id.len() as u64).to_be_bytes());
            digest.update(native_id);
            let mut components = Vec::with_capacity(prefix.len().saturating_add(suffix.len() + 2));
            components.extend(prefix.iter().map(|component| component.to_vec()));
            components.push(b"native-id-sha256".to_vec());
            components.push(digest.finalize().to_vec());
            components.extend(suffix.iter().map(|component| component.to_vec()));
            automatic_route_provenance(components)
        }
    }
}

#[cfg(test)]
mod tests {
    use ctx_history_capture_model::MAX_PROVIDER_ROUTE_ROLE_BYTES;

    use super::*;

    fn route_role(provenance: &ProviderSourceRouteProvenance) -> &ProviderRouteRole {
        provenance
            .automatic_route_role()
            .expect("test provenance should carry an automatic role")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn automatic_role_bytes_are_exactly_length_framed_and_collision_safe() {
        let role = automatic_route_provenance([b"agent".as_slice(), b"main".as_slice()])
            .expect("bounded role");
        assert_eq!(
            hex(route_role(&role).as_bytes()),
            "0000000000000000056167656e7400000000000000046d61696e"
        );

        let split =
            automatic_route_provenance([b"a".as_slice(), b"bc".as_slice()]).expect("bounded role");
        let joined =
            automatic_route_provenance([b"ab".as_slice(), b"c".as_slice()]).expect("bounded role");
        assert_ne!(route_role(&split), route_role(&joined));
    }

    #[test]
    fn native_ids_are_deterministic_and_oversized_values_remain_bounded() {
        let oversized = vec![b'x'; MAX_PROVIDER_ROUTE_ROLE_BYTES];
        assert!(automatic_route_provenance([oversized.as_slice()]).is_err());

        let first = automatic_route_provenance_with_native_id(
            &[b"installation", b"profile"],
            &oversized,
            &[b"stable"],
        )
        .expect("oversized native id should use its bounded digest form");
        let repeated = automatic_route_provenance_with_native_id(
            &[b"installation", b"profile"],
            &oversized,
            &[b"stable"],
        )
        .expect("same oversized native id should remain valid");
        let distinct = automatic_route_provenance_with_native_id(
            &[b"installation", b"profile"],
            &vec![b'y'; MAX_PROVIDER_ROUTE_ROLE_BYTES],
            &[b"stable"],
        )
        .expect("distinct oversized native id should remain valid");

        assert_eq!(first, repeated);
        assert_ne!(first, distinct);
        assert!(route_role(&first).as_bytes().len() <= MAX_PROVIDER_ROUTE_ROLE_BYTES);
    }
}
