use anon_core::IdentityKeys;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct DiscoveryKey(Zeroizing<[u8; 32]>);

impl DiscoveryKey {
    pub fn for_identity(identity: &IdentityKeys) -> Self {
        let seed = identity.to_escrow_seed();
        let mut secret = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, seed.as_ref())
            .expand(b"anon/discovery/v1", secret.as_mut())
            .expect("valid HKDF output length");
        Self(secret)
    }

    pub fn public_key(&self) -> String {
        let secret = x25519_dalek::StaticSecret::from(*self.0);
        let public = x25519_dalek::PublicKey::from(&secret);
        format!(
            "descriptor:x25519:{}",
            data_encoding::BASE32_NOPAD.encode(public.as_bytes())
        )
    }

    #[cfg(feature = "arti")]
    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn validate_public_key(key: &str) -> bool {
        let Some(encoded) = key.strip_prefix("descriptor:x25519:") else {
            return false;
        };
        let Ok(bytes) = data_encoding::BASE32_NOPAD.decode(encoded.to_ascii_uppercase().as_bytes())
        else {
            return false;
        };
        let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
            return false;
        };
        let probe = x25519_dalek::StaticSecret::from([42u8; 32]);
        probe
            .diffie_hellman(&x25519_dalek::PublicKey::from(bytes))
            .was_contributory()
    }
}

impl std::fmt::Debug for DiscoveryKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DiscoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_keys_are_stable_separate_and_validated() {
        let alice = IdentityKeys::from_seed(&[1; 32]);
        let bob = IdentityKeys::from_seed(&[2; 32]);
        let key = DiscoveryKey::for_identity(&alice);
        assert_eq!(
            key.public_key(),
            DiscoveryKey::for_identity(&alice).public_key()
        );
        assert_ne!(
            key.public_key(),
            DiscoveryKey::for_identity(&bob).public_key()
        );
        assert!(DiscoveryKey::validate_public_key(&key.public_key()));
        assert!(!DiscoveryKey::validate_public_key("invalid"));
        assert!(!DiscoveryKey::validate_public_key(&format!(
            "descriptor:x25519:{}",
            data_encoding::BASE32_NOPAD.encode(&[0; 32])
        )));
        assert_eq!(format!("{key:?}"), "DiscoveryKey(<redacted>)");
    }
}
