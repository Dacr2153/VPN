// vpnd/src/crypto/key_exchange.rs
// Curve25519 ECDH key exchange for WireGuard
// Uses x25519-dalek — the same library as the official WireGuard implementation

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A WireGuard keypair (Curve25519)
#[derive(Clone)]
pub struct WireGuardKeyPair {
    /// 32-byte private key — kept in zeroizing memory
    private: Zeroizing<[u8; 32]>,
    /// 32-byte public key — derived from private via Curve25519
    public: [u8; 32],
}

impl WireGuardKeyPair {
    /// Generate a new random WireGuard keypair using OS entropy
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: *public.as_bytes(),
        }
    }

    /// Load from a base64-encoded private key (as used in wg conf files)
    pub fn from_private_key_base64(b64: &str) -> Result<Self> {
        let bytes = BASE64
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("Invalid base64 private key: {}", e))?;

        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("WireGuard private key must be 32 bytes"))?;

        let secret = StaticSecret::from(arr);
        let public = PublicKey::from(&secret);

        Ok(Self {
            private: Zeroizing::new(secret.to_bytes()),
            public: *public.as_bytes(),
        })
    }

    /// Return the private key bytes (zeroized on drop)
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private
    }

    /// Return the public key bytes
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// Base64-encoded private key (for config files)
    pub fn private_key_base64(&self) -> String {
        BASE64.encode(*self.private)
    }

    /// Base64-encoded public key (for sharing with peers)
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public)
    }

    /// Perform ECDH with a peer's public key, returns the shared secret.
    /// Used in the WireGuard handshake initiation to derive session keys.
    pub fn dh(&self, peer_public_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let secret = StaticSecret::from(*self.private);
        let peer_pub = PublicKey::from(*peer_public_key);
        let shared = secret.diffie_hellman(&peer_pub);
        Zeroizing::new(*shared.as_bytes())
    }
}

impl std::fmt::Debug for WireGuardKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardKeyPair")
            .field("public_key", &self.public_key_base64())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Generate a new WireGuard keypair (convenience function)
pub fn generate_wg_keypair() -> WireGuardKeyPair {
    WireGuardKeyPair::generate()
}

/// Decode a base64 WireGuard public key into 32 bytes
pub fn decode_wg_public_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| anyhow::anyhow!("Invalid base64 public key: {}", e))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard public key must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = WireGuardKeyPair::generate();
        assert_ne!(*kp.private_key(), [0u8; 32], "Private key must not be all zeros");
        assert_ne!(*kp.public_key(), [0u8; 32], "Public key must not be all zeros");
        // Private ≠ public (trivial but catches generation bugs)
        assert_ne!(kp.private_key(), kp.public_key());
    }

    #[test]
    fn test_dh_commutative() {
        // If Alice and Bob exchange public keys, they derive the same shared secret
        let alice = WireGuardKeyPair::generate();
        let bob = WireGuardKeyPair::generate();

        let alice_shared = alice.dh(bob.public_key());
        let bob_shared = bob.dh(alice.public_key());

        assert_eq!(*alice_shared, *bob_shared, "DH shared secrets must match");
    }

    #[test]
    fn test_base64_roundtrip() {
        let kp = WireGuardKeyPair::generate();
        let b64 = kp.private_key_base64();

        let kp2 = WireGuardKeyPair::from_private_key_base64(&b64).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn test_different_keypairs_different_shared_secrets() {
        let alice = WireGuardKeyPair::generate();
        let bob1 = WireGuardKeyPair::generate();
        let bob2 = WireGuardKeyPair::generate();

        let shared1 = alice.dh(bob1.public_key());
        let shared2 = alice.dh(bob2.public_key());

        assert_ne!(*shared1, *shared2, "Different peers must produce different shared secrets");
    }
}
