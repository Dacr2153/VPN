// vpnd/src/crypto/mod.rs

pub mod aes_gcm;
pub mod chacha20;
pub mod key_exchange;
pub mod profile_seal;
pub mod profile_signing;

pub use aes_gcm::AesGcmCipher;
pub use chacha20::ChaCha20Cipher;
pub use key_exchange::{generate_wg_keypair, WireGuardKeyPair};

/// Unified cipher interface
pub trait VpnCipher: Send + Sync {
    fn encrypt(&self, plaintext: &mut Vec<u8>, aad: &[u8]) -> anyhow::Result<[u8; 12]>;
    fn decrypt(
        &self,
        ciphertext: &mut Vec<u8>,
        nonce: [u8; 12],
        aad: &[u8],
    ) -> anyhow::Result<()>;
    fn name(&self) -> &'static str;
}
