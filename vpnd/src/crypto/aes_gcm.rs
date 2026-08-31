// vpnd/src/crypto/aes_gcm.rs
// Real AES-256-GCM authenticated encryption using the `ring` crate
// ring uses BoringSSL under the hood — FIPS 140-2 validated

use anyhow::{anyhow, Result};
use ring::aead::{Aad, AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use super::VpnCipher;

/// AES-256-GCM cipher backed by ring (BoringSSL)
///
/// Nonce: 96-bit random nonce (NIST SP 800-38D recommendation)
/// Tag:   128-bit authentication tag appended to ciphertext
/// Key:   256-bit key
pub struct AesGcmCipher {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl AesGcmCipher {
    /// Create a new cipher from a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Result<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|e| anyhow!("Failed to create AES-256-GCM key: {:?}", e))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        })
    }

    /// Create from raw key bytes (validates length)
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self> {
        let key: &[u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("AES-256-GCM key must be exactly 32 bytes"))?;
        Self::new(key)
    }

    /// Generate a random 32-byte key
    pub fn generate_key() -> Result<Zeroizing<[u8; 32]>> {
        let rng = SystemRandom::new();
        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill(key.as_mut())
            .map_err(|e| anyhow!("Failed to generate random key: {:?}", e))?;
        Ok(key)
    }
}

impl VpnCipher for AesGcmCipher {
    /// Encrypt plaintext in-place, appending the 16-byte authentication tag.
    /// Returns the 12-byte random nonce that must be sent alongside the ciphertext.
    ///
    /// Wire format: [nonce (12B)] [ciphertext + tag (N+16 B)]
    fn encrypt(&self, plaintext: &mut Vec<u8>, aad: &[u8]) -> Result<[u8; 12]> {
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {:?}", e))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), plaintext)
            .map_err(|e| anyhow!("AES-256-GCM encryption failed: {:?}", e))?;
        Ok(nonce_bytes)
    }

    /// Decrypt ciphertext (with tag) in-place, verifying the authentication tag.
    /// Fails if the tag does not match (tampering detected).
    fn decrypt(&self, ciphertext: &mut Vec<u8>, nonce_bytes: [u8; 12], aad: &[u8]) -> Result<()> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext_len = self
            .key
            .open_in_place(nonce, Aad::from(aad), ciphertext)
            .map_err(|_| anyhow!("AES-256-GCM decryption failed: authentication tag mismatch"))?
            .len();
        ciphertext.truncate(plaintext_len);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let plaintext = b"Hello, VPNForge! This is a real packet.";
        let aad = b"vpnd-v1";

        let mut buf = plaintext.to_vec();
        let nonce = cipher.encrypt(&mut buf, aad).unwrap();

        // After encryption, buf contains ciphertext + tag (not readable)
        let len = plaintext.len().min(buf.len());
        assert_ne!(&buf[..len], plaintext.as_slice());

        cipher.decrypt(&mut buf, nonce, aad).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let mut buf = b"secret data".to_vec();
        let nonce = cipher.encrypt(&mut buf, b"aad").unwrap();

        // Tamper with the ciphertext
        buf[0] ^= 0xFF;

        let result = cipher.decrypt(&mut buf, nonce, b"aad");
        assert!(result.is_err(), "Tampered ciphertext must be rejected");
    }

    #[test]
    fn test_wrong_aad_rejected() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let mut buf = b"secret data".to_vec();
        let nonce = cipher.encrypt(&mut buf, b"correct-aad").unwrap();

        let result = cipher.decrypt(&mut buf, nonce, b"wrong-aad");
        assert!(result.is_err(), "Wrong AAD must be rejected (AEAD protection)");
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let mut buf = b"data".to_vec();
            let nonce = cipher.encrypt(&mut buf, b"aad").unwrap();
            assert!(nonces.insert(nonce), "Nonce collision detected!");
        }
    }

    #[test]
    fn test_empty_plaintext() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let mut buf = vec![];
        let nonce = cipher.encrypt(&mut buf, b"aad").unwrap();
        cipher.decrypt(&mut buf, nonce, b"aad").unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_max_packet_size() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(&*key).unwrap();

        let mut buf = vec![0xABu8; 65535]; // Max IP packet
        let nonce = cipher.encrypt(&mut buf, b"aad").unwrap();
        cipher.decrypt(&mut buf, nonce, b"aad").unwrap();
        assert_eq!(buf.len(), 65535);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }
}
