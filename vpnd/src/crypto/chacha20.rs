// vpnd/src/crypto/chacha20.rs
// Real ChaCha20-Poly1305 authenticated encryption using the `chacha20poly1305` crate
// Based on RFC 8439 — the same algorithm used by WireGuard and TLS 1.3

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::Zeroizing;

use super::VpnCipher;

/// ChaCha20-Poly1305 cipher (RFC 8439)
///
/// Nonce: 96-bit (12 bytes) — randomly generated per packet
/// Tag:   128-bit Poly1305 authentication tag
/// Key:   256-bit (32 bytes)
///
/// Preferred over AES-GCM on systems without hardware AES acceleration
/// (e.g. ARM processors, embedded hardware)
pub struct ChaCha20Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Cipher {
    /// Create from a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self> {
        let key: &[u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("ChaCha20-Poly1305 key must be exactly 32 bytes"))?;
        Ok(Self::new(key))
    }

    /// Generate a cryptographically secure random 32-byte key
    pub fn generate_key() -> Zeroizing<[u8; 32]> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(key.as_slice());
        out
    }
}

impl VpnCipher for ChaCha20Cipher {
    /// Encrypt plaintext in-place using ChaCha20-Poly1305.
    /// Returns the 12-byte nonce.
    fn encrypt(&self, plaintext: &mut Vec<u8>, aad: &[u8]) -> Result<[u8; 12]> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

        let encrypted = self
            .cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| anyhow!("ChaCha20-Poly1305 encryption failed"))?;

        *plaintext = encrypted;
        Ok(nonce_bytes)
    }

    /// Decrypt ciphertext in-place, verifying the Poly1305 authentication tag.
    fn decrypt(&self, ciphertext: &mut Vec<u8>, nonce_bytes: [u8; 12], aad: &[u8]) -> Result<()> {
        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypted = self
            .cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| {
                anyhow!("ChaCha20-Poly1305 decryption failed: authentication tag mismatch")
            })?;

        *ciphertext = decrypted;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = ChaCha20Cipher::generate_key();
        let cipher = ChaCha20Cipher::new(&*key);

        let plaintext = b"ChaCha20-Poly1305 test - VPNForge real crypto";
        let aad = b"vpnd-chacha-v1";

        let mut buf = plaintext.to_vec();
        let nonce = cipher.encrypt(&mut buf, aad).unwrap();

        // Encrypted data must not equal plaintext
        assert_ne!(&buf[..plaintext.len().min(buf.len())], plaintext.as_ref());

        cipher.decrypt(&mut buf, nonce, aad).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = ChaCha20Cipher::generate_key();
        let cipher = ChaCha20Cipher::new(&*key);

        let mut buf = b"sensitive payload".to_vec();
        let nonce = cipher.encrypt(&mut buf, b"aad").unwrap();

        buf[2] ^= 0x55; // tamper

        assert!(
            cipher.decrypt(&mut buf, nonce, b"aad").is_err(),
            "Tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = ChaCha20Cipher::generate_key();
        let key2 = ChaCha20Cipher::generate_key();
        let cipher1 = ChaCha20Cipher::new(&*key1);
        let cipher2 = ChaCha20Cipher::new(&*key2);

        let mut buf = b"secret".to_vec();
        let nonce = cipher1.encrypt(&mut buf, b"aad").unwrap();

        assert!(
            cipher2.decrypt(&mut buf, nonce, b"aad").is_err(),
            "Different key must fail decryption"
        );
    }
}
