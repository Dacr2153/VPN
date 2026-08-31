// vpnd/src/crypto/profile_seal.rs
// Passphrase-based authenticated encryption for VPN profile secrets.
//
// Algorithm:
//   - KDF:    Argon2id with OWASP 2023 recommended parameters
//             (m_cost = 64 MiB, t_cost = 3, p_cost = 4, output = 32 bytes)
//   - AEAD:   AES-256-GCM (via `ring`, BoringSSL/AWS-LC backend)
//   - Salt:   16 random bytes (per encryption)
//   - Nonce:  12 random bytes (per encryption — never reused)
//   - AAD:    profile name + version tag, binds ciphertext to profile identity
//
// Wire format (single ASCII string, persisted in TOML):
//
//     vpf1$<base64(salt | nonce | ciphertext_with_tag)>
//
// "vpf1" is the format version; future formats will use vpf2$, vpf3$ …
//
// SECURITY NOTES
//   * The plaintext key material is held in `Zeroizing<Vec<u8>>` and wiped
//     on drop. Callers MUST avoid copying the inner bytes into untracked
//     containers (e.g. `String::from_utf8(…)`).
//   * Failed unseal attempts return a generic error. We do not leak whether
//     the failure was due to a wrong passphrase, a corrupted ciphertext or
//     a tampered AAD — all three indicate the same outcome from the
//     attacker's perspective.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use zeroize::Zeroizing;

/// Format version prefix written into TOML files.
pub const SEAL_FORMAT_PREFIX: &str = "vpf1$";

/// Argon2id parameters (OWASP 2023 — interactive login profile).
///
/// Tuned for desktop class hardware: ~250 ms on a modern x86_64 CPU.
/// Profile decryption happens at most once per VPN connection so the
/// latency is acceptable.
const ARGON2_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const KEY_LEN: usize = 32; // AES-256
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Derive a 32-byte symmetric key from `passphrase` and `salt`.
///
/// Returns the key in zeroizing memory so it is wiped from RAM as soon as
/// the caller drops it.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    if salt.len() != SALT_LEN {
        bail!("salt must be {} bytes", SALT_LEN);
    }

    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` with a key derived from `passphrase` and emit the
/// `vpf1$<base64>` envelope.
///
/// `aad` is bound into the AEAD authentication tag — typically the profile
/// name. Tampering with the surrounding TOML (e.g. swapping the sealed blob
/// into a different profile) will cause decryption to fail.
pub fn seal(plaintext: &[u8], passphrase: &[u8], aad: &[u8]) -> Result<String> {
    if plaintext.is_empty() {
        bail!("plaintext must not be empty");
    }

    // Generate fresh salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(passphrase, &salt)?;

    // AES-256-GCM encrypt-in-place
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to construct AES-256-GCM key"))?;
    let key = LessSafeKey::new(unbound);

    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| anyhow!("AES-256-GCM seal failed"))?;

    // Concatenate salt | nonce | ciphertext+tag
    let mut envelope = Vec::with_capacity(SALT_LEN + NONCE_LEN + buf.len());
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&buf);

    Ok(format!("{}{}", SEAL_FORMAT_PREFIX, BASE64.encode(envelope)))
}

/// Decrypt and authenticate a `vpf1$<base64>` envelope.
///
/// On any error (truncated, wrong passphrase, tampered, wrong AAD) returns
/// `Err` without disclosing which specific check failed.
pub fn unseal(envelope: &str, passphrase: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body = envelope
        .strip_prefix(SEAL_FORMAT_PREFIX)
        .ok_or_else(|| anyhow!("unknown sealed-secret format"))?;

    let raw = BASE64
        .decode(body.as_bytes())
        .context("sealed secret is not valid base64")?;

    if raw.len() < SALT_LEN + NONCE_LEN + 16 {
        bail!("sealed secret is truncated");
    }

    let (salt, rest) = raw.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext_with_tag) = rest.split_at(NONCE_LEN);

    let key_bytes = derive_key(passphrase, salt)?;
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to construct AES-256-GCM key"))?;
    let key = LessSafeKey::new(unbound);

    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("invalid nonce length"))?;

    // Copy into mutable buffer for in-place open
    let mut buf = ciphertext_with_tag.to_vec();
    let plaintext_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| anyhow!("authentication failed (wrong passphrase or tampered data)"))?
        .len();
    buf.truncate(plaintext_len);

    Ok(Zeroizing::new(buf))
}

/// Returns true if `s` is a recognised sealed-secret envelope.
pub fn is_sealed(s: &str) -> bool {
    s.starts_with(SEAL_FORMAT_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_succeeds() {
        let pt = b"my-very-secret-WireGuard-private-key";
        let pass = b"correct horse battery staple";
        let aad = b"profile:home-server";

        let env = seal(pt, pass, aad).unwrap();
        assert!(env.starts_with(SEAL_FORMAT_PREFIX));

        let opened = unseal(&env, pass, aad).unwrap();
        assert_eq!(opened.as_slice(), pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let env = seal(b"secret", b"good", b"aad").unwrap();
        assert!(unseal(&env, b"bad", b"aad").is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let env = seal(b"secret", b"pass", b"profile:a").unwrap();
        assert!(unseal(&env, b"pass", b"profile:b").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let env = seal(b"secret", b"pass", b"aad").unwrap();
        // Flip a bit in the base64 body
        let mut bytes = env.into_bytes();
        let last = bytes.len() - 5;
        bytes[last] ^= 0x01;
        let mutated = String::from_utf8(bytes).unwrap();
        assert!(unseal(&mutated, b"pass", b"aad").is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(seal(b"x", b"", b"aad").is_err());
    }

    #[test]
    fn unknown_prefix_rejected() {
        assert!(unseal("vpf99$AAAA", b"pass", b"aad").is_err());
    }

    #[test]
    fn each_seal_uses_fresh_salt_and_nonce() {
        let env1 = seal(b"x", b"pass", b"aad").unwrap();
        let env2 = seal(b"x", b"pass", b"aad").unwrap();
        assert_ne!(env1, env2, "envelopes must differ across calls");
    }
}
