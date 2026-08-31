//! Profile signing using **Ed25519 (RFC 8032)** via `ring`.
//!
//! Why this matters
//! ----------------
//! Profile files (`*.toml`) live in `/etc/vpnforge/profiles/` and contain the
//! WireGuard public-key, peer endpoint, allowed IPs and DNS settings of a
//! VPN connection.  An attacker with **write** access to that directory could
//! replace the peer endpoint, redirecting the user's traffic to a malicious
//! server while keeping the same on-disk file name.
//!
//! Profile signing closes that gap: every saved profile is signed with a
//! daemon-local Ed25519 keypair.  When the daemon loads a profile it
//! verifies the signature and refuses to use it if the signature is missing
//! or invalid (when `require_signed_profiles = true`, the default).
//!
//! Wire format
//! -----------
//! The signature is appended to the TOML body as a **comment** so the file
//! still parses as valid TOML:
//!
//! ```toml
//! name = "home"
//! protocol = "wireguard"
//! …
//! # vpnforge-signature: alg=ed25519 sig=<base64>
//! ```
//!
//! The signed payload is the **whole TOML body up to (but not including)
//! the signature comment line**, byte-for-byte.  This means the file can
//! be edited cosmetically (re-indented, sorted keys) **only by re-signing**,
//! which is exactly the property we want.
//!
//! Cryptographic choices
//! ---------------------
//!   * Ed25519 — fast, deterministic, no nonce-reuse foot-guns.
//!   * `ring` — FIPS-leaning crypto used elsewhere in this daemon; avoids
//!     adding `ed25519-dalek` which has incompatible curve25519-dalek
//!     version requirements vs. `boringtun`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use tracing::info;

/// Marker that introduces the trailing signature line.
///
/// Anything that begins with this string on a fresh line is treated as a
/// signature footer.  Using a comment keeps the rest of the body valid TOML.
const SIG_PREFIX: &str = "# vpnforge-signature:";

const SIG_ALGO: &str = "ed25519";

// ────────────────────────────────────────────────────────────────────────────
// Key persistence
// ────────────────────────────────────────────────────────────────────────────

/// Load (or generate-and-persist) the daemon's Ed25519 signing keypair.
///
/// On first call the function generates a fresh keypair, writes the PKCS#8
/// representation to `key_path` with mode `0600`, and returns it.  On all
/// subsequent calls it loads the existing key.
///
/// The parent directory is created with mode `0700` if it does not exist.
pub fn load_or_generate_keypair(key_path: &Path) -> Result<Ed25519KeyPair> {
    if key_path.exists() {
        let pkcs8 = std::fs::read(key_path)
            .with_context(|| format!("failed to read signing key {}", key_path.display()))?;
        return Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|e| anyhow!("invalid PKCS8 in signing key file: {}", e));
    }

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| anyhow!("Ed25519 key generation failed: {}", e))?;
    let pkcs8_bytes = pkcs8.as_ref();

    // Write atomically with mode 0600.
    let tmp = key_path.with_extension("key.tmp");
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true).truncate(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        f.write_all(pkcs8_bytes)
            .context("failed to write signing key")?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, key_path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), key_path.display()))?;

    info!(path = %key_path.display(), "generated new Ed25519 profile-signing keypair");

    Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
        .map_err(|e| anyhow!("freshly generated PKCS8 was rejected: {}", e))
}

/// Default location for the daemon's signing key.
pub fn default_key_path() -> PathBuf {
    PathBuf::from("/var/lib/vpnforge/signing.key")
}

// ────────────────────────────────────────────────────────────────────────────
// Signing / verification
// ────────────────────────────────────────────────────────────────────────────

/// Append a signature footer to `body`.
///
/// `body` should *not* already contain a signature line; the function
/// strips any existing one before re-signing so the operation is idempotent.
pub fn sign_profile(body: &str, keypair: &Ed25519KeyPair) -> String {
    let stripped = strip_signature(body);
    let sig = keypair.sign(stripped.as_bytes());
    let sig_b64 = B64.encode(sig.as_ref());
    let mut out = String::with_capacity(stripped.len() + 80);
    out.push_str(stripped);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(SIG_PREFIX);
    out.push_str(" alg=");
    out.push_str(SIG_ALGO);
    out.push_str(" sig=");
    out.push_str(&sig_b64);
    out.push('\n');
    out
}

/// Verify the signature embedded in `body` against `public_key` (the raw
/// 32-byte Ed25519 public key).
///
/// Returns `Ok(())` on success, `Err` if:
///   - no signature line is present
///   - the algorithm tag is not `ed25519`
///   - the base64 is malformed
///   - the signature does not validate
pub fn verify_profile(body: &str, public_key: &[u8]) -> Result<()> {
    let footer = extract_signature(body)
        .ok_or_else(|| anyhow!("profile is not signed (no '{}' line found)", SIG_PREFIX))?;
    if footer.alg != SIG_ALGO {
        bail!("unsupported signature algorithm '{}'", footer.alg);
    }
    let sig_bytes = B64
        .decode(&footer.sig)
        .context("malformed base64 in profile signature")?;
    let body_signed = strip_signature(body);
    let key = UnparsedPublicKey::new(&ED25519, public_key);
    key.verify(body_signed.as_bytes(), &sig_bytes)
        .map_err(|_| anyhow!("profile signature verification failed"))
}

/// True if `body` already carries a valid signature footer line.
pub fn has_signature(body: &str) -> bool {
    extract_signature(body).is_some()
}

/// Return `body` with the trailing signature line (if any) removed.
fn strip_signature(body: &str) -> &str {
    if let Some((idx, _line)) = find_signature_line(body) {
        &body[..idx]
    } else {
        body
    }
}

#[derive(Debug)]
struct SigFooter {
    alg: String,
    sig: String,
}

fn extract_signature(body: &str) -> Option<SigFooter> {
    let (_, line) = find_signature_line(body)?;
    let payload = line.trim_start_matches(SIG_PREFIX).trim();
    let mut alg = None::<String>;
    let mut sig = None::<String>;
    for kv in payload.split_ascii_whitespace() {
        if let Some(v) = kv.strip_prefix("alg=") {
            alg = Some(v.to_string());
        } else if let Some(v) = kv.strip_prefix("sig=") {
            sig = Some(v.to_string());
        }
    }
    Some(SigFooter {
        alg: alg?,
        sig: sig?,
    })
}

/// Return `(byte_index, line_text)` of the *last* signature line in body, if any.
fn find_signature_line(body: &str) -> Option<(usize, &str)> {
    // Iterate lines with their byte offsets so we can slice precisely.
    let mut last: Option<(usize, &str)> = None;
    let mut idx = 0usize;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']).trim_start();
        if trimmed.starts_with(SIG_PREFIX) {
            last = Some((idx, line));
        }
        idx += line.len();
    }
    last
}

// ────────────────────────────────────────────────────────────────────────────
// Public-key helpers
// ────────────────────────────────────────────────────────────────────────────

/// Return the raw 32-byte Ed25519 public key derived from `keypair`.
pub fn public_key_bytes(keypair: &Ed25519KeyPair) -> Vec<u8> {
    keypair.public_key().as_ref().to_vec()
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    const SAMPLE: &str = r#"name = "home"
protocol = "wireguard"
server_host = "vpn.example.com"
server_port = 51820
"#;

    #[test]
    fn sign_then_verify_roundtrip() {
        let kp = fresh_keypair();
        let pk = public_key_bytes(&kp);
        let signed = sign_profile(SAMPLE, &kp);
        assert!(has_signature(&signed));
        verify_profile(&signed, &pk).unwrap();
    }

    #[test]
    fn unsigned_body_is_rejected() {
        let kp = fresh_keypair();
        let pk = public_key_bytes(&kp);
        let err = verify_profile(SAMPLE, &pk).unwrap_err();
        assert!(format!("{}", err).contains("not signed"));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let kp = fresh_keypair();
        let pk = public_key_bytes(&kp);
        let signed = sign_profile(SAMPLE, &kp);
        // Modify the body before the signature footer
        let tampered = signed.replace("vpn.example.com", "evil.attacker.net");
        let err = verify_profile(&tampered, &pk).unwrap_err();
        assert!(format!("{}", err).contains("verification failed"));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let kp = fresh_keypair();
        let pk = public_key_bytes(&kp);
        let signed = sign_profile(SAMPLE, &kp);
        // Flip a base64 character in the signature
        let tampered = signed.replace("sig=", "sig=AAAA");
        verify_profile(&tampered, &pk).unwrap_err();
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let kp1 = fresh_keypair();
        let kp2 = fresh_keypair();
        let signed = sign_profile(SAMPLE, &kp1);
        verify_profile(&signed, &public_key_bytes(&kp2)).unwrap_err();
    }

    #[test]
    fn re_signing_replaces_old_signature() {
        let kp1 = fresh_keypair();
        let kp2 = fresh_keypair();
        let signed1 = sign_profile(SAMPLE, &kp1);
        // Signing again with kp2 should produce a body verifiable with kp2 only.
        let signed2 = sign_profile(&signed1, &kp2);
        verify_profile(&signed2, &public_key_bytes(&kp2)).unwrap();
        assert!(verify_profile(&signed2, &public_key_bytes(&kp1)).is_err());
    }

    #[test]
    fn alien_algorithm_is_rejected() {
        let signed = format!(
            "{}\n# vpnforge-signature: alg=rsa sig=AAAA\n",
            SAMPLE
        );
        let err = verify_profile(&signed, &[0u8; 32]).unwrap_err();
        assert!(format!("{}", err).contains("unsupported"));
    }

    #[test]
    fn key_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        let kp1 = load_or_generate_keypair(&path).unwrap();
        let pk1 = public_key_bytes(&kp1);
        // Second call should load — same public key
        let kp2 = load_or_generate_keypair(&path).unwrap();
        assert_eq!(pk1, public_key_bytes(&kp2));
    }
}
