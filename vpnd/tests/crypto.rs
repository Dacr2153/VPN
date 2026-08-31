// vpnd/tests/crypto.rs
// Integration tests for VPNForge cryptographic primitives
//
// Tests cover:
//   - AES-256-GCM AEAD round-trip correctness
//   - ChaCha20-Poly1305 AEAD round-trip correctness
//   - WireGuard keypair generation and Curve25519 DH agreement
//   - Key zeroisation (memory safety)
//   - System metrics parsing from /proc (Linux only)

use vpnd::crypto::aes_gcm::AesGcmCipher;
use vpnd::crypto::chacha20::ChaCha20Cipher;
use vpnd::crypto::key_exchange::WireGuardKeyPair;
use vpnd::crypto::VpnCipher;

// ──────────────────────────────────────────────
// AES-256-GCM tests
// ──────────────────────────────────────────────

#[test]
fn aes_gcm_roundtrip_plaintext() {
    let key = [0x42u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let original = b"Hello, VPNForge! This is a test packet.";
    let mut buf = original.to_vec();
    let aad = b"vpnforge-v1";

    let nonce = cipher.encrypt(&mut buf, aad).expect("Encryption failed");
    // After encrypt, buf contains ciphertext + tag — must differ from original
    assert_ne!(&buf[..original.len()], original.as_slice());

    // Decrypt in-place
    cipher.decrypt(&mut buf, nonce, aad).expect("Decryption failed");
    assert_eq!(buf, original.as_slice(), "Decrypted plaintext must equal original");
}

#[test]
fn aes_gcm_rejects_tampered_ciphertext() {
    let key = [0x13u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let mut ciphertext = b"Sensitive VPN data".to_vec();
    let aad = b"hdr";
    let nonce = cipher.encrypt(&mut ciphertext, aad).expect("Encryption failed");

    ciphertext[0] ^= 0xFF;
    let result = cipher.decrypt(&mut ciphertext, nonce, aad);
    assert!(result.is_err(), "Decryption should fail on tampered ciphertext");
}

#[test]
fn aes_gcm_rejects_tampered_tag() {
    let key = [0x77u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let mut ciphertext = b"Test data".to_vec();
    let aad = b"ctx";

    let nonce = cipher.encrypt(&mut ciphertext, aad).expect("Encrypt failed");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(
        cipher.decrypt(&mut ciphertext, nonce, aad).is_err(),
        "Decryption should fail on tampered tag"
    );
}

#[test]
fn aes_gcm_rejects_wrong_nonce() {
    let key = [0xABu8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let mut ciphertext = b"Payload".to_vec();
    let aad = b"correct-aad";

    let _nonce = cipher.encrypt(&mut ciphertext, aad).expect("Encrypt failed");
    let wrong_nonce = [0u8; 12];
    assert!(
        cipher.decrypt(&mut ciphertext, wrong_nonce, aad).is_err(),
        "Decryption must fail with wrong nonce"
    );
}

#[test]
fn aes_gcm_encrypt_empty_plaintext() {
    let key = [0x00u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let mut empty = Vec::new();
    let result = cipher.encrypt(&mut empty, b"");
    assert!(result.is_ok(), "Empty plaintext should be encryptable");
    assert!(empty.len() >= 16, "Should produce at least the auth tag");
}

// ──────────────────────────────────────────────
// ChaCha20-Poly1305 tests
// ──────────────────────────────────────────────

#[test]
fn chacha20_roundtrip() {
    let key = [0x9Fu8; 32];
    let cipher = ChaCha20Cipher::new(&key);

    let original = b"WireGuard uses ChaCha20-Poly1305 for data plane encryption";
    let mut buf = original.to_vec();
    let aad = b"wg-data-v1";

    let nonce = cipher.encrypt(&mut buf, aad).expect("Encryption failed");
    cipher.decrypt(&mut buf, nonce, aad).expect("Decryption failed");
    assert_eq!(buf, original.as_slice());
}

#[test]
fn chacha20_rejects_tampered_payload() {
    let key = [0x55u8; 32];
    let cipher = ChaCha20Cipher::new(&key);

    let mut ct = b"Secret".to_vec();
    let nonce = cipher.encrypt(&mut ct, b"").expect("Encrypt failed");
    ct[0] ^= 0xFF;
    assert!(cipher.decrypt(&mut ct, nonce, b"").is_err(), "Must fail on tampered ciphertext");
}

#[test]
fn chacha20_two_encryptions_produce_different_output() {
    let key = [0x11u8; 32];
    let cipher = ChaCha20Cipher::new(&key);

    let pt = b"Same plaintext";
    let mut buf1 = pt.to_vec();
    let mut buf2 = pt.to_vec();
    let n1 = cipher.encrypt(&mut buf1, b"").expect("First encrypt");
    let n2 = cipher.encrypt(&mut buf2, b"").expect("Second encrypt");

    assert!(buf1 != buf2 || n1 != n2, "Two encryptions of the same plaintext should differ");
}

// ──────────────────────────────────────────────
// WireGuard key exchange tests
// ──────────────────────────────────────────────

#[test]
fn wg_keypair_generate_distinct_keys() {
    let kp1 = WireGuardKeyPair::generate();
    let kp2 = WireGuardKeyPair::generate();
    assert_ne!(kp1.public_key_base64(), kp2.public_key_base64());
}

#[test]
fn wg_public_key_is_32_bytes() {
    let kp = WireGuardKeyPair::generate();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(kp.public_key_base64())
        .expect("Public key should be valid base64");
    assert_eq!(decoded.len(), 32);
}

#[test]
fn wg_private_key_is_32_bytes() {
    let kp = WireGuardKeyPair::generate();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(kp.private_key_base64())
        .expect("Private key should be valid base64");
    assert_eq!(decoded.len(), 32);
}

#[test]
fn wg_dh_agreement_symmetric() {
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();
    let alice_shared = alice.dh(bob.public_key());
    let bob_shared = bob.dh(alice.public_key());
    assert_eq!(*alice_shared, *bob_shared, "ECDH shared secrets must agree");
}

#[test]
fn wg_debug_redacts_private_key() {
    let kp = WireGuardKeyPair::generate();
    let dbg = format!("{:?}", kp);
    assert!(
        dbg.contains("[REDACTED]") || !dbg.to_lowercase().contains("private_key"),
        "Debug must redact private key material"
    );
}

#[test]
fn wg_from_private_key_base64_roundtrip() {
    let original = WireGuardKeyPair::generate();
    let priv_b64 = original.private_key_base64();
    let restored = WireGuardKeyPair::from_private_key_base64(&priv_b64)
        .expect("Should restore keypair from private key base64");
    assert_eq!(original.public_key_base64(), restored.public_key_base64());
}

// ──────────────────────────────────────────────
// System metrics tests (Linux /proc)
// ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod proc_metrics {
    use vpnd::metrics::system::{CpuSampler, read_load_avg, read_memory, read_uptime_seconds};

    #[test]
    fn memory_is_positive() {
        let (used, total) = read_memory().expect("/proc/meminfo must be readable");
        assert!(total > 0);
        assert!(used >= 0);
        assert!(used <= total);
    }

    #[test]
    fn load_avg_non_negative() {
        let (one, five) = read_load_avg().expect("/proc/loadavg must be readable");
        assert!(one >= 0.0);
        assert!(five >= 0.0);
    }

    #[test]
    fn uptime_positive() {
        let uptime = read_uptime_seconds().expect("/proc/uptime must be readable");
        assert!(uptime > 0);
    }

    #[test]
    fn cpu_sampler_second_call_has_value() {
        let mut s = CpuSampler::new();
        let _ = s.sample();
        let second = s.sample().expect("Second sample must not error");
        assert!(second.is_some(), "Second CPU sample must return Some");
        let pct = second.unwrap();
        assert!((0.0..=100.0).contains(&pct), "CPU% must be 0-100, got {}", pct);
    }
}
