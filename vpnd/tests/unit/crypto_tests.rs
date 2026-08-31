// vpnd/tests/unit/crypto_tests.rs
// Unit tests for VPNForge cryptographic primitives
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
    let mut plaintext = original.to_vec();
    let aad = b"vpnforge-v1";

    let nonce = cipher.encrypt(&mut plaintext, aad).expect("Encryption failed");
    // After encrypt, plaintext contains ciphertext + tag — must differ from original
    assert_ne!(plaintext, original.as_slice());

    // Decrypt in-place
    cipher.decrypt(&mut plaintext, nonce, aad).expect("Decryption failed");
    assert_eq!(plaintext, original.as_slice(), "Decrypted plaintext must equal original");
}

#[test]
fn aes_gcm_rejects_tampered_ciphertext() {
    let key = [0x13u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let mut ciphertext = b"Sensitive VPN data".to_vec();
    let aad = b"hdr";
    let nonce = cipher.encrypt(&mut ciphertext, aad).expect("Encryption failed");

    // Flip a byte in the ciphertext body
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
    // Flip the last byte (authentication tag)
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
    // Use a wrong nonce
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
    // After encryption, the buffer should contain the 16-byte tag at minimum
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
    ct[0] ^= 0xFF; // Tamper
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

    // With random nonces, ciphertexts must differ (IND-CPA)
    assert!(buf1 != buf2 || n1 != n2, "Two encryptions of the same plaintext should differ");
}

// ──────────────────────────────────────────────
// WireGuard key exchange tests
// ──────────────────────────────────────────────

#[test]
fn wg_keypair_generate_distinct_keys() {
    let kp1 = WireGuardKeyPair::generate();
    let kp2 = WireGuardKeyPair::generate();
    assert_ne!(
        kp1.public_key_base64(),
        kp2.public_key_base64(),
        "Each keypair generation must produce a distinct public key"
    );
}

#[test]
fn wg_public_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let pub_b64 = kp.public_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&pub_b64)
        .expect("Public key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 public key must be exactly 32 bytes");
}

#[test]
fn wg_private_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let priv_b64 = kp.private_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&priv_b64)
        .expect("Private key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 private key must be exactly 32 bytes");
}

#[test]
fn wg_dh_agreement_symmetric() {
    // Alice and Bob perform ECDH — shared secrets must match
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();

    let alice_pub = alice.public_key();
    let bob_pub = bob.public_key();

    let alice_shared = alice.dh(&bob_pub);
    let bob_shared = bob.dh(&alice_pub);

    assert_eq!(
        alice_shared, bob_shared,
        "DH shared secrets must be equal (Curve25519 ECDH)"
    );
}

#[test]
fn wg_dh_result_is_32_bytes() {
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();
    let shared = alice.dh(&bob.public_key());
    assert_eq!(shared.len(), 32, "Curve25519 DH result must be 32 bytes");
}

#[test]
fn wg_debug_redacts_private_key() {
    let kp = WireGuardKeyPair::generate();
    let dbg = format!("{:?}", kp);
    // The debug representation must not contain actual private key material
    assert!(
        dbg.contains("[REDACTED]") || !dbg.contains("private"),
        "Debug must redact private key material, got: {}",
        dbg
    );
}

#[test]
fn wg_from_private_key_base64_roundtrip() {
    let original = WireGuardKeyPair::generate();
    let priv_b64 = original.private_key_base64();

    let restored = WireGuardKeyPair::from_private_key_base64(&priv_b64)
        .expect("Should restore keypair from private key base64");

    assert_eq!(
        original.public_key_base64(),
        restored.public_key_base64(),
        "Public key must match after restoring from private key"
    );
}

// ──────────────────────────────────────────────
// System metrics tests (Linux /proc)
// ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod system_metrics {
    use vpnd::metrics::system::{CpuSampler, read_memory, read_load_avg, read_uptime_seconds};

    #[test]
    fn system_memory_is_positive() {
        let (used, total) = read_memory().expect("/proc/meminfo must be readable");
        assert!(total > 0, "Total RAM must be > 0");
        assert!(used >= 0, "Used RAM must be non-negative");
        assert!(used <= total, "Used RAM must not exceed total");
    }

    #[test]
    fn system_load_avg_non_negative() {
        let (one, five) = read_load_avg().expect("/proc/loadavg must be readable");
        assert!(one >= 0.0, "1m load avg must be >= 0");
        assert!(five >= 0.0, "5m load avg must be >= 0");
    }

    #[test]
    fn system_uptime_positive() {
        let uptime = read_uptime_seconds().expect("/proc/uptime must be readable");
        assert!(uptime > 0, "Uptime must be positive");
    }

    #[test]
    fn cpu_sampler_second_call_has_value() {
        let mut s = CpuSampler::new();
        let _ = s.sample(); // Prime (returns None)
        let second = s.sample().expect("Second sample must not error");
        assert!(second.is_some(), "Second CPU sample must return a value");
        let pct = second.unwrap();
        assert!((0.0..=100.0).contains(&pct), "CPU% must be 0-100, got {}", pct);
    }
}


// ──────────────────────────────────────────────
// AES-256-GCM tests
// ──────────────────────────────────────────────

#[test]
fn aes_gcm_roundtrip_plaintext() {
    let key = [0x42u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let plaintext = b"Hello, VPNForge! This is a test packet.";
    let aad = b"vpnforge-v1";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());

    let recovered = cipher
        .decrypt(&ciphertext, aad)
        .expect("Decryption failed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_gcm_rejects_tampered_ciphertext() {
    let key = [0x13u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let plaintext = b"Sensitive VPN data";
    let aad = b"hdr";

    let mut ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    // Flip a byte in the ciphertext (not the tag)
    ciphertext[0] ^= 0xFF;

    let result = cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Decryption should fail on tampered ciphertext");
}

#[test]
fn aes_gcm_rejects_tampered_tag() {
    let key = [0x77u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let plaintext = b"Test data";
    let aad = b"ctx";

    let mut ciphertext = cipher.encrypt(plaintext, aad).expect("Encrypt failed");
    // Flip a byte in the authentication tag (last 16 bytes)
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(
        cipher.decrypt(&ciphertext, aad).is_err(),
        "Decryption should fail on tampered tag"
    );
}

#[test]
fn aes_gcm_rejects_wrong_aad() {
    let key = [0xABu8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let plaintext = b"Payload";
    let aad = b"correct-aad";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encrypt failed");
    assert!(
        cipher.decrypt(&ciphertext, b"wrong-aad").is_err(),
        "Decryption must fail with wrong AAD"
    );
}

#[test]
fn aes_gcm_encrypt_empty_plaintext() {
    let key = [0x00u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let result = cipher.encrypt(b"", b"");
    assert!(result.is_ok(), "Empty plaintext should be encryptable");
    let ct = result.unwrap();
    // Should be at least the 12-byte nonce + 16-byte tag
    assert!(ct.len() >= 28, "Should produce nonce + tag even for empty plaintext");
}

// ──────────────────────────────────────────────
// ChaCha20-Poly1305 tests
// ──────────────────────────────────────────────

#[test]
fn chacha20_roundtrip() {
    let key = [0x9Fu8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create ChaCha20 cipher");

    let plaintext = b"WireGuard uses ChaCha20-Poly1305 for data plane encryption";
    let aad = b"wg-data-v1";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    let recovered = cipher.decrypt(&ciphertext, aad).expect("Decryption failed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn chacha20_rejects_tampered_payload() {
    let key = [0x55u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create cipher");

    let mut ct = cipher.encrypt(b"Secret", b"").expect("Encrypt failed");
    ct[5] ^= 0xFF; // Tamper
    assert!(cipher.decrypt(&ct, b"").is_err(), "Must fail on tampered ciphertext");
}

#[test]
fn chacha20_nonces_differ_between_encryptions() {
    let key = [0x11u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create cipher");

    let pt = b"Same plaintext";
    let ct1 = cipher.encrypt(pt, b"").expect("First encrypt");
    let ct2 = cipher.encrypt(pt, b"").expect("Second encrypt");

    // Different nonces → different ciphertexts (IND-CPA)
    assert_ne!(ct1, ct2, "Two encryptions of the same plaintext must produce different ciphertexts (nonce reuse prevention)");
}

// ──────────────────────────────────────────────
// WireGuard key exchange tests
// ──────────────────────────────────────────────

#[test]
fn wg_keypair_generate_distinct_keys() {
    let kp1 = WireGuardKeyPair::generate();
    let kp2 = WireGuardKeyPair::generate();
    assert_ne!(
        kp1.public_key_base64(),
        kp2.public_key_base64(),
        "Each keypair generation must produce a distinct public key"
    );
}

#[test]
fn wg_public_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let pub_b64 = kp.public_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&pub_b64)
        .expect("Public key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 public key must be exactly 32 bytes");
}

#[test]
fn wg_private_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let priv_b64 = kp.private_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&priv_b64)
        .expect("Private key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 private key must be exactly 32 bytes");
}

#[test]
fn wg_dh_agreement_symmetric() {
    // Alice and Bob perform ECDH — shared secrets must match
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();

    let alice_pub = alice.public_key();
    let bob_pub = bob.public_key();

    let alice_shared = alice.dh(&bob_pub);
    let bob_shared = bob.dh(&alice_pub);

    assert_eq!(
        alice_shared, bob_shared,
        "DH shared secrets must be equal (Curve25519 ECDH)"
    );
}

#[test]
fn wg_dh_result_is_32_bytes() {
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();
    let shared = alice.dh(&bob.public_key());
    assert_eq!(shared.len(), 32, "Curve25519 DH result must be 32 bytes");
}

#[test]
fn wg_debug_redacts_private_key() {
    let kp = WireGuardKeyPair::generate();
    let dbg = format!("{:?}", kp);
    // The debug representation must not contain the raw private key bytes
    assert!(
        !dbg.contains("private_key") || dbg.contains("[REDACTED]"),
        "Debug must redact private key material"
    );
}

#[test]
fn wg_from_private_key_base64_roundtrip() {
    let original = WireGuardKeyPair::generate();
    let priv_b64 = original.private_key_base64();

    let restored = WireGuardKeyPair::from_private_key_base64(&priv_b64)
        .expect("Should restore keypair from private key base64");

    assert_eq!(
        original.public_key_base64(),
        restored.public_key_base64(),
        "Public key must match after restoring from private key"
    );
}

// ──────────────────────────────────────────────
// System metrics tests (Linux /proc)
// ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod system_metrics {
    use vpnd::metrics::system::{CpuSampler, read_memory, read_load_avg, read_uptime_seconds};

    #[test]
    fn system_memory_is_positive() {
        let (used, total) = read_memory().expect("/proc/meminfo must be readable");
        assert!(total > 0, "Total RAM must be > 0");
        assert!(used >= 0, "Used RAM must be non-negative");
        assert!(used <= total, "Used RAM must not exceed total");
    }

    #[test]
    fn system_load_avg_non_negative() {
        let (one, five) = read_load_avg().expect("/proc/loadavg must be readable");
        assert!(one >= 0.0, "1m load avg must be >= 0");
        assert!(five >= 0.0, "5m load avg must be >= 0");
    }

    #[test]
    fn system_uptime_positive() {
        let uptime = read_uptime_seconds().expect("/proc/uptime must be readable");
        assert!(uptime > 0, "Uptime must be positive");
    }

    #[test]
    fn cpu_sampler_second_call_has_value() {
        let mut s = CpuSampler::new();
        let _ = s.sample(); // Prime (returns None)
        let second = s.sample().expect("Second sample must not error");
        assert!(second.is_some(), "Second CPU sample must return a value");
        let pct = second.unwrap();
        assert!((0.0..=100.0).contains(&pct), "CPU% must be 0-100, got {}", pct);
    }
}


// ──────────────────────────────────────────────
// AES-256-GCM tests
// ──────────────────────────────────────────────

#[test]
fn aes_gcm_roundtrip_plaintext() {
    let key = [0x42u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let plaintext = b"Hello, VPNForge! This is a test packet.";
    let aad = b"vpnforge-v1";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());

    let recovered = cipher
        .decrypt(&ciphertext, aad)
        .expect("Decryption failed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_gcm_rejects_tampered_ciphertext() {
    let key = [0x13u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create AES-GCM cipher");

    let plaintext = b"Sensitive VPN data";
    let aad = b"hdr";

    let mut ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    // Flip a byte in the ciphertext (not the tag)
    ciphertext[0] ^= 0xFF;

    let result = cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Decryption should fail on tampered ciphertext");
}

#[test]
fn aes_gcm_rejects_tampered_tag() {
    let key = [0x77u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let plaintext = b"Test data";
    let aad = b"ctx";

    let mut ciphertext = cipher.encrypt(plaintext, aad).expect("Encrypt failed");
    // Flip a byte in the authentication tag (last 16 bytes)
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(
        cipher.decrypt(&ciphertext, aad).is_err(),
        "Decryption should fail on tampered tag"
    );
}

#[test]
fn aes_gcm_rejects_wrong_aad() {
    let key = [0xABu8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let plaintext = b"Payload";
    let aad = b"correct-aad";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encrypt failed");
    assert!(
        cipher.decrypt(&ciphertext, b"wrong-aad").is_err(),
        "Decryption must fail with wrong AAD"
    );
}

#[test]
fn aes_gcm_encrypt_empty_plaintext() {
    let key = [0x00u8; 32];
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher");
    let result = cipher.encrypt(b"", b"");
    assert!(result.is_ok(), "Empty plaintext should be encryptable");
    let ct = result.unwrap();
    // Should be at least the 12-byte nonce + 16-byte tag
    assert!(ct.len() >= 28, "Should produce nonce + tag even for empty plaintext");
}

// ──────────────────────────────────────────────
// ChaCha20-Poly1305 tests
// ──────────────────────────────────────────────

#[test]
fn chacha20_roundtrip() {
    let key = [0x9Fu8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create ChaCha20 cipher");

    let plaintext = b"WireGuard uses ChaCha20-Poly1305 for data plane encryption";
    let aad = b"wg-data-v1";

    let ciphertext = cipher.encrypt(plaintext, aad).expect("Encryption failed");
    let recovered = cipher.decrypt(&ciphertext, aad).expect("Decryption failed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn chacha20_rejects_tampered_payload() {
    let key = [0x55u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create cipher");

    let mut ct = cipher.encrypt(b"Secret", b"").expect("Encrypt failed");
    ct[5] ^= 0xFF; // Tamper
    assert!(cipher.decrypt(&ct, b"").is_err(), "Must fail on tampered ciphertext");
}

#[test]
fn chacha20_nonces_differ_between_encryptions() {
    let key = [0x11u8; 32];
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("Failed to create cipher");

    let pt = b"Same plaintext";
    let ct1 = cipher.encrypt(pt, b"").expect("First encrypt");
    let ct2 = cipher.encrypt(pt, b"").expect("Second encrypt");

    // Different nonces → different ciphertexts (IND-CPA)
    assert_ne!(ct1, ct2, "Two encryptions of the same plaintext must produce different ciphertexts (nonce reuse prevention)");
}

// ──────────────────────────────────────────────
// WireGuard key exchange tests
// ──────────────────────────────────────────────

#[test]
fn wg_keypair_generate_distinct_keys() {
    let kp1 = WireGuardKeyPair::generate();
    let kp2 = WireGuardKeyPair::generate();
    assert_ne!(
        kp1.public_key_base64(),
        kp2.public_key_base64(),
        "Each keypair generation must produce a distinct public key"
    );
}

#[test]
fn wg_public_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let pub_b64 = kp.public_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&pub_b64)
        .expect("Public key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 public key must be exactly 32 bytes");
}

#[test]
fn wg_private_key_is_32_bytes_base64() {
    let kp = WireGuardKeyPair::generate();
    let priv_b64 = kp.private_key_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&priv_b64)
        .expect("Private key should be valid base64");
    assert_eq!(decoded.len(), 32, "Curve25519 private key must be exactly 32 bytes");
}

#[test]
fn wg_dh_agreement_symmetric() {
    // Alice and Bob perform ECDH — shared secrets must match
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();

    let alice_pub = alice.public_key();
    let bob_pub = bob.public_key();

    let alice_shared = alice.dh(&bob_pub);
    let bob_shared = bob.dh(&alice_pub);

    assert_eq!(
        alice_shared, bob_shared,
        "DH shared secrets must be equal (Curve25519 ECDH)"
    );
}

#[test]
fn wg_dh_result_is_32_bytes() {
    let alice = WireGuardKeyPair::generate();
    let bob = WireGuardKeyPair::generate();
    let shared = alice.dh(&bob.public_key());
    assert_eq!(shared.len(), 32, "Curve25519 DH result must be 32 bytes");
}

#[test]
fn wg_debug_redacts_private_key() {
    let kp = WireGuardKeyPair::generate();
    let dbg = format!("{:?}", kp);
    // The debug representation must not contain the raw private key bytes
    assert!(
        !dbg.contains("private_key") || dbg.contains("[REDACTED]"),
        "Debug must redact private key material"
    );
}

#[test]
fn wg_from_private_key_base64_roundtrip() {
    let original = WireGuardKeyPair::generate();
    let priv_b64 = original.private_key_base64();

    let restored = WireGuardKeyPair::from_private_key_base64(&priv_b64)
        .expect("Should restore keypair from private key base64");

    assert_eq!(
        original.public_key_base64(),
        restored.public_key_base64(),
        "Public key must match after restoring from private key"
    );
}

// ──────────────────────────────────────────────
// System metrics tests (Linux /proc)
// ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod system_metrics {
    use vpnd::metrics::system::{CpuSampler, read_memory, read_load_avg, read_uptime_seconds};

    #[test]
    fn system_memory_is_positive() {
        let (used, total) = read_memory().expect("/proc/meminfo must be readable");
        assert!(total > 0, "Total RAM must be > 0");
        assert!(used >= 0, "Used RAM must be non-negative");
        assert!(used <= total, "Used RAM must not exceed total");
    }

    #[test]
    fn system_load_avg_non_negative() {
        let (one, five) = read_load_avg().expect("/proc/loadavg must be readable");
        assert!(one >= 0.0, "1m load avg must be >= 0");
        assert!(five >= 0.0, "5m load avg must be >= 0");
    }

    #[test]
    fn system_uptime_positive() {
        let uptime = read_uptime_seconds().expect("/proc/uptime must be readable");
        assert!(uptime > 0, "Uptime must be positive");
    }

    #[test]
    fn cpu_sampler_second_call_has_value() {
        let mut s = CpuSampler::new();
        let _ = s.sample(); // Prime (returns None)
        let second = s.sample().expect("Second sample must not error");
        assert!(second.is_some(), "Second CPU sample must return a value");
        let pct = second.unwrap();
        assert!((0.0..=100.0).contains(&pct), "CPU% must be 0-100, got {}", pct);
    }
}
