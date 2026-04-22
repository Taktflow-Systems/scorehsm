// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Coverage-oriented edge tests for optional/default backend paths and session wrappers.

use std::sync::Arc;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    error::{HsmError, HsmResult},
    ids::{IdsEvent, IdsHook, LoggingIds, NullIds},
    safety::{Clock, KeyStoreChecksum, LibraryState, MockClock, NonceManager, TokenBucketRateLimiter},
    session::HsmSession,
    types::{AesGcmParams, BootStatus, EcdsaSignature, KeyHandle, KeyType},
};
use sha3::{Digest, Sha3_256, Sha3_512};

#[cfg(feature = "mock")]
use scorehsm_host::backend::mock::{MockFaultConfig, MockHardwareBackend};

#[derive(Default)]
struct DefaultOnlyBackend;

impl HsmBackend for DefaultOnlyBackend {
    fn init(&mut self) -> HsmResult<()> {
        Ok(())
    }

    fn deinit(&mut self) -> HsmResult<()> {
        Ok(())
    }

    fn key_generate(&mut self, _key_type: KeyType) -> HsmResult<KeyHandle> {
        Err(HsmError::Unsupported)
    }

    fn key_import(&mut self, _key_type: KeyType, _material: &[u8]) -> HsmResult<KeyHandle> {
        Err(HsmError::Unsupported)
    }

    fn key_delete(&mut self, _handle: KeyHandle) -> HsmResult<()> {
        Err(HsmError::Unsupported)
    }

    fn random(&mut self, _out: &mut [u8]) -> HsmResult<()> {
        Err(HsmError::Unsupported)
    }

    fn sha256(&self, _data: &[u8]) -> HsmResult<[u8; 32]> {
        Err(HsmError::Unsupported)
    }

    fn hmac_sha256(&self, _handle: KeyHandle, _data: &[u8]) -> HsmResult<[u8; 32]> {
        Err(HsmError::Unsupported)
    }

    fn aes_gcm_encrypt(
        &self,
        _handle: KeyHandle,
        _params: &AesGcmParams<'_>,
        _plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        Err(HsmError::Unsupported)
    }

    fn aes_gcm_decrypt(
        &self,
        _handle: KeyHandle,
        _params: &AesGcmParams<'_>,
        _ciphertext: &[u8],
        _tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    fn ecdsa_sign(&self, _handle: KeyHandle, _digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        Err(HsmError::Unsupported)
    }

    fn ecdsa_verify(
        &self,
        _handle: KeyHandle,
        _digest: &[u8; 32],
        _signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        Err(HsmError::Unsupported)
    }

    fn key_derive(
        &mut self,
        _base: KeyHandle,
        _info: &[u8],
        _out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        Err(HsmError::Unsupported)
    }

    fn ecdh_agree(&self, _handle: KeyHandle, _peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        Err(HsmError::Unsupported)
    }
}

struct SinkIds;

impl IdsHook for SinkIds {
    fn on_event(&self, _event: IdsEvent) {}
}

#[test]
fn backend_trait_default_optional_methods_are_stable() {
    let backend = DefaultOnlyBackend;
    let iv16 = [0u8; 16];
    let nonce12 = [0u8; 12];
    let tag16 = [0u8; 16];
    let digest = [0u8; 32];

    assert!(matches!(
        backend.aes_cbc_encrypt(KeyHandle(1), &iv16, &[0u8; 16]),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.aes_cbc_decrypt(KeyHandle(1), &iv16, &[0u8; 16]),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.aes_ccm_encrypt(KeyHandle(1), &nonce12, b"", b"pt", 16),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.aes_ccm_decrypt(KeyHandle(1), &nonce12, b"", b"ciphertext-and-tag", 16),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.chacha20_poly1305_encrypt(KeyHandle(1), &nonce12, b"", b"pt"),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.chacha20_poly1305_decrypt(KeyHandle(1), &nonce12, b"", b"ct", &tag16),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.sha3_256(b"sha3"),
        Err(HsmError::Unsupported)
    ));
    assert!(matches!(
        backend.sha3_512(b"sha3"),
        Err(HsmError::Unsupported)
    ));
    assert_eq!(
        backend.boot_status().unwrap(),
        BootStatus {
            verified: false,
            firmware_version: 0,
        }
    );

    let _ = digest;
}

#[test]
fn session_optional_algorithms_and_configuration_paths_work() {
    let clock = Arc::new(MockClock::new());
    let state = Arc::new(LibraryState::new());
    let rate = Arc::new(TokenBucketRateLimiter::with_defaults(clock.clone()));

    let mut session = HsmSession::new(SoftwareBackend::default())
        .with_clock(clock)
        .with_library_state(state)
        .with_rate_limiter(rate)
        .with_ids_hook(Box::new(SinkIds));
    session.init().unwrap();

    let boot = session.boot_status().unwrap();
    assert!(!boot.verified);
    assert_eq!(boot.firmware_version, 0);

    let aes_key = [0x42u8; 32];
    let aes_handle = session.key_import(KeyType::Aes256, &aes_key).unwrap();

    let cbc_iv = [0x24u8; 16];
    let cbc_plaintext = *b"0123456789ABCDEF";
    let cbc_ciphertext = session
        .aes_cbc_encrypt(aes_handle, &cbc_iv, &cbc_plaintext)
        .unwrap();
    let cbc_roundtrip = session
        .aes_cbc_decrypt(aes_handle, &cbc_iv, &cbc_ciphertext)
        .unwrap();
    assert_eq!(cbc_roundtrip, cbc_plaintext);

    let ccm_nonce = [0x33u8; 13];
    let ccm_ciphertext = session
        .aes_ccm_encrypt(aes_handle, &ccm_nonce, b"aad", b"ccm-plaintext", 16)
        .unwrap();
    let ccm_roundtrip = session
        .aes_ccm_decrypt(aes_handle, &ccm_nonce, b"aad", &ccm_ciphertext, 16)
        .unwrap();
    assert_eq!(ccm_roundtrip, b"ccm-plaintext");

    let chacha_nonce = [0x55u8; 12];
    let (chacha_ciphertext, chacha_tag) = session
        .chacha20_poly1305_encrypt(aes_handle, &chacha_nonce, b"aad", b"chacha")
        .unwrap();
    let chacha_roundtrip = session
        .chacha20_poly1305_decrypt(
            aes_handle,
            &chacha_nonce,
            b"aad",
            &chacha_ciphertext,
            &chacha_tag,
        )
        .unwrap();
    assert_eq!(chacha_roundtrip, b"chacha");

    let expected_sha3_256: [u8; 32] = Sha3_256::digest(b"sha3-256").into();
    let expected_sha3_512: [u8; 64] = Sha3_512::digest(b"sha3-512").into();
    assert_eq!(session.sha3_256(b"sha3-256").unwrap(), expected_sha3_256);
    assert_eq!(session.sha3_512(b"sha3-512").unwrap(), expected_sha3_512);

    let ecc_scalar = [7u8; 32];
    let ecc_handle = session.key_import(KeyType::EccP256, &ecc_scalar).unwrap();
    let peer_secret = p256::SecretKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let peer_point = peer_secret.public_key().to_encoded_point(false);
    let peer_pub: [u8; 64] = peer_point.as_bytes()[1..65].try_into().unwrap();
    let shared = session.ecdh_agree(ecc_handle, &peer_pub).unwrap();
    assert_eq!(shared.len(), 32);
}

#[test]
fn ids_hooks_execute_without_panicking() {
    NullIds.on_event(IdsEvent::UpdateRejected {
        reason: "coverage",
    });
    LoggingIds.on_event(IdsEvent::ActivationRejected {
        reason: "coverage",
    });
}

#[test]
fn default_constructors_produce_usable_state() {
    let clock = MockClock::default();
    let nonce_manager = NonceManager::default();
    let checksum = KeyStoreChecksum::default();

    assert_eq!(clock.now(), clock.now());
    let (counter, iv) = nonce_manager.next_iv(7, b"coverage").unwrap();
    assert_eq!(counter, 1);
    assert_eq!(iv.len(), 12);

    let handles = std::collections::HashSet::new();
    checksum.verify(&handles).unwrap();
}

#[test]
fn aes_ccm_supported_nonce_and_tag_matrix_roundtrip() {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    let handle = backend
        .key_import(KeyType::Aes256, &[0x11u8; 32])
        .unwrap();

    for nonce_len in 7..=13 {
        let nonce = vec![nonce_len as u8; nonce_len];
        for &tag_len in &[4usize, 6, 8, 10, 12, 14, 16] {
            let label = format!("nonce_len={nonce_len}, tag_len={tag_len}");
            let ciphertext = backend
                .aes_ccm_encrypt(handle, &nonce, b"aad", b"matrix-plaintext", tag_len)
                .unwrap_or_else(|e| panic!("{label}: encrypt failed: {e}"));
            let plaintext = backend
                .aes_ccm_decrypt(handle, &nonce, b"aad", &ciphertext, tag_len)
                .unwrap_or_else(|e| panic!("{label}: decrypt failed: {e}"));
            assert_eq!(plaintext, b"matrix-plaintext", "{label}: roundtrip mismatch");
        }
    }
}

#[test]
fn aes_ccm_rejects_invalid_nonce_and_tag_lengths() {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    let handle = backend
        .key_import(KeyType::Aes256, &[0x22u8; 32])
        .unwrap();

    assert!(matches!(
        backend.aes_ccm_encrypt(handle, &[0u8; 6], b"aad", b"pt", 16),
        Err(HsmError::InvalidParam(_))
    ));
    assert!(matches!(
        backend.aes_ccm_encrypt(handle, &[0u8; 13], b"aad", b"pt", 5),
        Err(HsmError::InvalidParam(_))
    ));
    assert!(matches!(
        backend.aes_ccm_decrypt(handle, &[0u8; 13], b"aad", b"tiny", 16),
        Err(HsmError::InvalidParam(_))
    ));
}

#[cfg(feature = "mock")]
#[test]
fn mock_backend_happy_path_exercises_full_trait_surface() {
    let mut backend = MockHardwareBackend::new(MockFaultConfig::default());
    backend.init().unwrap();

    let aes = backend.key_generate(KeyType::Aes256).unwrap();
    let hmac = backend
        .key_import(KeyType::HmacSha256, &[0x44u8; 32])
        .unwrap();
    let ecc = backend.key_generate(KeyType::EccP256).unwrap();

    let mut random = [0u8; 8];
    backend.random(&mut random).unwrap();
    assert_ne!(random, [0u8; 8]);
    assert_eq!(backend.sha256(b"mock-sha").unwrap().len(), 32);
    assert_eq!(backend.hmac_sha256(hmac, b"mock-hmac").unwrap().len(), 32);

    let params = AesGcmParams {
        iv: &[0x5Au8; 12],
        aad: b"mock-aad",
    };
    let (ciphertext, tag) = backend.aes_gcm_encrypt(aes, &params, b"mock-plaintext").unwrap();
    assert_eq!(
        backend
            .aes_gcm_decrypt(aes, &params, &ciphertext, &tag)
            .unwrap(),
        b"mock-plaintext"
    );

    let digest = backend.sha256(b"mock-digest").unwrap();
    let signature = backend.ecdsa_sign(ecc, &digest).unwrap();
    assert!(backend.ecdsa_verify(ecc, &digest, &signature).unwrap());

    let derived = backend
        .key_derive(hmac, b"derive-info", KeyType::HmacSha256)
        .unwrap();
    assert_eq!(backend.hmac_sha256(derived, b"derived").unwrap().len(), 32);

    let peer_pub = [0x77u8; 64];
    assert_eq!(backend.ecdh_agree(ecc, &peer_pub).unwrap().len(), 32);

    let boot = backend.boot_status().unwrap();
    assert!(boot.verified);
    assert_eq!(boot.firmware_version, 1);

    backend.key_delete(aes).unwrap();
    backend.key_delete(hmac).unwrap();
    backend.key_delete(ecc).unwrap();
    backend.key_delete(derived).unwrap();
    backend.deinit().unwrap();
}
