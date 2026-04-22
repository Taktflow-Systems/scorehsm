// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use scorehsm_host::{
    error::HsmError,
    ids::{IdsEvent, IdsHook},
    update::verify_update_image,
};
use std::sync::{Arc, Mutex};

fn sign_image(image: &[u8], sk_bytes: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha2::{Digest, Sha256};

    let digest: [u8; 32] = Sha256::digest(image).into();
    let sk = SigningKey::from_bytes(sk_bytes.into()).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    sig.to_der().as_bytes().to_vec()
}

fn pubkey_from_scalar(scalar: &[u8; 32]) -> [u8; 65] {
    use p256::ecdsa::SigningKey;

    let sk = SigningKey::from_bytes(scalar.into()).unwrap();
    let pk = sk.verifying_key().to_encoded_point(false);
    pk.as_bytes().try_into().unwrap()
}

#[derive(Clone, Default)]
struct RecordingIds {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingIds {
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl IdsHook for RecordingIds {
    fn on_event(&self, event: IdsEvent) {
        self.events.lock().unwrap().push(format!("{event:?}"));
    }
}

const TEST_SK: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20u8,
];

#[test]
fn test_update_ids_event_on_rollback() {
    let image = b"firmware_v1";
    let signature = sign_image(image, &TEST_SK);
    let public_key = pubkey_from_scalar(&TEST_SK);
    let ids = RecordingIds::default();

    let err = verify_update_image(image, &signature, &public_key, 1, 2, &ids).unwrap_err();
    assert!(matches!(err, HsmError::InvalidParam(_)));
    assert!(ids
        .events()
        .iter()
        .any(|event| event.contains("UpdateRejected") && event.contains("version rollback")));
}

#[test]
fn test_update_ids_event_on_bad_sig() {
    let image = b"firmware_v2";
    let wrong_sk = [0x55u8; 32];
    let signature = sign_image(image, &wrong_sk);
    let public_key = pubkey_from_scalar(&TEST_SK);
    let ids = RecordingIds::default();

    let err = verify_update_image(image, &signature, &public_key, 2, 1, &ids).unwrap_err();
    assert!(matches!(err, HsmError::CryptoFail(_)));
    assert!(ids
        .events()
        .iter()
        .any(|event| event.contains("UpdateRejected") && event.contains("signature invalid")));
}

#[test]
fn test_update_truncated_signature_rejected() {
    let image = b"firmware_v2";
    let mut signature = sign_image(image, &TEST_SK);
    signature.truncate(signature.len().saturating_sub(5));
    let public_key = pubkey_from_scalar(&TEST_SK);
    let ids = RecordingIds::default();

    let err = verify_update_image(image, &signature, &public_key, 2, 1, &ids).unwrap_err();
    assert!(matches!(err, HsmError::CryptoFail(_)));
    assert!(ids
        .events()
        .iter()
        .any(|event| event.contains("UpdateRejected") && event.contains("signature parse failed")));
}

#[test]
fn test_update_corrupted_der_rejected() {
    let image = b"firmware_v2";
    let mut signature = sign_image(image, &TEST_SK);
    signature[0] ^= 0x7F;
    let public_key = pubkey_from_scalar(&TEST_SK);
    let ids = RecordingIds::default();

    let err = verify_update_image(image, &signature, &public_key, 2, 1, &ids).unwrap_err();
    assert!(matches!(err, HsmError::CryptoFail(_)));
    assert!(ids
        .events()
        .iter()
        .any(|event| event.contains("UpdateRejected") && event.contains("signature parse failed")));
}
