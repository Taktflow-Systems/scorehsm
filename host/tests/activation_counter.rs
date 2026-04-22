// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use scorehsm_host::{
    error::HsmError,
    feature_activation::{
        verify_activation_token_and_update_no_ids, ActivationToken,
    },
};

fn sign_token(feature_id: &str, counter: u64, sk_bytes: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha2::{Digest, Sha256};

    let mut msg = feature_id.as_bytes().to_vec();
    msg.push(0x00);
    msg.extend_from_slice(&counter.to_be_bytes());
    let digest: [u8; 32] = Sha256::digest(&msg).into();
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

const AUTH_SK: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
    0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78,
];

#[test]
fn counter_increments_on_accepted_token() {
    let public_key = pubkey_from_scalar(&AUTH_SK);
    let signature = sign_token("ADAS", 5, &AUTH_SK);
    let token = ActivationToken {
        feature_id: "ADAS",
        counter: 5,
        signature_der: &signature,
    };
    let mut last_counter = 4;

    verify_activation_token_and_update_no_ids(&token, &public_key, &mut last_counter).unwrap();

    assert_eq!(last_counter, 5);
}

#[test]
fn counter_does_not_advance_on_rejected_token() {
    let public_key = pubkey_from_scalar(&AUTH_SK);
    let wrong_signature = sign_token("ADAS", 5, &[0x44u8; 32]);
    let token = ActivationToken {
        feature_id: "ADAS",
        counter: 5,
        signature_der: &wrong_signature,
    };
    let mut last_counter = 4;

    let err =
        verify_activation_token_and_update_no_ids(&token, &public_key, &mut last_counter).unwrap_err();

    assert!(matches!(err, HsmError::CryptoFail(_)));
    assert_eq!(last_counter, 4);
}

#[test]
fn counter_persists_across_simulated_restart() {
    let public_key = pubkey_from_scalar(&AUTH_SK);
    let first_signature = sign_token("ADAS", 5, &AUTH_SK);
    let second_signature = sign_token("ADAS", 6, &AUTH_SK);
    let first_token = ActivationToken {
        feature_id: "ADAS",
        counter: 5,
        signature_der: &first_signature,
    };
    let second_token = ActivationToken {
        feature_id: "ADAS",
        counter: 6,
        signature_der: &second_signature,
    };

    let mut persisted_counter = 4;
    verify_activation_token_and_update_no_ids(&first_token, &public_key, &mut persisted_counter)
        .unwrap();

    let mut reloaded_counter = persisted_counter;
    verify_activation_token_and_update_no_ids(&second_token, &public_key, &mut reloaded_counter)
        .unwrap();

    assert_eq!(persisted_counter, 5);
    assert_eq!(reloaded_counter, 6);
}
