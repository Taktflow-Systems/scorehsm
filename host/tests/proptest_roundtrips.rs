// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use proptest::prelude::*;
use scorehsm_host::{
    feature_activation::{verify_activation_token_no_ids, ActivationToken},
    update::verify_update_image_no_ids,
};

fn sign_image(image: &[u8], sk_bytes: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use sha2::{Digest, Sha256};

    let digest: [u8; 32] = Sha256::digest(image).into();
    let sk = SigningKey::from_bytes(sk_bytes.into()).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    sig.to_der().as_bytes().to_vec()
}

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

const UPDATE_SK: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20u8,
];

const ACTIVATION_SK: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
    0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78,
];

proptest! {
    #[test]
    fn update_sign_verify_roundtrip(image in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let signature = sign_image(&image, &UPDATE_SK);
        let public_key = pubkey_from_scalar(&UPDATE_SK);
        prop_assert!(verify_update_image_no_ids(&image, &signature, &public_key, 1, 0).is_ok());
    }

    #[test]
    fn activation_token_roundtrip(feature_id in "[A-Z_]{1,32}", counter in 1u64..=u64::MAX) {
        let signature = sign_token(&feature_id, counter, &ACTIVATION_SK);
        let public_key = pubkey_from_scalar(&ACTIVATION_SK);
        let token = ActivationToken {
            feature_id: &feature_id,
            counter,
            signature_der: &signature,
        };

        prop_assert!(verify_activation_token_no_ids(&token, &public_key, counter - 1).is_ok());
    }
}
