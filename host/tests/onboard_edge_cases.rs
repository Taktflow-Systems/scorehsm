// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    onboard_comm::{ikev2_derive_keys, macsec_derive_mka_keys},
    types::{KeyHandle, KeyType},
};

fn init_backend() -> SoftwareBackend {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    backend
}

#[test]
fn test_ikev2_nonce_domain_separation() {
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    let mut backend = init_backend();
    let handle = backend.key_generate(KeyType::EccP256).unwrap();

    let peer_sk = SigningKey::random(&mut OsRng);
    let peer_pk = peer_sk.verifying_key().to_encoded_point(false);
    let mut peer_pub = [0u8; 64];
    peer_pub.copy_from_slice(&peer_pk.as_bytes()[1..65]);

    let spi_i = [0x01u8; 8];
    let spi_r = [0x02u8; 8];

    let keys_a = ikev2_derive_keys(
        &backend,
        handle,
        &peer_pub,
        &[0xAAu8; 32],
        &[0xBBu8; 32],
        &spi_i,
        &spi_r,
    )
    .unwrap();
    let keys_b = ikev2_derive_keys(
        &backend,
        handle,
        &peer_pub,
        &[0xCCu8; 32],
        &[0xDDu8; 32],
        &spi_i,
        &spi_r,
    )
    .unwrap();

    assert_ne!(keys_a.sk_d, keys_b.sk_d);
    assert_ne!(keys_a.sk_ei, keys_b.sk_ei);
}

#[test]
fn test_ikev2_ecdh_invalid_handle() {
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    let backend = init_backend();
    let peer_sk = SigningKey::random(&mut OsRng);
    let peer_pk = peer_sk.verifying_key().to_encoded_point(false);
    let mut peer_pub = [0u8; 64];
    peer_pub.copy_from_slice(&peer_pk.as_bytes()[1..65]);

    let result = ikev2_derive_keys(
        &backend,
        KeyHandle(0xDEAD_BEEF),
        &peer_pub,
        &[0xAAu8; 16],
        &[0xBBu8; 16],
        &[0x11u8; 8],
        &[0x22u8; 8],
    );

    assert!(result.is_err(), "invalid ECDH handle must be rejected");
}

#[test]
fn test_macsec_wrong_key_type_rejected() {
    let mut backend = init_backend();
    let aes_handle = backend.key_generate(KeyType::Aes256).unwrap();

    assert!(
        macsec_derive_mka_keys(&backend, aes_handle, b"CAK_NAME").is_err(),
        "MACsec derivation must reject non-HMAC key handles"
    );
}
