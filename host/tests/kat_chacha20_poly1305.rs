// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! ChaCha20-Poly1305 KATs from RFC 8439 and the upstream crate corpus.

use aead::dev::blobby::Blob6Iterator;
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    safety::NonceManager,
    types::KeyType,
};

fn import_chacha_key(backend: &mut SoftwareBackend, key: &[u8]) -> scorehsm_host::types::KeyHandle {
    backend
        .key_import(KeyType::Aes256, key)
        .expect("ChaCha20-Poly1305 test key import must succeed")
}

#[test]
fn kat_chacha20_poly1305_rfc_8439_section_2_8_2() {
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ct = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
        0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
        0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
        0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
        0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
        0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    let expected_tag = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91,
    ];

    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    let handle = import_chacha_key(&mut backend, &key);

    let (actual_ct, actual_tag) = backend
        .chacha20_poly1305_encrypt(handle, &nonce, &aad, plaintext)
        .expect("RFC 8439 encrypt must succeed");
    assert_eq!(actual_ct, expected_ct);
    assert_eq!(actual_tag, expected_tag);

    let actual_pt = backend
        .chacha20_poly1305_decrypt(handle, &nonce, &aad, &expected_ct, &expected_tag)
        .expect("RFC 8439 decrypt must succeed");
    assert_eq!(actual_pt, plaintext);

    backend.key_delete(handle).unwrap();
    backend.deinit().unwrap();
}

#[test]
fn kat_chacha20_poly1305_wycheproof_subset() {
    // Source: chacha20poly1305 crate test corpus, commit 746f70a5f6c7371e723dc64e04f2115b56f24d27.
    let data = include_bytes!("vectors/chacha20_poly1305/wycheproof_chacha20poly1305.blb");
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();

    let mut pass_vectors = 0usize;

    for row in Blob6Iterator::new(data).expect("invalid wycheproof blob") {
        let [key, nonce, aad, pt, ct_and_tag, status] = row.expect("invalid wycheproof row");
        if status[0] != 1 {
            continue;
        }

        let nonce = <[u8; 12]>::try_from(nonce).expect("wycheproof nonce must be 12 bytes");
        let split = ct_and_tag.len() - 16;
        let expected_ct = &ct_and_tag[..split];
        let expected_tag = <[u8; 16]>::try_from(&ct_and_tag[split..]).unwrap();
        let handle = import_chacha_key(&mut backend, key);

        let (actual_ct, actual_tag) = backend
            .chacha20_poly1305_encrypt(handle, &nonce, aad, pt)
            .expect("wycheproof encrypt must succeed");
        assert_eq!(actual_ct, expected_ct, "wycheproof ciphertext mismatch");
        assert_eq!(actual_tag, expected_tag, "wycheproof tag mismatch");

        let actual_pt = backend
            .chacha20_poly1305_decrypt(handle, &nonce, aad, expected_ct, &expected_tag)
            .expect("wycheproof decrypt must succeed");
        assert_eq!(actual_pt, pt, "wycheproof plaintext mismatch");

        backend.key_delete(handle).unwrap();
        pass_vectors += 1;
        if pass_vectors == 5 {
            break;
        }
    }

    backend.deinit().unwrap();
    assert_eq!(pass_vectors, 5, "expected 5 passing wycheproof vectors");
}

#[test]
fn nonce_manager_never_reuses_chacha20_poly1305_nonce_for_same_key() {
    let manager = NonceManager::new();
    let (_, nonce1) = manager.next_iv(42, b"chacha20-poly1305").unwrap();
    let (_, nonce2) = manager.next_iv(42, b"chacha20-poly1305").unwrap();

    assert_ne!(
        nonce1, nonce2,
        "NonceManager must not reuse a ChaCha20-Poly1305 nonce for the same key"
    );
}
