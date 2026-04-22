// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! NIST AES-256-CCM known-answer tests (SP 800-38C DVPT256).

mod common;

use std::path::PathBuf;

use common::{field, hex_field, load_rsp, RspCase};
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    error::HsmError,
    types::KeyType,
};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("aes_ccm")
        .join(name)
}

fn section_value(case: &RspCase, name: &str) -> usize {
    case.section
        .as_deref()
        .expect("DVPT256 section must exist")
        .split(',')
        .map(str::trim)
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key.trim() == name {
                Some(value.trim().parse::<usize>().expect("invalid DVPT256 number"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing `{name}` in DVPT256 section {:?}", case.section))
}

fn bytes_or_empty(case: &RspCase, field_name: &str, expected_len: usize) -> Vec<u8> {
    if expected_len == 0 {
        Vec::new()
    } else {
        let bytes = hex_field(case, field_name);
        assert_eq!(
            bytes.len(),
            expected_len,
            "unexpected length for {field_name} in COUNT={}",
            field(case, "COUNT")
        );
        bytes
    }
}

#[test]
fn kat_aes_ccm_dvpt256() {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();

    let mut pass_cases = 0usize;
    let mut fail_cases = 0usize;

    for case in load_rsp(vector_path("DVPT256.rsp")) {
        let nonce_len = section_value(&case, "Nlen");
        let tag_len = section_value(&case, "Tlen");
        let aad_len = section_value(&case, "Alen");
        let payload_len = section_value(&case, "Plen");

        let key = hex_field(&case, "Key");
        let nonce = bytes_or_empty(&case, "Nonce", nonce_len);
        let aad = bytes_or_empty(&case, "Adata", aad_len);
        let ciphertext = hex_field(&case, "CT");
        let handle = backend.key_import(KeyType::Aes256, &key).unwrap();

        match field(&case, "Result") {
            "Pass" => {
                pass_cases += 1;
                let payload = bytes_or_empty(&case, "Payload", payload_len);
                let actual_ct = backend
                    .aes_ccm_encrypt(handle, &nonce, &aad, &payload, tag_len)
                    .expect("AES-CCM encrypt must succeed for passing vectors");
                assert_eq!(
                    actual_ct, ciphertext,
                    "AES-CCM encrypt mismatch in Count={}",
                    field(&case, "Count")
                );

                let actual_pt = backend
                    .aes_ccm_decrypt(handle, &nonce, &aad, &ciphertext, tag_len)
                    .expect("AES-CCM decrypt must succeed for passing vectors");
                assert_eq!(
                    actual_pt, payload,
                    "AES-CCM decrypt mismatch in Count={}",
                    field(&case, "Count")
                );
            }
            "Fail" => {
                fail_cases += 1;
                let err = backend
                    .aes_ccm_decrypt(handle, &nonce, &aad, &ciphertext, tag_len)
                    .expect_err("AES-CCM decrypt must fail for failing vectors");
                assert!(
                    matches!(err, HsmError::TagMismatch),
                    "expected tag mismatch in Count={}, got {err:?}",
                    field(&case, "Count")
                );
            }
            other => panic!("unexpected DVPT256 Result={other}"),
        }

        backend.key_delete(handle).unwrap();
    }

    backend.deinit().unwrap();
    assert!(pass_cases > 0, "expected pass vectors in DVPT256");
    assert!(fail_cases > 0, "expected fail vectors in DVPT256");
}
