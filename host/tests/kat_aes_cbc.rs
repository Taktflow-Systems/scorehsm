// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! NIST AES-256-CBC known-answer tests (CAVP AESAVS).

mod common;

use std::path::PathBuf;

use common::{field, hex_field, load_rsp, RspCase};
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
    types::KeyType,
};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("aes_cbc")
        .join(name)
}

fn run_case(backend: &mut SoftwareBackend, case: &RspCase) {
    let key = hex_field(case, "KEY");
    let iv = <[u8; 16]>::try_from(hex_field(case, "IV")).expect("CBC IV must be 16 bytes");
    let handle = backend
        .key_import(KeyType::Aes256, &key)
        .expect("AES-256 key import must succeed");

    match case.section.as_deref() {
        Some("ENCRYPT") => {
            let plaintext = hex_field(case, "PLAINTEXT");
            let expected = hex_field(case, "CIPHERTEXT");
            let actual = backend
                .aes_cbc_encrypt(handle, &iv, &plaintext)
                .expect("AES-CBC encrypt must succeed");
            assert_eq!(
                actual, expected,
                "CBC encrypt mismatch in COUNT={}",
                field(case, "COUNT")
            );
        }
        Some("DECRYPT") => {
            let ciphertext = hex_field(case, "CIPHERTEXT");
            let expected = hex_field(case, "PLAINTEXT");
            let actual = backend
                .aes_cbc_decrypt(handle, &iv, &ciphertext)
                .expect("AES-CBC decrypt must succeed");
            assert_eq!(
                actual, expected,
                "CBC decrypt mismatch in COUNT={}",
                field(case, "COUNT")
            );
        }
        other => panic!("unexpected AES-CBC section: {other:?}"),
    }

    backend
        .key_delete(handle)
        .expect("AES-256 key delete must succeed");
}

fn run_file(name: &str) {
    let mut backend = SoftwareBackend::new();
    backend.init().unwrap();
    for case in load_rsp(vector_path(name)) {
        run_case(&mut backend, &case);
    }
    backend.deinit().unwrap();
}

#[test]
fn kat_aes_cbc_gfsbox256() {
    run_file("CBCGFSbox256.rsp");
}

#[test]
fn kat_aes_cbc_varkey256() {
    run_file("CBCVarKey256.rsp");
}

#[test]
fn kat_aes_cbc_vartxt256() {
    run_file("CBCVarTxt256.rsp");
}

#[test]
fn kat_aes_cbc_mmt256() {
    run_file("CBCMMT256.rsp");
}
