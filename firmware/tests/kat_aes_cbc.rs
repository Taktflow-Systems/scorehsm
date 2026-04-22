// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! NIST AES-256-CBC KATs against the firmware crypto module.

#[path = "../../host/tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::{field, hex_field, load_rsp, RspCase};
use scorehsm_firmware::crypto::{aes_cbc_decrypt, aes_cbc_encrypt};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("host")
        .join("tests")
        .join("vectors")
        .join("aes_cbc")
        .join(name)
}

fn run_case(case: &RspCase) {
    let key = hex_field(case, "KEY");
    let iv = <[u8; 16]>::try_from(hex_field(case, "IV")).expect("CBC IV must be 16 bytes");

    match case.section.as_deref() {
        Some("ENCRYPT") => {
            let plaintext = hex_field(case, "PLAINTEXT");
            let expected = hex_field(case, "CIPHERTEXT");
            let actual = aes_cbc_encrypt(&key, &iv, &plaintext)
                .expect("firmware AES-CBC encrypt must succeed");
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "firmware CBC encrypt mismatch in COUNT={}",
                field(case, "COUNT")
            );
        }
        Some("DECRYPT") => {
            let ciphertext = hex_field(case, "CIPHERTEXT");
            let expected = hex_field(case, "PLAINTEXT");
            let actual = aes_cbc_decrypt(&key, &iv, &ciphertext)
                .expect("firmware AES-CBC decrypt must succeed");
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "firmware CBC decrypt mismatch in COUNT={}",
                field(case, "COUNT")
            );
        }
        other => panic!("unexpected AES-CBC section: {other:?}"),
    }
}

fn run_file(name: &str) {
    for case in load_rsp(vector_path(name)) {
        run_case(&case);
    }
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
