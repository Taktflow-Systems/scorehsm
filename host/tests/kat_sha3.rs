// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! NIST SHA-3 known-answer tests for byte-oriented messages.

mod common;

use std::path::PathBuf;

use common::{field, hex_field, load_rsp, RspCase};
use scorehsm_host::{
    backend::{sw::SoftwareBackend, HsmBackend},
};

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("sha3")
        .join(name)
}

fn message_bytes(case: &RspCase) -> Vec<u8> {
    let bits = field(case, "Len").parse::<usize>().expect("invalid SHA-3 Len");
    if bits == 0 {
        return Vec::new();
    }
    assert_eq!(bits % 8, 0, "byte-oriented SHA-3 vectors must align to bytes");
    let bytes = hex_field(case, "Msg");
    assert_eq!(bytes.len(), bits / 8, "unexpected SHA-3 message length");
    bytes
}

fn run_sha3_256_file(name: &str) {
    let backend = {
        let mut backend = SoftwareBackend::new();
        backend.init().unwrap();
        backend
    };

    for case in load_rsp(vector_path(name)) {
        let msg = message_bytes(&case);
        let expected = <[u8; 32]>::try_from(hex_field(&case, "MD")).unwrap();
        let actual = backend.sha3_256(&msg).unwrap();
        assert_eq!(actual, expected, "SHA3-256 mismatch at Len={}", field(&case, "Len"));
    }
}

fn run_sha3_512_file(name: &str) {
    let backend = {
        let mut backend = SoftwareBackend::new();
        backend.init().unwrap();
        backend
    };

    for case in load_rsp(vector_path(name)) {
        let msg = message_bytes(&case);
        let expected = <[u8; 64]>::try_from(hex_field(&case, "MD")).unwrap();
        let actual = backend.sha3_512(&msg).unwrap();
        assert_eq!(actual, expected, "SHA3-512 mismatch at Len={}", field(&case, "Len"));
    }
}

#[test]
fn kat_sha3_256_short_msg() {
    run_sha3_256_file("SHA3_256ShortMsg.rsp");
}

#[test]
fn kat_sha3_256_long_msg() {
    run_sha3_256_file("SHA3_256LongMsg.rsp");
}

#[test]
fn kat_sha3_512_short_msg() {
    run_sha3_512_file("SHA3_512ShortMsg.rsp");
}

#[test]
fn kat_sha3_512_long_msg() {
    run_sha3_512_file("SHA3_512LongMsg.rsp");
}
