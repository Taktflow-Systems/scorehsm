// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

#![cfg(feature = "ffi")]

use scorehsm_host::ffi::{HSM_Deinit, HSM_Init, HSM_OK, HSM_Random};

#[test]
fn ffi_init_random_deinit_roundtrip() {
    let mut out = [0u8; 32];

    // SAFETY: the exported FFI functions are invoked with valid pointers and sizes.
    unsafe {
        assert_eq!(HSM_Init(), HSM_OK);
        assert_eq!(HSM_Random(out.as_mut_ptr(), out.len()), HSM_OK);
        assert_eq!(HSM_Deinit(), HSM_OK);
    }

    assert!(out.iter().any(|&byte| byte != 0));
}
