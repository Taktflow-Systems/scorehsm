// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use scorehsm_host::error::HsmError;

#[test]
fn buffer_too_small_roundtrip() {
    let err = HsmError::BufferTooSmall {
        required: 64,
        provided: 16,
    };

    match err {
        HsmError::BufferTooSmall { required, provided } => {
            assert_eq!(required, 64);
            assert_eq!(provided, 16);
        }
        other => panic!("expected BufferTooSmall, got {other:?}"),
    }

    let msg = format!(
        "{}",
        HsmError::BufferTooSmall {
            required: 64,
            provided: 16,
        }
    );
    assert!(msg.contains("required 64 bytes"), "error message: {msg}");
    assert!(msg.contains("provided 16 bytes"), "error message: {msg}");
}
