// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use scorehsm_host::safety::crc32_mpeg2;
use scorehsm_host::transport::{Cmd, FRAME_OVERHEAD, HDR_LEN, MAGIC};

fn legacy_crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[test]
fn crc32_mpeg2_matches_legacy_frame_bytes() {
    let payload = b"scorehsm-crc-regression";
    let payload_len = payload.len();
    let mut frame = vec![0u8; FRAME_OVERHEAD + payload_len];
    frame[0] = MAGIC[0];
    frame[1] = MAGIC[1];
    frame[2] = Cmd::Sha256 as u8;
    frame[3..7].copy_from_slice(&0x0102_0304u32.to_le_bytes());
    frame[7..9].copy_from_slice(&(payload_len as u16).to_le_bytes());
    frame[HDR_LEN..HDR_LEN + payload_len].copy_from_slice(payload);

    let frame_bytes = &frame[..HDR_LEN + payload_len];
    assert_eq!(crc32_mpeg2(frame_bytes), legacy_crc32_mpeg2(frame_bytes));
}
