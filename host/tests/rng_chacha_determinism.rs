// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Deterministic ChaCha20Rng stream checks.
//!
//! Source vectors: rand_chacha upstream commit
//! 98a0339f99ecfe0467b2829c329bd8b7525a1c21 (`src/chacha.rs` tests
//! `test_chacha_true_values_a`, `test_chacha_true_values_b`, and
//! `test_chacha_true_values_c`).

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

struct StreamVector {
    seed: [u8; 32],
    word_pos: u128,
    expected_u32: [u32; 16],
}

fn expected_bytes(words: &[u32; 16]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (index, word) in words.iter().enumerate() {
        out[index * 4..(index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[test]
fn chacha20rng_deterministic_stream_vectors() {
    let vectors = [
        StreamVector {
            seed: [0u8; 32],
            word_pos: 0,
            expected_u32: [
                0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0,
                0xccef36a8, 0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
                0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
            ],
        },
        StreamVector {
            seed: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1,
            ],
            word_pos: 16,
            expected_u32: [
                0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01,
                0xf38422b8, 0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f,
                0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00,
            ],
        },
        StreamVector {
            seed: [
                0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
            word_pos: 32,
            expected_u32: [
                0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039,
                0xa1bebbc1, 0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6,
                0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e,
            ],
        },
    ];

    for vector in vectors {
        let mut rng = ChaCha20Rng::from_seed(vector.seed);
        rng.set_word_pos(vector.word_pos);

        let mut actual = [0u8; 64];
        rng.fill_bytes(&mut actual);

        assert_eq!(
            actual,
            expected_bytes(&vector.expected_u32),
            "ChaCha20Rng stream mismatch for seed {:?} at word_pos {}",
            vector.seed,
            vector.word_pos
        );
    }
}
