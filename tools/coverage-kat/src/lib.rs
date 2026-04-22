// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Known-answer fixture for `cargo-llvm-cov` TCL-2 validation.

pub fn branch_kat(x: u8) -> u8 {
    if x == 0 {
        return 1;
    }
    if x == 1 {
        return 2;
    }
    if x == 2 {
        return 3;
    }
    4
}

#[cfg(test)]
mod tests {
    use super::branch_kat;

    #[test]
    fn branch_a_is_covered() {
        assert_eq!(branch_kat(0), 1);
    }

    #[test]
    fn branch_b_is_covered() {
        assert_eq!(branch_kat(1), 2);
    }
}
