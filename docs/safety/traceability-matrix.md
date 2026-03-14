# scorehsm — Full Bidirectional Traceability Matrix

Date: 2026-03-14
Standard: ISO 26262-6:2018 §6 / §7 / §9 / §10 / §11
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-TRM

---

## 1. Purpose

This document provides the complete bidirectional traceability chain for all safety-relevant artefacts in the `scorehsm` ISO 26262-6 V-model:

```
Hazardous Event → Safety Goal → Functional Safety Requirement → Technical Safety Requirement
                               → Software Safety Requirement → Unit Test / Integration Test / Qualification Test
```

Bidirectionality means the matrix supports both **forward tracing** (what does this SG require?) and **backward tracing** (which SG does this test verify?).

---

## 2. Hazardous Event → Safety Goal

| Hazardous Event | ASIL | Safety Goal | Short Title |
|---|---|---|---|
| HE-01: Forged firmware accepted as genuine | B | SG-01 | No false verification |
| HE-01: Forged firmware accepted as genuine | B | SG-02 | No silent output corruption |
| HE-02: Nonce reuse enables ciphertext forgery | B | SG-04 | Nonce uniqueness |
| HE-02: Nonce reuse enables ciphertext forgery | B | SG-05 | Transport fault detection |
| HE-03: Key material disclosed to attacker | B(d) | SG-03 | No key disclosure |
| HE-03: Key material disclosed to attacker | B | SG-05 | Transport fault detection |
| HE-04: HSM becomes unavailable during safety operation | B | SG-06 | Safe state on integrity fault |
| HE-04: HSM becomes unavailable during safety operation | B | SG-07 | Session isolation |

---

## 3. Safety Goal → Functional Safety Requirement

| SG | ASIL | FSR | FSR Description |
|---|---|---|---|
| SG-01 | B | FSR-01 | Definitive pass/fail verification result |
| SG-01 | B | FSR-16 | Certificate validity window check |
| SG-01, SG-02 | B | FSR-02 | Constant-time cryptographic comparisons |
| SG-02 | B | FSR-03 | Output correlation check (hash) |
| SG-03 | B(d) | FSR-04 | No raw key export |
| SG-03 | B(d) | FSR-05 | Key material zeroization |
| SG-04 | B | FSR-06 | Nonce uniqueness (AEAD) |
| SG-04 | B | FSR-07 | Nonce counter persistence |
| SG-05 | B | FSR-08 | Frame integrity (transport) |
| SG-05 | B | FSR-09 | Sequence number integrity |
| SG-06 | B | FSR-10 | Safe state on integrity fault |
| SG-06 | B | FSR-11 | Re-initialization from safe state |
| SG-06 | B | FSR-14 | Rate limiting and resource bound |
| SG-06 | B | FSR-15 | Device identity verification |
| SG-07 | B | FSR-12 | Session isolation |
| SG-07 | B | FSR-13 | Session inactivity timeout |

---

## 4. Functional Safety Requirement → Technical Safety Requirement

| FSR | TSR | TSR Description |
|---|---|---|
| FSR-01 | — | Implemented via software design (definitive bool return type) |
| FSR-02 | — | Implemented via `subtle::ConstantTimeEq` in software |
| FSR-03 | — | Implemented via SHA-256 KAT in POST |
| FSR-04 | TSR-KLG-02 | No export opcode in USB protocol |
| FSR-05 | TSR-KLG-01 | ZeroizeOnDrop on all key-material types |
| FSR-06 | TSR-NMG-01 | Per-key 64-bit counter in SQLite WAL |
| FSR-06 | TSR-NMG-02 | HKDF domain separation, non-empty info string |
| FSR-07 | TSR-NMG-01 | Per-key 64-bit counter in SQLite WAL (persistence) |
| FSR-08 | TSR-TIG-01 | CRC-32/MPEG-2 on every frame |
| FSR-08 | TSR-TIG-04 | 2-retry back-off; safe state after 3 consecutive failures |
| FSR-09 | TSR-TIG-02 | 32-bit monotonic sequence number, no wrap |
| FSR-10 | TSR-TIG-04 | Retry + safe state after 3 consecutive failures |
| FSR-10 | TSR-SSG-01 | State machine with AtomicU8, SafeState blocks all ops |
| FSR-10 | TSR-SSG-02 | CRC-32 checksum on key store map |
| FSR-11 | TSR-SSG-01 | State machine: reinit path from SafeState |
| FSR-12 | TSR-SMG-01 | HashMap<SessionId, HashSet<KeyHandle>> with session scope check |
| FSR-13 | TSR-SMG-02 | Inactivity timeout via Instant, 300 s default |
| FSR-14 | TSR-SMG-03 | Max 8 concurrent sessions |
| FSR-14 | TSR-RLG-01 | Token bucket per operation class |
| FSR-15 | TSR-IVG-01 | Startup capability handshake with VID/PID + version |
| FSR-16 | TSR-CG-01 | notBefore/notAfter check against system clock |

---

## 5. Technical Safety Requirement → Software Safety Requirement

| TSR | SSR(s) | SSR Description |
|---|---|---|
| TSR-TIG-01 | HSM-REQ-050 | CRC-32/MPEG-2 frame check; mismatch → `CrcMismatch` |
| TSR-TIG-02 | HSM-REQ-051 | 32-bit seq#, monotonic, no-wrap at MAX |
| TSR-TIG-03 | HSM-REQ-052 | Per-operation command timeout (configurable) |
| TSR-TIG-04 | HSM-REQ-053 | Safe state after 3 consecutive failures |
| TSR-TIG-04 | HSM-REQ-054 | Retry up to 2× with exponential back-off |
| TSR-NMG-01 | HSM-REQ-055 | Per-key 64-bit nonce counter, SQLite WAL, pre-increment |
| TSR-NMG-02 | HSM-REQ-056 | Reject empty HKDF info string |
| TSR-NMG-02 | HSM-REQ-057 | Distinct HKDF info strings per algorithm |
| TSR-SMG-01 | HSM-REQ-058 | Cross-session handle access → `InvalidHandle` |
| TSR-SMG-02 | HSM-REQ-059 | Session inactivity timeout, default 300 s |
| TSR-SMG-03 | HSM-REQ-060 | Max 8 concurrent sessions → `ResourceExhausted` |
| TSR-RLG-01 | HSM-REQ-061 | Token-bucket rate limiter; exceed → `RateLimitExceeded` |
| TSR-RLG-01 | HSM-REQ-062 | Rate limits configurable via `HsmConfig::rate_limits` |
| TSR-SSG-01 | HSM-REQ-063 | L55 fault opcode → `HardwareFault` |
| TSR-SSG-01 | HSM-REQ-064 | Library state machine: 4 states, AtomicU8, SafeState blocks all ops |
| TSR-SSG-02 | HSM-REQ-065 | Key store CRC-32 checksum; mismatch → `IntegrityViolation` + SafeState |
| TSR-KLG-01 | HSM-REQ-066 | ZeroizeOnDrop on all key-material types; compile-time assertion |
| TSR-KLG-02 | HSM-REQ-067 | No key-export path in public API or USB opcode table |
| TSR-IVG-01 | HSM-REQ-068 | Startup handshake: VID/PID, firmware version, capability bitmask |
| TSR-IVG-01 | HSM-REQ-069 | Post-init VID/PID change → `DeviceIdentityChanged` + SafeState |
| TSR-CG-01 | HSM-REQ-070 | Certificate notBefore/notAfter validity window check |
| TSR-CG-01 | HSM-REQ-071 | Clock unavailable → reject all certificate operations |
| FSR-01, FSR-02 | HSM-REQ-072 | AEAD decrypt: tag fail → error only, no partial plaintext |
| FSR-02 | HSM-REQ-073 | `subtle::ConstantTimeEq` for AEAD tags and ECDSA signatures |
| TSR-IVG-01 (POST) | HSM-REQ-074 | AES-GCM KAT at startup |
| TSR-IVG-01 (POST) | HSM-REQ-075 | ECDSA P-256 sign/verify KAT at startup |
| TSR-IVG-01 (POST) | HSM-REQ-076 | KAT fail → `SelfTestFailed`; library stays in `Initializing` |
| — | HSM-REQ-077 | MockHardwareBackend simulates all SSR fault paths for CI |

---

## 6. Software Safety Requirement → Test

| SSR | Unit Test | Integration Test | Qualification Test | HIL Test |
|---|---|---|---|---|
| HSM-REQ-050 | `test_crc_error_injection` ✓ | ITP-TIG-01-a..d | QT-FSR-08-a..c | HIL-TIG-05 |
| HSM-REQ-051 | `test_seq_mismatch_injection` ✓ `test_sequence_overflow` ✓ | ITP-TIG-02-a..d | QT-FSR-09-a..c | — |
| HSM-REQ-052 | `test_timeout_injection` ✓ | ITP-TIG-03-a..d | QT-FSR-10-b | — |
| HSM-REQ-053 | — | ITP-TIG-04-c, ITP-SSG-01-b | QT-FSR-10-a..e | — |
| HSM-REQ-054 | — | ITP-TIG-04-a..d | QT-FSR-10-a | — |
| HSM-REQ-055 | — | ITP-NMG-01-a..f | QT-FSR-06-a..d, QT-FSR-07-a..c | — |
| HSM-REQ-056 | `test_hkdf_empty_info_rejected` ✓ | ITP-NMG-02-a | — | — |
| HSM-REQ-057 | — | ITP-NMG-02-b..c | — | — |
| HSM-REQ-058 | — | ITP-SMG-01-a..c | QT-FSR-12-a..c | — |
| HSM-REQ-059 | — | ITP-SMG-02-a..d | QT-FSR-13-a..b | — |
| HSM-REQ-060 | — | ITP-SMG-03-a..c | QT-FSR-14-b | — |
| HSM-REQ-061 | — | ITP-RLG-01-a..e | QT-FSR-14-a..c | — |
| HSM-REQ-062 | — | ITP-RLG-01-d | QT-FSR-14-c | — |
| HSM-REQ-063 | `test_hw_fault_injection` ✓ | — | QT-FSR-10-c | — |
| HSM-REQ-064 | — | ITP-SSG-01-a..g | QT-FSR-10-a..e, QT-FSR-11-a..c | — |
| HSM-REQ-065 | — | ITP-SSG-02-a..c | QT-FSR-10-d | — |
| HSM-REQ-066 | `test_key_zeroized_on_delete` ✓ (+ compile assertion ✓) | — | QT-FSR-05-a..d | — |
| HSM-REQ-067 | `test_no_key_export_via_import` ✓ | — | QT-FSR-04-a..d | — |
| HSM-REQ-068 | — | ITP-IVG-01-a..c | QT-FSR-15-a..c | HIL-IVG-01 |
| HSM-REQ-069 | — | ITP-IVG-01-d | QT-FSR-15-b | HIL-IVG-02 |
| HSM-REQ-070 | — | ITP-CG-01-a..c | QT-FSR-16-a..c | — |
| HSM-REQ-071 | — | ITP-CG-01-d | QT-FSR-16-d | — |
| HSM-REQ-072 | `test_aead_auth_failure_returns_error_not_partial_plaintext` ✓ | — | QT-FSR-01-a..e | — |
| HSM-REQ-073 | `test_ecdsa_verify_rejects_wrong_signature` ✓ | — | QT-FSR-02-a..c | — |
| HSM-REQ-074 | — | ITP-POST-01 | — | — |
| HSM-REQ-075 | — | ITP-POST-02 | — | — |
| HSM-REQ-076 | — | ITP-POST-03..04 | — | — |
| HSM-REQ-077 | All mock tests ✓ | — | — | — |

**Legend:** ✓ = currently passing | — = specified, not yet implemented

---

## 7. Test → SSR Reverse Index

| Test ID | Type | SSR(s) Verified |
|---|---|---|
| `test_crc_error_injection` | Unit | HSM-REQ-050, HSM-REQ-077 |
| `test_seq_mismatch_injection` | Unit | HSM-REQ-051, HSM-REQ-077 |
| `test_timeout_injection` | Unit | HSM-REQ-052, HSM-REQ-077 |
| `test_hw_fault_injection` | Unit | HSM-REQ-063, HSM-REQ-077 |
| `test_no_key_export_via_import` | Unit | HSM-REQ-067, HSM-REQ-077 |
| `test_aead_auth_failure_returns_error_not_partial_plaintext` | Unit | HSM-REQ-072, HSM-REQ-077 |
| `test_hkdf_empty_info_rejected` | Unit | HSM-REQ-056, HSM-REQ-077 |
| `test_ecdsa_verify_rejects_wrong_signature` | Unit | HSM-REQ-073, HSM-REQ-077 |
| `test_key_zeroized_on_delete` | Unit | HSM-REQ-066, HSM-REQ-077 |
| `test_sequence_overflow` | Unit | HSM-REQ-051, HSM-REQ-077 |
| Compile-time ZeroizeOnDrop assertion | Static | HSM-REQ-066 |
| ITP-TIG-01-a..d (4 tests) | Integration | HSM-REQ-050 |
| ITP-TIG-02-a..d (4 tests) | Integration | HSM-REQ-051 |
| ITP-TIG-03-a..d (4 tests) | Integration | HSM-REQ-052 |
| ITP-TIG-04-a..e (5 tests) | Integration | HSM-REQ-053, HSM-REQ-054 |
| ITP-NMG-01-a..f (6 tests) | Integration | HSM-REQ-055 |
| ITP-NMG-02-a..c (3 tests) | Integration | HSM-REQ-056, HSM-REQ-057 |
| ITP-SMG-01-a..c (3 tests) | Integration | HSM-REQ-058 |
| ITP-SMG-02-a..d (4 tests) | Integration | HSM-REQ-059 |
| ITP-SMG-03-a..c (3 tests) | Integration | HSM-REQ-060 |
| ITP-RLG-01-a..e (5 tests) | Integration | HSM-REQ-061, HSM-REQ-062 |
| ITP-SSG-01-a..g (7 tests) | Integration | HSM-REQ-053, HSM-REQ-064 |
| ITP-SSG-02-a..c (3 tests) | Integration | HSM-REQ-065 |
| ITP-IVG-01-a..d (4 tests) | Integration | HSM-REQ-068, HSM-REQ-069 |
| ITP-CG-01-a..d (4 tests) | Integration | HSM-REQ-070, HSM-REQ-071 |
| ITP-POST-01..04 (4 tests) | Integration | HSM-REQ-074, HSM-REQ-075, HSM-REQ-076 |
| QT-FSR-01..16 (57 tests) | Qualification | FSR-01..16 (all SSRs via FSR) |
| HIL-IVG-01..02 | HIL | HSM-REQ-068, HSM-REQ-069 |
| HIL-TIG-05 | HIL | HSM-REQ-050 |
| HIL-RNG-01 | HIL | HSM-REQ-025 (original) |

---

## 8. FSR Coverage Summary

| FSR | SG(s) | TSR(s) | SSR(s) | Tests (all levels) |
|---|---|---|---|---|
| FSR-01 | SG-01 | — | HSM-REQ-072 | QT-FSR-01 (5) |
| FSR-02 | SG-01, SG-02 | — | HSM-REQ-072, REQ-073 | Unit (2) + QT-FSR-02 (3) |
| FSR-03 | SG-02 | — | — | QT-FSR-03 (3) |
| FSR-04 | SG-03 | TSR-KLG-02 | HSM-REQ-067 | Unit (1) + QT-FSR-04 (4) |
| FSR-05 | SG-03 | TSR-KLG-01 | HSM-REQ-066 | Unit (2) + QT-FSR-05 (4) |
| FSR-06 | SG-04 | TSR-NMG-01, NMG-02 | HSM-REQ-055..057 | Unit (1) + Integ (9) + QT-FSR-06 (4) |
| FSR-07 | SG-04 | TSR-NMG-01 | HSM-REQ-055 | Integ (6) + QT-FSR-07 (3) |
| FSR-08 | SG-05 | TSR-TIG-01, TIG-04 | HSM-REQ-050, REQ-053, REQ-054 | Unit (1) + Integ (9) + QT-FSR-08 (3) |
| FSR-09 | SG-05 | TSR-TIG-02 | HSM-REQ-051 | Unit (2) + Integ (4) + QT-FSR-09 (3) |
| FSR-10 | SG-06 | TSR-TIG-04, SSG-01, SSG-02 | HSM-REQ-053, REQ-063..065 | Unit (1) + Integ (17) + QT-FSR-10 (5) |
| FSR-11 | SG-06 | TSR-SSG-01 | HSM-REQ-064 | Integ (7) + QT-FSR-11 (3) |
| FSR-12 | SG-07 | TSR-SMG-01 | HSM-REQ-058 | Integ (3) + QT-FSR-12 (3) |
| FSR-13 | SG-07 | TSR-SMG-02 | HSM-REQ-059 | Integ (4) + QT-FSR-13 (2) |
| FSR-14 | SG-06, SG-07 | TSR-SMG-03, RLG-01 | HSM-REQ-060..062 | Integ (8) + QT-FSR-14 (3) |
| FSR-15 | SG-06 | TSR-IVG-01 | HSM-REQ-068, REQ-069 | Integ (4) + QT-FSR-15 (3) + HIL (2) |
| FSR-16 | SG-01 | TSR-CG-01 | HSM-REQ-070, REQ-071 | Integ (4) + QT-FSR-16 (4) |

**All 16 FSRs have at least one test at unit, integration, or qualification level.**

---

## 9. Document Index

| Document | ID | Status |
|---|---|---|
| Safety Goals | SCORE-SG | Released |
| Assumed Safety Requirements | SCORE-ASR | Released |
| Functional Safety Requirements | SCORE-FSR | Released |
| Technical Safety Requirements | SCORE-TSR | Released |
| Requirements (incl. SSRs) | SCORE-REQ | Released |
| Software Architectural Design | SCORE-SAD | Released |
| Software Unit Design | SCORE-SUD | Released |
| MockHardwareBackend (`mock.rs`) | — | Implemented, 13/13 pass |
| Unit Test Traceability | SCORE-UTT | Released |
| Integration Test Plan | SCORE-ITP | Released (52 tests specified) |
| Qualification Test Evidence | SCORE-QTE | Released (57 tests specified) |
| Dependent Failure Analysis | SCORE-DFA | Released |
| Tool Qualification Records | SCORE-TQR | Released |
| Verification Report | SCORE-VER | Released (Rev 1.1) |
| Safety Case | SCORE-SC | Released (CONDITIONALLY VALID) |
| **This document** | **SCORE-TRM** | **Released** |

---

## 10. Open Items Before Full VALID Status

| ID | Item | Blocks |
|---|---|---|
| UC-01 | HIL test execution (4 HIL tests) | SC-03 hardware claim, G2/G3 hardware sub-claims |
| UC-02 | Coverage measurement on Linux CI (≥85%/≥80%) | G5 |
| UC-03 | T1 independence review sign-off | G1 procedural |
| TQR-OI-01 | Pin `rust-toolchain.toml` to nightly commit | T1 (TCL-1) |
| TQR-OI-02 | Execute `cargo-llvm-cov` KAT | T3 (TCL-2 validation) |
| TQR-OI-03 | Configure clippy as blocking CI step | T4 (TCL-2 validation) |
| SCORE-ITP | Implement 52 integration tests | G2, G5 |
| SCORE-QTE | Execute 57 qualification tests | G2, G5 |

**Current verified evidence: 13/13 unit tests pass (mock.rs), ~110 original tests pass (host/tests/), 0 warnings, 0 unsafe blocks.**
**V-model specification complete: 7 SGs, 12 ASRs, 16 FSRs, 16 TSRs, 28 SSRs, 52 integration tests specified, 57 qualification tests specified, DFA complete, TQR complete.**

---

## 11. Out-of-ASIL-B-Scope Error Codes

The following `HsmError` variants exist in the codebase but are **not part of the ASIL B safety claim** and therefore not traced through the FSR → TSR → SSR chain above:

| Variant | Source | Reason out of scope |
|---|---|---|
| `ReplayDetected(u64, u64)` | `update.rs`, `feature_activation.rs` | HSM-REQ-047 (firmware update replay) is a functional requirement in Section 13 of requirements.md; it carries no ASIL designation |

The `Algorithm::Aes256Cbc` and `Algorithm::Aes256Ccm` enum variants are defined for HSM-REQ-003/004 (algorithm agility) but have no corresponding `HsmBackend` method implementation. They are reserved for a future hardware protocol extension and are not safety-relevant in the current scope.

---

*Document end — SCORE-TRM rev 1.0 — 2026-03-14*
