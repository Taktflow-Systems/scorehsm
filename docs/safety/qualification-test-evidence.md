# scorehsm — Qualification Test Evidence

Date: 2026-03-14
Standard: ISO 26262-6:2018 §10 / §11
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-QTE

---

## 1. Purpose

Qualification testing (ISO 26262-6 §11) verifies that the software element satisfies its **Functional Safety Requirements (FSRs)** at the highest integration level available — the complete host library binary operating against the `MockHardwareBackend`. This document provides:

1. The FSR → qualification test forward traceability
2. The qualification test → FSR reverse traceability
3. Overall V-model right-side coverage summary

**Traceability direction:** SG → FSR → TSR → SSR → Unit Test / Integration Test → Qualification Test

---

## 2. Qualification Test Environment

| Item | Description |
|---|---|
| Test level | Software qualification (ISO 26262-6 §11) |
| System under test | `scorehsm-host` library, `default` feature set |
| Hardware simulation | `MockHardwareBackend` (all fault modes exercised) |
| Platform | Linux (`ubuntu-latest` in CI), Windows (`windows-latest` in CI) |
| Evidence type | Automated test pass record + coverage report |
| Coverage target | Statement ≥85%, Branch ≥80% (ASIL B, ISO 26262-6 Table 10) |
| Tool | `cargo-llvm-cov` (TCL-2 qualified, see SCORE-TQR) |

---

## 3. FSR → Qualification Test Forward Traceability

### FSR-01 — Definitive Pass/Fail Verification Result

**Safety Goal:** SG-01 (no false verification)
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-01-a` | ECDSA verify with valid key+sig returns `true` | `Ok(true)` |
| `QT-FSR-01-b` | ECDSA verify with tampered sig returns `false` (not error) | `Ok(false)` |
| `QT-FSR-01-c` | ECDSA verify with wrong key returns `false` | `Ok(false)` |
| `QT-FSR-01-d` | HMAC verify with wrong data returns `false` | `Ok(false)` |
| `QT-FSR-01-e` | Result is never `Option` — always definitive | API type: `HsmResult<bool>` (no `Option`) |

### FSR-02 — Constant-Time Cryptographic Comparisons

**Safety Goal:** SG-01, SG-02
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-02-a` | AES-GCM tag comparison uses `subtle::ConstantTimeEq` | Code review + `grep subtle` in decrypt path |
| `QT-FSR-02-b` | ECDSA signature comparison uses `subtle::ConstantTimeEq` | Code review + `grep subtle` in verify path |
| `QT-FSR-02-c` | Tag mismatch → `AuthenticationFailed`, not early exit leaking data | Timing analysis: <10 μs variance across correct/incorrect tags (mock) |

### FSR-03 — Output Correlation Check (Hash)

**Safety Goal:** SG-02
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-03-a` | SHA-256 NIST KAT vector verified | Known-good output matches NIST FIPS 180-4 vector |
| `QT-FSR-03-b` | HMAC-SHA256 NIST KAT vector verified | Known-good output matches RFC 4231 vector |
| `QT-FSR-03-c` | Output length always 32 bytes | API returns `[u8; 32]` (compile-time guarantee) |

### FSR-04 — No Raw Key Export

**Safety Goal:** SG-03
**ASIL:** B(d)

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-04-a` | No function in public API returns raw key bytes | API surface audit: no `Vec<u8>` or `[u8; N]` in key access paths |
| `QT-FSR-04-b` | `key_import` returns `KeyHandle` only | Return type = `HsmResult<KeyHandle>` |
| `QT-FSR-04-c` | `key_generate` returns `KeyHandle` only | Return type = `HsmResult<KeyHandle>` |
| `QT-FSR-04-d` | USB opcode table audit: no export opcode | Firmware opcode enumeration reviewed at each release |

### FSR-05 — Key Material Zeroization

**Safety Goal:** SG-03
**ASIL:** B(d)

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-05-a` | Key slot bytes zeroed on `key_delete` | `resolve_key` after delete → `InvalidKeyHandle`; memory check shows zeros |
| `QT-FSR-05-b` | `Drop` calls `zeroize` on all key-material types | Compile-time: `ZeroizeOnDrop` bound; runtime: `drop(key)` then check memory |
| `QT-FSR-05-c` | `SoftwareBackend` key store zeroized on `deinit` | After `deinit()`, key slots are cleared |
| `QT-FSR-05-d` | Compile-time assertion present for each key-material type | `cargo check` passes with assert |

### FSR-06 — Nonce Uniqueness (AEAD)

**Safety Goal:** SG-04
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-06-a` | N=1000 consecutive AES-GCM encryptions: all IVs unique | All 1000 IVs distinct |
| `QT-FSR-06-b` | Same key, same counter value: IV is deterministic (HKDF) | Two invocations with same counter → same IV |
| `QT-FSR-06-c` | Different keys, same counter: distinct IVs | Key isolation in IV derivation |
| `QT-FSR-06-d` | Nonce counter pre-incremented in SQLite before operation | DB counter = operation count (no reuse on simulated crash) |

### FSR-07 — Nonce Counter Persistence

**Safety Goal:** SG-04
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-07-a` | Counter survives library re-init (SQLite WAL flush) | After `deinit` + `init`, counter continues from last value |
| `QT-FSR-07-b` | Counter not reset by `hsm_reinit` (only key rotation resets) | `hsm_reinit()` does not reset nonce counter |
| `QT-FSR-07-c` | WAL journal mode verified (`PRAGMA journal_mode=WAL`) | SQLite `PRAGMA journal_mode` returns `wal` |

### FSR-08 — Frame Integrity (Transport)

**Safety Goal:** SG-05
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-08-a` | CRC-32/MPEG-2 KAT: known input → known CRC | CRC of `[0x00; 4]` = `0x2144DF1C` (MPEG-2 reference) |
| `QT-FSR-08-b` | Bit-flip in any frame byte → CRC mismatch detected | 100/100 single-bit flips detected |
| `QT-FSR-08-c` | CRC covers header + opcode + length + payload | Full-frame computation verified |

### FSR-09 — Sequence Number Integrity

**Safety Goal:** SG-05
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-09-a` | Normal operation: seq# monotonically increasing | Verified via `call_count` inspection |
| `QT-FSR-09-b` | Replayed response (stale seq#) → `ProtocolError` | Error on second delivery of same seq# |
| `QT-FSR-09-c` | Overflow at `u32::MAX` → `SequenceOverflow`, no wrap | No operation executed at max |

### FSR-10 — Safe State on Integrity Fault

**Safety Goal:** SG-06
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-10-a` | 3× CRC failure → library state = `SafeState` | State machine in `SafeState` |
| `QT-FSR-10-b` | Seq# mismatch → library state = `SafeState` | State machine in `SafeState` |
| `QT-FSR-10-c` | Hardware fault opcode → library state = `SafeState` | State machine in `SafeState` |
| `QT-FSR-10-d` | Key store checksum fail → `SafeState` + `IntegrityViolation` | Both error and state transition |
| `QT-FSR-10-e` | In `SafeState`: all ops return `HsmError::SafeState` | No backend contact |

### FSR-11 — Re-initialization from Safe State

**Safety Goal:** SG-06
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-11-a` | `hsm_reinit()` from `SafeState` → `Initializing → Ready` | Successful re-init |
| `QT-FSR-11-b` | `hsm_reinit()` from `Ready` → error (already initialized) | `HsmError::InitializationFailed` |
| `QT-FSR-11-c` | After reinit, new operations succeed | `Ok` on subsequent crypto calls |

### FSR-12 — Session Isolation

**Safety Goal:** SG-07
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-12-a` | Session A handle rejected in session B | `HsmError::InvalidHandle` |
| `QT-FSR-12-b` | Session closure removes all handles from map | Map entry deleted on `close_session` |
| `QT-FSR-12-c` | Concurrent sessions do not share handle namespaces | Handle IDs are globally unique but session-scoped |

### FSR-13 — Session Inactivity Timeout

**Safety Goal:** SG-07
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-13-a` | Session idle 300+ s → auto-closed | `SessionExpired` event; handles invalid |
| `QT-FSR-13-b` | Active session not closed before timeout | `Ok` on ops within timeout |

### FSR-14 — Rate Limiting

**Safety Goal:** SG-06, SG-07
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-14-a` | ECDSA burst > token bucket → `RateLimitExceeded` | Error, no queue |
| `QT-FSR-14-b` | Max session limit enforced → `ResourceExhausted` | Error on 9th session |
| `QT-FSR-14-c` | Rate limiter protects all sessions globally | Single session cannot exhaust ECDSA budget for others |

### FSR-15 — Device Identity Verification

**Safety Goal:** SG-06
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-15-a` | Wrong VID/PID at init → `InitializationFailed` | Error; state = `Initializing` |
| `QT-FSR-15-b` | VID/PID change post-init → `DeviceIdentityChanged`, `SafeState` | Safe state triggered |
| `QT-FSR-15-c` | Firmware version < minimum → `InitializationFailed` | Error |

### FSR-16 — Certificate Validity

**Safety Goal:** SG-01
**ASIL:** B

| QT ID | Test Description | Pass Criteria |
|---|---|---|
| `QT-FSR-16-a` | Expired certificate rejected | `HsmError::CertificateExpired` |
| `QT-FSR-16-b` | Pre-valid certificate rejected | `HsmError::CertificateNotYetValid` |
| `QT-FSR-16-c` | Valid certificate accepted | `Ok` |
| `QT-FSR-16-d` | Clock unavailable → all cert ops rejected | `HsmError::ClockUnavailable` |

---

## 4. Qualification Test → FSR Reverse Traceability

| QT Group | FSR(s) Covered | Test Count |
|---|---|---|
| QT-FSR-01-a..e | FSR-01 | 5 |
| QT-FSR-02-a..c | FSR-02 | 3 |
| QT-FSR-03-a..c | FSR-03 | 3 |
| QT-FSR-04-a..d | FSR-04 | 4 |
| QT-FSR-05-a..d | FSR-05 | 4 |
| QT-FSR-06-a..d | FSR-06 | 4 |
| QT-FSR-07-a..c | FSR-07 | 3 |
| QT-FSR-08-a..c | FSR-08 | 3 |
| QT-FSR-09-a..c | FSR-09 | 3 |
| QT-FSR-10-a..e | FSR-10 | 5 |
| QT-FSR-11-a..c | FSR-11 | 3 |
| QT-FSR-12-a..c | FSR-12 | 3 |
| QT-FSR-13-a..b | FSR-13 | 2 |
| QT-FSR-14-a..c | FSR-14 | 3 |
| QT-FSR-15-a..c | FSR-15 | 3 |
| QT-FSR-16-a..d | FSR-16 | 4 |
| **Total** | **16/16 FSRs** | **57** |

**Qualification test FSR coverage: 16/16 (100%)**

---

## 5. V-Model Right-Side Coverage Summary

| Level | Document | Tests Defined | Tests Passing | Coverage |
|---|---|---|---|---|
| Unit (mock) | SCORE-UTT | 13 | 13 | 11/28 SSRs direct |
| Integration | SCORE-ITP | 52 | 0 (specified) | 28/28 SSRs (spec complete) |
| Qualification | SCORE-QTE (this) | 57 | 0 (specified) | 16/16 FSRs |
| HIL | SCORE-ITP §6 | 4 | 0 | Pending hardware |

**Total tests specified across all levels: 126**
**Tests currently executing and passing: 13 (unit level)**

---

## 6. Evidence Collection Plan

Evidence for ISO 26262-6 §11 sign-off must include:

1. **`cargo test --lib` pass record** — 13/13 unit tests, 0 warnings (collected 2026-03-14)
2. **`cargo llvm-cov` HTML report** — statement ≥85%, branch ≥80% (to be collected after integration test implementation)
3. **Integration test pass record** — 52/52 integration tests passing in CI
4. **Qualification test pass record** — 57/57 qualification tests passing in CI
5. **HIL test record** — 4/4 HIL tests on STM32L552 hardware
6. **Static analysis report** — `cargo clippy -- -D warnings` (zero warnings)
7. **MISRA/coding guidelines audit** — per SCORE-TQR (Step 13)

Items 2–7 are open items to be closed before final ASIL B sign-off.

---

*Document end — SCORE-QTE rev 1.0 — 2026-03-14*
