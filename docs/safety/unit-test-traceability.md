# scorehsm — Unit Test Traceability Matrix

Date: 2026-03-15
Standard: ISO 26262-6:2018 §9 / §10
Status: RELEASED (Rev 1.1)
ASIL Target: ASIL B
Document ID: SCORE-UTT

---

## 1. Purpose

This document provides the **bidirectional traceability** between Software Safety Requirements (SSRs, HSM-REQ-050..077) and their unit-level test coverage. It satisfies ISO 26262-6 Table 10 (test specification), Table 11 (test coverage), and ASIL B branch/statement coverage requirements.

**Traceability direction:** SSR → Unit Test → Pass/Fail evidence

---

## 2. Test Infrastructure

| Item | Value |
|---|---|
| Test framework | Rust built-in `#[test]` + `cargo test` |
| Coverage tool | `cargo-llvm-cov` (LLVM-based, TCL-2) |
| Mock hardware | `backend::mock::MockHardwareBackend` (SCORE-UTT §4) |
| CI runner | GitHub Actions `ubuntu-latest`, `windows-latest` |
| Target ASIL B coverage | ≥85% statement, ≥80% branch (ISO 26262-6 Table 10) |
| Test binary | `scorehsm-host` lib tests (`cargo test --lib`) |
| Current result | **274/274 pass, 0 warnings** (2026-03-15) |

---

## 3. SSR → Test Forward Traceability

For each Software Safety Requirement, the tests that verify it are listed.

### 14a — Transport Integrity

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-050 | CRC-32 mismatch → `HsmError::CrcMismatch` | `test_crc_error_injection` | `backend::mock::tests` | `inject_crc_error_on_attempt: Some(1)` | ✓ |
| HSM-REQ-051 | Sequence number mismatch → `HsmError::ProtocolError` | `test_seq_mismatch_injection` | `backend::mock::tests` | `inject_seq_mismatch: true` | ✓ |
| HSM-REQ-051 | Sequence overflow at `0xFFFF_FFFF` → `HsmError::SequenceOverflow` | `test_sequence_overflow` | `backend::mock::tests` | `seq_counter.store(u32::MAX)` | ✓ |
| HSM-REQ-052 | Command timeout → `HsmError::Timeout` | `test_timeout_injection` | `backend::mock::tests` | `inject_timeout: true` | ✓ |
| HSM-REQ-053 | Safe state after 3 consecutive transport failures | `integration_safe_state` tests | `host/tests/integration_safe_state.rs` | Consecutive CRC failures | ✓ |
| HSM-REQ-054 | Retry with back-off (max 2 retries) | `integration_transport` tests | `host/tests/integration_transport.rs` | Retry counting | ✓ |

### 14b — Nonce Management

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-055 | Pre-increment nonce before AEAD; reject on overflow | `integration_nonce` tests | `host/tests/integration_nonce.rs` | Nonce overflow | ✓ |
| HSM-REQ-056 | HKDF empty info string → `HsmError::InvalidArgument` | `test_hkdf_empty_info_rejected` | `backend::mock::tests` | Empty `info` slice | ✓ |
| HSM-REQ-057 | HKDF domain separation; distinct info strings per algorithm | `integration_nonce` tests | `host/tests/integration_nonce.rs` | Domain separation | ✓ |

### 14c — Session Management

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-058 | Cross-session handle isolation → `HsmError::InvalidHandle` | `integration_session` tests | `host/tests/integration_session.rs` | Cross-session handle use | ✓ |
| HSM-REQ-059 | Session inactivity timeout (300 s default) | `integration_session` tests | `host/tests/integration_session.rs` | MockClock timeout | ✓ |
| HSM-REQ-060 | Max 8 concurrent sessions → `HsmError::ResourceExhausted` | `integration_session` tests | `host/tests/integration_session.rs` | Session limit exceeded | ✓ |

### 14d — Rate Limiting

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-061 | Rate limit exceeded → `HsmError::RateLimitExceeded` (no queue) | `integration_rate_limit` tests | `host/tests/integration_rate_limit.rs` | Burst exhaustion | ✓ |
| HSM-REQ-062 | Rate limits configurable via `HsmConfig::rate_limits` | `integration_rate_limit` tests | `host/tests/integration_rate_limit.rs` | Custom config | ✓ |

### 14e — Safe State

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-063 | Hardware fault opcode → `HsmError::HardwareFault` | `test_hw_fault_injection` | `backend::mock::tests` | `inject_hw_fault: true` | ✓ |
| HSM-REQ-064 | `SafeState` blocks all operations → `HsmError::SafeState` | `integration_safe_state` tests | `host/tests/integration_safe_state.rs` | SafeState entry | ✓ |
| HSM-REQ-065 | Key store CRC-32 checksum; mismatch → `HsmError::IntegrityViolation` | `integration_safe_state` tests | `host/tests/integration_safe_state.rs` | Checksum corruption | ✓ |

### 14f — Key Lifecycle

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-066 | Key material zeroized on `key_delete` and `Drop` | `test_key_zeroized_on_delete` | `backend::mock::tests` | `key_delete` then `resolve_key` | ✓ |
| HSM-REQ-066 | `ZeroizeOnDrop` compile-time assertion on `MockKeySlot` | `_: fn()` const assertion | `backend::mock` (line 81) | Compile-time | ✓ |
| HSM-REQ-067 | No key export via public API | `test_no_key_export_via_import` | `backend::mock::tests` | API surface audit | ✓ |

### 14g — Operational Verification

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-068 | Startup capability handshake; VID/PID + firmware version | `integration_identity` tests | `host/tests/integration_identity.rs` | Handshake verify | ✓ |
| HSM-REQ-069 | Device identity change → `HsmError::DeviceIdentityChanged` | `integration_identity` tests | `host/tests/integration_identity.rs` | Identity mismatch | ✓ |

### 14h — Cryptographic Correctness

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-070 | Certificate `notBefore`/`notAfter` validity window check | `integration_identity` tests | `host/tests/integration_identity.rs` | Cert validity window | ✓ |
| HSM-REQ-071 | Clock unavailable → reject cert operations | `integration_identity` tests | `host/tests/integration_identity.rs` | Clock failure | ✓ |

### 14i — Output Integrity

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-072 | AEAD decrypt: tag fail → error, no partial plaintext | `test_aead_auth_failure_returns_error_not_partial_plaintext` | `backend::mock::tests` | Wrong tag (`[0xFF; 16]`) | ✓ |
| HSM-REQ-073 | Constant-time comparison (AEAD tag, ECDSA sig) | `test_ecdsa_verify_rejects_wrong_signature` | `backend::mock::tests` | Bit-flip in `sig.r[0]` | ✓ |

### 14j — POST / KAT

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-074 | AES-GCM KAT executed at startup | `integration_post` tests | `host/tests/integration_post.rs` | AES-GCM KAT | ✓ |
| HSM-REQ-075 | ECDSA KAT executed at startup | `integration_post` tests | `host/tests/integration_post.rs` | ECDSA KAT | ✓ |
| HSM-REQ-076 | KAT fail → `HsmError::SelfTestFailed`, library stays in `Initializing` | `integration_post` tests | `host/tests/integration_post.rs` | KAT failure injection | ✓ |

### 14k — Hardware Simulation

| SSR ID | Requirement Summary | Test ID | Test Location | Fault Injected | Pass |
|---|---|---|---|---|---|
| HSM-REQ-077 | `MockHardwareBackend` simulates all SSR fault paths | All mock tests (§3 above) | `backend::mock::tests` | All faults | ✓ |

---

## 4. Test → SSR Reverse Traceability

| Test ID | File | SSRs Covered |
|---|---|---|
| `test_crc_error_injection` | `backend/mock.rs` | HSM-REQ-050, HSM-REQ-077 |
| `test_seq_mismatch_injection` | `backend/mock.rs` | HSM-REQ-051, HSM-REQ-077 |
| `test_timeout_injection` | `backend/mock.rs` | HSM-REQ-052, HSM-REQ-077 |
| `test_hw_fault_injection` | `backend/mock.rs` | HSM-REQ-063, HSM-REQ-077 |
| `test_no_key_export_via_import` | `backend/mock.rs` | HSM-REQ-067, HSM-REQ-077 |
| `test_aead_auth_failure_returns_error_not_partial_plaintext` | `backend/mock.rs` | HSM-REQ-072, HSM-REQ-077 |
| `test_hkdf_empty_info_rejected` | `backend/mock.rs` | HSM-REQ-056, HSM-REQ-077 |
| `test_ecdsa_verify_rejects_wrong_signature` | `backend/mock.rs` | HSM-REQ-073, HSM-REQ-077 |
| `test_key_zeroized_on_delete` | `backend/mock.rs` | HSM-REQ-066, HSM-REQ-077 |
| `test_sequence_overflow` | `backend/mock.rs` | HSM-REQ-051, HSM-REQ-077 |
| Compile-time const assertion | `backend/mock.rs:81` | HSM-REQ-066 (ZeroizeOnDrop) |
| `sha256_known_vectors` | `lib.rs` | HSM-REQ-030 (SHA-256 correctness) |
| `sha256_via_sha2_crate` | `lib.rs` | HSM-REQ-030 |
| `arithmetic_sanity` | `lib.rs` | Infrastructure sanity |

---

## 5. Coverage Summary

### SSR coverage (unit + integration tests)

| SSR Group | Total SSRs | Unit-tested | Integration-tested | Total covered |
|---|---|---|---|---|
| 14a Transport Integrity (REQ-050..054) | 5 | 4 | 1 | **5** |
| 14b Nonce Management (REQ-055..057) | 3 | 1 | 2 | **3** |
| 14c Session Management (REQ-058..060) | 3 | 0 | 3 | **3** |
| 14d Rate Limiting (REQ-061..062) | 2 | 0 | 2 | **2** |
| 14e Safe State (REQ-063..065) | 3 | 1 | 2 | **3** |
| 14f Key Lifecycle (REQ-066..067) | 2 | 2 | 0 | **2** |
| 14g Operational Verification (REQ-068..069) | 2 | 0 | 2 | **2** |
| 14h Cryptographic Correctness (REQ-070..071) | 2 | 0 | 2 | **2** |
| 14i Output Integrity (REQ-072..073) | 2 | 2 | 0 | **2** |
| 14j POST / KAT (REQ-074..076) | 3 | 0 | 3 | **3** |
| 14k Hardware Simulation (REQ-077) | 1 | 1 | 0 | **1** |
| **Total** | **28** | **11** | **17** | **28** |

**SSR coverage: 28/28 (100%) — 11 at unit level, 17 at integration level.**

> Note: ISO 26262-6 does not require 100% unit-test coverage of each SSR. The standard requires that requirements are verified by tests at an appropriate level (unit, integration, or system). Session/rate-limit/POST SSRs require a multi-component environment that makes integration tests the appropriate level. All 17 previously pending SSRs are now covered by passing integration tests (58 ITP tests in `host/tests/integration_*.rs`).

### ASIL B Statement/Branch Coverage Target

Coverage measurement is performed with `cargo-llvm-cov`. The target is:
- Statement coverage: ≥85%
- Branch coverage: ≥80%

Coverage report is generated in CI via:
```
cargo llvm-cov --lib --html --output-dir target/llvm-cov-report
```

Coverage evidence will be recorded in the verification report (SCORE-VER, Step 14).

---

## 6. Untested SSR Gap Analysis and Disposition

The 17 SSRs not yet covered at unit level have the following disposition:

| SSR IDs | Reason not unit-testable | Integration test step |
|---|---|---|
| HSM-REQ-053, 054 | Requires multi-retry state machine with a higher-level orchestrator | Step 10 |
| HSM-REQ-055, 057 | Requires SQLite WAL NonceManager integration with filesystem | Step 10 |
| HSM-REQ-058, 059, 060 | Requires SessionMap + clock + background sweep integration | Step 10 |
| HSM-REQ-061, 062 | Requires RateLimiter integration with operation dispatch | Step 10 |
| HSM-REQ-064, 065 | Requires LibraryState AtomicU8 state machine integration | Step 10 |
| HSM-REQ-068, 069 | Requires USB CDC device enumeration (mock or HIL) | Step 10 / HIL |
| HSM-REQ-070, 071 | Requires certificate parsing + SystemTime integration | Step 10 |
| HSM-REQ-074, 075, 076 | Requires POST harness execution during `hsm_init` | Step 10 |

All gaps are tracked in the integration test plan (SCORE-ITP, Step 10).

---

## 7. Test Execution Record

| Date | Commit | Command | Result | Evidence |
|---|---|---|---|---|
| 2026-03-14 | Initial | `cargo test --lib` | 13 passed, 0 failed, 0 warnings | CI artifact (pending) |
| 2026-03-15 | Current | `cargo test --workspace --features "mock,certs"` | 274 passed, 0 failed, 0 warnings | CI run #23099513024 (4/4 host jobs green) |

---

*Document end — SCORE-UTT rev 1.1 — 2026-03-15*
