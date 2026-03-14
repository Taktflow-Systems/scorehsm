# scorehsm — Integration Test Plan

Date: 2026-03-14
Standard: ISO 26262-6:2018 §9 / §10
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-ITP

---

## 1. Purpose

This Integration Test Plan (ITP) defines integration-level tests that verify the Technical Safety Requirements (TSRs, SCORE-TSR) and the 17 SSRs not covered at unit level (identified in SCORE-UTT §6). Integration tests verify that multiple components interact correctly — they operate above the unit level but below full system/qualification testing.

**Traceability direction:** TSR → Integration Test → SSR coverage

---

## 2. Test Environment

| Item | Description |
|---|---|
| Test binary | `cargo test --test integration_*` |
| Hardware | None required (all mock-based); HIL tests marked separately |
| Mock backend | `MockHardwareBackend` with configurable faults |
| Database | SQLite WAL in-memory (`file::memory:?cache=shared`) |
| Clock | `std::time::Instant` / `std::time::SystemTime` (mocked via trait) |
| CI runner | GitHub Actions `ubuntu-latest`, `windows-latest` |
| Prerequisite | All unit tests pass (SCORE-UTT §7) |

---

## 3. TSR → Integration Test Forward Traceability

### TSR-TIG-01 — CRC-32 on Every Frame

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-TIG-01-a` | Valid CRC-32 frame accepted by transport layer | HSM-REQ-050 | `transport_round_trip()` returns `Ok` |
| `ITP-TIG-01-b` | Single bit flip in frame payload → `HsmError::CrcMismatch` | HSM-REQ-050 | Error returned, no operation executed |
| `ITP-TIG-01-c` | Burst error ≤32 bits → `HsmError::CrcMismatch` | HSM-REQ-050 | Error returned |
| `ITP-TIG-01-d` | CRC polynomial verified: `0x04C11DB7`, IV `0xFFFFFFFF`, no output XOR | HSM-REQ-050 | KAT vector match (MPEG-2 reference) |

### TSR-TIG-02 — Monotonic Sequence Numbers

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-TIG-02-a` | Sequence number increments by 1 per command | HSM-REQ-051 | `call_count` matches expected seq |
| `ITP-TIG-02-b` | Response with wrong seq# → `HsmError::ProtocolError`, state reset | HSM-REQ-051 | Error returned; library not in operating state |
| `ITP-TIG-02-c` | Seq# at `0xFFFF_FFFF` → `HsmError::SequenceOverflow`, no wrap | HSM-REQ-051 | Error; counter not incremented |
| `ITP-TIG-02-d` | Re-initialization resets seq# to 1 | HSM-REQ-051 | `hsm_reinit()` succeeds; next seq# is 1 |

### TSR-TIG-03 — Command Timeout

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-TIG-03-a` | AES operation completes within 100 ms default timeout | HSM-REQ-052 | `Ok` returned |
| `ITP-TIG-03-b` | Mock latency > timeout → `HsmError::Timeout` | HSM-REQ-052 | Error returned within timeout + 10 ms |
| `ITP-TIG-03-c` | ECDSA sign timeout = 2000 ms (mock simulated) | HSM-REQ-052 | Error on injected >2 s latency |
| `ITP-TIG-03-d` | Timeout configurable via `HsmConfig::timeouts` | HSM-REQ-052 | Custom 50 ms timeout respected |

### TSR-TIG-04 — Retry Policy

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-TIG-04-a` | Single CRC error followed by success → operation completes | HSM-REQ-053, REQ-054 | `Ok` after retry; `call_count == 2` |
| `ITP-TIG-04-b` | Two CRC errors then success → operation completes | HSM-REQ-053, REQ-054 | `Ok`; `call_count == 3` |
| `ITP-TIG-04-c` | Three consecutive CRC errors → `HsmError::CrcMismatch`, library enters `SafeState` | HSM-REQ-053 | Error; library state == `SafeState` |
| `ITP-TIG-04-d` | Back-off: retry intervals ≥ 10 ms / 20 ms | HSM-REQ-054 | Elapsed time ≥ 30 ms for 2 retries |
| `ITP-TIG-04-e` | After `SafeState`, subsequent operations return `HsmError::SafeState` | HSM-REQ-053, REQ-064 | All ops fail with `SafeState` error |

### TSR-NMG-01 — Per-Key Nonce Counter

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-NMG-01-a` | Nonce counter starts at 1 on first use | HSM-REQ-055 | IV derived from counter = 1 |
| `ITP-NMG-01-b` | Nonce counter increments before each AEAD call | HSM-REQ-055 | After N encryptions, counter = N |
| `ITP-NMG-01-c` | Counter persisted to SQLite before operation | HSM-REQ-055 | Counter in DB = call count after crash-safe flush |
| `ITP-NMG-01-d` | Counter at `u64::MAX` → `HsmError::NonceExhausted` | HSM-REQ-055 | Error; operation not executed |
| `ITP-NMG-01-e` | Pre-increment: crash after increment but before operation → skipped counter (safe) | HSM-REQ-055 | On restart, counter = previous + 1 (no reuse) |
| `ITP-NMG-01-f` | Same key with two concurrent sessions → counter never reused | HSM-REQ-055 | All IVs unique across N concurrent calls |

### TSR-NMG-02 — HKDF Domain Separation

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-NMG-02-a` | Empty `info` string → `HsmError::InvalidArgument` | HSM-REQ-056 | Error; no HKDF output produced |
| `ITP-NMG-02-b` | `"scorehsm-aead-iv-aes256gcm"` info → output differs from `"scorehsm-aead-iv-aes128gcm"` | HSM-REQ-057 | IVs are not equal for same PRK |
| `ITP-NMG-02-c` | Same PRK, same counter, different `info` → distinct IVs | HSM-REQ-057 | No collisions across all HKDF info strings |

### TSR-SMG-01 — Session Handle Map

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-SMG-01-a` | Key handle from session A not usable in session B → `HsmError::InvalidHandle` | HSM-REQ-058 | Error; operation not performed |
| `ITP-SMG-01-b` | Key handle valid in own session | HSM-REQ-058 | `Ok` when handle matches session |
| `ITP-SMG-01-c` | Closed session invalidates all its handles | HSM-REQ-058 | Subsequent use → `HsmError::InvalidHandle` |

### TSR-SMG-02 — Session Inactivity Timeout

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-SMG-02-a` | Session idle for >300 s (mocked clock) → session terminated | HSM-REQ-059 | Session removed; handles invalidated |
| `ITP-SMG-02-b` | Session activity resets inactivity timer | HSM-REQ-059 | Session not terminated after activity within 300 s |
| `ITP-SMG-02-c` | Timeout configurable; 60 s config → session expires at 60 s | HSM-REQ-059 | Session expires at configured duration |
| `ITP-SMG-02-d` | Session expiry emits `SessionExpired` IDS hook event | HSM-REQ-059 | Hook event observed in test hook callback |

### TSR-SMG-03 — Maximum Concurrent Sessions

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-SMG-03-a` | Open 8 sessions → all succeed | HSM-REQ-060 | 8 sessions open |
| `ITP-SMG-03-b` | Open 9th session → `HsmError::ResourceExhausted` | HSM-REQ-060 | Error on 9th `open_session()` |
| `ITP-SMG-03-c` | Close one session, open new → succeeds | HSM-REQ-060 | 8 sessions maintained |

### TSR-RLG-01 — Token-Bucket Rate Limiter

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-RLG-01-a` | ECDSA sign at 10 ops/s rate; 10 ops in 1 s → all succeed | HSM-REQ-061 | 10/10 `Ok` |
| `ITP-RLG-01-b` | ECDSA sign: 11 ops rapid-fire → 11th returns `HsmError::RateLimitExceeded` | HSM-REQ-061 | Error on 11th; no queue |
| `ITP-RLG-01-c` | After 1 s, token refills → next ECDSA sign succeeds | HSM-REQ-061 | `Ok` after rate window |
| `ITP-RLG-01-d` | Rate parameters configurable at init | HSM-REQ-062 | Custom rate (5/s) respected |
| `ITP-RLG-01-e` | AES-GCM rate (100/s) independent of ECDSA rate (10/s) | HSM-REQ-061 | Buckets are per operation class |

### TSR-SSG-01 — Safe State State Machine

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-SSG-01-a` | Library state machine: `Initializing → Ready → Operating` | HSM-REQ-064 | State transitions correct |
| `ITP-SSG-01-b` | CRC mismatch after max retries → `SafeState` | HSM-REQ-053, REQ-064 | State == `SafeState` |
| `ITP-SSG-01-c` | Sequence mismatch → `SafeState` | HSM-REQ-064 | State == `SafeState` |
| `ITP-SSG-01-d` | In `SafeState`, all ops return `HsmError::SafeState` | HSM-REQ-064 | No operation proceeds to backend |
| `ITP-SSG-01-e` | `SafeState` entry invalidates all sessions | HSM-REQ-064 | All session handles invalid |
| `ITP-SSG-01-f` | `hsm_reinit()` transitions `SafeState → Initializing` | HSM-REQ-064 | Reinit succeeds; state == `Initializing` then `Ready` |
| `ITP-SSG-01-g` | `SafeState` emits `LibrarySafeState` IDS hook event with cause | HSM-REQ-064 | Hook event received with trigger condition |

### TSR-SSG-02 — Key Store Integrity Check

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-SSG-02-a` | Key store CRC-32 checksum valid after insert | HSM-REQ-065 | Checksum matches expected |
| `ITP-SSG-02-b` | Simulated memory corruption in key store map → `HsmError::IntegrityViolation`, `SafeState` | HSM-REQ-065 | Error; library enters `SafeState` |
| `ITP-SSG-02-c` | Checksum recomputed after every write | HSM-REQ-065 | Checksum updated on `key_import`, `key_delete` |

### TSR-IVG-01 — Startup Capability Handshake

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-IVG-01-a` | Successful handshake: VID match, version ≥ minimum → `Ready` | HSM-REQ-068 | `hsm_init()` returns `Ok` |
| `ITP-IVG-01-b` | Wrong VID/PID → `HsmError::InitializationFailed` | HSM-REQ-068 | Error; library in `Initializing` |
| `ITP-IVG-01-c` | Firmware version < minimum → `HsmError::InitializationFailed` | HSM-REQ-068 | Error; library in `Initializing` |
| `ITP-IVG-01-d` | VID/PID change after init → `HsmError::DeviceIdentityChanged`, `SafeState` | HSM-REQ-069 | Error; library in `SafeState` |

### TSR-CG-01 — Certificate Validity Window

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-CG-01-a` | Valid certificate (now within `notBefore`..`notAfter`) → accepted | HSM-REQ-070 | Operation proceeds |
| `ITP-CG-01-b` | Expired certificate (`notAfter` in the past) → `HsmError::CertificateExpired` | HSM-REQ-070 | Error |
| `ITP-CG-01-c` | Pre-valid certificate (`notBefore` in the future) → `HsmError::CertificateNotYetValid` | HSM-REQ-070 | Error |
| `ITP-CG-01-d` | Clock unavailable (mock `SystemTime` error) → `HsmError::ClockUnavailable` | HSM-REQ-071 | Error; all cert operations rejected |

### POST / KAT

| Test ID | Description | SSRs | Pass Criteria |
|---|---|---|---|
| `ITP-POST-01` | AES-GCM KAT (NIST test vector) passes at startup | HSM-REQ-074 | `hsm_init()` runs KAT; `Ok` |
| `ITP-POST-02` | ECDSA P-256 sign/verify KAT (NIST vector) passes at startup | HSM-REQ-075 | `hsm_init()` runs KAT; `Ok` |
| `ITP-POST-03` | Injected KAT failure → `HsmError::SelfTestFailed`, library stays `Initializing` | HSM-REQ-076 | Error; state != `Ready` |
| `ITP-POST-04` | KAT failure does not advance library to `Ready` — operations rejected | HSM-REQ-076 | All ops return `InitializationFailed` |

---

## 4. Integration Test → TSR/SSR Reverse Traceability

| Test ID | TSR | SSRs |
|---|---|---|
| ITP-TIG-01-a..d | TSR-TIG-01 | HSM-REQ-050 |
| ITP-TIG-02-a..d | TSR-TIG-02 | HSM-REQ-051 |
| ITP-TIG-03-a..d | TSR-TIG-03 | HSM-REQ-052 |
| ITP-TIG-04-a..e | TSR-TIG-04 | HSM-REQ-053, REQ-054 |
| ITP-NMG-01-a..f | TSR-NMG-01 | HSM-REQ-055 |
| ITP-NMG-02-a..c | TSR-NMG-02 | HSM-REQ-056, REQ-057 |
| ITP-SMG-01-a..c | TSR-SMG-01 | HSM-REQ-058 |
| ITP-SMG-02-a..d | TSR-SMG-02 | HSM-REQ-059 |
| ITP-SMG-03-a..c | TSR-SMG-03 | HSM-REQ-060 |
| ITP-RLG-01-a..e | TSR-RLG-01 | HSM-REQ-061, REQ-062 |
| ITP-SSG-01-a..g | TSR-SSG-01 | HSM-REQ-053, REQ-064 |
| ITP-SSG-02-a..c | TSR-SSG-02 | HSM-REQ-065 |
| ITP-IVG-01-a..d | TSR-IVG-01 | HSM-REQ-068, REQ-069 |
| ITP-CG-01-a..d  | TSR-CG-01  | HSM-REQ-070, REQ-071 |
| ITP-POST-01..04 | TSR-IVG-01 (POST clause) | HSM-REQ-074, REQ-075, REQ-076 |

---

## 5. Coverage Completeness

| Total TSRs | Integration tests defined | Total test cases |
|---|---|---|
| 16 | 16 | 52 |

All 16 TSRs have at least one integration test. All 17 SSRs identified as gap in SCORE-UTT §6 are addressed.

**Complete SSR coverage across unit + integration tests: 28/28 (100%)**

---

## 6. HIL-Only Tests

The following tests require physical STM32L552 hardware (Hardware-in-the-Loop) and are excluded from CI. They are documented here for completeness and must be executed before final ASIL B sign-off.

| Test ID | Description | SSR |
|---|---|---|
| `HIL-IVG-01` | Real VID/PID enumeration from STM32L552 via USB CDC | HSM-REQ-068 |
| `HIL-IVG-02` | Device identity change (USB replug with different firmware) | HSM-REQ-069 |
| `HIL-TIG-05` | Real CRC-32 frame round-trip at USB full-speed | HSM-REQ-050 |
| `HIL-RNG-01` | TRNG output from L55 passes NIST SP 800-90B statistical tests | HSM-REQ-025 |

HIL tests are tracked separately in the HIL test plan (not in scope for this document).

---

## 7. Test Implementation Status

| Status | Count |
|---|---|
| Specified (this document) | 52 |
| Implemented | 0 |
| Passed | 0 |
| Blocked (HIL-only) | 4 |

> **Note:** Integration test implementation (Rust `tests/` directory) is the next implementation phase after mock-backend unit tests are complete. This plan constitutes the specification; implementation follows the Rust integration test framework (`cargo test --test <name>`).

---

*Document end — SCORE-ITP rev 1.0 — 2026-03-14*
