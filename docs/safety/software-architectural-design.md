# scorehsm — Software Architectural Design (SAD)

Date: 2026-03-14
Standard: ISO 26262-6:2018 §7
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-SAD

---

## 1. Purpose

This document describes the software architecture of `scorehsm-host`, the host-side Rust
library. It allocates Software Safety Requirements (SSRs, HSM-REQ-050..077) and Technical
Safety Requirements (TSRs) to specific software components, defines component interfaces,
and provides the architectural-level Dependent Failure Analysis (DFA) required by
ISO 26262-6 §7.4.

---

## 2. Architectural Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  scorehsm-host process (single-threaded async, tokio or blocking)           │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Public API Layer  (lib.rs)                                          │   │
│  │  HsmContext — state machine (AtomicU8)                               │   │
│  │  Validates: state, session/handle, rate, POST                        │   │
│  └───────┬────────────────────────────────────────────────────────────┬─┘   │
│          │ dispatch (enum HsmOp)                                       │     │
│  ┌───────▼──────────────┐     ┌─────────────────────────────────┐    │     │
│  │  Session Layer       │     │  Safety Services Layer           │    │     │
│  │  session.rs          │     │  safety.rs                       │    │     │
│  │  ─────────────────── │     │  ──────────────────────────────  │    │     │
│  │  SessionMap (HashMap)│     │  NonceManager (SQLite WAL)       │    │     │
│  │  Handle registry     │     │  RateLimiter (token bucket)      │    │     │
│  │  Timeout sweep       │     │  LibraryState (AtomicU8)         │    │     │
│  │  RAII session guard  │     │  KeyStoreChecksum (CRC-32)       │    │     │
│  └───────┬──────────────┘     └─────────────────┬───────────────┘    │     │
│          │                                        │                    │     │
│  ┌───────▼────────────────────────────────────────▼───────────────┐  │     │
│  │  Backend Dispatch (HsmBackend trait)                            │  │     │
│  │  backend.rs                                                     │  │     │
│  └────────────────────────────────────────────────────────────────┘  │     │
│           │                              │                            │     │
│  ┌────────▼─────────┐        ┌───────────▼───────────────────────┐  │     │
│  │  SoftwareBackend │        │  HardwareBackend                   │  │     │
│  │  sw.rs           │        │  hw.rs                             │  │     │
│  │  ──────────────  │        │  ──────────────────────────────── │  │     │
│  │  ring / RustCrypto│       │  Transport Layer (transport.rs)    │  │     │
│  │  In-process keys │        │  ── Frame encoder/decoder          │  │     │
│  │  ZeroizeOnDrop   │        │  ── CRC-32 (HSM-REQ-050)          │  │     │
│  │  ASIL: QM        │        │  ── Seq# tracker (HSM-REQ-051)    │  │     │
│  │  (development/CI)│        │  ── Timeout (HSM-REQ-052)         │  │     │
│  └──────────────────┘        │  ── Retry (HSM-REQ-053)           │  │     │
│                               │  ── Device identity (HSM-REQ-068) │  │     │
│                               │  USB CDC driver (usb.rs)          │  │     │
│                               │  ASIL: B                          │  │     │
│                               └─────────────┬─────────────────────┘  │     │
│                                             │ USB CDC                 │     │
│  ┌──────────────────────────────────────────│─────────────────────┐  │     │
│  │  IDS Hook (ids.rs)  ◄────────────────────┘                     │  │     │
│  │  Fire-and-forget event sink                                     │  │     │
│  └─────────────────────────────────────────────────────────────────┘  │     │
│                                                                        │     │
│  ┌─────────────────────────────────────────────────────────────────┐  │     │
│  │  Certificate Module (cert.rs)                                   │  │     │
│  │  x509-cert crate, validity window check (HSM-REQ-070/071)      │◄─┘     │
│  └─────────────────────────────────────────────────────────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                         │ USB CDC (/dev/ttyACM0)
                         ▼
           ┌─────────────────────────────┐
           │  STM32L552 L55 Firmware     │
           │  (separate ASIL B element)  │
           └─────────────────────────────┘
```

---

## 3. Component Descriptions

### 3.1 Public API Layer (`lib.rs`)

**ASIL:** B

**Responsibilities:**
- Expose the public `HsmContext` type and all API functions
- Enforce library state machine (`Initializing / Ready / Operating / SafeState`) before dispatching any operation (HSM-REQ-061, HSM-REQ-062)
- Call POST (HSM-REQ-074, HSM-REQ-075, HSM-REQ-076) during initialization
- Call device identity verification (HSM-REQ-068) during initialization
- Delegate to Session Layer for handle validation
- Delegate to Safety Services for rate limiting and nonce management

**Safety requirements allocated:** HSM-REQ-061, HSM-REQ-062, HSM-REQ-063, HSM-REQ-064, HSM-REQ-068, HSM-REQ-072, HSM-REQ-073, HSM-REQ-074, HSM-REQ-075, HSM-REQ-076

**Interfaces:**
- Input: caller API calls (sync or async)
- Output: `HsmResult<T>` — either value or typed error
- To Session Layer: session ID + handle
- To Safety Services: rate limit token, nonce request
- To Backend Dispatch: typed `HsmOp` enum

---

### 3.2 Session Layer (`session.rs`)

**ASIL:** B

**Responsibilities:**
- Maintain `HashMap<SessionId, SessionState>` where `SessionState` contains `HashSet<KeyHandle>` and `last_active: Instant`
- Enforce per-session handle binding (HSM-REQ-057)
- Run inactivity timeout sweep at ≤1 s intervals (HSM-REQ-058)
- Enforce maximum concurrent session limit (HSM-REQ-059)
- Emit `SessionExpired` IDS events on timeout
- Maintain key store map CRC-32 checksum (HSM-REQ-065)

**Safety requirements allocated:** HSM-REQ-057, HSM-REQ-058, HSM-REQ-059, HSM-REQ-065

**Interfaces:**
- From API Layer: `open_session()`, `close_session()`, `validate_handle(session_id, handle)`
- To Safety Services: checksum verification calls
- To IDS Hook: `SessionExpired`, `SessionOpened`, `SessionClosed` events

---

### 3.3 Safety Services Layer (`safety.rs`)

**ASIL:** B

**Responsibilities:**
- `NonceManager`: per-key 64-bit counter in SQLite WAL (HSM-REQ-054); pre-increment and persist before AEAD encryption (HSM-REQ-055); enforce HKDF domain separation (HSM-REQ-056); detect overflow (HSM-REQ-054)
- `RateLimiter`: token-bucket per operation class (HSM-REQ-060); configurable from `HsmConfig`
- `LibraryState`: `AtomicU8` state with `SeqCst` ordering (HSM-REQ-061); provides `enter_safe_state(reason)` function (HSM-REQ-063, HSM-REQ-064)
- `KeyStoreChecksum`: CRC-32 over serialized session map; checked on every read (HSM-REQ-065)

**Safety requirements allocated:** HSM-REQ-054, HSM-REQ-055, HSM-REQ-056, HSM-REQ-060, HSM-REQ-061, HSM-REQ-063, HSM-REQ-064, HSM-REQ-065

**Interfaces:**
- From API Layer: `check_rate(op_class)`, `next_nonce(key_id, algo)`, `get_state()`
- From Session Layer: `update_checksum(map_ref)`, `verify_checksum(map_ref, stored_crc)`
- To IDS Hook: `LibrarySafeState`, `RateLimitExceeded` events

---

### 3.4 Backend Dispatch (`backend.rs`, `HsmBackend` trait)

**ASIL:** B (dispatch logic); backend ASIL depends on selected backend

**Responsibilities:**
- Provide the `HsmBackend` trait with all crypto operation signatures
- At runtime, dispatch to either `SoftwareBackend` or `HardwareBackend` based on build feature / configuration
- Provide `MockHardwareBackend` for CI (HSM-REQ-077)

**Safety requirements allocated:** HSM-REQ-077

---

### 3.5 Hardware Backend (`hw.rs`)

**ASIL:** B

**Responsibilities:**
- Implement `HsmBackend` by issuing USB CDC commands to the L55
- Delegate to Transport Layer for frame encoding, CRC, sequence numbers, timeouts, retries

**Sub-component: Transport Layer (`transport.rs`)**

**ASIL:** B

- Frame encoder: serializes `HsmOp` to wire format; appends CRC-32/MPEG-2 (HSM-REQ-050)
- Frame decoder: deserializes response; verifies CRC-32 (HSM-REQ-050); verifies sequence number echo (HSM-REQ-051)
- Sequence tracker: maintains monotonic 32-bit counter (HSM-REQ-051)
- Timeout enforcer: applies per-operation deadline (HSM-REQ-052)
- Retry logic: up to 2 retries with back-off; enters safe state after 3 consecutive failures (HSM-REQ-053)
- Device identity: verifies VID/PID and capability handshake at init (HSM-REQ-068); rechecks on re-enumeration (HSM-REQ-069)

**Sub-component: USB CDC Driver (`usb.rs`)**

**ASIL:** B (interface level); platform USB driver assumed correct (ASR-OS-01)

- Opens `/dev/ttyACM0` (or platform-equivalent)
- Provides `write_frame(&[u8])` and `read_frame() -> Vec<u8>` with OS timeout integration

**Safety requirements allocated:** HSM-REQ-050, HSM-REQ-051, HSM-REQ-052, HSM-REQ-053, HSM-REQ-068, HSM-REQ-069

---

### 3.6 Software Backend (`sw.rs`)

**ASIL:** QM — for CI / development use only

**Responsibilities:**
- Implement `HsmBackend` using `ring` and `RustCrypto` crates in-process
- All key material held in host process memory
- `ZeroizeOnDrop` on all key material types (HSM-REQ-066) — also required here for CI safety hygiene

**Safety requirements allocated:** HSM-REQ-066 (applies to both backends)

**Production restriction:** Must not be deployed in ASIL B production contexts (enforced by `#[cfg(not(feature = "hw-backend"))]` compile-time warning per HSM-REQ-045).

---

### 3.7 Certificate Module (`cert.rs`)

**ASIL:** B

**Responsibilities:**
- Parse X.509 certificates using `x509-cert` crate
- Validate `notBefore` / `notAfter` against `SystemTime::now()` (HSM-REQ-070)
- Return `HsmError::ClockUnavailable` if clock fails (HSM-REQ-071)
- Provide public-key extraction for ECDSA verification

**Safety requirements allocated:** HSM-REQ-070, HSM-REQ-071

---

### 3.8 IDS Hook (`ids.rs`)

**ASIL:** QM (fire-and-forget; non-blocking; safety logic does not depend on IDS success)

**Responsibilities:**
- Provide `ids_event(event: IdsEvent)` — non-blocking, best-effort delivery
- Events include: key lifecycle, session lifecycle, rate limit, safe state, auth failure, device identity change, POST failure

**Note:** IDS hook failure shall not propagate as an error to the caller. Safety logic (safe state, error return) is independent of IDS delivery.

---

### 3.9 MockHardwareBackend (test infrastructure)

**ASIL:** N/A (test-only, not deployed in production)

**Responsibilities:**
- Implement `HsmBackend` with in-process simulated L55 responses
- Support injection of: CRC errors, sequence number mismatches, timeouts, L55 fault opcodes, configurable latency
- Enable CI testing of all HSM-REQ-050..076 without physical hardware

**Safety requirements enabled:** HSM-REQ-077

---

## 4. Safety Requirement Allocation Matrix

| SSR | Component | ASIL |
|---|---|---|
| HSM-REQ-050 (CRC-32) | transport.rs | B |
| HSM-REQ-051 (seq#) | transport.rs | B |
| HSM-REQ-052 (timeout) | transport.rs | B |
| HSM-REQ-053 (retry/safe state) | transport.rs + safety.rs | B |
| HSM-REQ-054 (nonce counter) | safety.rs / NonceManager | B |
| HSM-REQ-055 (IV derivation) | safety.rs / NonceManager | B |
| HSM-REQ-056 (HKDF domain sep) | safety.rs / NonceManager | B |
| HSM-REQ-057 (session handle map) | session.rs | B |
| HSM-REQ-058 (session timeout) | session.rs | B |
| HSM-REQ-059 (max sessions) | session.rs | B |
| HSM-REQ-060 (rate limiter) | safety.rs / RateLimiter | B |
| HSM-REQ-061 (state machine) | safety.rs / LibraryState | B |
| HSM-REQ-062 (safe state blocks) | lib.rs (checked before dispatch) | B |
| HSM-REQ-063 (safe state triggers) | safety.rs + transport.rs + session.rs | B |
| HSM-REQ-064 (safe state IDS) | safety.rs → ids.rs | B |
| HSM-REQ-065 (key store checksum) | session.rs + safety.rs | B |
| HSM-REQ-066 (ZeroizeOnDrop) | sw.rs + key material structs | B(d) |
| HSM-REQ-067 (no key export) | hw.rs / opcode table (firmware) | B(d) |
| HSM-REQ-068 (startup handshake) | transport.rs | B |
| HSM-REQ-069 (VID/PID recheck) | transport.rs / usb.rs | B |
| HSM-REQ-070 (cert validity) | cert.rs | B |
| HSM-REQ-071 (clock unavail) | cert.rs | B |
| HSM-REQ-072 (definitive verify) | lib.rs (API contract) | B |
| HSM-REQ-073 (constant-time compare) | hw.rs + sw.rs (both backends) | B |
| HSM-REQ-074 (AES-GCM KAT) | lib.rs (init) → backend | B |
| HSM-REQ-075 (ECDSA KAT) | lib.rs (init) → backend | B |
| HSM-REQ-076 (POST failure blocks) | lib.rs (init state machine) | B |
| HSM-REQ-077 (MockHardwareBackend) | tests/ (test infra) | N/A |

---

## 5. Architectural Constraints

### 5.1 No Unsafe Code in Safety-Critical Components

The following modules shall maintain `#![deny(unsafe_code)]`:
- `lib.rs`, `session.rs`, `safety.rs`, `transport.rs`, `cert.rs`, `ids.rs`

The `usb.rs` and `hw.rs` modules may use `unsafe` only for platform USB FFI calls, subject to a documented safety argument for each `unsafe` block.

### 5.2 No Panic in Safety-Critical Path

Safety-critical modules shall handle all error conditions via `Result<>` and shall not invoke `unwrap()`, `expect()`, or `panic!()`. Violations shall be caught by the CI `#![deny(clippy::unwrap_used)]` lint.

### 5.3 Single-Instance Enforcement

The `HsmContext` constructor shall use a process-level lock (`std::sync::OnceLock`) to enforce that only one `HsmContext` exists per process (supports ASR-OS-03).

### 5.4 Thread Safety

All public-facing state (`LibraryState` AtomicU8, `SessionMap`, `NonceManager`) shall be protected by either:
- Atomic operations with `SeqCst` ordering (for state flags), or
- `std::sync::Mutex` with poisoning propagation (for complex data structures)

---

## 6. Architectural-Level Dependent Failure Analysis (DFA)

Per ISO 26262-6 §7.4.4, dependent failures at the architectural level are analyzed here.
The full software DFA is in `dependent-failure-analysis.md` (SCORE-DFA).

### 6.1 Common Cause Failures (CCF) at Architecture Level

| Potential CCF | Affected Components | Mitigation |
|---|---|---|
| Compiler bug corrupts AtomicU8 state | LibraryState + all state reads | Rustc TCL-1 qualification (tool-qualification.md); two independent state reads at decision points |
| SQLite library bug corrupts nonce DB | NonceManager | Nonce DB on separate storage path; SHA-256 hash of DB file checked on open |
| CRC-32 implementation defect | transport.rs frame check | Cross-checked with NIST test vectors in unit test; CRC also present in AES-GCM tag (independent integrity mechanism) |
| `std::time` returns wrong value | cert.rs + session timeout | Session timeout uses `Instant` (monotonic); cert validity uses `SystemTime` (wall clock). If `SystemTime` fails, cert ops fail safe (HSM-REQ-071). Independent clock reads. |

### 6.2 Cascading Failures at Architecture Level

| Initiating failure | Cascade path | Barrier |
|---|---|---|
| Transport layer CRC failure | transport.rs error → lib.rs enters SafeState → all sessions invalidated | SafeState is a defined terminal state; no further cascade |
| Session map memory corruption | session.rs checksum mismatch → safety.rs `enter_safe_state` | CRC-32 on map catches corruption before it affects handle validation |
| Nonce counter DB write failure | NonceManager returns `IoError` → AEAD encrypt returns error | Error propagated without using possibly-stale counter; no silent nonce reuse |
| IDS hook delivery failure | ids.rs fire-and-forget → no error propagated | IDS is non-safety; safety logic (safe state, error return) completed before IDS call |

---

## 7. Design Decisions

| Decision | Rationale |
|---|---|
| `AtomicU8` for library state | Lock-free, sequentially consistent — cannot be poisoned by a panicking thread holding a mutex |
| SQLite WAL for nonce counters | Write-ahead log guarantees atomicity of counter increment + persist; survives process crash between increment and fsync |
| Token-bucket rate limiter (not queue) | Reject immediately on bucket empty; queueing would allow slow ECDSA flood to build up latency — worse than rejection for safety-critical callers |
| CRC-32/MPEG-2 (upgrade from CRC-16) | CRC-32 achieves >99.9% single-bit error detection on frames up to 4096 bytes; ASIL B requires this margin |
| `subtle::ConstantTimeEq` for tag comparison | Provides timing-side-channel resistance without `unsafe` code; required by FSR-02 |
| MockHardwareBackend (not mocking at trait level) | Mock implements full transport protocol simulation including CRC, seq#, fault injection — tests protocol logic, not just API shape |

---

*Document end — SCORE-SAD rev 1.0 — 2026-03-14*
