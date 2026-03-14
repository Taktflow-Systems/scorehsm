# scorehsm — Technical Safety Requirements (TSR)

Date: 2026-03-14
Standard: ISO 26262-6:2018 §6 / §7
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-TSR

---

## 1. Purpose

Technical Safety Requirements (TSRs) define **how** the Functional Safety Requirements (SCORE-FSR) are achieved at the technology level. Where FSRs say "what must be safe", TSRs say "which mechanism implements the safety property, with what parameters". TSRs are the direct inputs to Software Safety Requirements (SSRs, in requirements.md HSM-REQ-050..099).

**Traceability direction:** FSR → TSR → SSR → test

---

## 2. Transport Integrity Group (TIG)

### TSR-TIG-01 — CRC-32 on Every Frame

**ASIL:** B
**Derived from:** FSR-08

**Statement:** Every USB CDC frame (both host-to-L55 command frames and L55-to-host response frames) shall carry a 4-byte CRC-32/MPEG-2 check value computed over the entire frame payload (header + data). The polynomial shall be `0x04C11DB7` with initial value `0xFFFFFFFF` and no output XOR. The receiver shall recompute the CRC over the received bytes and compare with the carried value. Any mismatch shall result in rejection of the frame.

**Parameters:**
- Polynomial: CRC-32/MPEG-2 (0x04C11DB7)
- Bit width: 32 bits
- Diagnostic coverage: ≥99.9% for single-bit errors; ≥99% for burst errors ≤32 bits
- Position in frame: last 4 bytes
- Scope: entire frame (header + opcode + payload length + payload)

**Rationale:** CRC-32/MPEG-2 achieves >99.9% single-bit error detection over frames up to 4096 bytes, satisfying the SG-05 diagnostic coverage target. CRC-16 (used in the original design) achieves only ~99.998% for short frames; for ASIL B the upgrade to CRC-32 provides the required margin. Frame upgrade is coordinated with the L55 firmware.

**Replaces:** The existing CRC-16 in the USB protocol (upgrade required).

---

### TSR-TIG-02 — Monotonic Sequence Numbers, 32-Bit, Saturating

**ASIL:** B
**Derived from:** FSR-09

**Statement:** The host library shall maintain a 32-bit unsigned monotonic sequence number, initialized to 1 on library initialization and incremented by 1 for each command issued. The L55 shall echo the received sequence number in the response. The host library shall reject any response whose sequence number does not exactly match the pending command's sequence number. On sequence number mismatch the host library shall log the event and return `HsmError::ProtocolError`. The sequence number shall not wrap: at `0xFFFF_FFFF` the library shall refuse further operations and require re-initialization.

**Parameters:**
- Width: 32-bit unsigned
- Initial value: 1
- Increment: 1 per command
- Wrap behavior: prohibited — safe state on overflow
- Mismatch behavior: error return, IDS hook event, pending-command state machine reset

---

### TSR-TIG-03 — Command Timeout

**ASIL:** B
**Derived from:** FSR-10 (safe state triggers)

**Statement:** The host library shall apply a configurable timeout to every USB command issued to the L55. If no response matching the pending sequence number is received within the timeout period, the library shall treat this as a transport error, emit an IDS hook event, and return `HsmError::Timeout`. The default timeout values shall be:

| Operation class | Default timeout |
|---|---|
| Symmetric crypto (AES) | 100 ms |
| Hash (SHA-256/384) | 100 ms |
| HMAC | 100 ms |
| ECDSA sign | 2000 ms |
| ECDSA verify | 2000 ms |
| Key generation (ECC) | 5000 ms |
| ECDH | 2000 ms |
| RNG | 100 ms |
| Administrative (capability, version) | 500 ms |

**Rationale:** Without a timeout, a hung L55 (e.g., stuck in a long PKA operation) would block the caller indefinitely. A blocking safety-critical caller (e.g., OTA verifier) would miss its deadline.

---

### TSR-TIG-04 — Retry Policy with Back-off

**ASIL:** B
**Derived from:** FSR-08, FSR-10

**Statement:** On CRC failure (TSR-TIG-01) or timeout (TSR-TIG-03), the host library may retry the command up to 2 times with exponential back-off (initial 10 ms, factor 2). After 2 failed retries the library shall return an error without further retry. It shall not enter safe state on a single retried failure; safe state is entered only after 3 consecutive failures on the same operation (indicating a persistent hardware fault, not a transient EMI event).

**Parameters:**
- Max retries: 2 (3 total attempts)
- Initial back-off: 10 ms
- Back-off factor: 2×
- Safe state threshold: 3 consecutive failures

---

## 3. Nonce Management Group (NMG)

### TSR-NMG-01 — Per-Key Nonce Counter in Non-Volatile Storage

**ASIL:** B
**Derived from:** FSR-06, FSR-07

**Statement:** The host library shall maintain one 64-bit nonce counter per active key handle for AEAD operations. The counter shall be stored in a local database file (SQLite, single table `nonce_counters(key_id INTEGER PRIMARY KEY, counter INTEGER NOT NULL)`) using a write-ahead log (WAL) journal mode. The counter shall be incremented and persisted to disk before each AEAD encryption invocation. The L55-generated IV (if used) shall be discarded and replaced by the library-controlled IV derived from the counter using the construction `IV = HKDF-SHA256(key_id || counter, info="aead-iv", length=12)`.

**Parameters:**
- Counter width: 64-bit unsigned
- Storage: SQLite WAL
- IV construction: HKDF-SHA256, 12-byte output
- Counter increment: before invocation (pre-increment, not post)
- Overflow behavior: reject operation, require key rotation

**Rationale:** Pre-increment guarantees that a crash after increment but before operation results in a skipped counter value (safe). Post-increment risks reuse if a crash occurs after the operation but before persistence.

---

### TSR-NMG-02 — HKDF Domain Separation for IV Derivation

**ASIL:** B
**Derived from:** FSR-06

**Statement:** The HKDF invocation used to derive the IV (TSR-NMG-01) shall use a non-empty, algorithm-specific `info` string. The `info` string shall encode the algorithm identifier and key purpose. Empty `info` strings shall be rejected at the HKDF API level. Distinct key purposes shall use distinct `info` values:

| Use case | info string |
|---|---|
| AES-GCM-128 encryption IV | `"scorehsm-aead-iv-aes128gcm"` |
| AES-GCM-256 encryption IV | `"scorehsm-aead-iv-aes256gcm"` |
| AES-CCM-128 encryption IV | `"scorehsm-aead-iv-aes128ccm"` |
| KDF output key material | `"scorehsm-kdf-okm-<purpose>"` |

---

## 4. Session Management Group (SMG)

### TSR-SMG-01 — Session Handle Map with Ownership

**ASIL:** B
**Derived from:** FSR-12

**Statement:** The library shall maintain an in-process `HashMap<SessionId, HashSet<KeyHandle>>` that records, for each active session, the set of key handles issued within that session. Every operation that accepts a key handle shall first look up the handle in the caller's session's handle set. If the handle is not present in that session's set (even if it is valid in another session's set), the operation shall return `HsmError::InvalidHandle`.

**Parameters:**
- Data structure: `HashMap<SessionId, HashSet<KeyHandle>>` (Rust std)
- Lookup: O(1) expected
- Handle type: `u32` opaque, assigned by L55, echoed to host on key creation

---

### TSR-SMG-02 — Session Inactivity Timeout via Monotonic Clock

**ASIL:** B
**Derived from:** FSR-13

**Statement:** Each session shall record the timestamp of its last completed operation using `std::time::Instant`. A background sweep (executed at most once per second) shall check all active sessions and terminate any session whose last-activity timestamp predates `Instant::now() - session_timeout`. The default session timeout shall be 300 seconds. The timeout shall be configurable via the `HsmConfig` struct at library initialization. Terminated sessions shall invalidate all associated key handles and emit a `SessionExpired` IDS hook event.

**Parameters:**
- Default timeout: 300 s (configurable)
- Sweep interval: ≤1 s
- Clock source: `std::time::Instant` (monotonic, cannot roll back)
- Termination effect: session removed, handles invalidated, IDS event emitted

---

### TSR-SMG-03 — Maximum Concurrent Sessions

**ASIL:** B
**Derived from:** FSR-14 (resource bound component)

**Statement:** The library shall enforce a configurable maximum number of concurrent sessions (default: 8). Requests to open a new session when the maximum is reached shall return `HsmError::ResourceExhausted`. This prevents unbounded memory growth and ensures the session map remains bounded.

**Parameters:**
- Default maximum: 8 sessions
- Configurable: yes, via `HsmConfig::max_sessions`
- Error on exceed: `HsmError::ResourceExhausted`

---

## 5. Rate Limiting Group (RLG)

### TSR-RLG-01 — Token-Bucket Rate Limiter per Operation Class

**ASIL:** B
**Derived from:** FSR-14

**Statement:** The library shall implement a token-bucket rate limiter for the following expensive operation classes:

| Operation class | Default rate (ops/s) | Default burst |
|---|---|---|
| ECDSA sign | 10 | 5 |
| ECDSA verify | 20 | 10 |
| ECC key generation | 2 | 1 |
| ECDH key agreement | 10 | 5 |
| AES-GCM encrypt/decrypt | 100 | 20 |

The token bucket shall be global (across all sessions). Requests that arrive when the bucket for their operation class is empty shall return `HsmError::RateLimitExceeded` immediately (no queueing). Rate parameters shall be configurable via `HsmConfig::rate_limits` at initialization.

**Rationale:** PKA operations on the L55 take ~50–200 ms. Without rate limiting, a single session could monopolize the HSM with ECDSA requests, starving safety-critical callers.

---

## 6. Safe State Group (SSG)

### TSR-SSG-01 — Safe State Transition State Machine

**ASIL:** B
**Derived from:** FSR-10, FSR-11

**Statement:** The library shall implement an explicit library state machine with states: `Initializing → Ready ⇄ Operating → SafeState → (requires reinit)`. The transition `Operating → SafeState` shall be triggered by any of the following events:
- `HsmError::CrcMismatch` after max retries (TSR-TIG-04)
- Sequence number mismatch (TSR-TIG-02)
- Session state integrity check failure
- L55 fault opcode received
- Key store inconsistency detected on access

In `SafeState`, all incoming operation requests shall return `HsmError::SafeState` immediately without contacting the L55. Re-initialization via `hsm_reinit()` transitions from `SafeState` back to `Initializing`.

**Parameters:**
- State enum: `{Initializing, Ready, Operating, SafeState}`
- State variable: `AtomicU8` (thread-safe, memory-order SeqCst for transitions)
- SafeState entry: also invalidates all sessions (calls TSR-SMG-01 teardown)
- SafeState entry: emits `LibrarySafeState` IDS hook event with triggering condition

---

### TSR-SSG-02 — Integrity Check on Key Store Access

**ASIL:** B
**Derived from:** FSR-10

**Statement:** The in-process key store metadata (the `HashMap<SessionId, HashSet<KeyHandle>>`) shall carry a checksum (CRC-32 of serialized map content) that is verified on every read access. If the checksum does not match, the library shall enter safe state (TSR-SSG-01) and return `HsmError::IntegrityViolation`. The checksum shall be updated on every write access.

**Rationale:** An in-process memory corruption event (e.g., buffer overflow in another module) could corrupt the session-handle map, causing invalid handles to appear valid.

---

## 7. Key Lifecycle Group (KLG)

### TSR-KLG-01 — Key Material Zeroize on Drop

**ASIL:** B(d)
**Derived from:** FSR-05

**Statement:** Any Rust type that contains key material (including `SoftwareBackend` key store, `KeyMaterial` struct, intermediate key import buffers) shall implement `ZeroizeOnDrop` via the `zeroize` crate. The compiler-generated `drop()` shall overwrite the key bytes with zeros before deallocating. A compile-time assertion (`static_assert`) shall verify that the zeroize attribute is present on every key-material-containing type.

**Implementation note:** Already implemented as of code review CR-SW-01. This TSR provides the requirements traceability.

---

### TSR-KLG-02 — No Key Export Opcode

**ASIL:** B(d)
**Derived from:** FSR-04

**Statement:** The USB CDC opcode table shall contain no opcode that returns raw key material from the L55 to the host. The opcode enumeration shall be audited at every firmware release to confirm this invariant. The opcode audit shall be documented in the verification report.

**Implementation note:** Confirmed in existing architecture. This TSR formalizes the requirement.

---

## 8. Identity Verification Group (IVG)

### TSR-IVG-01 — Startup Capability Handshake

**ASIL:** B
**Derived from:** FSR-15

**Statement:** During `hsm_init()`, the library shall execute the following sequence before any crypto operation is accepted:

1. Open USB CDC device, verify VID = `0x0483`, PID = `0xXXXX` (scorehsm product ID TBD)
2. Send `CMD_GET_CAPABILITIES` frame (sequence number 0)
3. Receive response: verify CRC-32, verify sequence number echo = 0, extract firmware version and capability bitmask
4. Verify firmware version ≥ minimum supported version (configurable)
5. Verify capability bitmask includes all required operations for the configured profile
6. If any step fails: return `HsmError::InitializationFailed`, library remains in `Initializing` state (does not proceed to `Ready`)
7. Store the verified VID/PID and firmware version in library state
8. On any subsequent USB re-enumeration: verify VID/PID again; if changed, enter safe state

**Parameters:**
- VID: `0x0483` (STMicroelectronics)
- PID: TBD (reserved for scorehsm firmware product)
- Minimum firmware version: configurable, default = current release version

---

## 9. Certificate Group (CG)

### TSR-CG-01 — Certificate Validity Window Check

**ASIL:** B
**Derived from:** FSR-16

**Statement:** Before any operation that uses a certificate (ECDSA verification with certificate-bound public key, X.509 chain validation, TLS certificate processing), the library shall:

1. Extract the `notBefore` and `notAfter` fields from the certificate's TBSCertificate
2. Read the current time from `std::time::SystemTime::now()`
3. Reject the certificate if `now < notBefore` (not yet valid)
4. Reject the certificate if `now > notAfter` (expired)
5. Return `HsmError::CertificateExpired` (for expired) or `HsmError::CertificateNotYetValid` (for pre-valid)
6. If the system clock is unavailable or returns an error, reject all certificate operations with `HsmError::ClockUnavailable`

**Rationale for clock unavailability handling:** A library that proceeds with certificate validation when the clock is unavailable cannot enforce expiry — it effectively treats all certificates as valid indefinitely. This violates FSR-16.

---

## 10. TSR Summary Table

| ID | ASIL | FSR | Group | Short Title |
|---|---|---|---|---|
| TSR-TIG-01 | B | FSR-08 | Transport | CRC-32/MPEG-2 on every frame |
| TSR-TIG-02 | B | FSR-09 | Transport | 32-bit monotonic sequence number, no wrap |
| TSR-TIG-03 | B | FSR-10 | Transport | Per-operation command timeout |
| TSR-TIG-04 | B | FSR-08, FSR-10 | Transport | 2-retry back-off; safe state after 3 consecutive failures |
| TSR-NMG-01 | B | FSR-06, FSR-07 | Nonce | Per-key 64-bit counter in SQLite WAL |
| TSR-NMG-02 | B | FSR-06 | Nonce | HKDF domain separation, non-empty info string |
| TSR-SMG-01 | B | FSR-12 | Session | HashMap<SessionId, HashSet<KeyHandle>> with session scope check |
| TSR-SMG-02 | B | FSR-13 | Session | Inactivity timeout via `Instant`, 300 s default |
| TSR-SMG-03 | B | FSR-14 | Session | Max 8 concurrent sessions |
| TSR-RLG-01 | B | FSR-14 | Rate | Token bucket per operation class |
| TSR-SSG-01 | B | FSR-10, FSR-11 | Safe State | State machine with AtomicU8, SafeState blocks all ops |
| TSR-SSG-02 | B | FSR-10 | Safe State | CRC-32 checksum on key store map |
| TSR-KLG-01 | B(d) | FSR-05 | Key Lifecycle | ZeroizeOnDrop on all key-material types |
| TSR-KLG-02 | B(d) | FSR-04 | Key Lifecycle | No export opcode in USB protocol |
| TSR-IVG-01 | B | FSR-15 | Identity | Startup capability handshake with VID/PID + version |
| TSR-CG-01 | B | FSR-16 | Certificate | notBefore/notAfter check against system clock |

---

*Document end — SCORE-TSR rev 1.0 — 2026-03-14*
