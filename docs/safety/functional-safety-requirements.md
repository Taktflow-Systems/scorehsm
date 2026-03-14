# scorehsm — Functional Safety Requirements (FSR)

Date: 2026-03-14
Standard: ISO 26262-6:2018 §6
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-FSR

---

## 1. Purpose

Functional Safety Requirements (FSRs) define **what** the `scorehsm` software element must do to satisfy the Safety Goals (SCORE-SG). They are technology-neutral statements of required software behavior, expressed at the system boundary level (caller ↔ `scorehsm-host` library). Each FSR is traced to one or more Safety Goals and is the input to Technical Safety Requirements (SCORE-TSR).

**Traceability direction:** SG → FSR → TSR → SSR → test

---

## 2. Functional Safety Requirements

### FSR-01 — Verification Operations Shall Return Only Definitive Pass or Fail

**ASIL:** B
**Derived from:** SG-01

**Statement:** Every cryptographic verification operation (signature verification, MAC verification, AEAD decryption with tag verification) shall return either a definitive success result or an error. The element shall never return partial plaintext, partial signature validity, or an indeterminate result from a verification operation.

**Rationale:** An indeterminate result leaves the caller in an ambiguous state that may be incorrectly interpreted as success, enabling a false-positive verification (SG-01 violation).

**Safety measure type:** Error detection — return-value contract

---

### FSR-02 — Verification Shall Use Constant-Time Comparison

**ASIL:** B
**Derived from:** SG-01

**Statement:** All comparison operations that determine the outcome of a cryptographic verification (tag comparison, signature comparison, MAC comparison) shall execute in constant time with respect to the secret comparison target. Timing differences that leak information about the correct value are prohibited.

**Rationale:** Timing side-channels allow an attacker to iteratively probe the correct tag or signature byte-by-byte, eventually producing a valid-appearing result without knowing the key — an indirect path to SG-01 violation.

**Safety measure type:** Error detection — side-channel resistance

---

### FSR-03 — All Outputs Shall Be Integrity-Checked Before Return

**ASIL:** B
**Derived from:** SG-02

**Statement:** Every value returned from the hardware HSM to the host library (decrypted plaintext, computed signature, RNG output, key operation result) shall be validated for transport integrity before being returned to the caller. If integrity validation fails, an error shall be returned and the output value shall not be used.

**Rationale:** A transport fault (USB bit error, DMA error, buffer overflow) can silently corrupt an output value. Without explicit integrity checking, the corrupted value is returned as if valid (SG-02 violation).

**Safety measure type:** Error detection — end-to-end integrity check

---

### FSR-04 — Key Material Shall Not Appear in Any Output

**ASIL:** B(d)
**Derived from:** SG-03

**Statement:** The `scorehsm-host` library shall not provide any function, diagnostic output, error message, or log entry that returns raw cryptographic key material. The API shall operate exclusively on key handles (opaque integer identifiers). Raw key bytes shall not appear in any user-accessible buffer, log stream, or error payload.

**Rationale:** Direct key disclosure defeats all cryptographic protections (SG-03).

**Safety measure type:** Secure design — no key export

---

### FSR-05 — Key Material in Host Memory Shall Be Zeroized After Use

**ASIL:** B(d)
**Derived from:** SG-03

**Statement:** Any transient copies of key material that must exist in host process memory (e.g., during key import from a secure channel before transmission to L55) shall be overwritten with zeros immediately after use, before the memory is released.

**Rationale:** Key material left in freed heap memory can be recovered by another process or via a core dump (SG-03 violation even if no API export exists).

**Safety measure type:** Error detection — secure memory lifecycle

---

### FSR-06 — Nonce Shall Be Unique per (Key, Algorithm) Invocation

**ASIL:** B
**Derived from:** SG-04

**Statement:** For every AEAD encryption invocation, the library shall guarantee that the nonce supplied to the HSM has not been used before with the same key in the same algorithm context. The library shall maintain a nonce counter per key handle and reject any nonce that equals or predates the last-used nonce.

**Rationale:** AES-GCM nonce reuse with the same key produces ciphertexts from which an attacker can recover plaintext XOR and forge authentication tags (SG-04 violation).

**Safety measure type:** Error prevention — nonce management

---

### FSR-07 — Nonce Counter Shall Survive Process Restart

**ASIL:** B
**Derived from:** SG-04

**Statement:** The per-key nonce counter used for uniqueness enforcement (FSR-06) shall be persisted to non-volatile storage and restored on library initialization. A library that restarts from zero on every process start does not satisfy FSR-06 across restarts.

**Rationale:** If the nonce counter resets on restart, the first N nonces after restart are guaranteed reuses of nonces issued before the restart.

**Safety measure type:** Error prevention — persistent state

---

### FSR-08 — Frame Corruption Shall Be Detected on Every USB Transaction

**ASIL:** B
**Derived from:** SG-05

**Statement:** Every USB CDC command frame sent to the L55 and every response frame received from the L55 shall carry a frame integrity check value (FICS) computed over the entire frame payload. The library shall verify the FICS before processing any response frame. Frames failing the FICS check shall be rejected and an error returned to the caller.

**Rationale:** USB cables in automotive environments experience EMI. Silent corruption of a command or response frame maps directly to SG-02 and SG-05 violations.

**Safety measure type:** Error detection — CRC / frame integrity

---

### FSR-09 — Command/Response Pairing Shall Use Sequence Numbers

**ASIL:** B
**Derived from:** SG-05

**Statement:** Each USB command frame shall carry a monotonically increasing sequence number. The corresponding response frame shall echo this sequence number. The library shall reject any response whose sequence number does not match the pending command's sequence number. Out-of-sequence responses shall be treated as transport errors.

**Rationale:** Without sequence number correlation, a delayed or replayed response to a previous command could be incorrectly associated with a different command, producing the wrong output for the wrong operation (SG-05 violation).

**Safety measure type:** Error detection — sequence number

---

### FSR-10 — Integrity Fault Shall Trigger Defined Safe State

**ASIL:** B
**Derived from:** SG-06

**Statement:** Upon detection of any of the following conditions, the library shall immediately enter the defined safe state (defined in FSR-11):
- FICS failure on a response frame (FSR-08)
- Sequence number mismatch (FSR-09)
- Session state inconsistency detected during internal consistency check
- Hardware fault notification from the L55 (fault opcode in response)
- Key store integrity check failure

**Rationale:** These are indicators of hardware faults, firmware corruption, or active attacks. Continuing operation in a compromised state produces arbitrary results (SG-06 violation).

**Safety measure type:** Error response — safe state entry

---

### FSR-11 — Safe State Definition

**ASIL:** B
**Derived from:** SG-06

**Statement:** The safe state of `scorehsm-host` is defined as follows:
1. All pending asynchronous operations are aborted with error return
2. All active sessions are invalidated (handles become invalid)
3. The library refuses all further operation requests with `HsmError::SafeState`
4. A safe state entry event is emitted to the IDS hook with the triggering condition
5. Re-initialization requires an explicit `hsm_reinit()` call from the application

**Rationale:** A clear, defined safe state allows the integrator's supervisor task to detect and respond to the condition rather than observing silent incorrect results.

**Safety measure type:** Error response — safe state definition

---

### FSR-12 — Session Handles Shall Not Be Transferable Between Sessions

**ASIL:** B
**Derived from:** SG-07

**Statement:** A key handle issued to Session A shall be valid only within the context of Session A. Presenting Session A's handle in the context of Session B (or without an associated session) shall result in `HsmError::InvalidHandle`. The library shall enforce session-handle binding for every operation that accepts a key handle.

**Rationale:** Handle transferability allows one application to leverage another's keys — a session isolation failure (SG-07 violation).

**Safety measure type:** Access control — session-scoped handles

---

### FSR-13 — Session Shall Time Out After Inactivity

**ASIL:** B
**Derived from:** SG-06, SG-07

**Statement:** A session with no completed operation for longer than the configured session timeout period shall be automatically terminated by the library. On automatic termination, all handles associated with the session shall be invalidated and a session-expired event shall be emitted to the IDS hook.

**Rationale:** An abandoned session with valid handles represents an ongoing attack surface. Automatic termination bounds the window during which a compromised application can exploit stale handles.

**Safety measure type:** Error prevention — session lifecycle

---

### FSR-14 — Operation Rate Shall Be Limited per Type

**ASIL:** B
**Derived from:** SG-06

**Statement:** The library shall enforce a configurable maximum rate for each expensive HSM operation type (ECDSA sign, ECDSA verify, key generation). Requests that exceed the rate limit shall be rejected with `HsmError::RateLimitExceeded`. The rate limit shall be enforced globally across all sessions.

**Rationale:** Unconstrained ECDSA or key generation flood exhausts the L55 PKA peripheral, starving other callers including safety-critical ones (SG-06: denial of service causes inability to complete safety-critical operations in time).

**Safety measure type:** Error prevention — rate control

---

### FSR-15 — Library Initialization Shall Verify Hardware Identity

**ASIL:** B
**Derived from:** SG-01, SG-02, SG-06 (ASR-HW-03 complementary)

**Statement:** During library initialization, the host library shall perform a device identity verification sequence: USB VID/PID check, capability handshake, and firmware version exchange. If any step fails, initialization shall fail with an error and the library shall remain in safe state. A successfully initialized library shall maintain the verified device identity and reject commands if the device identity changes unexpectedly (e.g., unexpected USB re-enumeration with different VID/PID).

**Rationale:** A rogue device on the USB port returns attacker-controlled outputs for all subsequent operations — defeating SG-01 and SG-02 from the first command.

**Safety measure type:** Error detection — device identity

---

### FSR-16 — Certificate Expiry Shall Be Verified Before Use

**ASIL:** B
**Derived from:** SG-01

**Statement:** Before using a certificate (e.g., in ECDSA verification against a certificate-bound public key, or in X.509 chain validation), the library shall check the certificate's `notAfter` field against the current time from the trusted clock. An expired certificate shall cause the operation to fail with `HsmError::CertificateExpired`. An unverified or untrusted clock shall cause the library to reject certificate-based operations.

**Rationale:** An expired certificate may have a revoked or compromised key. Accepting it as valid allows a compromised entity to continue asserting trust (SG-01 violation).

**Safety measure type:** Error detection — certificate lifecycle

---

## 3. FSR Summary Table

| ID | ASIL | Safety Goal | Safety Measure Type | Short Title |
|---|---|---|---|---|
| FSR-01 | B | SG-01 | Error detection | Verification returns definitive pass/fail only |
| FSR-02 | B | SG-01 | Error detection | Constant-time comparison |
| FSR-03 | B | SG-02 | Error detection | All HSM outputs integrity-checked before return |
| FSR-04 | B(d) | SG-03 | Secure design | No key material in any output |
| FSR-05 | B(d) | SG-03 | Secure lifecycle | Transient key material zeroized after use |
| FSR-06 | B | SG-04 | Error prevention | Nonce unique per (key, algo) invocation |
| FSR-07 | B | SG-04 | Error prevention | Nonce counter persisted across restarts |
| FSR-08 | B | SG-05 | Error detection | Frame FICS on every USB transaction |
| FSR-09 | B | SG-05 | Error detection | Sequence numbers on command/response pairs |
| FSR-10 | B | SG-06 | Error response | Integrity fault triggers safe state |
| FSR-11 | B | SG-06 | Error response | Safe state defined and observable |
| FSR-12 | B | SG-07 | Access control | Session-scoped handle binding |
| FSR-13 | B | SG-06, SG-07 | Error prevention | Session inactivity timeout |
| FSR-14 | B | SG-06 | Error prevention | Per-type operation rate limiting |
| FSR-15 | B | SG-01, SG-02, SG-06 | Error detection | Hardware identity verified at init |
| FSR-16 | B | SG-01 | Error detection | Certificate expiry checked against trusted clock |

---

## 4. Allocation Note

FSRs are allocated to the `scorehsm-host` library (software). Each FSR is further refined into Technical Safety Requirements (SCORE-TSR) which specify the mechanism (CRC-32 polynomial, counter storage location, session handle map structure, etc.) and then into Software Safety Requirements (SSR, in requirements.md §HSM-REQ-050..099) which are directly implementable and testable.

---

*Document end — SCORE-FSR rev 1.0 — 2026-03-14*
