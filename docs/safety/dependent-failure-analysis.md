# scorehsm — Dependent Failure Analysis (DFA)

Date: 2026-03-14
Standard: ISO 26262-6:2018 §7.4.15 / ISO 26262-9 §7
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-DFA

---

## 1. Purpose and Scope

Dependent Failure Analysis (DFA) is mandatory for ASIL B per ISO 26262-6 §7.4.15 and ISO 26262-9 §7. It identifies:

- **Common Cause Failures (CCF)**: a single root cause simultaneously defeating two or more safety mechanisms
- **Cascading Failures**: a failure in one component propagating and defeating a second safety mechanism

**Scope:** Software host library (`scorehsm-host`) and its interaction with the STM32L552 hardware backend over USB CDC. Hardware-internal failures are covered by the hardware FMEA (not in scope here).

**Safety mechanisms analyzed:** The 16 TSRs defined in SCORE-TSR, which implement the 7 Safety Goals.

---

## 2. DFA Methodology

For each pair of safety mechanisms that protect the same or complementary safety goals, this analysis asks:

> *"Can a single event simultaneously defeat both mechanisms?"*

If yes → CCF identified → mitigation required.
If a failure of mechanism A creates conditions under which mechanism B can no longer operate → Cascading failure → mitigation required.

**Independence criterion (ISO 26262-9 §7.4.7):** Two mechanisms are considered sufficiently independent if no single software fault, hardware fault, or external perturbation can defeat both simultaneously.

---

## 3. Safety Mechanism Inventory

| ID | Mechanism | TSR | Protects SG |
|---|---|---|---|
| SM-01 | CRC-32/MPEG-2 on every frame | TSR-TIG-01 | SG-05 |
| SM-02 | Monotonic 32-bit sequence number | TSR-TIG-02 | SG-05 |
| SM-03 | Per-operation command timeout | TSR-TIG-03 | SG-05, SG-06 |
| SM-04 | Retry with back-off; safe state after 3× | TSR-TIG-04 | SG-05, SG-06 |
| SM-05 | Per-key 64-bit nonce counter in SQLite WAL | TSR-NMG-01 | SG-04 |
| SM-06 | HKDF domain separation | TSR-NMG-02 | SG-04 |
| SM-07 | Session-scoped key handle map | TSR-SMG-01 | SG-07 |
| SM-08 | Session inactivity timeout | TSR-SMG-02 | SG-07 |
| SM-09 | Max concurrent sessions | TSR-SMG-03 | SG-06 |
| SM-10 | Token-bucket rate limiter | TSR-RLG-01 | SG-06 |
| SM-11 | Library state machine (SafeState) | TSR-SSG-01 | SG-06 |
| SM-12 | Key store CRC-32 integrity check | TSR-SSG-02 | SG-06 |
| SM-13 | ZeroizeOnDrop on key-material types | TSR-KLG-01 | SG-03 |
| SM-14 | No export opcode in USB protocol | TSR-KLG-02 | SG-03 |
| SM-15 | Startup capability handshake (VID/PID) | TSR-IVG-01 | SG-06 |
| SM-16 | Certificate validity window check | TSR-CG-01 | SG-01 |

---

## 4. Common Cause Failure Analysis

### CCF-01: Memory Corruption Affecting CRC Engine and Sequence Counter

**Mechanisms:** SM-01 (CRC) + SM-02 (seq#)
**Common cause:** Buffer overflow in USB CDC receive buffer corrupts both the CRC state variable and the sequence counter variable
**Effect:** CRC check passes (corrupted expected value), sequence number matches (corrupted expected value) → forged frame accepted
**Severity:** High — both transport integrity guards defeated simultaneously

**Mitigation:**
- SM-01 state (CRC lookup table) and SM-02 state (sequence counter) are stored in separate memory regions: CRC is computed on-the-fly (no state variable beyond the running CRC value); seq# is an `AtomicU32` in the `MockHardwareBackend` struct.
- The `AtomicU32` for seq# is separated from the frame receive buffer by at least one struct field boundary.
- Safe state (SM-11) is triggered by either CRC mismatch or seq# mismatch — even if only one mechanism is corrupted, the other detects the anomaly.
- **Residual CCF risk:** Low. A corruption event large enough to hit both structures would also corrupt the library state machine (SM-11), which is separately protected by `AtomicU8` with `SeqCst` ordering.

**Classification:** Residual — mitigated

---

### CCF-02: Clock Source Failure Affecting Timeout and Session Timeout

**Mechanisms:** SM-03 (command timeout via `Instant`) + SM-08 (session timeout via `Instant`)
**Common cause:** `std::time::Instant` becoming unavailable or monotonicity broken (OS bug, VM clock issue)
**Effect:** Both timeout mechanisms fail simultaneously — commands hang indefinitely; sessions never expire
**Severity:** Medium — availability impact; safety impact if HSM operations are blocking safety-critical path

**Mitigation:**
- Both SM-03 and SM-08 use the same `std::time::Instant` clock source (monotonic, cannot go backward per Rust documentation). This is a deliberate shared dependency.
- Since the clock failure affects both non-safety-independently, this is flagged as a CCF with the following mitigations:
  1. SM-04 (retry/safe state) provides a count-based fallback: after 3 consecutive failures, safe state is entered regardless of timeout.
  2. SM-11 (library state machine) provides an upper bound: persistent transport failures eventually trigger safe state.
  3. Integrators are required (ASR-HW-05) to provide a trusted, monotonic real-time clock. Clock unavailability on the integration platform is an integrator responsibility.
- **Residual CCF risk:** Low-Medium. Mitigated by SM-04 count-based safe state.

**Classification:** Residual — mitigated by SM-04

---

### CCF-03: Zeroize Library Bug Defeating Both Key Protection Mechanisms

**Mechanisms:** SM-13 (ZeroizeOnDrop) + SM-14 (no export opcode)
**Common cause:** A bug in the `zeroize` crate or compiler optimization eliminating the zero-write
**Effect:** Key material remains in memory after `Drop`; if SM-14 were also compromised, material could be read
**Severity:** High (ASIL B(d) — SG-03 decomposed)

**Mitigation:**
- SM-13 and SM-14 are **architecturally independent mechanisms**: SM-13 is a software memory operation; SM-14 is a protocol-level constraint (USB opcode table).
- A `zeroize` crate bug cannot affect SM-14 (USB opcode table is in firmware).
- A firmware opcode table change cannot affect SM-13 (software memory zeroization).
- The ASIL B(d) decomposition explicitly requires that each half independently satisfy ASIL B(d). The dual-channel structure (SW zeroize + HW non-export) means both must fail for SG-03 to be violated.
- Compile-time assertion (`const _: fn()`) verifies `ZeroizeOnDrop` bound at every build. Optimizer cannot remove `zeroize()` for `volatile` write implementations in the `zeroize` crate v1.x.
- **Residual CCF risk:** Negligible — mechanisms are architecturally independent at HW/SW boundary.

**Classification:** Independent — no residual CCF

---

### CCF-04: Session Map Corruption Defeating Handle Isolation and Integrity Check

**Mechanisms:** SM-07 (session handle map) + SM-12 (key store CRC-32)
**Common cause:** Buffer overflow in caller code corrupting the `HashMap<SessionId, HashSet<KeyHandle>>` in-process memory
**Effect:** Corrupted map accepts invalid handles (SM-07 defeated); corrupted checksum passes (SM-12 defeated)
**Severity:** High — both session isolation mechanisms defeated simultaneously

**Mitigation:**
- SM-12 (CRC-32 on the serialized map) is designed specifically to detect in-process memory corruption. A corruption large enough to corrupt both the map contents and the stored CRC simultaneously is possible, but:
  1. The CRC checksum is stored in a separate field from the map data.
  2. A single targeted overflow would need to corrupt both the map payload and the CRC field simultaneously to evade detection.
  3. SM-11 (library state machine) also performs periodic integrity checks via SM-12 on every map read — a corrupted map is detected on the next operation.
- Safe state (SM-11) is entered on any integrity violation — preventing further operations even if the immediate detection is partial.
- **Residual CCF risk:** Low — mitigation by structural separation + SM-11 detection.

**Classification:** Residual — mitigated by structural separation and SM-11

---

### CCF-05: SQLite WAL Failure Affecting Both Nonce Management and Persistence

**Mechanisms:** SM-05 (nonce counter in SQLite WAL) + SM-06 (HKDF domain separation)
**Common cause:** SQLite database corruption (filesystem error, power loss without WAL sync)
**Effect:** Nonce counter lost (SM-05 may reset to 0, risking reuse); HKDF inputs corrupted
**Severity:** High — nonce reuse is a catastrophic AEAD failure mode (SG-04)

**Mitigation:**
- SQLite WAL with `PRAGMA synchronous=FULL` ensures the counter is flushed to disk before the AEAD operation proceeds. Power loss after the WAL write but before the operation is safe (counter was pre-incremented — see SCORE-TSR TSR-NMG-01).
- A complete SQLite DB corruption event would cause the library to fail to open the database, returning `HsmError::NonceExhausted` or `HsmError::InitializationFailed` — preventing operation with an unknown counter state.
- SM-06 (HKDF domain separation) derives IVs from the nonce counter value using a static `info` string. A corrupted counter value would produce an anomalous but still unique IV (different from the pre-corruption sequence). The uniqueness property is only violated if the counter rolls back to a previously-used value, which is prevented by the WAL pre-increment.
- **Residual CCF risk:** Low — mitigated by SQLite WAL + pre-increment + library refusing to operate on DB error.

**Classification:** Residual — mitigated

---

## 5. Cascading Failure Analysis

### CF-01: Transport Failure Cascading to Safe State Exhaustion

**Trigger:** Persistent EMI or USB cable fault causes repeated CRC failures (SM-01 triggers repeatedly)
**Cascade:** SM-04 (retry) exhausted → SM-11 (SafeState) entered → all operations blocked
**Effect on other mechanisms:** SM-07 (session map) torn down; SM-05 (nonce counter) not updated (no AEAD operations in SafeState). No cascading safety violation — SafeState is the correct response.
**Classification:** Benign cascade (correct fail-safe behavior)

---

### CF-02: Session Expiry Triggering State Machine Under Load

**Trigger:** SM-08 (session timeout sweep) runs while SM-10 (rate limiter) is active
**Cascade:** Background sweep acquires session map lock; rate limiter also needs map access
**Effect:** Potential deadlock if both hold different locks and wait for each other
**Mitigation:**
- Rate limiter and session map use separate `Mutex` instances; lock acquisition order is always `rate_limiter → session_map` (never reverse). Deadlock is prevented by consistent lock ordering (documented in SCORE-SUD §3.4).
- Timeout sweep is a separate background thread with lower priority — it does not hold the rate limiter lock.
**Classification:** Mitigated — lock ordering prevents deadlock

---

### CF-03: Safe State Entry Cascading to Session Destruction

**Trigger:** SM-11 (SafeState) entered due to transport fault
**Cascade:** SafeState entry invalidates all sessions (SM-07 cleared) and all nonce counters suspended
**Effect:** All active sessions terminated; callers receive `HsmError::SafeState`
**Classification:** Intentional cascade — documented in TSR-SSG-01. Callers must handle `SafeState` and re-initialize.

---

### CF-04: Clock Skew Causing Certificate Rejection Cascade

**Trigger:** System clock jumps backward (e.g., NTP sync during operation)
**Cascade:** SM-16 (certificate validity) rejects previously valid certs as "not yet valid" (if `notBefore` is now in the future)
**Effect:** Certificate operations fail with `CertificateNotYetValid`
**Mitigation:**
- SM-08 (session timeout) uses `std::time::Instant` (monotonic, immune to NTP jumps).
- SM-16 (certificate validity) uses `std::time::SystemTime` (can be affected by NTP). This is unavoidable — certificate expiry is wall-clock-based.
- Integrators are required to maintain stable NTP sync (ASR-HW-05). Clock jumps >1 s on safety-critical platforms indicate a system fault that should be reported to the OEM ECU supervisor.
- **Residual cascading risk:** Low-Medium — acceptable for ASIL B; integrator responsibility.

**Classification:** Residual — integrator mitigation required (ASR-HW-05)

---

## 6. Software Design Independence Assessment

For ASIL B, ISO 26262-9 §7.4.7 requires that safety mechanisms for the same safety goal are **sufficiently independent**. The following pairs protect the same SG:

| SG | Mechanism 1 | Mechanism 2 | Independence Assessment |
|---|---|---|---|
| SG-05 | SM-01 (CRC) | SM-02 (seq#) | Different algorithms, different data (CRC over frame bytes; seq# over header field). Low CCF risk (see CCF-01). ✓ |
| SG-05 | SM-01/SM-02 (frame integrity) | SM-03 (timeout) | Orthogonal: frame content vs. time domain. Independent. ✓ |
| SG-04 | SM-05 (nonce counter) | SM-06 (HKDF domain sep.) | Different data + algorithm layers. SM-06 does not depend on SM-05 counter value for domain isolation. ✓ |
| SG-06 | SM-04 (retry/safe state) | SM-11 (state machine) | SM-04 is the trigger; SM-11 is the enforcement. They are the same mechanism at different abstraction levels — intentional, not CCF. ✓ |
| SG-06 | SM-09 (max sessions) | SM-10 (rate limit) | Different data structures (session count vs. token bucket). Independent. ✓ |
| SG-03 | SM-13 (zeroize) | SM-14 (no export opcode) | HW/SW independence — see CCF-03. ✓ |
| SG-07 | SM-07 (handle map) | SM-08 (session timeout) | Different enforcement: active check vs. time-based expiry. Independent. ✓ |

**Conclusion:** All mechanism pairs protecting the same safety goal are sufficiently independent for ASIL B.

---

## 7. DFA Summary

| ID | Type | Mechanisms | Severity | Residual Risk | Disposition |
|---|---|---|---|---|---|
| CCF-01 | CCF | SM-01 + SM-02 | High | Low | Mitigated by SM-11 |
| CCF-02 | CCF | SM-03 + SM-08 | Medium | Low-Medium | Mitigated by SM-04 + integrator |
| CCF-03 | CCF | SM-13 + SM-14 | High | Negligible | Independent by design |
| CCF-04 | CCF | SM-07 + SM-12 | High | Low | Mitigated by structural separation |
| CCF-05 | CCF | SM-05 + SM-06 | High | Low | Mitigated by WAL + pre-increment |
| CF-01 | Cascade | SM-01→SM-11 | — | Benign | Correct fail-safe |
| CF-02 | Cascade | SM-08→SM-10 | Medium | Mitigated | Lock ordering enforced |
| CF-03 | Cascade | SM-11→SM-07 | — | Intentional | Documented design |
| CF-04 | Cascade | Clock→SM-16 | Low-Medium | Residual | Integrator responsibility |

**All residual risks are rated Low or Low-Medium — acceptable for ASIL B SEooC.**

---

## 8. Open Items

None. DFA is complete at software architecture level. Hardware-level DFA (covering STM32L552 TrustZone + USB PHY + PKA co-processor fault modes) is performed by the hardware FMEA team and is outside the scope of this document.

---

*Document end — SCORE-DFA rev 1.0 — 2026-03-14*
