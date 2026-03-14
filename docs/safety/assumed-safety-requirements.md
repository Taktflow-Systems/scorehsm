# scorehsm — Assumed Safety Requirements (ASRs)

Date: 2026-03-14
Standard: ISO 26262-10:2018 §9.3 — SEooC integration
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-ASR

---

## 1. Purpose

Assumed Safety Requirements (ASRs) define the conditions that the integrator must satisfy for the ASIL B claim of `scorehsm` to be valid at vehicle level. They are obligations on the integration context, not on the `scorehsm` element itself.

Per ISO 26262-10:2018 §9.3, the integrator shall:
1. Confirm that each ASR is met by the item design, or
2. Provide additional safety measures to compensate where an ASR cannot be met, or
3. Re-derive the safety case if the ASR cannot be met and no compensation is feasible.

The `scorehsm` ASIL B safety integrity claim is **conditional** on all ASRs being satisfied.

---

## 2. Hardware Platform ASRs

### ASR-HW-01 — TrustZone Enforcement Active

**Statement:** The STM32L552 shall be configured with TrustZone active and SAU/IDAU programmed such that the Secure-world SRAM2 region containing key material is inaccessible from the Non-Secure world. Any NS attempt to access S-world memory shall trigger a SecureFault exception.

**ASIL:** B(d) — hardware side of the SG-03 decomposition

**Verification:** Integrator shall provide evidence of SAU configuration register values and a test showing that a deliberate NS access to S-world SRAM raises a SecureFault.

**Rationale:** Without hardware enforcement, software key isolation (SG-03) is not achievable at ASIL B.

---

### ASR-HW-02 — SWD Debug Port Locked in Production

**Statement:** In production-grade hardware, SWD/JTAG debug access to the L55 shall be locked (RDP Level 2 or equivalent). Development boards used in testing and CI are exempt.

**ASIL:** B

**Verification:** Integrator shall document the programming step that sets RDP Level 2 in the production flashing procedure, with evidence that the lock is irreversible.

**Rationale:** An unlocked SWD port enables direct memory read of S-world SRAM, bypassing all software key isolation (violates SG-03).

---

### ASR-HW-03 — Genuine STM32L552 Device

**Statement:** The hardware device connected to the USB CDC interface shall be a genuine STM32L552ZE-Q running the production `scorehsm` firmware. The integrator shall implement device identity verification at startup (VID/PID check plus capability handshake, per S1 countermeasure in the threat model).

**ASIL:** B

**Verification:** Integrator shall provide test evidence that startup rejects a simulated rogue USB device.

**Rationale:** A rogue device substituted on the USB port can return attacker-controlled RNG output, forged verification results, or trigger SG-01/SG-02 violations.

---

### ASR-HW-04 — USB Physical Protection

**Statement:** The USB cable connecting the host platform to the L55 HSM shall be routed inside the vehicle harness and not externally accessible to an unaided attacker during normal vehicle operation. An integrator who cannot guarantee physical protection shall implement USB-layer encryption (see RR1 in threat model).

**ASIL:** B

**Verification:** Integrator provides a statement in the safety case covering physical routing.

**Rationale:** An accessible USB cable allows plaintext sniffing and replay (I3, S2 in threat model). Physical protection is the baseline mitigation; USB-layer encryption is the software alternative.

---

### ASR-HW-05 — Trusted Time Source Available

**Statement:** The host platform shall provide a monotonic clock with at least 1-second resolution that does not roll back. The clock shall be used by `scorehsm` for session timeout enforcement and certificate expiry validation.

**ASIL:** B

**Verification:** Integrator shall demonstrate that the clock source is protected against software manipulation and survives ECU reset.

**Rationale:** Without a trusted time source, session timeout (SSR for SG-06) and certificate expiry (SSR for SG-01/SG-02) cannot be enforced.

---

## 3. Operating System / Platform ASRs

### ASR-OS-01 — Process Isolation

**Statement:** The OS on the host platform shall enforce process isolation such that a compromised application process cannot read the memory of the `scorehsm-host` process or inject data into its address space.

**ASIL:** B (maps to T4 accepted risk boundary in threat model)

**Verification:** Integrator provides evidence of OS hardening measures (e.g., SELinux policy, AppArmor profile, memory-safe kernel configuration) covering the `scorehsm-host` process.

**Rationale:** `scorehsm-host` holds session state and key handles in process memory. Without OS isolation, an attacker with a foothold in another process can access these.

---

### ASR-OS-02 — Supply Chain Integrity for `scorehsm-host` Binary

**Statement:** The integrator shall deploy `scorehsm-host` binaries that are built from a verified, unmodified source tree (verified by hash or code signature) and distributed via an integrity-protected channel.

**ASIL:** B (maps to T4 out-of-scope boundary)

**Verification:** Integrator provides hash of deployed binary and build reproducibility evidence.

**Rationale:** A tampered binary could log key handles, bypass access control, or return attacker-controlled data — defeating all software-side safety properties.

---

### ASR-OS-03 — Single Active Instance per Device

**Statement:** No more than one instance of `scorehsm-host` shall run concurrently on a single host-to-L55 interface. The OS integration layer shall enforce this with a lock file or platform-level singleton mechanism.

**ASIL:** B

**Verification:** Integrator demonstrates that a second startup attempt is rejected while the first is running.

**Rationale:** Two concurrent instances sharing one USB device result in interleaved command/response frames, breaking sequence number ordering (SG-05) and session isolation (SG-07).

---

## 4. Integration / Configuration ASRs

### ASR-INT-01 — ASIL B Integration Context

**Statement:** The integrator shall deploy `scorehsm` only in integration contexts whose vehicle-level safety goals require at most ASIL B. If `scorehsm` is used in an ASIL C or D context, the integrator shall perform a gap analysis and additional hardening before deployment.

**ASIL:** B

**Verification:** Integrator HARA extract showing that the `scorehsm` function is in the ASIL B safety goal decomposition.

---

### ASR-INT-02 — Caller Error Handling

**Statement:** Every caller of `scorehsm-host` API functions shall handle `HsmError` return values and shall not use output buffers when an error is returned. The integrator shall not suppress or ignore errors in application code.

**ASIL:** B

**Verification:** Code review of application integration layer demonstrating `?` propagation or explicit error handling at every call site.

**Rationale:** An application that ignores a failed verification result and proceeds (e.g., `let _ = hsm.verify(...)`) defeats SG-01 at the application layer.

---

### ASR-INT-03 — Rate Limiting Not Bypassed

**Statement:** The integrator shall not disable the `scorehsm` rate limiter configuration (see HSM-REQ-057). If the integrator requires higher throughput, they shall perform a safety analysis demonstrating that the increased rate does not exhaust HSM resources and starve safety-critical operations.

**ASIL:** B

**Verification:** Configuration review confirming rate limiter is enabled in production build.

---

### ASR-INT-04 — Key Provisioning Integrity

**Statement:** Cryptographic keys provisioned into the L55 HSM shall be generated by a trusted key management system, transferred via an authenticated and encrypted channel, and audited. The provisioning procedure is out of scope for `scorehsm` but is a prerequisite for the element's safety properties.

**ASIL:** B

**Verification:** Integrator provides key management system documentation and provisioning audit log format.

**Rationale:** A weak or compromised key is equivalent to no key isolation — the element's entire safety argument depends on the keys being secret and unpredictable.

---

## 5. ASR Summary Table

| ID | Category | ASIL | Short Statement |
|---|---|---|---|
| ASR-HW-01 | Hardware | B(d) | TrustZone enforcement active in production |
| ASR-HW-02 | Hardware | B | SWD locked at RDP Level 2 in production |
| ASR-HW-03 | Hardware | B | Genuine L55 device verified at startup |
| ASR-HW-04 | Hardware | B | USB physically protected or USB-layer encryption used |
| ASR-HW-05 | Hardware | B | Monotonic clock available for timeout/expiry |
| ASR-OS-01 | OS/Platform | B | Process isolation enforced by OS |
| ASR-OS-02 | OS/Platform | B | Binary supply chain integrity verified |
| ASR-OS-03 | OS/Platform | B | Single active instance per interface |
| ASR-INT-01 | Integration | B | Integration context ≤ ASIL B |
| ASR-INT-02 | Integration | B | All API errors handled by caller |
| ASR-INT-03 | Integration | B | Rate limiter not disabled |
| ASR-INT-04 | Integration | B | Keys provisioned via trusted KMS |

---

## 6. Integrator Verification Checklist

The integrator shall complete and retain the following checklist prior to SOP:

```
□ ASR-HW-01: SAU configuration evidence attached
□ ASR-HW-02: Production flashing procedure reviewed and RDP Level 2 confirmed
□ ASR-HW-03: Startup device verification test result attached
□ ASR-HW-04: Physical routing documented OR USB encryption enabled
□ ASR-HW-05: Clock source specification and protection evidence attached
□ ASR-OS-01: OS hardening review complete (SELinux/AppArmor policy attached)
□ ASR-OS-02: Binary hash and build evidence attached
□ ASR-OS-03: Singleton enforcement test result attached
□ ASR-INT-01: HARA extract showing ASIL B context attached
□ ASR-INT-02: Integration layer code review record attached
□ ASR-INT-03: Configuration review confirming rate limiter enabled
□ ASR-INT-04: KMS documentation and provisioning audit format attached
```

---

*Document end — SCORE-ASR rev 1.0 — 2026-03-14*
