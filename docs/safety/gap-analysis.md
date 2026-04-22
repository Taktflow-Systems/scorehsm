# SCORE-HSM Gap Analysis

| Field | Value |
|-------|-------|
| Document ID | SCORE-GAP |
| Date | 2026-04-22 |
| Revision | 1.1 |
| Status | ACTIVE |
| Scope | Audit of scorehsm safety, verification, and test artefacts against ASIL B release criteria |

---

## 1  Release-Blocking Gaps

Items that would still matter for a full ASIL B release claim. Repository-owned
software evidence is now closed where possible; remaining items are explicitly
deferred rather than left implicitly open.

| ID | Gap | Source | Owner | Target | Status |
|----|-----|--------|-------|--------|--------|
| RB-01 | HIL test execution - 6 of 9 hardware-layer requirements still need bench-only evidence: HSM-REQ-021 (TrustZone key storage), HSM-REQ-029 (constant-time HW), HSM-REQ-031 (TrustZone isolation), HSM-REQ-036 (OS-level protection), HSM-REQ-043 (SRAM2 zeroize), HSM-REQ-046 (secure boot) | SCORE-VER OVI-01 | Embedded Developer | 2026-05-15 | Deferred - hardware evidence not completed in this workspace |
| RB-02 | Coverage extraction and CI gating | SCORE-VER OVI-02 | Host Library Developer | 2026-04-30 | Closed 2026-04-22 - `coverage-summary.json` records 92.54% line coverage and CI now archives both line/function and branch summaries |
| RB-03 | `cargo-llvm-cov` TCL-2 validation | SCORE-TQR T3, SCORE-VER OVI-06 | Tester | 2026-04-01 | Closed 2026-04-22 - `tools/coverage-kat/` KAT reports exactly 50.0% branch coverage |
| RB-04 | T1 independence review sign-off - required for ASIL B procedural compliance (ISO 26262-6 Table 10) | SCORE-VER OVI-05, SCORE-TRM UC-03 | Safety Engineer | Before v0.1.0 | Deferred - independent reviewer not assigned in this workspace |
| RB-05 | Mutation testing for FM-019 (version check), FM-029 (auth bypass), FM-031 (rollback) | SCORE-FMEA Section 3.4, SCORE-VER OVI-07 | Software Safety Engineer | 2026-04-15 | Closed 2026-04-22 - `cargo-mutants 26.0.0` caught all five viable mutants and left zero survivors |

---

## 2  High-Priority Gaps

Items that affect verification evidence quality or future hardware readiness.

| ID | Gap | Source | Owner | Target | Status |
|----|-----|--------|-------|--------|--------|
| HP-01 | Product ID (PID) TBD in TSR Section 8 IVG-01 - must be assigned before hardware deployment | SCORE-TSR line 277 | Configuration Manager | Before HW flash | Deferred - production PID assignment is a later hardware deployment decision |
| HP-02 | PQC tests excluded from Windows CI (linker issue) - HSM-REQ-033 coverage unconfirmed on Linux | SCORE-VER OVI-04 | Host Library Developer | Linux CI runner available | Closed 2026-04-22 - Linux PQC CI job added in `.github/workflows/ci.yml` |
| HP-03 | Firmware timing audit - DWT cycle counter instrumentation planned but blocked on hardware availability | timing-evidence.md Section 4 | Embedded Developer | After HIL setup | Deferred - requires dedicated hardware timing campaign |
| HP-04 | TRNG health test validation report (FM-002, FM-027) | SCORE-FMEA Section 3.4 | Embedded Developer | 2026-04-30 | Deferred - requires live bench execution and report |
| HP-05 | `verify_activation_token` counter-update test coverage (FM-034) | SCORE-FMEA Section 3.4 | Host Library Developer | 2026-04-15 | Closed 2026-04-22 - covered by `host/tests/activation_counter.rs` |

---

## 3  Crypto Requirement Coverage Gaps

Algorithms defined in the requirement set that were identified as missing
coverage in the original audit. All five rows below are now closed with direct
test evidence.

| ID | Requirement | Algorithm | Issue |
|----|-------------|-----------|-------|
| CR-01 | HSM-REQ-003 | AES-256-CBC | Closed 2026-04-22: NIST AES-CBC vectors are vendored under `host/tests/vectors/aes_cbc/` and exercised by `host/tests/kat_aes_cbc.rs` plus `firmware/tests/kat_aes_cbc.rs` |
| CR-02 | HSM-REQ-004 | AES-256-CCM | Closed 2026-04-22: software backend implements AES-256-CCM and `host/tests/kat_aes_ccm.rs` runs the NIST DVPT256 vectors; hardware scope is explicitly documented as software-only in `software-unit-design.md` |
| CR-03 | HSM-REQ-005 | ChaCha20-Poly1305 | Closed 2026-04-22: software backend implements ChaCha20-Poly1305 and `host/tests/kat_chacha20_poly1305.rs` covers RFC 8439 plus upstream corpus vectors |
| CR-04 | HSM-REQ-014 | SHA-3 | Closed 2026-04-22: `host/tests/kat_sha3.rs` runs NIST SHA3-256 and SHA3-512 vectors; `software-unit-design.md` records SHA-3 as software-only because STM32L552 HASH does not implement SHA-3 |
| CR-05 | HSM-REQ-017 | ChaCha20Rng seeding | Closed 2026-04-22: `host/tests/rng_chacha_determinism.rs` verifies deterministic stream mappings against upstream `rand_chacha` vectors |

---

## 4  Missing Test Cases

Items originally noted as missing now fall into two buckets: repository-owned
software tests that have been added, and hardware/performance evidence that is
still deferred to a dedicated bench campaign.

### 4.1  Update module edge cases

Closed 2026-04-22 via `host/tests/update_edge_cases.rs`.

| Test | Purpose |
|------|---------|
| `test_update_ids_event_on_rollback` | IDS event fires on version rollback attempt |
| `test_update_ids_event_on_bad_sig` | IDS event fires on invalid signature |
| `test_update_truncated_signature_rejected` | Truncated DER signature rejected cleanly |
| `test_update_corrupted_der_rejected` | Corrupted DER payload rejected cleanly |

### 4.2  Onboard communication edge cases

Closed 2026-04-22 via `host/tests/onboard_edge_cases.rs`.

| Test | Purpose |
|------|---------|
| `test_ikev2_nonce_domain_separation` | IKEv2 nonce does not collide with other domains |
| `test_ikev2_ecdh_invalid_handle` | Invalid key handle rejected in ECDH exchange |
| `test_macsec_wrong_key_type_rejected` | MACsec operation rejects non-MACsec key type |

### 4.3  Property-based tests (proptest)

Closed 2026-04-22 via `host/tests/proptest_roundtrips.rs`.

| Test | Purpose |
|------|---------|
| Update sign-verify roundtrip | Arbitrary payloads survive sign then verify |
| Activation token roundtrip | Arbitrary tokens survive issue then verify |

### 4.4  Performance evidence

Still deferred to hardware/performance follow-up.

| Test | Purpose |
|------|---------|
| HSM-REQ-028 bench harness | Criterion benchmarks for all crypto primitives |

---

## 5  Safety Documentation Gaps

| ID | Document / Artefact | Gap | Target |
|----|---------------------|-----|--------|
| SD-01 | Safety Case (GSN) | Closed 2026-04-22 - `docs/safety/safety-case.md` is now the maintained structured argument | 2026-05-15 |
| SD-02 | SW-FMEA | Closed 2026-04-22 - USB protocol layer and key management sections are fully authored | 2026-04-15 |
| SD-03 | HW-level zeroize evidence (FM-008) | Deferred - still requires debug probe + SRAM2 read on L552 | 2026-05-15 |
| SD-04 | Tool qualification (Clippy CI) | Closed 2026-04-22 - TQR sections now consistently mark Clippy as complete | Clarify |
| SD-05 | HSM-REQ-044 frame-length validation | Deferred - oversized-frame injection remains hardware-only work | 2026-05-15 |

---

## 6  Integrator Obligations (ASR Evidence)

12 Assumed Safety Requirements are defined with integrator verification
checklists. Repository-owned deferral records now exist for all 12 rows under
`docs/safety/integrator-evidence/`, but no integrator-supplied program evidence
has been collected. These are not blocking the SEooC release but will block any
ASIL B vehicle integration until replaced with real program evidence.

| ASR | Obligation | Evidence Required |
|-----|-----------|-------------------|
| ASR-HW-01 | TrustZone enforcement | SAU configuration evidence |
| ASR-HW-02 | SWD locked (RDP Level 2) | Production flashing procedure |
| ASR-HW-03 | Genuine L552 device | Device verification test evidence |
| ASR-HW-04 | USB physical protection or encryption | Physical routing statement |
| ASR-HW-05 | Trusted time source | Clock source specification |
| ASR-OS-01 | Process isolation | OS hardening evidence |
| ASR-OS-02 | Supply chain integrity | Binary hash and build evidence |
| ASR-OS-03 | Single active instance | Singleton enforcement test |
| ASR-INT-01 | ASIL B integration context | HARA extract |
| ASR-INT-02 | Caller error handling | Integration layer code review |
| ASR-INT-03 | Rate limiter not bypassed | Configuration review |
| ASR-INT-04 | Key provisioning integrity | KMS documentation |

---

## 7  Accepted Residual Risks

Risks reviewed and accepted with documented rationale.

| ID | Risk | Rationale |
|----|------|-----------|
| RR-01 | Plaintext visible on USB cable | Physical access required; in-vehicle USB physically protected. Future: USB encryption. |
| RR-02 | Software fallback has no key isolation | CI / development only. Production must use hardware backend. |
| RR-03 | SWD not locked in development | Development board. Production deployment guide mandates RDP Level 2. |
| RR-04 | Timing side-channel residual over USB | USB jitter dominates. Hardware crypto is constant-time. |

---

## 8  Summary

| Category | Count |
|----------|-------|
| Release blockers | 5 (3 closed, 2 deferred) |
| High-priority gaps | 5 (2 closed, 3 deferred) |
| Untested crypto requirements | 0 |
| Missing test cases | 1 deferred performance item |
| Safety documentation gaps | 5 (3 closed, 2 deferred) |
| Integrator ASR evidence items | 12 (12 deferred to downstream integrator records) |
| Accepted residual risks | 4 |

**Software-layer verdict:** CONDITIONALLY PASSED - coverage, PQC Linux CI, tool
validation, and mutation evidence are now closed; independent release review
remains deferred.

**Hardware-layer verdict:** DEFERRED - remaining bench-only evidence is
documented but not complete.

**Full ASIL B sign-off:** Deferred pending RB-01 (hardware evidence) and RB-04
(T1-independent release review).
