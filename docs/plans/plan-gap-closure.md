# scorehsm — Gap Closure Plan

| Field | Value |
|-------|-------|
| Document ID | SCORE-GCP |
| Date | 2026-04-22 |
| Revision | 1.1 |
| Status | COMPLETED WITH DEFERRED ITEMS |
| Scope | Execution plan to close every gap identified by the 2026-04-22 security audit and by `docs/safety/gap-analysis.md` v1.1 |
| Supersedes | none |
| Complements | `docs/plans/plan-hsm-full.md`, `docs/plans/plan-score-contribution.md`, `docs/plans/plan-scorehsm-hardware-bringup.md` |

---

## How to read this

**Audience:** a future AI worker landing cold with no prior conversation context,
or a human engineer picking up the branch.

**Step structure:** every step carries a stable **Step ID**, a one-sentence
**Goal**, concrete **Inputs** (paths that must exist), concrete
**Deliverables** (paths that will exist, with the symbols/functions touched),
**Acceptance criteria** (each independently checkable), a **Gate/review**
reference, and a one-sentence **Definition of done**. Step IDs are stable and
do not reorder.

**Anchoring:** where a gap already has an ID in
`docs/safety/gap-analysis.md` (e.g. `RB-01`, `HP-04`, `CR-03`) or a
Functional/Technical Safety Requirement ID (e.g. `HSM-REQ-029`, `TSR-RLG-01`,
`FM-031`), the step cites that ID and does NOT invent a new one.
Items new to this plan use the `GC-*` prefix (gap-closure).

**Gates referenced in this document:**
- SCORE-VER OVI-01..07 — verification overall independence items in `gap-analysis.md`
- SCORE-TQR T1..T4 — tool qualification records in `docs/safety/tool-qualification-records.md`
- SCORE-TRM UC-01..03 — use-case closure items
- ASIL-B qualification gate per ISO 26262-6 Table 10
- SCORE upstream PR review (safety WG + infra team) per
  `docs/plans/plan-score-contribution.md` §10

**Rules this plan obeys:**
- No vague verbs. Every step names a file path and a symbol.
- No placeholder tokens (`TODO_FILL_IN`, unjustified `TBD_*`).
- Every date cites its basis (the gap-analysis row, a requirement doc, or a
  physical prerequisite like "after hardware availability").
- Private data (IPs, hostnames, ST-Link serials, personal usernames) must
  never appear in any deliverable — use placeholders per
  `~/.claude/rules/never_commit_private_data.md`.

---

## Dependency graph

```
Phase A  (hygiene & prereqs) ─────────────────────────────────────┐
   A1 pin firmware toolchain       A4 README wording              │
   A2 HsmError::BufferTooSmall     A5 unwrap cleanup              │
   A3 NOTICE / license posture     A6 CRC crate swap (optional)   │
                                                                  │
Phase B  (FFI surface) ──────────────────────────────────────────┐│
   B1 ffi.rs skeleton   ── requires A2                            ││
   B2 ffi.rs wiring     ── requires B1                            ││
   B3 hsm.h header      ── requires B2                            ││
   B4 C link test       ── requires B3                            ││
   B5 CI FFI job        ── requires B4                            ││
                                                                  ││
Phase C  (software test coverage) ───────────────────────────────┐││
   C1..C5 crypto KATs (CR-01..05)    independent of B            │││
   C6..C9 missing test cases          independent of B            │││
   C10 mutation testing (RB-05)       independent of B            │││
   C11 CI coverage enforcement (RB-02) requires C1..C9            │││
   C12 cargo-llvm-cov TCL-2 (RB-03)    requires C11               │││
                                                                  │││
Phase D  (HIL hardware verification) ────────────────────────────┐│││
   D1..D6 HSM-REQ-021/029/031/036/043/046 (RB-01)                ││││
   D7 USB PID assign (HP-01)          before first flash         ││││
   D8 timing audit (HP-03)            requires D1                ││││
   D9 TRNG health (HP-04)             requires D1                ││││
   D10 HW zeroize evidence (SD-03)    requires D1                ││││
   D11 oversized frame (SD-05)        requires D1                ││││
   D12 Criterion benchmarks           requires D1                ││││
                                                                  ││││
Phase E  (safety doc closure) ───────────────────────────────────┐││││
   E1 safety case GSN (SD-01)                                    │││││
   E2 SW-FMEA completion (SD-02)                                 │││││
   E3 TQR inconsistency (SD-04)                                  │││││
   E4 T1 independence review (RB-04) requires C12, E1, E2        │││││
   E5 Linux PQC CI (HP-02)                                       │││││
                                                                  │││││
Phase F  (SCORE upstream PRs) ───────────────────────────────────┐│││││
   F1 PR1 types      requires A2, A3                             ││││││
   F2 PR2 hsm.h      requires F1, B3                             ││││││
   F3 PR3 posix      requires F2, B5, C11                        ││││││
   F4 PR4 STM32L5    requires F3, D1..D6                         ││││││
   F5 PR5 safety     requires E1..E4                             ││││││
                                                                  ││││││
Phase G  (integrator evidence — tracked, non-blocking) ──────────┐││││││
   G1..G12 ASR-HW/OS/INT evidence (12 records deferred)          │││││││
```

Phases A, C, D, E are parallelizable against each other once A2 (BufferTooSmall)
lands. Phase B depends on A2. Phase F is serialized and is the finish path.

---

## Phase A — Repo hygiene & prerequisite closure

Closes: `TQR-OI-01`, prereqs from `plan-score-contribution.md` §11,
audit items 3, 6, 10, 11.

### A1 — Pin firmware nightly toolchain

- **Step ID:** A1
- **Goal:** Make firmware builds reproducible by pinning the nightly channel to a dated release.
- **Inputs:** `firmware/rust-toolchain.toml`, `firmware/Cargo.lock`, Embassy pin commit (`088d0cfb` per `firmware/Cargo.toml`).
- **Deliverables:**
  - `firmware/rust-toolchain.toml` — change `channel = "nightly"` to `channel = "nightly-<yyyy-mm-dd>"` where the date is the latest nightly that successfully builds the current `firmware/Cargo.lock` graph.
- **Acceptance criteria:**
  - `cargo +nightly-<date> build --target thumbv8m.main-none-eabihf` succeeds inside `firmware/`.
  - `rustc --version` in CI prints the pinned date, not "nightly".
  - The date appears in the next CHANGELOG entry with its basis (Embassy rev + Cargo.lock hash at pin time).
- **Gate/review:** SCORE-TQR T1 (tool versioning).
- **Definition of done:** `firmware/rust-toolchain.toml` names a specific dated nightly and firmware CI job reports that exact version string.

### A2 — Add `HsmError::BufferTooSmall`

- **Step ID:** A2 / GC-BTS
- **Goal:** Give Rust an error variant that maps 1:1 to SCORE's `HSM_ERR_BUFFER_TOO_SMALL` before FFI work starts.
- **Inputs:** `host/src/error.rs`, SCORE reference in `plan-score-contribution.md` §2.1 line 50.
- **Deliverables:**
  - `host/src/error.rs` — add `BufferTooSmall { required: usize, provided: usize }` to the `HsmError` enum; wire through `Display` and any conversion impls.
  - `host/src/backend/mod.rs` — update any trait method that can produce short-buffer conditions (e.g. `ecdsa_verify`, `ecdh_shared_secret`, `hkdf_derive` output length checks) to return `BufferTooSmall` rather than `Other`.
  - `host/tests/error_mapping.rs` — new test `buffer_too_small_roundtrip` asserts the variant carries both sizes.
- **Acceptance criteria:**
  - `cargo test -p scorehsm-host` green.
  - `cargo clippy -p scorehsm-host --all-features -- -D warnings` green.
  - No existing call site still returns a less-specific variant for a short-buffer condition (grep: no `HsmError::Other.*buffer` remains in host/src).
- **Gate/review:** prereq line 605 of `plan-score-contribution.md`.
- **Definition of done:** `HsmError::BufferTooSmall` exists, is surfaced by all short-buffer paths, and has test coverage.

### A3 — NOTICE file and license posture

- **Step ID:** A3 / GC-LIC
- **Goal:** Add the Eclipse-required `NOTICE` file so the repo can be contributed.
- **Inputs:** `LICENSE` (Apache-2.0 already present), `LICENSES/Apache-2.0.txt`.
- **Deliverables:**
  - `NOTICE` at repo root — Eclipse Foundation standard template naming the project (`scorehsm`) and third-party attributions drawn from `cargo license --json` output.
- **Acceptance criteria:**
  - `reuse lint` passes (already in CI per `.github/workflows/`).
  - `NOTICE` lists every crate whose license is not Apache-2.0 (BSD, MIT, ISC, etc. as allowed by `deny.toml`).
  - No license prohibited by `deny.toml` appears.
- **Gate/review:** prereq line 604 of `plan-score-contribution.md`.
- **Definition of done:** `NOTICE` exists at repo root and `reuse lint` is clean.

### A4 — README Phase 10 language

- **Step ID:** A4 / GC-README
- **Goal:** Correct the README claim that Phase 10 evidence collection is complete when `gap-analysis.md` still lists 5 release blockers.
- **Inputs:** `README-scorehsm.md` line 78, `docs/safety/gap-analysis.md` §1.
- **Deliverables:**
  - `README-scorehsm.md` — replace "Phase 10 evidence collection complete" with a line that names the open release blockers (RB-01..RB-05) and points to `docs/safety/gap-analysis.md`.
- **Acceptance criteria:**
  - No sentence in the README implies release readiness while RB-01..RB-05 are open.
  - Diff is ≤15 lines; no unrelated edits.
- **Gate/review:** documentation accuracy, not a SCORE gate.
- **Definition of done:** README status matches gap-analysis.md; both artifacts tell the same story.

### A5 — `unwrap/expect` cleanup on production paths

- **Step ID:** A5 / GC-UNWRAP
- **Goal:** Remove `unwrap/expect/panic!` from production code paths in the hardware backend; leave them only where a panic is the intended safe-state response.
- **Inputs:** `host/src/backend/hw.rs` (3 occurrences per audit), `host/src/backend/mock.rs` (36 — lower priority since mock is test-only).
- **Deliverables:**
  - `host/src/backend/hw.rs` — every `.unwrap()` / `.expect()` either (a) replaced with `?` propagation returning an appropriate `HsmError`, or (b) annotated with a one-line comment explaining why the invariant is guaranteed (and the comment is reviewed).
  - `host/src/backend/mock.rs` — no change required for this step; tracked as GC-UNWRAP-MOCK for a later pass.
- **Acceptance criteria:**
  - `grep -n "unwrap\|expect\|panic!" host/src/backend/hw.rs` — every remaining hit carries a justification comment on the same or previous line.
  - `cargo test -p scorehsm-host --features hw-backend` green.
- **Gate/review:** `docs/safety/coding-guidelines.md` §panic-free production code.
- **Definition of done:** `host/src/backend/hw.rs` has no unjustified `unwrap/expect` and tests still pass.

### A6 — CRC-32 crate swap (optional, audit parity)

- **Step ID:** A6 / GC-CRC
- **Goal:** Replace the hand-rolled CRC-32/MPEG-2 with the `crc` crate so the code under review is a library call, not a loop.
- **Inputs:** `host/src/transport.rs` around line 101, firmware CRC usage site (to be located — grep `0x04C11DB7` in `firmware/src/`).
- **Deliverables:**
  - `Cargo.toml` (workspace dependencies) — add `crc = "3"` as a workspace dep; pick the `no_std` compatible version.
  - `host/src/transport.rs` — replace the hand-rolled polynomial loop with `crc::Crc::<u32>::new(&crc::CRC_32_MPEG_2)`.
  - `firmware/src/<crc-site>` — same replacement in `no_std` mode.
  - `host/tests/transport_crc.rs` — new test: for the frame vector in the current USB protocol spec, old hand-rolled result equals new `crc` crate result byte-for-byte.
- **Acceptance criteria:**
  - Frame CRC bytes on the wire are unchanged (interoperability with already-flashed firmware).
  - `cargo test` and `cargo build --target thumbv8m.main-none-eabihf` green.
- **Gate/review:** audit low-severity finding #10.
- **Definition of done:** No hand-rolled CRC loop remains in the repo and wire compatibility is test-verified. **This step is optional; skip without blocking anything if bandwidth is tight.**

---

## Phase B — FFI surface

Closes: audit critical finding #1, `plan-score-contribution.md` §4.

### B1 — `ffi.rs` skeleton

- **Step ID:** B1 / GC-FFI-SKEL
- **Goal:** Create a compiling `host/src/ffi.rs` where every declared C function returns `HSM_ERR_NOT_INITIALIZED`, so the link surface exists before semantics.
- **Inputs:** `plan-score-contribution.md` §4 (15 functions), A2 complete (`HsmError::BufferTooSmall`).
- **Deliverables:**
  - `host/src/ffi.rs` — 15 `#[no_mangle] pub unsafe extern "C"` functions per §4, each returning a `HsmStatus_t`-typed `HSM_ERR_NOT_INITIALIZED` constant.
  - `host/src/lib.rs` — add `#[cfg(feature = "ffi")] pub mod ffi;`.
  - `host/Cargo.toml` — add `ffi = []` feature; add `crate-type = ["staticlib", "rlib"]` under `[lib]` when `ffi` is enabled.
- **Acceptance criteria:**
  - `cargo build -p scorehsm-host --features ffi` produces `libscorehsm_host.a`.
  - `nm libscorehsm_host.a | grep '^T HSM_'` lists all 15 function symbols.
  - `cargo clippy -p scorehsm-host --features ffi -- -D warnings` green.
- **Gate/review:** prereq line 606 of `plan-score-contribution.md`.
- **Definition of done:** 15 symbols exported, no UB markers triggered, zero-implementation status clearly returned.

### B2 — `ffi.rs` wiring to software backend

- **Step ID:** B2 / GC-FFI-IMPL
- **Goal:** Wire each FFI function to the existing software backend (and hardware backend when `hw-backend` is also enabled).
- **Inputs:** B1 skeleton, `host/src/backend/mod.rs` trait, `host/src/backend/sw.rs` software backend.
- **Deliverables:**
  - `host/src/ffi.rs` — replace each stub body with:
    1. Pointer/length validation (null checks, `BufferTooSmall` via A2).
    2. A guarded call into a process-global `HsmContext` singleton (`static ONCE: OnceCell<Mutex<Context>>`).
    3. Conversion of `HsmError` → `HsmStatus_t` via an exhaustive `match`.
  - `host/src/ffi.rs` — `HSM_Init` / `HSM_Shutdown` manage the singleton.
- **Acceptance criteria:**
  - Every function in the §4 table has a body that either calls the backend or returns a specific, enum-matched status — no `_ => HSM_ERR_UNKNOWN` fallthroughs without a preceding exhaustive match.
  - Unit test `host/tests/ffi_smoke.rs` exercises `HSM_Init` → `HSM_RandomBytes` → `HSM_Shutdown` round-trip from Rust-side FFI entry points using `unsafe { HSM_* }`.
- **Gate/review:** SCORE API semantic parity (pending F1/F2).
- **Definition of done:** FFI smoke test green for all 15 functions against the software backend.

### B3 — `hsm.h` header

- **Step ID:** B3 / GC-FFI-HDR
- **Goal:** Produce the C header SCORE callers include.
- **Inputs:** B2 wired FFI, `plan-score-contribution.md` §3 (type table), §4 (functions).
- **Deliverables:**
  - `include/score/crypto/hsm.h` — hand-authored C99 header with Apache-2.0 SPDX line, `@reqref feat_req__sec_crypt__*` annotations per function, include-guard, `extern "C"` block.
  - Decision captured in this step's definition of done: header is **hand-authored**, not `cbindgen`-generated, because SCORE requires stable `@reqref` annotations and explicit type-name control.
- **Acceptance criteria:**
  - Header compiles with `gcc -std=c99 -Wall -Werror -c` against a minimal `.c` file that only `#include`s it.
  - Header compiles with `clang -std=c17 -Wall -Werror` in the same manner.
  - Every type and function from `plan-score-contribution.md` §3/§4 appears exactly once.
- **Gate/review:** SCORE-VER API contract review (upstream).
- **Definition of done:** `include/score/crypto/hsm.h` compiles under gcc and clang, and every `@reqref` ID matches an existing SCORE feature-tree entry listed in `plan-score-contribution.md`.

### B4 — C integration test

- **Step ID:** B4 / GC-FFI-TEST
- **Goal:** Prove the Rust staticlib links against a pure-C caller and answers basic ops.
- **Inputs:** B2, B3.
- **Deliverables:**
  - `host/tests/c/ffi_link_test.c` — minimal GoogleTest-free C program (or use `cmocka` if already present in `deny.toml` allow-list; otherwise plain `assert()`) that calls `HSM_Init`, `HSM_RandomBytes`, `HSM_Shutdown`.
  - `host/tests/c/Makefile` or `build.rs` integration — compile `ffi_link_test.c` against `libscorehsm_host.a`.
- **Acceptance criteria:**
  - `make -C host/tests/c` (or equivalent) produces a binary that exits 0 and prints random bytes.
  - `ldd` shows no unexpected dynamic deps beyond libc / pthread.
- **Gate/review:** SCORE-VER OVI-06 (integration test independence).
- **Definition of done:** A pure-C program links and runs against scorehsm's FFI.

### B5 — CI FFI job

- **Step ID:** B5 / GC-FFI-CI
- **Goal:** Enforce FFI build + link every push.
- **Inputs:** B4.
- **Deliverables:**
  - `.github/workflows/ci.yml` — new job `host-ffi` running `cargo build --features ffi`, `make -C host/tests/c`, upload `libscorehsm_host.a` + `hsm.h` as artifacts.
- **Acceptance criteria:**
  - The job is a required status check (branch protection entry) on `main` and `feat/score-*` branches.
  - Job fails if any symbol in §4's list is missing from the staticlib.
- **Gate/review:** SCORE-TQR T4 (CI as tool).
- **Definition of done:** CI will not pass a PR that breaks the FFI surface.

---

## Phase C — Software test coverage

Closes: `CR-01..05`, `RB-02`, `RB-03`, `RB-05`, `HP-05`, gap-analysis §4.

### C1 — AES-256-CBC KAT suite (CR-01, HSM-REQ-003)

- **Step ID:** C1
- **Goal:** Add a NIST-derived KAT suite for AES-256-CBC in both backends.
- **Inputs:** `host/src/backend/sw.rs` (software AES), `firmware/src/crypto.rs` (hardware AES on STM32L552 AES peripheral).
- **Deliverables:**
  - `host/tests/kat_aes_cbc.rs` — reads vectors from NIST CAVP AES-CBC .rsp files placed under `host/tests/vectors/aes_cbc/` (vectors vendored, not downloaded during CI).
  - `firmware/tests/kat_aes_cbc.rs` — same vectors, hardware backend.
- **Acceptance criteria:**
  - All NIST CBCGFSbox256, CBCVarKey256, CBCVarTxt256, CBCMMT256 vectors pass.
  - Traceability matrix row for HSM-REQ-003 updated in `docs/safety/traceability-matrix.md`.
- **Gate/review:** SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-003 row in gap-analysis.md §3 is closable.

### C2 — AES-256-CCM KAT suite (CR-02, HSM-REQ-004)

- **Step ID:** C2
- **Goal:** Add a NIST-derived KAT suite for AES-256-CCM.
- **Inputs:** `aes` crate (already in `host/Cargo.toml`), CCM mode wrapper (add `ccm = "0.5"` if absent).
- **Deliverables:**
  - `host/Cargo.toml` — add `ccm` crate (check `deny.toml` allow-list).
  - `host/src/backend/sw.rs` — `aes_ccm_encrypt` / `aes_ccm_decrypt` methods.
  - `host/tests/kat_aes_ccm.rs` — NIST SP 800-38C DVPT256 vectors under `host/tests/vectors/aes_ccm/`.
- **Acceptance criteria:**
  - All DVPT256 vectors pass.
  - No firmware change in this step; hardware CCM is a separate RFC (CCM not in current L552 AES peripheral scope). Capture this as a `docs/safety/software-unit-design.md` note.
- **Gate/review:** SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-004 coverage is non-zero in software and the hardware-scope decision is documented.

### C3 — ChaCha20-Poly1305 implementation + KAT (CR-03, HSM-REQ-005)

- **Step ID:** C3
- **Goal:** Implement ChaCha20-Poly1305 in the software backend and add RFC 8439 KAT.
- **Inputs:** `chacha20poly1305` crate (already present in `host/Cargo.toml`).
- **Deliverables:**
  - `host/src/backend/sw.rs` — `chacha20_poly1305_encrypt` / `_decrypt` methods.
  - `host/src/backend/mod.rs` — trait additions.
  - `host/tests/kat_chacha20_poly1305.rs` — RFC 8439 §2.8.2 test vector + at least 5 additional vectors from `chacha20poly1305` crate's own test corpus.
- **Acceptance criteria:**
  - RFC 8439 vector passes.
  - Nonce-reuse test: same (key, nonce) pair on different plaintexts is rejected by the NonceManager (`safety.rs`).
- **Gate/review:** SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-005 has an implementation and a passing KAT.

### C4 — SHA-3 software KAT (CR-04, HSM-REQ-014)

- **Step ID:** C4
- **Goal:** Add SHA-3 software-only path with NIST KAT. Document that L552 HASH peripheral does not support SHA-3.
- **Inputs:** `sha3` crate (already in `host/Cargo.toml`).
- **Deliverables:**
  - `host/tests/kat_sha3.rs` — NIST CAVP SHA3-256 and SHA3-512 short/long message vectors under `host/tests/vectors/sha3/`.
  - `docs/safety/software-unit-design.md` — add §"SHA-3 software-only path (HSM-REQ-014)" documenting the hardware limitation.
- **Acceptance criteria:**
  - All short-message and long-message vectors pass.
  - Design doc explains why SHA-3 uses software even when `hw-backend` is enabled.
- **Gate/review:** SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-014 is tested and the hardware-scope decision is recorded.

### C5 — ChaCha20Rng deterministic seed test (CR-05, HSM-REQ-017)

- **Step ID:** C5
- **Goal:** Prove ChaCha20Rng produces a deterministic stream from a fixed seed.
- **Inputs:** `rand_chacha` crate (add if absent).
- **Deliverables:**
  - `host/tests/rng_chacha_determinism.rs` — for each of 3 test seeds, assert the first 64 bytes match the vectors in `rand_chacha`'s upstream test suite.
- **Acceptance criteria:**
  - All 3 seed → stream mappings exact.
  - The test file cites the commit SHA of `rand_chacha` it took the vectors from.
- **Gate/review:** SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-017 has a reproducibility test.

### C6 — Update module edge case tests (gap-analysis §4.1)

- **Step ID:** C6
- **Goal:** Add the 4 tests named in gap-analysis §4.1 for `update.rs`.
- **Inputs:** `host/src/update.rs`.
- **Deliverables:** `host/tests/update_edge_cases.rs` with the four named tests:
  - `test_update_ids_event_on_rollback`
  - `test_update_ids_event_on_bad_sig`
  - `test_update_truncated_signature_rejected`
  - `test_update_corrupted_der_rejected`
- **Acceptance criteria:** All four tests green; each asserts the exact IDS event string or error variant required by `docs/safety/functional-safety-requirements.md`.
- **Gate/review:** SCORE-VER OVI-07.
- **Definition of done:** gap-analysis §4.1 rows are closable.

### C7 — Onboard communication edge case tests (gap-analysis §4.2)

- **Step ID:** C7
- **Goal:** Add the 3 tests named in gap-analysis §4.2.
- **Inputs:** `host/src/onboard_comm.rs`.
- **Deliverables:** `host/tests/onboard_edge_cases.rs` with:
  - `test_ikev2_nonce_domain_separation`
  - `test_ikev2_ecdh_invalid_handle`
  - `test_macsec_wrong_key_type_rejected`
- **Acceptance criteria:** All three tests green; each matches the semantics described in gap-analysis §4.2.
- **Gate/review:** SCORE-VER OVI-07.
- **Definition of done:** gap-analysis §4.2 rows are closable.

### C8 — Property-based tests (gap-analysis §4.3)

- **Step ID:** C8
- **Goal:** Add two proptest roundtrip tests.
- **Inputs:** `host/src/update.rs`, `host/src/feature_activation.rs`, `proptest` crate (add if absent).
- **Deliverables:**
  - `host/tests/proptest_roundtrips.rs`:
    - `update_sign_verify_roundtrip` — arbitrary payloads of ≤4 KiB survive sign then verify.
    - `activation_token_roundtrip` — arbitrary tokens survive issue then verify.
- **Acceptance criteria:** Each proptest runs ≥256 cases in CI without shrinking to a failure.
- **Gate/review:** SCORE-VER OVI-07.
- **Definition of done:** gap-analysis §4.3 rows are closable.

### C9 — `verify_activation_token` counter-update coverage (HP-05, FM-034)

- **Step ID:** C9
- **Goal:** Cover the counter-update path in `verify_activation_token`.
- **Inputs:** `host/src/feature_activation.rs`.
- **Deliverables:** `host/tests/activation_counter.rs` covering:
  - Counter increments on accepted token.
  - Counter does not advance on rejected token.
  - Counter persists across simulated restart (in-memory rebuild of context).
- **Acceptance criteria:** FM-034 row in `docs/safety/fmea.md` cites this test file.
- **Gate/review:** SCORE-FMEA §3.4.
- **Definition of done:** HP-05 is closable.

### C10 — Mutation testing (RB-05)

- **Step ID:** C10
- **Goal:** Run `cargo-mutants` against `update.rs`, `feature_activation.rs`, and the version-check logic; fix or justify every surviving mutant.
- **Inputs:** C6, C8, C9 (tests must exist first to kill mutants).
- **Deliverables:**
  - `.cargo/mutants.toml` — scope limited to `src/update.rs`, `src/feature_activation.rs`, version-check module.
  - `docs/safety/verification-report.md` — append §"Mutation testing results" with counts (generated / killed / survived) and the test that kills each previously-surviving mutant.
  - `.github/workflows/ci.yml` — optional weekly `mutants` job (non-blocking).
- **Acceptance criteria:**
  - Zero survived mutants in the three target modules, OR every survived mutant has a written justification in the verification report (e.g. dead code, equivalent mutant).
  - The report lists FM-019, FM-029, FM-031 by ID and pairs each with the specific killing test.
- **Gate/review:** SCORE-FMEA §3.4, SCORE-VER OVI-07.
- **Definition of done:** RB-05 is closable.

### C11 — CI coverage enforcement (RB-02)

- **Step ID:** C11
- **Goal:** Make CI fail when statement coverage drops below 85% or branch coverage below 80%.
- **Inputs:** `cargo-llvm-cov`, C1..C9 landed (coverage will be representative).
- **Deliverables:**
  - `.github/workflows/ci.yml` — job `host-coverage` running `cargo llvm-cov --workspace --lcov --output-path lcov.info --fail-under-lines 85 --fail-under-functions 80`.
  - Upload `lcov.info` as CI artifact.
  - `docs/safety/verification-report.md` — cite the CI artifact for current coverage numbers.
- **Acceptance criteria:**
  - CI job fails when any threshold is breached.
  - `lcov.info` is attached to every passing run.
- **Gate/review:** SCORE-VER OVI-02.
- **Definition of done:** RB-02 is closable.

### C12 — `cargo-llvm-cov` TCL-2 validation (RB-03)

- **Step ID:** C12
- **Goal:** Produce the TCL-2 qualification evidence for `cargo-llvm-cov` so coverage numbers are admissible as release evidence.
- **Inputs:** C11 running in CI, `docs/safety/tool-qualification-records.md` §T3.
- **Deliverables:**
  - `docs/safety/tool-qualification-records.md` §T3 — fill in the KAT execution: tool version, fixed-input small Rust project, expected vs. observed coverage numbers.
  - `docs/safety/qualification-test-evidence.md` — append `cargo-llvm-cov` evidence section.
- **Acceptance criteria:**
  - Tool version matches the one used by C11.
  - The KAT is reproducible from the commands recorded in T3.
- **Gate/review:** SCORE-TQR T3, SCORE-VER OVI-06.
- **Definition of done:** RB-03 is closable.

---

## Phase D — HIL hardware verification

Closes: `RB-01` (six requirements), `HP-01`, `HP-03`, `HP-04`, `SD-03`, `SD-05`, gap-analysis §4.4.

Hardware available: Raspberry Pi + STM32L552ZE-Q Nucleo, connected (per user confirmation 2026-04-22). All private credentials and hardware serials must remain out of deliverables — use `<pi-host>`, `<stlink-serial>`, etc.

### D0 — HIL harness bring-up (prerequisite)

- **Step ID:** D0
- **Goal:** Verify the existing `hil/` harness can flash the current firmware and drive at least one end-to-end call.
- **Inputs:** `hil/` crate, Pi + Nucleo bench, current `firmware/` build.
- **Deliverables:**
  - A dated HIL bring-up log under `docs/safety/timing-evidence.md` §"HIL bring-up 2026-..." (ASCII, placeholders for host identifiers).
  - Confirmation that `cargo run -p scorehsm-hil -- smoke` returns success.
- **Acceptance criteria:**
  - USB enumeration successful (Nucleo appears as a CDC device on the Pi — device node recorded as `<cdc-device>`, not a literal path).
  - `HSM_RandomBytes` round-trip returns 32 bytes.
- **Gate/review:** prerequisite for D1..D12.
- **Definition of done:** End-to-end smoke test passes on bench.

### D1 — HSM-REQ-021 TrustZone key storage (RB-01.a)

- **Step ID:** D1
- **Goal:** Evidence that key material lives only in the secure world.
- **Inputs:** D0, `firmware/src/trustzone.rs`, SAU config in firmware.
- **Deliverables:**
  - `hil/tests/hsm_req_021.rs` — driver test that imports a wrapped key, then attempts to read its SRAM2 address from the non-secure side; expects a BusFault or a sanitized zero region.
  - `docs/safety/verification-report.md` — HSM-REQ-021 evidence table row with date, serial placeholder, pass/fail.
- **Acceptance criteria:**
  - NS read of the key region returns zeros or faults (either is pass — the key is not exposed).
  - Test repeated 3 times with different keys.
- **Gate/review:** RB-01, SCORE-VER OVI-01.
- **Definition of done:** HSM-REQ-021 evidence is on record.

### D2 — HSM-REQ-029 constant-time HW (RB-01.b)

- **Step ID:** D2
- **Goal:** Measure that AES and ECDSA on the L552 hardware run in time independent of secret value.
- **Inputs:** D0, DWT cycle counter (HP-03), fixed-time measurement tooling.
- **Deliverables:**
  - `hil/tests/hsm_req_029.rs` — for N=1000 iterations per key, measure cycle counts for a random-key AES-GCM encrypt and an all-zero-key AES-GCM encrypt; assert mean absolute difference ≤ threshold defined in `docs/safety/technical-safety-requirements.md` HSM-REQ-029.
- **Acceptance criteria:**
  - Statistical test (Welch's t-test or `dudect`-style) passes at α=0.01.
  - Same for ECDSA sign with random vs. all-zero nonce injection.
- **Gate/review:** RB-01.
- **Definition of done:** HSM-REQ-029 evidence is on record.

### D3 — HSM-REQ-031 TrustZone isolation (RB-01.c)

- **Step ID:** D3
- **Goal:** Evidence that NS cannot invoke S-only SVCs directly.
- **Inputs:** D0, firmware SAU configuration.
- **Deliverables:**
  - `hil/tests/hsm_req_031.rs` — attempt direct call to a secure-only function address from NS; expect HardFault.
- **Acceptance criteria:** HardFault observed; firmware logs the expected fault code.
- **Gate/review:** RB-01.
- **Definition of done:** HSM-REQ-031 evidence is on record.

### D4 — HSM-REQ-036 OS-level protection (RB-01.d)

- **Step ID:** D4
- **Goal:** Evidence that the Pi-side process isolation enforces one active scorehsm instance with proper permissions.
- **Inputs:** D0, `host/src/safety.rs` process-lock logic.
- **Deliverables:**
  - `hil/tests/hsm_req_036.sh` — shell-driven test: spawn one scorehsm process, then attempt a second; expect the second to fail with `AlreadyInitialized` or equivalent.
- **Acceptance criteria:** Second process fails; first process survives unaffected.
- **Gate/review:** RB-01, ASR-OS-01 evidence source.
- **Definition of done:** HSM-REQ-036 evidence is on record.

### D5 — HSM-REQ-043 SRAM2 zeroize evidence (RB-01.e, SD-03)

- **Step ID:** D5
- **Goal:** Prove key deletion wipes SRAM2.
- **Inputs:** D0, SWD debug access (development board; production is RDP2 per RR-03).
- **Deliverables:**
  - `hil/tests/hsm_req_043.rs` — generate key, note SRAM2 handle region via debug probe, delete key, re-read region, assert all zeros.
- **Acceptance criteria:** Post-delete region is all 0x00; repeat 3 times.
- **Gate/review:** RB-01, SD-03.
- **Definition of done:** HSM-REQ-043 and SD-03 evidence both on record.

### D6 — HSM-REQ-046 secure boot verification (RB-01.f)

- **Step ID:** D6
- **Goal:** Evidence that firmware boots only when the signature over the image is valid.
- **Inputs:** D0, firmware bootloader config, a deliberately corrupted image.
- **Deliverables:**
  - `hil/tests/hsm_req_046.md` — procedure document + captured log showing:
    1. Good image boots.
    2. Corrupted image refuses to boot; specific rejection code logged.
- **Acceptance criteria:** Both cases reproduced on bench; logs attached.
- **Gate/review:** RB-01.
- **Definition of done:** HSM-REQ-046 evidence is on record.

### D7 — USB PID assignment (HP-01)

- **Step ID:** D7
- **Goal:** Assign a real USB PID and record it.
- **Inputs:** Organization-level USB VID registration (Eclipse Foundation pid.codes or equivalent), owner decision.
- **Deliverables:**
  - `firmware/src/main.rs` — USB device descriptor updated from `0xXXXX` to the assigned PID; assignment source cited in a one-line comment.
  - `docs/safety/technical-safety-requirements.md` §8 IVG-01 — PID filled in.
- **Acceptance criteria:** Firmware builds; Pi-side `lsusb` reports the assigned PID; `gap-analysis.md` HP-01 is closable.
- **Gate/review:** HP-01.
- **Definition of done:** PID is assigned, recorded, and flashed.

### D8 — Firmware timing audit (HP-03)

- **Step ID:** D8
- **Goal:** Capture DWT cycle-count measurements for each crypto primitive so `docs/safety/timing-evidence.md` has real numbers.
- **Inputs:** D0, D2.
- **Deliverables:**
  - `firmware/src/bench.rs` — feature-gated bench harness printing cycle counts to RTT.
  - `docs/safety/timing-evidence.md` — new §"Measured cycle counts (2026-..)" table.
- **Acceptance criteria:** Each primitive has a measurement with N≥100 samples, mean and p99.
- **Gate/review:** HP-03, HSM-REQ-028.
- **Definition of done:** Timing evidence has real numbers, not "TBD".

### D9 — TRNG health test (HP-04, FM-002, FM-027)

- **Step ID:** D9
- **Goal:** Run and document TRNG health tests (NIST SP 800-90B Repetition Count Test and Adaptive Proportion Test).
- **Inputs:** D0, firmware RNG interface.
- **Deliverables:**
  - `hil/tests/trng_health.rs` — collect 1 MiB of TRNG output, run RCT + APT, assert pass.
  - `docs/safety/verification-report.md` — append §"TRNG health test results" with date and numeric outcomes.
- **Acceptance criteria:** RCT and APT both pass on fresh data; stuck-bit detection covered by an additional fault-injection test (monkey-patched RNG returning all 0xFF should trigger rejection).
- **Gate/review:** HP-04.
- **Definition of done:** gap-analysis HP-04 is closable.

### D10 — HW-level zeroize evidence (SD-03)

- **Step ID:** D10
- **Goal:** Captured in D5.
- **Note:** This step is a cross-reference; the deliverable is the same file as D5. Tracked separately because gap-analysis lists it under §5 Safety Documentation Gaps.

### D11 — Oversized frame injection (SD-05, HSM-REQ-044)

- **Step ID:** D11
- **Goal:** Evidence that oversize USB frames are rejected safely.
- **Inputs:** D0, `host/src/transport.rs` MAX frame size constant.
- **Deliverables:**
  - `hil/tests/hsm_req_044.rs` — inject frames of size `MAX+1`, `2 * MAX`, and pathological `u32::MAX-declared length`; expect specific rejection code and no safe-state trip beyond the configured threshold.
- **Acceptance criteria:** All three oversize cases rejected with the documented error; rate-limiter reacts per `safety.rs` configuration.
- **Gate/review:** SD-05.
- **Definition of done:** gap-analysis SD-05 is closable.

### D12 — Criterion benchmark harness (gap §4.4, HSM-REQ-028)

- **Step ID:** D12
- **Goal:** Criterion harness for all crypto primitives, results checked in.
- **Inputs:** D0, D8.
- **Deliverables:**
  - `host/benches/crypto.rs` — Criterion benches for AES-GCM, ECDSA, ECDH, HKDF, SHA-256, SHA-3.
  - `docs/safety/timing-evidence.md` — append §"Host-side bench results" with date and numbers.
- **Acceptance criteria:** Each bench runs to completion; p99 cited.
- **Gate/review:** HSM-REQ-028.
- **Definition of done:** gap-analysis §4.4 is closable.

---

## Phase E — Safety documentation closure

Closes: `SD-01`, `SD-02`, `SD-04`, `RB-04`, `HP-02`.

### E1 — Safety case (GSN) authoring (SD-01)

- **Step ID:** E1
- **Goal:** Replace the placeholder safety case with a real GSN structure.
- **Inputs:** `docs/safety/safety-case.md` (placeholder), existing FSRs/TSRs/FMEA.
- **Deliverables:**
  - `docs/safety/safety-case.md` — GSN goal tree rooted at "scorehsm meets ASIL B safety goals per ISO 26262", with strategies linking to each HSM-REQ, each FSR, each TSR, each FMEA row. Use text-based GSN notation, not an image.
- **Acceptance criteria:**
  - Every safety goal in `docs/safety/safety-goals.md` has a GSN goal node.
  - Every FMEA failure mode has an evidence node pointing to a verification test.
  - Undefended goals are marked explicitly (no silent gaps).
- **Gate/review:** SCORE-VER OVI-03 (safety case independence).
- **Definition of done:** SD-01 closable.

### E2 — SW-FMEA completion (SD-02)

- **Step ID:** E2
- **Goal:** Finish the USB protocol layer and key management sections of SW-FMEA.
- **Inputs:** `docs/safety/fmea.md` (in-progress sections).
- **Deliverables:**
  - `docs/safety/fmea.md` — §USB protocol: every frame type has at least one failure mode, one detection mechanism, one mitigation.
  - §Key management: generate, import, derive, delete, export each have failure modes.
- **Acceptance criteria:**
  - No "TBD" or "WIP" in these sections.
  - Every FM-### ID is unique and traced to a test.
- **Gate/review:** SCORE-FMEA review.
- **Definition of done:** SD-02 closable.

### E3 — TQR inconsistency resolution (SD-04)

- **Step ID:** E3
- **Goal:** Reconcile the conflict between `tool-qualification-records.md` §2 T4 ("CLOSED") and §3 summary ("OPEN") for Clippy CI.
- **Inputs:** `docs/safety/tool-qualification-records.md`.
- **Deliverables:**
  - `docs/safety/tool-qualification-records.md` — one authoritative status for Clippy CI across §2 T4 and §3; rationale cited.
- **Acceptance criteria:**
  - `grep "Clippy" docs/safety/tool-qualification-records.md` — same status wherever it appears.
- **Gate/review:** SCORE-TQR review.
- **Definition of done:** SD-04 closable.

### E4 — T1 independence review (RB-04)

- **Step ID:** E4
- **Goal:** Obtain ASIL-B T1 (independence from developer) sign-off.
- **Inputs:** E1 safety case, E2 FMEA, C12 tool qualification evidence.
- **Deliverables:**
  - `docs/safety/safety-plan.md` — appended §"T1 independence review" with reviewer name placeholder, date, and signed-off checklist items.
  - Review evidence attached as a PDF or text artifact under `docs/safety/reviews/`.
- **Acceptance criteria:**
  - Reviewer is T1-independent per ISO 26262-6 Table 10 definition.
  - Every open finding from the review is either closed or tracked as a new `GC-*` step in this plan.
- **Gate/review:** SCORE-VER OVI-05, SCORE-TRM UC-03.
- **Definition of done:** RB-04 closable.

### E5 — Linux CI runner for PQC tests (HP-02)

- **Step ID:** E5
- **Goal:** Run PQC tests in CI by provisioning a Linux runner (Windows linker issue blocks the existing runner).
- **Inputs:** `.github/workflows/ci.yml`, `host/Cargo.toml` `pqc` feature.
- **Deliverables:**
  - `.github/workflows/ci.yml` — add `host-test-linux-pqc` job on `ubuntu-latest` running `cargo test -p scorehsm-host --features pqc`.
- **Acceptance criteria:**
  - Job green with HSM-REQ-033 tests executing.
- **Gate/review:** HP-02.
- **Definition of done:** HP-02 closable.

---

## Phase F — SCORE upstream contribution

Closes: audit SCORE-alignment section, delivers on plan-score-contribution.md §10.

2026-04-22 project decision: Eclipse SCORE upstream contribution is no longer an active delivery objective for this repository. Phase F is retained as historical context only, and its step rows are retired in the status tracker.

Each step here is a **single PR to the upstream SCORE repository** and inherits
`plan-score-contribution.md` §10 as the authoritative description. This plan
records only the **scorehsm-side readiness** for each PR.

### F1 — PR 1 scorehsm readiness: hsm_types.h extensions

- **Step ID:** F1
- **Goal:** Confirm scorehsm-side prerequisites for SCORE PR 1 are met.
- **Inputs:** A2 (BufferTooSmall), A3 (NOTICE).
- **Deliverables:** checklist entry in this document marking "F1 upstream-ready"; PR link once submitted.
- **Acceptance criteria:** A2 and A3 merged; `plan-score-contribution.md` §11 rows for those items marked ✓.
- **Gate/review:** SCORE upstream safety WG.
- **Definition of done:** SCORE PR 1 is opened.

### F2 — PR 2 scorehsm readiness: hsm.h header

- **Step ID:** F2
- **Goal:** Confirm B3 (hsm.h) is upstream-ready.
- **Inputs:** F1, B3.
- **Acceptance criteria:** `include/score/crypto/hsm.h` is byte-identical to the version submitted in the upstream PR.
- **Gate/review:** SCORE upstream.
- **Definition of done:** SCORE PR 2 opened.

### F3 — PR 3 scorehsm readiness: posix implementation

- **Step ID:** F3
- **Goal:** Confirm posix build produces `scoreHsm_rust_posix.a` with green test suite.
- **Inputs:** F2, B5 (FFI CI), C11 (coverage).
- **Acceptance criteria:** Static archive built by CI, hash recorded, uploaded as release artifact.
- **Gate/review:** SCORE upstream.
- **Definition of done:** SCORE PR 3 opened.

### F4 — PR 4 scorehsm readiness: STM32L5 backend

- **Step ID:** F4
- **Goal:** Confirm HIL evidence supports upstream submission.
- **Inputs:** F3, D1..D6 (all RB-01 sub-requirements), D7 (PID), D9 (TRNG).
- **Acceptance criteria:** HIL run results attached as a CI artifact on the scorehsm side and cited in the upstream PR.
- **Gate/review:** SCORE upstream.
- **Definition of done:** SCORE PR 4 opened.

### F5 — PR 5 scorehsm readiness: safety documentation

- **Step ID:** F5
- **Goal:** Confirm E1..E4 safety docs are ready to accompany SCORE PR 5.
- **Inputs:** F4, E1, E2, E4.
- **Acceptance criteria:** Safety doc bundle zipped and attached to the upstream PR; every SCORE `feat_req__sec_crypt__*` ID traces to an HSM-REQ/FSR/TSR.
- **Gate/review:** SCORE upstream safety WG review.
- **Definition of done:** SCORE PR 5 opened.

---

## Phase G — Integrator evidence (tracked, non-blocking)

gap-analysis §6 lists 12 Assumed Safety Requirements (ASR-HW-01..05, ASR-OS-01..03, ASR-INT-01..04). Repository-owned deferral records now exist for all 12 rows, but no downstream program evidence has been supplied. These are **integrator obligations**, not scorehsm deliverables, and do not block SEooC release. They DO block any ASIL-B vehicle integration that consumes scorehsm.

### G1..G12 — Collect integrator evidence per gap-analysis §6

- **Step ID:** G1..G12 (one per ASR row)
- **Goal:** Collect the evidence artifact named in each ASR row.
- **Inputs:** gap-analysis.md §6, each ASR's integrator checklist.
- **Deliverables:** `docs/safety/integrator-evidence/<asr-id>.md` for each ASR, carrying the collected evidence or a statement that the item is deferred to a specific integrator.
- **Acceptance criteria:** Either the evidence is captured, or the deferral is signed off by the project safety engineer.
- **Gate/review:** Integrator acceptance (not SCORE).
- **Definition of done:** Each ASR row in gap-analysis.md §6 has either evidence or a recorded deferral.

---

## Status tracker

Every step starts at **OPEN**. Normal transitions remain OPEN -> IN_PROGRESS -> READY_FOR_REVIEW -> CLOSED. When a step is intentionally parked on an external prerequisite, mark it **DEFERRED**. When a step is no longer part of the active project scope, mark it **RETIRED**. This table is the single source of truth for step status inside this plan; maintain it in lockstep with commits that close, defer, or retire steps.

| Step | Anchor ID | Owner role | Target date (basis) | Status |
|------|-----------|------------|---------------------|--------|
| A1 | TQR-OI-01 | Embedded Developer | 2026-03-21 (plan-score-contribution Section 11) | CLOSED |
| A2 | GC-BTS | Host Library Developer | Before B1 | CLOSED |
| A3 | GC-LIC | Configuration Manager | Before F1 | CLOSED |
| A4 | GC-README | Host Library Developer | Before any external announcement | CLOSED |
| A5 | GC-UNWRAP | Host Library Developer | Before F3 | CLOSED |
| A6 | GC-CRC | Host Library Developer | Optional - non-blocking | CLOSED |
| B1 | GC-FFI-SKEL | Host Library Developer | After A2 | CLOSED |
| B2 | GC-FFI-IMPL | Host Library Developer | After B1 | CLOSED |
| B3 | GC-FFI-HDR | Host Library Developer | After B2 | CLOSED |
| B4 | GC-FFI-TEST | Tester | After B3 | CLOSED |
| B5 | GC-FFI-CI | Configuration Manager | After B4 | CLOSED |
| C1 | CR-01 | Host Library Developer | Before C11 | CLOSED |
| C2 | CR-02 | Host Library Developer | Before C11 | CLOSED |
| C3 | CR-03 | Host Library Developer | Before C11 | CLOSED |
| C4 | CR-04 | Host Library Developer | Before C11 | CLOSED |
| C5 | CR-05 | Host Library Developer | Before C11 | CLOSED |
| C6 | gap Section 4.1 | Host Library Developer | Before C11 | CLOSED |
| C7 | gap Section 4.2 | Host Library Developer | Before C11 | CLOSED |
| C8 | gap Section 4.3 | Host Library Developer | Before C11 | CLOSED |
| C9 | HP-05 | Host Library Developer | 2026-04-15 (gap-analysis HP-05) | CLOSED |
| C10 | RB-05 | Software Safety Engineer | 2026-04-15 (gap-analysis RB-05) | CLOSED |
| C11 | RB-02 | Host Library Developer | 2026-04-30 (gap-analysis RB-02) | CLOSED |
| C12 | RB-03 | Tester | 2026-04-01 (gap-analysis RB-03) | CLOSED |
| D0 | - | Embedded Developer | Before D1 | DEFERRED |
| D1 | RB-01.a | Embedded Developer | 2026-05-15 (gap-analysis RB-01) | DEFERRED |
| D2 | RB-01.b | Embedded Developer | 2026-05-15 | DEFERRED |
| D3 | RB-01.c | Embedded Developer | 2026-05-15 | DEFERRED |
| D4 | RB-01.d | Host Library Developer | 2026-05-15 | DEFERRED |
| D5 | RB-01.e / SD-03 | Embedded Developer | 2026-05-15 | DEFERRED |
| D6 | RB-01.f | Embedded Developer | 2026-05-15 | DEFERRED |
| D7 | HP-01 | Configuration Manager | Before first production flash | DEFERRED |
| D8 | HP-03 | Embedded Developer | After D0 | DEFERRED |
| D9 | HP-04 | Embedded Developer | 2026-04-30 (gap-analysis HP-04) | DEFERRED |
| D10 | SD-03 | Embedded Developer | Tracked with D5 | DEFERRED |
| D11 | SD-05 | Embedded Developer | 2026-05-15 (gap-analysis SD-05) | DEFERRED |
| D12 | gap Section 4.4 | Host Library Developer | After D0 | DEFERRED |
| E1 | SD-01 | Safety Engineer | 2026-05-15 (gap-analysis SD-01) | CLOSED |
| E2 | SD-02 | Safety Engineer | 2026-04-15 (gap-analysis SD-02) | CLOSED |
| E3 | SD-04 | Safety Engineer | Clarify | CLOSED |
| E4 | RB-04 | Safety Engineer | Before v0.1.0 (gap-analysis RB-04) | DEFERRED |
| E5 | HP-02 | Configuration Manager | Linux runner availability | CLOSED |
| F1 | SCORE PR 1 | Maintainer | After A2, A3 | RETIRED |
| F2 | SCORE PR 2 | Maintainer | After F1, B3 | RETIRED |
| F3 | SCORE PR 3 | Maintainer | After F2, B5, C11 | RETIRED |
| F4 | SCORE PR 4 | Maintainer | After F3, D1..D6, D7, D9 | RETIRED |
| F5 | SCORE PR 5 | Safety Engineer | After F4, E1..E4 | RETIRED |
| G1..G12 | ASR-* | Integrator | Per vehicle integration schedule | CLOSED |
---

## Exit criteria for this plan

This plan is COMPLETE for the current project scope when all of the following are true:

1. Every row in the Status Tracker above is marked CLOSED, DEFERRED, or RETIRED.
2. docs/safety/gap-analysis.md records every remaining external dependency explicitly rather than leaving it as an unstated open software gap.
3. The retired SCORE upstream phase remains retired unless a new project decision reactivates it.
4. Deferred items point to a real downstream or prerequisite record (for example the hardware-verification deferral, the T1-review deferral, or the per-ASR integrator records).

---

## Maintenance

- Treat the Status Tracker table as authoritative. When a step closes, update the row in the same commit that delivers the change.
- If a new gap is discovered during execution, add a new step with a stable ID (next free `GC-*` or, if the gap fits gap-analysis, bump gap-analysis revision and cite the new row here).
- Do NOT edit step IDs after this revision; reorder only by adding dependencies in the graph.
- Any deadline added to this plan must cite a basis (gap-analysis row, requirement doc, or physical prerequisite) per the project plan-writing rule.