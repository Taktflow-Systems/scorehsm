# scorehsm - Tool Qualification Records

Date: 2026-04-22
Standard: ISO 26262-8:2018 Section 11 (Software Tools)
Status: ACTIVE
ASIL Target: ASIL B
Document ID: SCORE-TQR

---

## 1. Purpose

ISO 26262-8 Section 11 requires that software tools used in the development and
verification of safety-relevant software be qualified. Tool qualification
establishes confidence that tool failures do not introduce undetected errors
into the safety-relevant software.

Tool Confidence Level (TCL) is derived from:
- TI (Tool Impact): could a malfunction introduce or fail to detect a fault?
- TD (Tool Error Detection): would other measures detect that malfunction?

| TCL | TI | TD | Qualification requirement |
|---|---|---|---|
| TCL-1 | 1 | 1 | No additional qualification beyond normal controls |
| TCL-2 | 1 | 0 | Tool validation with recorded evidence |
| TCL-3 | 1 | 0 (high impact) | Full qualification or tool avoidance |

For ASIL B, TCL-2 tools require validation evidence; TCL-3 tools require full
qualification or avoidance.

---

## 2. Tool Inventory

### T1 - Rust Compiler (rustc)

| Field | Value |
|---|---|
| Tool name | `rustc` (Rust compiler) |
| Version | Host/library CI: `rustc 1.87.0`; firmware CI: `rustc 1.96.0-nightly (1d8897a4e 2026-03-13)` pinned by `nightly-2026-03-14` |
| Vendor | The Rust Project Developers (Rust Foundation) |
| Purpose | Compiles safety-relevant Rust source code to native binaries |
| TI | 1 - a compiler bug could generate incorrect code without warning |
| TD | 1 - extensive upstream compiler testing plus repository test coverage and CI diversity |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** Although `rustc` has TI=1, TD=1 because:
1. `rustc` has a large upstream regression suite.
2. Safety-relevant paths are exercised by repository unit/integration tests.
3. CI diversity across host and firmware paths would surface many toolchain regressions.
4. The firmware nightly is pinned to a specific dated release and printed in CI.

**Validation evidence:** Host tests run on the pinned 1.87.0 toolchain in CI.
Firmware CI installs `nightly-2026-03-14`, prints `rustc --version`, and
builds both the non-TrustZone and TrustZone firmware paths against that exact
nightly.

**Note on nightly toolchain:** The host library is intentionally kept on stable
`1.87.0`. The firmware path remains on a dated nightly because the Embassy-based
STM32L5 build currently requires it. The nightly is pinned in
`firmware/rust-toolchain.toml` and mirrored in `.github/workflows/ci.yml`,
which closes the toolchain-drift risk for firmware work.

**Status:** **CLOSED** - both host and firmware compiler versions are pinned and
recorded.

---

### T2 - Cargo (Build System and Package Manager)

| Field | Value |
|---|---|
| Tool name | `cargo` |
| Version | Host `1.87.0`; firmware nightly companion to `nightly-2026-03-14` |
| Vendor | The Rust Project Developers |
| Purpose | Dependency resolution, build orchestration, test runner |
| TI | 1 - wrong dependency version or build flag could silently change behavior |
| TD | 1 - `Cargo.lock`, pinned toolchains, and CI make drift visible |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** `Cargo.lock` provides reproducibility for the host
crate graph, while the pinned firmware nightly constrains the embedded build.
Cargo orchestrates builds; it does not itself generate machine code.

**Validation evidence:** `Cargo.lock` is committed; CI builds and tests are
reproducible against pinned toolchains.

---

### T3 - cargo-llvm-cov (Coverage Tool)

| Field | Value |
|---|---|
| Tool name | `cargo-llvm-cov` |
| Version | `cargo-llvm-cov 0.8.5` |
| Vendor | Community (Taiki Endo) |
| Purpose | Measures structural coverage for ASIL B coverage evidence |
| TI | 1 - incorrect coverage could falsely assert the target was met |
| TD | 0 - incorrect coverage numbers would not otherwise be detected reliably |
| **TCL** | **TCL-2** |

**Qualification approach (TCL-2 - Tool Validation):**

Coverage tool validation demonstrates that the tool correctly measures coverage
on a committed known-answer test fixture.

**Validation test: Coverage KAT**

The repository includes `tools/coverage-kat/`, a standalone crate with a small
branching function and two tests that intentionally cover only part of the
instrumented control flow.

```rust
pub fn branch_kat(x: u8) -> u8 {
    if x == 0 { return 1; }
    if x == 1 { return 2; }
    if x == 2 { return 3; }
    4
}
```

**Execution record (2026-04-22):**
- Tool: `cargo-llvm-cov 0.8.5`
- Compiler: `rustc 1.96.0-nightly (1d8897a4e 2026-03-13)` via `nightly-2026-03-14`
- Command: `cargo +nightly-2026-03-14 llvm-cov --manifest-path tools/coverage-kat/Cargo.toml --branch --json --summary-only --output-path .tmp/coverage-kat-summary.json`
- Observed result: branch coverage = `50.0%` (`3/6` LLVM-instrumented branches covered), line coverage = `72.22%`

**Pass criterion:** Reported branch coverage = `50.0%` for the committed
fixture.

**Status:** **CLOSED** - the KAT executed and matched the expected branch result
exactly.

**Validation evidence:** `tools/coverage-kat/`,
`.tmp/coverage-kat-summary.json`, and
`docs/safety/qualification-test-evidence.md` Section 7.

---

### T4 - Clippy (Static Analysis)

| Field | Value |
|---|---|
| Tool name | `cargo clippy` |
| Version | Same as host CI toolchain (`cargo clippy 1.87.0`) |
| Vendor | The Rust Project Developers |
| Purpose | Static analysis - detects Rust anti-patterns and likely defects |
| TI | 1 - a missed warning could allow a latent bug to pass review |
| TD | 0 - false negatives are not detected by other static analysis automatically |
| **TCL** | **TCL-2** |

**Qualification approach (TCL-2 - Tool Validation):**

Clippy is run with `-- -D warnings` (zero-warning policy). Validation
demonstrates:
1. Clippy is wired into CI as a blocking step.
2. The repository runs clean with zero warnings on the safety-relevant host path.

**Validation evidence:** The `host-clippy` job in `.github/workflows/ci.yml`
runs `cargo clippy --workspace --all-targets --features "mock,certs" -- -D warnings`
on every push and pull request.

**Status:** **CLOSED** - blocking CI integration is in place and consistent.

---

### T5 - cargo-audit (Dependency Vulnerability Scanner)

| Field | Value |
|---|---|
| Tool name | `cargo-audit` |
| Version | Latest stable (CI-managed) |
| Vendor | RustSec Advisory Database |
| Purpose | Identifies known vulnerabilities in transitive dependencies |
| TI | 0 - read-only tool; does not modify the build artifact |
| TD | 1 |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** `cargo-audit` is advisory and read-only. It is useful
defense in depth but does not itself create safety-relevant output.

---

### T6 - GitHub Actions (CI Platform)

| Field | Value |
|---|---|
| Tool name | GitHub Actions |
| Version | Hosted runners (`ubuntu-24.04`, firmware nightly workflow) |
| Vendor | GitHub (Microsoft) |
| Purpose | Automated CI execution of build, test, coverage, and lint |
| TI | 1 - a CI platform failure could conceal a failing check |
| TD | 1 - check status visibility and local reruns make silent failures unlikely |
| **TCL** | **TCL-1** |

**Rationale for TCL-1:** CI failures are visible as failed checks, and developers
can reproduce the same commands locally.

---

## 3. Tool Qualification Summary

| ID | Tool | Version | TCL | Status |
|---|---|---|---|---|
| T1 | rustc | host `1.87.0`; firmware `nightly-2026-03-14` | TCL-1 | Complete |
| T2 | cargo | host `1.87.0`; firmware nightly companion | TCL-1 | Complete |
| T3 | cargo-llvm-cov | `0.8.5` | TCL-2 | Complete |
| T4 | cargo clippy | `1.87.0` | TCL-2 | Complete |
| T5 | cargo-audit | latest | TCL-1 | Complete |
| T6 | GitHub Actions | hosted | TCL-1 | Complete |

Open tooling items: none at the repository level. Future toolchain upgrades must
update this record and rerun the `cargo-llvm-cov` KAT.

---

## 4. Dependency Security Audit

The following table lists direct host dependencies with their safety-relevant
security posture as of this document date.

| Crate | Version | Purpose | Advisory Status |
|---|---|---|---|
| `aes-gcm` | 0.10 | AES-256-GCM encryption | No known advisories |
| `sha2` | 0.10 | SHA-256 hashing | No known advisories |
| `hmac` | 0.12 | HMAC-SHA256 | No known advisories |
| `hkdf` | 0.12 | HKDF key derivation | No known advisories |
| `p256` | 0.13 | ECDSA P-256, ECDH | No known advisories |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 | No known advisories |
| `sha3` | 0.10 | SHA-3 | No known advisories |
| `rand_core` | 0.6 | RNG interface | No known advisories |
| `rand_chacha` | 0.3 | ChaCha RNG | No known advisories |
| `zeroize` | 1 | Key zeroization | No known advisories |
| `subtle` | 2 | Constant-time operations | No known advisories |
| `serialport` | 4 | USB CDC serial | No known advisories |
| `thiserror` | 1 | Error handling | No known advisories |

`cargo audit` remains a read-only assurance check and is tracked as ongoing
release hygiene rather than a blocking qualification item.

---

Document end - SCORE-TQR rev 1.1 - 2026-04-22
