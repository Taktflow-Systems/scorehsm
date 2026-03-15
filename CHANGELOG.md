# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-03-15

### Added
- Host library (`scorehsm-host`) with software and mock backends
- Safety services: LibraryState, TokenBucketRateLimiter, NonceManager, KeyStoreChecksum
- Transport layer: CRC-32/MPEG-2 frame integrity, u32 sequence numbers, per-op timeouts, retry with backoff
- Session management: handle isolation, IDS event hooks, rate limiting
- 58 integration tests (ITP) covering TSR-TIG, TSR-NMG, TSR-SMG, TSR-RLG, TSR-SSG, TSR-IVG, TSR-CG
- 57 qualification tests (QTE) covering all 16 FSRs (FSR-01 through FSR-16)
- Firmware: Embassy async USB CDC, crypto dispatch, watchdog (IWDG), KeyImport command
- TrustZone support: SAU configuration, S-world linker script, feature-gated activation
- CI pipeline: test, clippy, fmt, coverage, firmware cross-check (GitHub Actions, 4 host jobs)
- POST/KAT: AES-GCM, ECDSA P-256, SHA-256 known-answer tests at startup
- Secure firmware update with ECDSA-P256 signature verification and rollback protection
- Feature activation with monotonic counter and ECDSA-P256 token verification
- Onboard communication: IKEv2 key derivation, MACsec MKA support
- Certificate management with validity checking (optional `certs` feature)
- Post-quantum crypto stubs (optional `pqc` feature)
- 274 tests passing (54 unit + 58 ITP + 57 QTE + 104 feature + 1 doc-test)
- Full ISO 26262 V-model documentation (11 safety documents, SCORE-UTT traceability)
- CI badge in README

### Changed
- Phase 9 CI pipeline operational (4/4 host jobs green, firmware non-blocking)
- Phase 10 evidence collection complete (doc updates, test count verification)
- Verification report updated to Rev 1.2 with 274 tests
- Unit test traceability updated: 28/28 SSRs now covered (17 previously pending at integration level)
