# scorehsm — Software Unit Design (SUD)

Date: 2026-03-14
Standard: ISO 26262-6:2018 §8
Status: RELEASED
ASIL Target: ASIL B
Document ID: SCORE-SUD

---

## 1. Purpose

This document defines the unit-level design for safety-critical software units in
`scorehsm-host`. For each unit, it specifies: data structures, algorithms, invariants,
error handling, and the SSRs implemented. This is the input to unit implementation
and unit testing.

Only ASIL B safety-critical units are described. Non-safety units (IDS hook, software
backend, PQC module) are excluded.

---

## 2. Unit: `LibraryState` (`safety.rs`)

**SSRs:** HSM-REQ-061, HSM-REQ-062, HSM-REQ-063, HSM-REQ-064

### 2.1 Data Structure

```rust
/// Encoded as u8: 0=Initializing, 1=Ready, 2=Operating, 3=SafeState
static LIBRARY_STATE: AtomicU8 = AtomicU8::new(0 /* Initializing */);

#[repr(u8)]
enum LibState { Initializing = 0, Ready = 1, Operating = 2, SafeState = 3 }
```

### 2.2 State Transition Rules

| From | To | Trigger | Guard |
|---|---|---|---|
| Initializing | Ready | POST passes + device handshake succeeds | All POST KATs pass; VID/PID verified |
| Ready | Operating | First operation dispatched | State must be Ready |
| Operating | Operating | Operation completes normally | — |
| Any | SafeState | `enter_safe_state(reason)` | Unconditional |
| SafeState | Initializing | `hsm_reinit()` | Explicit caller action |

### 2.3 `enter_safe_state` Algorithm

```
fn enter_safe_state(reason: SafeStateReason):
    1. CAS LIBRARY_STATE from {any} to SafeState with SeqCst
       (compare_exchange_weak loop until success or already SafeState)
    2. session_layer.invalidate_all_sessions()
    3. ids_hook.emit(IdsEvent::LibrarySafeState {
           reason,
           seq_num: transport.current_seq_num(),
           active_sessions: session_count_at_entry,
       })
    -- Do NOT return error from this function; it is called on error paths
```

### 2.4 Guard at Every API Entry

```
fn api_entry_guard(state: &AtomicU8) -> HsmResult<()>:
    match state.load(SeqCst):
        SafeState  → Err(HsmError::SafeState)
        Initializing → Err(HsmError::NotInitialized)
        Ready | Operating → Ok(())
```

### 2.5 Invariants

- `LIBRARY_STATE` transitions are monotonically towards `SafeState` except for re-init
- `SafeState` entry is idempotent (second `enter_safe_state` call is a no-op)
- `SeqCst` ordering on every load/store ensures visibility across threads

---

## 3. Unit: `NonceManager` (`safety.rs`)

**SSRs:** HSM-REQ-054, HSM-REQ-055, HSM-REQ-056

### 3.1 Data Structure

```sql
-- SQLite WAL schema
CREATE TABLE IF NOT EXISTS nonce_counters (
    key_id   INTEGER PRIMARY KEY,
    counter  INTEGER NOT NULL DEFAULT 0,
    algo     TEXT NOT NULL
);
```

```rust
struct NonceManager {
    conn: Mutex<rusqlite::Connection>,  // WAL mode, single writer
}
```

### 3.2 `next_iv` Algorithm

```
fn next_iv(key_id: u64, algo: AeadAlgo) -> HsmResult<[u8; 12]>:
    1. BEGIN IMMEDIATE TRANSACTION
    2. SELECT counter FROM nonce_counters WHERE key_id = ?
       -- If not found: INSERT (key_id, 0, algo_string)
    3. IF counter == u64::MAX → ROLLBACK; return Err(NonceExhausted)
    4. new_counter = counter + 1  -- pre-increment
    5. UPDATE nonce_counters SET counter = new_counter WHERE key_id = ?
    6. COMMIT  -- fsync guaranteed by WAL + PRAGMA synchronous=FULL
    7. info = algo.domain_string()  -- from approved table
    8. ikm = key_id.to_le_bytes() || new_counter.to_le_bytes()
    9. iv = hkdf_sha256(ikm, info, length=12)
    10. return Ok(iv)
```

### 3.3 Domain String Table

| Algo | Domain string |
|---|---|
| AES-128-GCM | `"scorehsm-aead-iv-aes128gcm"` |
| AES-256-GCM | `"scorehsm-aead-iv-aes256gcm"` |
| AES-128-CCM | `"scorehsm-aead-iv-aes128ccm"` |

Any algo not in this table → `Err(UnsupportedAlgorithm)`

### 3.4 Invariants

- Counter is always incremented **before** the crypto operation uses it
- Rollback on any DB error means the counter is not advanced (safe: skipped value, no reuse)
- `synchronous=FULL` ensures the increment survives a power loss between commit and AEAD call

---

## 4. Unit: `RateLimiter` (`safety.rs`)

**SSRs:** HSM-REQ-060

### 4.1 Data Structure

```rust
struct TokenBucket {
    tokens: f64,          // current token count
    capacity: f64,        // burst capacity
    refill_rate: f64,     // tokens per second
    last_refill: Instant,
}

struct RateLimiter {
    buckets: Mutex<HashMap<OpClass, TokenBucket>>,
}
```

### 4.2 `check_and_consume` Algorithm

```
fn check_and_consume(op: OpClass) -> HsmResult<()>:
    1. Lock buckets
    2. bucket = buckets[op]
    3. elapsed = Instant::now() - bucket.last_refill
    4. bucket.tokens = min(bucket.capacity,
                           bucket.tokens + elapsed.as_secs_f64() * bucket.refill_rate)
    5. bucket.last_refill = Instant::now()
    6. IF bucket.tokens < 1.0:
          ids_hook.emit(IdsEvent::RateLimitExceeded { op })
          return Err(HsmError::RateLimitExceeded)
    7. bucket.tokens -= 1.0
    8. return Ok(())
```

### 4.3 Default Configuration

| OpClass | rate (ops/s) | burst |
|---|---|---|
| EcdsaSign | 10 | 5 |
| EcdsaVerify | 20 | 10 |
| KeyGen | 2 | 1 |
| Ecdh | 10 | 5 |
| AesGcm | 100 | 20 |

---

## 5. Unit: `SessionMap` (`session.rs`)

**SSRs:** HSM-REQ-057, HSM-REQ-058, HSM-REQ-059, HSM-REQ-065

### 5.1 Data Structure

```rust
struct SessionState {
    handles:     HashSet<KeyHandle>,
    last_active: Instant,
}

struct SessionMap {
    inner:    Mutex<HashMap<SessionId, SessionState>>,
    checksum: AtomicU32,   // CRC-32 of serialized map
    max_sessions: usize,
}
```

### 5.2 `open_session` Algorithm

```
fn open_session() -> HsmResult<SessionId>:
    1. lock inner
    2. IF inner.len() >= max_sessions → Err(ResourceExhausted)
    3. session_id = new_unique_id()
    4. inner.insert(session_id, SessionState { handles: {}, last_active: now })
    5. update_checksum(&inner)
    6. ids_hook.emit(SessionOpened { session_id })
    7. return Ok(session_id)
```

### 5.3 `validate_handle` Algorithm

```
fn validate_handle(session_id: SessionId, handle: KeyHandle) -> HsmResult<()>:
    1. lock inner
    2. verify_checksum(&inner, checksum.load(SeqCst)) → if fail: enter_safe_state; Err
    3. session = inner.get(session_id) → if None: Err(InvalidSession)
    4. IF !session.handles.contains(handle) → Err(InvalidHandle)
    5. session.last_active = Instant::now()
    6. Ok(())
```

### 5.4 Timeout Sweep Algorithm

```
fn timeout_sweep(timeout: Duration):
    -- Called by background task at ≤1 s intervals
    1. now = Instant::now()
    2. lock inner
    3. expired = inner.retain(|_, s| now - s.last_active <= timeout; collect removed)
    4. FOR EACH expired session:
          ids_hook.emit(SessionExpired { session_id })
    5. IF !expired.is_empty(): update_checksum(&inner)
```

### 5.5 `update_checksum` and `verify_checksum`

```
fn update_checksum(map: &HashMap<SessionId, SessionState>):
    bytes = serialize_deterministic(map)  -- sorted by key
    crc = crc32_mpeg2(bytes)
    checksum.store(crc, SeqCst)

fn verify_checksum(map: &HashMap<SessionId, SessionState>, stored: u32) -> bool:
    bytes = serialize_deterministic(map)
    crc = crc32_mpeg2(bytes)
    crc == stored
```

---

## 6. Unit: Transport Layer (`transport.rs`)

**SSRs:** HSM-REQ-050, HSM-REQ-051, HSM-REQ-052, HSM-REQ-053, HSM-REQ-068, HSM-REQ-069

### 6.1 Frame Format

```
 0        1        2        3        4        5        6        7
 ┌────────┬────────┬────────┬────────┬────────────────┬────────────────┐
 │ MAGIC  │ OPCODE │  SEQ# (32-bit LE)               │ LEN (16-bit LE)│
 ├────────┴────────┴─────────────────────────────────┴────────────────┤
 │ PAYLOAD (0..LEN bytes)                                              │
 ├─────────────────────────────────────────────────────────────────────┤
 │ CRC-32/MPEG-2 (4 bytes LE, over bytes 0..LEN+8)                   │
 └─────────────────────────────────────────────────────────────────────┘
 Total frame size: 8 + LEN + 4 bytes
 Maximum LEN: 4096 bytes (enforced by HSM-REQ-044)
```

### 6.2 `send_command` Algorithm

```
fn send_command(op: HsmOp, timeout: Duration) -> HsmResult<HsmResponse>:
    attempt = 0
    LOOP:
        1. seq = seq_counter  -- current value (pre-increment)
        2. IF seq == u64::MAX → Err(SequenceOverflow); enter_safe_state
        3. seq_counter += 1  -- increment after guard
        4. frame = encode_frame(op, seq as u32)
        5. frame.append(crc32_mpeg2(&frame))
        6. usb.write_frame(&frame)
        7. response_raw = usb.read_with_timeout(timeout)
              IF timeout: → attempt++; if attempt == 3: enter_safe_state; Err(Timeout)
                            else: back_off(attempt); continue LOOP
        8. IF crc32_mpeg2(response_raw[..len-4]) != response_raw[len-4..]:
              → attempt++; if attempt == 3: enter_safe_state; Err(CrcMismatch)
              else: back_off(attempt); continue LOOP
        9. resp_seq = decode_seq(response_raw)
        10. IF resp_seq != seq as u32 → enter_safe_state; Err(ProtocolError)
        11. IF resp_opcode == FAULT_OPCODE → enter_safe_state; Err(HardwareFault)
        12. return Ok(decode_response(response_raw))
```

### 6.3 `back_off` Function

```
fn back_off(attempt: u8):
    sleep(Duration::from_millis(10 * 2u64.pow(attempt - 1)))
    -- attempt 1: 10 ms; attempt 2: 20 ms
```

### 6.4 Startup Handshake Algorithm

```
fn run_startup_handshake(config: &HsmConfig) -> HsmResult<()>:
    1. dev = open_usb_device()
    2. IF dev.vid != VID_STM32 OR dev.pid != config.expected_pid → Err(InitializationFailed)
    3. frame = encode_capability_request(seq=0)
    4. usb.write_frame(frame)
    5. resp = usb.read_with_timeout(500 ms) → if fail: Err(InitializationFailed)
    6. verify CRC-32 of resp → if fail: Err(InitializationFailed)
    7. verify resp.seq == 0 → if fail: Err(InitializationFailed)
    8. cap = decode_capabilities(resp)
    9. IF cap.fw_version < config.min_fw_version → Err(InitializationFailed)
    10. IF !cap.bitmask.contains(config.required_ops) → Err(InitializationFailed)
    11. stored_vid_pid = (dev.vid, dev.pid)
    12. return Ok(())

fn on_usb_reenumeration(new_dev):
    IF (new_dev.vid, new_dev.pid) != stored_vid_pid → enter_safe_state; Err(DeviceIdentityChanged)
```

---

## 7. Unit: Certificate Validity Check (`cert.rs`)

**SSRs:** HSM-REQ-070, HSM-REQ-071

### 7.1 Algorithm

```
fn check_certificate_validity(cert: &Certificate) -> HsmResult<()>:
    1. now_result = SystemTime::now().duration_since(UNIX_EPOCH)
    2. IF now_result.is_err() → Err(HsmError::ClockUnavailable)
    3. now = now_result.unwrap()  -- safe: checked above
    4. not_before = cert.tbs_certificate.validity.not_before.to_unix_duration()
    5. not_after  = cert.tbs_certificate.validity.not_after.to_unix_duration()
    6. IF now < not_before → Err(HsmError::CertificateNotYetValid)
    7. IF now > not_after  → Err(HsmError::CertificateExpired)
    8. return Ok(())
```

### 7.2 Invariant

- This function is called unconditionally before any operation that uses a certificate
- No caller may skip this check via a feature flag or configuration option

---

## 8. Unit: Power-On Self-Test (`lib.rs` initialization path)

**SSRs:** HSM-REQ-074, HSM-REQ-075, HSM-REQ-076

### 8.1 AES-256-GCM KAT

```
const KAT_AES_KEY: [u8; 32]  = [...];  // NIST SP 800-38D test vector
const KAT_AES_PT:  [u8; 16]  = [...];
const KAT_AES_IV:  [u8; 12]  = [...];
const KAT_AES_AAD: [u8; 20]  = [...];
const KAT_AES_CT:  [u8; 16]  = [...];
const KAT_AES_TAG: [u8; 16]  = [...];

fn post_aes_gcm_kat(backend: &dyn HsmBackend) -> HsmResult<()>:
    1. result = backend.aead_encrypt(KAT_AES_KEY, KAT_AES_PT, KAT_AES_IV, KAT_AES_AAD)
    2. IF result.ciphertext != KAT_AES_CT OR result.tag != KAT_AES_TAG →
          Err(HsmError::SelfTestFailed)
    3. plaintext = backend.aead_decrypt(KAT_AES_KEY, KAT_AES_CT, KAT_AES_TAG,
                                         KAT_AES_IV, KAT_AES_AAD)
    4. IF plaintext != KAT_AES_PT → Err(HsmError::SelfTestFailed)
    5. return Ok(())
```

### 8.2 ECDSA P-256 KAT

```
const KAT_EC_SK:  [u8; 32] = [...];  // NIST P-256 CAVS test vector
const KAT_EC_PK:  [u8; 64] = [...];
const KAT_EC_MSG: [u8; 32] = [...];
const KAT_EC_SIG: [u8; 64] = [...];

fn post_ecdsa_kat(backend: &dyn HsmBackend) -> HsmResult<()>:
    1. verify_result = backend.ecdsa_verify(KAT_EC_PK, KAT_EC_MSG, KAT_EC_SIG)
    2. IF !verify_result → Err(HsmError::SelfTestFailed)
    -- Sign-then-verify with derived key pair also acceptable as KAT
    3. return Ok(())
```

### 8.3 POST Sequencing

```
fn hsm_init(config: HsmConfig) -> HsmResult<HsmContext>:
    assert LIBRARY_STATE == Initializing
    1. backend = select_backend(config)
    2. run_startup_handshake(&config) → if Err: return Err(InitializationFailed)
    3. post_aes_gcm_kat(&backend) → if Err: return Err(SelfTestFailed)
    4. post_ecdsa_kat(&backend) → if Err: return Err(SelfTestFailed)
    5. LIBRARY_STATE.store(Ready, SeqCst)  -- only reached if all POST pass
    6. return Ok(HsmContext { backend, session_map, safety_services, ... })
```

---

## 9. Unit Design Invariants (All Safety Units)

1. **No `.unwrap()` on `Result` or `Option`** — use `?`, `ok_or`, or `match`
2. **No `.expect()` with a message that leaks key material** — error messages are constants, not formatted with runtime data
3. **All `Mutex` locks use `.lock().map_err(|_| HsmError::InternalError)?`** — poison propagated as error
4. **All `AtomicU8` operations use `SeqCst`** — no relaxed/acquire/release for state transitions
5. **Every function that calls `enter_safe_state` does NOT subsequently return `Ok(_)`** — safe state entry always accompanies an error return

---

*Document end — SCORE-SUD rev 1.0 — 2026-03-14*
