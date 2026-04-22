// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! C FFI bridge for scorehsm-host.
//!
//! The exported `HSM_*` functions mirror the planned C surface and route all
//! operations through a single global [`crate::session::HsmSession`] instance.

#![allow(non_camel_case_types, non_snake_case)]

use std::panic::{self, AssertUnwindSafe};
use std::slice;
use std::sync::{Mutex, OnceLock};

use crate::backend::HsmBackend;
use crate::error::{HsmError, HsmResult};
use crate::session::HsmSession;
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};

#[cfg(feature = "sw-backend")]
use crate::backend::sw::SoftwareBackend;

#[cfg(feature = "hw-backend")]
use crate::backend::hw::HardwareBackend;

/// C status type used by the exported `HSM_*` API.
pub type HsmStatus_t = i32;
/// Opaque C key-handle type.
pub type HsmKeyHandle_t = u32;
/// C key-type discriminant.
pub type HsmKeyType_t = u32;

/// Success status.
pub const HSM_OK: HsmStatus_t = 0;
/// Invalid argument or pointer status.
pub const HSM_ERR_INVALID_PARAM: HsmStatus_t = -1;
/// Unknown key-handle status.
pub const HSM_ERR_INVALID_KEY_ID: HsmStatus_t = -2;
/// No free key-slot status.
pub const HSM_ERR_KEY_SLOT_FULL: HsmStatus_t = -3;
/// Generic cryptographic failure status.
pub const HSM_ERR_CRYPTO_FAIL: HsmStatus_t = -4;
/// Backend not initialized status.
pub const HSM_ERR_NOT_INITIALIZED: HsmStatus_t = -5;
/// AEAD authentication-tag mismatch status.
pub const HSM_ERR_TAG_MISMATCH: HsmStatus_t = -6;
/// Output buffer too small status.
pub const HSM_ERR_BUFFER_TOO_SMALL: HsmStatus_t = -7;
/// Unsupported-operation status.
pub const HSM_ERR_UNSUPPORTED: HsmStatus_t = -8;
/// Global safe-state status.
pub const HSM_ERR_SAFE_STATE: HsmStatus_t = -9;
/// Rate-limit rejection status.
pub const HSM_ERR_RATE_LIMIT: HsmStatus_t = -10;
/// Sequence-counter exhaustion status.
pub const HSM_ERR_SEQUENCE_OVERFLOW: HsmStatus_t = -11;
/// Nonce-space exhaustion status.
pub const HSM_ERR_NONCE_EXHAUSTED: HsmStatus_t = -12;
/// Certificate expired status.
pub const HSM_ERR_CERT_EXPIRED: HsmStatus_t = -13;
/// Certificate not-yet-valid status.
pub const HSM_ERR_CERT_NOT_YET_VALID: HsmStatus_t = -14;

/// AES-256 key-type constant.
pub const HSM_KEY_TYPE_AES_256: HsmKeyType_t = 0x0001;
/// HMAC-SHA256 key-type constant.
pub const HSM_KEY_TYPE_HMAC_SHA256: HsmKeyType_t = 0x0002;
/// ECC P-256 key-type constant.
pub const HSM_KEY_TYPE_ECC_P256: HsmKeyType_t = 0x0003;

/// SHA-256 digest length.
pub const HSM_SHA256_DIGEST_SIZE: usize = 32;
/// HMAC-SHA256 output length.
pub const HSM_HMAC_SHA256_SIZE: usize = 32;
/// AES-GCM IV length.
pub const HSM_AES_GCM_IV_SIZE: usize = 12;
/// AES-GCM tag length.
pub const HSM_AES_GCM_TAG_SIZE: usize = 16;
/// ECDH shared-secret length.
pub const HSM_ECDH_SHARED_SECRET_SIZE: usize = 32;
/// Uncompressed P-256 public key length without the SEC1 prefix.
pub const HSM_ECC_P256_PUBKEY_SIZE: usize = 64;

/// C boot-status struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmBootStatus_t {
    /// `true` if secure boot verification succeeded.
    pub verified: bool,
    /// Monotonic firmware version reported by the backend.
    pub firmware_version: u32,
}

/// C ECDSA signature struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmEcdsaSignature_t {
    /// `r` scalar in big-endian form.
    pub r: [u8; 32],
    /// `s` scalar in big-endian form.
    pub s: [u8; 32],
}

/// AES-GCM encrypt request.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmAesGcmEncryptReq_t {
    /// Opaque handle of the AES-256 key.
    pub key_handle: HsmKeyHandle_t,
    /// Pointer to a 12-byte IV.
    pub iv: *const u8,
    /// Pointer to additional authenticated data.
    pub aad: *const u8,
    /// Length of `aad` in bytes.
    pub aad_len: usize,
    /// Pointer to plaintext bytes.
    pub plaintext: *const u8,
    /// Length of `plaintext` in bytes.
    pub plaintext_len: usize,
    /// Caller-owned output buffer for ciphertext. Must be at least `plaintext_len`.
    pub ciphertext_out: *mut u8,
    /// Caller-owned output buffer for the 16-byte authentication tag.
    pub tag_out: *mut u8,
}

/// AES-GCM decrypt request.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmAesGcmDecryptReq_t {
    /// Opaque handle of the AES-256 key.
    pub key_handle: HsmKeyHandle_t,
    /// Pointer to a 12-byte IV.
    pub iv: *const u8,
    /// Pointer to additional authenticated data.
    pub aad: *const u8,
    /// Length of `aad` in bytes.
    pub aad_len: usize,
    /// Pointer to ciphertext bytes.
    pub ciphertext: *const u8,
    /// Length of `ciphertext` in bytes.
    pub ciphertext_len: usize,
    /// Pointer to the 16-byte authentication tag.
    pub tag: *const u8,
    /// Caller-owned output buffer for plaintext. Must be at least `ciphertext_len`.
    pub plaintext_out: *mut u8,
}

/// ECDSA verify request.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmEcdsaVerifyReq_t {
    /// Opaque handle of the verifying key.
    pub key_handle: HsmKeyHandle_t,
    /// Pointer to a 32-byte SHA-256 digest.
    pub digest: *const u8,
    /// Pointer to the signature to verify.
    pub signature: *const HsmEcdsaSignature_t,
    /// Caller-owned output location for the boolean verification result.
    pub result_out: *mut bool,
}

/// ECDH P-256 key-agreement request.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmEcdhReq_t {
    /// Opaque handle of the private P-256 key.
    pub key_handle: HsmKeyHandle_t,
    /// Pointer to a 64-byte uncompressed `X || Y` peer public key.
    pub peer_pub: *const u8,
    /// Caller-owned output buffer for the 32-byte shared secret.
    pub shared_secret_out: *mut u8,
}

/// HKDF-SHA256 derive request.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmHkdfReq_t {
    /// Opaque handle of the base key.
    pub base_handle: HsmKeyHandle_t,
    /// Pointer to HKDF `info` bytes.
    pub info: *const u8,
    /// Length of `info` in bytes.
    pub info_len: usize,
    /// Requested output key type.
    pub out_type: HsmKeyType_t,
    /// Caller-owned output location for the derived key handle.
    pub derived_handle_out: *mut HsmKeyHandle_t,
}

fn global_session() -> &'static Mutex<Option<HsmSession>> {
    static SESSION: OnceLock<Mutex<Option<HsmSession>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}

fn map_error(err: HsmError) -> HsmStatus_t {
    match err {
        HsmError::InvalidParam(_)
        | HsmError::InvalidArgument
        | HsmError::ClockUnavailable => HSM_ERR_INVALID_PARAM,
        HsmError::InvalidKeyHandle => HSM_ERR_INVALID_KEY_ID,
        HsmError::KeyStoreFull => HSM_ERR_KEY_SLOT_FULL,
        HsmError::CryptoFail(_)
        | HsmError::UsbError(_)
        | HsmError::Timeout
        | HsmError::ResourceExhausted
        | HsmError::InitializationFailed(_)
        | HsmError::HardwareFault
        | HsmError::IntegrityViolation
        | HsmError::SelfTestFailed
        | HsmError::DeviceIdentityChanged => HSM_ERR_CRYPTO_FAIL,
        HsmError::NotInitialized => HSM_ERR_NOT_INITIALIZED,
        HsmError::TagMismatch | HsmError::AuthenticationFailed => HSM_ERR_TAG_MISMATCH,
        HsmError::BufferTooSmall { .. } => HSM_ERR_BUFFER_TOO_SMALL,
        HsmError::Unsupported => HSM_ERR_UNSUPPORTED,
        HsmError::SafeState => HSM_ERR_SAFE_STATE,
        HsmError::RateLimitExceeded => HSM_ERR_RATE_LIMIT,
        HsmError::SequenceOverflow => HSM_ERR_SEQUENCE_OVERFLOW,
        HsmError::NonceExhausted => HSM_ERR_NONCE_EXHAUSTED,
        HsmError::CertificateExpired => HSM_ERR_CERT_EXPIRED,
        HsmError::CertificateNotYetValid => HSM_ERR_CERT_NOT_YET_VALID,
        HsmError::ReplayDetected(_, _) | HsmError::CrcMismatch | HsmError::ProtocolError => {
            HSM_ERR_CRYPTO_FAIL
        }
    }
}

fn ffi_status<T>(f: impl FnOnce() -> HsmResult<T>) -> HsmStatus_t {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(_)) => HSM_OK,
        Ok(Err(err)) => map_error(err),
        Err(_) => HSM_ERR_CRYPTO_FAIL,
    }
}

fn key_type_from_ffi(value: HsmKeyType_t) -> HsmResult<KeyType> {
    match value {
        HSM_KEY_TYPE_AES_256 => Ok(KeyType::Aes256),
        HSM_KEY_TYPE_HMAC_SHA256 => Ok(KeyType::HmacSha256),
        HSM_KEY_TYPE_ECC_P256 => Ok(KeyType::EccP256),
        _ => Err(HsmError::InvalidParam(format!("unknown key type {value:#06x}"))),
    }
}

fn build_session() -> HsmResult<HsmSession> {
    #[cfg(feature = "hw-backend")]
    if let Ok(port_path) = std::env::var("SCOREHSM_PORT") {
        let backend: Box<dyn HsmBackend> = Box::new(HardwareBackend::new(port_path));
        return Ok(HsmSession::from_boxed(backend));
    }

    #[cfg(feature = "sw-backend")]
    {
        let backend: Box<dyn HsmBackend> = Box::new(SoftwareBackend::new());
        return Ok(HsmSession::from_boxed(backend));
    }

    #[allow(unreachable_code)]
    Err(HsmError::Unsupported)
}

fn with_session_mut<T>(f: impl FnOnce(&mut HsmSession) -> HsmResult<T>) -> HsmResult<T> {
    let mut guard = global_session()
        .lock()
        .map_err(|_| HsmError::InitializationFailed("ffi session mutex poisoned".into()))?;
    let session = guard.as_mut().ok_or(HsmError::NotInitialized)?;
    f(session)
}

fn with_session<T>(f: impl FnOnce(&HsmSession) -> HsmResult<T>) -> HsmResult<T> {
    let guard = global_session()
        .lock()
        .map_err(|_| HsmError::InitializationFailed("ffi session mutex poisoned".into()))?;
    let session = guard.as_ref().ok_or(HsmError::NotInitialized)?;
    f(session)
}

unsafe fn input_slice<'a>(ptr: *const u8, len: usize, name: &str) -> HsmResult<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(HsmError::InvalidParam(format!("{name} pointer is null")));
    }
    // SAFETY: caller validated that `ptr` is non-null and promises it points to
    // `len` readable bytes for the duration of this call.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn output_slice<'a>(ptr: *mut u8, len: usize, name: &str) -> HsmResult<&'a mut [u8]> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(HsmError::InvalidParam(format!("{name} pointer is null")));
    }
    // SAFETY: caller validated that `ptr` is non-null and promises it points to
    // `len` writable bytes for the duration of this call.
    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

unsafe fn array_ref<const N: usize>(ptr: *const u8, name: &str) -> HsmResult<[u8; N]> {
    if ptr.is_null() {
        return Err(HsmError::InvalidParam(format!("{name} pointer is null")));
    }
    let mut out = [0u8; N];
    // SAFETY: caller validated that `ptr` points to at least `N` readable bytes.
    out.copy_from_slice(unsafe { slice::from_raw_parts(ptr, N) });
    Ok(out)
}

unsafe fn write_array<const N: usize>(ptr: *mut u8, bytes: &[u8; N], name: &str) -> HsmResult<()> {
    if ptr.is_null() {
        return Err(HsmError::InvalidParam(format!("{name} pointer is null")));
    }
    // SAFETY: caller validated that `ptr` points to at least `N` writable bytes.
    unsafe { slice::from_raw_parts_mut(ptr, N) }.copy_from_slice(bytes);
    Ok(())
}

unsafe fn write_struct<T: Copy>(ptr: *mut T, value: T, name: &str) -> HsmResult<()> {
    if ptr.is_null() {
        return Err(HsmError::InvalidParam(format!("{name} pointer is null")));
    }
    // SAFETY: caller validated that `ptr` points to writable storage for `T`.
    unsafe { ptr.write(value) };
    Ok(())
}

/// Initialize the global HSM session.
///
/// # Safety
///
/// This function may be called from C or other foreign code. Callers must
/// ensure they do not race `HSM_Init` against other `HSM_*` functions that
/// mutate the same process-global session from signal handlers or other
/// unsynchronized contexts.
#[no_mangle]
pub unsafe extern "C" fn HSM_Init() -> HsmStatus_t {
    ffi_status(|| {
        let mut guard = global_session()
            .lock()
            .map_err(|_| HsmError::InitializationFailed("ffi session mutex poisoned".into()))?;
        if let Some(session) = guard.as_mut() {
            return session.init();
        }
        let mut session = build_session()?;
        session.init()?;
        *guard = Some(session);
        Ok(())
    })
}

/// Deinitialize and drop the global HSM session.
///
/// # Safety
///
/// Foreign callers must ensure no other thread is concurrently using pointers
/// or handles owned by the active FFI session while teardown is in progress.
#[no_mangle]
pub unsafe extern "C" fn HSM_Deinit() -> HsmStatus_t {
    ffi_status(|| {
        let mut guard = global_session()
            .lock()
            .map_err(|_| HsmError::InitializationFailed("ffi session mutex poisoned".into()))?;
        let mut session = guard.take().ok_or(HsmError::NotInitialized)?;
        session.deinit()
    })
}

/// Recover the global HSM session from safe state.
///
/// # Safety
///
/// Foreign callers must ensure this function is not raced against other
/// mutating `HSM_*` calls from unsynchronized contexts.
#[no_mangle]
pub unsafe extern "C" fn HSM_Reinit() -> HsmStatus_t {
    ffi_status(|| with_session_mut(HsmSession::reinit))
}

/// Query secure-boot status from the active backend.
///
/// # Safety
///
/// `status_out` must point to writable storage for one [`HsmBootStatus_t`].
#[no_mangle]
pub unsafe extern "C" fn HSM_BootStatus(status_out: *mut HsmBootStatus_t) -> HsmStatus_t {
    ffi_status(|| {
        let status = with_session(HsmSession::boot_status)?;
        // SAFETY: `status_out` must point to writable storage for `HsmBootStatus_t`.
        unsafe {
            write_struct(
                status_out,
                HsmBootStatus_t {
                    verified: status.verified,
                    firmware_version: status.firmware_version,
                },
                "status_out",
            )
        }
    })
}

/// Generate a new key and return its handle.
///
/// # Safety
///
/// `handle_out` must point to writable storage for one [`HsmKeyHandle_t`].
#[no_mangle]
pub unsafe extern "C" fn HSM_KeyGenerate(
    key_type: HsmKeyType_t,
    handle_out: *mut HsmKeyHandle_t,
) -> HsmStatus_t {
    ffi_status(|| {
        let handle = with_session_mut(|session| session.key_generate(key_type_from_ffi(key_type)?))?;
        // SAFETY: `handle_out` must point to writable storage for one key handle.
        unsafe { write_struct(handle_out, handle.0, "handle_out") }
    })
}

/// Import raw or wrapped key material and return its handle.
///
/// # Safety
///
/// If `material_len > 0`, `material` must point to `material_len` readable
/// bytes. `handle_out` must point to writable storage for one
/// [`HsmKeyHandle_t`].
#[no_mangle]
pub unsafe extern "C" fn HSM_KeyImport(
    key_type: HsmKeyType_t,
    material: *const u8,
    material_len: usize,
    handle_out: *mut HsmKeyHandle_t,
) -> HsmStatus_t {
    ffi_status(|| {
        // SAFETY: the FFI caller promises `material` points to `material_len` readable bytes.
        let material = unsafe { input_slice(material, material_len, "material") }?;
        let handle =
            with_session_mut(|session| session.key_import(key_type_from_ffi(key_type)?, material))?;
        // SAFETY: `handle_out` must point to writable storage for one key handle.
        unsafe { write_struct(handle_out, handle.0, "handle_out") }
    })
}

/// Delete a key handle owned by the current session.
///
/// # Safety
///
/// Foreign callers must ensure the handle is not being used concurrently via
/// another mutating `HSM_*` call.
#[no_mangle]
pub unsafe extern "C" fn HSM_KeyDelete(handle: HsmKeyHandle_t) -> HsmStatus_t {
    ffi_status(|| with_session_mut(|session| session.key_delete(KeyHandle(handle))))
}

/// Derive a new key from an existing handle via HKDF-SHA256.
///
/// # Safety
///
/// `req` must point to a valid [`HsmHkdfReq_t`]. If `req.info_len > 0`,
/// `req.info` must point to `req.info_len` readable bytes, and
/// `req.derived_handle_out` must point to writable storage for one
/// [`HsmKeyHandle_t`].
#[no_mangle]
pub unsafe extern "C" fn HSM_KeyDerive(req: *const HsmHkdfReq_t) -> HsmStatus_t {
    ffi_status(|| {
        if req.is_null() {
            return Err(HsmError::InvalidParam("req pointer is null".into()));
        }
        // SAFETY: caller promises `req` points to a valid `HsmHkdfReq_t`.
        let req = unsafe { &*req };
        // SAFETY: `info` points to `info_len` readable bytes when non-empty.
        let info = unsafe { input_slice(req.info, req.info_len, "info") }?;
        let handle = with_session_mut(|session| {
            session.key_derive(
                KeyHandle(req.base_handle),
                info,
                key_type_from_ffi(req.out_type)?,
            )
        })?;
        // SAFETY: `derived_handle_out` must point to writable storage for one key handle.
        unsafe { write_struct(req.derived_handle_out, handle.0, "derived_handle_out") }
    })
}

/// Fill the caller-provided buffer with random bytes.
///
/// # Safety
///
/// If `len > 0`, `out` must point to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn HSM_Random(out: *mut u8, len: usize) -> HsmStatus_t {
    ffi_status(|| {
        // SAFETY: `out` points to `len` writable bytes when `len > 0`.
        let out = unsafe { output_slice(out, len, "out") }?;
        with_session_mut(|session| session.random(out))
    })
}

/// Compute SHA-256 over the input buffer.
///
/// # Safety
///
/// If `len > 0`, `data` must point to `len` readable bytes. `digest_out` must
/// point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn HSM_Sha256(
    data: *const u8,
    len: usize,
    digest_out: *mut u8,
) -> HsmStatus_t {
    ffi_status(|| {
        // SAFETY: `data` points to `len` readable bytes when `len > 0`.
        let data = unsafe { input_slice(data, len, "data") }?;
        let digest = with_session(|session| session.sha256(data))?;
        // SAFETY: `digest_out` points to 32 writable bytes.
        unsafe { write_array(digest_out, &digest, "digest_out") }
    })
}

/// Compute HMAC-SHA256 with the specified handle.
///
/// # Safety
///
/// If `len > 0`, `data` must point to `len` readable bytes. `mac_out` must
/// point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn HSM_HmacSha256(
    handle: HsmKeyHandle_t,
    data: *const u8,
    len: usize,
    mac_out: *mut u8,
) -> HsmStatus_t {
    ffi_status(|| {
        // SAFETY: `data` points to `len` readable bytes when `len > 0`.
        let data = unsafe { input_slice(data, len, "data") }?;
        let mac = with_session_mut(|session| session.hmac_sha256(KeyHandle(handle), data))?;
        // SAFETY: `mac_out` points to 32 writable bytes.
        unsafe { write_array(mac_out, &mac, "mac_out") }
    })
}

/// Encrypt plaintext with AES-256-GCM and write ciphertext plus tag to caller buffers.
///
/// # Safety
///
/// `req` must point to a valid [`HsmAesGcmEncryptReq_t`]. `req.iv` must point
/// to 12 readable bytes. If `req.aad_len > 0`, `req.aad` must point to
/// `req.aad_len` readable bytes. If `req.plaintext_len > 0`, `req.plaintext`
/// and `req.ciphertext_out` must point to `req.plaintext_len` readable and
/// writable bytes respectively. `req.tag_out` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn HSM_AesGcmEncrypt(req: *const HsmAesGcmEncryptReq_t) -> HsmStatus_t {
    ffi_status(|| {
        if req.is_null() {
            return Err(HsmError::InvalidParam("req pointer is null".into()));
        }
        // SAFETY: caller promises `req` points to a valid `HsmAesGcmEncryptReq_t`.
        let req = unsafe { &*req };
        // SAFETY: `iv`, `aad`, and `plaintext` point to readable buffers of the stated sizes.
        let iv = unsafe { array_ref::<HSM_AES_GCM_IV_SIZE>(req.iv, "iv") }?;
        let aad = unsafe { input_slice(req.aad, req.aad_len, "aad") }?;
        let plaintext = unsafe { input_slice(req.plaintext, req.plaintext_len, "plaintext") }?;
        let params = AesGcmParams {
            iv: &iv,
            aad,
        };
        let (ciphertext, tag) = with_session_mut(|session| {
            session.aes_gcm_encrypt(KeyHandle(req.key_handle), &params, plaintext)
        })?;
        if ciphertext.len() != req.plaintext_len {
            return Err(HsmError::BufferTooSmall {
                required: ciphertext.len(),
                provided: req.plaintext_len,
            });
        }
        // SAFETY: `ciphertext_out` points to `plaintext_len` writable bytes and `tag_out`
        // points to 16 writable bytes.
        unsafe {
            output_slice(req.ciphertext_out, req.plaintext_len, "ciphertext_out")?
                .copy_from_slice(&ciphertext);
            write_array(req.tag_out, &tag, "tag_out")
        }
    })
}

/// Decrypt and authenticate AES-256-GCM ciphertext into the caller buffer.
///
/// # Safety
///
/// `req` must point to a valid [`HsmAesGcmDecryptReq_t`]. `req.iv` must point
/// to 12 readable bytes and `req.tag` must point to 16 readable bytes. If
/// `req.aad_len > 0`, `req.aad` must point to `req.aad_len` readable bytes. If
/// `req.ciphertext_len > 0`, `req.ciphertext` and `req.plaintext_out` must
/// point to `req.ciphertext_len` readable and writable bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn HSM_AesGcmDecrypt(req: *const HsmAesGcmDecryptReq_t) -> HsmStatus_t {
    ffi_status(|| {
        if req.is_null() {
            return Err(HsmError::InvalidParam("req pointer is null".into()));
        }
        // SAFETY: caller promises `req` points to a valid `HsmAesGcmDecryptReq_t`.
        let req = unsafe { &*req };
        // SAFETY: `iv`, `aad`, `ciphertext`, and `tag` point to readable buffers of the stated sizes.
        let iv = unsafe { array_ref::<HSM_AES_GCM_IV_SIZE>(req.iv, "iv") }?;
        let aad = unsafe { input_slice(req.aad, req.aad_len, "aad") }?;
        let ciphertext =
            unsafe { input_slice(req.ciphertext, req.ciphertext_len, "ciphertext") }?;
        let tag = unsafe { array_ref::<HSM_AES_GCM_TAG_SIZE>(req.tag, "tag") }?;
        let params = AesGcmParams {
            iv: &iv,
            aad,
        };
        let plaintext = with_session_mut(|session| {
            session.aes_gcm_decrypt(KeyHandle(req.key_handle), &params, ciphertext, &tag)
        })?;
        if plaintext.len() != req.ciphertext_len {
            return Err(HsmError::BufferTooSmall {
                required: plaintext.len(),
                provided: req.ciphertext_len,
            });
        }
        // SAFETY: `plaintext_out` points to `ciphertext_len` writable bytes.
        unsafe {
            output_slice(req.plaintext_out, req.ciphertext_len, "plaintext_out")?
                .copy_from_slice(&plaintext);
        }
        Ok(())
    })
}

/// Sign a SHA-256 digest with the specified P-256 key.
///
/// # Safety
///
/// `digest` must point to 32 readable bytes and `sig_out` must point to
/// writable storage for one [`HsmEcdsaSignature_t`].
#[no_mangle]
pub unsafe extern "C" fn HSM_EcdsaSign(
    handle: HsmKeyHandle_t,
    digest: *const u8,
    sig_out: *mut HsmEcdsaSignature_t,
) -> HsmStatus_t {
    ffi_status(|| {
        // SAFETY: `digest` points to 32 readable bytes.
        let digest = unsafe { array_ref::<HSM_SHA256_DIGEST_SIZE>(digest, "digest") }?;
        let sig = with_session_mut(|session| session.ecdsa_sign(KeyHandle(handle), &digest))?;
        // SAFETY: `sig_out` points to writable storage for `HsmEcdsaSignature_t`.
        unsafe {
            write_struct(
                sig_out,
                HsmEcdsaSignature_t { r: sig.r, s: sig.s },
                "sig_out",
            )
        }
    })
}

/// Verify a P-256 ECDSA signature against a SHA-256 digest.
///
/// # Safety
///
/// `req` must point to a valid [`HsmEcdsaVerifyReq_t`]. `req.digest` must point
/// to 32 readable bytes, `req.signature` must point to a valid
/// [`HsmEcdsaSignature_t`], and `req.result_out` must point to writable storage
/// for one `bool`.
#[no_mangle]
pub unsafe extern "C" fn HSM_EcdsaVerify(req: *const HsmEcdsaVerifyReq_t) -> HsmStatus_t {
    ffi_status(|| {
        if req.is_null() {
            return Err(HsmError::InvalidParam("req pointer is null".into()));
        }
        // SAFETY: caller promises `req` points to a valid `HsmEcdsaVerifyReq_t`.
        let req = unsafe { &*req };
        if req.signature.is_null() {
            return Err(HsmError::InvalidParam("signature pointer is null".into()));
        }
        // SAFETY: `digest` points to 32 readable bytes and `signature` points to a valid struct.
        let digest = unsafe { array_ref::<HSM_SHA256_DIGEST_SIZE>(req.digest, "digest") }?;
        let signature = unsafe { &*req.signature };
        let signature = EcdsaSignature {
            r: signature.r,
            s: signature.s,
        };
        let valid = with_session_mut(|session| {
            session.ecdsa_verify(KeyHandle(req.key_handle), &digest, &signature)
        })?;
        // SAFETY: `result_out` points to writable storage for `bool`.
        unsafe { write_struct(req.result_out, valid, "result_out") }
    })
}

/// Perform P-256 ECDH key agreement.
///
/// # Safety
///
/// `req` must point to a valid [`HsmEcdhReq_t`]. `req.peer_pub` must point to
/// 64 readable bytes and `req.shared_secret_out` must point to 32 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn HSM_EcdhAgree(req: *const HsmEcdhReq_t) -> HsmStatus_t {
    ffi_status(|| {
        if req.is_null() {
            return Err(HsmError::InvalidParam("req pointer is null".into()));
        }
        // SAFETY: caller promises `req` points to a valid `HsmEcdhReq_t`.
        let req = unsafe { &*req };
        // SAFETY: `peer_pub` points to 64 readable bytes.
        let peer_pub = unsafe { array_ref::<HSM_ECC_P256_PUBKEY_SIZE>(req.peer_pub, "peer_pub") }?;
        let shared = with_session_mut(|session| {
            session.ecdh_agree(KeyHandle(req.key_handle), &peer_pub)
        })?;
        // SAFETY: `shared_secret_out` points to 32 writable bytes.
        unsafe { write_array(req.shared_secret_out, &shared, "shared_secret_out") }
    })
}
