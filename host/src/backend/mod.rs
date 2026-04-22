// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Backend abstraction — software fallback and hardware (USB/L55).

use crate::error::{HsmError, HsmResult};
use crate::types::{AesGcmParams, BootStatus, EcdsaSignature, KeyHandle, KeyType};

pub mod sw;

#[cfg(feature = "hw-backend")]
pub mod hw;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

/// Core backend trait — implemented by both software fallback and hardware backend.
///
/// All operations use key handles. Key material never crosses this interface.
/// The current Rust API returns owned outputs, so caller-visible short-buffer
/// failures are expected at the FFI boundary rather than inside these trait
/// methods. Any future API that writes into caller-provided buffers must use
/// `HsmError::BufferTooSmall` instead of overloading `InvalidParam`.
pub trait HsmBackend: Send + Sync {
    /// Initialize the backend.
    fn init(&mut self) -> HsmResult<()>;

    /// Deinitialize the backend and release resources.
    fn deinit(&mut self) -> HsmResult<()>;

    /// Generate a new key of the given type. Returns an opaque handle.
    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle>;

    /// Import key material and return an opaque handle.
    ///
    /// # Backend-specific behaviour (HSM-REQ-022)
    ///
    /// **Software backend:** accepts raw (unwrapped) key bytes.  This is
    /// permitted because the software backend provides no hardware isolation —
    /// KEK-wrapping would add no security benefit.  Use the software backend
    /// for testing and development only; never for production provisioning.
    ///
    /// **Hardware backend (STM32L552):** material MUST be wrapped under the
    /// device Key Encryption Key (KEK) provisioned at manufacturing time.  The
    /// KEK never leaves the STM32L552 Secure world.  The firmware rejects any
    /// attempt to import raw, unwrapped material with `ErrBadParam`.
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InvalidParam` if `material` is the wrong length or
    /// contains an invalid key value (e.g. zero scalar for EccP256).
    fn key_import(&mut self, key_type: KeyType, material: &[u8]) -> HsmResult<KeyHandle>;

    /// Delete a key slot and zeroize key material.
    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()>;

    /// Generate random bytes from the entropy source.
    fn random(&mut self, out: &mut [u8]) -> HsmResult<()>;

    /// SHA-256 hash.
    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]>;

    /// HMAC-SHA256.
    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]>;

    /// AES-256-GCM encrypt.
    ///
    /// Returns (ciphertext, tag). Ciphertext is the same length as plaintext.
    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])>;

    /// AES-256-GCM decrypt and verify.
    ///
    /// Returns plaintext. Returns `HsmError::TagMismatch` if tag fails.
    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>>;

    /// AES-256-CBC encrypt.
    ///
    /// `plaintext` must be a whole number of AES blocks (16 bytes each).
    fn aes_cbc_encrypt(
        &self,
        _handle: KeyHandle,
        _iv: &[u8; 16],
        _plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    /// AES-256-CBC decrypt.
    ///
    /// `ciphertext` must be a whole number of AES blocks (16 bytes each).
    fn aes_cbc_decrypt(
        &self,
        _handle: KeyHandle,
        _iv: &[u8; 16],
        _ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    /// AES-256-CCM encrypt.
    ///
    /// Returns `ciphertext || tag`, with `tag_len` bytes of authentication tag
    /// appended to the ciphertext to match the NIST CCM vector format.
    fn aes_ccm_encrypt(
        &self,
        _handle: KeyHandle,
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        _tag_len: usize,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    /// AES-256-CCM decrypt.
    ///
    /// `ciphertext_and_tag` must contain the authentication tag as the trailing
    /// `tag_len` bytes.
    fn aes_ccm_decrypt(
        &self,
        _handle: KeyHandle,
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext_and_tag: &[u8],
        _tag_len: usize,
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    /// ChaCha20-Poly1305 encrypt.
    ///
    /// Returns (ciphertext, tag). Ciphertext is the same length as plaintext.
    fn chacha20_poly1305_encrypt(
        &self,
        _handle: KeyHandle,
        _nonce: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        Err(HsmError::Unsupported)
    }

    /// ChaCha20-Poly1305 decrypt and verify.
    fn chacha20_poly1305_decrypt(
        &self,
        _handle: KeyHandle,
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &[u8],
        _tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        Err(HsmError::Unsupported)
    }

    /// ECDSA P-256 sign. Signs a pre-computed SHA-256 digest (32 bytes).
    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature>;

    /// ECDSA P-256 verify.
    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool>;

    /// HKDF-SHA256 key derivation. Derives a new key slot from an existing one.
    fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle>;

    /// ECDH P-256 key agreement. Returns the shared secret (32 bytes).
    fn ecdh_agree(&self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]>;

    /// SHA3-256 hash.
    fn sha3_256(&self, _data: &[u8]) -> HsmResult<[u8; 32]> {
        Err(HsmError::Unsupported)
    }

    /// SHA3-512 hash.
    fn sha3_512(&self, _data: &[u8]) -> HsmResult<[u8; 64]> {
        Err(HsmError::Unsupported)
    }

    /// Query secure boot status — HSM-REQ-046.
    ///
    /// The software backend returns `BootStatus { verified: false, firmware_version: 0 }`
    /// to indicate that hardware secure boot is not applicable.
    /// The hardware backend queries the firmware for the actual boot result.
    fn boot_status(&self) -> HsmResult<BootStatus> {
        Ok(BootStatus {
            verified: false,
            firmware_version: 0,
        })
    }
}
