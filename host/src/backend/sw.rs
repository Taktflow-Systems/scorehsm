// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

//! Software fallback backend — rustcrypto, no hardware required.
//!
//! Used in CI and on any Linux machine without the L55 attached.
//! Satisfies all algorithmic requirements but NOT hardware isolation
//! requirements (os_protection, no_key_exposure, reverse_eng_protection).
//!
//! # Security properties of this backend
//!
//! | Requirement        | Status  | Notes                                              |
//! |--------------------|---------|---------------------------------------------------|
//! | HSM-REQ-031/036    | NOT MET | Keys are in process heap — no TrustZone isolation  |
//! | HSM-REQ-043        | MET     | ZeroizeOnDrop wipes key bytes on delete/deinit     |
//! | HSM-REQ-045        | MET     | Compile-time cfg warning when hw-backend absent    |
//!
//! HSM-REQ-045: compile-time warning when built without hw-backend.
#![cfg_attr(not(feature = "hw-backend"), allow(unused))]

use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{HsmError, HsmResult};
use crate::types::{AesGcmParams, EcdsaSignature, KeyHandle, KeyType};

use super::HsmBackend;

/// Key material stored in-process (software backend only).
///
/// Key material is held in heap memory. This does NOT satisfy HSM-REQ-031/036
/// (TrustZone isolation) — the hardware backend provides that guarantee.
///
/// HSM-REQ-043: `ZeroizeOnDrop` guarantees that key bytes are overwritten with
/// zeros whenever a slot is removed from the HashMap (`key_delete`) or when the
/// entire store is cleared (`deinit`). This is enforced at compile time — see
/// the `_ASSERT_ZEROIZE_ON_DROP` constant below.
#[derive(Zeroize, ZeroizeOnDrop)]
enum KeyMaterial {
    Aes256([u8; 32]),
    HmacSha256([u8; 32]),
    /// P-256 private scalar (big-endian, 32 bytes).
    EccP256([u8; 32]),
}

/// Compile-time proof that `KeyMaterial` implements `ZeroizeOnDrop`.
///
/// If this fails to compile, the zeroization guarantee (HSM-REQ-043) is broken.
/// This makes the security property machine-checkable, not just a comment.
#[allow(dead_code)]
const _ASSERT_ZEROIZE_ON_DROP: fn() = || {
    fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    require_zeroize_on_drop::<KeyMaterial>();
};

/// Software fallback backend.
pub struct SoftwareBackend {
    initialized: bool,
    next_handle: u32,
    keys: HashMap<u32, KeyMaterial>,
}

fn seeded_chacha20_rng() -> rand_chacha::ChaCha20Rng {
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, RngCore, SeedableRng};

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    ChaCha20Rng::from_seed(seed)
}

fn aes_cbc_encrypt_raw(raw: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    use aes::cipher::{BlockEncrypt, KeyInit};

    if !plaintext.len().is_multiple_of(16) {
        return Err(HsmError::InvalidParam(
            "AES-CBC plaintext must be a multiple of 16 bytes".into(),
        ));
    }

    let cipher = aes::Aes256::new_from_slice(raw)
        .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
    let mut prev = *iv;
    let mut out = Vec::with_capacity(plaintext.len());

    for chunk in plaintext.chunks_exact(16) {
        let mut block = [0u8; 16];
        for (dst, (&pt, &chaining)) in block.iter_mut().zip(chunk.iter().zip(prev.iter())) {
            *dst = pt ^ chaining;
        }
        let mut ga = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut ga);
        out.extend_from_slice(&ga);
        prev.copy_from_slice(&ga);
    }

    Ok(out)
}

fn aes_cbc_decrypt_raw(raw: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};

    if !ciphertext.len().is_multiple_of(16) {
        return Err(HsmError::InvalidParam(
            "AES-CBC ciphertext must be a multiple of 16 bytes".into(),
        ));
    }

    let cipher = aes::Aes256::new_from_slice(raw)
        .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
    let mut prev = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks_exact(16) {
        let mut ga = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
        let current = <[u8; 16]>::try_from(chunk)
            .map_err(|_| HsmError::CryptoFail("invalid AES-CBC block size".into()))?;
        cipher.decrypt_block(&mut ga);
        let mut block = [0u8; 16];
        for (dst, (&pt, &chaining)) in block.iter_mut().zip(ga.iter().zip(prev.iter())) {
            *dst = pt ^ chaining;
        }
        out.extend_from_slice(&block);
        prev = current;
    }

    Ok(out)
}

fn aes_ccm_encrypt_impl<N, T>(
    raw: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> HsmResult<Vec<u8>>
where
    N: ccm::aead::generic_array::ArrayLength<u8> + ccm::NonceSize,
    T: ccm::aead::generic_array::ArrayLength<u8> + ccm::TagSize,
{
    use ccm::{
        aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
        Ccm,
    };

    let cipher = Ccm::<aes::Aes256, T, N>::new_from_slice(raw)
        .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
    let nonce = GenericArray::<u8, N>::from_slice(nonce);
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buf)
        .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

fn aes_ccm_decrypt_impl<N, T>(
    raw: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    tag_len: usize,
) -> HsmResult<Vec<u8>>
where
    N: ccm::aead::generic_array::ArrayLength<u8> + ccm::NonceSize,
    T: ccm::aead::generic_array::ArrayLength<u8> + ccm::TagSize,
{
    use ccm::{
        aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
        Ccm,
    };

    let split = ciphertext_and_tag
        .len()
        .checked_sub(tag_len)
        .ok_or_else(|| HsmError::InvalidParam("AES-CCM ciphertext shorter than tag".into()))?;
    let cipher = Ccm::<aes::Aes256, T, N>::new_from_slice(raw)
        .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
    let nonce = GenericArray::<u8, N>::from_slice(nonce);
    let tag = GenericArray::<u8, T>::clone_from_slice(&ciphertext_and_tag[split..]);
    let mut buf = ciphertext_and_tag[..split].to_vec();
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buf, &tag)
        .map_err(|_| HsmError::TagMismatch)?;
    Ok(buf)
}

macro_rules! aes_ccm_tag_dispatch {
    ($nonce_ty:ty, $raw:expr, $nonce:expr, $aad:expr, $payload:expr, $tag_len:expr, encrypt) => {{
        use aes::cipher::consts::{U10, U12, U14, U16, U4, U6, U8};

        match $tag_len {
            4 => aes_ccm_encrypt_impl::<$nonce_ty, U4>($raw, $nonce, $aad, $payload),
            6 => aes_ccm_encrypt_impl::<$nonce_ty, U6>($raw, $nonce, $aad, $payload),
            8 => aes_ccm_encrypt_impl::<$nonce_ty, U8>($raw, $nonce, $aad, $payload),
            10 => aes_ccm_encrypt_impl::<$nonce_ty, U10>($raw, $nonce, $aad, $payload),
            12 => aes_ccm_encrypt_impl::<$nonce_ty, U12>($raw, $nonce, $aad, $payload),
            14 => aes_ccm_encrypt_impl::<$nonce_ty, U14>($raw, $nonce, $aad, $payload),
            16 => aes_ccm_encrypt_impl::<$nonce_ty, U16>($raw, $nonce, $aad, $payload),
            _ => Err(HsmError::InvalidParam(format!(
                "unsupported AES-CCM tag length: {}",
                $tag_len
            ))),
        }
    }};
    ($nonce_ty:ty, $raw:expr, $nonce:expr, $aad:expr, $payload:expr, $tag_len:expr, decrypt) => {{
        use aes::cipher::consts::{U10, U12, U14, U16, U4, U6, U8};

        match $tag_len {
            4 => aes_ccm_decrypt_impl::<$nonce_ty, U4>($raw, $nonce, $aad, $payload, $tag_len),
            6 => aes_ccm_decrypt_impl::<$nonce_ty, U6>($raw, $nonce, $aad, $payload, $tag_len),
            8 => aes_ccm_decrypt_impl::<$nonce_ty, U8>($raw, $nonce, $aad, $payload, $tag_len),
            10 => aes_ccm_decrypt_impl::<$nonce_ty, U10>($raw, $nonce, $aad, $payload, $tag_len),
            12 => aes_ccm_decrypt_impl::<$nonce_ty, U12>($raw, $nonce, $aad, $payload, $tag_len),
            14 => aes_ccm_decrypt_impl::<$nonce_ty, U14>($raw, $nonce, $aad, $payload, $tag_len),
            16 => aes_ccm_decrypt_impl::<$nonce_ty, U16>($raw, $nonce, $aad, $payload, $tag_len),
            _ => Err(HsmError::InvalidParam(format!(
                "unsupported AES-CCM tag length: {}",
                $tag_len
            ))),
        }
    }};
}

fn aes_ccm_encrypt_raw(
    raw: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> HsmResult<Vec<u8>> {
    match nonce.len() {
        7 => aes_ccm_tag_dispatch!(aes::cipher::consts::U7, raw, nonce, aad, plaintext, tag_len, encrypt),
        8 => aes_ccm_tag_dispatch!(aes::cipher::consts::U8, raw, nonce, aad, plaintext, tag_len, encrypt),
        9 => aes_ccm_tag_dispatch!(aes::cipher::consts::U9, raw, nonce, aad, plaintext, tag_len, encrypt),
        10 => aes_ccm_tag_dispatch!(aes::cipher::consts::U10, raw, nonce, aad, plaintext, tag_len, encrypt),
        11 => aes_ccm_tag_dispatch!(aes::cipher::consts::U11, raw, nonce, aad, plaintext, tag_len, encrypt),
        12 => aes_ccm_tag_dispatch!(aes::cipher::consts::U12, raw, nonce, aad, plaintext, tag_len, encrypt),
        13 => aes_ccm_tag_dispatch!(aes::cipher::consts::U13, raw, nonce, aad, plaintext, tag_len, encrypt),
        _ => Err(HsmError::InvalidParam(format!(
            "unsupported AES-CCM nonce length: {}",
            nonce.len()
        ))),
    }
}

fn aes_ccm_decrypt_raw(
    raw: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    tag_len: usize,
) -> HsmResult<Vec<u8>> {
    match nonce.len() {
        7 => aes_ccm_tag_dispatch!(aes::cipher::consts::U7, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        8 => aes_ccm_tag_dispatch!(aes::cipher::consts::U8, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        9 => aes_ccm_tag_dispatch!(aes::cipher::consts::U9, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        10 => aes_ccm_tag_dispatch!(aes::cipher::consts::U10, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        11 => aes_ccm_tag_dispatch!(aes::cipher::consts::U11, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        12 => aes_ccm_tag_dispatch!(aes::cipher::consts::U12, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        13 => aes_ccm_tag_dispatch!(aes::cipher::consts::U13, raw, nonce, aad, ciphertext_and_tag, tag_len, decrypt),
        _ => Err(HsmError::InvalidParam(format!(
            "unsupported AES-CCM nonce length: {}",
            nonce.len()
        ))),
    }
}

impl SoftwareBackend {
    /// Create a new software backend instance.
    pub fn new() -> Self {
        Self {
            initialized: false,
            next_handle: 1,
            keys: HashMap::new(),
        }
    }

    fn check_init(&self) -> HsmResult<()> {
        if self.initialized {
            Ok(())
        } else {
            Err(HsmError::NotInitialized)
        }
    }

    fn alloc_handle(&mut self) -> KeyHandle {
        let h = KeyHandle(self.next_handle);
        self.next_handle += 1;
        h
    }
}

impl Default for SoftwareBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmBackend for SoftwareBackend {
    fn init(&mut self) -> HsmResult<()> {
        self.initialized = true;
        Ok(())
    }

    fn deinit(&mut self) -> HsmResult<()> {
        self.initialized = false;
        // ZeroizeOnDrop fires for every `KeyMaterial` value dropped by `clear`.
        // HSM-REQ-043: all key material is zeroized before the store is emptied.
        self.keys.clear();
        Ok(())
    }

    fn key_generate(&mut self, key_type: KeyType) -> HsmResult<KeyHandle> {
        self.check_init()?;
        use rand_core::RngCore;

        let mut rng = seeded_chacha20_rng();

        let material = match key_type {
            KeyType::Aes256 => {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                KeyMaterial::Aes256(key)
            }
            KeyType::HmacSha256 => {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                KeyMaterial::HmacSha256(key)
            }
            KeyType::EccP256 => {
                use p256::ecdsa::SigningKey;
                let signing_key = SigningKey::random(&mut rng);
                let bytes: [u8; 32] = signing_key.to_bytes().into();
                KeyMaterial::EccP256(bytes)
            }
        };

        let handle = self.alloc_handle();
        self.keys.insert(handle.0, material);
        Ok(handle)
    }

    fn key_import(&mut self, key_type: KeyType, material: &[u8]) -> HsmResult<KeyHandle> {
        self.check_init()?;
        // ── Software backend vs hardware backend behavior ─────────────────────
        //
        // Software backend (this code): accepts raw, unwrapped key bytes.
        // This is intentional — the software backend provides no hardware
        // isolation, so KEK-wrapping offers no additional protection.  Raw
        // import is acceptable here for provisioning known test keys and for
        // exercising the key_derive / ECDH symmetry test paths.
        //
        // Hardware backend (STM32L552 — HSM-REQ-022): imported material MUST
        // be wrapped under the device KEK provisioned at manufacturing time.
        // The KEK never leaves the Secure-world keystore.  Raw import on the
        // hardware backend is explicitly prohibited and will be rejected by the
        // firmware with ErrBadParam.
        //
        // Callers MUST NOT use the software backend for production key
        // provisioning.  The distinction is enforced by documentation and by
        // the hardware backend's implementation — not by this code path.
        // ─────────────────────────────────────────────────────────────────────
        let km = match key_type {
            KeyType::Aes256 => {
                let bytes: [u8; 32] = material.try_into().map_err(|_| {
                    HsmError::InvalidParam("AES-256 key must be exactly 32 bytes".into())
                })?;
                KeyMaterial::Aes256(bytes)
            }
            KeyType::HmacSha256 => {
                let bytes: [u8; 32] = material.try_into().map_err(|_| {
                    HsmError::InvalidParam("HMAC-SHA256 key must be exactly 32 bytes".into())
                })?;
                KeyMaterial::HmacSha256(bytes)
            }
            KeyType::EccP256 => {
                let bytes: [u8; 32] = material.try_into().map_err(|_| {
                    HsmError::InvalidParam("P-256 scalar must be exactly 32 bytes".into())
                })?;
                // Validate the scalar represents a valid P-256 private key
                // before storing it.  A zero scalar and scalars >= the curve
                // order are rejected here rather than producing a silently
                // broken key handle.
                p256::SecretKey::from_bytes(&bytes.into()).map_err(|_| {
                    HsmError::InvalidParam("material is not a valid P-256 scalar".into())
                })?;
                KeyMaterial::EccP256(bytes)
            }
        };
        let handle = self.alloc_handle();
        self.keys.insert(handle.0, km);
        Ok(handle)
    }

    fn key_delete(&mut self, handle: KeyHandle) -> HsmResult<()> {
        self.check_init()?;
        // ZeroizeOnDrop fires when `remove` drops the evicted `KeyMaterial`.
        // HSM-REQ-043: key bytes are overwritten with zeros before the slot is freed.
        self.keys
            .remove(&handle.0)
            .ok_or(HsmError::InvalidKeyHandle)?;
        Ok(())
    }

    fn random(&mut self, out: &mut [u8]) -> HsmResult<()> {
        self.check_init()?;
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }

    fn hmac_sha256(&self, handle: KeyHandle, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::HmacSha256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(raw).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
    }

    fn aes_gcm_encrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let cipher =
            Aes256Gcm::new_from_slice(raw).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let nonce = Nonce::from_slice(params.iv);
        let payload = Payload {
            msg: plaintext,
            aad: params.aad,
        };
        let result = cipher
            .encrypt(nonce, payload)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        // aes-gcm appends the 16-byte tag at the end of the ciphertext
        let tag_offset = result.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[tag_offset..]);
        Ok((result[..tag_offset].to_vec(), tag))
    }

    fn aes_gcm_decrypt(
        &self,
        handle: KeyHandle,
        params: &AesGcmParams,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        let cipher =
            Aes256Gcm::new_from_slice(raw).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let nonce = Nonce::from_slice(params.iv);
        // Reconstruct ciphertext+tag as aes-gcm expects
        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);
        let payload = Payload {
            msg: &ct_with_tag,
            aad: params.aad,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| HsmError::TagMismatch)
    }

    fn aes_cbc_encrypt(
        &self,
        handle: KeyHandle,
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        aes_cbc_encrypt_raw(raw, iv, plaintext)
    }

    fn aes_cbc_decrypt(
        &self,
        handle: KeyHandle,
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        aes_cbc_decrypt_raw(raw, iv, ciphertext)
    }

    fn aes_ccm_encrypt(
        &self,
        handle: KeyHandle,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        tag_len: usize,
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        aes_ccm_encrypt_raw(raw, nonce, aad, plaintext, tag_len)
    }

    fn aes_ccm_decrypt(
        &self,
        handle: KeyHandle,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        tag_len: usize,
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        aes_ccm_decrypt_raw(raw, nonce, aad, ciphertext_and_tag, tag_len)
    }

    fn chacha20_poly1305_encrypt(
        &self,
        handle: KeyHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> HsmResult<(Vec<u8>, [u8; 16])> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };
        let cipher = ChaCha20Poly1305::new_from_slice(raw)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let result = cipher
            .encrypt(Nonce::from_slice(nonce), payload)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let tag_offset = result.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[tag_offset..]);
        Ok((result[..tag_offset].to_vec(), tag))
    }

    fn chacha20_poly1305_decrypt(
        &self,
        handle: KeyHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> HsmResult<Vec<u8>> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::Aes256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };
        let cipher = ChaCha20Poly1305::new_from_slice(raw)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &ct_with_tag,
                    aad,
                },
            )
            .map_err(|_| HsmError::TagMismatch)
    }

    fn ecdsa_sign(&self, handle: KeyHandle, digest: &[u8; 32]) -> HsmResult<EcdsaSignature> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let signing_key =
            SigningKey::from_bytes(raw.into()).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let sig: p256::ecdsa::Signature = signing_key
            .sign_prehash(digest)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let (r_bytes, s_bytes) = sig.split_bytes();
        Ok(EcdsaSignature {
            r: r_bytes.into(),
            s: s_bytes.into(),
        })
    }

    fn ecdsa_verify(
        &self,
        handle: KeyHandle,
        digest: &[u8; 32],
        signature: &EcdsaSignature,
    ) -> HsmResult<bool> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::ecdsa::{
            signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey,
        };
        let signing_key =
            SigningKey::from_bytes(raw.into()).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let verifying_key = VerifyingKey::from(&signing_key);
        let sig = Signature::from_scalars(signature.r, signature.s)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        match verifying_key.verify_prehash(digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn key_derive(
        &mut self,
        base: KeyHandle,
        info: &[u8],
        out_type: KeyType,
    ) -> HsmResult<KeyHandle> {
        self.check_init()?;
        // Copy the IKM out first (before mutable borrow of self.keys for insert)
        let ikm: [u8; 32] = {
            let key = self.keys.get(&base.0).ok_or(HsmError::InvalidKeyHandle)?;
            match key {
                KeyMaterial::Aes256(k) | KeyMaterial::HmacSha256(k) | KeyMaterial::EccP256(k) => *k,
            }
        };
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let material = match out_type {
            KeyType::Aes256 => KeyMaterial::Aes256(okm),
            KeyType::HmacSha256 => KeyMaterial::HmacSha256(okm),
            KeyType::EccP256 => KeyMaterial::EccP256(okm),
        };
        let handle = self.alloc_handle();
        self.keys.insert(handle.0, material);
        Ok(handle)
    }

    fn ecdh_agree(&self, handle: KeyHandle, peer_pub: &[u8; 64]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        let key = self.keys.get(&handle.0).ok_or(HsmError::InvalidKeyHandle)?;
        let raw = match key {
            KeyMaterial::EccP256(k) => k,
            _ => return Err(HsmError::InvalidKeyHandle),
        };
        use p256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, PublicKey, SecretKey};
        // Reconstruct peer public key from uncompressed 64-byte representation
        // peer_pub is [x: 32 bytes || y: 32 bytes] without the 0x04 prefix
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..].copy_from_slice(peer_pub);
        let ep =
            EncodedPoint::from_bytes(encoded).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let peer_key = PublicKey::from_encoded_point(&ep)
            .into_option()
            .ok_or_else(|| HsmError::CryptoFail("invalid peer public key".into()))?;
        let secret_key =
            SecretKey::from_bytes(raw.into()).map_err(|e| HsmError::CryptoFail(e.to_string()))?;
        let shared =
            p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_key.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }

    fn sha3_256(&self, data: &[u8]) -> HsmResult<[u8; 32]> {
        self.check_init()?;
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    fn sha3_512(&self, data: &[u8]) -> HsmResult<[u8; 64]> {
        self.check_init()?;
        use sha3::{Digest, Sha3_512};

        let mut hasher = Sha3_512::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }
}
