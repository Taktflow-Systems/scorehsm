/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Taktflow Systems */

#ifndef SCORE_LIB_CRYPTO_HSM_H
#define SCORE_LIB_CRYPTO_HSM_H

#include "score/crypto/hsm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Lifecycle */
/** @reqref feat_req__sec_crypt__api_lifecycle */
HsmStatus_t HSM_Init(void);
/** @reqref feat_req__sec_crypt__api_lifecycle */
HsmStatus_t HSM_Deinit(void);
/** @reqref feat_req__sec_crypt__api_lifecycle */
HsmStatus_t HSM_Reinit(void);
/** @reqref feat_req__sec_crypt__boot_status */
HsmStatus_t HSM_BootStatus(HsmBootStatus_t *status_out);

/* Key management */
/** @reqref feat_req__sec_crypt__key_generation */
HsmStatus_t HSM_KeyGenerate(HsmKeyType_t key_type, HsmKeyHandle_t *handle_out);
/** @reqref feat_req__sec_crypt__key_import */
HsmStatus_t HSM_KeyImport(
    HsmKeyType_t key_type,
    const uint8_t *material,
    size_t material_len,
    HsmKeyHandle_t *handle_out
);
/** @reqref feat_req__sec_crypt__key_deletion */
HsmStatus_t HSM_KeyDelete(HsmKeyHandle_t handle);
/** @reqref feat_req__sec_crypt__key_derivation */
HsmStatus_t HSM_KeyDerive(const HsmHkdfReq_t *req);

/* Entropy */
/** @reqref feat_req__sec_crypt__rng */
HsmStatus_t HSM_Random(uint8_t *out, size_t len);

/* Hashing and MAC */
/** @reqref feat_req__sec_crypt__hashing_algo_sha2 */
HsmStatus_t HSM_Sha256(
    const uint8_t *data,
    size_t len,
    uint8_t digest_out[HSM_SHA256_DIGEST_SIZE]
);
/** @reqref feat_req__sec_crypt__mac */
HsmStatus_t HSM_HmacSha256(
    HsmKeyHandle_t handle,
    const uint8_t *data,
    size_t len,
    uint8_t mac_out[HSM_HMAC_SHA256_SIZE]
);

/* Symmetric cryptography */
/** @reqref feat_req__sec_crypt__sym_symmetric_encrypt */
/** @reqref feat_req__sec_crypt__sym_algo_aes_gcm */
HsmStatus_t HSM_AesGcmEncrypt(const HsmAesGcmEncryptReq_t *req);
/** @reqref feat_req__sec_crypt__sym_symmetric_encrypt */
/** @reqref feat_req__sec_crypt__sym_algo_aes_gcm */
HsmStatus_t HSM_AesGcmDecrypt(const HsmAesGcmDecryptReq_t *req);

/* Asymmetric cryptography */
/** @reqref feat_req__sec_crypt__sig_creation */
HsmStatus_t HSM_EcdsaSign(
    HsmKeyHandle_t handle,
    const uint8_t digest[HSM_SHA256_DIGEST_SIZE],
    HsmEcdsaSignature_t *sig_out
);
/** @reqref feat_req__sec_crypt__sig_verification */
HsmStatus_t HSM_EcdsaVerify(const HsmEcdsaVerifyReq_t *req);
/** @reqref feat_req__sec_crypt__asym_algo_ecdh */
HsmStatus_t HSM_EcdhAgree(const HsmEcdhReq_t *req);

#ifdef __cplusplus
}
#endif

#endif /* SCORE_LIB_CRYPTO_HSM_H */
