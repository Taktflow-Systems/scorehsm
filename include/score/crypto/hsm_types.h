/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Taktflow Systems */

#ifndef SCORE_LIB_CRYPTO_HSM_TYPES_H
#define SCORE_LIB_CRYPTO_HSM_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int32_t HsmStatus_t;
typedef uint32_t HsmKeyHandle_t;
typedef uint32_t HsmKeyType_t;

#define HSM_OK                          ((HsmStatus_t)0)
#define HSM_ERR_INVALID_PARAM           ((HsmStatus_t)-1)
#define HSM_ERR_INVALID_KEY_ID          ((HsmStatus_t)-2)
#define HSM_ERR_KEY_SLOT_FULL           ((HsmStatus_t)-3)
#define HSM_ERR_CRYPTO_FAIL             ((HsmStatus_t)-4)
#define HSM_ERR_NOT_INITIALIZED         ((HsmStatus_t)-5)
#define HSM_ERR_TAG_MISMATCH            ((HsmStatus_t)-6)
#define HSM_ERR_BUFFER_TOO_SMALL        ((HsmStatus_t)-7)
#define HSM_ERR_UNSUPPORTED             ((HsmStatus_t)-8)
#define HSM_ERR_SAFE_STATE              ((HsmStatus_t)-9)
#define HSM_ERR_RATE_LIMIT              ((HsmStatus_t)-10)
#define HSM_ERR_SEQUENCE_OVERFLOW       ((HsmStatus_t)-11)
#define HSM_ERR_NONCE_EXHAUSTED         ((HsmStatus_t)-12)
#define HSM_ERR_CERT_EXPIRED            ((HsmStatus_t)-13)
#define HSM_ERR_CERT_NOT_YET_VALID      ((HsmStatus_t)-14)

#define HSM_KEY_TYPE_AES_256            ((HsmKeyType_t)0x0001u)
#define HSM_KEY_TYPE_HMAC_SHA256        ((HsmKeyType_t)0x0002u)
#define HSM_KEY_TYPE_ECC_P256           ((HsmKeyType_t)0x0003u)

#define HSM_AES_GCM_IV_SIZE             (12u)
#define HSM_AES_GCM_TAG_SIZE            (16u)
#define HSM_SHA256_DIGEST_SIZE          (32u)
#define HSM_HMAC_SHA256_SIZE            (32u)
#define HSM_ECC_P256_SIG_R_SIZE         (32u)
#define HSM_ECC_P256_SIG_S_SIZE         (32u)
#define HSM_ECDH_SHARED_SECRET_SIZE     (32u)
#define HSM_ECC_P256_PUBKEY_SIZE        (64u)

typedef struct {
    uint8_t r[HSM_ECC_P256_SIG_R_SIZE];
    uint8_t s[HSM_ECC_P256_SIG_S_SIZE];
} HsmEcdsaSignature_t;

typedef struct {
    bool verified;
    uint32_t firmware_version;
} HsmBootStatus_t;

typedef struct {
    HsmKeyHandle_t key_handle;
    const uint8_t *iv;
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *plaintext;
    size_t plaintext_len;
    uint8_t *ciphertext_out;
    uint8_t *tag_out;
} HsmAesGcmEncryptReq_t;

typedef struct {
    HsmKeyHandle_t key_handle;
    const uint8_t *iv;
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    const uint8_t *tag;
    uint8_t *plaintext_out;
} HsmAesGcmDecryptReq_t;

typedef struct {
    HsmKeyHandle_t key_handle;
    const uint8_t *digest;
    const HsmEcdsaSignature_t *signature;
    bool *result_out;
} HsmEcdsaVerifyReq_t;

typedef struct {
    HsmKeyHandle_t key_handle;
    const uint8_t *peer_pub;
    uint8_t *shared_secret_out;
} HsmEcdhReq_t;

typedef struct {
    HsmKeyHandle_t base_handle;
    const uint8_t *info;
    size_t info_len;
    HsmKeyType_t out_type;
    HsmKeyHandle_t *derived_handle_out;
} HsmHkdfReq_t;

#endif /* SCORE_LIB_CRYPTO_HSM_TYPES_H */
