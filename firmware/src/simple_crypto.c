/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hmac.h"

/** @brief Encrypts plaintext using AES-256-GCM
 */
int aes_gcm_encrypt(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *iv, 
                    uint8_t *aad, size_t aad_len, uint8_t *ciphertext, uint8_t *tag) {
    Aes ctx;
    int ret;

    ret = wc_AesGcmSetKey(&ctx, key, 32);
    if (ret != 0) return ret;

    ret = wc_AesGcmEncrypt(&ctx, ciphertext, plaintext, len, iv, 12, tag, 16, aad, aad_len);
    return ret;
}

/** @brief Decrypts ciphertext using AES-256-GCM
 */
int aes_gcm_decrypt(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, 
                    uint8_t *aad, size_t aad_len, uint8_t *tag, uint8_t *plaintext) {
    Aes ctx;
    int ret;

    ret = wc_AesGcmSetKey(&ctx, key, 32);
    if (ret != 0) return ret;

    ret = wc_AesGcmDecrypt(&ctx, plaintext, ciphertext, len, iv, 12, tag, 16, aad, aad_len);
    return ret;
}

/** @brief Hashes data using SHA-256
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}

/** @brief Derives keys using HKDF-SHA256
 */
int hkdf_sha256(uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, 
                 uint8_t *okm, size_t okm_len) {
    return wc_Tls13HKDF_Extract_And_Expand(SHA256, ikm, ikm_len, salt, salt_len, 
                                           (uint8_t *)"Fortress-M0", 11, okm, okm_len);
}
