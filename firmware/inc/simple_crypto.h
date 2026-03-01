/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/******************************** FUNCTION PROTOTYPES ********************************/

/** @brief Encrypts plaintext using AES-256-GCM
 *
 * @param plaintext A pointer to a buffer containing the plaintext to encrypt
 * @param len The length of the plaintext
 * @param key A pointer to the 32-byte key
 * @param iv A pointer to the 12-byte IV
 * @param aad A pointer to the additional authenticated data
 * @param aad_len The length of the AAD
 * @param ciphertext A pointer to the buffer where ciphertext will be written
 * @param tag A pointer to the 16-byte buffer where the authentication tag will be written
 *
 * @return 0 on success, non-zero on error
 */
int aes_gcm_encrypt(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *iv, 
                    uint8_t *aad, size_t aad_len, uint8_t *ciphertext, uint8_t *tag);

/** @brief Decrypts ciphertext using AES-256-GCM
 *
 * @param ciphertext A pointer to the buffer containing the ciphertext to decrypt
 * @param len The length of the ciphertext
 * @param key A pointer to the 32-byte key
 * @param iv A pointer to the 12-byte IV
 * @param aad A pointer to the additional authenticated data
 * @param aad_len The length of the AAD
 * @param tag A pointer to the 16-byte authentication tag
 * @param plaintext A pointer to the buffer where plaintext will be written
 *
 * @return 0 on success (including tag validation), non-zero on error or validation failure
 */
int aes_gcm_decrypt(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, 
                    uint8_t *aad, size_t aad_len, uint8_t *tag, uint8_t *plaintext);

/** @brief Hashes data using SHA-256
 *
 * @param data A pointer to the data to hash
 * @param len The length of the data
 * @param hash_out A pointer to the 32-byte buffer where the hash will be written
 *
 * @return 0 on success, non-zero on error
 */
int hash(void *data, size_t len, uint8_t *hash_out);

/** @brief Derives keys using HKDF-SHA256
 *
 * @param salt A pointer to the salt
 * @param salt_len The length of the salt
 * @param ikm A pointer to the input keying material
 * @param ikm_len The length of the IKM
 * @param okm A pointer to the output buffer
 * @param okm_len The length of the output keying material
 *
 * @return 0 on success, non-zero on error
 */
int hkdf_sha256(uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, 
                 uint8_t *okm, size_t okm_len);

#endif // ECTF_CRYPTO_H
