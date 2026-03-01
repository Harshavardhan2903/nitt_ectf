/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "security.h"

//need this for hardcode values of global root secret and permissions
#include "secrets.h"

//need this for HKDF(hashing and key derivation) and SHA256
#include "simple_crypto.h"

#include <string.h>

// Global keys K_dev and K_dep stored in internal SRAM only
// K_dev is the device-specific key
// K_dep is the deployment-specific key
// K_root is the root secret

// Sram safer then flash as in flash memory cold boot attacks can happen 
uint8_t K_dev[KEY_SIZE];
uint8_t K_dep[KEY_SIZE];

/** @brief Cryptographically secure memory comparison
*/

//constant time comparison to prevent timing attacks
int CRYPTO_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    unsigned char result = 0;
    for (size_t i = 0; i < n; i++) {
        result |= p1[i] ^ p2[i];
    }
    return result;
}

/** @brief Validate a pin against the HSM's pin hash
*/

//checks if user provided pin is correct without actually storing the plaintext PIN in device memory
//instead of storing the pin in memory we store the hash of the pin

//when we enter pin , performs same mathematical operation on it and compares it with the hash stored in flash memory
//this is a constant time comparison to prevent timing attacks
bool check_pin(unsigned char *pin) {

    //flow : salting -> hashing -> comparison


    //salting : takes the raw pin and attaches a unique , non secret string of data called salt to the front
    //ensure even if two users have the same pin , their hashes will be different
    
    //hashing : runs the combined string through a one-way mathematical function

    //comparison : compares newly-generated hash with official hash stored in flash memory
    //takes constant time for comparison to prevent timing attacks



    //temporary buffer to store computed hash
    uint8_t computed_hash[HASH_SIZE];

    //temporary buffer to store 16 bytes of salt + PIN_LENGTH bytes of pin
    uint8_t salted_pin[16 + PIN_LENGTH];


    // salted_pin = salt | pin
    // memcpy() is a function that copies a block of memory from one location to another
    //this is similar to microprocessor 8085 MOV A,B where A is destination and B is source

    //copies HSM_PIN_SALT from secrets.h to salted_pin
    memcpy(salted_pin, HSM_PIN_SALT, 16);
    //copies pin from user input to salted_pin
    memcpy(salted_pin + 16, pin, PIN_LENGTH);

    // Hash the salted pin , hash function is defined in simple_crypto.h
    hash(salted_pin, sizeof(salted_pin), computed_hash);

    // Constant-time comparison
    return CRYPTO_memcmp(computed_hash, HSM_PIN_HASH, HASH_SIZE) == 0;
}

/** @brief Derive device-specific and deployment-specific keys
*/
void derive_keys(void) {
    // Derive Deployment Key: K_dep = HKDF(Salt="DEPLOY_2026", IKM=K_root)
    hkdf_sha256((uint8_t *)"DEPLOY_2026", 11, GLOBAL_ROOT_SECRET, 32, K_dep, KEY_SIZE);

    // Derive Device Key: K_dev = HKDF(Salt=MCU_UUID, IKM=K_root)
    // NOTE: For now, we use a constant placeholder for the UUID. 
    // In production, this would be read from fixed hardware registers.
    uint8_t uuid[16] = {0x46, 0x4f, 0x52, 0x54, 0x52, 0x45, 0x53, 0x53, 0x2d, 0x4d, 0x30, 0x2d, 0x32, 0x30, 0x32, 0x36};
    hkdf_sha256(uuid, 16, GLOBAL_ROOT_SECRET, 32, K_dev, KEY_SIZE);
}

/** @brief Ensure the HSM has the requested permission
*/
bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    for (uint8_t i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:
                    return global_permissions[i].read;
                case PERM_WRITE:
                    return global_permissions[i].write;
                case PERM_RECEIVE:
                    return global_permissions[i].receive;
                default:
                    return false;
            }
        }
    }
    return false;
}
