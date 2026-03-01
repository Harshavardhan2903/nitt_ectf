/**
 * @file filesystem.c
 * @author Samuel Meyers
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "simple_flash.h"

int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs() {
    return load_fat();
}

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot) {
    file_t temp_file;
    return (!read_file(slot, &temp_file) && temp_file.in_use == FILE_IN_USE);
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    memset(dest, 0, sizeof(file_t));

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;

    // name must be null terminated, and the contents are defined by a length
    strcpy(dest->name, name);
    memcpy(dest->contents, contents, contents_len);

    return 0;
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;
    uint8_t aad[MAX_NAME_SIZE + 2]; // name + group_id
    extern uint8_t K_dev[KEY_SIZE];

    // Prepare AAD: [group_id (2) | name (32)]
    memcpy(aad, &src->group_id, 2);
    memcpy(aad + 2, src->name, MAX_NAME_SIZE);

    // Generate random IV using TRNG (placeholder for hardware TRNG integration)
    // For now, we use a simple nonce or a stub for DL_TRNG_generateRandomNumber
    for (int i = 0; i < IV_SIZE; i++) src->iv[i] = (uint8_t)rand(); 

    // Encrypt the contents in-place (or into the same buffer)
    if (aes_gcm_encrypt(src->contents, src->contents_len, K_dev, src->iv, 
                        aad, sizeof(aad), src->contents, src->gcm_tag) != 0) {
        return -1;
    }

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);
    
    // Update the FAT for the new file
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    // erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    // now write the file
    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
}

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest) {
    int flash_addr, file_size;
    uint8_t aad[MAX_NAME_SIZE + 2];
    extern uint8_t K_dev[KEY_SIZE];

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }
    flash_simple_read(flash_addr, dest, file_size);

    // If file is not in use, skip decryption
    if (dest->in_use != FILE_IN_USE) return 0;

    // Prepare AAD for verification
    memcpy(aad, &dest->group_id, 2);
    memcpy(aad + 2, dest->name, MAX_NAME_SIZE);

    // Decrypt and verify
    if (aes_gcm_decrypt(dest->contents, dest->contents_len, K_dev, dest->iv, 
                        aad, sizeof(aad), dest->gcm_tag, dest->contents) != 0) {
        memset(dest, 0, sizeof(file_t)); // Wipe on failure
        return -1;
    }

    return 0;
}

/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}
