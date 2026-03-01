/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroizing memory is a pretty good practice
    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }
    // copy structure of the persistent file
    memcpy(file_info.name, &curr_file.name, strlen(curr_file.name));
    memcpy(file_info.contents, &curr_file.contents, curr_file.contents_len);

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // write a success message with the file information
    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    int ret;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    uint8_t challenge[12]; // Challenge Nonce
    uint8_t iv[12];
    uint8_t tag[16];
    msg_type_t cmd;
    uint16_t len_recv_msg;
    extern uint8_t K_dep[KEY_SIZE];

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // Generate random challenge nonce
    for (int i = 0; i < 12; i++) challenge[i] = (uint8_t)rand();

    // Send challenge to neighbor
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, challenge, 12);

    // Prepare request (encrypted)
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);
    
    // In a full implementation, we would encrypt 'request' here. 
    // For brevity and focus on file transfer:
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    // Wait for response packet
    len_recv_msg = sizeof(recv_resp) + 12 + 16; // Response + IV + Tag
    uint8_t transfer_buf[sizeof(recv_resp) + 12 + 16];
    read_packet(TRANSFER_INTERFACE, &cmd, transfer_buf, &len_recv_msg);

    // Extract IV, Tag, and Ciphertext
    memcpy(iv, transfer_buf, 12);
    memcpy(tag, transfer_buf + 12, 16);
    
    // Decrypt and verify with K_dep + challenge in AAD
    if (aes_gcm_decrypt(transfer_buf + 28, sizeof(recv_resp), K_dep, iv, 
                        challenge, 12, tag, (uint8_t *)&recv_resp) != 0) {
        print_error("Transfer authentication failed");
        return -1;
    }

    // write that file into the file system
    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the listen operation
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[MAX_CONTENTS_SIZE + 512];
    uint8_t challenge[12];
    uint8_t iv[12];
    uint8_t tag[16];
    msg_type_t cmd;
    pkt_len_t read_length;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;
    extern uint8_t K_dep[KEY_SIZE];

    // Wait for challenge
    read_length = 12;
    read_packet(TRANSFER_INTERFACE, &cmd, challenge, &read_length);

    // Wait for request
    read_length = sizeof(receive_request_t);
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:
            // Interrogate implementation omitted for brevity, similar to RECEIVE
            break;
        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;
            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Failed to read file");
                return -1;
            }
            metadata = get_file_metadata(command->slot);
            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            // Generate IV
            for (int i = 0; i < 12; i++) iv[i] = (uint8_t)rand();

            // Encrypt response with K_dep + challenge in AAD
            uint8_t out_buf[sizeof(recv_resp) + 28];
            memcpy(out_buf, iv, 12);
            if (aes_gcm_encrypt((uint8_t *)&recv_resp, sizeof(recv_resp), K_dep, iv, 
                                challenge, 12, out_buf + 28, out_buf + 12) != 0) {
                return -1;
            }

            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, out_buf, sizeof(out_buf));
            break;
        default:
            print_error("Bad message type");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
