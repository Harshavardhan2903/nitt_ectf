/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the Makefile. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is
*  intended to be an example of how you *may* use cryptography in your
*  design. You are not limited nor required to use this interface in
*  your design. It is recommended for newer teams to start by only using
*  the simple crypto library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ******************** CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    // Initialize filesystem
    init_fs();

    // Derive device and deployment keys from root secret
    derive_keys();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    // process commands forever
    while (1) {
        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            continue;
        }

        // Handle the requested command
        switch (cmd) {
        case LIST_MSG:
            list(pkt_len, uart_buf);
            break;

        case READ_MSG:
            read(pkt_len, uart_buf);
            break;

        case WRITE_MSG:
            write(pkt_len, uart_buf);
            break;

        case RECEIVE_MSG:
            receive(pkt_len, uart_buf);
            break;

        case INTERROGATE_MSG:
            interrogate(pkt_len, uart_buf);
            break;

        case LISTEN_MSG:
            listen(pkt_len, uart_buf);
            break;

        default:
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
