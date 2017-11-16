/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to common definitions for the client and server
 */

#ifndef COMMON_H
#define COMMON_H

#include <gcrypt.h>

#define DEFAULT_SERVER_PORT "6060"

#define FILES_BYTES 2
#define INIT_VEC_BYTES 16
#define NAME_BYTES 255
#define SIZE_BYTES 4
#define HASH_BYTES 64
#define RETURN_SIZE 3 // Response from server

#define HEADER_INIT_SIZE FILES_BYTES + INIT_VEC_BYTES
#define HEADER_LINE_SIZE NAME_BYTES + SIZE_BYTES + HASH_BYTES

#define AES_BLOCKSIZE 16	// bytes - 128 bits
#define KEY_SIZE 32		// bytes - 256 bits

/*
 * Checks if the return value from any gcry functions contains an error or not
 */
void g_error(gcry_error_t err);

/*
 * Display an error message and exit when a memory allocation error
 * occurs
 */
void mem_error(void);

/*
 * Initialize the gcrypt library
 */
void init_gcrypt();

/*
 * Return the number of padding bytes needed for a raw size to fit
 * into the AES block size
 */
int padding_aes(int raw_size);

#endif
