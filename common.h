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
#include <signal.h>
#include <stdint.h>

#define DEFAULT_SERVER_PORT "6060"

#define FILES_BYTES 2
#define INIT_VEC_BYTES 16
#define NAME_BYTES 255
#define SIZE_BYTES 4

#define HASH_ALGO GCRY_MD_SHA1
#define HASH_BYTES 20

#define RETURN_SIZE 3	// Response from server
#define CHUNK_SIZE (2 << 14) //  ~32 KB for better large file performance

#define HEADER_INIT_SIZE (FILES_BYTES + INIT_VEC_BYTES)
#define HEADER_LINE_SIZE (NAME_BYTES + SIZE_BYTES + HASH_BYTES)

#define TRANSFER_D 2 // Duplicate
#define TRANSFER_Y 1 // Successful
#define TRANSFER_N 0 // Unsuccessful

#define AES_BLOCKSIZE 16 // bytes - 128 bits
#define KEY_SIZE 32      // bytes - 256 bits

#define BURN 1
#define NO_BURN 0

extern sig_atomic_t TERMINATED;

/*
 * Initialize the signal handler for SIGINT and SIGCHLD
 */
void init_sig_handler();

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
 * Initialize an AES-256 cipher context with the given initialization
 * vector and key
 */
gcry_cipher_hd_t init_cipher_context(uint8_t *vector, uint8_t *key);

/*
 * Parse the ip address from the given string with an optional ip and
 * required port in the format ip:port
 */
char *parse_ip(char *ip_port);

/*
 * Parse the port from the given strign with an optional ip and
 * required port in the format ip:port
 */
char *parse_port(char *ip_port);

/*
 * Convert a binary hash to hex representation safe for file system
 * and terminal use
 */
char *hash_to_hex(uint8_t *hash);

#endif /* COMMON_H */
