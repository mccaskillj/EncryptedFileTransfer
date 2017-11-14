/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to common definitions for the client and server
 */

#ifndef COMMON_H
#define COMMON_H

#define DEFAULT_SERVER_PORT "6060"

#define FILES_BYTES 2
#define INIT_VEC_BYTES 16
#define NAME_BYTES 255
#define SIZE_BYTES 4
#define HASH_BYTES 64

#define KEY_SIZE 32 // bytes

void mem_error(void);

#endif
