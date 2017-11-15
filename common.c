/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Functions with application wide usage
 */

#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"

void mem_error(void)
{
	fprintf(stderr, "malloc failed\n");
	exit(EXIT_FAILURE);
}

int padding_aes(int raw_size)
{
	if (raw_size % AES_BLOCKSIZE == 0)
		return 0;

	int padded = raw_size + AES_BLOCKSIZE - (raw_size % AES_BLOCKSIZE);
	return padded - raw_size;
}

void init_gcrypt()
{
	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		exit(EXIT_FAILURE);
	}

	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
