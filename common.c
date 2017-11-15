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

/*
 * Returns the lowest multiple of the number
 * Parameters: number - the number that the lowest multiple is being found for
 *	       multiple - the multiple of this number
 */
int lowest_multiple(int number, int multiple)
{
	int lowest_multiple = multiple;

	while (lowest_multiple < number)
		lowest_multiple += multiple;

	return lowest_multiple;
}

/*
 * Checks if the return value from any gcry functions contains an error or not
 */
void g_error(gcry_error_t err)
{
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
			gcry_strerror(err));
		exit(EXIT_FAILURE);
	}
}

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
