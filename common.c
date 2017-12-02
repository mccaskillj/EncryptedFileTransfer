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

sig_atomic_t TERMINATED;

/*
 * Changes TERMINATED to 1. Passed into a signal handler for SIGINT
 */
static void sigint_handler() { TERMINATED = 1; }

void init_sig_handler()
{
	struct sigaction sigint, sigchld;
	memset(&sigint, '\0', sizeof(sigint));
	memset(&sigchld, '\0', sizeof(sigchld));

	// Cleanup children immediately
	sigchld.sa_handler = SIG_IGN;

	// Allow interruption of all system calls
	sigint.sa_flags &= ~SA_RESTART;
	sigint.sa_handler = sigint_handler;

	TERMINATED = 0;
	sigaction(SIGINT, &sigint, NULL);
	sigaction(SIGCHLD, &sigchld, NULL);
}

void g_error(gcry_error_t err)
{
	if (err) {
		fprintf(stderr, "gcrypt fatal error: %s/%s\n",
			gcry_strsource(err), gcry_strerror(err));
		exit(EXIT_FAILURE);
	}
}

void mem_error(void)
{
	fprintf(stderr, "malloc failed\n");
	exit(EXIT_FAILURE);
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

gcry_cipher_hd_t init_cipher_context(uint8_t *vector, uint8_t *key)
{
	gcry_cipher_hd_t hd;
	gcry_error_t err = 0;

	err =
	    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	g_error(err);

	err = gcry_cipher_setkey(hd, key, KEY_SIZE);
	g_error(err);

	gcry_cipher_setiv(hd, vector, INIT_VEC_BYTES);
	g_error(err);

	return hd;
}

char *parse_ip(char *ip_port)
{
	int host_len = 0;
	char *port_start = NULL, *host = NULL;

	port_start = strchr(ip_port, ':');
	if (port_start != NULL && port_start == ip_port)
		return NULL; // IP not specified

	host_len = strlen(ip_port);

	if (NULL != port_start) {
		port_start++;
		host_len = (port_start - ip_port) - 1;
	}

	host = malloc(host_len + 1);
	if (NULL == host)
		mem_error();

	strncpy(host, ip_port, host_len);
	host[host_len] = '\0';
	return host;
}

char *parse_port(char *ip_port)
{
	int port_len = 0;
	char *port_start = NULL, *port = NULL;

	int len = strlen(ip_port);

	port_start = strchr(ip_port, ':');
	if (NULL == port_start)
		return NULL; // Port required

	port_start++;
	port_len = (ip_port + len) - port_start;

	port = malloc(port_len + 1);
	if (NULL == port)
		mem_error();

	strncpy(port, port_start, port_len);
	port[port_len] = '\0';
	return port;
}

char *hash_to_hex(uint8_t *hash)
{
	char *hex = malloc(HASH_BYTES * 2 + 1);
	if (NULL == hex)
		mem_error();

	for (int i = 0; i < HASH_BYTES; i++) {
		snprintf(&hex[i * 2], 2 * HASH_BYTES + 1, "%02X", hash[i]);
	}

	hex[HASH_BYTES * 2] = '\0';
	return hex;
}
