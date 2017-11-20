/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Client (txer) entry point.
 */

#include <gcrypt.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "datalist.h"
#include "filesys.h"
#include "net.h"
#include "parser.h"

#define HASH_CHUNK_SIZE 2 << 14    // 2^14 for better large file performance
#define ENCRYPT_CHUNK_SIZE 2 << 10 // ~1.5x MTU

static void usage(char *bin_path, int exit_status)
{
	char *bin = basename(bin_path);

	fprintf(stderr,
		"Usage: %s -f files [-k key][-p port][-h]\n\n"
		"Options:\n"
		"-f Comma separated path(s) to file(s) to transfer (eg: "
		"file1,file2)\n"
		"-k Path to 256 bit AES encryption key (default %s)\n"
		"-p Port to connect to server (default %s)\n"
		"-h Help\n\n",
		bin, DEFAULT_KEY_PATH, DEFAULT_SERVER_PORT);
	exit(exit_status);
}

/*
 * Generate the initialization vector for a file transfer
 */
static char *generate_vector()
{
	srand(time(NULL));

	char *vector = malloc(INIT_VEC_BYTES);
	if (NULL == vector)
		mem_error();

	for (int i = 0; i < INIT_VEC_BYTES; i++) {
		vector[i] = rand() % 255;
	}

	return vector;
}

/*
 * Parse comma separated file paths into an array of strings.
 */
static char **parse_filepaths(char *file_paths, uint16_t file_cnt)
{
	char **paths = malloc(file_cnt * sizeof(char *));

	// Single - no need to parse
	if (file_cnt == 1) {
		paths[0] = calloc(NAME_BYTES, 1);
		if (NULL == paths[0])
			mem_error();
		memcpy(paths[0], file_paths, strlen(file_paths));
		return paths;
	}

	// We have multiple - parse them out
	int n = 0;

	char *path = strtok(file_paths, ",");
	while (path != NULL) {
		paths[n] = calloc(NAME_BYTES, 1);
		if (NULL == paths[n])
			mem_error();
		memcpy(paths[n], path, strlen(path));

		n++;
		path = strtok(NULL, ",");
	}

	return paths;
}

/*
 * Generate SHA-512 hashes for each file are transferring. Returns
 * an array of pointers to hashes in the same order as the argument.
 * Will return NULL if one of the file paths is invalid.
 */
static char **generate_hashes(char **to_transfer, uint16_t num_files)
{
	char **hashes = malloc(num_files * sizeof(char *));
	if (NULL == hashes)
		mem_error();

	gcry_md_hd_t hd;
	gcry_error_t err;
	char tmpbuf[HASH_CHUNK_SIZE];

	err = gcry_md_open(&hd, GCRY_MD_SHA512, 0);
	if (err) {
		gcry_strerror(err);
		exit(EXIT_FAILURE);
	}

	// Hash each file and store it. We will re-use the cipher handle
	for (int i = 0; i < num_files; i++) {
		hashes[i] = malloc(HASH_BYTES);
		if (NULL == hashes[i])
			mem_error();

		FILE *f = fopen(to_transfer[i], "r");
		if (NULL == f) {
			fprintf(stderr, "open %s failed: digest\n",
				to_transfer[i]);
			return NULL;
		}

		while (1) {
			int len = fread(tmpbuf, 1, HASH_CHUNK_SIZE, f);

			gcry_md_write(hd, tmpbuf, len);
			if (len < HASH_CHUNK_SIZE)
				break;
		}

		unsigned char *digest = gcry_md_read(hd, GCRY_MD_SHA512);
		memcpy(hashes[i], digest, HASH_BYTES);
		gcry_md_reset(hd);
		fclose(f);
	}

	gcry_md_close(hd);
	return hashes;
}

/*
 * Determine the size of each file to be transferred with AES-256
 * encryption. Returns an array of sizes
 */
static uint32_t *parse_sizes(char **to_transfer, uint16_t num_files)
{
	uint32_t *sizes = malloc(num_files * sizeof(uint32_t));
	if (NULL == sizes)
		mem_error();

	for (int i = 0; i < num_files; i++) {
		uint32_t size = filesize(to_transfer[i]);
		sizes[i] = size + padding_aes(size);
	}

	return sizes;
}

/*
 * Parse the number of files that are comma separated in the command
 * line argument for files that should be transferred
 */
static uint16_t parse_file_cnt(char *files_arg)
{
	int paths_len = strlen(files_arg);
	uint16_t file_cnt = 1;

	for (int i = 0; i < paths_len; i++) {
		if (files_arg[i] == ',')
			file_cnt++;
	}

	return file_cnt;
}

/*
 * Initialize the file transfer with the server by sending the file
 * transfer header. Returns index of file requested by server, -1
 * otherwise.
 */
static int init_transfer(int serv, data_head *dh)
{
	char *transfer_header = datalist_generate_payload(dh);
	int header_len = HEADER_INIT_SIZE + (dh->size * HEADER_LINE_SIZE);

	int n = write_all(serv, transfer_header, header_len);
	if (n != header_len)
		return -1;

	char request[RETURN_SIZE];
	n = recv(serv, request, RETURN_SIZE, 0);
	if (n != RETURN_SIZE)
		return -1;

	return parse_next_file(request);
}

/*
 * Encrypt a chunk of data of size src_len from src into dst with the
 * provided key
 */
static void encrypt_chunk(char *dst, char *src, int src_len, char *key,
			  char *vector)
{
	gcry_cipher_hd_t hd;
	gcry_error_t err = 0;

	err =
	    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	g_error(err);

	err = gcry_cipher_setkey(hd, key, KEY_SIZE);
	g_error(err);

	err = gcry_cipher_setiv(hd, vector, INIT_VEC_BYTES);
	g_error(err);

	err = gcry_cipher_encrypt(hd, (unsigned char *)dst, src_len, src,
				  src_len);

	g_error(err);
}

/*
 * Encrypt and Write specified file to the server. Returns true if
 * the file is encrypted and written entirely, false otherwise.
 */
static bool send_file(int sfd, char *key, char *vector, char *filepath)
{
	FILE *f = fopen(filepath, "r");
	if (NULL == f)
		return false;

	// We will re-use the buffers for efficiency
	char f_buf[ENCRYPT_CHUNK_SIZE];
	char enc_buf[ENCRYPT_CHUNK_SIZE];

	// Read a chunk fo the file, encrypt, and write to server
	int len;
	while (1) {
		// TODO: optimize by memset'ing what we don't in the buffers
		memset(f_buf, 0, ENCRYPT_CHUNK_SIZE);
		memset(enc_buf, 0, ENCRYPT_CHUNK_SIZE);

		len = fread(f_buf, 1, ENCRYPT_CHUNK_SIZE, f);

		if (len % 16 != 0)
			len += padding_aes(len);

		encrypt_chunk(enc_buf, f_buf, len, key, vector);

		int n = write_all(sfd, enc_buf, len);
		if (n < len) {
			fprintf(stderr, "failed to write encoded buffer\n");
			fclose(f);
			return false;
		}

		if (len < ENCRYPT_CHUNK_SIZE)
			break;
	}

	fclose(f);
	return true;
}

/*
 * Transfer comma separated files to the server at the specified address
 * with the given AES key. Returns true on successful transfer of all
 * non-duplicate files, false otherwise.
 */
static bool transfer_files(char *port, char *comma_files, char *key)
{
	// Prep for transfer
	uint16_t num_files = parse_file_cnt(comma_files);
	char **files = parse_filepaths(comma_files, num_files);
	uint32_t *sizes = parse_sizes(files, num_files);

	char *vector = generate_vector();
	init_gcrypt();
	char **hashes = generate_hashes(files, num_files);
	if (NULL == hashes)
		exit(EXIT_FAILURE);

	// Initialize the transfer by sending the initialization header
	data_head *dh = datalist_init(vector);
	for (int i = 0; i < num_files; i++) {
		datalist_append(dh, files[i], sizes[i], hashes[i]);
	}

	fprintf(stdout, "connecting to server\n");
	int sfd = client_socket(port);
	uint32_t requested_idx = init_transfer(sfd, dh);
	fprintf(stdout, "got first file request for file %d\n", requested_idx);

	char resp_buf[RETURN_SIZE]; // Server response after file sent
	bool all_sent = true;

	// We send any files the server requests
	while (requested_idx > 0 && requested_idx <= num_files) {
		int idx = requested_idx - 1; // 1 based in protocol
		fprintf(stdout, "transferring %.*s...\n", NAME_BYTES,
			files[idx]);
		bool ok = send_file(sfd, key, vector, files[idx]);
		if (!ok) {
			fprintf(stderr, "writing file failed\n");
			all_sent = false;
			break;
		}

		int n = recv(sfd, resp_buf, RETURN_SIZE, 0);
		if (n != RETURN_SIZE) {
			fprintf(stderr, "bad transfer response: %d\n", n);
			all_sent = false;
			break;
		}

		fprintf(stdout, "transferring  %.*s done\n", NAME_BYTES,
			files[idx]);
		requested_idx = parse_next_file(resp_buf);
	}

	// Cleanup
	for (int i = 0; i < num_files; i++) {
		free(files[i]);
		free(hashes[i]);
	}

	free(files);
	free(hashes);
	free(sizes);
	free(vector);
	datalist_destroy(dh);
	return all_sent;
}

int main(int argc, char *argv[])
{
	int opt = 0;
	char *port = NULL, *key_path = NULL, *file_paths = NULL;

	while ((opt = getopt(argc, argv, "p:k:f:h")) != -1) {
		switch (opt) {
		case 'p':
			port = strdup(optarg);
			break;
		case 'k':
			key_path = strdup(optarg);
			break;
		case 'f':
			file_paths = strdup(optarg);
			break;
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
		case ':':
			usage(argv[0], EXIT_FAILURE);
		case '?':
			usage(argv[0], EXIT_FAILURE);
		default:
			usage(argv[0], EXIT_FAILURE);
		}
	}

	if (NULL == file_paths)
		usage(argv[0], EXIT_FAILURE); // Files required for transfer

	if (NULL == key_path)
		key_path = strdup(DEFAULT_KEY_PATH);

	if (NULL == port)
		port = strdup(DEFAULT_SERVER_PORT);

	char *key = read_key(key_path);
	if (NULL == key) {
		fprintf(stderr, "reading key %s failed\n", key_path);
		exit(EXIT_FAILURE);
	}

	int status = EXIT_SUCCESS;

	bool ok = transfer_files(port, file_paths, key);
	if (!ok) {
		status = EXIT_FAILURE;
		fprintf(stderr, "transferring files failed\n");
	}

	free(port);
	free(key_path);
	free(key);
	free(file_paths);
	return status;
}
