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

static void usage(char *bin_path, int exit_status)
{
	char *bin = basename(bin_path);

	fprintf(
	    stderr,
	    "Usage: %s -f files [-l [ip]:port] [-r [ip]:port] [-k key] [-h]\n\n"
	    "Options:\n"
	    "-f Comma separated path(s) to file(s) to transfer (eg: "
	    "file1,file2)\n"
	    "-r Remote address ip:port (default ip is localhost, default port "
	    "is %s)\n"
	    "-l Local address ip:port (default ip is localhost, default port "
	    "is random)\n"
	    "-k Path to 256 bit AES encryption key (default %s)\n"
	    "-h Help\n\n",
	    bin, DEFAULT_SERVER_PORT, DEFAULT_KEY_PATH);
	exit(exit_status);
}

/*
 * Generate the initialization vector for a file transfer
 */
static uint8_t *generate_vector()
{
	srand(time(NULL));

	uint8_t *vector = malloc(INIT_VEC_BYTES);
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
static uint8_t **generate_hashes(char **to_transfer, uint16_t num_files)
{
	uint8_t **hashes = malloc(num_files * sizeof(uint8_t *));
	if (NULL == hashes)
		mem_error();

	gcry_md_hd_t hd;
	gcry_error_t err;
	uint8_t tmpbuf[HASH_CHUNK_SIZE];

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
		sizes[i] = filesize(to_transfer[i]);
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
static void encrypt_chunk(gcry_cipher_hd_t hd, char *dst, char *src,
			  int src_len)
{
	gcry_error_t err = 0;
	err = gcry_cipher_encrypt(hd, (unsigned char *)dst, src_len, src,
				  src_len);
	g_error(err);
}

/*
 * Encrypt and Write specified file to the server. Returns true if
 * the file is encrypted and written entirely, false otherwise.
 */
static bool send_file(int sfd, gcry_cipher_hd_t hd, char *filepath)
{
	FILE *f = fopen(filepath, "r");
	if (NULL == f)
		return false;

	// We will re-use the buffers for efficiency
	char f_buf[CHUNK_SIZE];
	char enc_buf[CHUNK_SIZE];

	// Read a chunk from the file, encrypt, and write to server
	while (1) {
		int f_len = fread(f_buf, 1, CHUNK_SIZE, f);

		// Remaining bytes in file buf are set to random garbage
		if (f_len < CHUNK_SIZE) {
			for (int i = f_len; i < CHUNK_SIZE; i++) {
				f_buf[i] = rand() % 255;
			}
		}

		encrypt_chunk(hd, enc_buf, f_buf, CHUNK_SIZE);

		int n = write_all(sfd, enc_buf, CHUNK_SIZE);
		if (n < CHUNK_SIZE) {
			fprintf(stderr, "failed to write encoded buffer\n");
			fclose(f);
			return false;
		}

		if (f_len < CHUNK_SIZE)
			break;
	}

	fclose(f);
	return true;
}

/*
 * Transfer comma separated files from the specified local port to the
 * server at the specified destination port with the given AES key.
 * Returns true on successful transfer of all non-duplicate files,
 * false otherwise.
 */
static bool transfer_files(char *svr_ip, char *svr_port, char *loc_ip,
			   char *loc_port, char *comma_files, uint8_t *key)
{
	// Prep for transfer
	uint16_t num_files = parse_file_cnt(comma_files);
	char **files = parse_filepaths(comma_files, num_files);
	uint32_t *sizes = parse_sizes(files, num_files);

	uint8_t *vector = generate_vector();
	init_gcrypt();
	uint8_t **hashes = generate_hashes(files, num_files);
	if (NULL == hashes)
		exit(EXIT_FAILURE);

	// Initialize the transfer by sending the initialization header
	data_head *dh = datalist_init(vector);
	for (int i = 0; i < num_files; i++) {
		datalist_append(dh, files[i], sizes[i], hashes[i]);
	}

	fprintf(stdout, "connecting to server\n");
	int sfd = client_socket(svr_ip, svr_port, loc_ip, loc_port);
	uint32_t requested_idx = init_transfer(sfd, dh);
	fprintf(stdout, "got first file request for file %d\n", requested_idx);

	char resp_buf[RETURN_SIZE]; // Server response after file sent
	bool all_sent = true;
	gcry_cipher_hd_t hd = init_cipher_context(vector, key);

	// We send any files the server requests
	while (requested_idx > 0 && requested_idx <= num_files) {
		int idx = requested_idx - 1; // 1 based in protocol
		fprintf(stdout, "transferring %.*s...\n", NAME_BYTES,
			files[idx]);
		bool ok = send_file(sfd, hd, files[idx]);
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
	gcry_cipher_close(hd);

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
	char *l_port = NULL, *l_ip = NULL;
	char *r_port = NULL, *r_ip = NULL;
	char *key_path = NULL, *file_paths = NULL;

	while ((opt = getopt(argc, argv, "l:r:k:f:h")) != -1) {
		switch (opt) {
		case 'r':
			r_ip = parse_ip(optarg);
			r_port = parse_port(optarg);
			break;
		case 'l':
			l_ip = parse_ip(optarg);
			l_port = parse_port(optarg);
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

	if (NULL == r_port)
		r_port = strdup(DEFAULT_SERVER_PORT);

	uint8_t *key = read_key(key_path);
	if (NULL == key) {
		fprintf(stderr, "reading key %s failed\n", key_path);
		exit(EXIT_FAILURE);
	}

	int status = EXIT_SUCCESS;
	bool ok = transfer_files(r_ip, r_port, l_ip, l_port, file_paths, key);
	if (!ok) {
		status = EXIT_FAILURE;
		fprintf(stderr, "transferring files failed\n");
	}

	if (l_port != NULL)
		free(l_port);

	if (l_ip != NULL)
		free(l_ip);

	if (r_ip != NULL)
		free(r_ip);

	free(r_port);
	free(key_path);
	free(key);
	free(file_paths);
	return status;
}
