/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Client (txer) entry point.
 */

#include <errno.h>
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
#include "ui.h"

typedef struct {
	uint8_t *key;
	uint8_t *vector;
	data_head *transferring;

	char *l_port;
	char *l_ip;
	char *r_port;
	char *r_ip;
} client;

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
			fprintf(stderr, "%.*s: %s\n", NAME_BYTES,
				to_transfer[i], strerror(errno));
			exit(EXIT_FAILURE);
		}

		while (!TERMINATED) {
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
 * Parse the next file requested by the server to transfer
 */
static uint16_t parse_next_file(uint8_t *request)
{
	uint16_t next = 0;
	next += request[1];
	next += request[0] << 8;
	return next;
}

/*
 * Parse the pass/fail status of a file transfer from the server
 * file request
 */
static bool transfer_passed(uint8_t *request)
{
	return request[2] == TRANSFER_Y;
}

/*
 * Initialize the file transfer with the server by sending the file
 * transfer header. Returns index of file requested by server, 0
 * otherwise.
 */
static int init_transfer(int serv, data_head *dh)
{
	uint8_t *transfer_header = datalist_generate_payload(dh);
	int header_len = HEADER_INIT_SIZE + (dh->size * HEADER_LINE_SIZE);

	write_all(serv, transfer_header, header_len);
	free(transfer_header);

	uint8_t request[RETURN_SIZE];
	recv_all(serv, request, RETURN_SIZE);

	// Verify the server has clients key
	static const uint8_t no_key[RETURN_SIZE] = {0};
	if (memcmp(request, no_key, 3) == 3) {
		return 0;
	}

	return parse_next_file(request);
}

/*
 * Encrypt and Write specified file to the server. Returns true if
 * the file is encrypted and written entirely, false otherwise.
 */
static bool send_file(int sfd, gcry_cipher_hd_t hd, char *filepath, prg_bar *pb)
{
	FILE *f = fopen(filepath, "r");
	if (NULL == f)
		return false;

	gcry_error_t err = 0;
	uint8_t f_buf[CHUNK_SIZE];

	// Read a chunk from the file, encrypt, and write to server
	while (!TERMINATED) {
		int f_len = fread(f_buf, 1, CHUNK_SIZE, f);

		// Remaining bytes in file buf are set to random garbage
		if (f_len < CHUNK_SIZE) {
			for (int i = f_len; i < CHUNK_SIZE; i++) {
				f_buf[i] = rand() % 255;
			}
		}

		err = gcry_cipher_encrypt(hd, f_buf, CHUNK_SIZE, NULL, 0);
		g_error(err);

		write_all(sfd, f_buf, CHUNK_SIZE);
		prg_update(pb);

		if (f_len < CHUNK_SIZE)
			break;
	}

	fclose(f);
	return true;
}

/*
 * Create a new client that encapsulates what is needed to transfer
 * files to the server
 */
static client *new_client(char *svr_ip, char *svr_port, char *loc_ip,
			  char *loc_port, char *comma_files, char *key_path)
{
	client *c = malloc(sizeof(client));
	if (NULL == c)
		mem_error();

	// Determine file names, sizes, and hashes and store them
	uint16_t num_files = parse_file_cnt(comma_files);
	char **files = parse_filepaths(comma_files, num_files);
	uint32_t *sizes = parse_sizes(files, num_files);

	init_gcrypt();
	c->vector = generate_vector();
	uint8_t **hashes = generate_hashes(files, num_files);

	c->transferring = datalist_init(c->vector);
	for (int i = 0; i < num_files; i++) {
		datalist_append(c->transferring, files[i], sizes[i], hashes[i], TRANSFER_Y);
		free(files[i]);
		free(hashes[i]);
	}

	c->key = read_key(key_path);
	if (NULL == c->key) {
		fprintf(stderr, "reading key %s failed\n", key_path);
		exit(EXIT_FAILURE);
	}

	c->r_port = svr_port;
	c->r_ip = svr_ip;
	c->l_port = loc_port;
	c->l_ip = loc_ip;

	free(files);
	free(hashes);
	free(sizes);
	return c;
}

/*
 * Release all resources for a client
 */
void destroy_client(client *c)
{
	datalist_destroy(c->transferring);
	free(c->key);
	free(c->vector);
	free(c);
	c = NULL;
}

/*
 * Connect to the server and transfer files for the given client
 * configuration. Returns true on successful transfer of all
 * non-duplicate files, false otherwise.
 */
static bool transfer_files(client *c)
{
	fprintf(stdout, "Connecting to server...\n");
	int sfd = client_socket(c->r_ip, c->r_port, c->l_ip, c->l_port);

	uint32_t requested_idx = init_transfer(sfd, c->transferring);
	if (requested_idx == 0) {
		fprintf(stderr, "No AES key on server\n");
		return false;
	}

	data_node *file = datalist_get_index(c->transferring, requested_idx);
	if (NULL == file) {
		fprintf(stderr, "bad first file request from server\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Server initiated file transfer\n");

	uint8_t resp_buf[RETURN_SIZE]; // Server response after file sent
	bool all_sent = true; // Whether ALL files were sent successfully
	gcry_cipher_hd_t hd = init_cipher_context(c->vector, c->key);
	prg_bar *pb = init_prg_bar();

	// We send any files the server requests
	while (file != NULL) {
		prg_reset(pb, file->size / CHUNK_SIZE, CHUNK_SIZE, file->name);

		bool ok = send_file(sfd, hd, file->name, pb);
		if (!ok) {
			prg_error(pb, "sending file failed");
			all_sent = false;
			break;
		}

		int n = recv(sfd, resp_buf, RETURN_SIZE, 0);
		if (n != RETURN_SIZE) {
			prg_error(pb, "bad transfer response from server");
			all_sent = false;
			break;
		}

		if (!transfer_passed(resp_buf)) {
			prg_error(pb, "server indicated the transfer failed");
			all_sent = false;
			break;
		}

		requested_idx = parse_next_file(resp_buf);
		file = datalist_get_index(c->transferring, requested_idx);
	}

	prg_destroy(pb);
	gcry_cipher_close(hd);
	return all_sent;
}

int main(int argc, char *argv[])
{
	int opt = 0;
	char *l_port = NULL, *l_ip = NULL;
	char *r_port = NULL, *r_ip = NULL;
	char *key_path = NULL, *file_paths = NULL;
	init_sig_handler();

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
		usage(argv[0],
		      EXIT_FAILURE); // Files required for transfer

	if (NULL == key_path)
		key_path = strdup(DEFAULT_KEY_PATH);

	if (NULL == r_port)
		r_port = strdup(DEFAULT_SERVER_PORT);

	client *c =
	    new_client(r_ip, r_port, l_ip, l_port, file_paths, key_path);

	int status = EXIT_SUCCESS;
	bool ok = transfer_files(c);
	if (!ok) {
		status = EXIT_FAILURE;
		fprintf(stderr, "Transferring all files failed\n");
	}

	destroy_client(c);

	if (l_port != NULL)
		free(l_port);

	if (l_ip != NULL)
		free(l_ip);

	if (r_ip != NULL)
		free(r_ip);

	free(r_port);
	free(key_path);
	free(file_paths);
	return status;
}
