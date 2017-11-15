/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Client (txer) entry point.
 */

#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <libgen.h>
#include <math.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "datalist.h"
#include "filesys.h"

static void usage(char *bin_path, int exit_status)
{
	char *bin = basename(bin_path);

	fprintf(stderr,
		"Usage: %s [-k key][-f files][-p port][-h]\n\n"
		"Options:\n"
		"-k Path to 256 bit AES encryption key (default %s)\n"
		"-f Comma separated path(s) to file(s) to transfer (eg: "
		"file1,file2)\n"
		"-p Port to connect to server (default %s)\n"
		"-h Help\n\n",
		bin, DEFAULT_KEY_PATH, DEFAULT_SERVER_PORT);
	exit(exit_status);
}

static int open_socket(char *port)
{
	struct addrinfo hints, *results, *p;
	int socketfd = 0, rv;
	int size = strlen("Connection Established\n");

	// Initialize hints and set the options for a TCP connection
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Get avaliable address, ports
	rv = getaddrinfo(NULL, port, &hints, &results);
	if (rv == -1) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(rv));
		exit(EXIT_FAILURE);
	}

	// Loop through all the results and connect to the first we can
	for (p = results; p != NULL; p = p->ai_next) {
		socketfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (socketfd == -1) {
			perror("client socket error");
			continue;
		}

		rv = connect(socketfd, p->ai_addr, p->ai_addrlen);
		if (rv == -1) {
			close(socketfd);
			perror("client connect errror");
			continue;
		}

		// Connection was established
		break;
	}

	if (p == NULL) {
		perror("client failed to connect");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(results);

	// This can go, it's for checking if the data can be received.
	char buf[size];
	recv(socketfd, buf, size, 0);
	printf("%s", buf);

	return socketfd;
}

// Transfer files to the server at the specified address with the
// given AES key. Returns true on successful transfer of all non-duplicate
// files, false otherwise.
static bool transfer(data_head *files, char *port, char *key)
{
	(void)files;
	(void)port;
	(void)key;
	open_socket(port);
	return false;
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
		paths[0] = strdup(file_paths);
		return paths;
	}

	// We have multiple - parse them out
	int n = 0;

	char *path = strtok(file_paths, ",");
	while (path != NULL) {
		paths[n] = strdup(path);
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
 * Read the contents in the file
 */
static char *read_file(char *filepath, size_t filesize)
{
	char *filedata = NULL;
	mode_t mode = S_IRUSR | S_IRGRP | S_IROTH;
	int fd = open(filepath, O_RDONLY, mode);
	int bytesread = -1;

	if (fd == -1) {
		perror("file open error");
		exit(EXIT_FAILURE);
	}

	filedata = malloc(filesize + 1);
	if (filedata == NULL)
		mem_error();

	memset(filedata, 0, filesize + 1);

	bytesread = read(fd, filedata, filesize);

	if (bytesread == -1) {
		close(fd);
		perror("file read error");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return filedata;
}

/*
 * Encrypt the file at a given index in the linked list. The encryption is done
 * on the vector and key passed it.
 */
static unsigned char *encrypt_file(data_head *dh, int index, char *vector,
				   char *key)
{
	data_node *node = datalist_get_index(dh, index);

	if (node == NULL)
		return NULL;

	char *data = read_file(node->name, node->size);
	int rawsize = strlen(data);
	int size = rawsize + padding_aes(rawsize);

	gcry_cipher_hd_t hd;
	gcry_error_t err = 0;

	err =
	    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	g_error(err);

	// Set the key for ciphering
	err = gcry_cipher_setkey(hd, key, KEY_SIZE);
	g_error(err);

	// Set the init vector
	err = gcry_cipher_setiv(hd, vector, INIT_VEC_BYTES);
	g_error(err);

	unsigned char *encry_data = malloc(size);
	if (encry_data == NULL)
		mem_error();

	memset(encry_data, 0, size);

	size_t encry_bufsize = size;
	size_t encry_inlen = size;

	// Encrypt the data into a buffer
	err = gcry_cipher_encrypt(hd, encry_data, encry_bufsize,
				  (unsigned char *)data, encry_inlen);
	g_error(err);

	// Left here for demo purposes
	printf("encrypted data: %s\n", encry_data);
	fflush(stdout);

	// Clear the handle, the key doesn't get cleared
	err = gcry_cipher_reset(hd);
	g_error(err);

	// Set the init vector
	err = gcry_cipher_setiv(hd, vector, INIT_VEC_BYTES);
	g_error(err);

	// All this will be moved to the server side.
	unsigned char decry_out[size];
	memset(decry_out, 0, size);

	// Decrypt the encrypted data and print it out for demo purposes
	err =
	    gcry_cipher_decrypt(hd, decry_out, size, encry_data, encry_bufsize);
	g_error(err);

	printf("decrypted data:\n%s\n", decry_out);
	// Up till here

	gcry_cipher_close(hd);
	free(data);
	return encry_data;
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

	uint16_t num_files = parse_file_cnt(file_paths);
	char **files = parse_filepaths(file_paths, num_files);
	uint32_t *sizes = parse_sizes(files, num_files);

	char *vector = generate_vector();
	init_gcrypt();
	char **hashes = generate_hashes(files, num_files);
	if (NULL == hashes)
		exit(EXIT_FAILURE);

	// Begin functionality demo
	printf("generated vector: ");
	fwrite(vector, 1, INIT_VEC_BYTES, stdout);
	printf("\n");

	for (int i = 0; i < num_files; i++) {
		printf("Parsed file %.*s with encrypted size %d and hash:\n",
		       NAME_BYTES, files[i], sizes[i]);
		fwrite(hashes[i], 1, HASH_BYTES, stdout);
		printf("\n");
	}

	fflush(stdout);
	// End demo

	data_head *dh = datalist_init(vector);
	for (int i = 0; i < num_files; i++) {
		datalist_append(dh, files[i], sizes[i], hashes[i]);
		free(files[i]);
		free(hashes[i]);
	}

	// For demo purposes, encryption function just on the first 2 files
	// passed in
	unsigned char *edata = encrypt_file(dh, 0, vector, key);
	if (edata != NULL)
		free(edata);

	edata = encrypt_file(dh, 1, vector, key);
	if (edata != NULL)
		free(edata);

	free(files);
	free(sizes);
	free(hashes);

	int status = EXIT_SUCCESS;

	bool ok = transfer(dh, port, key);
	if (!ok) {
		status = EXIT_FAILURE;
		fprintf(stderr, "transferring files failed\n");
	}

	datalist_destroy(dh);
	free(port);
	free(key_path);
	free(key);
	free(file_paths);
	free(vector);
	return status;
}
