/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Server (rxer) entry point.
 */

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "datalist.h"
#include "filesys.h"
#include "net.h"
#include "parser.h"

/*
 * Transfer context while receiving file(s) from
 * a client
 */
typedef struct {
	gcry_cipher_hd_t hd;
	data_head *list;
	uint16_t cur;    // Index of current file
	char *client_id; // ip:port
	uint8_t *key;
	int burn;
} transfer_ctx;

/*
 * Create a new transfer context for the client ip:port
 */
static transfer_ctx *new_transfer_ctx(char *client_id)
{
	transfer_ctx *t = malloc(sizeof(transfer_ctx));
	if (NULL == t)
		mem_error();

	t->client_id = client_id;
	t->cur = 0;
	t->list = NULL;
	t->hd = NULL;
	t->key = NULL;
	t->burn = NO_BURN;
	return t;
}

/*
 * Release resources for a transfer context
 */
static void destroy_transfer_ctx(transfer_ctx *t)
{
	free(t->client_id);
	free(t);
	t = NULL;
}

static void usage(char *bin_path, int exit_status)
{
	char *bin = basename(bin_path);

	fprintf(stderr,
		"Usage: %s [-p port][-h]\n\n"
		"Options:\n"
		"-p Port for clients to connect to (default %s)\n"
		"-h Help\n\n",
		bin, DEFAULT_SERVER_PORT);
	exit(exit_status);
}

static uint8_t *read_initial_header(int socketfd, transfer_ctx *t)
{
	uint32_t header_size = HEADER_INIT_SIZE;
	uint64_t files_info = HEADER_LINE_SIZE;
	uint8_t *buf = NULL;

	static const uint8_t burn[HEADER_INIT_SIZE] = {0}; // Burn detection
	uint8_t initial_read[header_size];
	memset(initial_read, 0, header_size);

	fprintf(stdout, "reading initial transfer header bytes\n");
	recv_all(socketfd, initial_read, header_size);

	// Remove the clients key when they send an empty header
	if (memcmp(initial_read, burn, HEADER_INIT_SIZE) == 0) {
		char *key_path = concat_paths(CWD_KEYS, t->client_id);
		fprintf(stdout, "burn initiated...client key eliminated\n");
		int r = remove(key_path);
		if (r == -1)
			perror("remove burn");

		free(key_path);
		t->burn = BURN;
		return NULL;
	}

	uint16_t raw_file_cnt;
	memcpy(&raw_file_cnt, initial_read, sizeof(uint16_t));
	files_info = files_info * ntohs(raw_file_cnt) + header_size;

	buf = calloc(header_size + files_info, 1);
	if (buf == NULL)
		mem_error();

	memcpy(buf, initial_read, header_size);
	recv_all(socketfd, buf + header_size, files_info - header_size);
	fprintf(stdout, "read full transfer header\n");
	return buf;
}

/*
 * Save the actual file and the meta file. The actual file uses the hash as the
 * name, and contains actual file contents received. The meta file is a dotfile
 * of the hash and contains information about the file.
 */
static void save_files(char *tmp_name, data_node *n, char *client_id)
{
	char *hex = hash_to_hex(n->hash);

	// Write the meta file
	int hex_size = 2 * HASH_BYTES;
	char *meta = malloc(hex_size + 2);
	if (NULL == meta)
		mem_error();

	strncpy(meta, ".", 1);
	memcpy(meta + 1, hex, hex_size);
	meta[hex_size + 1] = '\0';

	FILE *fp = fopen(meta, "w");
	if (NULL == fp) {
		perror("fopen meta");
		exit(EXIT_FAILURE);
	}

	// Original filename and client ip:port written to meta file
	fprintf(fp, "%.*s\n", NAME_BYTES, n->name);
	fprintf(fp, "%s\n", client_id);
	fclose(fp);

	// Rename the temp file to its hash - we keep it
	int r = rename(tmp_name, hex);
	if (r == -1) {
		perror("rename");
		exit(EXIT_FAILURE);
	}

	free(meta);
	free(hex);
}

/*
 * Returns true if the given expected hash matches the actual.
 * If the hash is not the same, remove the given temp file.
 */
static bool hash_matches(uint8_t *actual, uint8_t *expected, char *tmp)
{
	if (memcmp(actual, expected, HASH_BYTES) != 0) {
		if (unlink(tmp) == -1) {
			perror("unlink");
			exit(EXIT_FAILURE);
		}

		return false;
	}

	return true;
}

/*
 * Receive a file at the current index of the transfer context.
 * Incoming chunks of data for the file are hashed as they come in.
 * Incoming data is written to a temp file until the contents are
 * validated against the expected hash. Returns the transfer status
 * for the given file.
 */
static uint8_t receive_file(int cfd, transfer_ctx *t)
{
	data_node *node = datalist_get_index(t->list, t->cur);
	if (NULL == node) {
		fprintf(stderr, "no file to save at idx %d\n", t->cur);
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "receiving %s...\n", node->name);

	// Read into a temp file because the hash isn't validated
	char tmp_name[] = "incoming-XXXXXX";
	int fd = mkstemp(tmp_name);
	if (fd == -1) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}

	FILE *fp = fdopen(fd, "w");
	if (fp == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	uint8_t rx_buf[CHUNK_SIZE];
	uint32_t total_read = 0;
	uint32_t bytes_left = node->size;
	uint32_t fwrite_size = CHUNK_SIZE;

	gcry_md_hd_t hash_hd;
	gcry_error_t err = gcry_md_open(&hash_hd, HASH_ALGO, 0);
	g_error(err);

	while (total_read < node->size) {
		recv_all(cfd, rx_buf, CHUNK_SIZE);

		err = gcry_cipher_decrypt(t->hd, rx_buf, CHUNK_SIZE, NULL, 0);
		g_error(err);

		total_read += CHUNK_SIZE;

		// Last chunk is handled here
		if (bytes_left < CHUNK_SIZE)
			fwrite_size = bytes_left;

		gcry_md_write(hash_hd, rx_buf, fwrite_size);
		fwrite(rx_buf, 1, fwrite_size, fp);
		bytes_left -= CHUNK_SIZE;
	}

	fclose(fp);

	//  Validate the received contents
	uint8_t *actual_hash = gcry_md_read(hash_hd, HASH_ALGO);
	bool matches = hash_matches(actual_hash, node->hash, tmp_name);
	gcry_md_close(hash_hd);

	if (!matches) {
		fprintf(stderr, "%s digest mismatch\n", node->name);
		return TRANSFER_N;
	}

	// Temp file renamed to actual name and create the meta file
	save_files(tmp_name, node, t->client_id);
	fprintf(stdout, "receiving %s done\n", node->name);
	return TRANSFER_Y;
}

static void read_from_client(int socketfd, transfer_ctx *t)
{
	uint8_t response[RETURN_SIZE];
	memset(response, 0, RETURN_SIZE);
	uint8_t status = 0;

	if (t->list == NULL) {
		uint8_t *header = read_initial_header(socketfd, t);

		// Client wants to burn their key
		if (header == NULL) {
			t->list = datalist_init(NULL);
			t->cur = t->list->size + 1;
			return;
		}

		t->list = header_parse(header);
		free(header);

		t->cur = datalist_get_next_active(t->list, t->cur);
		if (t->cur > t->list->size)
			return; // All files are duplicates off the bat

		t->hd = init_cipher_context(t->list->vector, t->key);
	} else {
		status = receive_file(socketfd, t);
		t->cur = datalist_get_next_active(t->list, t->cur);
	}

	uint16_t client_sends = htons(t->cur);
	memcpy(response, &client_sends, sizeof(uint16_t));
	response[RETURN_SIZE - 1] = status;

	write_all(socketfd, response, RETURN_SIZE);
}

/*
 * Handle an incoming client connection. We will ensure they have a
 * directory for files, and a valid key before receiving any files
 */
static void handle_conn(int cfd, transfer_ctx *t)
{
	uint8_t failure[RETURN_SIZE];

	// Ensure the client has a valid key on the server
	char *key_location = concat_paths(KEYS_DIR, t->client_id);
	t->key = read_key(key_location);
	if (t->key == NULL) {
		memset(failure, 0, RETURN_SIZE);
		write_all(cfd, failure, RETURN_SIZE);
		free(key_location);
		return;
	}

	// Ensure the client has a directory for their files
	char *client_path = concat_paths(RECV_DIR, t->client_id);
	ensure_dir(client_path);

	// Work from the clients directory to make fs work easier
	int err = chdir(client_path);
	if (err == -1) {
		perror("chdir to client hashes");
		exit(EXIT_FAILURE);
	}

	while (t->list == NULL || t->cur <= t->list->size)
		read_from_client(cfd, t);

	gcry_cipher_close(t->hd);
	datalist_destroy(t->list);
	free(client_path);
	free(key_location);
	free(t->key);
	if (t->burn == NO_BURN)
		fprintf(stdout, "done reading files from client\n\n");
}

static void accept_connection(int socketfd)
{
	pid_t pid;
	char *ip_port;

	while (!TERMINATED) {
		// Structs for storing the sender's address and port
		struct sockaddr_storage recv_addr;
		memset(&recv_addr, 0, sizeof(recv_addr));
		socklen_t recv_size = sizeof(recv_addr);

		// Wait for a connection on the socket and then accept it
		int recvfd =
		    accept(socketfd, (struct sockaddr *)&recv_addr, &recv_size);
		if (recvfd == -1) {
			if (errno == EINTR)
				break;

			if (errno != EWOULDBLOCK)
				perror("accept");
			continue;
		}

		// Duplicate process and check for failure
		if ((pid = fork()) == -1) {
			perror("fork error");
			close(socketfd);
			close(recvfd);
			exit(EXIT_FAILURE);
		}

		if (pid == 0) {
			// Child process
			close(socketfd);
			ip_port = make_ip_port(&recv_addr, recv_size);
			transfer_ctx *t = new_transfer_ctx(ip_port);

			handle_conn(recvfd, t);

			destroy_transfer_ctx(t);
			close(recvfd);
			return;
		} else {
			// Parent process; loop back to accept more connections
			close(recvfd);
			continue;
		}
	}

	close(socketfd);
}

int main(int argc, char *argv[])
{
	int opt = 0;
	char *port = NULL;
	init_sig_handler();

	while ((opt = getopt(argc, argv, "p:h")) != -1) {
		switch (opt) {
		case 'p':
			port = strdup(optarg);
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

	if (NULL == port)
		port = strdup(DEFAULT_SERVER_PORT);

	int sfd = server_socket(port);

	ensure_dir(KEYS_DIR);
	ensure_dir(RECV_DIR);

	accept_connection(sfd);

	free(port);
	return EXIT_SUCCESS;
}
