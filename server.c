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
#include <string.h>
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
	return t;
}

/*
 * Release resources for a transfer context
 */
static void destroy_transfer_ctx(transfer_ctx *t)
{
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

static uint8_t *read_initial_header(int socketfd)
{
	uint64_t total_read = 0;
	uint32_t header_size = HEADER_INIT_SIZE;
	uint64_t files_info = HEADER_LINE_SIZE;
	uint8_t *buf = NULL;

	uint8_t initial_read[header_size];
	memset(initial_read, 0, header_size);

	fprintf(stdout, "reading initial transfer header bytes\n");

	while (header_size - total_read > 0) {
		int n = recv(socketfd, initial_read + total_read,
			     header_size - total_read, 0);
		if (n == -1) {
			perror("recv");
			exit(EXIT_FAILURE);
		}
		total_read += n;
	}

	uint16_t raw_file_cnt;
	memcpy(&raw_file_cnt, initial_read, sizeof(uint16_t));
	files_info = files_info * ntohs(raw_file_cnt) + header_size;

	buf = calloc(header_size + files_info, 1);
	if (buf == NULL)
		mem_error();
	memcpy(buf, initial_read, header_size);

	while (files_info - total_read > 0) {
		int n = recv(socketfd, buf + total_read,
			     files_info - total_read, 0);
		if (n == -1) {
			perror("recv");
			exit(EXIT_FAILURE);
		}
		total_read += n;
	}

	fprintf(stdout, "read full transfer header\n");
	return buf;
}

/*
 * Save the actual file and the meta file. The actual file uses the hash as the
 * name, and contains actual file contents received. The meta file is a dotfile
 * of the hash and contains information about the file.
 */
static void save_files(char *tmp_name, char *dst_name, uint8_t *hash)
{
	char *hex = hash_to_hex(hash);

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

	fwrite("filename: ", 1, 10, fp);
	fwrite(dst_name, 1, NAME_BYTES, fp);
	fwrite("\n", 1, 1, fp);
	fclose(fp);

	// Rename the temp file - we keep it
	int r = rename(tmp_name, hex);
	if (r == -1) {
		perror("rename");
		exit(EXIT_FAILURE);
	}

	free(meta);
	free(hex);
}

/*
 * Receive the file at the given index in the list from a client,
 * and write the file and meta file to disk (clients dir space)
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
	gcry_error_t err = 0;
	uint32_t bytes_left = node->size;
	uint32_t fwrite_size = CHUNK_SIZE;
	gcry_md_hd_t hash_hd;

	err = gcry_md_open(&hash_hd, HASH_ALGO, 0);
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

	unsigned char *cur_digest = gcry_md_read(hash_hd, HASH_ALGO);
	unsigned char *expec_digest = node->hash;

	// Expected hash doesn't match the acquired hash. Return a failure
	// status
	if (memcmp(cur_digest, expec_digest, HASH_BYTES) != 0) {
		int rv = unlink(tmp_name);
		if (rv == -1) {
			perror("unlink error");
			exit(EXIT_FAILURE);
		}

		printf("Digest mismatch: %s failed integrity check.\n",
		       node->name);

		return TRANSFER_N;
	}

	save_files(tmp_name, node->name, node->hash);
	fclose(fp);
	gcry_md_close(hash_hd);

	fprintf(stdout, "receiving %s done\n", node->name);
	return TRANSFER_Y;
}

static void read_from_client(int socketfd, transfer_ctx *t)
{
	uint32_t sent_total = 0;
	uint8_t *read_val = NULL;
	char return_string[RETURN_SIZE];
	memset(return_string, 0, RETURN_SIZE);
	uint8_t status = 0;

	if (t->list == NULL) {
		read_val = read_initial_header(socketfd);
		t->list = header_parse(read_val);

		t->cur = datalist_get_next_active(t->list, t->cur);
		if (t->cur > t->list->size)
			return; // All files are duplicates off the bat

		t->hd = init_cipher_context(t->list->vector, t->key);
	} else {
		status = receive_file(socketfd, t);
		t->cur = datalist_get_next_active(t->list, t->cur);
	}

	uint16_t client_sends = htons(t->cur);
	memcpy(return_string, &client_sends, sizeof(uint16_t));
	return_string[RETURN_SIZE - 1] = status;

	while (RETURN_SIZE - sent_total != 0) {
		int n = send(socketfd, &return_string[sent_total],
			     RETURN_SIZE - sent_total, 0);
		if (n == -1) {
			perror("send");
			exit(EXIT_FAILURE);
		}
		sent_total += n;
	}
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
			free(ip_port);
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
