/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Server (rxer) entry point.
 */

#include <getopt.h>
#include <libgen.h>
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

static char *read_initial_header(int socketfd)
{
	uint64_t total_read = 0;
	uint32_t header_size = HEADER_INIT_SIZE;
	uint64_t files_info = HEADER_LINE_SIZE;
	char *buf = NULL;

	char initial_read[header_size];
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
 * Decrypt a chunk of data from src into dst
 */
static void decrypt_data(gcry_cipher_hd_t hd, char *src, char *dst)
{
	gcry_error_t err = 0;

	err = gcry_cipher_decrypt(hd, dst, CHUNK_SIZE, src, CHUNK_SIZE);
	g_error(err);
}

/*
 * Creates a directory for the client and all the sub directories that the
 * client's directory needs
 */
static char *gen_client_dirs(char *clientdir)
{
	char *client_path = gen_path(RECV_DIR, clientdir);
	char *hash_path = gen_path(client_path, HASHS_DIR);
	char *files_path = gen_path(client_path, FILES_DIR);

	ensure_dir(client_path);
	free(client_path);

	ensure_dir(hash_path);
	free(hash_path);

	ensure_dir(files_path);
	return files_path;
}

static uint8_t save_file(int socketfd, data_head **list, uint16_t *pos)
{
	data_node *node = datalist_get_index(*list, *pos);
	fprintf(stderr, "receiving %s...\n", node->name);

	if (NULL == node) {
		fprintf(stderr, "no file to save at idx %d\n", *pos);
		exit(EXIT_FAILURE);
	}

	struct sockaddr_storage sa_in;
	socklen_t len = sizeof(sa_in);

	if (getpeername(socketfd, (struct sockaddr *)&sa_in, &len) == -1)
		perror("getpeername");

	char *clientaddr = addr_dirname(sa_in);
	char *filesdir = gen_client_dirs(clientaddr);
	char *filepath = gen_path(filesdir, basename(node->name));

	char *key = read_key(gen_path(KEYS_DIR, clientaddr));
	char *vector = (*list)->vector;

	FILE *fp = fopen(filepath, "w");
	if (fp == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	gcry_cipher_hd_t h = init_cipher_context(vector, key);
	char rx_buf[CHUNK_SIZE];
	char f_buf[CHUNK_SIZE];
	uint32_t total_read = 0;

	while (total_read < node->size) {
		int n = recv_all(socketfd, rx_buf, CHUNK_SIZE);
		if (n < CHUNK_SIZE) {
			fprintf(stderr, "receiving full chunk failed\n");
			exit(EXIT_FAILURE);
		}

		decrypt_data(h, rx_buf, f_buf);
		fwrite(f_buf, 1, CHUNK_SIZE, fp);
		total_read += n;
	}

	free(filepath);
	free(key);
	free(clientaddr);
	fclose(fp);
	gcry_cipher_close(h);

	fprintf(stdout, "receiving %s done\n", node->name);
	return TRANSFER_Y;
}

static void read_from_client(int socketfd, data_head **list, uint16_t *pos)
{
	uint32_t sent_total = 0;
	char *read_val = NULL;
	char return_string[RETURN_SIZE];
	memset(return_string, 0, RETURN_SIZE);
	uint8_t status = 0;

	if (*list == NULL) {
		read_val = read_initial_header(socketfd);
		*list = header_parse(read_val);
	} else {
		status = save_file(socketfd, list, pos);
		*pos = datalist_get_next_active(*list, *pos);
	}

	uint16_t client_sends = htons(*pos);
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

static void accept_connection(int socketfd)
{
	pid_t pid;
	data_head *list = NULL;
	uint16_t pos = 1;

	while (1) {
		// Structs for storing the sender's address and port
		struct sockaddr_storage recv_addr;
		memset(&recv_addr, 0, sizeof(recv_addr));
		socklen_t recv_size = sizeof(recv_addr);

		// Wait for a connection on the socket and then accept it
		int recvfd =
		    accept(socketfd, (struct sockaddr *)&recv_addr, &recv_size);
		if (recvfd == -1) {
			perror("accept");
			continue;
		}

		// Duplicate process and check for failure. Close the sockets
		// and terminate program.
		if ((pid = fork()) == -1) {
			perror("fork error");
			close(socketfd);
			close(recvfd);
			exit(EXIT_FAILURE);
		}

		// Child process; sends a stream of bytes to the sender
		if (pid == 0) {
			close(socketfd);

			while (list == NULL || pos <= list->size)
				read_from_client(recvfd, &list, &pos);

			datalist_destroy(list);
			close(recvfd);
			fprintf(stdout, "done reading files from client\n\n");
			// Parent process; loop back to accept more connections
			break;
		} else {
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
