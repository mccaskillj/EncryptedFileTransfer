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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

static uint8_t save_file(int socketfd, data_head **list, uint16_t *pos)
{
	uint64_t total_read = 0;

	data_node *node = datalist_get_index(*list, *pos);

	fprintf(stderr, "receiving %s...\n", node->name);

	if (NULL == node) {
		fprintf(stderr, "no file to save at idx %d\n", *pos);
		exit(EXIT_FAILURE);
	}

	uint32_t enc_size = node->size;
	if (node->size % 16 != 0)
		enc_size += padding_aes(node->size);

	char *buf = malloc(enc_size);
	if (buf == NULL)
		mem_error();

	while (enc_size - total_read > 0) {
		int n =
		    recv(socketfd, buf + total_read, enc_size - total_read, 0);
		total_read += n;
	}

	struct sockaddr_storage sa_in;
	socklen_t len = sizeof(sa_in);
	if (getsockname(socketfd, (struct sockaddr *)&sa_in, &len) == -1)
		perror("getsockname");

	char *fname = addr_dirname(sa_in);

	FILE *f = fopen(fname, "w");
	if (NULL == f)
		exit(EXIT_FAILURE);

	fwrite(buf, enc_size, 1, f);
	fclose(f);

	/*
		decrypt the file and generate hash
	*/

	/*
		check if file matches and return uint8_t 0 on no match
	*/

	/*
		save file to correct directory location
	*/

	fprintf(stderr, "receiving  %s done\n", node->name);

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
		socklen_t recv_size = 0;

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
	accept_connection(sfd);

	free(port);
	return EXIT_SUCCESS;
}
