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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#include "common.h"
#include "datalist.h"
#include "parser.h"

#define BACKLOG 10

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
	uint64_t read = 0;
	uint32_t header_size = FILES_BYTES + INIT_VEC_BYTES;
	uint64_t files_info = NAME_BYTES + SIZE_BYTES + HASH_BYTES;
	char *buf;

	char initial_read[header_size + 1];
	memset(initial_read, 0, header_size + 1);

	while (header_size - total_read != 0) {
		read = recv(socketfd, initial_read, header_size - total_read, 0);
		total_read += read;
	}

	files_info = files_info * ntohs(*initial_read);

	buf = calloc((header_size + files_info + 1),sizeof(char));
	if (buf == NULL)
		mem_error();
	memcpy(buf, initial_read, header_size);

	while (files_info - total_read != 0) {
		read = recv(socketfd, &buf[total_read], files_info - total_read, 0);
		total_read += read;
	}

	return buf;
}

static uint8_t save_file(int socketfd, data_head **list, uint32_t *pos)
{
	uint64_t read = 0;
	uint64_t total_read = 0;
	data_node *node = datalist_get_index(*list, *pos);
	char *buf = malloc(sizeof(char) * node->size);
	if (buf == NULL)
		mem_error();

	while (node->size - total_read != 0) {
		read = recv(socketfd, &buf[total_read], node->size - total_read, 0);
		total_read += read;
	}

/*
	decrypt the file and generate hash
*/

/*	
	check if file matches and return uint8_t 0 on no match
*/

/*
	save file to correct directory location
*/

	return (uint8_t)1;
}

static void read_from_client(int socketfd, data_head **list, uint32_t *pos)
{
	uint32_t sent = 0;
	uint32_t sent_total = 0;
	char *read_val;
	char return_string[RETURN_SIZE];
	memset(return_string, 0, 3);
	uint8_t status;

	if (*list == NULL) {
		read_val = read_initial_header(socketfd);
		*list = header_parse(read_val);
		free(read_val);

		*((uint16_t *)(return_string)) = htons(*pos);
		return_string[RETURN_SIZE - 1] = 1;
	} else {
		status = save_file(socketfd, list, pos);
		*pos = *pos + 1;

		*((uint16_t *)(return_string)) = htons(*pos);
		return_string[RETURN_SIZE - 1] = status;
	}

	while (RETURN_SIZE - sent_total != 0) {
		sent = send(socketfd, &return_string[sent_total], RETURN_SIZE - sent_total, 0);
		sent_total += sent;
	}

}

static void accept_connection(int socketfd)
{
	pid_t pid;
	data_head *list = NULL;
	uint32_t pos = 0;

	while (1) {
		// Structs for storing the sender's address and port
		struct sockaddr_storage recv_addr;
		socklen_t recv_size;

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
			read_from_client(socketfd, &list, &pos);
			break;
		// Parent process; loop back to accept more connections
		} else {
			close(recvfd);
			continue;
		}
	}

	close(socketfd);
}

static int open_socket(char *port)
{
	int socketfd, rv;
	struct addrinfo hints, *results, *p;

	// Clear hints and set the options for TCP
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	if ((rv = getaddrinfo(NULL, port, &hints, &results)) == -1) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(rv));
		exit(EXIT_FAILURE);
	}

	// Loop through all the results and bind to the first we can
	for (p = results; p != NULL; p = p->ai_next) {
		socketfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (socketfd == -1) {
			perror("socket error");
			continue;
		}

		int value = 1;

		rv = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &value,
				sizeof(int));
		if (rv == -1) {
			perror("setsockopt error");
			exit(EXIT_FAILURE);
		}

		rv = bind(socketfd, p->ai_addr, p->ai_addrlen);
		if (rv == -1) {
			perror("bind error");
			close(socketfd);
			continue;
		}

		break;
	}

	freeaddrinfo(results);

	if (p == NULL) {
		perror("couldn't bind");
		exit(EXIT_FAILURE);
	}

	rv = listen(socketfd, BACKLOG);
	if (rv == -1) {
		perror("listen error");
		exit(1);
	}

	return socketfd;
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

	int socket = open_socket(port);
	accept_connection(socket);

	free(port);
	return EXIT_SUCCESS;
}
