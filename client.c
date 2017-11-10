/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Client (txer) entry point.
 */

#include <getopt.h>
#include <libgen.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

void usage(char *bin_path, int exit_status)
{
	char *bin = basename(bin_path);

	fprintf(stderr,
		"Usage: %s [-p port][-h]\n\n"
		"Options:\n"
		"-p Port to connect to server (default %s)\n"
		"-h Help\n\n",
		bin, DEFAULT_SERVER_PORT);
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

	// This can go, it's for checking if the data can be received.
	char buf[size];
	recv(socketfd, buf, size, 0);
	printf("%s", buf);

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
	close(socket);

	free(port);
	return EXIT_SUCCESS;
}
