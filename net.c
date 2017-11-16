/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Networking related functions
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

#define BACKLOG 10

int write_all(int fd, char *src, int src_len)
{
	int written = 0, n = 0;

	while (written < src_len) {
		n = write(fd, src + written, src_len - written);
		if (n < 0) {
			if (errno == EINTR)
				break;
			perror("write failed");
			exit(EXIT_FAILURE);
		}
		written += n;
	}

	return written;
}

int server_socket(char *port)
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

	if (p == NULL) {
		fprintf(stderr, "failed to bind socket\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(results);

	rv = listen(socketfd, BACKLOG);
	if (rv == -1) {
		perror("listen error");
		exit(EXIT_FAILURE);
	}

	return socketfd;
}

int client_socket(char *port)
{
	struct addrinfo hints, *results, *p;
	int socketfd = 0, rv;

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
		fprintf(stderr, "failed to connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(results);
	return socketfd;
}
