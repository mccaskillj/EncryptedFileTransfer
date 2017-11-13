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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

	// This can go, it's for checking if the data can be received.
	char buf[size];
	recv(socketfd, buf, size, 0);
	printf("%s", buf);

	return socketfd;
}

// Transfer files to the server at the specified address with the
// given AES key. Returns true on successful transfer of all non-duplicate
// files, false otherwise.
static bool transfer(dataHead *files, char *port, char *key)
{
	(void)files;
	(void)port;
	(void)key;
	open_socket(port);
	return false;
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
		free(port);
		free(key_path);
		exit(EXIT_FAILURE);
	}

	dataHead *files = datalistInit("fakevector", 1);
	int status = EXIT_SUCCESS;

	// TODO: Initialize the list nodes for each file to be transferred

	bool ok = transfer(files, port, key);
	if (!ok) {
		status = EXIT_FAILURE;
		fprintf(stderr, "transferring files failed\n");
	}

	free(port);
	free(key_path);
	free(key);
	return status;
}
