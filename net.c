/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Networking related functions
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

#include "common.h"

#define BACKLOG 10

void write_all(int dstfd, uint8_t *src, int src_len)
{
	int written = 0;

	while (written < src_len) {
		int n = write(dstfd, src + written, src_len - written);
		if (n < 0) {
			if (errno == EINTR)
				break;
			perror("write failed");
			exit(EXIT_FAILURE);
		}
		written += n;
	}
}

void recv_all(int srcfd, uint8_t *dst, int dst_len)
{
	int total_read = 0;

	while (total_read < dst_len) {
		int n = recv(srcfd, dst + total_read, dst_len - total_read, 0);
		if (n == -1) {
			if (errno == EINTR)
				break;
			perror("recv failed");
			exit(EXIT_FAILURE);
		}

		total_read += n;
	}
}

char *make_ip_port(struct sockaddr_storage *connection, socklen_t size)
{
	int err;
	int str_size;
	char *ip_port;
	char ip[NI_MAXHOST];
	memset(ip, '\0', NI_MAXHOST);
	char port[NI_MAXSERV];
	memset(port, '\0', NI_MAXSERV);

	err = getnameinfo((struct sockaddr *)connection, size, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	
	/*check for error getting host and port*/
	if (err != 0)
		return "";

	str_size = snprintf(NULL, 0, "%s:%s", ip, port);
	ip_port = calloc(str_size + 1, sizeof(char));
	if (ip_port == NULL)
		mem_error();

	snprintf(ip_port, str_size + 1, "%s:%s", ip, port);

	return ip_port;
}

int server_socket(char *port)
{
	int socketfd, rv;
	struct addrinfo hints, *results, *p;
	struct timeval timeout;

	// Clear hints and set the options for TCP
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	// Set the read timeout
	timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

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

		rv = setsockopt (socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                sizeof(timeout));
		if (rv == -1) {
        	perror("setsockopt error");
        	exit(EXIT_FAILURE);
        }

        rv = setsockopt (socketfd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                sizeof(timeout));
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

int client_socket(char *svr_ip, char *svr_port, char *loc_ip, char *loc_port)
{
	int rv = 0;
	struct sockaddr_in raddr, laddr;
	memset(&raddr, 0, sizeof(raddr));
	memset(&laddr, 0, sizeof(laddr));
	struct timeval timeout;

	timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = htonl(INADDR_ANY);
	raddr.sin_port = htons(atoi(svr_port));

	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (NULL == loc_port)
		laddr.sin_port = htons(0); // OS assigned
	else
		laddr.sin_port = htons(atoi(loc_port));

	// Connect to specified server IPs
	if (NULL != svr_ip) {
		raddr.sin_addr.s_addr = inet_addr(svr_ip);
	}

	// Bind to specified local IPs
	if (NULL != loc_ip) {
		laddr.sin_addr.s_addr = inet_addr(loc_ip);
	}

	int socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	rv = setsockopt (socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
            sizeof(timeout));
	if (rv == -1) {
    	perror("setsockopt error");
    	exit(EXIT_FAILURE);
    }

    rv = setsockopt (socketfd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
            sizeof(timeout));
	if (rv == -1) {
    	perror("setsockopt error");
    	exit(EXIT_FAILURE);
    }

	if (NULL != loc_port) {
		rv = bind(socketfd, (struct sockaddr *)&laddr, sizeof(laddr));
		if (rv == -1) {
			perror("bind");
			close(socketfd);
			exit(EXIT_FAILURE);
		}
	}

	rv = connect(socketfd, (struct sockaddr *)&raddr,
		     sizeof(struct sockaddr));
	if (rv == -1) {
		close(socketfd);
		perror("connect");
		exit(EXIT_FAILURE);
	}

	return socketfd;
}
