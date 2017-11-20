/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: File system related functions
 */

#define _XOPEN_SOURCE // enable sys/stat macros

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "common.h"

static const char *IP_PORT_FORMAT = "%s:%hu";

char *addr_dirname(struct sockaddr_storage s)
{
	// Parts of this technique was adapted from Apple source:
	// https://opensource.apple.com/source/postfix/postfix-197/postfix/src/util/sock_addr.c
	char *ip = NULL;
	uint16_t port = 0;

	struct sockaddr *si = (struct sockaddr *)&s;
	struct sockaddr_in *si4 = (struct sockaddr_in *)&si;
	struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&si;

	switch (si->sa_family) {
	case AF_INET:
		ip = malloc(INET_ADDRSTRLEN + 1);
		if (NULL == ip)
			mem_error();

		inet_ntop(AF_INET, &(si4->sin_addr), ip, INET_ADDRSTRLEN);
		ip[INET_ADDRSTRLEN] = '\0';
		port = si4->sin_port;
		break;
	case AF_INET6:
		ip = malloc(INET6_ADDRSTRLEN + 1);
		if (NULL == ip)
			mem_error();

		inet_ntop(AF_INET6, &(si6->sin6_addr), ip, INET6_ADDRSTRLEN);
		ip[INET6_ADDRSTRLEN] = '\0';
		port = si6->sin6_port;
		break;
	default:
		return NULL;
	}

	int to_write = snprintf(NULL, 0, IP_PORT_FORMAT, ip, port);
	char *ip_port = malloc(to_write + 1);
	if (NULL == ip_port)
		mem_error();

	snprintf(ip_port, to_write + 1, IP_PORT_FORMAT, ip, port);

	free(ip);
	return ip_port;
}

char *read_key(char *key_path)
{
	struct stat st;

	int err = stat(key_path, &st);
	if (err == -1)
		return NULL;

	if (st.st_size != 32)
		return NULL;

	FILE *fp = fopen(key_path, "r");
	if (NULL == fp)
		return NULL;

	char *key = malloc(KEY_SIZE);
	if (NULL == key)
		mem_error();

	err = fread(key, KEY_SIZE, 1, fp);
	if (err == -1) {
		free(key);
		fclose(fp);
		return NULL;
	}

	fclose(fp);
	return key;
}

bool ensure_dir(char *path)
{
	struct stat st;

	int err = stat(path, &st);
	if (err == -1)
		return false;

	if (st.st_mode == S_IFDIR)
		return true;

	// Perms for user/group/other to read & write
	err = mkdir(path, 0666);
	if (err == -1)
		return false;

	return true;
}

uint32_t filesize(char *path)
{
	struct stat st;

	int err = stat(path, &st);
	if (err == -1)
		return 0;

	return st.st_size;
}
