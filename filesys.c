/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: File system related functions
 */

#define _XOPEN_SOURCE // enable sys/stat macros

#include <arpa/inet.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "common.h"
#include "filesys.h"

uint8_t *read_key(char *key_path)
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

	uint8_t *key = malloc(KEY_SIZE);
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

	if (err != -1 && st.st_mode == S_IFDIR) {
		return true; // Already exists
	}

	// Perms for all to read & write
	err = mkdir(path, 0755);
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

char *concat_paths(char *s1, char *s2)
{
	char *path = malloc(PATH_MAX);
	if (path == NULL)
		mem_error();

	snprintf(path, PATH_MAX, "%s/%s", s1, s2);
	return path;
}
