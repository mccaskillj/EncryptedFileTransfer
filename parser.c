/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Functions that take byte payloads and turn
 *  them into list-related structures
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>

#include "common.h"
#include "datalist.h"
#include "filesys.h"
#include "parser.h"

/*
 * Ensure that the given hash does not exist in the current directory.
 * This function should be called while already in a given clients
 * working directory
 */
static int check_duplicate(uint8_t *hash)
{
	DIR *d;
	struct dirent *directory;
	char *hex_hash;

	int file_path_size = snprintf(NULL, 0, CUR_DIR);

	char filepath[file_path_size + 1];

	snprintf(filepath, file_path_size + 1, CUR_DIR);

	d = opendir(filepath);
	if (d) {
		directory = readdir(d);
		while (directory != NULL) {
			if (directory->d_name[0] != '.') {
				hex_hash = hash_to_hex(hash);
				if (memcmp(directory->d_name, hex_hash,
					   HASH_BYTES * 2) == 0) {
					free(hex_hash);
					closedir(d);
					return TRANSFER_N;
				}
				free(hex_hash);
			}
			directory = readdir(d);
		}
		closedir(d);
	}

	return TRANSFER_Y;
}

/*
 * Add a list node to the given list, interpreted from the given
 * file data bytes containing the files name, size, and hash
 */
static void header_add_node(data_head *list, uint8_t *file_data)
{
	char *name = (char *)file_data;

	uint32_t raw_enc_size;
	memcpy(&raw_enc_size, file_data + NAME_BYTES, sizeof(uint32_t));

	uint8_t *hash = file_data + NAME_BYTES + SIZE_BYTES;

	int transfer_flag = check_duplicate(hash);

	datalist_append(list, name, ntohl(raw_enc_size), hash, transfer_flag);
}

data_head *header_parse(uint8_t *header)
{
	int num_files;
	uint8_t *read_loc = header;

	uint16_t files_raw;
	memcpy(&files_raw, read_loc, sizeof(uint16_t));
	num_files = ntohs(files_raw);
	read_loc += FILES_BYTES;

	data_head *list = datalist_init(read_loc);
	read_loc += INIT_VEC_BYTES;

	for (int i = 0; i < num_files; i++) {
		header_add_node(list, read_loc);
		read_loc += NAME_BYTES + SIZE_BYTES + HASH_BYTES;
	}

	return list;
}
