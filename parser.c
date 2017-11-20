#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "datalist.h"
#include "parser.h"

static void header_add_node(data_head *list, char *file_data)
{
	char *name = file_data;

	uint32_t raw_enc_size;
	memcpy(&raw_enc_size, file_data + NAME_BYTES, sizeof(uint32_t));

	char *hash = file_data + NAME_BYTES + SIZE_BYTES;
	datalist_append(list, name, ntohl(raw_enc_size), hash);
}

data_head *header_parse(char *header)
{
	int num_files;
	char *read_loc = header;

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

uint16_t parse_next_file(char *request)
{
	uint16_t next = 0;
	next += request[1];
	next += request[0] << 8;
	return next;
}

uint8_t parse_transfer_status(char *request) { return request[2]; }
