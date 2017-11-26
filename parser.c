#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "datalist.h"
#include "parser.h"

static void header_add_node(data_head *list, uint8_t *file_data)
{
	char *name = (char *)file_data;

	uint32_t raw_enc_size;
	memcpy(&raw_enc_size, file_data + NAME_BYTES, sizeof(uint32_t));

	uint8_t *hash = file_data + NAME_BYTES + SIZE_BYTES;
	datalist_append(list, name, ntohl(raw_enc_size), hash);
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
