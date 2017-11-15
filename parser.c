#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "parser.h"
#include "datalist.h"
#include "common.h"

static void header_add_node(data_head *list, char *file_data)
{
	char *name = file_data;
	int size = ntohl(file_data[NAME_BYTES]);
	char *hash = &file_data[NAME_BYTES + SIZE_BYTES];

	datalist_append(list, name, size, hash);
}

data_head *header_parse(char *header)
{
	int num_files;
	char *read_loc = header;

	num_files = ntohs(*read_loc);
	read_loc += FILES_BYTES;

	data_head *list = datalist_init(read_loc);
	read_loc += INIT_VEC_BYTES;

	for (int i = 0; i < num_files; i++) {
		header_add_node(list, read_loc);
		read_loc += NAME_BYTES + SIZE_BYTES + HASH_BYTES;
	}

	read_loc = NULL;

	return list;
}
