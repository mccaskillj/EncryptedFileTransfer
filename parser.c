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
	char *tok;
	const char delimiter[2] = "\n";

	tok = strtok(header, delimiter);
	num_files = ntohs(*tok);
	
	tok = strtok(header, delimiter);
	data_head *list = datalist_init(tok, num_files);

	tok = strtok(header, delimiter);
	while (tok != NULL) {
		header_add_node(list, tok);
		tok = strtok(header, delimiter);
	}

	return list;
}
