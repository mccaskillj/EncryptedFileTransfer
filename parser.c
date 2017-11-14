#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "parser.h"
#include "datalist.h"
#include "common.h"

static void headerAddNode(dataHead *list, char *fileData)
{
	char *name = fileData;
	int size = ntohl(fileData[NAME_BYTES]);
	char *hash = &fileData[NAME_BYTES + SIZE_BYTES];

	datalistAppend(list, name, size, hash);
}

dataHead *headerParse(char *header)
{
	int numFiles;
	char *tok;
	const char delimiter[2] = "\n";

	tok = strtok(header, delimiter);
	numFiles = ntohs(*tok);
	
	tok = strtok(header, delimiter);
	dataHead *list = datalistInit(tok, numFiles);

	tok = strtok(header, delimiter);
	while (tok != NULL) {
		headerAddNode(list, tok);
		tok = strtok(header, delimiter);
	}

	return list;
}
