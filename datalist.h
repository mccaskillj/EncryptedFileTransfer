/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to linked list which has nodes that contain
 *  file transfer specific fields
 */

#ifndef DATALIST_H
#define DATALIST_H

typedef struct dataNode {
	struct dataNode *prev;
	struct dataNode *next;
	char *name;
	int size;
	char *hash;
} dataNode;

typedef struct dataHead {
	dataNode *first;
	dataNode *last;
	int size;
	char *vector;
	int numFiles;
} dataHead;

dataHead *datalistInit(char *vector, int numFiles);

void datalistAppend(dataHead *list, char *name, int size, char *hash);

void datalistRemove(dataHead *list, dataNode *node);

void datalistDestroy(dataHead *list);

dataNode *datalistGetIndex(dataHead *list, int index);

char *datalistGeneratePayload(dataHead *list);

#endif /*DATALIST_H*/