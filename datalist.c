/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Linked list which has nodes that contain file
 *  transfer specific fields
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "datalist.h"

dataHead *datalistInit(char *vector, int numFiles)
{
	dataHead *list = malloc(sizeof(dataNode));
	if (list == NULL)
		mem_error();

	list->vector = calloc(INIT_VEC_BYTES + 1, sizeof(char));
	if (list->vector == NULL)
		mem_error();

	strncpy(list->vector, vector, INIT_VEC_BYTES);
	list->numFiles = numFiles;
	list->first = NULL;
	list->last = NULL;
	list->size = 0;
	list->size = 0;

	return list;
}

static dataNode *datalistCreateNode(char *name, int size, char *hash)
{
	dataNode *node = malloc(sizeof(dataNode));
	if (node == NULL)
		mem_error();

	node->name = malloc(sizeof(char) * NAME_BYTES + 1);
	if (node->name == NULL)
		mem_error();
	strncpy(node->name, name, NAME_BYTES);

	node->hash = malloc(sizeof(char) * HASH_BYTES + 1);
	if (node->hash == NULL)
		mem_error();
	strncpy(node->hash, hash, HASH_BYTES);

	node->next = NULL;
	node->prev = NULL;
	node->size = size;

	return node;
}

void datalistAppend(dataHead *list, char *name, int size, char *hash)
{
	dataNode *newNode = datalistCreateNode(name, size, hash);
	if (list->size == 0) {
		list->first = newNode;
		list->last = newNode;
	} else {
		list->last->next = newNode;
		newNode->prev = list->last;
		list->last = newNode;
	}

	list->size++;
}

void datalistRemove(dataHead *list, dataNode *node)
{
	if (list->size == 1) {
		list->first = NULL;
		list->last = NULL;
	} else if (node == list->first) {
		list->first = node->next;
		list->first->prev = NULL;
	} else if (node == list->last) {
		list->last = node->prev;
		list->last->next = NULL;
	} else {
		node->prev->next = node->next;
		node->next->prev = node->prev;
	}

	list->size--;

	node->next = NULL;
	node->prev = NULL;
	free(node->name);
	free(node->hash);
	node->name = NULL;
	node->hash = NULL;
	free(node);
	node = NULL;
}

static char *datalistCopyItem(dataNode *node, char *cpyLocation)
{
	strncpy(cpyLocation, node->name, NAME_BYTES);
	cpyLocation += NAME_BYTES;
	*((uint32_t *)(cpyLocation)) = (uint32_t)htons(node->size);
	cpyLocation += SIZE_BYTES;
	strncpy(cpyLocation, node->hash, HASH_BYTES);
	cpyLocation += HASH_BYTES;
	strncpy(cpyLocation, "\n", 1);
	cpyLocation += 1;

	return cpyLocation;
}

char *datalistGeneratePayload(dataHead *list)
{
	char *payload;
	char *cpyLocation;
	dataNode *pos;

	// size of the line plus a newline character
	int lineSize = NAME_BYTES + SIZE_BYTES + HASH_BYTES + 1;

	// size of header portion including 2 newlines
	int payloadSize = FILES_BYTES + INIT_VEC_BYTES + 2;
	payloadSize += list->size * lineSize;

	payload = calloc(payloadSize + 1, sizeof(char));
	if (payload == NULL)
		mem_error();

	cpyLocation = payload;

	*((uint16_t *)(cpyLocation)) = (uint16_t)htons(list->numFiles);
	cpyLocation += FILES_BYTES;
	strncpy(cpyLocation, "\n", 1);
	cpyLocation += 1;
	strncpy(cpyLocation, list->vector, INIT_VEC_BYTES);
	cpyLocation += INIT_VEC_BYTES;
	strncpy(cpyLocation, "\n", 1);

	for (pos = list->first; pos != NULL; pos = pos->next) {
		cpyLocation = datalistCopyItem(pos, cpyLocation);
	}

	return payload;
}

void datalistDestroy(dataHead *list)
{
	while (list->first != NULL)
		datalistRemove(list, list->first);

	free(list->vector);
	list->vector = NULL;
	free(list);
	list = NULL;
}

dataNode *datalistGetIndex(dataHead *list, int index)
{
	if (index >= list->size)
		return NULL;

	dataNode *node = list->first;
	for (int i = 0; i < index; i++, node = node->next)
		;

	return node;
}
