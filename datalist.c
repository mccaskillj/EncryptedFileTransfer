#include <stdlib.h>
#include <string.h>

#include "datalist.h"

dataHead *datalistInit()
{
	dataHead *list = malloc(sizeof(dataNode));
	if (list == NULL)
		exit(EXIT_FAILURE);

	list->vector = malloc(sizeof(char) * VECTOR_SIZE);
	if (list->vector == NULL)
		exit(EXIT_FAILURE);

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
		exit(EXIT_FAILURE);

	node->name = malloc(sizeof(char) * NAME_SIZE);
	if (node->name == NULL)
		exit(EXIT_FAILURE);
	strncpy(node->name, name, NAME_SIZE - 1);

	node->hash = malloc(sizeof(char) * HASH_SIZE);
	if (node->hash == NULL)
		exit(EXIT_FAILURE);
	strncpy(node->hash, hash, HASH_SIZE - 1);

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
	for (int i = 0; i < index; i++, node = node->next);

	return node;
}