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

data_head *datalist_init(char *vector)
{
	data_head *list = malloc(sizeof(data_node));
	if (list == NULL)
		mem_error();

	list->vector = calloc(INIT_VEC_BYTES + 1, sizeof(char));
	if (list->vector == NULL)
		mem_error();

	strncpy(list->vector, vector, INIT_VEC_BYTES);
	list->first = NULL;
	list->last = NULL;
	list->size = 0;
	list->size = 0;

	return list;
}

static data_node *datalist_create_node(char *name, int size, char *hash)
{
	data_node *node = malloc(sizeof(data_node));
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

void datalist_append(data_head *list, char *name, int size, char *hash)
{
	data_node *newNode = datalist_create_node(name, size, hash);
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

void datalist_remove(data_head *list, data_node *node)
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

static char *datalist_copy_item(data_node *node, char *copy_location)
{
	strncpy(copy_location, node->name, NAME_BYTES);
	copy_location += NAME_BYTES;
	*((uint32_t *)(copy_location)) = (uint32_t)htons(node->size);
	copy_location += SIZE_BYTES;
	strncpy(copy_location, node->hash, HASH_BYTES);
	copy_location += HASH_BYTES;

	return copy_location;
}

char *datalist_generate_payload(data_head *list)
{
	char *payload;
	char *copy_location;
	data_node *pos;

	//size of the line
	int line_size = NAME_BYTES + SIZE_BYTES + HASH_BYTES;

	//size of header portion
	int payload_size = FILES_BYTES + INIT_VEC_BYTES;
	payload_size += list->size * line_size;

	payload = calloc(payload_size + 1, sizeof(char));
	if (payload == NULL)
		mem_error();

	copy_location = payload;

	*((uint16_t *)(copy_location)) = (uint16_t)htons(list->size);
	copy_location += FILES_BYTES;
	strncpy(copy_location, list->vector, INIT_VEC_BYTES);

	for (pos = list->first; pos != NULL; pos = pos->next) {
		copy_location = datalist_copy_item(pos, copy_location);
	}

	return payload;
}

void datalist_destroy(data_head *list)
{
	while (list->first != NULL)
		datalist_remove(list, list->first);

	free(list->vector);
	list->vector = NULL;
	free(list);
	list = NULL;
}

data_node *datalist_get_index(data_head *list, int index)
{
	if (index >= list->size)
		return NULL;

	data_node *node = list->first;
	for (int i = 0; i < index; i++, node = node->next)
		;

	return node;
}
