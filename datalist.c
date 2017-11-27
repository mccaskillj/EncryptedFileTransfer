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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "datalist.h"

data_head *datalist_init(uint8_t *vector)
{
	data_head *list = calloc(1, sizeof(data_node));
	if (list == NULL)
		mem_error();

	list->vector = calloc(INIT_VEC_BYTES, 1);
	if (list->vector == NULL)
		mem_error();

	memcpy(list->vector, vector, INIT_VEC_BYTES);
	list->first = NULL;
	list->last = NULL;
	list->size = 0;

	return list;
}

/*finish this function once file structure is established*/
int check_hash(char *name, uint8_t *hash)
{
	(void)name;
	(void)hash;
	return TRANSFER_Y;
}

static data_node *datalist_create_node(char *name, uint32_t size, uint8_t *hash)
{
	data_node *node = calloc(1, sizeof(data_node));
	if (node == NULL)
		mem_error();

	node->name = calloc(NAME_BYTES, 1);
	if (node->name == NULL)
		mem_error();
	memcpy(node->name, name, NAME_BYTES);

	node->hash = calloc(HASH_BYTES, 1);
	if (node->hash == NULL)
		mem_error();
	memcpy(node->hash, hash, HASH_BYTES);

	node->transfer = check_hash(name, hash);
	node->next = NULL;
	node->prev = NULL;
	node->size = size;

	return node;
}

void datalist_append(data_head *list, char *name, uint32_t size, uint8_t *hash)
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

static void datalist_copy_item(data_node *node, uint8_t *copy_location)
{
	memcpy(copy_location, node->name, NAME_BYTES);
	copy_location += NAME_BYTES;

	uint32_t net_file_size = htonl(node->size);
	memcpy(copy_location, &net_file_size, sizeof(uint32_t));

	copy_location += SIZE_BYTES;
	memcpy(copy_location, node->hash, HASH_BYTES);
}

uint8_t *datalist_generate_payload(data_head *list)
{
	uint8_t *payload;
	uint8_t *copy_location;
	data_node *pos = list->first;

	int payload_size = HEADER_INIT_SIZE;
	payload_size += list->size * HEADER_LINE_SIZE;

	payload = calloc(payload_size, 1);
	if (payload == NULL)
		mem_error();

	copy_location = payload;

	uint16_t tmp = htons(list->size);
	memcpy(copy_location, &tmp, sizeof(uint16_t));

	copy_location += FILES_BYTES;
	memcpy(copy_location, list->vector, INIT_VEC_BYTES);
	copy_location += INIT_VEC_BYTES;

	while (pos != NULL) {
		datalist_copy_item(pos, copy_location);
		copy_location += NAME_BYTES + HASH_BYTES + SIZE_BYTES;
		pos = pos->next;
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

data_node *datalist_get_index(data_head *list, uint32_t index)
{
	if (index > list->size || index < 1)
		return NULL;

	data_node *node = list->first;

	for (uint32_t i = 1; i < index; i++, node = node->next)
		;

	return node;
}

uint32_t datalist_get_next_active(data_head *list, uint32_t index)
{
	uint32_t next = index + 1;
	data_node *pos = datalist_get_index(list, next);

	if (pos == NULL)
		return list->size + 1;

	for (; pos != NULL && pos->transfer == TRANSFER_N;
	     pos = pos->next, next++)
		;

	return next;
}
