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

#include <stdint.h>

typedef struct data_node {
	struct data_node *prev;
	struct data_node *next;
	char *name;
	uint32_t size;
	char *hash;
} data_node;

typedef struct data_head {
	data_node *first;
	data_node *last;
	uint32_t size;
	char *vector;
} data_head;

data_head *datalist_init(char *vector);

void datalist_append(data_head *list, char *name, uint32_t size, char *hash);

void datalist_remove(data_head *list, data_node *node);

void datalist_destroy(data_head *list);

data_node *datalist_get_index(data_head *list, uint32_t index);

char *datalist_generate_payload(data_head *list);

#endif /*DATALIST_H*/
