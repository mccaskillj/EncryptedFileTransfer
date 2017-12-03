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

/*
 * Represents a single file for transfer
 */
typedef struct data_node {
	struct data_node *prev;
	struct data_node *next;
	char *name;
	uint32_t size;
	uint8_t *hash;
	int transfer;
} data_node;

/*
 * Encapsulate all files for transfer
 */
typedef struct data_head {
	data_node *first;
	data_node *last;
	uint32_t size;
	uint8_t *vector;
} data_head;

/*
 * Initialize a list with the given initialization vector
 */
data_head *datalist_init(uint8_t *vector);

/*
 * Append a new node to the given list with the given name, size,
 * hash, and transfer status
 */
void datalist_append(data_head *list, char *name, uint32_t size, uint8_t *hash,
		     int transfer);

/*
 * Release all resources for the given list
 */
void datalist_destroy(data_head *list);

/*
 * Return the node in the list at the given index (1 based index)
 */
data_node *datalist_get_index(data_head *list, uint32_t index);

/*
 * Return the initial transfer payload for the given list
 */
uint8_t *datalist_generate_payload(data_head *list);

/*
 * Return the index of the next node active for transferring relative
 * to the provided index. Returns list size + 1 if no more nodes after
 * the provided index are marked as active for transfer
 */
uint32_t datalist_get_next_active(data_head *list, uint32_t index);

#endif /* DATALIST_H */
