/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to functions that take byte payloads
 *  and turn them into list-related structures
 */

#ifndef PARSER_H
#define PARSER_H

#include "datalist.h"

/*
 * Parse the given transfer header into a list representing
 * the given transfer.
 */
data_head *header_parse(uint8_t *header);

#endif /* PARSER_H */
