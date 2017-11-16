#ifndef PARSER_H
#define PARSER_H

#include "datalist.h"

data_head *header_parse(char *header);

/*
 * Parse the next file requested by the server
 * from the request
 */
uint16_t parse_next_file(char *request);

/*
 * Parse the pass/fail status of a file transfer
 * from the server file request
 */
uint8_t parse_transfer_status(char *request);

#endif /*PARSER_H*/
