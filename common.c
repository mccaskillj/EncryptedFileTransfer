/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Functions with application wide usage
 */

#include <stdio.h>
#include <stdlib.h>

void mem_error(void)
{
    fprintf(stderr, "malloc failed\n");
    exit(EXIT_FAILURE);
}
