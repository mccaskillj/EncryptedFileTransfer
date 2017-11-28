/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Interface to functions for the file transfer UI
 *
 *
 *  Example usage:
 *
 *  prg_bar *p = init_prg_bar();
 *
 *  while(sending files){
 *      prg_reset(p, file_blocks, file_name);
 *
 *      while(transferring blocks){
 *          prg_update();
 *      }
 *  }
 *
 *  prg_destroy(p);
 */

#ifndef UI_H
#define UI_H

#include <stdint.h>
#include <sys/ioctl.h>
#include <time.h>

typedef struct {
	float next_bar; // % of next bar
	uint32_t current;
	float per_bar;	// % per bar
	float per_item;       // % per item
	struct timeval start; // wall clock time
	float item_mb;	// float for items < 1 MB
	const char *desc;
	int term_width;
} prg_bar;

/*
 * Initialize a new progress bar. Can be re-used for multiple
 * items that require a progress bar
 */
prg_bar *init_prg_bar(void);

/*
 * Prepare an empty progress bar with a given description for a
 * maximum of items which are the specified number of bytes in
 * size.Finish with a previous progress bar if there was one.
 */
void prg_reset(prg_bar *pg, uint32_t max_items, uint32_t item_bytes,
	       const char *desc);

/*
 * Update the progress bar. Renders a change to stdout only if
 * needed.
 */
void prg_update(prg_bar *pg);

/*
 * Erase the progress bar and show an error message for the given item
 */
void prg_error(prg_bar *pg, const char *msg);

/*
 * Release resources for the given progress bar
 */
void prg_destroy(prg_bar *pg);

#endif