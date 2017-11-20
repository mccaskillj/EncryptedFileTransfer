/*
 *  Group 3
 *  Assignment #3 - Secure File Transfer
 *  CMPT361 F17
 *
 *  Purpose: Functions for the file transfer UI.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "ui.h"

#define BAR_WIDTH 20
#define FILENAME_WIDTH 50
#define SPEED_DIGITS_WIDTH 7  // 999.999 max displayed
#define SPEED_MEASURE_WIDTH 8 // MB/sec plus space on each side
#define SPEED_WIDTH (SPEED_DIGITS_WIDTH + SPEED_MEASURE_WIDTH)
#define RIGHT_PAD 4 // Bar to terminal

// Terminal colouring
#define C_RED "\x1B[31m"
#define C_NORM "\x1B[0m"

/*
 * Read terminal width and store it
 */
static void update_term_width(prg_bar *pg)
{
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	pg->term_width = w.ws_col - RIGHT_PAD;
}

prg_bar *init_prg_bar()
{
	prg_bar *pg = malloc(sizeof(prg_bar));
	if (NULL == pg)
		mem_error();

	pg->current = 0;
	pg->per_bar = 0;
	pg->next_bar = 0;
	pg->per_item = 0;
	pg->item_mb = 0;
	pg->desc = NULL;
	memset(&pg->start, 0, sizeof(struct timeval));
	update_term_width(pg);
	return pg;
}

/*
 * Write and update the given progress bar in place. Speed
 * is calculated by looking at the total elapsed microseconds
 * and then converting to kilobytes per second based on the
 * item size.
 */
static void prg_write(prg_bar *pg)
{
	struct timeval now;
	long us, s;
	update_term_width(pg);
	gettimeofday(&now, NULL);

	s = (now.tv_sec - pg->start.tv_sec);
	us = ((s * 1000000) + now.tv_usec) - (pg->start.tv_usec);

	float speed = (pg->current * pg->item_mb) / (us / 1000000.0);
	int name_width = pg->term_width - SPEED_WIDTH - BAR_WIDTH;

	printf("%-*.*s%*.3f MB/sec [", name_width, name_width, pg->desc,
	       SPEED_DIGITS_WIDTH, speed);

	for (int i = 1; i <= BAR_WIDTH; i++) {
		if (pg->current * pg->per_item >= (pg->per_bar * i)) {
			printf("#");
		} else {
			printf("-");
		}
	}

	printf("]\r");
	fflush(stdout);
}

void prg_reset(prg_bar *pg, uint32_t max_items, uint32_t item_bytes,
	       const char *desc)
{
	if (pg->current > 0)
		printf("\n"); // leave previous bar in-tact, start new

	pg->per_bar = 100.0 / BAR_WIDTH;
	pg->per_item = 100.0 / max_items;
	pg->next_bar = pg->per_bar;
	pg->desc = desc;
	pg->current = 0;
	pg->item_mb = item_bytes / (float)(2 << 19); // bytes / bytes per 1 MB
	gettimeofday(&pg->start, NULL);
	prg_write(pg);
}

void prg_update(prg_bar *pg)
{
	pg->current++;

	if (pg->current * pg->per_item > pg->next_bar) {
		prg_write(pg);
		pg->next_bar += pg->per_bar;
	}
}

void prg_error(prg_bar *pg, const char *msg)
{
	// Current to zero to prevent double newline if reset is called.
	// Start with newline to flush the existing progress bar out
	pg->current = 0;
	printf(C_RED "\nTransferring %.*s error: %s" C_NORM "\n", NAME_BYTES,
	       pg->desc, msg);
}

void prg_destroy(prg_bar *pg)
{
	printf("\n");
	free(pg);
	pg = NULL;
}
