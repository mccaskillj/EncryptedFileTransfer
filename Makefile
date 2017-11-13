# CMPT 361 F17
# Group 3
#
# Makefile rules for building secure file transfer transmitter and receiver

CC = gcc
CFLAGS = -Wall -Werror -Wextra -pedantic -Wno-missing-braces -Wshadow -Wpointer-arith -pedantic-errors -std=c99 -D_POSIX_C_SOURCE=200809L

.PHONY: all clean

all: txer rxer

txer: client.o parser.o datalist.o common.o
	$(CC) $^ -o $@

rxer: server.o parser.o datalist.o common.o
	$(CC) $^ -o $@

server.o: server.c common.h

client.o: client.c common.h

datalist.o: datalist.c common.h

parser.o: parser.c common.h

common.o: common.h

clean:
	$(RM) txer rxer *.o
