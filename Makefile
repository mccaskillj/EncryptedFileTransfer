# CMPT 361 F17
# Group 3
#
# Makefile rules for building secure file transfer transmitter and receiver

CC = gcc
CFLAGS = -Wall -Werror -Wextra -pedantic -Wno-missing-braces -Wshadow -Wpointer-arith -pedantic-errors -std=c99 -D_POSIX_C_SOURCE=201112L

.PHONY: all clean

all: txer rxer

txer: client.o parser.o datalist.o common.o filesys.o net.o ui.o
	$(CC) $^ -o $@  `libgcrypt-config --cflags --libs`

rxer: server.o parser.o datalist.o common.o filesys.o net.o ui.o
	$(CC) $^ -o $@  `libgcrypt-config --cflags --libs`

server.o: server.c common.h net.h datalist.h filesys.h parser.h

client.o: client.c common.h ui.h net.h datalist.h filesys.h parser.h

datalist.o: datalist.c datalist.h common.h

parser.o: parser.c datalist.h common.h

common.o: common.c common.h

filesys.o: filesys.c filesys.h common.h

net.o: net.c net.h common.h

ui.o: ui.c ui.h common.h

clean:
	$(RM) txer rxer *.o
