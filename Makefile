CC = gcc
CFLAGS = -Wall -Werror -Wextra -pedantic -Wno-missing-braces -Wshadow -Wpointer-arith -pedantic-errors -std=c99

.PHONY: all clean

all: txer rxer

txer: client.o datalist.o
	$(CC) $^ -o $@

rxer: server.o datalist.o
	$(CC) $^ -o $@

server.o: server.c

client.o: client.c

datalist.o: datalist.c

clean:
	$(RM) txer rxer *.o
