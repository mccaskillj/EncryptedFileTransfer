CC = gcc
CFLAGS = -Wall -Werror -Wextra -pedantic -Wno-missing-braces -Wshadow -Wpointer-arith -pedantic-errors -std=c99

.PHONY: all clean

all: txer rxer

txer: client.o
	$(CC) $^ -o $@

rxer: server.o
	$(CC) $^ -o $@

server.o: server.c

client.o: client.c

clean:
	$(RM) txer rxer *.o
