CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c common.c
targets := client server

.PHONY: clean default all

default: all
all: $(targets)

client: client.o common.o
	$(CC) $(LDFLAGS) client.o common.o -o client

server: server.o
	$(CC) $(LDFLAGS) server.o common.o -o server


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

common.o: common.c
	$(CC) $(CFLAGS) -c -o common.o  common.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~
