CC=gcc
CFLAGS=-Wall -Wextra -O2
LDFLAGS=-lcrypt

all: server_0919

server_0919: server_0919.c
	$(CC) $(CFLAGS) -o server_0919 server_0919.c $(LDFLAGS)

clean:
	rm -f server_0919
