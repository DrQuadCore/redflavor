PREFIX ?= /usr/local
DESTLIB ?= $(PREFIX)/lib64

CC := gcc

CLIENT_SRCS := client.c
SERVER_SRCS := server.c

CLIENT_EXE := $(SRCS:.c=).out
SERVER_EXE := $(SRCS:.c=).out


all: client server

client: 
	$(CC) $(CFLAGS) -fPIC -DHAPPY $(CLIENT_SRCS) -o $@

server: 
	$(CC) $(CFLAGS) -fPIC -DHAPPY $(SERVER_SRCS) -o $@

.cc.o:
	$(CC) $(CFLAGS) -fPIC -DHAPPY $< -o $@

clean:
	rm -f *.o client server

.PHONY: clean  
