CC ?= $(CROSS_COMPILE)gcc
CCFLAGS ?= -Wall -Werror -g
LDFLAGS ?= -Wall -Werror

all: aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) $(CCFLAGS) -pthread -c aesdsocket.c

aesdsocket: aesdsocket.o
	$(CC) $(LDFLAGS) aesdsocket.o -o aesdsocket -lpthread

clean:
	rm -f aesdsocket.o aesdsocket