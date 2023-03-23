all: default

default: aesdsocket.c
	$(CC) $(CCFLAGS) -Wall -Werror -pthread -g -c aesdsocket.c
	$(CC) $(LDFLAGS) -Wall -Werror aesdsocket.o -o aesdsocket -lpthread

clean:
	rm -f aesdsocket.o aesdsocket