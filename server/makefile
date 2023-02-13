all: default

default: aesdsocket.c
	$(CC) $(CCFLAGS) -Wall -Werror -c aesdsocket.c
	$(CC) $(LDFLAGS) -Wall -Werror aesdsocket.o -o aesdsocket

clean:
	rm -f aesdsocket.o aesdsocket