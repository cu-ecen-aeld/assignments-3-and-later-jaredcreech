USE_AESD_CHAR_DEVICE ?= 1
CC ?= $(CROSS_COMPILE)gcc
CCFLAGS ?= -Wall -Werror -g
ifeq ($(USE_AESD_CHAR_DEVICE),1)
	CCFLAGS += -DUSE_AESD_CHAR_DEVICE
endif
LDFLAGS ?= -Wall -Werror

all: aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) $(CCFLAGS) -pthread -c aesdsocket.c

aesdsocket: aesdsocket.o
	$(CC) $(LDFLAGS) aesdsocket.o -o aesdsocket -lpthread

clean:
	rm -f aesdsocket.o aesdsocket