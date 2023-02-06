all: writer

writer: writer.c
	$(CC) $(CCFLAGS) -c writer.c
	$(CC) $(LDFLAGS) writer.o -o writer

clean:
	rm -f writer.o writer