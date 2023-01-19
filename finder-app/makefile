writer: writer.c
	$(CROSS_COMPILE)gcc -g -Wall -c -o writer.o writer.c
	$(CROSS_COMPILE)gcc -g -Wall -I/ writer.o -o writer

clean:
	rm -f writer.o writer