CC=gcc
CFLAGS=-I. -g -pthread

sigfuz: sigfuz.o
	$(CC) $(CFLAGS) -g -o sigfuz sigfuz.o

clean:
	rm -fr sigfuz sigfuz.o
