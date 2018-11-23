CC=gcc
CFLAGS=-I. -g

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sigfuz: sigfuz.o
	$(CC) -o sigfuz sigfuz.o

clean:
	rm -fr sigfuz sigfuz.o
