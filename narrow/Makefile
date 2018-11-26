CC=gcc
CFLAGS=-I. -g

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

ts: ts.o
	$(CC) -o ts ts.o

clean:
	rm -fr ts ts.o
