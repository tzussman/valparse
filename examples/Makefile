CC = gcc
CFLAGS = -g -Wall
LDFLAGS =
LDLIBS =

bad:

.PHONY: clean
clean:
	rm -f *.o a.out core bad

.PHONY: all
all: clean bad

.PHONY: vg
vg: bad
	valgrind --leak-check=full --xml=yes --xml-file=bad-test.xml --gen-suppressions=all ./bad

