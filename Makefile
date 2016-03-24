RM=rm -f
CC=gcc
PROGRAM=rpp
LDADD=-lbsd `pkg-config --libs liboping` `pkg-config --libs riemann-client`
CFLAGS=-Wall

all: rpp.c
	$(CC) $(CFLAGS) -o rpp rpp.c $(LDADD)

clean:
	$(RM) $(PROGRAM)
