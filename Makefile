RM=rm -f
CC=gcc
PROGRAM=rpp
LDADD=-lbsd -loping `pkg-config --libs riemann-client`
CFLAGS=-Wall -g

all: rpp.c
	$(CC) $(CFLAGS) -o rpp rpp.c $(LDADD)

clean:
	$(RM) $(PROGRAM)
