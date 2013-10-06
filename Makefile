#
#
# Makefile for various small c programs
#
#
CC = gcc
RM = rm -f
ECHO = echo
CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -Wunused -D_XOPEN_SOURCE=700 -g
bin_PROGRAMS = lsc lcc
lsc_OBJECTS = ssl-config.o
lcc_OBJECTS = containers.o

all:	lsc lcc

lcc:	$(lcc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lcc_OBJECTS)

lsc:	$(lsc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lsc_OBJECTS)

clean:
	$(RM) *.o lsc lcc
