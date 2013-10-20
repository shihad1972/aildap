#
#
# Makefile for various small c programs
#
#
CC = gcc
RM = rm -f
ECHO = echo
CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -Wunused -D_XOPEN_SOURCE=700 -g
LDFLAGS = -lcrypto
bin_PROGRAMS = lsc lcc
lsc_OBJECTS = ssl-config.o
lcc_OBJECTS = containers.o
lcd_OBJECTS = domains.o
sha_OBJECTS = sha1.c

all:	lsc lcc lcd tsha

lcc:	$(lcc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lcc_OBJECTS)

lsc:	$(lsc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lsc_OBJECTS)

lcd:	$(lcd_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(lcd_OBJECTS)

tsha:	$(sha_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(sha_OBJECTS)

clean:
	$(RM) *.o lsc lcc lcd tsha
