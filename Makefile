#
#
# Makefile for various small c programs
#
#
CC = gcc
RM = rm -f
ECHO = echo
CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -Wunused -D_XOPEN_SOURCE=700 -g
PCFLAGS = -DLDAP_DEPRECATED
LDFLAGS = -lldap
bin_PROGRAMS = lsc lcc
lsc_OBJECTS = ssl-config.o
lcc_OBJECTS = containers.o
ltc_OBJECTS = test-ldap-connection.o

all:	lsc lcc ltc

lcc:	$(lcc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lcc_OBJECTS)

lsc:	$(lsc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lsc_OBJECTS)
ltc:	$(ltc_OBJECTS)
	$(CC) $(PCFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(ltc_OBJECTS)

clean:
	$(RM) *.o lsc lcc ltc
