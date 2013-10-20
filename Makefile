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
LLDFLAGS = -L/lib/x86_64-linux-gnu -lldap
SLDFLAGS = -L/lib/x86_64-linux-gnu -lcrypto
bin_PROGRAMS = lsc lcc lcd tsha ltc
lsc_OBJECTS = ssl-config.o
lcc_OBJECTS = containers.o
ltc_OBJECTS = test-ldap-connection.o
lcd_OBJECTS = domains.o
sha_OBJECTS = sha1.c


all:	lsc lcc lcd tsha ltc

lcc:	$(lcc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lcc_OBJECTS)

lsc:	$(lsc_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lsc_OBJECTS)

ltc:	$(ltc_OBJECTS)
	$(CC) $(PCFLAGS) $(CFLAGS) -o $@ $(ltc_OBJECTS) $(LLDFLAGS)

lcd:	$(lcd_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(lcd_OBJECTS) $(SLDFLAGS)

tsha:	$(sha_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(sha_OBJECTS) $(SLDFLAGS)

clean:
	$(RM) *.o lsc lcc ltc lcd tsha
