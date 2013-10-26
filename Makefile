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
bin_PROGRAMS = lsc lcc tsha ltc
lsc_SOURCES = ssl-config.c
lcc_SOURCES = containers.c
ltc_SOURCES = test-ldap-connection.c
lcd_SOURCES = domains.c
sha_SOURCES = sha1.c base-sha.c


all:	lsc lcc tsha ltc

lcc:	$(lcc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcc_SOURCES)

lsc:	$(lsc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lsc_SOURCES)

ltc:	$(ltc_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(ltc_SOURCES) $(LLDFLAGS)

lcd:	$(lcd_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcd_SOURCES) $(SLDFLAGS)

tsha:	$(sha_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(sha_SOURCES) $(SLDFLAGS)

clean:
	$(RM) *.o lsc lcc ltc lcd tsha
