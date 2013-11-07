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
GCFLAGS = `pkg-config --cflags glib-2.0`
GLDFLAGS = `pkg-config --libs-only-L glib-2.0`
GLIBS = `pkg-config --libs-only-l glib-2.0`
LLDFLAGS = -L/lib/x86_64-linux-gnu -lldap
SLDFLAGS = -L/lib/x86_64-linux-gnu -lcrypto
bin_PROGRAMS = lcd tsha gsha gsha2
lsc_SOURCES = ssl-config.c
lcc_SOURCES = containers.c
ltc_SOURCES = test-ldap-connection.c
lcd_SOURCES = domains.c
sha_SOURCES = sha1.c base-sha.c
gsha_SOURCES = glib-sha1.c base-sha.c
gsha2_SOURCES = glib-sha1-2.c base-sha.c
gsha3_SOURCES = glib-sha1-3.c

all:	lcd tsha gsha gsha2

tsha:	$(sha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(sha_SOURCES) $(SLDFLAGS) $(GLIBS)

gsha:	$(gsha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha_SOURCES) $(GLIBS)
	
gsha2:	$(gsha2_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha2_SOURCES) $(GLIBS)

lcd:	$(lcd_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcd_SOURCES) $(SLDFLAGS) $(GLIBS)
	
clean:
	$(RM) *.o $(bin_PROGRAMS)
