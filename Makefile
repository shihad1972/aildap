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
bin_PROGRAMS = lsc lcc tsha ltc gsha gsha2 gsha3
lsc_SOURCES = ssl-config.c
lcc_SOURCES = containers.c
ltc_SOURCES = test-ldap-connection.c
lcd_SOURCES = domains.c
sha_SOURCES = sha1.c base-sha.c
gsha_SOURCES = glib-sha1.c base-sha.c
gsha2_SOURCES = glib-sha1-2.c base-sha.c
gsha3_SOURCES = glib-sha1-3.c


all:	lsc lcc lcd tsha ltc gsha3

lcc:	$(lcc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcc_SOURCES)

lsc:	$(lsc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lsc_SOURCES)

ltc:	$(ltc_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(ltc_SOURCES) $(LLDFLAGS)

lcd:	$(lcd_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcd_SOURCES) $(SLDFLAGS) $(GLIBS)

tsha:	$(sha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(sha_SOURCES) $(SLDFLAGS) $(GLIBS)

gsha:	$(gsha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha_SOURCES) $(GLIBS)
	
gsha2:	$(gsha2_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha2_SOURCES) $(GLIBS)
	
gsha3:	$(gsha3_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha3_SOURCES) $(GLIBS)
clean:
	$(RM) *.o $(bin_PROGRAMS) pas
