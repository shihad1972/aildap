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
bin_PROGRAMS = lsc lcc ltc lgc luc ssha lrc
lsc_SOURCES = ssl-config.c
lcc_SOURCES = containers.c
lgc_SOURCES = lgc.c
ltc_SOURCES = test-ldap-connection.c
lrc_SOURCES = ldap-replication.c
ssha_SOURCES = ssha1.c
user_SOURCES = user.c base-sha.c


all:	$(bin_PROGRAMS)

lcc:	$(lcc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcc_SOURCES)

lsc:	$(lsc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lsc_SOURCES)

lrc:	$(lrc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lrc_SOURCES)

lgc:	$(lgc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lgc_SOURCES)
	
luc:	$(user_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(user_SOURCES) $(SLDFLAGS) $(GLIBS)

ltc:	$(ltc_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(ltc_SOURCES) $(LLDFLAGS)

ssha:	$(ssha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(ssha_SOURCES) $(GLIBS)

clean:
	$(RM) *.o $(bin_PROGRAMS)
