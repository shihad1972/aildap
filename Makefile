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
bin_PROGRAMS = lcs lcc lct lcg lcu ssha lcr
lcs_SOURCES = ssl-config.c
lcc_SOURCES = containers.c
lcg_SOURCES = lcg.c
lct_SOURCES = test-ldap-connection.c
lcr_SOURCES = ldap-replication.c
ssha_SOURCES = ssha1.c
user_SOURCES = user.c base-sha.c


all:	$(bin_PROGRAMS)

lcc:	$(lcc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcc_SOURCES)

lcs:	$(lcs_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcs_SOURCES)

lcr:	$(lcr_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcr_SOURCES)

lcg:	$(lcg_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcg_SOURCES)
	
lcu:	$(user_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(user_SOURCES) $(SLDFLAGS) $(GLIBS)

lct:	$(lct_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(lct_SOURCES) $(LLDFLAGS)

ssha:	$(ssha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(ssha_SOURCES) $(GLIBS)

clean:
	$(RM) *.o $(bin_PROGRAMS)
