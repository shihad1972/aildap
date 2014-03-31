PCFLAGS = -DLDAP_DEPRECATED
GCFLAGS = `pkg-config --cflags glib-2.0`
GLDFLAGS = `pkg-config --libs-only-L glib-2.0`
GLIBS = `pkg-config --libs-only-l glib-2.0`
LLDFLAGS = -L/lib/x86_64-linux-gnu -lldap
SLDFLAGS = -L/lib/x86_64-linux-gnu -lcrypto

bin_PROGRAMS = lcs lcc lct lcg lcu ssha lcr lcdb
shared_SOURCES = ldap-rep.c
lcdb_SOURCES = lcdb.c $(shared_SOURCES) base-sha.c
lcs_SOURCES = ssl-config.c
lcc_SOURCES = containers.c $(shared_SOURCES)
lcg_SOURCES = lcg.c $(shared_SOURCES)
lct_SOURCES = test-ldap-connection.c
lcr_SOURCES = ldap-replication.c $(shared_SOURCES) base-sha.c
ssha_SOURCES = ssha1.c
lcu_SOURCES = user.c $(shared_SOURCES) base-sha.c

lcc:	$(lcc_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcc_SOURCES)

lcs:	$(lcs_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcs_SOURCES)

lcr:	$(lcr_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcr_SOURCES) $(SLDFLAGS) $(GLIBS)

lcg:	$(lcg_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(lcg_SOURCES)

lcu:	$(lcu_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcu_SOURCES) $(SLDFLAGS) $(GLIBS)

lcdb:	$(lcdb_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcdb_SOURCES) $(SLDFLAGS) $(GLIBS)

lct:	$(lct_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(lct_SOURCES) $(LLDFLAGS)

ssha:	$(ssha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(ssha_SOURCES) $(GLIBS)

clean:
	$(RM) *.o $(bin_PROGRAMS)
