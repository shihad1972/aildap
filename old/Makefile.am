
PCFLAGS = -DLDAP_DEPRECATED
GCFLAGS = `pkg-config --cflags glib-2.0`
GLDFLAGS = `pkg-config --libs-only-L glib-2.0`
GLIBS = `pkg-config --libs-only-l glib-2.0`
LLDFLAGS = -L/lib/x86_64-linux-gnu -lldap
SLDFLAGS = -L/lib/x86_64-linux-gnu -lcrypto
bin_PROGRAMS = lcd tsha gsha gsha2 sha1 lct ssha sha
shared_SOURCES = ldap-rep.c
lct_SOURCES = test-ldap-connection.c
ssha_SOURCES = ssha1.c
lcd_SOURCES = domains.c
sha_SOURCES = sha.c
tsha_SOURCES = sha1.c base-sha.c $(shared_SOURCES)
sha1_SOURCES = sha1.c
gsha_SOURCES = glib-sha1.c base-sha.c $(shared_SOURCES)
gsha2_SOURCES = glib-sha1-2.c base-sha.c $(shared_SOURCES)

all:	$(bin_PROGRAMS)

tsha:	$(tsha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(tsha_SOURCES) $(SLDFLAGS) $(GLIBS)

gsha:	$(gsha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha_SOURCES) $(SLDFLAGS) $(GLIBS)

gsha2:	$(gsha2_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(gsha2_SOURCES) $(SLDFLAGS) $(GLIBS)

lcd:	$(lcd_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(lcd_SOURCES) $(SLDFLAGS) $(GLIBS)

sha1:	$(sha1_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(sha1_SOURCES) $(SLDFLAGS)

sha:	$(sha_SOURCES)
	$(CC) $(CFLAGS) -o $@ $(sha_SOURCES) $(SLDFLAGS)

lct:	$(lct_SOURCES)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $(lct_SOURCES) $(LLDFLAGS)

ssha:	$(ssha_SOURCES)
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $(ssha_SOURCES) $(GLIBS)
	
clean:
	$(RM) *.o $(bin_PROGRAMS)
