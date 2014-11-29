bin_PROGRAMS = 
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =

noinst_HEADERS = base-sha.h ldap-col.h

if HAVE_LIBCRYPTO
LIBS += -lcrypto
bin_PROGRAMS += sha1 sha
sha_SOURCES = sha.c
sha1_SOURCES = sha1.c
if HAVE_GLIB
LIBS += -lglib-2.0
shared_SOURCES = ldap-rep.c
tsha_SOURCES = sha1.c base-sha.c $(shared_SOURCES)
tsha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
tsha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
gsha_SOURCES = glib-sha1.c base-sha.c $(shared_SOURCES)
gsha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
gsha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
lcd_SOURCES = domains.c
lcd_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
lcd_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
gsha2_SOURCES = glib-sha1-2.c base-sha.c $(shared_SOURCES)
gsha2_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
gsha2_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
ssha_SOURCES = ssha1.c
ssha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
ssha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
bin_PROGRAMS += tsha gsha lcd gsha2 ssha
endif
endif

if HAVE_LIBLDAP
lct_SOURCES = test-ldap-connection.c
lct_CFLAGS = $(AM_CFLAGS)
lct_LDFLAGS = $(AM_LDFLAGS)
lct_CFLAGS += $(PCFLAGS)
bin_PROGRAMS += lct
endif
