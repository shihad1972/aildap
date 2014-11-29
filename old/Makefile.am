## Process this file with automake to produce Makefile.in
#

bin_PROGRAMS = 
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =

sha_SOURCES = sha.c
sha1_SOURCES = sha1.c
tsha_SOURCES = sha1.c base-sha.c $(shared_SOURCES)
gsha_SOURCES = glib-sha1.c base-sha.c $(shared_SOURCES)
lcd_SOURCES = domains.c
gsha2_SOURCES = glib-sha1-2.c base-sha.c $(shared_SOURCES)
ssha_SOURCES = ssha1.c
lct_SOURCES = test-ldap-connection.c
noinst_HEADERS = base-sha.h ldap-col.h

if HAVE_LIBCRYPTO
bin_PROGRAMS += sha1 sha
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
if HAVE_GLIB
bin_PROGRAMS += tsha gsha lcd gsha2 ssha
LIBS += -lglib-2.0
shared_SOURCES = ldap-rep.c
tsha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
tsha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
gsha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
gsha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
lcd_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
lcd_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
gsha2_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
gsha2_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
ssha_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
ssha_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LDFLAGS)
endif
endif

if HAVE_LIBLDAP
bin_PROGRAMS += lct
lct_CFLAGS = $(AM_CFLAGS)
lct_LDFLAGS = $(AM_LDFLAGS)
lct_CFLAGS += $(PCFLAGS)
endif
