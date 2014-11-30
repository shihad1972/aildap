## Process this file with automake to produce Makefile.in
#

bin_PROGRAMS = 
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =
AM_CPPFLAGS =

shared_SOURCES = ldap-rep.c
sha_SOURCES = sha.c
sha1_SOURCES = sha1.c
tsha_SOURCES = sha1.c base-sha.c $(shared_SOURCES)
gsha_SOURCES = glib-sha1.c base-sha.c $(shared_SOURCES)
lcd_SOURCES = domains.c
gsha2_SOURCES = glib-sha1-2.c base-sha.c $(shared_SOURCES)
ssha_SOURCES = ssha1.c
lct_SOURCES = test-ldap-connection.c
lct_CFLAGS =
noinst_HEADERS = base-sha.h ldap-col.h

if HAVE_GLIB
bin_PROGRAMS += tsha gsha lcd gsha2 ssha
AM_CPPFLAGS += $(GLIB_CPPFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += -lglib-2.0
endif

if HAVE_LIBLDAP
bin_PROGRAMS += lct
lct_CFLAGS += $(PCFLAGS)
LIBS += -lldap
endif

if HAVE_LIBCRYPTO
bin_PROGRAMS += sha1 sha
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
endif

