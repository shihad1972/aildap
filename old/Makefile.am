## Process this file with automake to produce Makefile.in
#

bin_PROGRAMS = 
# Add this to AM_CPPFLAGS if you want to have bind authentication
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =
AM_CPPFLAGS = -I../include/

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

if HAVE_LIBLDAP
bin_PROGRAMS += lct
lct_CFLAGS += $(PCFLAGS)
LIBS += -lldap
endif

if HAVE_OPENSSL
bin_PROGRAMS += sha1 tsha sha
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)

if HAVE_GLIB
bin_PROGRAMS += gsha lcd gsha2 ssha
AM_CFLAGS += $(GLIB_CFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += -lglib-2.0
endif

endif

