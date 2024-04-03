AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_CPPFLAGS = -I$(top_srcdir)/include/
AM_LDFLAGS =
LIBS =

lib_LTLIBRARIES = libailsaldap.la
libailsaldap_la_SOURCES = common.c password.c ldif.c config.c
include_HEADERS = $(top_srcdir)/include/ailsaldap.h

if HAVE_LIBLDAP
AM_CPPFLAGS += $(LDAP_CFLAGS)
AM_LDFLAGS +=  $(LDAP_LDFLAGS)
LIBS += $(LDAP_LIBS)
endif

if HAVE_AILSA
AM_CFLAGS += $(AILSA_CFLAGS)
AM_LDFLAGS += $(AILSA_LDFLAGS)
LIBS += $(AILSA_LIBS)
endif

if HAVE_KERBEROS
AM_CFLAGS += $(K5CFLAGS)
LIBS += $(K5LIBS)
endif

if HAVE_LIBGCRYPT
AM_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
AM_LDFLAGS += $(LIBGCRYPT_LIBS)
libailsaldap_la_SOURCES += gcrypt_hash.c
endif
