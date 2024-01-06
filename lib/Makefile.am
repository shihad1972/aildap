AM_CPPFLAGS = -I$(top_srcdir)/include/
AM_LDFLAGS = 

lib_LTLIBRARIES = libailsaldap.la
libailsaldap_la_SOURCES = common.c password.c ldif.c config.c
include_HEADERS = $(top_srcdir)/include/ailsaldap.h

if HAVE_LIBLDAP
AM_CPPFLAGS += $(LDAP_CFLAGS)
AM_LDFLAGS +=  $(LDAP_LDFLAGS)
LIBS += $(LDAP_LIBS)
endif

if HAVE_OPENSSL 
AM_CPPFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
endif

if HAVE_GLIB 
AM_CPPFLAGS += $(GLIB_CFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += $(GLIB_LIBS)
endif

if HAVE_LIBGCRYPT
AM_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
AM_LDFLAGS += $(LIBGCRYPT_LIBS)
endif
