AM_CPPFLAGS = -I$(top_srcdir)/include/ $(LDAP_CFLAGS) $(OPENSSL_INCLUDES) $(GLIB_CFLAGS)
AM_LDFLAGS = $(LDAP_LDFLAGS) $(OPENSSL_LDFLAGS) $(GLIB_LDFLAGS)
LIBS = $(OPENSSL_LIBS)
lib_LTLIBRARIES = libailsaldap.la
libailsaldap_la_SOURCES = common.c password.c
include_HEADERS = ../include/ailsaldap.h
