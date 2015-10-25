AM_CPPFLAGS = -I$(top_srcdir)/include/ $(GLIB_CFLAGS)
AM_LDFLAGS = -lldap -lcrypto $(GLIB_LDFLAGS)
lib_LTLIBRARIES = libailsaldap.la
libailsaldap_la_SOURCES = common.c password.c
include_HEADERS = ../include/ailsaldap.h
