## Process this file with automake to produce Makefile.in
#

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =
AM_CPPFLAGS =

bin_PROGRAMS = lcs lcc lcg lck lcu lcr lcdb
shared_SOURCES = ldap-rep.c
noinst_HEADERS = base-sha.h ldap-col.h
lcs_SOURCES = lcs.c $(shared_SOURCES)
lcc_SOURCES = lcc.c $(shared_SOURCES)
lcg_SOURCES = lcg.c $(shared_SOURCES)
lck_SOURCES = lck.c $(shared_SOURCES)
lcdb_SOURCES = lcdb.c $(shared_SOURCES) base-sha.c
lcr_SOURCES = lcr.c $(shared_SOURCES) base-sha.c
lcu_SOURCES = lcu.c $(shared_SOURCES) base-sha.c

if HAVE_GLIB
AM_CPPFLAGS += $(GLIB_CPPFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += -lglib-2.0
endif

if HAVE_OPENSSL

AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
endif
