## Process this file with automake to produce Makefile.in
#

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =

bin_PROGRAMS = lcs lcc lcg lck
shared_SOURCES = ldap-rep.c
noinst_HEADERS = base-sha.h ldap-col.h
lcs_SOURCES = lcs.c $(shared_SOURCES)
lcc_SOURCES = lcc.c $(shared_SOURCES)
lcg_SOURCES = lcg.c $(shared_SOURCES)
lck_SOURCES = lck.c $(shared_SOURCES)

if HAVE_LIBCRYPTO
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
if HAVE_GLIB
LIBS += -lglib-2.0
lcdb_SOURCES = lcdb.c $(shared_SOURCES) base-sha.c
lcdb_CFLAGS = $(AM_CFLAGS)
lcdb_LDFLAGS = $(AM_LDFLAGS)
lcr_SOURCES = lcr.c $(shared_SOURCES) base-sha.c
lcr_CFLAGS = $(AM_CFLAGS)
lcr_LDFLAGS = $(AM_LDFLAGS)
lcu_SOURCES = lcu.c $(shared_SOURCES) base-sha.c
lcu_CFLAGS = $(AM_CFLAGS)
lcu_LDFLAGS = $(AM_LDFLAGS)
lcdb_CFLAGS += $(GLIB_CFLAGS)
lcdb_LDFLAGS += $(GLIB_LDFLAGS)
lcr_CFLAGS += $(GLIB_CFLAGS)
lcr_LDFLAGS += $(GLIB_LDFLAGS)
lcu_CFLAGS += $(GLIB_CFLAGS)
lcu_LDFLAGS += $(GLIB_LDFLAGS)
bin_PROGRAMS += lcu lcr lcdb
endif
endif
