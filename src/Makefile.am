## Process this file with automake to produce Makefile.in
#

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =
AM_CPPFLAGS = -I../include/

bin_PROGRAMS = lcs lcc lcg lck lcu lcr lcdb lcou lcsudo
shared_SOURCES = ldap-rep.c base-sha.h ldap-col.h
lcs_SOURCES = lcs.c $(shared_SOURCES)
lcc_SOURCES = lcc.c $(shared_SOURCES)
lcg_SOURCES = lcg.c $(shared_SOURCES)
lck_SOURCES = lck.c $(shared_SOURCES)
lcou_SOURCES = lcou.c $(shared_SOURCES)
lcsudo_SOURCES = lcsudo.c $(shared_SOURCES)
lcdb_SOURCES = lcdb.c $(shared_SOURCES) base-sha.c
lcr_SOURCES = lcr.c $(shared_SOURCES) base-sha.c
lcu_SOURCES = lcu.c $(shared_SOURCES) base-sha.c

if HAVE_GLIB
AM_CFLAGS += $(GLIB_CFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += -lglib-2.0
endif

if HAVE_OPENSSL

AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
endif
