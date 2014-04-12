AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =

bin_PROGRAMS = lcs lcc lcg
shared_SOURCES = ldap-rep.c
lcs_SOURCES = ssl-config.c
lcc_SOURCES = containers.c $(shared_SOURCES)
lcg_SOURCES = lcg.c $(shared_SOURCES)
lcdb_SOURCES = lcdb.c $(shared_SOURCES) base-sha.c
lcdb_CFLAGS = $(AM_CFLAGS)
lcdb_LDFLAGS = $(AM_LDFLAGS)
lcdb_LIBS =
lcr_SOURCES = ldap-replication.c $(shared_SOURCES) base-sha.c
lcr_CFLAGS = $(AM_CFLAGS)
lcr_LDFLAGS = $(AM_LDFLAGS)
lcr_LIBS =
lcu_SOURCES = user.c $(shared_SOURCES) base-sha.c
lcu_CFLAGS = $(AM_CFLAGS)
lcu_LDFLAGS = $(AM_LDFLAGS)
lcu_LIBS =

if HAVE_LIBCRYPTO
if HAVE_GLIBS
lcdb_CFLAGS += $(GLIB_CFLAGS)
lcdb_LDFLAGS += $(GLIB_LDFLAGS)
lcdb_LIBS += -lglib-2.0 -lcrypto
lcr_CFLAGS += $(GLIB_CFLAGS)
lcr_LDFLAGS += $(GLIB_LDFLAGS)
lcr_LIBS += -lglib-2.0 -lcrypto
lcu_CFLAGS += $(GLIB_CFLAGS)
lcu_LDFLAGS += $(GLIB_LDFLAGS)
lcu_LIBS += -lglib-2.0 -lcrypto
bin_PROGRAMS += lcu lcr lcdb
endif
endif