bin_PROGRAMS = 
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =

shared_SOURCES = ldap-rep.c
lct_SOURCES = test-ldap-connection.c
lct_CFLAGS = $(AM_CFLAGS)
lct_LDFLAGS = $(AM_LDFLAGS)
lct_LIBS =
ssha_SOURCES = ssha1.c
ssha_CFLAGS = $(AM_CFLAGS)
ssha_LDFLAGS = $(AM_LDFLAGS)
ssha_LIBS =
lcd_SOURCES = domains.c
lcd_CFLAGS = $(AM_CFLAGS)
lcd_LDFLAGS = $(AM_LDFLAGS)
lcd_LIBS =
sha_SOURCES = sha.c
sha_LIBS =
tsha_SOURCES = sha1.c base-sha.c $(shared_SOURCES)
tsha_CFLAGS = $(AM_CFLAGS)
tsha_LDFLAGS = $(AM_LDFLAGS)
tsha_LIBS =
sha1_SOURCES = sha1.c
sha1_LIBS =
gsha_SOURCES = glib-sha1.c base-sha.c $(shared_SOURCES)
gsha_CFLAGS = $(AM_CFLAGS)
gsha_LDFLAGS = $(AM_LDFLAGS)
gsha_LIBS =
gsha2_SOURCES = glib-sha1-2.c base-sha.c $(shared_SOURCES)
gsha2_CFLAGS = $(AM_CFLAGS)
gsha2_LDFLAGS = $(AM_LDFLAGS)
gsha2_LIBS =

if HAVE_LIBCRYPTO
sha_LIBS += -lcrypto
sha1_LIBS += -lcrypto
bin_PROGRAMS += sha1 sha
if HAVE_GLIBS
tsha_CFLAGS += $(GLIB_CFLAGS)
tsha_LDFLAGS += $(GLIB_LDFLAGS)
tsha_LIBS += -lcrypto -lglib-2.0
gsha_CFLAGS += $(GLIB_CFLAGS)
gsha_LDFLAGS += $(GLIB_LDFLAGS)
gsha_LIBS += -lcrypto -lglib-2.0
lcd_CFLAGS += $(GLIB_CFLAGS)
lcd_LDFLAGS += $(GLIB_LDFLAGS)
lcd_LIBS += -lcrypto -lglib-2.0
gsha2_CFLAGS += $(GLIB_CFLAGS)
gsha2_LDFLAGS += $(GLIB_LDFLAGS)
gsha2_LIBS += -lcrypto -lglib-2.0
ssha_CFLAGS += $(GLIB_CFLAGS)
ssha_LDFLAGS += $(GLIB_LDFLAGS)
ssha_LIBS += -lcrypto -lglib-2.0
bin_PROGRAMS += tsha gsha lcd gsha2 ssha
endif
endif

if HAVE_LIBLDAP
lct_CFLAGS += $(PCFLAGS)
lct_LIBS += -lldap
bin_PROGRAMS += lct
endif