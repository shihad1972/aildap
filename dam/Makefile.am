## Process this file with automake to produce Makefile.in
#

bin_PROGRAMS = 
sbin_PROGRAMS = 
# Add this to AM_CPPFLAGS if you want to have bind authentication
lct_CFLAGS =
PCFLAGS = -DLDAP_DEPRECATED

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_LDFLAGS =
AM_CPPFLAGS = -I../include/

if HAVE_LIBLDAP
lct_CFLAGS += $(PCFLAGS)
LIBS += -lldap
endif

if HAVE_OPENSSL
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)

if HAVE_GLIB
AM_CFLAGS += $(GLIB_CFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += -lglib-2.0
endif

endif

