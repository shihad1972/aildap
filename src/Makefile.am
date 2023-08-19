## Process this file with automake to produce Makefile.in
#

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_CPPFLAGS = -I$(top_srcdir)/include/
AM_LDFLAGS = -L$(top_builddir)/lib
LIBS += -lailsaldap
bin_PROGRAMS = lcs lcc lcg lck lcu lcr lcdb lcou lcsudo lcdhcp lds

if HAVE_LIBLDAP
AM_CPPFLAGS += $(LDAP_CFLAGS) -DLDAP_DEPRECATED
AM_LDFLAGS +=  $(LDAP_LDFLAGS)
LIBS += $(LDAP_LIBS)
endif

if HAVE_GLIB
AM_CFLAGS += $(GLIB_CFLAGS)
AM_LDFLAGS += $(GLIB_LDFLAGS)
LIBS += $(GLIB_LIBS)
endif

if HAVE_OPENSSL
AM_CFLAGS += $(OPENSSL_INCLUDES)
AM_LDFLAGS += $(OPENSSL_LDFLAGS)
LIBS += $(OPENSSL_LIBS)
endif

if HAVE_GLIB
        if HAVE_OPENSSL
                bin_PROGRAMS += hh
        endif
endif
