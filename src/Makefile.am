## Process this file with automake to produce Makefile.in
#

AM_CFLAGS = -W -Wall -Wshadow -Wcast-qual -Wwrite-strings -D_XOPEN_SOURCE=700
AM_CPPFLAGS = -I$(top_srcdir)/include/
AM_LDFLAGS = -L$(top_builddir)/lib
LIBS += -lailsaldap
LDADD =
bin_PROGRAMS = lcs lcg lck lcu lcr lcdb lcou lcsudo lcdhcp

if HAVE_LIBLDAP
AM_CPPFLAGS += $(LDAP_CFLAGS) -DLDAP_DEPRECATED
AM_LDFLAGS +=  $(LDAP_LDFLAGS)
LIBS += $(LDAP_LIBS)
bin_PROGRAMS += lds
endif

if HAVE_AILSA
AM_CFLAGS += $(AILSA_CFLAGS)
AM_LDFLAGS += $(AILSA_LDFLAGS)
LIBS += $(AILSA_LIBS)
endif

if HAVE_KERBEROS
AM_CFLAGS += $(K5CFLAGS)
LIBS += $(K5LIBS)
endif

if HAVE_LIBGCRYPT
AM_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
AM_LDFLAGS += $(LIBGCRYPT_LIBS)
endif
