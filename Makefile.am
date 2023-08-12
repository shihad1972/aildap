#
#
# Makefile.am for ldap-utils c programs
#
#
RM = rm -f
ECHO = echo
DIR = src
SUBDIRS = lib src man
if HAVE_OLD
SUBDIRS += old
endif
if HAVE_DAM
SUBDIRS += dam
endif
EXTRA_DIST = lib src man old dam tests
ACLOCAL_AMFLAGS = -I m4
SUBDIRS += tests
