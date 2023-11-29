if HAVE_CHECK
TESTS = check_get_ldif_format
check_PROGRAMS = check_get_ldif_format
AM_CFLAGS = @CHECK_CFLAGS@
AM_LDFLAGS = $(top_builddir)/lib/libailsaldap.la @CHECK_LIBS@

check_get_ldif_format_SOURCES = check_get_ldif_format.c $(top_builddir)/include/ailsaldap.h
endif
