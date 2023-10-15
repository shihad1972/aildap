TESTS = check_get_ldif_format check_kv
check_PROGRAMS = check_get_ldif_format check_kv
AM_CFLAGS = @CHECK_CFLAGS@
AM_LDFLAGS = $(top_builddir)/lib/libailsaldap.la @CHECK_LIBS@

check_get_ldif_format_SOURCES = check_get_ldif_format.c $(top_builddir)/include/ailsaldap.h
check_kv_SOURCES = check_kv.c $(top_builddir)/include/ailsaldap.h

