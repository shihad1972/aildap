TESTS = check_get_ldif_domain check_get_ldif_format
check_PROGRAMS = check_get_ldif_domain check_get_ldif_format
AM_CFLAGS = @CHECK_CFLAGS@
AM_LDADD = $(top_builddir)/lib/libailsaldap.la @CHECK_LIBS@

check_get_ldif_domain_SOURCES = check_get_ldif_domain.c $(top_builddir)/include/ailsaldap.h
check_get_ldif_format_SOURCES = check_get_ldif_format.c $(top_builddir)/include/ailsaldap.h
