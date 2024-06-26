#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([aildap], [0.5.3], [iain@ailsatech.net])
AC_CONFIG_SRCDIR([src/lcou.c])
AC_CONFIG_HEADERS([include/config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_MAKE_SET
AM_PROG_AR

# Initialize libtool
LT_INIT

# Add m4 macros
AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h netinet/in.h stdlib.h string.h termios.h unistd.h getopt.h error.h errno.h regex.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostname getpass memset strchr strerror strndup strrchr strstr strtoul])

AX_LIB_LDAP
AX_LIB_AILSA
AX_CHECK_KRB5
AM_PATH_LIBGCRYPT([1.8.0], [AC_DEFINE([HAVE_LIBGCRYPT], [1], [libgcrypt found])])

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [HAVE_CHECK="true"], [HAVE_CHECK="false"])

#AX_CHECK_OLD
#AX_CHECK_DAM

AM_CONDITIONAL([HAVE_LIBLDAP], [test x"$HAVE_LIBLDAP" = xtrue])
#AM_CONDITIONAL([HAVE_OLD], [test x"$enable_old" = xyes])
#AM_CONDITIONAL([HAVE_DAM], [test x"$enable_dam" = xyes])
AM_CONDITIONAL([HAVE_CHECK], [test x"$HAVE_CHECK" = xtrue])
AM_CONDITIONAL([HAVE_LIBGCRYPT], [$HAVE_LIBGCRYPT])
AM_CONDITIONAL([HAVE_AILSA], [test x"$HAVE_AILSA" = "xtrue"])
AM_CONDITIONAL([HAVE_KERBEROS], [test x"$HAVE_KERBEROS" = "xtrue"])
AC_CONFIG_FILES([Makefile
                 man/Makefile
		 lib/Makefile
                 tests/Makefile
                 src/Makefile])
AC_OUTPUT
