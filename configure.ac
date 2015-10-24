#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ldap-collection], [1.0], [iain@thargoid.co.uk])
AC_CONFIG_SRCDIR([src/lcc.c])
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
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass memset strchr strndup strstr strtoul])

AX_LIB_LDAP
AX_CHECK_OPENSSL([AC_DEFINE([HAVE_OPENSSL], [1], [Have openssl])])

PKG_CHECK_MODULES([GLIB], [glib-2.0],
  [AC_DEFINE([HAVE_GLIB], [1], [glib-2.0 found])
])

AX_CHECK_OLD
AX_CHECK_DAM

AM_CONDITIONAL([HAVE_GLIB], [$HAVE_GLIB])
AM_CONDITIONAL([HAVE_LIBLDAP], [$HAVE_LIBLDAP])
AM_CONDITIONAL([HAVE_OPENSSL], [$HAVE_OPENSSL])
AM_CONDITIONAL([HAVE_OLD], [test "$enable_old" = yes])
AM_CONDITIONAL([HAVE_DAM], [test "$enable_dam" = yes])
AC_CONFIG_FILES([Makefile
                 man/Makefile
                 old/Makefile
		 dam/Makefile
		 lib/Makefile
                 src/Makefile])
AC_OUTPUT
