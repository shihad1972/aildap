#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Ldap Collection], [1.0], [iain@thargoid.co.uk])
AC_CONFIG_SRCDIR([src/lcc.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([crypto], [EVP_MD_CTX_create])
AC_CHECK_LIB([ldap], [ldap_initialize])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass memset strchr strndup strstr strtoul])

PKG_CHECK_MODULES([GLIB], [glib-2.0])
AM_CONDITIONAL([HAVE_GLIBS], [$HAVE_GLIBS])
AM_CONDITIONAL([HAVE_LIBLDAP], [$HAVE_LIBLDAP])
AM_CONDITIONAL([HAVE_LIBCRYPTO], [$HAVE_LIBCRYPTO])
AC_CONFIG_FILES([Makefile
                 man/Makefile
                 old/Makefile
                 src/Makefile])
AC_OUTPUT