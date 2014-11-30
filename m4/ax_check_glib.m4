#
# M4 macro to check for glib
#
# This depends on pkg-config
#


AU_ALIASS([CHECK_GLIB], [AX_CHECK_GLIB])
AC_DEFUN([AX_CHECK_GLIB], [
    found=false
    AC_ARG_WITH([glib],
        [AS_HELP_STRING([--with-glib=DIR],
            [root directory of glib installation])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-glib value])
             ;;
            *) glibdirs="$withval"
             ;;
            esac
        ], [
            AC_PATH_PROG([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                GLIB_LDFLAGS=`$PKG_CONFIG --libs-only-L glib-2.0 2>/dev/null`
                if test $? = 0; then
                    GLIB_LIBS=`$PKG_CONFIG --libs-only-l glib-2.0 2>/dev/null`
                    GLIB_INCLUDES=`$PKG_CONFIG --cflags glib-2.0 2>/dev/null`
                    found=true
                    HAVE_GLIB="true"
                fi
            fi

        ]
        )

    AC_MSG_CHECKING([whether compiling and linking against glib works])
    old_LIBS="$LIBS"
    old_LDFLAGS="$LDFLAGS"
    old_CPPFLAGS="CPPFLAGS"
    LDFLAGS="$LDFLAGS $GLIB_LDFLAGS"
    LIBS="$LIBS $GLIB_LIBS"
    CPPFLAGS="$CPPFLAGS $GLIB_CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <glib.h>], [g_base64_encode("filter", 6)])],
            [
                AC_MSG_RESULT([yes])
                HAVE_GLIB="true"
                $1
            ], [
                AC_MSG_RESULT([no])
                HAVE_GLIB="false"
                $2
            ])
    CPPFLAGS="$old_CPPFLAGS"
    LDFLAGS="$old_LDFLAGS"
    LIBS="$old_LIBS"

    AC_SUBST([GLIB_LDFLAGS])
    AC_SUBST([GLIB_LIBS])
    AC_SUBST([GLIB_CPPFLAGS])
])

