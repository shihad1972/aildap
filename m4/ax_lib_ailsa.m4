#
# M4 Macro to run tests for configure to find libailsa
# library
#
# (C) 2023 Iain M. Conochie <iain-AT-ailsatech-DOT-net>
#

AC_DEFUN([AX_LIB_AILSA], [dnl
AC_ARG_WITH([libailsa],
[  --with-libailsa[[=prefix]] compile using libailsa])
if test ".$with_libailsa" = "."; then
        AC_CHECK_LIB([ailsa], [ailsa_list_init])
        if test "$ac_cv_lib_ailsa_ailsa_list_init" = "yes"; then
                AILSA_LIBS="-lailsa"
                AC_MSG_CHECKING([libailsa])
                AC_MSG_RESULT([$AILSA_LIBS])
                m4_ifval($1,$1)
                AC_CHECK_HEADER([ailsa.h], 
                                [AC_MSG_NOTICE([found ailsa.h])],
                                [AC_MSG_ERROR([Cannot find ailsa.h. Do you have the -dev package installed?])])
                HAVE_AILSA="true"
        else
                AC_MSG_RESULT([no])
                AC_MSG_WARN([libailsa not found])
        fi
else
        OLDLDFLAGS="$LDFLAGS"; LDFLAGS="$LDFLAGS -L$with_libailsa/lib"
        OLDCPPFLAGS="$CPPFLAGS"; CPPFLAGS="$CPPFLAGS -I$with_libailsa/include"
        AC_CHECK_LIB([alisa], [ailsa_list_init])
        if test "$ac_cv_lib_ailsa_ailsa_list_init" = "yes"; then
                AILSA_LIBS="-L$with_libailsa/lib -lailsa"
                HAVE_AILSA="true"
                test -f "$with_libailsa/include/ailsa.h" && AILSA_CFLAGS="-I$with_libailsa/include"
                AC_MSG_CHECKING([libailsa])
                AC_MSG_RESULT([$AILSA_LIBS])
                m4_ifval($1,$1)
        else
                AC_MSG_RESULT([no])
                AC_MSG_WARN([libailsa not found])
        fi
fi
AC_SUBST([AILSA_LIBS])
AC_SUBST([AILSA_LDFLAGS])
])
