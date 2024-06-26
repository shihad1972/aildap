dnl Copyright (C) 2005 by the Massachusetts Institute of Technology.
dnl All rights reserved.
dnl
dnl Export of this software from the United States of America may
dnl   require a specific license from the United States Government.
dnl   It is the responsibility of any person or organization contemplating
dnl   export to obtain such a license before exporting.
dnl 
dnl WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
dnl distribute this software and its documentation for any purpose and
dnl without fee is hereby granted, provided that the above copyright
dnl notice appear in all copies and that both that copyright notice and
dnl this permission notice appear in supporting documentation, and that
dnl the name of M.I.T. not be used in advertising or publicity pertaining
dnl to distribution of the software without specific, written prior
dnl permission.  Furthermore if you modify this software you must label
dnl your software as modified software and not distribute it in such a
dnl fashion that it might be confused with the original M.I.T. software.
dnl M.I.T. makes no representations about the suitability of
dnl this software for any purpose.  It is provided "as is" without express
dnl or implied warranty.

dnl
dnl Updates by Iain M. Conochie December 2023
dnl  * Change macro name
dnl  * Updated initial search path
dnl

dnl AX_CHECK_KRB5
dnl
dnl Check for krb5-config; update CPPFLAGS and LDFLAGS accordingly.
dnl
AC_DEFUN([AX_CHECK_KRB5],
[AC_ARG_WITH([kerberos5],
[  --with-kerberos5=[[=prefix]]   Enable Kerberos 5 support])
if test "x$with_kerberos5" = "xno"; then
	AC_MSG_ERROR([kerberos5 is required for this program])
else
	if test "x$with_kerberos" = "x"; then
		KRB5ROOT=/usr
	else
		KRB5ROOT=${withval}
	fi
	AC_MSG_CHECKING([for krb5-config])
	if test -x "$KRB5ROOT/bin/krb5-config"; then
		KRB5CONF=$KRB5ROOT/bin/krb5-config
		AC_MSG_RESULT([$KRB5CONF])
		AC_MSG_CHECKING([for gssapi support in krb5-config])
		if "$KRB5CONF" | grep gssapi > /dev/null; then
			AC_MSG_RESULT([yes])
			k5confopts=gssapi
		else
			AC_MSG_ERROR([gssapi library is required for this program])
		fi
		K5CFLAGS=`"$KRB5CONF" --cflags $k5confopts`
		K5LIBS=`"$KRB5CONF" --libs $k5confopts`
		HAVE_KERBEROS="true"
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([--with-kerberos5 specified but krb5-config not found])
	fi
fi
AC_SUBST([K5CFLAGS])
AC_SUBST([K5LIBS])
])
