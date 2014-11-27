#
# M4 macro to run test for configure to find and test for libldap
# headers and libraries.
#
# (C) Iain M Conochie 2014
#
#

AC_DEFUN([AX_LIB_LDAP],
[
	AC_ARG_WITH([libldap],
		AS_HELP_STRING(
			[--with-libldap=@<:@ARG@:>@],
			[use ldap library @<:@default=yes@:>@, optionally specify prefix for path]
		),
		[
		if test "$withval" = "no"; then
			WANT_LDAP="no"
		elif test "$withval" = "yes"; then
			WANT_LDAP="yes"
			ac_libldap_path=""
		else
			WANT_LDAP="yes"
			ac_libldap_path="$withval"
		fi
		],
		[WANT_LDAP="yes"]
	)

	LDAP_CFLAGS=""
	LDAP_LDFLAGS=""

	if test "x$WANT_LDAP" = "xyes"; then
		ac_ldap_header="ldap.h"

		AC_MSG_CHECKING([for libldap library])

		if test "$ac_ldap_path" != ""; then
			ac_ldap_ldflags="-L$ac_ldap_path/lib"
			ac_ldap_cppflags="-I$ac_ldap_path/include"
		else
			for ac_ldap_path_tmp in /usr /usr/local /opt; do
				if test -f "$ac_ldap_path_tmp/include/$ac_ldap_header" \
					&& test -r "$ac_ldap_path_tmp/include/$ac_ldap_header"; then
					ac_ldap_path=$ac_ldap_path_tmp
					ac_ldap_cppflags="-I$ac_ldap_path_tmp/include"
					ac_ldap_ldflags="-I$ac_ldap_path_tmp/lib"
					break;
				fi
			done
		fi
		ac_ldap_ldflags="$ac_ldap_ldflags -lldap"

		if test "$success" = "yes"; then

			LDAP_CFLAGS="$ac_ldap_cppflags"
			LDAP_LDFLAGS="$ac_ldap_ldflags"

			AC_SUBST(LDAP_CFLAGS])
			AC_SUBST(LDAP_LDFLAGS])
			AC_DEFINE([HAVE_LDAP], [], [Have ldap library])
		fi
	fi
])

