#
# M4 macro to run test for configure to find and test for libldap
# headers and libraries.
#
# (C) Iain M Conochie 2014
#
#

AC_DEFUN([AX_LIB_LDAP],[dnl
AC_ARG_WITH([libldap],
[  --with-libldap[[=prefix]] compile using libldap])
if test ".$with_libldap" = ".no"; then
	AC_MSG_RESULT([disabled])
	m4_ifval($2,$2)
else
	AC_CHECK_LIB([ldap], [ldap_initialize])
	if test "$ac_cv_lib_ldap_ldap_initialize" = "yes" ; then
		LDAP_LIBS="-lldap"
		HAVE_LIBLDAP="true"
		AC_MSG_CHECKING([libldap])
		AC_MSG_RESULT([$LDAP_LIBS])
		m4_ifval($1,$1)
	else
		AC_MSG_CHECKING([libldap])
		AC_MSG_RESULT([..setting LDAP_LIBS -L$with_libldap/lib -lldap])
		OLDLDFLAGS="$LDFLAGS" ; LDFLAGS="$LDFLAGS -L$with_libldap/lib"
		OLDCPPFLAGS="$CPPFLAGS" ; CPPFLAGS="$CPPFLAGS -I$with_libldap/include"
		AC_CHECK_LIB([ldap], [ldap_initialize])
		CPPFLAGS="$OLDCPPFLAGS"
		LDFLAGS="$OLDLDFLAGS"
		if test "$ac_cv_lib_ldap_ldap_initialize" = "yes" ; then
			LDAP_LIBS="-L$with_libldap/lib -lldap"
			HAVE_LIBLDAP="true"
			test -d "$with_libldap/include" && LDAP_CFLAGS="-I$with_libldap/include"
			AC_MSG_CHECKING([libldap])
			AC_MSG_RESULT([$LDAP_LIBS])
			m4_ifval($1,$1)
		else
			AC_MSG_CHECKING([lib ldap])
			AC_MSG_RESULT([no, (WARNING)])
			m4_ifval($2,$2)
			HAVE_LIBLDAP="false"
		fi
	fi
fi
AC_SUBST([LDAP_CFLAGS])
AC_SUBST([LDAP_LDFLAGS])
])

