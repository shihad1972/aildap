#=============================================================================
#
# Check to see if programs in old directory should be compiled.
#
#=============================================================================

AC_DEFUN([AX_CHECK_OLD],[dnl
  AC_MSG_CHECKING([to enable old programs])
  AC_ARG_ENABLE([old],
    [  --enable-old            compile old programs],,
          enable_old="no")
  if test ".$enable_old" = ".yes" ; then
    AC_DEFINE([HAVE_OLD], [1], [Compile old programs])
    AC_MSG_RESULT([yes])
    m4_ifval($1,$1)
  else
    AC_MSG_RESULT([disabled])
    m4_ifval($2,$2)
  fi
])

#=============================================================================
#
# End of test
#
#=============================================================================
