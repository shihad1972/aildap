#=============================================================================
#
# Check to see if programs in dam directory should be compiled.
#
#=============================================================================

AC_DEFUN([AX_CHECK_DAM],[dnl
  AC_MSG_CHECKING([to enable dam programs])
  AC_ARG_ENABLE([dam],
    [  --enable-dam            compile dam programs],,
          enable_dam="no")
  if test ".$enable_dam" = ".yes" ; then
    AC_DEFINE([HAVE_DAM], [1], [Compile dam programs])
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
