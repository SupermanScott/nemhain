AC_INIT([nemhain], [1.0], [scott@scottreynolds.us])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC_C99
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([m], [fabs])
AC_CHECK_LIB([ev], [ev_version_major])
AC_CHECK_LIB([zmq], [zmq_init])
AC_CHECK_LIB([czmq], [zclock_sleep])
AC_OUTPUT
