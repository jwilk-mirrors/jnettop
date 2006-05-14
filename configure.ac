#
# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/configure.ac,v 1.27 2006-05-14 23:55:40 merunka Exp $
#
# Process this file with autoconf to produce a configure script.
AC_INIT([jnettop], [0.14.0], [j@kubs.cz])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_NETTOP_GCC_FLAGS

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/sockio.h])

# with definitions
AC_ARG_WITH([ncurses],
	AC_HELP_STRING([--without-ncurses], [don't use ncurses, default is YES when available]),
	[ac_cv_use_ncurses=$withval], [ac_cv_use_ncurses=yes])

if test "$ac_cv_use_ncurses" = "yes"; then
	# Checks for libraries.
	AC_CHECK_LIB([ncurses], [wbkgdset],,)
	AC_CHECK_HEADERS([ncurses.h ncurses/ncurses.h])
	AC_DEFINE([WITH_NCURSES],[1],[NCURSES will be supported (if available)])
fi

AC_ARG_WITH([syslog],
	AC_HELP_STRING([--without-syslog], [don't use syslog, default is YES when available]),
	[ac_cv_use_syslog=$withval], [ac_cv_use_syslog=yes])
if test "$ac_cv_use_syslog" = "yes"; then
	AC_CHECK_HEADERS([syslog.h])
	AC_DEFINE([WITH_SYSLOG],[1],[syslog will be supported (if available)])
fi

AC_ARG_WITH([db4],
	AC_HELP_STRING([--without-db4], [don't use DB4 for DNS cache, default is USE when available]),
	[ac_cv_use_db4=$withval], [ac_cv_use_db4=yes])
if test "$ac_cv_use_db4" = "yes"; then
	AC_CHECK_HEADERS([db.h])
	AC_CHECK_LIB([db], [db_create],,)
	AC_DEFINE([WITH_DB4],[1],[DB4 will be used as DNS cache (if available)])
fi

AC_ARG_ENABLE([uia],
	AC_HELP_STRING([--enable-uia], [compile in UIA display support, default is NO]),
	[ac_cv_enable_uia=$enableval], [ac_cv_enable_uia=no])
if test "$ac_cv_enable_uia" = "yes"; then
	AC_DEFINE([ENABLE_UIA],[1],[UIA will be compiled in])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM

AC_NETTOP_GETHOSTBY_LIB_CHECK
AC_NETTOP_SOCKET_LIB_CHECK
AC_NETTOP_PCAP_CHECK
AC_NETTOP_CHECK_PCAP_FREECODE
AC_NETTOP_CHECK_IN6_ADDR

LDFLAGS="$LDFLAGS $NSL_LIBS $SOCKET_LIBS"

AC_NETTOP_CHECK_WORKING_RESOLVER
AC_NETTOP_CHECK_GETHOSTBYADDR_R

AM_PATH_GLIB_2_0(2.0.1,, AC_MSG_ERROR("glib >= 2.0.1 library required"), gthread)

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([localtime_r memmove memset pcap_findalldevs pcap_setnonblock inet_ntop inet_ntoa inet_pton inet_aton syslog])

AM_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
