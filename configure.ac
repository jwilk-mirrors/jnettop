#
# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/configure.ac,v 1.12 2002-10-13 20:20:54 merunka Exp $
#
# Process this file with autoconf to produce a configure script.
AC_INIT([jnettop], [0.6b], [j@kubs.cz])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_NETTOP_GCC_FLAGS

# Checks for libraries.
AC_CHECK_LIB([ncurses], [wbkgdset],, AC_MSG_ERROR("ncurses library is required"))
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM

AC_NETTOP_GETHOSTBY_LIB_CHECK
AC_NETTOP_SOCKET_LIB_CHECK
AC_NETTOP_PCAP_CHECK

LDFLAGS="$LDFLAGS $NSL_LIBS $SOCKET_LIBS"

AC_NETTOP_CHECK_WORKING_RESOLVER
AC_NETTOP_CHECK_GETHOSTBYADDR_R

AM_PATH_GLIB_2_0(2.0.1,, AC_MSG_ERROR("glib >= 2.0.1 library required"), gthread)

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([localtime_r memmove memset pcap_findalldevs pcap_setnonblock inet_ntop inet_ntoa])

AM_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
