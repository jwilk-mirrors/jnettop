
# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/acinclude.m4,v 1.7 2004-10-01 20:26:03 merunka Exp $

AH_TEMPLATE([HAVE_GETHOSTBYADDR_R_5], [Set to 1 if gethostbyaddr_r takes 5 arguments])
AH_TEMPLATE([HAVE_GETHOSTBYADDR_R_7], [Set to 1 if gethostbyaddr_r takes 7 arguments])
AH_TEMPLATE([HAVE_GETHOSTBYADDR_R_8], [Set to 1 if gethostbyaddr_r takes 8 arguments])
AH_TEMPLATE([HAVE_PCAP_FREECODE_2], [Set to 1 if pcap_freecode takes 2 arguments])
AH_TEMPLATE([HAVE_PCAP_FREECODE_1], [Set to 1 if pcap_freecode takes 1 argument])
AH_TEMPLATE([HAVE_IP6_S6_ADDR32], [Set to 1 if struct in6_addr contains s6_addr32 member])
AH_TEMPLATE([HAVE_IP6__S6_UN__S6_U32], [Set to 1 if struct in6_addr contains _S6_un._S6_u32 member])
AH_TEMPLATE([HAVE_IP6___U6_ADDR___U6_ADDR32], [Set to 1 if struct in6_addr contains __u6_addr.__u6_addr32 member])
AH_TEMPLATE([NEED_REENTRANT], [Set to 1 if gethostbyaddr_r requires _REENTRANT symbol to be defined])

AC_DEFUN(AC_NETTOP_GCC_FLAGS,
[
if test "$GCC" = "yes"; then
  CFLAGS="$CFLAGS -Wall"
fi
])


#
# AC_NETTOP_GETHOSTBY_LIB_CHECK
#
# Checks whether we need "-lnsl" to get "gethostby*()", which we use
# in "resolv.c".
#
# Copied from EtherReal package ;
# Done by Jakub Skopal <j@kubs.cz> on 2002-08-22.
#
# Adapted from stuff in the AC_PATH_XTRA macro in "acspecific.m4" in
# GNU Autoconf 2.13; the comment came from there.
# Done by Guy Harris <guy@alum.mit.edu> on 2000-01-14. 
#
AC_DEFUN(AC_NETTOP_GETHOSTBY_LIB_CHECK,
[
    # msh@cis.ufl.edu says -lnsl (and -lsocket) are needed for his 386/AT,
    # to get the SysV transport functions.
    # chad@anasazi.com says the Pyramid MIS-ES running DC/OSx (SVR4)
    # needs -lnsl.
    # The nsl library prevents programs from opening the X display
    # on Irix 5.2, according to dickey@clark.net.
    AC_CHECK_FUNC(gethostbyname, ,
	AC_CHECK_LIB(nsl, gethostbyname, NSL_LIBS="-lnsl"))
    AC_SUBST(NSL_LIBS)
])


#
# AC_NETTOP_SOCKET_LIB_CHECK
#
# Checks whether we need "-lsocket" to get "socket()", which is used
# by libpcap on some platforms - and, in effect, "gethostby*()" on
# most if not all platforms (so that it can use NIS or DNS or...
# to look up host names).
#
# Copied from EtherReal package ;
# Done by Jakub Skopal <j@kubs.cz> on 2002-08-22.
#
# Adapted from stuff in the AC_PATH_XTRA macro in "acspecific.m4" in
# GNU Autoconf 2.13; the comment came from there.
# Done by Guy Harris <guy@alum.mit.edu> on 2000-01-14. 
#
# We use "connect" because that's what AC_PATH_XTRA did.
#
AC_DEFUN(AC_NETTOP_SOCKET_LIB_CHECK,
[
    # lieder@skyler.mavd.honeywell.com says without -lsocket,
    # socket/setsockopt and other routines are undefined under SCO ODT
    # 2.0.  But -lsocket is broken on IRIX 5.2 (and is not necessary
    # on later versions), says simon@lia.di.epfl.ch: it contains
    # gethostby* variants that don't use the nameserver (or something).
    # -lsocket must be given before -lnsl if both are needed.
    # We assume that if connect needs -lnsl, so does gethostbyname.
    AC_CHECK_FUNC(connect, ,
      AC_CHECK_LIB(socket, connect, SOCKET_LIBS="-lsocket",
		AC_MSG_ERROR(Function 'socket' not found.), $NSL_LIBS))
    AC_SUBST(SOCKET_LIBS)
])

#
# AC_NETTOP_PCAP_CHECK
#
AC_DEFUN(AC_NETTOP_PCAP_CHECK,
[
	if test -z "$pcap_dir"
	then
	  #
	  # The user didn't specify a directory in which libpcap resides;
	  # we assume that the current library search path will work,
	  # but we may have to look for the header in a "pcap"
	  # subdirectory of "/usr/include" or "/usr/local/include",
	  # as some systems apparently put "pcap.h" in a "pcap"
	  # subdirectory, and we also check "$prefix/include".
	  #
	  # XXX - should we just add "$prefix/include" to the include
	  # search path and "$prefix/lib" to the library search path?
	  #
	  AC_MSG_CHECKING(for extraneous pcap header directories)
	  found_pcap_dir=""
	  for pcap_dir in /usr/include/pcap /usr/local/include/pcap $prefix/include
	  do
	    if test -d $pcap_dir ; then
		if test x$pcap_dir != x/usr/include; then
		    CFLAGS="$CFLAGS -I$pcap_dir"
		    CPPFLAGS="$CPPFLAGS -I$pcap_dir"
		fi
		found_pcap_dir=" $found_pcap_dir -I$pcap_dir"
	    fi
	  done

	  if test "$found_pcap_dir" != "" ; then
	    AC_MSG_RESULT(found --$found_pcap_dir added to CFLAGS)
	  else
	    AC_MSG_RESULT(not found)
	  fi
	else
	  #
	  # The user specified a directory in which libpcap resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a libpcap in a directory that's
	  # already in CFLAGS, CPPFLAGS, or LDFLAGS, this won't
	  # make us find the version in the specified directory,
	  # as the compiler and/or linker will search that other
	  # directory before it searches the specified directory.
	  #
	  CFLAGS="$CFLAGS -I$pcap_dir/include"
	  CPPFLAGS="$CPPFLAGS -I$pcap_dir/include"
	  LDFLAGS="$LDFLAGS -L$pcap_dir/lib"
	fi

	# Pcap header checks
	AC_CHECK_HEADER(pcap.h,, AC_MSG_ERROR(Header file pcap.h not found.))

	AC_CHECK_LIB(pcap, pcap_open_live,, AC_MSG_ERROR(Library libpcap not found.),
	  $SOCKET_LIBS $NSL_LIBS)
])

dnl ************************************************************
dnl check for "localhost", if it doesn't exist, we can't do the
dnl gethostbyname_r tests!
dnl 
dnl Copied from cURL package ;
dnl Done by Jakub Skopal <j@kubs.cz> on 2002-08-28.
dnl

AC_DEFUN(AC_NETTOP_CHECK_WORKING_RESOLVER,[
AC_MSG_CHECKING([if "localhost" resolves])
AC_TRY_RUN([
#include <string.h>
#include <sys/types.h>
#include <netdb.h>

int
main () {
struct hostent *h;
h = gethostbyname("localhost");
exit (h == NULL ? 1 : 0); }],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_ERROR([can't figure out gethostbyname_r() since localhost doesn't resolve])

      ]
)
])

dnl
dnl Try to discover struct in6_addr members
dnl
AC_DEFUN(AC_NETTOP_CHECK_IN6_ADDR,
[
  AC_MSG_CHECKING([if struct in6_addr contains s6_addr32 member])
  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>],[
struct in6_addr adr;
adr.s6_addr32[0]=0;
],[
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_IP6_S6_ADDR32)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING([if struct in6_addr contains _S6_un._S6_u32 member])
      AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>],[
struct in6_addr adr;
adr._S6_un._S6_u32[0]=0;
],[
        AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_IP6__S6_UN__S6_U32)],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING([if struct in6_addr contains __u6_addr.__u6_addr32 member])
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>],[
struct in6_addr adr;
adr.__u6_addr.__u6_addr32[0]=0;
],[
            AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_IP6___U6_ADDR___U6_ADDR32)],[
	      AC_MSG_RESULT(no)
	      AC_MSG_ERROR([can't figure out members of struct in6_addr])
	    ]
	  )
	]
      )
    ]
  )
])

dnl
dnl Find number of arguments of pcap_freecode
dnl
AC_DEFUN(AC_NETTOP_CHECK_PCAP_FREECODE,
[
  dnl check for number of arguments to pcap_freecode. it might take
  dnl either 1 or 2.
    AC_MSG_CHECKING(if pcap_freecode takes 2 arguments)
    AC_TRY_COMPILE([
#include <pcap.h>],[
struct bpf_program *program;
pcap_t *pcap;
pcap_freecode(pcap, program);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_PCAP_FREECODE_2)
      ac_cv_pcap_freecode_args=2],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(if pcap_freecode takes 1 argument)
      AC_TRY_COMPILE([
#include <pcap.h>],[
struct bpf_program *program;
pcap_freecode(program);],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_PCAP_FREECODE_1)
        ac_cv_pcap_freecode_args=1],[
          AC_MSG_RESULT(no)
          AC_MSG_ERROR([cannot discover number of arguments of pcap_freecode])
        ]
      )]
    )]
)


dnl 
dnl Copied from cURL package ;
dnl Done by Jakub Skopal <j@kubs.cz> on 2002-08-28.
dnl
AC_DEFUN(AC_NETTOP_CHECK_GETHOSTBYADDR_R,
[
  dnl check for number of arguments to gethostbyaddr_r. it might take
  dnl either 5, 7, or 8 arguments.
  AC_CHECK_FUNCS(gethostbyaddr_r,[
    AC_MSG_CHECKING(if gethostbyaddr_r takes 5 arguments)
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_5)
      ac_cv_gethostbyaddr_args=5],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(if gethostbyaddr_r with -D_REENTRANT takes 5 arguments)
      AC_TRY_COMPILE([
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_GETHOSTBYADDR_R_5)
	AC_DEFINE(NEED_REENTRANT)
	ac_cv_gethostbyaddr_args=5],[
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING(if gethostbyaddr_r takes 7 arguments)
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;

hp = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &h_errnop);],[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_GETHOSTBYADDR_R_7)
	  ac_cv_gethostbyaddr_args=7],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING(if gethostbyaddr_r takes 8 arguments)
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;
int rc;

rc = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &hp, &h_errnop);],[
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_GETHOSTBYADDR_R_8)
	    ac_cv_gethostbyaddr_args=8],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyaddr_r"])])])])])
])


