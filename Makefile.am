# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/Makefile.am,v 1.4 2002-10-16 20:02:50 merunka Exp $

INCLUDES = -I$(top_srcdir)/include @GLIB_CFLAGS@
LDFLAGS = @GLIB_LIBS@ @NSL_LIBS@ @SOCKET_LIBS@

EXTRA_DIST = jnettop.spec .jnettop

bin_PROGRAMS = jnettop

jnettop_SOURCES = jnettop.c jresolv.c jfilter.c jnettop.h include/ether.h include/ethertype.h include/ip.h include/tcp.h include/udp.h include/sll.h
