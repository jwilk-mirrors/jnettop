# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/Makefile.am,v 1.6 2004-10-01 12:32:45 merunka Exp $

INCLUDES = -I$(top_srcdir)/include @GLIB_CFLAGS@
LDFLAGS = @GLIB_LIBS@ @NSL_LIBS@ @SOCKET_LIBS@

man_MANS = jnettop.8

EXTRA_DIST = jnettop.spec .jnettop $(man_MANS)

bin_PROGRAMS = jnettop

jnettop_SOURCES = jnettop.c jresolv.c jfilter.c jnettop.h include/ether.h include/ethertype.h include/ip.h include/tcp.h include/udp.h include/sll.h include/icmp.h include/icmp6.h
