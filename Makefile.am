# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/Makefile.am,v 1.11 2005-07-01 10:02:07 merunka Exp $

INCLUDES = -I$(top_srcdir)/include @GLIB_CFLAGS@
AM_LDFLAGS = @GLIB_LIBS@ @NSL_LIBS@ @SOCKET_LIBS@

man_MANS = jnettop.8

EXTRA_DIST = jnettop.spec .jnettop $(man_MANS)

bin_PROGRAMS = jnettop

dist_pkgdata_SCRIPTS = jnettop-lookup-nmb
jnettop_SOURCES = jnettop.c jconfig.c jconfig.h jutil.c jutil.h jresolver.c jresolver.h jprocessor.c jprocessor.h jcapture.c jcapture.h jdevice.c jdevice.h jbase.c jbase.h jresolv.c jresolv.h jfilter.c jfilter.h include/ether.h include/ethertype.h include/ip.h include/tcp.h include/udp.h include/sll.h include/icmp.h include/icmp6.h
