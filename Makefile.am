
INCLUDES = -I$(top_srcdir)/include @GLIB_CFLAGS@
LDFLAGS = @GLIB_LIBS@ @NSL_LIBS@ @SOCKET_LIBS@

EXTRA_DIST = jnettop.spec

bin_PROGRAMS = jnettop

jnettop_SOURCES = jnettop.c jresolv.c jnettop.h include/ether.h include/ethertype.h include/ip.h include/tcp.h include/udp.h include/sll.h
