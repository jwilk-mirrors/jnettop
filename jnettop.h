/*
 *    jnettop, network online traffic visualiser
 *    Copyright (C) 2002 Jakub Skopal
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "config.h"
#include <stdlib.h>
#include <stdarg.h>
#if HAVE_STRING_H
# include <string.h>
#elif HAVE_STRINGS_H
# include <strings.h>
#else
# error "No string.h nor strings.h found"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <glib.h>
#include "ether.h"
#include "ethertype.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "sll.h"
#include <netinet/if_ether.h>
#include <ncurses.h>
#include <time.h>
#include <netdb.h>

#define HISTORY_LENGTH		5
#define FREEPACKETSTACK_PEEK	50

typedef struct __ntop_device {
	gchar	*name;
} ntop_device;

typedef struct __ntop_packet {
	struct pcap_pkthdr	header;
	guint			dataLink;
	gchar 			data[BUFSIZ];
} ntop_packet;

typedef struct __ntop_resolv_entry {
	struct in_addr		addr;
	gchar  *		name;
} ntop_resolv_entry;

struct __ntop_stream;

typedef struct __ntop_stream {
	// stream header information
	struct in_addr		src;
	struct in_addr		dst;
	guint			proto;
	gushort			srcport;
	gushort			dstport;
	struct __ntop_resolv_entry	*srcresolv;
	struct __ntop_resolv_entry	*dstresolv;

	// stream classification data
	gboolean		direction;

	// stream statistics information
	guint32			srcbytes, dstbytes, totalbytes;
	guint32			srcpackets, dstpackets, totalpackets;
	GTimeVal		firstSeen;
	GTimeVal		lastSeen;
	guint			hbytes[HISTORY_LENGTH];
	guint			hbytessum;
	guint			bps;

	// stream state information
	guint			dead;
	guint			displayed;

} ntop_stream;

#define	NTOP_PROTO_UNKNOWN	0
#define	NTOP_PROTO_IP		1
#define	NTOP_PROTO_TCP		2
#define	NTOP_PROTO_UDP		3
#define	NTOP_PROTO_ARP		4

extern gchar  *NTOP_PROTOCOLS[];

// forward declaration of jresolv exports
gboolean	resolveStream(const ntop_packet *packet, ntop_stream *stream);

