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
#if NEED_REENTRANT
# define _REENTRANT
#endif
#include <stdlib.h>
#include <stdarg.h>
#if HAVE_STRING_H
# include <string.h>
#elif HAVE_STRINGS_H
# include <strings.h>
#else
# error "No string.h nor strings.h found"
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <glib.h>
#include <errno.h>
#include "ether.h"
#include "ethertype.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "sll.h"
#include <net/if.h>
#include <netinet/if_ether.h>
#include <ncurses/ncurses.h>
#include <time.h>
#include <netdb.h>
#include <sys/ioctl.h>

#define HISTORY_LENGTH			5
#define FREEPACKETSTACK_PEEK		50
#define FILTER_DATA_STRING_LENGTH	256
#define FILTER_DATA_STRING_LENGTH_S	"255"

typedef struct __ntop_device {
	gchar			*name;
	struct sockaddr_storage	hwaddr;
} ntop_device;

typedef struct __ntop_packet {
	struct __ntop_device	* device;
	struct pcap_pkthdr	header;
	guint			dataLink;
	gchar 			data[BUFSIZ];
} ntop_packet;

typedef union __ntop_mutableaddress {
	struct in_addr addr4;
	struct in6_addr addr6;
} ntop_mutableaddress;

typedef struct __ntop_resolv_entry {
	ntop_mutableaddress	addr;
	int			af;
	gchar  *		name;
} ntop_resolv_entry;

struct __ntop_stream;
struct __ntop_payload_info;
struct __ntop_packet;

#define	RXTX_RX		1
#define	RXTX_UNKNOWN	0
#define	RXTX_TX		(-1)

typedef void (*FilterDataFunc) (struct __ntop_stream *stream, const struct __ntop_packet *packet, gboolean direction, const struct __ntop_payload_info *pi);
typedef void (*FilterDataFreeFunc) (struct __ntop_stream *stream);

typedef struct __ntop_stream {
	// stream header information
	ntop_mutableaddress	src;
	ntop_mutableaddress	dst;
	guint			proto;
	gint			srcport;
	gint			dstport;
	struct __ntop_resolv_entry	*srcresolv;
	struct __ntop_resolv_entry	*dstresolv;

	// stream classification data
	gboolean		direction;
	int			rxtx;

	// stream statistics information
	guint32			srcbytes, dstbytes, totalbytes;
	guint32			srcpackets, dstpackets, totalpackets;
	GTimeVal		firstSeen;
	GTimeVal		lastSeen;
	guint			hsrcbytes[HISTORY_LENGTH], hdstbytes[HISTORY_LENGTH];
	guint			hsrcpackets[HISTORY_LENGTH], hdstpackets[HISTORY_LENGTH];
	guint			hsrcbytessum, hdstbytessum;
	guint			hsrcpacketssum, hdstpacketssum;
	guint			srcbps, dstbps, totalbps;
	guint			srcpps, dstpps, totalpps;

	// stream state information
	guint			dead;
	guint			displayed;

	// filter data information
	guchar			filterDataString[FILTER_DATA_STRING_LENGTH];
	FilterDataFunc		filterDataFunc;
	FilterDataFreeFunc	filterDataFreeFunc;
	guchar			*filterData;
} ntop_stream;

#define	SET_FILTER_DATA_STRING(stream, string) { \
		memset((stream)->filterDataString, 0, FILTER_DATA_STRING_LENGTH); \
		g_strlcpy((stream)->filterDataString, string, FILTER_DATA_STRING_LENGTH); \
	}

#define SET_FILTER_DATA_STRING_2(stream, format, arg0, arg1) { \
		memset((stream)->filterDataString, 0, FILTER_DATA_STRING_LENGTH); \
		g_snprintf((stream)->filterDataString, FILTER_DATA_STRING_LENGTH, format, arg0, arg1); \
	}

typedef struct __ntop_payload_info {
	const gchar *		data;
	guint			len;
} ntop_payload_info;

#define	NTOP_PROTO_UNKNOWN	0
#define	NTOP_PROTO_IP		1
#define	NTOP_PROTO_TCP		2
#define	NTOP_PROTO_UDP		3
#define	NTOP_PROTO_ARP		4
#define NTOP_PROTO_ETHER	5
#define NTOP_PROTO_SLL		6
#define NTOP_PROTO_AGGR		7
#define NTOP_PROTO_IP6		8
#define NTOP_PROTO_TCP6		9
#define NTOP_PROTO_UDP6		10
#define NTOP_PROTO_MAX		16

#define NTOP_IS_IPV6(a)		((a) >= NTOP_PROTO_IP6 && (a) <= NTOP_PROTO_UDP6)
#define NTOP_AF(a)		(NTOP_IS_IPV6(a) ? AF_INET6 : AF_INET)

extern gchar  *NTOP_PROTOCOLS[];

// forward declaration of jresolv exports
gboolean	resolveStream(const ntop_packet *packet, ntop_stream *stream, ntop_payload_info *payloads);

// forward declaration of jfilter exports
void		assignDataFilter(ntop_stream *stream);

// forward declaration of jnettop exports
void		debug(const char *format, ...);

#define AGG_UNKNOWN		(-1)
#define AGG_NONE		0
#define AGG_PORT		1
#define AGG_HOST		2

