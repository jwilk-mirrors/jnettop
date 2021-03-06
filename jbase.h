/*
 *    jnettop, network online traffic visualiser
 *    Copyright (C) 2002-2005 Jakub Skopal
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
 *    $Header$
 *
 */

#ifndef __JBASE_H__
#define __JBASE_H__

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
#if HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <glib.h>
#include <errno.h>
#include <sys/wait.h>
#include "ether.h"
#include "ethertype.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmp6.h"
#include "sll.h"
#include "ieee8021q.h"
#include <net/if.h>
#include <netinet/if_ether.h>
#if WITH_NCURSES && HAVE_LIBNCURSES
# if HAVE_NCURSES_H
#  include <ncurses.h>
#  define SUPPORT_NCURSES
# elif HAVE_NCURSES_NCURSES_H
#  include <ncurses/ncurses.h>
#  define SUPPORT_NCURSES
# endif
#endif
#include <time.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netinet/ip6.h>
#include <ctype.h>
#if WITH_SYSLOG
# if HAVE_SYSLOG_H
#  include <syslog.h>
#  define SUPPORT_SYSLOG
# endif
#endif
#if WITH_DB4
# if HAVE_DB_H && HAVE_LIBDB
#  include <db.h>
#  define SUPPORT_DB4
# endif
#endif


#define HISTORY_LENGTH			5
#define FREEPACKETSTACK_PEEK		50
#define FILTER_DATA_STRING_LENGTH	256
#define FILTER_DATA_STRING_LENGTH_S	"255"

#ifdef HAVE_IP6_S6_ADDR32
# define ntop_s6_addr32	s6_addr32
#elif HAVE_IP6___U6_ADDR___U6_ADDR32
# define ntop_s6_addr32 __u6_addr.__u6_addr32
#elif HAVE_IP6__S6_UN__S6_U32
# define ntop_s6_addr32	_S6_un._S6_u32
#else
# error "Configure did not find the insides of struct in6_addr."
#endif

#if HAVE_PCAP_FREECODE_1
# define JBASE_PCAP_FREECODE(a,b) pcap_freecode(b)
#elif HAVE_PCAP_FREECODE_2
# define JBASE_PCAP_FREECODE(a,b) pcap_freecode(a,b)
#endif

extern char	pcap_errbuf[PCAP_ERRBUF_SIZE];
extern volatile int	threadCount;

void	jbase_cb_DrawStatus(const char *statusMesage);
void	debug(int priority, const char *format, ...);

typedef union __jbase_mutableaddress {
	struct in_addr addr4;
	struct in6_addr addr6;
} jbase_mutableaddress;

void	debugip(int priority, int af, const jbase_mutableaddress *addr, const char *message);

typedef struct __jbase_resolv_entry {
	jbase_mutableaddress	addr;
	int			af;
	const gchar  *		name;
} jbase_resolv_entry;

typedef struct __jbase_payload_info {
	const gchar *		data;
	guint			len;
} jbase_payload_info;

typedef struct __jbase_device {
        gchar                   *name;
        struct sockaddr_storage hwaddr;
} jbase_device;

typedef struct __jbase_packet {
	const jbase_device	* device;
	struct pcap_pkthdr	header;
	guint			dataLink;
	gchar 			data[BUFSIZ];
} jbase_packet;

struct __jbase_stream;
struct __jbase_payload_info;

#define	RXTX_RX		1
#define	RXTX_UNKNOWN	0
#define	RXTX_TX		(-1)

typedef void (*FilterDataFunc) (struct __jbase_stream *stream, const struct __jbase_packet *packet, gboolean direction, const struct __jbase_payload_info *pi);
typedef void (*FilterDataFreeFunc) (struct __jbase_stream *stream);

typedef struct __jbase_stream {
	// stream header information
	jbase_mutableaddress	src;
	jbase_mutableaddress	dst;
	guint			proto;
	gint			srcport;
	gint			dstport;
	struct __jbase_resolv_entry	*srcresolv;
	struct __jbase_resolv_entry	*dstresolv;

	// uid
	guint64			uid;

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
	guint			filterDataLastDisplayChangeCount;
	guint			filterDataChangeCount;
	gchar			filterDataString[FILTER_DATA_STRING_LENGTH];
	FilterDataFunc		filterDataFunc;
	FilterDataFreeFunc	filterDataFreeFunc;
	guchar			*filterData;
} jbase_stream;

#define	SET_FILTER_DATA_STRING(stream, string) { \
		memset((stream)->filterDataString, 0, FILTER_DATA_STRING_LENGTH); \
		g_strlcpy((stream)->filterDataString, string, FILTER_DATA_STRING_LENGTH); \
		(stream)->filterDataChangeCount ++; \
	}

#define SET_FILTER_DATA_STRING_2(stream, format, arg0, arg1) { \
		memset((stream)->filterDataString, 0, FILTER_DATA_STRING_LENGTH); \
		g_snprintf((stream)->filterDataString, FILTER_DATA_STRING_LENGTH, format, arg0, arg1); \
		(stream)->filterDataChangeCount ++; \
	}

typedef struct __jbase_display {
	gboolean	supported;
	gboolean	(*presetup)();
	void		(*setup)();
	gboolean	(*prerunsetup)();
	void		(*prerun)();
	gboolean	(*run)();
	void		(*shutdown)();
	void		(*drawstatus)(const gchar *msg);
	int		(*processargument)(const gchar **arg, int cnt);
} jbase_display;

typedef struct _jbase_network_mask_list {
	jbase_mutableaddress	network;
	jbase_mutableaddress	netmask;
	int			af;
	struct _jbase_network_mask_list * next;
} jbase_network_mask_list;

#define	JBASE_PROTO_UNKNOWN	0
#define	JBASE_PROTO_IP		1
#define	JBASE_PROTO_TCP		2
#define	JBASE_PROTO_UDP		3
#define	JBASE_PROTO_ARP		4
#define JBASE_PROTO_ETHER	5
#define JBASE_PROTO_SLL		6
#define JBASE_PROTO_AGGR	7
#define JBASE_PROTO_ICMP	8

#define JBASE_PROTO_IPv6_BEGIN	9
#define JBASE_PROTO_IP6		9
#define JBASE_PROTO_TCP6	10
#define JBASE_PROTO_UDP6	11
#define JBASE_PROTO_ICMP6	12
#define JBASE_PROTO_IPv6_END	12

#define JBASE_PROTO_MAX		16

#define JBASE_IS_IPV6(a)	((a) >= JBASE_PROTO_IPv6_BEGIN && (a) <= JBASE_PROTO_IPv6_END)
#define JBASE_AF(a)		(JBASE_IS_IPV6(a) ? AF_INET6 : AF_INET)

#define JBASE_AF_SIZE(a)	(a == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr))

extern gchar  *JBASE_PROTOCOLS[];

#define AGG_UNKNOWN		(-1)
#define AGG_NONE		0
#define AGG_PORT		1
#define AGG_HOST		2

extern gchar *JBASE_PROTOCOLS[];
extern gchar *JBASE_AGGREGATION[];

#ifndef LOG_NOTICE
#define	LOG_NOTICE	5	/* normal but significant condition */
#endif
#ifndef LOG_WARNING
#define LOG_WARNING     4       /* warning conditions */
#endif
#ifndef LOG_ERR
#define LOG_ERR         3       /* error conditions */
#endif
#ifndef LOG_DEBUG
#define LOG_DEBUG       7       /* debug-level messages */
#endif

#endif
