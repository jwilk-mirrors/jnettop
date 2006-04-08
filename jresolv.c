/*
 *    jnettop, network online traffic visualiser
 *    Copyright (C) 2002-2006 Jakub Skopal
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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jresolv.c,v 1.14 2006-04-08 11:48:34 merunka Exp $
 * 
 */

#include "jbase.h"
#include <netinet/ip6.h>

static gboolean resolveStreamTCP(const gchar *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	guint	hlen;
	const struct tcphdr *tcp = (const struct tcphdr *)data;
	if (len < sizeof(struct tcphdr)) {
		return FALSE;
	}
	hlen = TH_OFF(tcp) * 4;
	if (hlen < sizeof(struct tcphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(tcp->th_sport);
	stream->dstport = ntohs(tcp->th_dport);
	stream->proto = JBASE_PROTO_TCP;
	payloads[JBASE_PROTO_TCP].data = data + hlen;
	payloads[JBASE_PROTO_TCP].len = len - hlen;
	return TRUE;
}

static gboolean resolveStreamUDP(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct udphdr *udp = (const struct udphdr *)data;
	if (len < sizeof(struct udphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(udp->uh_sport);
	stream->dstport = ntohs(udp->uh_dport);
	stream->proto = JBASE_PROTO_UDP;
	payloads[JBASE_PROTO_UDP].data = data + sizeof(struct udphdr);
	payloads[JBASE_PROTO_UDP].len = len - sizeof(struct udphdr);
	return TRUE;
}

static gboolean resolveStreamICMP(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct icmp *icmp = (const struct icmp *)data;
	if (len < sizeof(struct icmp)) {
		return FALSE;
	}
	stream->proto = JBASE_PROTO_ICMP;
	stream->srcport = stream->dstport = icmp->icmp_type;
	return TRUE;
}

static gboolean resolveStreamIP(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	guint	hlen;
	const struct ip	*ip = (const struct ip *)data;
	if (len < sizeof(struct ip)) {
		return FALSE;
	}
	hlen = IP_HL(ip) * 4;
	if (hlen < sizeof(struct ip)) {
		return FALSE;
	}
	memcpy(&stream->src.addr4, &ip->ip_src, sizeof(struct in_addr));
	memcpy(&stream->dst.addr4, &ip->ip_dst, sizeof(struct in_addr));
	stream->proto = JBASE_PROTO_IP;
	if (len < hlen) {
		printf("len<hlen\n");
		return TRUE;
	}
	if ((ntohs(ip->ip_off) & 0x1fff) != 0) {
		// FIXME: there is currently no proper implementation of
		// handling fragmented packets.
		// printf("ip_off!=0\n");
		return TRUE;
	}
	data += hlen;
	len -= hlen;
	payloads[JBASE_PROTO_IP].data = data;
	payloads[JBASE_PROTO_IP].len = len;

	stream->srcport = stream->dstport = ip->ip_p;
	
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			return resolveStreamTCP(data, len, stream, payloads);
		case IPPROTO_UDP:
			return resolveStreamUDP(data, len, stream, payloads);
		case IPPROTO_ICMP:
			return resolveStreamICMP(data, len, stream, payloads);
	}
	return TRUE;
}

static gboolean resolveStreamTCP6(const gchar *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	guint	hlen;
	const struct tcphdr *tcp = (const struct tcphdr *)data;
	if (len < sizeof(struct tcphdr)) {
		return FALSE;
	}
	hlen = TH_OFF(tcp) * 4;
	if (hlen < sizeof(struct tcphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(tcp->th_sport);
	stream->dstport = ntohs(tcp->th_dport);
	stream->proto = JBASE_PROTO_TCP6;
	payloads[JBASE_PROTO_TCP6].data = data + hlen;
	payloads[JBASE_PROTO_TCP6].len = len - hlen;
	return TRUE;
}

static gboolean resolveStreamUDP6(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct udphdr *udp = (const struct udphdr *)data;
	if (len < sizeof(struct udphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(udp->uh_sport);
	stream->dstport = ntohs(udp->uh_dport);
	stream->proto = JBASE_PROTO_UDP6;
	payloads[JBASE_PROTO_UDP6].data = data + sizeof(struct udphdr);
	payloads[JBASE_PROTO_UDP6].len = len - sizeof(struct udphdr);
	return TRUE;
}

static gboolean resolveStreamICMP6(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct icmp6_hdr *icmp = (const struct icmp6_hdr *)data;
	if (len < sizeof(struct icmp6_hdr)) {
		return FALSE;
	}
	stream->proto = JBASE_PROTO_ICMP6;
	stream->srcport = stream->dstport = icmp->icmp6_type;
	return TRUE;
}

static gboolean resolveStreamIP6(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct ip6_hdr	*ip = (const struct ip6_hdr *)data;
	if (len < sizeof(struct ip6_hdr)) {
		return FALSE;
	}
	memcpy(&stream->src.addr6, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&stream->dst.addr6, &ip->ip6_dst, sizeof(struct in6_addr));
	stream->proto = JBASE_PROTO_IP6;
	data += sizeof(struct ip6_hdr);
	len -= sizeof(struct ip6_hdr);
	payloads[JBASE_PROTO_IP6].data = data;
	payloads[JBASE_PROTO_IP6].len = len;

	stream->srcport = stream->dstport = ip->ip6_nxt;

	/* TODO: traverse and check all IPv6 headers */
	switch (ip->ip6_nxt) {
		case IPPROTO_TCP:
			return resolveStreamTCP6(data, len, stream, payloads);
		case IPPROTO_UDP:
			return resolveStreamUDP6(data, len, stream, payloads);
		case IPPROTO_ICMPV6:
			return resolveStreamICMP6(data, len, stream, payloads);
	}
	return TRUE;
}

static gboolean resolveStreamARP(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	stream->proto = JBASE_PROTO_ARP;
	return TRUE;
}

static gboolean resolveStreamIPn(const jbase_packet *packet, const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	const struct ip	*ip = (const struct ip *)data;
	if (len < 4) {
		return FALSE;
	}
	switch (IP_V(ip)) {
		case 4:
			return resolveStreamIP(data, len, stream, payloads);
		case 6:
			return resolveStreamIP6(data, len, stream, payloads);
	}
	return FALSE;
}

// forward declaration
static gboolean resolveStreamByEtherType(const gchar *data, guint len, jbase_stream *stream, jbase_payload_info *payloads, guint16 proto);

static gboolean	resolveStream8021Q(const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	if (len<NTOP_8021Q_HDRLEN) {
		return FALSE;
	} else
	{
		guint16 proto = ntohs(((struct ntop_8021Q_header*)data)->protocol_type);
		data += NTOP_8021Q_HDRLEN;
		len -= NTOP_8021Q_HDRLEN;
		return resolveStreamByEtherType(data, len, stream, payloads, proto);
	}
}

static gboolean resolveStreamByEtherType(const gchar *data, guint len, jbase_stream *stream, jbase_payload_info *payloads, guint16 proto) {
	switch (proto) {
	case ETHERTYPE_IP:
		return resolveStreamIP(data, len, stream, payloads);
		break;
	case ETHERTYPE_ARP:
		return resolveStreamARP(data, len, stream, payloads);
		break;
	case ETHERTYPE_IPV6:
		return resolveStreamIP6(data, len, stream, payloads);
		break;
	case NTOP_ETHERTYPE_802_1Q:
		return resolveStream8021Q(data, len, stream, payloads);
		break;
	default:
		debug("Unknown ETHERNET protocol: %d\n", proto);
		return FALSE;
	}
}

static gboolean resolveStreamEther(const jbase_packet *packet, const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	if (len<NTOP_ETHER_HDRLEN) {
		return FALSE;
	} else
	{
		guint16 proto = ntohs(((struct ntop_ether_header*)data)->ether_type);
		if (!memcmp( &((struct ntop_ether_header *)data)->ether_shost, &((struct sockaddr *)&packet->device->hwaddr)->sa_data, 6)) {
			stream->rxtx = RXTX_TX;
		} else if (!memcmp( &((struct ntop_ether_header *)data)->ether_dhost, &((struct sockaddr *)&packet->device->hwaddr)->sa_data, 6)) {
			stream->rxtx = RXTX_RX;
		}

		data += NTOP_ETHER_HDRLEN;
		len -= NTOP_ETHER_HDRLEN;
		stream->proto = JBASE_PROTO_ETHER;
		payloads[JBASE_PROTO_ETHER].data = data;
		payloads[JBASE_PROTO_ETHER].len = len;
		return resolveStreamByEtherType(data, len, stream, payloads, proto);
	}
	// unreachable
}


#ifdef linux
static gboolean resolveStreamSLL(const jbase_packet *packet, const gchar  *data, guint len, jbase_stream *stream, jbase_payload_info *payloads) {
	if (len<SLL_HDR_LEN) {
		return FALSE;
	} else
	{
		guint16 proto = ntohs(((struct sll_header*)data)->sll_protocol);
		guint16 pkttype = ntohs(((struct sll_header*)data)->sll_pkttype);
		switch (pkttype) {
			case LINUX_SLL_HOST:
				stream->rxtx = RXTX_RX;
				break;
			case LINUX_SLL_OUTGOING:
				stream->rxtx = RXTX_TX;
				break;
		}
		data += SLL_HDR_LEN;
		len -= SLL_HDR_LEN;
		stream->proto = JBASE_PROTO_SLL;
		payloads[JBASE_PROTO_SLL].data = data;
		payloads[JBASE_PROTO_SLL].len = len;
		switch (proto) {
		case ETH_P_802_2:
			return resolveStreamEther(packet, data, len, stream, payloads);
			break;
		case ETH_P_ARP:
			return resolveStreamARP(data, len, stream, payloads);
			break;
		case ETH_P_IP:
			return resolveStreamIP(data, len, stream, payloads);
			break;
		default:
			debug("Unknown SLL protocol: %d\n", proto);
			return FALSE;
		}
	}
	// unreachable
}
#endif

gboolean jresolv_ResolveStream(const jbase_packet *packet, jbase_stream *stream, jbase_payload_info *payloads) {
	guint		len = packet->header.caplen;
	const gchar 	*data = packet->data;
	gboolean	result;
	int		cmpres;

	result = FALSE;

	payloads[JBASE_PROTO_UNKNOWN].data = data;
	payloads[JBASE_PROTO_UNKNOWN].len = len;

	switch (packet->dataLink) {
	case DLT_EN10MB:
		result = resolveStreamEther(packet, data, len, stream, payloads);
		break;
#ifdef linux
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		result = resolveStreamSLL(packet, data, len, stream, payloads);
		break;
#endif
#endif
#ifdef linux
#ifdef DLT_RAW
	case DLT_RAW:
		result = resolveStreamIPn(packet, data, len, stream, payloads);
		break;
#endif
#endif
	default:
		debug("Unknown DataLink encapsulation: %d\n", packet->dataLink);
		return FALSE;
		break;
	}
	cmpres = 0;
	if (stream->rxtx != RXTX_UNKNOWN) {
		cmpres = stream->rxtx;
	} else {
		cmpres = memcmp(&stream->src, &stream->dst, sizeof(jbase_mutableaddress));
		if (cmpres == 0) {
			cmpres = stream->srcport > stream->dstport;
		}
	}
	if (cmpres > 0) {
		jbase_mutableaddress addr;
		gushort		port;
		memcpy(&addr, &stream->src, sizeof(jbase_mutableaddress));
		memcpy(&stream->src, &stream->dst, sizeof(jbase_mutableaddress));
		memcpy(&stream->dst, &addr, sizeof(jbase_mutableaddress));
		port = stream->srcport;
		stream->srcport = stream->dstport;
		stream->dstport = port;
		stream->direction = !stream->direction;
	}
	return result;
}

