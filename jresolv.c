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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jresolv.c,v 1.9 2004-09-29 19:09:35 merunka Exp $
 * 
 */

#include "jnettop.h"
#include <netinet/ip6.h>

gboolean resolveStreamTCP(const gchar *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
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
	stream->proto = NTOP_PROTO_TCP;
	payloads[NTOP_PROTO_TCP].data = data + hlen;
	payloads[NTOP_PROTO_TCP].len = len - hlen;
	return TRUE;
}

gboolean resolveStreamUDP(const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
	const struct udphdr *udp = (const struct udphdr *)data;
	if (len < sizeof(struct udphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(udp->uh_sport);
	stream->dstport = ntohs(udp->uh_dport);
	stream->proto = NTOP_PROTO_UDP;
	payloads[NTOP_PROTO_UDP].data = data + sizeof(struct udphdr);
	payloads[NTOP_PROTO_UDP].len = len - sizeof(struct udphdr);
	return TRUE;
}

gboolean resolveStreamIP(const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
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
	stream->proto = NTOP_PROTO_IP;
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
	payloads[NTOP_PROTO_IP].data = data;
	payloads[NTOP_PROTO_IP].len = len;
	
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			return resolveStreamTCP(data, len, stream, payloads);
		case IPPROTO_UDP:
			return resolveStreamUDP(data, len, stream, payloads);
	}
	return TRUE;
}

gboolean resolveStreamTCP6(const gchar *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
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
	stream->proto = NTOP_PROTO_TCP6;
	payloads[NTOP_PROTO_TCP6].data = data + hlen;
	payloads[NTOP_PROTO_TCP6].len = len - hlen;
	return TRUE;
}

gboolean resolveStreamUDP6(const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
	const struct udphdr *udp = (const struct udphdr *)data;
	if (len < sizeof(struct udphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(udp->uh_sport);
	stream->dstport = ntohs(udp->uh_dport);
	stream->proto = NTOP_PROTO_UDP6;
	payloads[NTOP_PROTO_UDP6].data = data + sizeof(struct udphdr);
	payloads[NTOP_PROTO_UDP6].len = len - sizeof(struct udphdr);
	return TRUE;
}

gboolean resolveStreamIP6(const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
	const struct ip6_hdr	*ip = (const struct ip6_hdr *)data;
	if (len < sizeof(struct ip6_hdr)) {
		return FALSE;
	}
	memcpy(&stream->src.addr6, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&stream->dst.addr6, &ip->ip6_dst, sizeof(struct in6_addr));
	stream->proto = NTOP_PROTO_IP6;
	data += sizeof(struct ip6_hdr);
	len -= sizeof(struct ip6_hdr);
	payloads[NTOP_PROTO_IP6].data = data;
	payloads[NTOP_PROTO_IP6].len = len;
	/* TODO: traverse and check all IPv6 headers */
	switch (ip->ip6_nxt) {
		case IPPROTO_TCP:
			return resolveStreamTCP6(data, len, stream, payloads);
		case IPPROTO_UDP:
			return resolveStreamUDP6(data, len, stream, payloads);
	}
	return TRUE;
}

gboolean resolveStreamARP(const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
	stream->proto = NTOP_PROTO_ARP;
	return TRUE;
}

gboolean resolveStreamEther(const ntop_packet *packet, const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
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
		stream->proto = NTOP_PROTO_ETHER;
		payloads[NTOP_PROTO_ETHER].data = data;
		payloads[NTOP_PROTO_ETHER].len = len;
		switch (proto) {
		case ETHERTYPE_IP:
			return resolveStreamIP(data, len, stream, payloads);
			break;
		case ETHERTYPE_ARP:
			return resolveStreamARP(data, len, stream, payloads);
			break;
		case ETHERTYPE_IPV6:
			return resolveStreamIP6(data, len, stream, payloads);
		default:
			debug("Unknown ETHERNET protocol: %d\n", proto);
			return FALSE;
		}
	}
	// unreachable
}

#ifdef linux
gboolean resolveStreamSLL(const ntop_packet *packet, const gchar  *data, guint len, ntop_stream *stream, ntop_payload_info *payloads) {
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
		stream->proto = NTOP_PROTO_SLL;
		payloads[NTOP_PROTO_SLL].data = data;
		payloads[NTOP_PROTO_SLL].len = len;
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

gboolean resolveStream(const ntop_packet *packet, ntop_stream *stream, ntop_payload_info *payloads) {
	guint		len = packet->header.caplen;
	const gchar 	*data = packet->data;
	gboolean	result;
	int		cmpres;

	result = FALSE;

	payloads[NTOP_PROTO_UNKNOWN].data = data;
	payloads[NTOP_PROTO_UNKNOWN].len = len;

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
	default:
		debug("Unknown DataLink encapsulation: %d\n", packet->dataLink);
		return FALSE;
		break;
	}
	cmpres = 0;
	if (stream->rxtx != RXTX_UNKNOWN) {
		cmpres = stream->rxtx;
	} else {
		cmpres = memcmp(&stream->src, &stream->dst, sizeof(struct in_addr));
		cmpres = cmpres || (stream->srcport > stream->dstport);
	}
	if (cmpres > 0) {
		struct in6_addr	addr;
		gushort		port;
		memcpy(&addr, &stream->src, sizeof(struct in6_addr));
		memcpy(&stream->src, &stream->dst, sizeof(struct in6_addr));
		memcpy(&stream->dst, &addr, sizeof(struct in6_addr));
		port = stream->srcport;
		stream->srcport = stream->dstport;
		stream->dstport = port;
		stream->direction = !stream->direction;
	}
	return result;
}

