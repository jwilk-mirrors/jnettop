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

#include "jnettop.h"

gboolean resolveStreamTCP(const gchar  *data, guint len, ntop_stream *stream) {
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
	return TRUE;
}

gboolean resolveStreamUDP(const gchar  *data, guint len, ntop_stream *stream) {
	guint	hlen;
	const struct udphdr *udp = (const struct udphdr *)data;
	if (len < sizeof(struct udphdr)) {
		return FALSE;
	}
	stream->srcport = ntohs(udp->uh_sport);
	stream->dstport = ntohs(udp->uh_dport);
	stream->proto = NTOP_PROTO_UDP;
	return TRUE;
}

gboolean resolveStreamIP(const gchar  *data, guint len, ntop_stream *stream) {
	guint	hlen;
	const struct ip	*ip = (const struct ip *)data;
	if (len < sizeof(struct ip)) {
		return FALSE;
	}
	hlen = IP_HL(ip) * 4;
	if (hlen < sizeof(struct ip)) {
		return FALSE;
	}
	memcpy(&stream->src, &ip->ip_src, sizeof(struct in_addr));
	memcpy(&stream->dst, &ip->ip_dst, sizeof(struct in_addr));
	stream->proto = NTOP_PROTO_IP;
	if (len < hlen) {
		printf("len<hlen\n");
		return TRUE;
	}
	if (ntohs(ip->ip_off) & 0x1fff != 0) {
		printf("ip_off!=0\n");
		return TRUE;
	}
	data += hlen;
	len -= hlen;
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			return resolveStreamTCP(data, len, stream);
		case IPPROTO_UDP:
			return resolveStreamUDP(data, len, stream);
	}
	return TRUE;
}

gboolean resolveStreamARP(const gchar  *data, guint len, ntop_stream *stream) {
	stream->proto = NTOP_PROTO_ARP;
	return TRUE;
}

gboolean resolveStreamEther(const gchar  *data, guint len, ntop_stream *stream) {
	if (len<NTOP_ETHER_HDRLEN) {
		return FALSE;
	} else
	{
		guint16 proto = ntohs(((struct ntop_ether_header*)data)->ether_type);
		data += NTOP_ETHER_HDRLEN;
		len -= NTOP_ETHER_HDRLEN;
		switch (proto) {
		case ETHERTYPE_IP:
			return resolveStreamIP(data, len, stream);
			break;
		case ETHERTYPE_ARP:
			return resolveStreamARP(data, len, stream);
			break;
		default:
			debug("Unknown ETHERNET protocol: %d\n", proto);
			return FALSE;
		}
	}
	// unreachable
}

gboolean resolveStreamSLL(const gchar  *data, guint len, ntop_stream *stream) {
	if (len<SLL_HDR_LEN) {
		return FALSE;
	} else
	{
		guint16 proto = ntohs(((struct sll_header*)data)->sll_protocol);
		data += SLL_HDR_LEN;
		len -= SLL_HDR_LEN;
		switch (proto) {
		case ETH_P_802_2:
			return resolveStreamEther(data, len, stream);
			break;
		case ETH_P_ARP:
			return resolveStreamARP(data, len, stream);
			break;
		case ETH_P_IP:
			return resolveStreamIP(data, len, stream);
			break;
		default:
			debug("Unknown SLL protocol: %d\n", proto);
			return FALSE;
		}
	}
	// unreachable
}


gboolean resolveStream(const ntop_packet *packet, ntop_stream *stream) {
	guint		len = packet->header.caplen;
	const gchar 	*data = packet->data;
	gboolean	result;
	int		cmpres;

	result = FALSE;

	switch (packet->dataLink) {
	case DLT_EN10MB:
		result = resolveStreamEther(data, len, stream);
		break;
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		result = resolveStreamSLL(data, len, stream);
		break;
#endif
	default:
		debug("Unknown DataLink encapsulation: %d\n", packet->dataLink);
		return FALSE;
		break;
	}
	cmpres = memcmp(&stream->src, &stream->dst, sizeof(struct in_addr));
	if (cmpres > 0 || (cmpres == 0 && stream->srcport > stream->dstport)) {
		struct in_addr	addr;
		gushort		port;
		memcpy(&addr, &stream->src, sizeof(struct in_addr));
		memcpy(&stream->src, &stream->dst, sizeof(struct in_addr));
		memcpy(&stream->dst, &addr, sizeof(struct in_addr));
		port = stream->srcport;
		stream->srcport = stream->dstport;
		stream->dstport = port;
		stream->direction = !stream->direction;
	}
	return result;
}

