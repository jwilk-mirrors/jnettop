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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jutil.c,v 1.7 2006-04-12 07:47:01 merunka Exp $
 *
 */

#include "jbase.h"
#include "jutil.h"

const char * jutil_ValidateBPFFilter(char *filter) {
	const char *ret = NULL;
	struct bpf_program program;
	pcap_t *pcap;
	pcap = pcap_open_dead(DLT_EN10MB, 1500);
	if (pcap_compile(pcap, &program, filter, 0, 0xFFFFFFFF) == -1) {
		ret = pcap_geterr(pcap);
	} else {
		JBASE_PCAP_FREECODE(pcap, &program);
	}
	pcap_close(pcap);
	return ret;
}

int	jutil_IsHostAggregation(int af, const jbase_mutableaddress *addr) {
	switch (af) {
		case AF_INET:
			return addr->addr4.s_addr == htonl(0x01000000);
		case AF_INET6:
			return addr->addr6.ntop_s6_addr32[0] == 0x0 && addr->addr6.ntop_s6_addr32[1] == 0x0 && addr->addr6.ntop_s6_addr32[2] == 0x0  && addr->addr6.ntop_s6_addr32[3] == htonl(0x01000000);
	}
	return 0;
}

const char * jutil_Address2String(int af, const jbase_mutableaddress *src, char *dst, size_t cnt) {
	if (jutil_IsHostAggregation(af, src)) {
		*dst = '\0';
		return dst;
	}
#if HAVE_INET_NTOP
	return inet_ntop(af, (const void *)src, dst, cnt);
#elif HAVE_INET_NTOA
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	char *tmp, *ret = NULL;
	g_static_mutex_lock(&mutex);
	switch (af) {
	case AF_INET:
		tmp = inet_ntoa(src->addr4);
		break;
	case AF_INET6:
		g_snprintf(dst, cnt, "ipv6-res.-n/a"); //TODO: find an alternative way to resolve IPv6
		return dst;
	}
	if (tmp && strlen(tmp)<cnt-1) {
		strcpy(dst, tmp);
		ret = dst;
	}
	g_static_mutex_unlock(&mutex);
	return ret;
#else
# error "no funtion to convert internet address to string found by configure"
#endif
}

guint     jutil_ParseAggregation(const char *agg) {
	if (strcmp(agg, "none") && strcmp(agg,"host") && strcmp(agg,"port")) {
		return AGG_UNKNOWN;
	}
	switch (*agg) {
		case 'n': return AGG_NONE;
		case 'h': return AGG_HOST;
		case 'p': return AGG_PORT;
	}
	return AGG_UNKNOWN;
}

void memand(char *buf1, const char *buf2, int length) {
	int i;
	for (i=0; i<length; i++) {
		buf1[i] &= buf2[i];
	}
}

gboolean jutil_String2Address(const char *address, jbase_mutableaddress *dest, int *af) {
	memset(dest, '\0', sizeof(jbase_mutableaddress));
#ifdef INET_ATON
	if (inet_aton(address, &dest->addr4)) {
		*af = AF_INET;
		return TRUE;
	}
	return FALSE;
#else
	unsigned long int tmpaddr;
	tmpaddr = inet_addr(address);
	if (tmpaddr == -1 && strcmp(address, "255.255.255.255"))
		return FALSE;
	memcpy(&dest->addr4, &tmpaddr, sizeof(struct in_addr));
	*af = AF_INET;
	return TRUE;
#endif
}

void jutil_formatNumber(guint32 n, gboolean onoffPackets, gchar *buf, int len) {
	gchar suffixes[] = {'b','k','m','g','t'};
	gchar fmt[64];
	int  mag = 0;
	int  ipart,fpart = 0;
	gdouble f = (gdouble)n;
	while (mag<4 && f>1000.0) {
		mag ++;
		f /= 1024.0;
	}
	sprintf(fmt, "%.0f", f);
	ipart = strlen(fmt);
	while (ipart+1+fpart+2 < len && mag > 0)
		fpart ++;
	if (ipart+1+fpart+2 > len) {
		sprintf(buf, "ERR");
		return;
	}
	sprintf(fmt, "%%%d.%df%c", ipart, fpart, !mag && onoffPackets ? 'p' : suffixes[mag]);
	sprintf(buf, fmt, f);
}

gboolean jutil_IsInNetwork(const jbase_mutableaddress *address, int address_af, const jbase_mutableaddress *network, const jbase_mutableaddress *netmask, int network_af) {
	jbase_mutableaddress	addr;
	if (address_af != network_af)
		return FALSE;
	memcpy(&addr, address, JBASE_AF_SIZE(address_af));
	memand((char *) &addr, (const char *) netmask, JBASE_AF_SIZE(address_af));
	return !memcmp(&addr, network, JBASE_AF_SIZE(address_af));
}
