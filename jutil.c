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

const char * jutil_StorageAddress2String(const struct sockaddr_storage *hwaddr0, char *dst, size_t cnt) {
	int i;
	char *buf;
	const struct sockaddr *hwaddr = (const struct sockaddr *) hwaddr0;

	if (cnt < 20) {
		return dst;
	}

	buf = dst;
	for (i=0; i<6; i++) {
		if (i > 0)
			*(buf++) = ':';
		sprintf(buf, "%02x", hwaddr->sa_data[i]);
		buf += 2;
	}
	*buf = '\0';
	return dst;
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
#if HAVE_INET_PTON
	memset(dest, '\0', sizeof(jbase_mutableaddress));
	if (inet_pton(AF_INET, address, &dest->addr4) > 0) {
		*af = AF_INET;
		return TRUE;
	}
	if (inet_pton(AF_INET6, address, &dest->addr6) > 0) {
		*af = AF_INET6;
		return TRUE;
	}
	return FALSE;
#else
#if HAVE_INET_ATON
	memset(dest, '\0', sizeof(jbase_mutableaddress));
	if (inet_aton(address, &dest->addr4)) {
		*af = AF_INET;
		return TRUE;
	}
	return FALSE;
#else
	unsigned long int tmpaddr;
	memset(dest, '\0', sizeof(jbase_mutableaddress));
	tmpaddr = inet_addr(address);
	if (tmpaddr == -1 && strcmp(address, "255.255.255.255"))
		return FALSE;
	memcpy(&dest->addr4, &tmpaddr, sizeof(struct in_addr));
	*af = AF_INET;
	return TRUE;
#endif
#endif
}

void jutil_BuildNetmask(int masklength, int af, jbase_mutableaddress *netmask) {
	int i;
	unsigned char * cnetmask = (unsigned char *) netmask;
	for (i=0; i<JBASE_AF_SIZE(af); i++) {
		int ones = masklength < 8 ? masklength : 8;
		int c = ((1<<ones) - 1) << (8-ones);
		* (cnetmask++) = (unsigned char) c;
		masklength = masklength > 8 ? masklength - 8 : 0;
	}
}

gboolean jutil_String2AddressAndNetmask(const char *address, jbase_mutableaddress *dest, jbase_mutableaddress *netmask, int *af) {
	char * charpos;
	char *endofint;
	int masklength;
	char buffer[128];
	if (strlen(address) > 127)
		return FALSE;
	strcpy(buffer, address);
	charpos = strchr(buffer, '/');
	if (!charpos)
		return FALSE;
	*(charpos++) = '\0';
	if (!jutil_String2Address(buffer, dest, af))
		return FALSE;
	masklength = strtol(charpos, &endofint, 10);
	if (*endofint)
		return FALSE;
	if (masklength < 0 || masklength > JBASE_AF_SIZE(*af) * 8)
		return FALSE;
	jutil_BuildNetmask(masklength, *af, netmask);
	return TRUE;
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

void jutil_InterpretStreamFormat(GString *str, const char *formatString, const jbase_stream *s) {
	const char *fmt;
	gchar addr[INET6_ADDRSTRLEN + 1];
	gchar *eitem;

	fmt = formatString;

#define PRINT_ADDRESS(id,fld) if (!strcmp(fmt, id)) { \
				jutil_Address2String(JBASE_AF(s->proto), &(fld), addr, INET6_ADDRSTRLEN); \
				g_string_append_printf(str, "%s", addr); \
				goto nexteitem; \
			}
				
#define PRINT_STRING_OR_NULL(id,snull,fld) if (!strcmp(fmt, id)) { \
				g_string_append_printf(str, "%s", (snull) ? "" : fld); \
				goto nexteitem; \
			}

#define PRINT_GUINT(id,fld) if (!strcmp(fmt, id)) { \
				g_string_append_printf(str, "%d", fld); \
				goto nexteitem; \
			}

#define PRINT_GUINT64(id,fld) if (!strcmp(fmt, id)) { \
				g_string_append_printf(str, "%08x%08x", (unsigned int)(fld>>32), (unsigned int)(fld&0xffffffff)); \
				goto nexteitem; \
			}

#define PRINT_PORT(id,fld) if (!strcmp(fmt, id)) { \
				if ((fld)==-1) g_string_append(str, "AGGR."); else g_string_append_printf(str, "%d", fld); \
				goto nexteitem; \
			}

		do {
			eitem = strchr(fmt, '$');
			if (eitem) *eitem = '\0';
			g_string_append(str, fmt);
			if (eitem)
				*eitem = '$';
			else
				break;
			
			fmt = eitem + 1;
			eitem = strchr(fmt, '$');
			if (eitem) *eitem = '\0';
			PRINT_GUINT64("uid", s->uid);
			PRINT_ADDRESS("src", s->src);
			PRINT_ADDRESS("dst", s->dst);
			PRINT_STRING_OR_NULL("srcname", s->srcresolv == NULL || s->srcresolv->name == NULL, s->srcresolv->name);
			PRINT_STRING_OR_NULL("dstname", s->dstresolv == NULL || s->dstresolv->name == NULL, s->dstresolv->name);
			PRINT_STRING_OR_NULL("proto", FALSE, JBASE_PROTOCOLS[s->proto]);
			PRINT_PORT("srcport", s->srcport);
			PRINT_PORT("dstport", s->dstport);
			PRINT_GUINT("srcbytes", s->srcbytes);
			PRINT_GUINT("dstbytes", s->dstbytes);
			PRINT_GUINT("srcpackets", s->srcpackets);
			PRINT_GUINT("dstpackets", s->dstpackets);
			PRINT_GUINT("totalbytes", s->totalbytes);
			PRINT_GUINT("totalpackets", s->totalpackets);
			PRINT_GUINT("srcbps", s->srcbps);
			PRINT_GUINT("dstbps", s->dstbps);
			PRINT_GUINT("totalbps", s->totalbps);
			PRINT_GUINT("srcpps", s->srcpps);
			PRINT_GUINT("dstpps", s->dstpps);
			PRINT_GUINT("totalpps", s->totalpps);
			PRINT_STRING_OR_NULL("filterdata", s->filterDataString == NULL, s->filterDataString);
			PRINT_STRING_OR_NULL("filterdataifchanged", s->filterDataString == NULL || s->filterDataLastDisplayChangeCount == s->filterDataChangeCount, s->filterDataString);
			g_string_append_printf(str, "?%s?", fmt);
nexteitem:
			if (eitem)
				*eitem = '$';
			else
				break;
			fmt = eitem + 1;
		} while (TRUE); 
}
