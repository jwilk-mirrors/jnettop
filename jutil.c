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

