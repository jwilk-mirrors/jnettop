#include "jbase.h"

char	pcap_errbuf[PCAP_ERRBUF_SIZE];

gchar 	*JBASE_PROTOCOLS[] = { "UNK.", "IP", "TCP", "UDP", "ARP", "ETHER", 
                              "SLL", "AGGR.", "ICMP", "IP6", "TCP6", "UDP6", "ICMP6" };
gchar 	*JBASE_AGGREGATION[] = { "none", "port", "host" };

