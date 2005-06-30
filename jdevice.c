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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jdevice.c,v 1.3 2005-06-30 21:34:48 merunka Exp $
 *
 */

#include "jbase.h"
#include "jdevice.h"

gint jdevice_DevicesCount;
jbase_device *jdevice_Devices;

gboolean jdevice_LookupDevices() {
#if HAVE_PCAP_FINDALLDEVS
	pcap_if_t	*head, *t;
	int		i;
	if (pcap_findalldevs(&head, pcap_errbuf) != 0) {
		fprintf(stderr, "pcap_findalldevs: %s\n", pcap_errbuf);
		return FALSE;
	}
	jdevice_DevicesCount = 0;
	t = head;
	while (t) {
		jdevice_DevicesCount ++;
		t = t->next;
	}
	jdevice_Devices = g_new0(jbase_device, jdevice_DevicesCount);
	t = head;
	i = 0;
	while (t) {
		jdevice_Devices[i++].name = g_strndup((const gchar*)t->name, strlen(t->name));
		t = t->next;
	}
	pcap_freealldevs(head);
#else
	char		*name;
	jdevice_DevicesCount = 1;
	jdevice_Devices = g_new(jbase_device, 1);
	name = pcap_lookupdev(pcap_errbuf);
	if (!name) {
		fprintf(stderr, "pcap_lookupdev: %s\n", pcap_errbuf);
		return FALSE;
	}
	jdevice_Devices[0].name = g_strndup((const gchar*)name, strlen(name));
#endif
	return TRUE;
}

jbase_device * jdevice_CreateSingleDevice(const gchar *deviceName) {
	jdevice_DevicesCount = 1;
	jdevice_Devices = g_new(jbase_device, 1);
	jdevice_Devices[0].name = g_strndup(deviceName, strlen(deviceName));
	return jdevice_Devices;
}

gboolean jdevice_CheckDevices() {
	struct ifreq ifr;
	int s,i;

	memset(&ifr, 0, sizeof(struct ifreq));
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s==-1) {
		fprintf(stderr, "Could not open datagram socket used to discover HW addresses of interfaces: %s\n", strerror(errno));
		return FALSE;
	}
	for (i=0; i<jdevice_DevicesCount; i++) {
		strncpy(ifr.ifr_name, jdevice_Devices[i].name, IFNAMSIZ);
#ifdef SIOCGIFHWADDR
		ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
		if (ioctl(s, SIOCGIFHWADDR, &ifr) >= 0) {
			memcpy(&jdevice_Devices[i].hwaddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
#else
		if (ioctl(s, SIOCGIFADDR, &ifr) >= 0) {
			memcpy(&jdevice_Devices[i].hwaddr, &ifr.ifr_addr, sizeof(struct sockaddr));
#endif
		} else {
			fprintf(stderr, "Could not get HW address of interface %s: %s\n", jdevice_Devices[i].name, strerror(errno));
		}
	}
	close(s);
	return TRUE;
}
