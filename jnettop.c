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

gchar 	*NTOP_PROTOCOLS[] = { "UNK.", "IP", "TCP", "UDP", "ARP" };

char		pcap_errbuf[PCAP_ERRBUF_SIZE];

int		devices_count;
ntop_device	*devices, *activeDevice, *newDevice;

FILE *		debugFile = NULL;

int		threadCount;

GQueue		*packetQueue;
GMutex		*packetQueueMutex;
GCond		*packetQueueCond;
GHashTable	*streamTable;
GMutex		*streamTableMutex;
GPtrArray	*streamArray;
GMutex		*streamArrayMutex;
GHashTable	*resolverCache;
GMutex		*resolverCacheMutex;
GTrashStack	*freePacketStack = NULL;
int		freePacketStackSize = 0;
GMutex		*freePacketStackMutex;

GThread		*snifferThread;
GThread		*sorterThread;
GThread		*processorThread;
GThread		*displayThread;
GThreadPool	*resolverThreadPool;

GTimeVal	startTime;
GTimeVal	historyTime;

guint32		totalBytes;
guint32		totalPackets;
guint32		totalBPS;

GMutex		*displayStreamsMutex;
ntop_stream	**displayStreams;
int		displayStreamsCount;
gchar 		line0FormatString[128], line1FormatString[128];

WINDOW		*listWindow;

void debug(const char *format, ...) {
	if (debugFile) {
		va_list ap;
		va_start(ap, format);
		vfprintf(debugFile, format, ap);
		va_end(ap);
	}
}

void freeStream(gpointer ptr) {
	ntop_stream *s = (ntop_stream *)ptr;
	g_free(s);
}

void createDevice(char *deviceName) {
	devices_count = 1;
	devices = g_new(ntop_device, 1);
	devices[0].name = g_strndup((gchar*)deviceName, strlen(deviceName));
}

void lookupDevices() {
#if HAVE_PCAP_FINDALLDEVS
	pcap_if_t	*head, *t;
	int		i;
	if (pcap_findalldevs(&head, pcap_errbuf) != 0) {
		fprintf(stderr, "pcap_findalldevs: %s\n", pcap_errbuf);
		exit(255);
	}
	devices_count = 0;
	t = head;
	while (t) {
		devices_count ++;
		t = t->next;
	}
	devices = g_new(ntop_device, devices_count);
	t = head;
	i = 0;
	while (t) {
		devices[i++].name = g_strndup((gchar*)t->name, strlen(t->name));
		t = t->next;
	}
	pcap_freealldevs(head);
#else
	char		*name;
	devices_count = 1;
	devices = g_new(ntop_device, 1);
	name = pcap_lookupdev(pcap_errbuf);
	if (!name) {
		fprintf(stderr, "pcap_lookupdev: %s\n", pcap_errbuf);
		exit(255);
	}
	devices[0].name = g_strndup((gchar*)name, strlen(name));
#endif
}
	
guint hashStream(gconstpointer key) {
	const ntop_stream	*stream = (const ntop_stream *)key;
	guint hash = 0;
	hash = stream->src.s_addr;
	hash ^= stream->dst.s_addr;
	hash ^= ((guint)stream->srcport) << 16 + (guint)stream->dstport;
	return hash;
}

gboolean compareStream(gconstpointer a, gconstpointer b) {
	const ntop_stream *astr = (const ntop_stream *)a;
	const ntop_stream *bstr = (const ntop_stream *)b;
	if ( astr->src.s_addr == bstr->src.s_addr &&
			astr->dst.s_addr == bstr->dst.s_addr &&
			astr->proto == bstr->proto &&
			astr->srcport == bstr->srcport &&
			astr->dstport == bstr->dstport )
		return TRUE;
	return FALSE;
}

gint compareStreamByStat(gconstpointer a, gconstpointer b) {
	const ntop_stream	*astr = *(const ntop_stream **)a;
	const ntop_stream	*bstr = *(const ntop_stream **)b;
	if (astr->bps > bstr->bps)
		return -1;
	else if (astr->bps == bstr->bps)
		return 0;
	return 1;
}

guint hashResolvEntry(gconstpointer key) {
	return GPOINTER_TO_UINT(key);
}

gboolean compareResolvEntry(gconstpointer a, gconstpointer b) {
	return a == b;
}

void	sortPacket(const ntop_packet *packet) {
	ntop_stream	packetStream;
	ntop_stream	*stat;
	totalBytes += packet->header.len;
	totalPackets ++;
	memset(&packetStream, 0, sizeof(ntop_stream));
	resolveStream(packet, &packetStream);
	g_mutex_lock(streamTableMutex);
	stat = (ntop_stream *)g_hash_table_lookup(streamTable, &packetStream);
	if (stat == NULL) {
		ntop_resolv_entry *rentry;
		stat = g_new0(ntop_stream, 1);
		memcpy(stat, &packetStream, sizeof(ntop_stream));
		g_get_current_time(&stat->firstSeen);
		g_hash_table_insert(streamTable, stat, stat);
		g_mutex_unlock(streamTableMutex);

		g_mutex_lock(resolverCacheMutex);
		rentry = g_hash_table_lookup(resolverCache, GUINT_TO_POINTER((guint)packetStream.src.s_addr));
		if (rentry == NULL) {
			rentry = g_new0(ntop_resolv_entry, 1);
			memcpy(&rentry->addr, &packetStream.src, sizeof(struct in_addr));
			g_hash_table_insert(resolverCache, GUINT_TO_POINTER((guint)packetStream.src.s_addr), rentry);
			g_mutex_unlock(resolverCacheMutex);
			g_thread_pool_push(resolverThreadPool, rentry, NULL);
			g_mutex_lock(resolverCacheMutex);
		}
		stat->srcresolv = rentry;
		rentry = g_hash_table_lookup(resolverCache, GUINT_TO_POINTER((guint)packetStream.dst.s_addr));
		if (rentry == NULL) {
			rentry = g_new0(ntop_resolv_entry, 1);
			memcpy(&rentry->addr, &packetStream.dst, sizeof(struct in_addr));
			g_hash_table_insert(resolverCache, GUINT_TO_POINTER((guint)packetStream.dst.s_addr), rentry);
			g_mutex_unlock(resolverCacheMutex);
			g_thread_pool_push(resolverThreadPool, rentry, NULL);
		} else {
			g_mutex_unlock(resolverCacheMutex);
		}
		stat->dstresolv = rentry;

		g_mutex_lock(streamArrayMutex);
		g_ptr_array_add(streamArray, stat);
		g_mutex_unlock(streamArrayMutex);
	} else {
		g_mutex_unlock(streamTableMutex);
	}
	if (packetStream.direction) {
		stat->dstbytes += packet->header.len;
		stat->dstpackets ++;
	} else {
		stat->srcbytes += packet->header.len;
		stat->srcpackets ++;
	}
	stat->totalbytes += packet->header.len;
	stat->totalpackets ++;
	*stat->hbytes += packet->header.len;
	stat->hbytessum += packet->header.len;
	g_get_current_time(&stat->lastSeen);
}

void	updateBPS() {
	GTimeVal	currentDateTime;
	uint		i;
	guint32		bps = 0;

	g_get_current_time(&currentDateTime);
	currentDateTime.tv_sec ++;

	for (i=0; i<streamArray->len; i++) {
		ntop_stream *s = (ntop_stream *)g_ptr_array_index(streamArray, i);
		int byteswindow = ( currentDateTime.tv_sec - s->firstSeen.tv_sec );
		if (byteswindow > HISTORY_LENGTH)
			byteswindow = HISTORY_LENGTH;
		bps += (s->bps = s->hbytessum / byteswindow);
		s->hbytessum -= s->hbytes[HISTORY_LENGTH-1];
		memmove(s->hbytes+1, s->hbytes, sizeof(guint)*(HISTORY_LENGTH-1));
		s->hbytes[0] = 0;
		if (!s->dead && currentDateTime.tv_sec - s->lastSeen.tv_sec > 10) {
			s->dead ++;
		}
	}

	totalBPS = bps;
}

int	activeLines=1, activeColumns=1;

void formatNumber(guint32 n, gchar *buf, int len) {
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
	sprintf(fmt, "%%%d.%df%c", ipart, fpart, suffixes[mag]);
	sprintf(buf, fmt, f);
}

void drawStatus(guchar *msg) {
	attron(A_BOLD);
	mvprintw(2, 0, "%s", msg);
	clrtoeol();
	attroff(A_BOLD);
	refresh();
}

void drawScreen() {
	if (LINES != activeLines || COLS != activeColumns) {
		activeLines = LINES;
		activeColumns = COLS;

		if (activeLines < 20 || activeColumns < 80) {
			endwin();
			fprintf(stderr, "Too small terminal\n");
			exit(255);
		}

		attrset(A_NORMAL);

		mvprintw(0, 0, "time XX:XX:XX run XXX:XX:XX device XXXXXXXXXX bytes XXXXXXX pkts XXXXXXXXX");
		mvprintw(1, 0, "                                               bps XXXXXXX@ strs XXXXXXXXX");
		mvprintw(2, 0, "[q]uit");
#if HAVE_PCAP_FINDALLDEVS
		if (devices_count>1) {
			mvprintw(2, 10, "[0]-[9] switch device");
		}
#endif
		mvprintw(0, activeColumns-1, ".");

		{
			int hostColumns = activeColumns - 8;
			int windowColumns = hostColumns / 2 - 2;
			sprintf(line0FormatString, "%%-%d.%ds %*c%%8s", windowColumns*2+1, windowColumns*2+1, hostColumns-2*windowColumns-2, ' ');
			sprintf(line1FormatString, " %%-15.15s %%5.5s %%6.6s%*c%%-15.15s %%5.5s%*c%%6.6s %%6.6s %%%d.%ds", windowColumns-30, ' ', windowColumns-30, ' ',activeColumns-2*windowColumns-4, activeColumns-2*windowColumns-4);
		}

		if (listWindow) {
			delwin(listWindow);
		}
		listWindow = newwin(activeLines-5, activeColumns, 5, 0);
	}
}

void drawHeader() {
	GTimeVal	currentTime;
	gchar		timeBuffer[32];
	struct tm tm;

	attron(A_BOLD);
	
	g_get_current_time(&currentTime);
	localtime_r(&currentTime.tv_sec, &tm);
	strftime(timeBuffer, 31, "%H:%M:%S", &tm);
	mvprintw(0, 5, "%s", timeBuffer);
	sprintf(timeBuffer, "%3d:%02d:%02d", (currentTime.tv_sec-startTime.tv_sec)/3600, (currentTime.tv_sec-startTime.tv_sec)%3600/60, (currentTime.tv_sec-startTime.tv_sec)%60);
	mvprintw(0, 18, "%s", timeBuffer);
	if (activeDevice)
		mvprintw(0, 35, "%-10s", activeDevice->name);
	formatNumber(totalBytes, timeBuffer, 7);
	mvprintw(0, 52, "%7s", timeBuffer);
	mvprintw(0, 65, "%9d", totalPackets);
	mvprintw(1, 65, "%9d", streamArray->len);
	formatNumber(totalBPS, timeBuffer, 6);
	mvprintw(1, 51, "%6s/s", timeBuffer);

	attroff(A_BOLD);
	
	attron(A_REVERSE);

	mvprintw(3, 0, line0FormatString, "HOSTS", "BPS");
	mvprintw(4, 0, line1FormatString, "(IP)", "PORT", "PROTO", "(IP)", "PORT", "->", "<-", "TOTAL");

	attroff(A_REVERSE);
}

void resolverThreadFunc(gpointer task, gpointer user_data) {
	ntop_resolv_entry *entry = (ntop_resolv_entry *)task;
	gchar buffer[4096];
	struct hostent shentry, *hentry;
	int  e;
	gchar *name;

	gethostbyaddr_r(&entry->addr, sizeof(struct in_addr), AF_INET, &shentry, buffer, 4096, &hentry, &e);
	if (!e) {
		name = g_strdup(hentry->h_name);
		entry->name = name;
	}
}

gpointer sorterThreadFunc(gpointer data) {
	threadCount ++;

	while (activeDevice != NULL) {
		guint		i, j;
		int		lines,oldLines;
		ntop_stream	**streams,**oldStreams;
		GTimeVal	t;

		lines = (activeLines - 5) / 3;

		streams = g_new0(ntop_stream *, lines);
		
		g_mutex_lock(streamArrayMutex);
		if (streamArray->len > 0) {
			updateBPS();
			g_ptr_array_sort(streamArray, (GCompareFunc)compareStreamByStat);
		}
		for (i=0,j=0; i<streamArray->len && j<lines; i++) {
			ntop_stream *s = (ntop_stream *)g_ptr_array_index(streamArray, i);
			if (s->dead > 5) {
				continue;
			}
			s->displayed ++;
			streams[j++] = s;
		}
		lines = j;
		g_mutex_unlock(streamArrayMutex);

		g_mutex_lock(displayStreamsMutex);
		oldStreams = displayStreams;
		oldLines   = displayStreamsCount;
		displayStreams = streams;
		displayStreamsCount = lines;
		g_mutex_unlock(displayStreamsMutex);

		for (i=0; i<oldLines; i++) {
			oldStreams[i]->displayed --;
		}
		if (oldStreams)
			g_free(oldStreams);

		g_mutex_lock(streamArrayMutex);
		g_mutex_lock(streamTableMutex);

		for (i=0; i<streamArray->len; i++) {
			ntop_stream *s = (ntop_stream *)g_ptr_array_index(streamArray, i);
			if (s->dead && ++s->dead > 6 && !s->displayed) {
				g_ptr_array_remove_index_fast ( streamArray, i );
				g_hash_table_remove ( streamTable, s );
				freeStream(s);
				i--;
			}
		}

		g_mutex_unlock(streamTableMutex);
		g_mutex_unlock(streamArrayMutex);

		g_get_current_time(&t);
		g_usleep(1000000 - t.tv_usec);
	}

	threadCount --;
}

gboolean	removeStreamTableEntry(gpointer key, gpointer value, gpointer user_data) {
	freeStream(key);
	// value is the same pointer as key
	return TRUE;
}

void     clearStatistics() {
	gpointer	ptr;
	int            	i;
	ntop_stream	*stat;

	while (ptr = g_queue_pop_tail(packetQueue)) {
		g_free(ptr);
	}
	for (i=streamArray->len-1; i>=0; i--) {
		g_ptr_array_remove_index_fast(streamArray, i);
	}
	g_hash_table_foreach_remove(streamTable, (GHRFunc)removeStreamTableEntry, NULL);
}

gpointer displayThreadFunc(gpointer data) {
	threadCount ++;
	g_usleep(500000);

	while (activeDevice != NULL) {
		int i;
		
		g_mutex_lock(displayStreamsMutex);
		drawScreen();
		drawHeader();
		werase(listWindow);
		for (i=0; i<displayStreamsCount; i++) {
			gchar srcaddr[20], dstaddr[20], srcport[10], dstport[10], bps[10], total[10], totalsrc[10], totaldst[10];
			gchar linebuffer[1024];
			gchar *psrcaddr, *pdstaddr;
			ntop_stream *s = displayStreams[i];
			uint ibps = s->bps;
			formatNumber(ibps, bps, 6);
			g_strlcat(bps, "/s", sizeof(bps));
			formatNumber(s->totalbytes, total, 6);
			formatNumber(s->srcbytes, totalsrc, 6);
			formatNumber(s->dstbytes, totaldst, 6);
			inet_ntop(AF_INET, &s->src, srcaddr, 19);
			if (s->srcresolv == NULL || s->srcresolv->name == NULL) {
				psrcaddr = srcaddr;
			} else {
				psrcaddr = s->srcresolv->name;
			}
			inet_ntop(AF_INET, &s->dst, dstaddr, 19);
			if (s->dstresolv == NULL || s->dstresolv->name == NULL) {
				pdstaddr = dstaddr;
			} else {
				pdstaddr = s->dstresolv->name;
			}
			sprintf(srcport, "%d", s->srcport);
			sprintf(dstport, "%d", s->dstport);
			sprintf(linebuffer, "%s <-> %s", psrcaddr, pdstaddr);
			mvwprintw(listWindow, i*3, 0, line0FormatString, linebuffer, bps);
			mvwchgat(listWindow, i*3, 0, activeColumns-8, A_BOLD, 0, NULL);
			mvwprintw(listWindow, i*3+1, 0, line1FormatString, srcaddr, srcport, NTOP_PROTOCOLS[s->proto], dstaddr, dstport, totalsrc, totaldst, total);
		}
		g_mutex_unlock(displayStreamsMutex);

		wnoutrefresh(listWindow);
		refresh();

		g_usleep(1000000);
		i = getch();
		if (i!=ERR) {
			switch (i) {
				case 'q':
				case 'Q':
					drawStatus("Please wait, shutting down...");
					activeDevice = NULL;
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					i -= '0';
					if (devices_count>1 && devices_count > i) {
						drawStatus("Please wait, cleaning up...");
						newDevice = devices + i;
						activeDevice = NULL;
					}
					break;
			}
		}
		while (getch() != ERR) ;
	}
	threadCount --;
}

ntop_packet *allocNtopPacket() {
	ntop_packet *ptr;
	g_mutex_lock(freePacketStackMutex);
	ptr = (ntop_packet *)g_trash_stack_pop(&freePacketStack);
	if (ptr) {
		freePacketStackSize --;
	}
	g_mutex_unlock(freePacketStackMutex);
	if (!ptr) {
		ptr = g_new(ntop_packet, 1);
	}
	return ptr;
}

void freeNtopPacket(ntop_packet *packet) {
	g_mutex_lock(freePacketStackMutex);
	if (freePacketStackSize < FREEPACKETSTACK_PEEK) {
		g_trash_stack_push(&freePacketStack, packet);
		freePacketStackSize ++;
		packet = NULL;
	}
	g_mutex_unlock(freePacketStackMutex);
	if (packet)
		g_free(packet);
	
}

gpointer processorThreadFunc(gpointer data) {
	threadCount ++;
	g_mutex_lock(packetQueueMutex);
	while (activeDevice != NULL) {
		ntop_packet	*packet;
		packet = (ntop_packet *)g_queue_pop_tail(packetQueue);
		if (packet == NULL) {
			g_cond_wait(packetQueueCond, packetQueueMutex);
			continue;
		}

		g_mutex_unlock(packetQueueMutex);

		sortPacket(packet);
		freeNtopPacket(packet);

		g_mutex_lock(packetQueueMutex);
	}
	g_mutex_unlock(packetQueueMutex);
	threadCount --;
}

gboolean	packetReceived;
int		deviceDataLink;

void     dispatch_callback(const u_char *udata, const struct pcap_pkthdr *hdr, const guchar *pcappacket) {
	ntop_packet * packet;
	packet = allocNtopPacket();
	packet->dataLink = deviceDataLink;
	memcpy(&(packet->header), hdr, sizeof(struct pcap_pkthdr));
	if (packet->header.caplen > BUFSIZ)
		packet->header.caplen = BUFSIZ;
	memcpy(packet->data, pcappacket, packet->header.caplen);
	g_mutex_lock(packetQueueMutex);
	g_queue_push_head(packetQueue, packet);
	g_mutex_unlock(packetQueueMutex);
	g_cond_signal(packetQueueCond);
}

gpointer snifferThreadFunc(gpointer data) {
	pcap_t		*handle;
	ntop_device	*device = NULL;
	gchar		pcap_errbuf[PCAP_ERRBUF_SIZE];

	threadCount ++;

	while (1) {
		if (device != activeDevice) {
			if (device) {
				pcap_close(handle);
			}
			device = activeDevice;
			if (!device) {
				g_cond_signal(packetQueueCond);
				threadCount --;

				return;
			}
			handle = pcap_open_live((char*)device->name, BUFSIZ, 0, 10, pcap_errbuf);
			if (handle == NULL) {
				char BUF[PCAP_ERRBUF_SIZE + 128];
				snprintf(BUF, PCAP_ERRBUF_SIZE + 128, "Not sniffing. Error while initializing %s: %s", device->name, pcap_errbuf);
				drawStatus(BUF);
				break;
			}
#if HAVE_PCAP_SETNONBLOCK
			pcap_setnonblock(handle, 1, NULL);
#endif
			deviceDataLink = pcap_datalink(handle);
		}
		packetReceived = FALSE;
		pcap_dispatch(handle, 10, (pcap_handler)dispatch_callback, NULL);
		if (!packetReceived)
			g_thread_yield();
	}

	threadCount --;
}

void    initDefaults() {
	ntop_resolv_entry *entry;
	entry = g_new0(ntop_resolv_entry, 1);
	entry->name = "UNKNOWN";
	g_hash_table_insert(resolverCache, GUINT_TO_POINTER(0), entry);
}

int main(int argc, char ** argv) {
	int a;
	char * deviceName = NULL;

	
	for (a=1; a<argc; a++) {
		if (!strcmp(argv[a], "-v") || !strcmp(argv[a], "--version")) {
			printf(PACKAGE_STRING "\nWritten by Jakub Skopal <j@kubs.cz>\n\nSee copyright in the COPYING file.\n");
			exit(0);
		}
		if (!strcmp(argv[a], "-h") || !strcmp(argv[a], "--help")) {
			printf(	"Usage: jnettop [-hv] [-i interface] [-d filename]\n"
				"\n"
				"    -h, --help             display this help message\n"
				"    -v, --version          display version information\n"
				"    -i, --interface name   capture packets on specified interface\n"
				"    -d, --debug filename   write debug information into file\n"
				"\n"
				"Report bugs to <j@kubs.cz>\n");
			exit(0);
		}
		if (!strcmp(argv[a], "-i") || !strcmp(argv[a], "--interface")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch required argument\n", argv[a]);
				exit(255);
			}
			deviceName = argv[++a];
			continue;
		}
		if (!strcmp(argv[a], "-d") || !strcmp(argv[a], "--debug")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch requires filename to debug to as an argument\n", argv[a]);
				exit(255);
			}
			debugFile = fopen(argv[++a], "w");
			if (!debugFile) {
				perror("Could not open debug file");
				exit(255);
			}
			continue;
		}
		fprintf(stderr, "Unknown argument: %s\n", argv[a]);
		exit(255);
	}

	if (deviceName) {
		createDevice(deviceName);
	} else {
		lookupDevices();
	}

	if (!devices_count) {
		fprintf(stderr, "Autodiscovery found no devices. Specify device you want to watch with -i parameter\n");
		exit(255);
	}

	newDevice = devices;

	g_thread_init(NULL);

	packetQueue = g_queue_new();
	packetQueueCond = g_cond_new();
	packetQueueMutex = g_mutex_new();

	resolverCache = g_hash_table_new((GHashFunc)hashResolvEntry, (GEqualFunc)compareResolvEntry);
	resolverCacheMutex = g_mutex_new();

	streamTable = g_hash_table_new((GHashFunc)hashStream, (GEqualFunc)compareStream);
	streamTableMutex = g_mutex_new();

	streamArray = g_ptr_array_new();
	streamArrayMutex = g_mutex_new();

	displayStreamsMutex = g_mutex_new();
	freePacketStackMutex = g_mutex_new();

	initDefaults();

	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);

	resolverThreadPool = g_thread_pool_new((GFunc)resolverThreadFunc, NULL, 5, FALSE, NULL);

	while (newDevice) {

		clearStatistics();
		activeDevice = newDevice;
		newDevice = NULL;
		displayStreams = NULL;
		displayStreamsCount = 0;

		g_get_current_time(&startTime);
		totalBytes = 0;
		totalPackets = 0;
		totalBPS = 0;

		activeLines = 0;
		activeColumns = 0;

		clear();
		drawScreen();
		
		snifferThread = g_thread_create((GThreadFunc)snifferThreadFunc, NULL, TRUE, NULL);
		sorterThread = g_thread_create((GThreadFunc)sorterThreadFunc, NULL, FALSE, NULL);
		processorThread = g_thread_create((GThreadFunc)processorThreadFunc, NULL, FALSE, NULL);
		displayThread = g_thread_create((GThreadFunc)displayThreadFunc, NULL, TRUE, NULL);
		g_thread_join(displayThread);

		if (!newDevice) {
			// In case we're not switching to another device, we can happily finish
			// after our display thread dies. (mind the endwin())
			break;
		}

		g_thread_join(snifferThread);
		
		while (threadCount) {
			g_thread_yield();
		}
	}

	if (debugFile) {
		fclose(debugFile);
	}

	endwin();
}
