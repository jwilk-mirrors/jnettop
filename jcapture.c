#include "jbase.h"
#include "jcapture.h"

/*
 * This stuff was copied out of Ethereal package by Gerald Combs <gerald@ethereal.com>
 * The point is, that we can use select() on platforms, where packet socket is
 * select()able. This prevents the capturer from taking all the processor time
 * doing g_tread_yeald() all the time.
 * Currently, this should happen only on BSD systems
 */
#if !defined(BSD)
# define USE_SELECT
#endif

const jbase_device	*jcapture_ActiveDevice;
const char		*jcapture_ActiveBpfFilterText;
GQueue			*jcapture_PacketQueue;
GMutex			*jcapture_PacketQueueMutex;
GCond			*jcapture_PacketQueueCond;
volatile gboolean	jcapture_IsRunning;

struct bpf_program	activeBpfFilterProgram;

gboolean		onoffPromisc;

GThread			*snifferThread;

GTrashStack		*freePacketStack = NULL;
int			freePacketStackSize = 0;
GMutex			*freePacketStackMutex;

gboolean		isEnding;

gboolean jcapture_Setup() {
	jcapture_ActiveDevice = NULL;
	jcapture_PacketQueue = g_queue_new();
	jcapture_PacketQueueCond = g_cond_new();
	jcapture_PacketQueueMutex = g_mutex_new();
	freePacketStackMutex = g_mutex_new();
	return TRUE;
}

void jcapture_SetPromisc(gboolean value) {
	onoffPromisc = value;
}

gboolean jcapture_SetDevice(const jbase_device *device) {
	if (jcapture_IsRunning) {
		debug("Attempt to set jcapture device while jcapture is running");
		return FALSE;
	}
	jcapture_ActiveDevice = device;
	return TRUE;
}

gboolean jcapture_SetBpfFilterText(const char *filterText) {
	if (jcapture_IsRunning) {
		debug("Attempt to set jcapture filter while jcapture is running");
		return FALSE;
	}
	jcapture_ActiveBpfFilterText = filterText;
	return TRUE;
}

jbase_packet *jbase_packet_Alloc() {
	jbase_packet *ptr;
	g_mutex_lock(freePacketStackMutex);
	ptr = (jbase_packet *)g_trash_stack_pop(&freePacketStack);
	if (ptr) {
		freePacketStackSize --;
	}
	g_mutex_unlock(freePacketStackMutex);
	if (!ptr) {
		ptr = g_new(jbase_packet, 1);
	}
	return ptr;
}

void jcapture_packet_Free(jbase_packet *packet) {
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

gboolean	packetReceived;
int		deviceDataLink;

static void     dispatch_callback(const u_char *udata, const struct pcap_pkthdr *hdr, const guchar *pcappacket) {
	jbase_packet * packet;
	packet = jbase_packet_Alloc();
	packet->device = jcapture_ActiveDevice;
	packet->dataLink = deviceDataLink;
	memcpy(&(packet->header), hdr, sizeof(struct pcap_pkthdr));
	if (packet->header.caplen > BUFSIZ)
		packet->header.caplen = BUFSIZ;
	memcpy(packet->data, pcappacket, packet->header.caplen);
	g_mutex_lock(jcapture_PacketQueueMutex);
	g_queue_push_head(jcapture_PacketQueue, packet);
	g_mutex_unlock(jcapture_PacketQueueMutex);
	g_cond_signal(jcapture_PacketQueueCond);
}

static gpointer snifferThreadFunc(gpointer data) {
	pcap_t		*handle = NULL;
	const jbase_device	*device = NULL;
	gchar		pcap_errbuf[PCAP_ERRBUF_SIZE];
	gboolean	isFilterUsed = FALSE;

	threadCount ++;

	while (!isEnding) {
		if (device != jcapture_ActiveDevice) {
			if (isFilterUsed) {
				JBASE_PCAP_FREECODE(handle, &activeBpfFilterProgram);
			}
			if (device) {
				pcap_close(handle);
			}
			device = jcapture_ActiveDevice;
			if (!device) {
				g_cond_signal(jcapture_PacketQueueCond);
				threadCount --;
				jcapture_IsRunning = TRUE;
				return NULL;
			}
			handle = pcap_open_live((char*)device->name, BUFSIZ, onoffPromisc, 10, pcap_errbuf);
			if (handle == NULL) {
				char BUF[PCAP_ERRBUF_SIZE + 128];
				snprintf(BUF, PCAP_ERRBUF_SIZE + 128, "Not sniffing. Error while initializing %s: %s", device->name, pcap_errbuf);
				jbase_cb_DrawStatus(BUF);
				break;
			}
#if HAVE_PCAP_SETNONBLOCK
			pcap_setnonblock(handle, 1, NULL);
#endif
			if (jcapture_ActiveBpfFilterText) {
				isFilterUsed = FALSE;
				debug("Filter: %s\n", jcapture_ActiveBpfFilterText);
				if (pcap_compile(handle, &activeBpfFilterProgram, (char *)jcapture_ActiveBpfFilterText, 0, 0xFFFFFFFF) == -1) {
					char BUF[PCAP_ERRBUF_SIZE + 128];
					snprintf(BUF, PCAP_ERRBUF_SIZE + 128, "Filter not applied. Error while compiling: %s", pcap_geterr(handle));
					jbase_cb_DrawStatus(BUF);
				} else {
					if (pcap_setfilter(handle, &activeBpfFilterProgram) == -1) {
						char BUF[PCAP_ERRBUF_SIZE + 128];
						snprintf(BUF, PCAP_ERRBUF_SIZE + 128, "Filter not applied. setfilter(): %s", pcap_geterr(handle));
						jbase_cb_DrawStatus(BUF);
					}
					isFilterUsed = TRUE;
				}
			}
			deviceDataLink = pcap_datalink(handle);
		}

#ifdef USE_SELECT
		{
			int pcap_fd = pcap_fileno(handle);
			int sel_ret;
			struct timeval timeout;
			fd_set set1;

			FD_ZERO(&set1);
			FD_SET(pcap_fd, &set1);
			timeout.tv_sec = 0;
			timeout.tv_usec = 500000;
			sel_ret = select(pcap_fd+1, &set1, NULL, NULL, &timeout);
			if (sel_ret > 0) {
				pcap_dispatch(handle, 10, (pcap_handler)dispatch_callback, NULL);
			}
		}
		
#else
		{
			packetReceived = FALSE;
			pcap_dispatch(handle, 10, (pcap_handler)dispatch_callback, NULL);
			if (!packetReceived)
				g_thread_yield();
		}
#endif
	}

	threadCount --;
	jcapture_IsRunning = FALSE;
	return NULL;
}


gboolean jcapture_Start() {
	isEnding = FALSE;
	jcapture_IsRunning = TRUE;
	snifferThread = g_thread_create((GThreadFunc)snifferThreadFunc, NULL, TRUE, NULL);
	return TRUE;
}

gboolean jcapture_Kill() {
	gpointer ptr;
	if (!jcapture_IsRunning || isEnding) {
		debug("Attempt to kill jcapture which is not running.");
		return FALSE;
	}
	isEnding = TRUE;
	g_thread_join(snifferThread);
	g_mutex_lock(jcapture_PacketQueueMutex);
	while ((ptr = g_queue_pop_tail(jcapture_PacketQueue))) {
		g_free(ptr);
	}
	g_mutex_unlock(jcapture_PacketQueueMutex);
	g_cond_signal(jcapture_PacketQueueCond);
	return TRUE;
}
