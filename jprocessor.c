#include "jbase.h"
#include "jcapture.h"
#include "jprocessor.h"
#include "jresolver.h"

GThread			*processorThread;
jprocessor_stats	jprocessor_Stats;
GHashTable		*jprocessor_StreamTable;
GMutex			*jprocessor_StreamTableMutex;
GPtrArray		*jprocessor_StreamArray;
GMutex			*jprocessor_StreamArrayMutex;
guint			jprocessor_LocalAggregation;
guint			jprocessor_RemoteAggregation;
gboolean		jprocessor_ContentFiltering;

static void	markAllAsDead() {
	int i;
	g_mutex_lock(jprocessor_StreamArrayMutex);
	for (i=0; i<jprocessor_StreamArray->len; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(jprocessor_StreamArray, i);
		s->dead=6;
	}
	g_mutex_unlock(jprocessor_StreamArrayMutex);
}

void		jprocessor_SetLocalAggregation(guint localAggregation) {
	if (localAggregation == jprocessor_LocalAggregation)
		return;
	markAllAsDead();
	jprocessor_LocalAggregation = localAggregation;
}

void		jprocessor_SetRemoteAggregation(guint remoteAggregation) {
	if (remoteAggregation == jprocessor_RemoteAggregation)
		return;
	markAllAsDead();
	jprocessor_RemoteAggregation = remoteAggregation;
}

void		jprocessor_SetContentFiltering(gboolean value) {
	jprocessor_ContentFiltering = value;
}

static guint hashStream(gconstpointer key) {
	const jbase_stream	*stream = (const jbase_stream *)key;
	guint hash = 0;
	hash = stream->src.addr6.ntop_s6_addr32[0];
	hash ^= stream->src.addr6.ntop_s6_addr32[1];
	hash ^= stream->src.addr6.ntop_s6_addr32[2];
	hash ^= stream->src.addr6.ntop_s6_addr32[3];
	hash ^= stream->dst.addr6.ntop_s6_addr32[0];
	hash ^= stream->dst.addr6.ntop_s6_addr32[1];
	hash ^= stream->dst.addr6.ntop_s6_addr32[2];
	hash ^= stream->dst.addr6.ntop_s6_addr32[3];
	hash ^= (((guint)stream->srcport) << 16) + (guint)stream->dstport;
	return hash;
}

static gboolean compareStream(gconstpointer a, gconstpointer b) {
	const jbase_stream *astr = (const jbase_stream *)a;
	const jbase_stream *bstr = (const jbase_stream *)b;
	if (astr->proto == bstr->proto &&
			astr->srcport == bstr->srcport &&
			astr->dstport == bstr->dstport &&
			IN6_ARE_ADDR_EQUAL(&astr->src.addr6, &bstr->src.addr6) &&
			IN6_ARE_ADDR_EQUAL(&astr->dst.addr6, &bstr->dst.addr6)
			)
		return TRUE;
	return FALSE;
}

gboolean	jprocessor_Setup() {
	jprocessor_StreamTable = g_hash_table_new((GHashFunc)hashStream, (GEqualFunc)compareStream);
	jprocessor_StreamTableMutex = g_mutex_new();
	jprocessor_StreamArray = g_ptr_array_new();
	jprocessor_StreamArrayMutex = g_mutex_new();
	jprocessor_ResetStats();
	return TRUE;
}

void	jprocessor_ResetStats() {
	memset(&jprocessor_Stats, 0, sizeof(jprocessor_Stats));
	g_get_current_time(&jprocessor_Stats.startTime);
}

void	jprocessor_UpdateBPS() {
	GTimeVal	currentDateTime;
	uint		i;
	guint32		srcbps = 0;
	guint32		dstbps = 0;
	guint32		srcpps = 0;
	guint32		dstpps = 0;

	g_get_current_time(&currentDateTime);
	currentDateTime.tv_sec ++;

	for (i=0; i<jprocessor_StreamArray->len; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(jprocessor_StreamArray, i);
		int byteswindow = ( currentDateTime.tv_sec - s->firstSeen.tv_sec );
		if (byteswindow > HISTORY_LENGTH)
			byteswindow = HISTORY_LENGTH;
			
		srcbps += (s->srcbps = s->hsrcbytessum / byteswindow);
		s->hsrcbytessum -= s->hsrcbytes[HISTORY_LENGTH-1];
		memmove(s->hsrcbytes+1, s->hsrcbytes, sizeof(guint)*(HISTORY_LENGTH-1));
		s->hsrcbytes[0] = 0;
		dstbps += (s->dstbps = s->hdstbytessum / byteswindow);
		s->hdstbytessum -= s->hdstbytes[HISTORY_LENGTH-1];
		memmove(s->hdstbytes+1, s->hdstbytes, sizeof(guint)*(HISTORY_LENGTH-1));
		s->hdstbytes[0] = 0;
		s->totalbps = s->srcbps + s->dstbps;
		
		srcpps += (s->srcpps = s->hsrcpacketssum / byteswindow);
		s->hsrcpacketssum -= s->hsrcpackets[HISTORY_LENGTH-1];
		memmove(s->hsrcpackets+1, s->hsrcpackets, sizeof(guint)*(HISTORY_LENGTH-1));
		s->hsrcpackets[0] = 0;
		dstpps += (s->dstpps = s->hdstpacketssum / byteswindow);
		s->hdstpacketssum -= s->hdstpackets[HISTORY_LENGTH-1];
		memmove(s->hdstpackets+1, s->hdstpackets, sizeof(guint)*(HISTORY_LENGTH-1));
		s->hdstpackets[0] = 0;
		s->totalpps = s->srcpps + s->dstpps;
		
		if (!s->dead && currentDateTime.tv_sec - s->lastSeen.tv_sec > 10) {
			s->dead ++;
		}
	}

	jprocessor_Stats.totalSrcBPS = srcbps;
	jprocessor_Stats.totalDstBPS = dstbps;
	jprocessor_Stats.totalBPS = srcbps + dstbps;
	jprocessor_Stats.totalSrcPPS = srcpps;
	jprocessor_Stats.totalDstPPS = dstpps;
	jprocessor_Stats.totalPPS = srcpps + dstpps;
}

static void	setToHostAggregation(int af, jbase_mutableaddress *addr) {
	switch (af) {
		case AF_INET:
			addr->addr4.s_addr = htonl(0x01000000);
			break;
		case AF_INET6:
			addr->addr6.ntop_s6_addr32[0] = 0x0;
			addr->addr6.ntop_s6_addr32[1] = 0x0;
			addr->addr6.ntop_s6_addr32[2] = 0x0;
			addr->addr6.ntop_s6_addr32[3] = htonl(0x01000000);
			break;
	}
}


static void	aggregateStream(jbase_stream *stream) {
	switch (jprocessor_LocalAggregation) {
		case AGG_HOST:
			setToHostAggregation(JBASE_AF(stream->proto), &stream->src);
		case AGG_PORT:
			stream->srcport = -1;
	}
	switch (jprocessor_RemoteAggregation) {
		case AGG_HOST:
			setToHostAggregation(JBASE_AF(stream->proto), &stream->dst);
		case AGG_PORT:
			stream->dstport = -1;
	}
}

static void	sortPacket(const jbase_packet *packet) {
	jbase_stream	packetStream;
	jbase_stream	*stat;
	jbase_payload_info	payloadInfo[JBASE_PROTO_MAX];
	jprocessor_Stats.totalBytes += packet->header.len;
	jprocessor_Stats.totalPackets ++;
	memset(&packetStream, 0, sizeof(jbase_stream));
	resolveStream(packet, &packetStream, payloadInfo);
	aggregateStream(&packetStream);
	g_mutex_lock(jprocessor_StreamTableMutex);
	stat = (jbase_stream *)g_hash_table_lookup(jprocessor_StreamTable, &packetStream);
	if (stat == NULL) {
		stat = g_new0(jbase_stream, 1);
		memcpy(stat, &packetStream, sizeof(jbase_stream));
		g_get_current_time(&stat->firstSeen);
		g_hash_table_insert(jprocessor_StreamTable, stat, stat);
		g_mutex_unlock(jprocessor_StreamTableMutex);

		if (jprocessor_ContentFiltering)
			assignDataFilter(stat);
		
		stat->srcresolv = jresolver_Lookup(JBASE_AF(packetStream.proto), &packetStream.src);
		stat->dstresolv = jresolver_Lookup(JBASE_AF(packetStream.proto), &packetStream.dst);

		g_mutex_lock(jprocessor_StreamArrayMutex);
		g_ptr_array_add(jprocessor_StreamArray, stat);
		g_mutex_unlock(jprocessor_StreamArrayMutex);
	} else {
		g_mutex_unlock(jprocessor_StreamTableMutex);
	}
	if (packetStream.direction) {
		stat->dstbytes += packet->header.len;
		stat->dstpackets ++;
		*stat->hdstbytes += packet->header.len;
		stat->hdstpackets[0]++;
		stat->hdstbytessum += packet->header.len;
		stat->hdstpacketssum++;
		jprocessor_Stats.totalDstBytes += packet->header.len;
		jprocessor_Stats.totalDstPackets++;
	} else {
		stat->srcbytes += packet->header.len;
		stat->srcpackets ++;
		*stat->hsrcbytes += packet->header.len;
		stat->hsrcpackets[0]++;
		stat->hsrcbytessum += packet->header.len;
		stat->hsrcpacketssum++;
		jprocessor_Stats.totalSrcBytes += packet->header.len;
		jprocessor_Stats.totalSrcPackets++;
	}
	stat->totalbytes += packet->header.len;
	stat->totalpackets ++;
	g_get_current_time(&stat->lastSeen);

	if (jprocessor_ContentFiltering && stat->filterDataFunc) {
		stat->filterDataFunc(stat, packet, packetStream.direction, payloadInfo);
	}
}

static gpointer processorThreadFunc(gpointer data) {
	threadCount ++;
	g_mutex_lock(jcapture_PacketQueueMutex);
	while (jcapture_IsRunning) {
		jbase_packet	*packet;
		packet = (jbase_packet *)g_queue_pop_tail(jcapture_PacketQueue);
		if (packet == NULL) {
			g_cond_wait(jcapture_PacketQueueCond, jcapture_PacketQueueMutex);
			continue;
		}

		g_mutex_unlock(jcapture_PacketQueueMutex);

		sortPacket(packet);
		jcapture_packet_Free(packet);

		g_mutex_lock(jcapture_PacketQueueMutex);
	}
	g_mutex_unlock(jcapture_PacketQueueMutex);
	threadCount --;

	return NULL;
}

gboolean	jprocessor_Start() {
	processorThread = g_thread_create((GThreadFunc)processorThreadFunc, NULL, FALSE, NULL);
	return TRUE;
}
