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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jprocessor.c,v 1.3 2005-06-30 19:55:19 merunka Exp $
 *
 */

#include "jbase.h"
#include "jcapture.h"
#include "jprocessor.h"
#include "jresolv.h"
#include "jfilter.h"
#include "jresolver.h"

GThread			*processorThread;
GThread			*heartbeatThread;
GHashTable		*streamTable;
GMutex			*streamTableMutex;
GPtrArray		*streamArray;
GMutex			*streamArrayMutex;

jprocessor_stats	jprocessor_Stats;
guint			jprocessor_LocalAggregation;
guint			jprocessor_RemoteAggregation;
gboolean		jprocessor_ContentFiltering;
gboolean		jprocessor_Sorting;
GCompareFunc		jprocessor_SortingFunction;
gint			jprocessor_MaxDeadTime;
ProcessStreamsFunc	jprocessor_ProcessStreamsFunc;

static void freeStream(gpointer ptr) {
	jbase_stream *s = (jbase_stream *)ptr;
	if (s->filterDataFreeFunc)
		s->filterDataFreeFunc(s);
	g_free(s);
}

static void	markAllAsDead() {
	int i;
	g_mutex_lock(streamArrayMutex);
	for (i=0; i<streamArray->len; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
		s->dead=6;
	}
	g_mutex_unlock(streamArrayMutex);
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

void		jprocessor_SetProcessStreamsFunc(ProcessStreamsFunc function) {
	g_mutex_lock(streamArrayMutex);
	jprocessor_ProcessStreamsFunc = function;
	g_mutex_unlock(streamArrayMutex);
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
	streamTable = g_hash_table_new((GHashFunc)hashStream, (GEqualFunc)compareStream);
	streamTableMutex = g_mutex_new();
	streamArray = g_ptr_array_new();
	streamArrayMutex = g_mutex_new();
	jprocessor_ResetStats();
	jprocessor_Sorting = TRUE;
	jprocessor_SortingFunction = (GCompareFunc) jprocessor_compare_ByBytesStat;
	jprocessor_MaxDeadTime = 7;
	return TRUE;
}

static gboolean	removeStreamTableEntry(gpointer key, gpointer value, gpointer user_data) {
	freeStream(key);
	// value is the same pointer as key
	return TRUE;
}

void	jprocessor_ResetStats() {
	int            	i;

	memset(&jprocessor_Stats, 0, sizeof(jprocessor_Stats));
	g_get_current_time(&jprocessor_Stats.startTime);

	for (i=streamArray->len-1; i>=0; i--) {
		g_ptr_array_remove_index_fast(streamArray, i);
	}
	g_hash_table_foreach_remove(streamTable, (GHRFunc)removeStreamTableEntry, NULL);
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

	for (i=0; i<streamArray->len; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
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
	jresolv_ResolveStream(packet, &packetStream, payloadInfo);
	aggregateStream(&packetStream);
	g_mutex_lock(streamTableMutex);
	stat = (jbase_stream *)g_hash_table_lookup(streamTable, &packetStream);
	if (stat == NULL) {
		stat = g_new0(jbase_stream, 1);
		memcpy(stat, &packetStream, sizeof(jbase_stream));
		g_get_current_time(&stat->firstSeen);
		g_hash_table_insert(streamTable, stat, stat);
		g_mutex_unlock(streamTableMutex);

		if (jprocessor_ContentFiltering)
			jfilter_AssignDataFilter(stat);
		
		stat->srcresolv = jresolver_Lookup(JBASE_AF(packetStream.proto), &packetStream.src);
		stat->dstresolv = jresolver_Lookup(JBASE_AF(packetStream.proto), &packetStream.dst);

		g_mutex_lock(streamArrayMutex);
		g_ptr_array_add(streamArray, stat);
		g_mutex_unlock(streamArrayMutex);
	} else {
		g_mutex_unlock(streamTableMutex);
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

static gpointer heartbeatThreadFunc(gpointer data) {
	threadCount ++;

	while (jcapture_IsRunning) {
		guint		i;
		GTimeVal	t;

		g_mutex_lock(streamArrayMutex);

		if (streamArray->len > 0) {
			jprocessor_UpdateBPS();
			if (jprocessor_Sorting)
				g_ptr_array_sort(streamArray, jprocessor_SortingFunction);
		}

		g_mutex_lock(streamTableMutex);

		for (i=0; i<streamArray->len; i++) {
			jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
			if (s->dead && ++s->dead > jprocessor_MaxDeadTime && !s->displayed) {
				g_ptr_array_remove_index_fast ( streamArray, i );
				g_hash_table_remove ( streamTable, s );
				freeStream(s);
				i--;
			}
		}

		g_mutex_unlock(streamTableMutex);

		if (jprocessor_ProcessStreamsFunc != NULL) {
			jprocessor_ProcessStreamsFunc(streamArray);
		}

		g_mutex_unlock(streamArrayMutex);

		g_get_current_time(&t);
		g_usleep(1000000 - t.tv_usec);
	}

	threadCount --;
	return NULL;
}

gboolean	jprocessor_Start() {
	processorThread = g_thread_create((GThreadFunc)processorThreadFunc, NULL, FALSE, NULL);
	heartbeatThread = g_thread_create((GThreadFunc)heartbeatThreadFunc, NULL, FALSE, NULL);
	return TRUE;
}

gint jprocessor_compare_ByPacketsStat(gconstpointer a, gconstpointer b) {
	const jbase_stream	*astr = *(const jbase_stream **)a;
	const jbase_stream	*bstr = *(const jbase_stream **)b;
	if (astr->totalpps > bstr->totalpps)
		return -1;
	else if (astr->totalpps == bstr->totalpps)
		return 0;
	return 1;
}

gint jprocessor_compare_ByBytesStat(gconstpointer a, gconstpointer b) {
	const jbase_stream	*astr = *(const jbase_stream **)a;
	const jbase_stream	*bstr = *(const jbase_stream **)b;
	if (astr->totalbps > bstr->totalbps)
		return -1;
	else if (astr->totalbps == bstr->totalbps)
		return 0;
	return 1;
}

void		jprocessor_SetSorting(gboolean onoff, GCompareFunc compareFunction) {
	jprocessor_Sorting = onoff;
	if (compareFunction != NULL)
		jprocessor_SortingFunction = compareFunction;
}
