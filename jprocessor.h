#ifndef __JPROCESSOR_H__
#define __JPROCESSOR_H__

#include "jbase.h"
#include "jcapture.h"

typedef struct __jprocessor_stats {
	GTimeVal	startTime;
	guint32		totalSrcBytes, totalDstBytes, totalBytes;
	guint32		totalSrcPackets, totalDstPackets, totalPackets;
	guint32		totalSrcBPS, totalDstBPS, totalBPS;
	guint32		totalSrcPPS, totalDstPPS, totalPPS;
} jprocessor_stats;

gboolean	jprocessor_Setup();
void		jprocessor_ResetStats();
void		jprocessor_UpdateBPS();
void		jprocessor_SetLocalAggregation(guint localAggregation);
void		jprocessor_SetRemoteAggregation(guint remoteAggregation);
void		jprocessor_SetContentFiltering(gboolean value);
void		jprocessor_SetSorting(gboolean onoff, GCompareFunc compareFunction);
void		jprocessor_SetMaxDeadTime(gint maxDeadTime);
gboolean	jprocessor_Start();

gint jprocessor_compare_ByPacketsStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByBytesStat(gconstpointer a, gconstpointer b);

extern jprocessor_stats	jprocessor_Stats;

extern GPtrArray	*jprocessor_StreamArray;
extern GMutex		*jprocessor_StreamArrayMutex;
extern GCond		*jprocessor_StreamArrayCond;
extern guint		jprocessor_LocalAggregation;
extern guint		jprocessor_RemoteAggregation;
extern gboolean		jprocessor_ContentFiltering;
extern gboolean		jprocessor_Sorting;
extern GCompareFunc	jprocessor_SortingFunction;
extern gint		jprocessor_MaxDeadTime;

#endif

