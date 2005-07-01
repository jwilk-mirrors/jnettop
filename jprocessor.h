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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jprocessor.h,v 1.4 2005-07-01 10:02:08 merunka Exp $
 *
 */

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

typedef void (*ProcessStreamsFunc) (GPtrArray *streamArray);

gboolean	jprocessor_Setup();
void		jprocessor_ResetStats();
void		jprocessor_UpdateBPS();
void		jprocessor_SetLocalAggregation(guint localAggregation);
void		jprocessor_SetRemoteAggregation(guint remoteAggregation);
void		jprocessor_SetContentFiltering(gboolean value);
void		jprocessor_SetSorting(gboolean onoff, GCompareFunc compareFunction);
void		jprocessor_SetMaxDeadTime(gint maxDeadTime);
void		jprocessor_SetProcessStreamsFunc(ProcessStreamsFunc processFunction);
gboolean	jprocessor_Start();

gint jprocessor_compare_ByPacketsStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByBytesStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByTxBytesStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByRxBytesStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByTxPacketsStat(gconstpointer a, gconstpointer b);
gint jprocessor_compare_ByRxPacketsStat(gconstpointer a, gconstpointer b);

extern jprocessor_stats	jprocessor_Stats;

extern guint		jprocessor_LocalAggregation;
extern guint		jprocessor_RemoteAggregation;
extern gboolean		jprocessor_ContentFiltering;
extern gboolean		jprocessor_Sorting;
extern GCompareFunc	jprocessor_SortingFunction;
extern gint		jprocessor_MaxDeadTime;
extern ProcessStreamsFunc jprocessor_ProcessStreamsFunc;

#endif

