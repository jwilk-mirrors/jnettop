/*
 *    jnettop, network online traffic visualiser
 *    Copyright (C) 2002-2006 Jakub Skopal
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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/juiadisplay.c,v 1.2 2006-05-14 23:55:40 merunka Exp $
 *
 */

#include "jbase.h"
#include "jdevice.h"
#include "jprocessor.h"
#include "jconfig.h"
#include "jutil.h"
#include "juiadisplay.h"

#ifdef ENABLE_UIA

#define LISTEN_ERROR_ANSWER			"listen:ASCII:NAK:Error compiling rule: syntax error\n\n"
#define ERROR_MAXIMUM_TIMEOUT_EXPIRED		"\n\n"
#define GET_REQUEST_END_BOUNDARY		"\n"

#define MAXRECV					32769
#define MAX_COMMAND_TIMEOUT_MINUTES		5
#define SMALL_WAIT				100
#define DEFAULT_LINE_COUNT			15

GMutex		*displayStreamsMutex;
jbase_stream	**displayStreams = NULL;
int		displayStreamsCount = 0;
gboolean	bHaveData = FALSE;
int		nLineCount = DEFAULT_LINE_COUNT;

gboolean	onoffPackets;
gboolean	onoffBitValues;

static void processStreamsFunc(GPtrArray * streamArray) {
	guint		i,j;
	guint		lines, oldLines;
	jbase_stream	**streams,**oldStreams;

	streams = g_new0(jbase_stream *, nLineCount);
	
	for (i=0,j=0; i<streamArray->len && j<nLineCount; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
		if (s->dead > 5) {
			continue;
		}
		s->displayed ++;
		streams[j++] = s;
	}

	lines = j;

	g_mutex_lock(displayStreamsMutex);
	if(lines > 0)
		bHaveData = TRUE;
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
}

static gchar * get_next_token_colon_delim(gchar ** text){
	gchar * tmp = NULL;
	if(!text)
		return NULL;

	tmp = strsep(text, ":");
	if(tmp && *tmp != '\0'){
		return strdup(tmp);
	}else{
		return NULL;
	}
}

void	doWriteFormatedNetworkStreams(pid_t nSessionID, gulong lUSecsWaited) {
	int i;
	gchar buffer[32768];
	gchar srcport[10], dstport[10], srcbps[10], dstbps[10], bps[10];

	debug(LOG_DEBUG, "streams count %d", displayStreamsCount);

	// dump out the totals line...
	jutil_formatNumber(onoffPackets?jprocessor_Stats.totalPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalBPS, onoffPackets, bps, 6);
	g_strlcat(bps, "/s", sizeof(bps));
	jutil_formatNumber(onoffPackets?jprocessor_Stats.totalSrcPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalSrcBPS, onoffPackets, srcbps, 6);
	g_strlcat(srcbps, "/s", sizeof(srcbps));
	jutil_formatNumber(onoffPackets?jprocessor_Stats.totalDstPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalDstBPS, onoffPackets, dstbps, 6);
	g_strlcat(dstbps, "/s", sizeof(dstbps));

	sprintf(buffer, "get:ASCII:%d:%d:ACK:TOTAL:::::%s:%s:%s\n", nSessionID, (int)lUSecsWaited, srcbps, dstbps, bps);
	//debug(LOG_DEBUG, "sending %d characters '%s'", strlen(buffer), buffer);
	printf("%s", buffer);

	for (i=0; i< displayStreamsCount; i++) {
		gchar srcaddr[INET6_ADDRSTRLEN + 1], dstaddr[INET6_ADDRSTRLEN + 1];
		gchar total[10], totalsrc[10], totaldst[10];
		uint tmp;
		gchar linebuffer[1024];
		const gchar *psrcaddr, *pdstaddr;
		jbase_stream *s = displayStreams[i];
		tmp = onoffPackets ? s->totalpps : (onoffBitValues?8:1)*s->totalbps;
		jutil_formatNumber(tmp, onoffPackets, bps, 6);
		g_strlcat(bps, "/s", sizeof(bps));
		tmp = onoffPackets ? s->srcpps : (onoffBitValues?8:1)*s->srcbps;
		jutil_formatNumber(tmp, onoffPackets, srcbps, 6);
		g_strlcat(srcbps, "/s", sizeof(srcbps));
		tmp = onoffPackets ? s->dstpps : (onoffBitValues?8:1)*s->dstbps;
		jutil_formatNumber(tmp, onoffPackets, dstbps, 6);
		g_strlcat(dstbps, "/s", sizeof(dstbps));
		jutil_formatNumber(onoffPackets ? s->totalpackets : s->totalbytes, onoffPackets, total, 6);
		jutil_formatNumber(onoffPackets ? s->srcpackets : s->srcbytes, onoffPackets, totalsrc, 6);
		jutil_formatNumber(onoffPackets ? s->dstpackets : s->dstbytes, onoffPackets, totaldst, 6);
		jutil_Address2String(JBASE_AF(s->proto), &s->src, srcaddr, INET6_ADDRSTRLEN);
		if (s->srcresolv == NULL || s->srcresolv->name == NULL) {
			psrcaddr = srcaddr;
		} else {
			psrcaddr = s->srcresolv->name;
		}
		jutil_Address2String(JBASE_AF(s->proto), &s->dst, dstaddr, INET6_ADDRSTRLEN);
		if (s->dstresolv == NULL || s->dstresolv->name == NULL) {
			pdstaddr = dstaddr;
		} else {
			pdstaddr = s->dstresolv->name;
		}
		if (s->srcport == -1)
			strcpy(srcport, "AGGR.");
		else
			sprintf(srcport, "%d", s->srcport);
		if (s->dstport == -1)
			strcpy(dstport, "AGGR.");
		else
			sprintf(dstport, "%d", s->dstport);
		sprintf(linebuffer, "%s:%s", psrcaddr, pdstaddr);
		
		sprintf(buffer, "get:ASCII:%d:%d:ACK:%s:%s:%s:%s:%s:%s:%s:%s\n", nSessionID, (int)lUSecsWaited, srcaddr, srcport, JBASE_PROTOCOLS[s->proto], dstaddr, dstport, srcbps, dstbps, bps);
		//debug(LOG_DEBUG, "sending %d characters '%s'", strlen(buffer), buffer);
		printf("%s", buffer);
	}
	printf(GET_REQUEST_END_BOUNDARY);
}

static GTimeVal timeNow(){
	GTimeVal timeNow;
	g_get_current_time(&timeNow);
	return timeNow;
}

static void networkConnectionLoop(){
	// get our pid...
	pid_t ourpid = getpid();
	gboolean bExit = FALSE;

	// setup timer here...
	GTimeVal	commandTimeout;
	g_get_current_time(&commandTimeout);

	while(!bExit && (timeNow().tv_sec - commandTimeout.tv_sec < MAX_COMMAND_TIMEOUT_MINUTES * 60)){
		// make sure we don't block forever...
		int nSelectReturn = 0;
		fd_set listenSet;
		struct timeval tm;
		tm.tv_sec = 10;  // wait ten seconds...
		tm.tv_usec = 0;
		FD_ZERO(&listenSet);
		FD_SET(fileno(stdin), &listenSet);

		nSelectReturn = select(fileno(stdin)+1, &listenSet, NULL, NULL, &tm);

		if(nSelectReturn > 0){
			if(FD_ISSET(fileno(stdin), &listenSet)){
				int nDataRecievedCount = 0;
 				gchar data[ MAXRECV + 1];
				bzero(data, MAXRECV);
				nDataRecievedCount = read(fileno(stdin), data, MAXRECV - 2);
								
				if(nDataRecievedCount > 0){
					gchar * strPid = NULL;
					gchar * strType = NULL;
					gchar * strMethod = NULL;
					gchar * strMaxWaitUSecs = NULL;
					gchar * cpdata = data;
					int nIndex;

					// make sure we end the string...
					data[nDataRecievedCount] = ':';
					data[nDataRecievedCount + 1] = '\0';

					// remove any control charaters...
					for(nIndex = 0; nIndex<nDataRecievedCount; nIndex++){
						if(iscntrl(data[nIndex])){
							// this is a control character - change it to a :
							data[nIndex] = ':';
						}
					}

					strMethod = get_next_token_colon_delim(&cpdata);
					strType = get_next_token_colon_delim(&cpdata);
					strPid = get_next_token_colon_delim(&cpdata);
					strMaxWaitUSecs = get_next_token_colon_delim(&cpdata);

					if(strPid && ourpid != atoi(strPid)){
						// error - key id not correct
						debug(LOG_DEBUG, "Invalid session - %s given, %d expected", strPid, ourpid);
						printf(LISTEN_ERROR_ANSWER);
					}else if(strncmp(strMethod, "end", strlen("end")) == 0){
						gchar endAnswer[16384];
						g_get_current_time(&commandTimeout);
						// recived an end command
						sprintf(endAnswer, "end:ASCII:%d:ACK\n\n", ourpid);
						debug(LOG_DEBUG, "Sending '%s'", endAnswer);
						printf("%s", endAnswer);
						bExit = TRUE;
					}else if(strncmp(data, "get", strlen("get")) == 0){
						gulong lMicroSeconds = 0;
						gulong lWaitedSeconds = 0;
						g_get_current_time(&commandTimeout);
						// see how long we should wait...
				
						if(strMaxWaitUSecs)
							lMicroSeconds = atol(strMaxWaitUSecs);
					

						debug(LOG_DEBUG, "waiting for data - will wait %d useconds", lMicroSeconds);
						while(!bHaveData && lWaitedSeconds < lMicroSeconds){
							lWaitedSeconds += SMALL_WAIT;
							g_usleep(SMALL_WAIT);
						}	

						debug(LOG_DEBUG, "waited %d useconds - bHaveData - %d", lWaitedSeconds, bHaveData);

						if(bHaveData){
							// recieved get request
							// lock the mutex...
							g_mutex_lock(displayStreamsMutex);
							doWriteFormatedNetworkStreams(ourpid, lWaitedSeconds);
							g_mutex_unlock(displayStreamsMutex);
						}else{
							debug(LOG_DEBUG, "Timed out waiting for data - sending '%s'", ERROR_MAXIMUM_TIMEOUT_EXPIRED);
							printf(ERROR_MAXIMUM_TIMEOUT_EXPIRED);
						}
					}
					fflush(NULL);
				} // nDataRecievedCount
			} // if(FD_ISSET)
		} // select != -1
	} // while (!bExit) 
	if(!(timeNow().tv_sec - commandTimeout.tv_sec  < MAX_COMMAND_TIMEOUT_MINUTES * 60)){
		// send timeout error
		debug(LOG_WARNING, "Timed out while waiting for get/end command - waited %d seconds", timeNow().tv_sec - commandTimeout.tv_sec);
		printf(ERROR_MAXIMUM_TIMEOUT_EXPIRED);
	}
}

gboolean parseListenLineAndConfig(){
	// wait here for a listen command with parameters...
	gboolean bInitialized = FALSE;

	static gchar data[ MAXRECV + 1];

	pid_t ourpid = getpid();
	gboolean bBitValuesBackup = onoffBitValues;
	GTimeVal	commandTimeout;

	// backup the device name
	gchar strDeviceBackup[30];
	strDeviceBackup[0] = '\0';

	if(jconfig_Settings.deviceName)
		strcpy(strDeviceBackup, jconfig_Settings.deviceName);


	// setup timer here...
	g_get_current_time(&commandTimeout);


	// keep going while we have not initialized, aren't shutting down, and haven't timed out
	while(!bInitialized && (timeNow().tv_sec - commandTimeout.tv_sec < MAX_COMMAND_TIMEOUT_MINUTES * 60)){
		// make sure we don't block forever...
		fd_set listenSet;
		struct timeval tm;
		int nSelectReturn = 0;
		FD_ZERO(&listenSet);
		FD_SET(fileno(stdin), &listenSet);
		tm.tv_sec = 10;  // wait ten seconds...
		tm.tv_usec = 0;
		nSelectReturn = select(fileno(stdin)+1, &listenSet, NULL, NULL, &tm);

		if(nSelectReturn != -1){
		// try to read stdout...
			if(FD_ISSET(fileno(stdin), &listenSet)){
				int nDataRecievedCount = read(fileno(stdin), data, MAXRECV - 2);
											
				if(nDataRecievedCount > 0){
					int nIndex;
					gchar * strMethod = NULL;
					gchar * strType = NULL;
					gchar * strDevice = NULL;
					gchar * strBits = NULL;
					gchar * strFilter = NULL;
					gchar * strMaxLines = NULL;
					gchar * cpdata = data; //(gchar *) strdup(data);

					// make sure we end the string...
					data[nDataRecievedCount] = ':';
					data[nDataRecievedCount+1] = '\0';

					// clear the bpf filter...
					JCONFIG_BPFFILTERS_SETNONE;
					// reset the device name
					if(strlen(strDeviceBackup) > 0){
						strcpy(jconfig_Settings.deviceName, strDeviceBackup);
					}	
					// reset the bit values
					onoffBitValues = bBitValuesBackup;

					// remove any control charaters...
					for(nIndex = 0; nIndex<nDataRecievedCount; nIndex++){
						if(iscntrl(data[nIndex])){
							// this is a control character - change it to a :
							data[nIndex] = ':';
						}	
					}	

					strMethod = get_next_token_colon_delim(&cpdata);
					strType = get_next_token_colon_delim(&cpdata);
					strDevice = get_next_token_colon_delim(&cpdata);
					strBits = get_next_token_colon_delim(&cpdata);
					strFilter = get_next_token_colon_delim(&cpdata);
					strMaxLines = get_next_token_colon_delim(&cpdata);

					if(strncmp(strMethod, "listen", strlen("listen")) == 0){
						gchar firstAnswer[16384];
						int nStrMaxLines = 0;
						gboolean bIsRequestGood = TRUE;

						if(strMaxLines)
							nStrMaxLines = atoi(strMaxLines);

						debug(LOG_DEBUG, "Got listen request");
						// got a listen request
		
		
						if(strFilter){
							// set the filter...
							const char * strFilterResult = jutil_ValidateBPFFilter(strFilter);
							if(!strFilterResult){
								// good - set filter
								JCONFIG_BPFFILTERS_SETSELECTEDFILTER(JCONFIG_BPFFILTERS_LEN);
								jconfig_AddBpfFilter("<fromlisten>", strFilter);
							}else{
								debug(LOG_WARNING, "strFilter is BAD - %s", strFilterResult);
								bIsRequestGood = FALSE;
								printf(LISTEN_ERROR_ANSWER);
							}
						}	
		
						if(strDevice){
							debug(LOG_DEBUG, "Setting device name '%s'", strDevice);
							// set the device...
							jconfig_Settings.deviceName = strDevice;
						}
		
						if(strBits && strcmp(strBits, "bits") == 0){
							debug(LOG_DEBUG, "Setting bits");
							// set bits...
							onoffBitValues = TRUE;
						}	
		
				
						if(bIsRequestGood){
							if(nStrMaxLines != 0)
								nLineCount = nStrMaxLines;

							sprintf(firstAnswer, "listen:ASCII:%d:ACK:%s:%s:%s:%s\n\n", ourpid, strDevice, strBits, strFilter, strMaxLines);
							debug(LOG_DEBUG,"sending '%s'", firstAnswer);
							printf(firstAnswer);
							bInitialized = TRUE;
						} else {
							printf(LISTEN_ERROR_ANSWER);
						}
						fflush(NULL);
						// reset the timeout timer..
						g_get_current_time(&commandTimeout);
					}
				} // if recv
			} // if FD_ISSET	
		} // select	
	} // while	
	if(!(timeNow().tv_sec - commandTimeout.tv_sec < MAX_COMMAND_TIMEOUT_MINUTES * 60)){
		// send timeout error
		debug(LOG_NOTICE, "Timed out while waiting for listen command - waited %d seconds", timeNow().tv_sec - commandTimeout.tv_sec);
		printf(ERROR_MAXIMUM_TIMEOUT_EXPIRED);fflush(NULL);
	}
	return bInitialized;
}

static gboolean juiadisplay_PreSetup() {
	setvbuf(stdin, NULL, _IOLBF, 0);
	setvbuf(stdout, NULL, _IOLBF, 0);
	return parseListenLineAndConfig();
}

static void juiadisplay_Setup() {
	displayStreamsMutex = g_mutex_new();

	jprocessor_SetProcessStreamsFunc((ProcessStreamsFunc) processStreamsFunc);
	onoffBitValues = FALSE;
	onoffPackets = FALSE;
}

static gboolean juiadisplay_PreRunSetup() {
	return TRUE;
}

static void juiadisplay_PreRun() {
}

static gboolean juiadisplay_Run() {
	networkConnectionLoop();
	return FALSE;
}

static void juiadisplay_Shutdown() {
}

static void juiadisplay_DrawStatus(const gchar *msg) {
}

static int juiadisplay_ProcessArgument(const gchar **arg, int argc) {
	if (!strcmp(*arg, "-b") || !strcmp(*arg, "--bit-units")) {
		onoffBitValues = TRUE;
		return 1;
	}
	return 0;
}

jbase_display	juiadisplay_Functions = {
	TRUE,
	juiadisplay_PreSetup,
	juiadisplay_Setup,
	juiadisplay_PreRunSetup,
	juiadisplay_PreRun,
	juiadisplay_Run,
	juiadisplay_Shutdown,
	juiadisplay_DrawStatus,
	juiadisplay_ProcessArgument
};

#else

jbase_display	juiadisplay_Functions = { FALSE };

#endif
