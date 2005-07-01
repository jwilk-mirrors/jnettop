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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jnettop.c,v 1.34 2005-07-01 10:02:08 merunka Exp $
 *
 */

#include "jbase.h"
#include "jdevice.h"
#include "jcapture.h"
#include "jprocessor.h"
#include "jresolver.h"
#include "jresolv.h"
#include "jfilter.h"
#include "jutil.h"
#include "jconfig.h"

FILE *			debugFile = NULL;

volatile int		threadCount;

GMutex		*statusMutex;
char		*statusMessage;
GTimeVal	statusTimeout;

gboolean	recycleJnettop;

GMutex		*displayStreamsMutex;
jbase_stream	**displayStreams;
int		displayStreamsCount;
gchar 		line0FormatString[512], line1FormatString[512], line2FormatString[512];

GCompareFunc	currentByBytesCompareFunc = (GCompareFunc) jprocessor_compare_ByBytesStat;
GCompareFunc	currentByPacketsCompareFunc = (GCompareFunc) jprocessor_compare_ByPacketsStat;

gboolean	onoffBitValues;
gboolean	onoffPackets;

#define		DISPLAYMODE_NORMAL		0
#define		DISPLAYMODE_BPFFILTERS		1
#define		DISPLAYMODE_HELP		2
#define		DISPLAYMODE_SORTING		3

int		displayMode = DISPLAYMODE_NORMAL;

WINDOW		*listWindow;

void debug(const char *format, ...) {
	if (debugFile) {
		va_list ap;
		va_start(ap, format);
		vfprintf(debugFile, format, ap);
		va_end(ap);
	}
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
	sprintf(fmt, "%%%d.%df%c", ipart, fpart, !mag && onoffPackets ? 'p' : suffixes[mag]);
	sprintf(buf, fmt, f);
}

void drawStatus(const gchar *msg) {
	g_mutex_lock(statusMutex);
	statusMessage = g_strdup(msg);
	g_get_current_time(&statusTimeout);
	g_time_val_add(&statusTimeout, 1000000);
	g_mutex_unlock(statusMutex);
	attron(A_BOLD);
	mvprintw(2, 0, "%s", statusMessage);
	clrtoeol();
	attroff(A_BOLD);
	refresh();
}

void jbase_cb_DrawStatus(const gchar *msg) {
	drawStatus(msg);
}

void drawScreen() {
	if (LINES != activeLines || COLS != activeColumns || !activeLines || !activeColumns) {
		activeLines = LINES;
		activeColumns = COLS;

		if (activeLines < 20 || activeColumns < 80) {
			endwin();
			fprintf(stderr, "Too small terminal (detected size: %dx%d), minimum required size: 80x20\n", activeColumns, activeLines);
			exit(255);
		}

		attrset(A_NORMAL);

		mvprintw(0, 0, "run XXX:XX:XX device XXXXXXXXXX pkt[f]ilter: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		mvprintw(1, 0, "[c]ntfilter: XXX [b]ps=XXXXXXX [l]ocal aggr.: XXXX [r]emote aggr.: XXXX   ");
		mvprintw(0, activeColumns-1, ".");

		{
			int addrColumns = (activeColumns - 48) / 2;
			sprintf(line0FormatString, "%%-%d.%ds %%7.7s %%7.7s %%8.8s", activeColumns-25, activeColumns-25);
			sprintf(line1FormatString, " %%-%d.%ds %%5.5s %%6.6s  %%-%d.%ds %%5.5s  %%7.7s %%7.7s %%8.8s", addrColumns, addrColumns, addrColumns, addrColumns);
			sprintf(line2FormatString, "  %%-%d.%ds", activeColumns-3, activeColumns-3);
		}

		if (listWindow) {
			delwin(listWindow);
		}
		listWindow = newwin(activeLines-8, activeColumns, 5, 0);
	}
	g_mutex_lock(statusMutex);
	if (statusMessage == NULL) {
		mvprintw(2, 0, "[q]uit [h]elp [s]orting [p]ackets [.] pause ");
		if (jdevice_DevicesCount>1) {
			mvprintw(2, 44, "[0]-[9] switch device");
		}
	} else {
		GTimeVal tv;
		attron(A_BOLD);
		mvprintw(2, 0, statusMessage);
		attroff(A_BOLD);
		g_get_current_time(&tv);
		if (tv.tv_sec >= statusTimeout.tv_sec) {
			g_free(statusMessage);
			statusMessage = NULL;
		}
	}
	g_mutex_unlock(statusMutex);
	clrtoeol();
}

void drawHeader() {
	GTimeVal	currentTime;
	gchar		timeBuffer[32];
	gchar srcbps[10], dstbps[10], bps[10], total[10], totalsrc[10], totaldst[10];
	int i;
	struct tm tm;

	attron(A_BOLD);
	
	g_get_current_time(&currentTime);
	localtime_r(&currentTime.tv_sec, &tm);
	sprintf(timeBuffer, "%3d:%02d:%02d", (int)((currentTime.tv_sec-jprocessor_Stats.startTime.tv_sec)/3600), (int)((currentTime.tv_sec-jprocessor_Stats.startTime.tv_sec)%3600/60), (int)((currentTime.tv_sec-jprocessor_Stats.startTime.tv_sec)%60));
	mvprintw(0, 4, "%s", timeBuffer);
	if (jcapture_ActiveDevice)
		mvprintw(0, 21, "%-10s", jcapture_ActiveDevice->name);
	mvprintw(0, 45, "%-29.29s", jconfig_GetSelectedBpfFilterName());
	mvprintw(1, 13, "%s", jprocessor_ContentFiltering?"on ":"off");
	mvprintw(1, 23, "%s", onoffPackets ? "pckts/s" : (onoffBitValues?"bits/s ":"bytes/s"));
	mvprintw(1, 46, "%s", JBASE_AGGREGATION[jprocessor_LocalAggregation]);
	mvprintw(1, 67, "%s", JBASE_AGGREGATION[jprocessor_RemoteAggregation]);

	attroff(A_BOLD);

	formatNumber(onoffPackets?jprocessor_Stats.totalPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalBPS, bps, 6);
	g_strlcat(bps, "/s", sizeof(bps));
	formatNumber(onoffPackets?jprocessor_Stats.totalSrcPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalSrcBPS, srcbps, 6);
	g_strlcat(srcbps, "/s", sizeof(srcbps));
	formatNumber(onoffPackets?jprocessor_Stats.totalDstPPS:(onoffBitValues?8:1)*jprocessor_Stats.totalDstBPS, dstbps, 6);
	g_strlcat(dstbps, "/s", sizeof(dstbps));
	mvprintw(activeLines-2, 0, line0FormatString, "TOTAL", srcbps, dstbps, bps);

	formatNumber(onoffPackets?jprocessor_Stats.totalPackets:(onoffBitValues?8:1)*jprocessor_Stats.totalBytes, total, 6);
	formatNumber(onoffPackets?jprocessor_Stats.totalSrcPackets:(onoffBitValues?8:1)*jprocessor_Stats.totalSrcBytes, totalsrc, 6);
	formatNumber(onoffPackets?jprocessor_Stats.totalDstPackets:(onoffBitValues?8:1)*jprocessor_Stats.totalDstBytes, totaldst, 6);
	mvprintw(activeLines-1, 0, line1FormatString, "", "", "", "", "", totalsrc, totaldst, total);

	mvchgat(activeLines-2, 0, activeColumns-25, A_BOLD, 0, NULL);

	for (i=0; i<activeColumns; i++)
		mvaddch(activeLines-3, i, ACS_HLINE);

	attron(A_REVERSE);

	mvprintw(3, 0, line0FormatString, "LOCAL <-> REMOTE", onoffPackets ? "TXPPS" : "TXBPS",
		onoffPackets ? "RXPPS" : "RXBPS", onoffPackets ? "TOTALPPS" : "TOTALBPS");
	mvprintw(4, 0, line1FormatString, "(IP)", "PORT", "PROTO", "(IP)", "PORT", "TX", "RX", "TOTAL");

	attroff(A_REVERSE);
}

void processStreamsFunc(GPtrArray * streamArray) {
	guint		i, j;
	int		lines,oldLines;
	jbase_stream	**streams,**oldStreams;

	lines = (activeLines - 8) / 3;
	streams = g_new0(jbase_stream *, lines);
	
	for (i=0,j=0; i<streamArray->len && j<lines; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
		if (s->dead > 5) {
			continue;
		}
		s->displayed ++;
		streams[j++] = s;
	}
	lines = j;

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
}

void	doDisplayStreams() {
	int i;
	for (i=0; i<displayStreamsCount; i++) {
		gchar srcaddr[INET6_ADDRSTRLEN + 1], dstaddr[INET6_ADDRSTRLEN + 1];
		gchar srcport[10], dstport[10], srcbps[10], dstbps[10], bps[10];
		gchar total[10], totalsrc[10], totaldst[10];
		uint tmp;
		gchar linebuffer[1024];
		const gchar *psrcaddr, *pdstaddr;
		jbase_stream *s = displayStreams[i];
		tmp = onoffPackets ? s->totalpps : (onoffBitValues?8:1)*s->totalbps;
		formatNumber(tmp, bps, 6);
		g_strlcat(bps, "/s", sizeof(bps));
		tmp = onoffPackets ? s->srcpps : (onoffBitValues?8:1)*s->srcbps;
		formatNumber(tmp, srcbps, 6);
		g_strlcat(srcbps, "/s", sizeof(srcbps));
		tmp = onoffPackets ? s->dstpps : (onoffBitValues?8:1)*s->dstbps;
		formatNumber(tmp, dstbps, 6);
		g_strlcat(dstbps, "/s", sizeof(dstbps));
		formatNumber(onoffPackets ? s->totalpackets : s->totalbytes, total, 6);
		formatNumber(onoffPackets ? s->srcpackets : s->srcbytes, totalsrc, 6);
		formatNumber(onoffPackets ? s->dstpackets : s->dstbytes, totaldst, 6);
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
		sprintf(linebuffer, "%s <-> %s", psrcaddr, pdstaddr);
		mvwprintw(listWindow, i*3, 0, line0FormatString, linebuffer, srcbps, dstbps, bps);
		mvwchgat(listWindow, i*3, 0, activeColumns-25, A_BOLD, 0, NULL);
		mvwprintw(listWindow, i*3+1, 0, line1FormatString, srcaddr, srcport, JBASE_PROTOCOLS[s->proto], dstaddr, dstport, totalsrc, totaldst, total);
		mvwprintw(listWindow, i*3+2, 0, line2FormatString, s->filterDataString);
	}
}

void    doDisplayWholeScreen() {
	drawScreen();
	drawHeader();
	werase(listWindow);
}

void displayLoop() {
	g_usleep(500000);

	while (jcapture_IsRunning) {
		int i;
		
		g_mutex_lock(displayStreamsMutex);
		doDisplayWholeScreen();

		switch (displayMode) {
		case DISPLAYMODE_NORMAL:
			doDisplayStreams();
			break;
		case DISPLAYMODE_BPFFILTERS:
			wattron(listWindow, A_BOLD);
			mvwprintw(listWindow, 1, 0, "Select rule you want to apply:");
			wattroff(listWindow, A_BOLD);
			mvwprintw(listWindow, 3, 5, "[.] None");
			for (i=0; i<JCONFIG_BPFFILTERS_LEN; i++) {
				mvwprintw(listWindow, i+5, 5, "[%c] %s", 'a'+i, JCONFIG_BPFFILTERS_GETNAME(i));
			}
			if (JCONFIG_BPFFILTERS_LEN == 0) {
				mvwprintw(listWindow, 6, 5, "You have no predefined filter rules. See README file for explanation");
				mvwprintw(listWindow, 7, 5, "on how to predefine filter rules");
			}
			break;
		case DISPLAYMODE_HELP:
			mvwprintw(listWindow, 2, 0, "I must write something here... :)");
			mvwprintw(listWindow, 4, 0, "Press any key to return.");
			break;
		case DISPLAYMODE_SORTING:
			mvwprintw(listWindow, 1, 0, "Select sorting column");
			mvwprintw(listWindow, 3, 0, " [.] on/off");
			mvwprintw(listWindow, 5, 0, " [t]xbps/txpps");
			mvwprintw(listWindow, 6, 0, " [r]xbps/rxpps");
			mvwprintw(listWindow, 7, 0, " total [b]ps/total pps");
		}

		g_mutex_unlock(displayStreamsMutex);

		wnoutrefresh(listWindow);
		refresh();

		i = getch();
		if (i==ERR) {
			g_usleep(1000000);
		} else {
			switch (displayMode) {
			case DISPLAYMODE_NORMAL:
				switch (i) {
					case '.':
						drawStatus("Paused. Press any key to resume.");
						while (getch() == ERR) {
							g_usleep(100000);
						}
						break;
					case 'q':
					case 'Q':
						drawStatus("Please wait, shutting down...");
						jcapture_Kill();
						break;
					case 'c':
						jprocessor_SetContentFiltering( !jprocessor_ContentFiltering );
						break;
					case 'b':
						onoffBitValues = !onoffBitValues;
						break;
					case 'p':
						onoffPackets = !onoffPackets;
						jprocessor_SetSorting( jprocessor_Sorting, onoffPackets ? currentByPacketsCompareFunc : currentByBytesCompareFunc );
						break;
					case 's':
						displayMode = DISPLAYMODE_SORTING;
						break;
					case 'f':
						displayMode = DISPLAYMODE_BPFFILTERS;
						break;
					case 'h':
						displayMode = DISPLAYMODE_HELP;
						break;
					case 'l':
						jprocessor_SetLocalAggregation((jprocessor_LocalAggregation + 1) % 3);
						break;
					case 'r':
						jprocessor_SetRemoteAggregation((jprocessor_RemoteAggregation + 1) % 3);
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
						if (jdevice_DevicesCount>1 && jdevice_DevicesCount>i) {
							drawStatus("Please wait, cleaning up...");
							jconfig_Settings.device = jdevice_Devices + i;
							jconfig_Settings.deviceName = jconfig_Settings.device->name;
							recycleJnettop = TRUE;
							jcapture_Kill();
						}
						break;
				}
				break;
			case DISPLAYMODE_BPFFILTERS:
				if ((i == '.') || ((i >= 'a') && (i < 'a' + (JCONFIG_BPFFILTERS_LEN)))) {
					drawStatus("Please wait, cleaning up...");
					switch (i) {
					case '.':
						JCONFIG_BPFFILTERS_SETNONE;
						break;
					default:
						JCONFIG_BPFFILTERS_SETSELECTEDFILTER(i-'a');
						break;
					}
					recycleJnettop = TRUE;
					jcapture_Kill();
					displayMode = DISPLAYMODE_NORMAL;
					break;
				}
				break;
			case DISPLAYMODE_SORTING:
				switch (i) {
					case '.':
						jprocessor_SetSorting(!jprocessor_Sorting, NULL);
						if (!jprocessor_Sorting)
							drawStatus("Streams sorting suspended.");
						else
							drawStatus("Streams sorting resumed.");
						displayMode = DISPLAYMODE_NORMAL;
						break;
					case 't':
						currentByBytesCompareFunc = (GCompareFunc) jprocessor_compare_ByTxBytesStat;
						currentByPacketsCompareFunc = (GCompareFunc) jprocessor_compare_ByTxPacketsStat;
						jprocessor_SetSorting(-1, onoffPackets ? currentByPacketsCompareFunc : currentByBytesCompareFunc );
						displayMode = DISPLAYMODE_NORMAL;
						break;
					case 'r':
						currentByBytesCompareFunc = (GCompareFunc) jprocessor_compare_ByRxBytesStat;
						currentByPacketsCompareFunc = (GCompareFunc) jprocessor_compare_ByRxPacketsStat;
						jprocessor_SetSorting(-1, onoffPackets ? currentByPacketsCompareFunc : currentByBytesCompareFunc );
						displayMode = DISPLAYMODE_NORMAL;
						break;
					case 'b':
						currentByBytesCompareFunc = (GCompareFunc) jprocessor_compare_ByBytesStat;
						currentByPacketsCompareFunc = (GCompareFunc) jprocessor_compare_ByPacketsStat;
						jprocessor_SetSorting(-1, onoffPackets ? currentByPacketsCompareFunc : currentByBytesCompareFunc );
						displayMode = DISPLAYMODE_NORMAL;
						break;
					default:
						drawStatus("Invalid key.");
						break;
				}
				break;
			case DISPLAYMODE_HELP:
				displayMode = DISPLAYMODE_NORMAL;
				break;
			}
		}
	}
}

void parseCommandLineAndConfig(int argc, char ** argv) {
	char * configFileName = NULL;
	char * selectRuleName = NULL;
	int a;

	jconfig_Setup();
	onoffBitValues = FALSE;
	
	for (a=1; a<argc; a++) {
		if (!strcmp(argv[a], "-v") || !strcmp(argv[a], "--version")) {
			printf(PACKAGE_STRING "\nWritten by Jakub Skopal <j@kubs.cz>\n\nSee copyright in the COPYING file.\n");
			exit(0);
		}
		if (!strcmp(argv[a], "-h") || !strcmp(argv[a], "--help")) {
			printf(	"Usage: jnettop [-hv] [-i interface] [-d filename]\n"
				"\n"
				"    -h, --help             display this help message\n"
				"    -v, --version          display version information\n\n"
				"    -b, --bit-units        show BPS in bits per second, not bytes per second\n"
				"    -c, --content-filter   disable content filtering\n"
				"    -d, --debug filename   write debug information into file\n"
				"    -f, --config-file name reads configuration from file. defaults to ~/.jnettop\n"
				"    -i, --interface name   capture packets on specified interface\n"
				"    --local-aggr arg       set local aggregation to none/host/port\n"
				"    -p, --promiscuous      enable promisc mode on the devices\n"
				"    --remote-aggr arg      set remote aggregation to none/host/port\n"
				"    -s, --select-rule rule selects one of the rules defined in config file\n"
				"                           by it's name\n"
				"    -x, --filter rule      allows for specification of custom filtering rule\n"
				"                           this follows tcpdump(1) syntax. don't forget to\n"
				"                           enclose the filter into quotes when running from shell\n"
				"\n"
				"Report bugs to <j@kubs.cz>\n");
			exit(0);
		}
		if (!strcmp(argv[a], "-b") || !strcmp(argv[a], "--bit-units")) {
			onoffBitValues = TRUE;
			continue;
		}
		if (!strcmp(argv[a], "-c") || !strcmp(argv[a], "--content-filter")) {
			jconfig_Settings.onoffContentFiltering = FALSE;
			continue;
		}
		if (!strcmp(argv[a], "-i") || !strcmp(argv[a], "--interface")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch requires argument\n", argv[a]);
				exit(255);
			}
			jconfig_Settings.deviceName = argv[++a];
			continue;
		}
		if (!strcmp(argv[a], "-s") || !strcmp(argv[a], "--select-rule")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch requires argument\n", argv[a]);
				exit(255);
			}
			selectRuleName = argv[++a];
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
		if (!strcmp(argv[a], "-f") || !strcmp(argv[a], "--config-file")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch required argument\n", argv[a]);
				exit(255);
			}
			configFileName = argv[++a];
			continue;
		}
		if (!strcmp(argv[a], "-x") || !strcmp(argv[a], "--filter")) {
			const char *ret;
			char *commandLineRule;
			if (a+1>=argc) {
				fprintf(stderr, "%s switch requires argument\n", argv[a]);
				exit(255);
			}
			commandLineRule = argv[++a];
			ret = jutil_ValidateBPFFilter(commandLineRule);
			if (ret) {
				fprintf(stderr, "Error compiling rule: %s\n", ret);
				exit(255);
			}
			JCONFIG_BPFFILTERS_SETSELECTEDFILTER(JCONFIG_BPFFILTERS_LEN);
			jconfig_AddBpfFilter("<commandline>", commandLineRule);
			continue;
		}
		if (!strcmp(argv[a], "-p") || !strcmp(argv[a], "--promiscuous")) {
			jconfig_Settings.onoffPromisc = TRUE;
			continue;
		}
		if (!strcmp(argv[a], "--local-aggr")) {
			if (a+1>=argc || (jconfig_Settings.localAggregation = jutil_ParseAggregation(argv[++a]))==-1) {
				fprintf(stderr, "%s switch requires none, host or port as an argument\n", argv[a]);
				exit(255);
			}
			continue;
		}
		if (!strcmp(argv[a], "--remote-aggr")) {
			if (a+1>=argc || (jconfig_Settings.remoteAggregation = jutil_ParseAggregation(argv[++a]))==-1) {
				fprintf(stderr, "%s switch requires none, host or port as an argument\n", argv[a]);
				exit(255);
			}
			continue;
		}
		fprintf(stderr, "Unknown argument: %s\n", argv[a]);
		exit(255);
	}

	if (!jconfig_ParseFile(configFileName)) {
		exit(255);
	}

	jconfig_SetDefaults();

	if (selectRuleName) {
		int i = jconfig_FindBpfFilterByName(selectRuleName);
		if (i == -1) {
			fprintf(stderr, "Rule '%s' specified on the command line is not defined.\n", selectRuleName);
			exit(255);
		}
		JCONFIG_BPFFILTERS_SETSELECTEDFILTER(i);
	}
}

void initializeDevices() {
	if (!jdevice_LookupDevices()) {
		exit(255);
	}
	
	if (!jdevice_DevicesCount) {
			if (!jconfig_Settings.deviceName) {
				fprintf(stderr, "Autodiscovery found no devices. Specify device you want to watch with -i parameter\n");
				exit(255);
			}
			if (!(jconfig_Settings.device = jdevice_CreateSingleDevice(jconfig_Settings.deviceName))) {
				exit(255);
			}
	} else if (jconfig_Settings.deviceName) {
		int i;
		for (i=0; i<jdevice_DevicesCount; i++) {
			if (!strcmp(jdevice_Devices[i].name, jconfig_Settings.deviceName)) {
				jconfig_Settings.device = jdevice_Devices + i;
				break;
			}
		}

		if (i >= jdevice_DevicesCount) {
			if (!(jconfig_Settings.device = jdevice_CreateSingleDevice(jconfig_Settings.deviceName))) {
				exit(255);
			}
		}
	}

	if (!jconfig_Settings.device) {
		jconfig_Settings.deviceName = jdevice_Devices[0].name;
		jconfig_Settings.device = jdevice_Devices;
	}

	if (!jdevice_CheckDevices()) {
		exit(255);
	}
}

int main(int argc, char ** argv) {
	g_thread_init(NULL);

	jcapture_Setup();
	jprocessor_Setup();
	jresolver_Setup();

	parseCommandLineAndConfig(argc, argv);

	jconfig_ConfigureModules();

	jprocessor_SetProcessStreamsFunc((ProcessStreamsFunc) processStreamsFunc);

	initializeDevices();

	displayStreamsMutex = g_mutex_new();
	statusMutex = g_mutex_new();

	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);

	recycleJnettop = TRUE;

	while (recycleJnettop) {

		jprocessor_ResetStats();

		jcapture_SetDevice(jconfig_Settings.device);
		jcapture_SetBpfFilterText(jconfig_GetSelectedBpfFilterText());

		recycleJnettop = FALSE;
		displayStreams = NULL;
		displayStreamsCount = 0;

		activeLines = 0;
		activeColumns = 0;

		if (statusMessage) {
			g_free(statusMessage);
			statusMessage = NULL;
		}

		clear();
		drawScreen();
		
		jcapture_Start();
		jprocessor_Start();
		displayLoop();

		if (!recycleJnettop) {
			// In case we're not switching to another device, we can happily finish
			// after our display thread dies. (mind the endwin())
			break;
		}

		jcapture_Kill();
		
		while (threadCount) {
			g_thread_yield();
		}
	}

	if (debugFile) {
		fclose(debugFile);
	}

	endwin();
	return 0;
}
