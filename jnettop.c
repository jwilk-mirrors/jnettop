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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jnettop.c,v 1.38 2006-04-12 07:47:01 merunka Exp $
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
#include "jcursesdisplay.h"
#include "jtxtdisplay.h"
#include "juiadisplay.h"

#define			DEBUGOUT_NONE	0
#define			DEBUGOUT_SYSLOG	1
#define			DEBUGOUT_FILE	2
int			debugOut = DEBUGOUT_NONE;
FILE *			debugFile = NULL;

volatile int		threadCount;

jbase_display *		currentDisplay;

void debug(int priority, const char *format, ...) {
	static char buffer[32768];
	va_list ap;
	va_start(ap, format);
	vsprintf(buffer, format, ap);
	va_end(ap);

	switch (debugOut) {
		case DEBUGOUT_FILE:
			fprintf(debugFile, "%d - %d, %s\n", getpid(), priority, buffer);
			break;
#ifdef SUPPORT_SYSLOG
		case DEBUGOUT_SYSLOG:
			syslog(priority, "%d - %d, %s\n", getpid(), priority, buffer);
#endif
	}
}

void jbase_cb_DrawStatus(const gchar *msg) {
	currentDisplay->drawstatus(msg);
}

void parseCommandLineAndConfig(int argc, char ** argv) {
	char * configFileName = NULL;
	char * selectRuleName = NULL;
	int a;

	jconfig_Setup();
	
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
				"    -d, --debug filename   write debug information into file (or syslog)\n"
				"    --display type         type of display (curses, text, uia)\n"
				"    -f, --config-file name reads configuration from file. defaults to ~/.jnettop\n"
				"    --format format        list of fields to list in text output\n"
				"    -i, --interface name   capture packets on specified interface\n"
				"    --local-aggr arg       set local aggregation to none/host/port\n"
				"    -n, --no-resolver      disable resolving of addresses\n"
				"    -p, --promiscuous      enable promisc mode on the devices\n"
				"    --remote-aggr arg      set remote aggregation to none/host/port\n"
				"    -s, --select-rule rule selects one of the rules defined in config file\n"
				"                           by it's name\n"
				"    -t, --timeout sec      timeout in seconds after which jnettop ends (text display)\n"
				"    -x, --filter rule      allows for specification of custom filtering rule\n"
				"                           this follows tcpdump(1) syntax. don't forget to\n"
				"                           enclose the filter into quotes when running from shell\n"
				"\n"
				"Report bugs to <j@kubs.cz>\n"
				"\n"
				"    Format variable can be CSV (comma separated values), TSV (tab separated values)\n"
				"    or completelly custom format string, where the following identifiers are subst-\n"
				"    ituted when surrounded by '$':\n"
				"       src, srcname, srcport, srcbytes, srcpackets, srcbps, srcpps,\n"
				"       dst, dstname, dstport, dstbytes, dstpackets, dstbps, dstpps,\n"
				"       proto, totalbytes, totalpackets, totalbps, totalpps, filterdata\n"
				"\n"
				"    example:\n"
				"       jnettop --display text -t 5 --format CSV\n"
				"       jnettop --display text -t 5 --format '$srcname$,$srcport$,$dstname$,$dstport$,$totalbps$'\n"
				"\n"
			);
			exit(0);
		}
		if (!strcmp(argv[a], "-c") || !strcmp(argv[a], "--content-filter")) {
			jconfig_Settings.onoffContentFiltering = FALSE;
			continue;
		}
		if (!strcmp(argv[a], "--display")) {
			if (a+1>=argc) {
				fprintf(stderr, "%s switch requires argument\n", argv[a]);
				exit(255);
			}
			++a;
			if (jcursesdisplay_Functions.supported && !strcmp(argv[a], "curses")) {
				currentDisplay = &jcursesdisplay_Functions;
			} else if (jtxtdisplay_Functions.supported && !strcmp(argv[a], "text")) {
				currentDisplay = &jtxtdisplay_Functions;
			} else if (juiadisplay_Functions.supported && !strcmp(argv[a], "uia")) {
				currentDisplay = &juiadisplay_Functions;
			} else {
				fprintf(stderr, "display type %s is not supported.\n", argv[a]);
				exit(255);
			}
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
			++a;
			if (!strcmp(argv[a], "syslog")) {
#ifdef SUPPORT_SYSLOG
				debugOut = DEBUGOUT_SYSLOG;
#else
				fprintf(stderr, "Syslog output not enabled in compilation\n");
				exit(255);
#endif
			} else {
				debugFile = fopen(argv[a], "w");
				if (!debugFile) {
					perror("Could not open debug file");
					exit(255);
				}
				debugOut = DEBUGOUT_FILE;
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
		if (!strcmp(argv[a], "-n") || !strcmp(argv[a], "--no-resolve")) {
			jconfig_Settings.onoffResolver = FALSE;
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
		{
			int consumed = currentDisplay->processargument((const gchar **) argv+a, argc-a);
			if (consumed) {
				a += consumed - 1;
				continue;
			}
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

	if (jcursesdisplay_Functions.supported)
		currentDisplay = &jcursesdisplay_Functions;
	else
		currentDisplay = &jtxtdisplay_Functions;

	parseCommandLineAndConfig(argc, argv);

	if (!currentDisplay->presetup()) {
		return 0;
	}

	jconfig_ConfigureModules();
	initializeDevices();

	currentDisplay->setup();

	while (TRUE) {

		jprocessor_ResetStats();

		jcapture_SetDevice(jconfig_Settings.device);
		jcapture_SetBpfFilterText(jconfig_GetSelectedBpfFilterText());

		currentDisplay->prerun();

		jcapture_Start();
		jprocessor_Start();

		if (!currentDisplay->run()) {
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

	currentDisplay->shutdown();
	return 0;
}
