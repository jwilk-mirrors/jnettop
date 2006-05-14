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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jtxtdisplay.c,v 1.3 2006-05-14 23:55:40 merunka Exp $
 *
 */

#include "jbase.h"
#include "jdevice.h"
#include "jprocessor.h"
#include "jconfig.h"
#include "jutil.h"
#include "jtxtdisplay.h"

int secondsToRun;
GPtrArray *lastStreamsArray;

#define CSV_FORMATSTRING "\"$src$\",\"$dst$\",\"$proto$\",\"$srcport$\",\"$dstport$\",\"$srcname$\",\"$dstname$\",\"$srcbytes$\",\"$dstbytes$\",\"$totalbytes$\",\"$srcpackets$\",\"$dstpackets$\",\"$totalpackets$\",\"$srcbps$\",\"$dstbps$\",\"$totalbps$\",\"$srcpps$\",\"$dstpps$\",\"$totalpps$\",\"$filterdata$\",\"$uid\""
#define TSV_FORMATSTRING "$src$\t$dst$\t$proto$\t$srcport$\t$dstport$\t$srcname$\t$dstname$\t$srcbytes$\t$dstbytes$\t$totalbytes$\t$srcpackets$\t$dstpackets$\t$totalpackets$\t$srcbps$\t$dstbps$\t$totalbps$\t$srcpps$\t$dstpps$\t$totalpps$\t$filterdata$\t$uid$"

gchar *formatString = NULL;

static void processStreamsFunc(GPtrArray * streamArray) {
	lastStreamsArray = streamArray;
}

static void displayLoop() {
	g_usleep(500000);
	while (jcapture_IsRunning && secondsToRun--) {
		g_usleep(1000000);
	}
}

static gboolean jtxtdisplay_PreSetup() {
	return TRUE;
}

static void jtxtdisplay_Setup() {
	jprocessor_SetProcessStreamsFunc((ProcessStreamsFunc) processStreamsFunc);
	if (formatString == NULL)
		formatString = strdup(TSV_FORMATSTRING);
}

static gboolean jtxtdisplay_PreRunSetup() {
	return TRUE;
}

static void jtxtdisplay_PreRun() {
}

static gboolean jtxtdisplay_Run() {
	displayLoop();
	return FALSE;
}

static void jtxtdisplay_Shutdown() {
	int i;
	GString *str;

	str = g_string_new("");

	for (i=0; i<lastStreamsArray->len; i++) {
		jbase_stream *s = (jbase_stream *)g_ptr_array_index(lastStreamsArray, i);

		g_string_truncate(str, 0);
		jutil_InterpretStreamFormat(str, formatString, s);

		printf("%s\n", str->str);
	}

	g_string_free(str, TRUE);
}

static void jtxtdisplay_DrawStatus(const gchar *msg) {
}

static int jtxtdisplay_ProcessArgument(const gchar **arg, int argc) {
	if (!strcmp(*arg, "-t") || !strcmp(*arg, "--timeout")) {
		if (argc<2) {
			fprintf(stderr, "%s parameter needs one numeric argument\n", *arg);
			exit(255);
		}
		secondsToRun = atoi(arg[1]);
		return 2;
	}
	if (!strcmp(*arg, "--format")) {
		if (argc<2) {
			fprintf(stderr, "%s parameter needs one argument\n", *arg);
			exit(255);
		}
		if (!strcmp(arg[1], "CSV"))
			formatString = strdup(CSV_FORMATSTRING);
		else if (!strcmp(arg[1], "TSV"))
			formatString = strdup(TSV_FORMATSTRING);
		else {
			formatString = strdup(arg[1]);
		}
		return 2;
	}
	return 0;
}

jbase_display	jtxtdisplay_Functions = {
	TRUE,
	jtxtdisplay_PreSetup,
	jtxtdisplay_Setup,
	jtxtdisplay_PreRunSetup,
	jtxtdisplay_PreRun,
	jtxtdisplay_Run,
	jtxtdisplay_Shutdown,
	jtxtdisplay_DrawStatus,
	jtxtdisplay_ProcessArgument
};

