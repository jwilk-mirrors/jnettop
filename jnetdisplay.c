#include "jbase.h"
#include "jdevice.h"
#include "jprocessor.h"
#include "jresolver.h"
#include "jconfig.h"
#include "jutil.h"
#include "juiadisplay.h"

#define ENABLE_JNET
#ifdef ENABLE_JNET

// protocol
//   HELLO <protocol-version>
//   HELLO:OK <protocol-version>\t<features>
//   SETFILTER "<filter>"
//   SETFILTER:OK
//   INTERFACE "<interface>"
//   INTERFACE:OK
//   RUN
//   RUN:OK
//   SOOB:S <statistics>
//   SOOB:N <streamid>,...streamdata...
//   SOOB:U <streamid>,...streamupdate...
//   SOOB:D <streamid>
//   SOOB:L <address>\t<name>
//   SOOB:E <msg>
//   STOP
//   STOP:OK
//   EXIT
//   EXIT:OK

GScanner	* inputScanner;
GScannerConfig	scannerConfig = {
	/* cset_skip_characters */ " \t",
	/* cset_identifier_first */ G_CSET_A_2_Z,
	/* cset_identifier_nth */ G_CSET_A_2_Z,
	/* cpair_comment_single */ "",
	/* case_sensitive */ TRUE,
	/* skip_comment_multi */ FALSE,
	/* skip_comment_single */ FALSE,
	/* scan_comment_multi */ FALSE,
	/* scan_identifier */ TRUE,
	/* scan_identifier_1char */ TRUE,
	/* scan_identifier_NULL */ FALSE,
	/* scan_symbols */ TRUE,
	/* scan_binary */ FALSE,
	/* scan_octal */ FALSE,
	/* scan_float */ FALSE,
	/* scan_hex */ FALSE,
	/* scan_hex_dollar */ FALSE,
	/* scan_string_sq */ FALSE,
	/* scan_string_dq */ TRUE,
	/* numbers_2_int */ TRUE,
	/* int_2_float */ FALSE,
	/* identifier_2_string */ TRUE,
	/* char_2_token */ TRUE,
	/* symbol_2_token */ FALSE,
	/* scope_0_fallback */ FALSE,
	/* store_int64 */ FALSE,
	/* padding_dummy */ 0 };

#define		INPUT_STATE_INITIAL	0
#define		INPUT_STATE_COMMAND	1
#define		INPUT_STATE_RUNNING	2

#define		RUNNING_STATE_DO_NOTHING	0
#define		RUNNING_STATE_RUNNING		1

int		inputState = INPUT_STATE_INITIAL;
volatile int	runningState = RUNNING_STATE_DO_NOTHING;
GMutex		*runningMutex;
GMutex		*outputMutex;
GString		*stringBuffer;
char		*soobuMessageFormat, *soobnMessageFormat;

#define RECV_BUFFER_SIZE		1024
#define MAX_LINE_SIZE			1024
#define MAX_INTERFACENAME_LENGTH	64
static gchar* readNextCommandLine() {
	fd_set	listenSet, exceptionSet;
	struct	timeval timeout;
	int	selectResult;
	GString *lineBuffer;
	char	*eoln = NULL;

	lineBuffer = g_string_sized_new(1024);

	do {
		int l;
		char buffer[RECV_BUFFER_SIZE];

		FD_ZERO(&listenSet);
		FD_SET(fileno(stdin), &listenSet);
		FD_ZERO(&exceptionSet);
		FD_SET(fileno(stdin), &exceptionSet);
		timeout.tv_sec = 10; // COMMAND TIMEOUT
		timeout.tv_usec = 0;
		selectResult = select(fileno(stdin)+1, &listenSet, NULL, &exceptionSet, &timeout);

		if (selectResult == -1) {
			g_string_free(lineBuffer, TRUE);
			return NULL;
		}

		if (FD_ISSET(fileno(stdin), &exceptionSet)) {
			g_string_free(lineBuffer, TRUE);
			return NULL;
		}

		if (!FD_ISSET(fileno(stdin), &listenSet)) {
			continue;
		}

		l = read(fileno(stdin), buffer, RECV_BUFFER_SIZE);
		if (l <= 0) {
			g_string_free(lineBuffer, TRUE);
			return NULL;
		}

		if (lineBuffer->len + l > MAX_LINE_SIZE) {
			g_string_free(lineBuffer, TRUE);
			return NULL;
		}

		g_string_append_len(lineBuffer, buffer, l);
		g_strdelimit(lineBuffer->str, "\r\n", '\n');
		eoln = strchr(lineBuffer->str, '\n');
	} while (eoln == NULL);
	
	*eoln = '\0';
	return g_string_free(lineBuffer, FALSE);
}

static void sendLine(const gchar *string) {
	g_mutex_lock(outputMutex);
	fprintf(stdout, "%s", string);
	fflush(stdout);
	g_mutex_unlock(outputMutex);
}

static void sendLinef(const gchar *formatString, ...) {
	va_list ap;
	va_start(ap, formatString);
	g_mutex_lock(outputMutex);
	vfprintf(stdout, formatString, ap);
	fflush(stdout);
	g_mutex_unlock(outputMutex);
	va_end(ap);
}

static gboolean parseNextToken(GTokenType expectedTokenType, const char *errorMessage) {
	GTokenType tt;
	tt = g_scanner_get_next_token(inputScanner);
	if (tt != expectedTokenType) {
		sendLine(errorMessage);
		return FALSE;
	}
	return TRUE;
}

#define parseNextString(errorMessage) parseNextToken(G_TOKEN_STRING, errorMessage)
#define parseNextInt(errorMessage) parseNextToken(G_TOKEN_INT, errorMessage)

static gboolean processNextCommand() {
	gchar		*commandLine;
	gboolean	stayConnected = TRUE;
	static char	interfaceName[MAX_INTERFACENAME_LENGTH];

	commandLine = readNextCommandLine();
	if (commandLine == NULL)
		return FALSE;
	
	g_scanner_input_text(inputScanner, commandLine, strlen(commandLine));
	if (!parseNextString("?:ERR Command expected.\n")) {
		goto line_processed;
	}

	if (inputState == INPUT_STATE_INITIAL && !strcmp(inputScanner->value.v_string, "HELLO")) {
		if (!parseNextInt("HELLO:ERR Version argument expected.\n")) {
			goto line_processed;
		}
		if (inputScanner->value.v_int < 1) {
			sendLine("HELLO:ERR Unsupported version.\n");
			goto line_processed;
		}
		sendLine("HELLO:OK 1\n");
		inputState = INPUT_STATE_COMMAND;
		goto line_processed;
	}

	if (inputState == INPUT_STATE_COMMAND && !strcmp(inputScanner->value.v_string, "SETFILTER")) {
		const char * filterValidationError;

		if (!parseNextString("SETFILTER:ERR Filter expected.\n")) {
			goto line_processed;
		}
		JCONFIG_BPFFILTERS_SETNONE;

		filterValidationError = jutil_ValidateBPFFilter(inputScanner->value.v_string);
		if (filterValidationError) {
			sendLinef("SETFILTER:ERR Error parsing filter rule: %s.\n", filterValidationError);
			goto line_processed;
		}

		JCONFIG_BPFFILTERS_SETSELECTEDFILTER(JCONFIG_BPFFILTERS_LEN);
		jconfig_AddBpfFilter("<fromsetfilter>", g_strdup(inputScanner->value.v_string));
		sendLine("SETFILTER:OK Filter set.\n");
		goto line_processed;
	}

	if (inputState == INPUT_STATE_COMMAND && !strcmp(inputScanner->value.v_string, "INTERFACE")) {
		if (!parseNextString("INTERFACE:ERR Device name expected.\n")) {
			goto line_processed;
		}

		if (strlen(inputScanner->value.v_string) > MAX_INTERFACENAME_LENGTH-1) {
			sendLine("INTERFACE:ERR Interface name too long.\n");
			goto line_processed;
		}

		strcpy(interfaceName, inputScanner->value.v_string);
		jconfig_SelectDevice(interfaceName);
		sendLine("INTERFACE:OK Interface set.\n");
		goto line_processed;
	}

	if (inputState == INPUT_STATE_COMMAND && !strcmp(inputScanner->value.v_string, "INTERFACES")) {
		int i;
		char buffer[256];

		sendLine("INTERFACES:OK Interface list follows.\n");
		for (i=0; i<jdevice_DevicesCount; i++) {
			jbase_device *device = jdevice_Devices+i;
			jutil_StorageAddress2String(&device->hwaddr, buffer, sizeof(buffer)-1);
			sendLinef("INTERFACES:INFO %s\t%d\t%s\n", device->name, ((const struct sockaddr *)&device->hwaddr)->sa_family, buffer);
		}
		sendLine("INTERFACES:END End of list.\n");
		goto line_processed;
	}

	if (inputState == INPUT_STATE_COMMAND && !strcmp(inputScanner->value.v_string, "RUN")) {
		inputState = INPUT_STATE_RUNNING;
		goto line_processed;
	}

	if (inputState == INPUT_STATE_RUNNING && !strcmp(inputScanner->value.v_string, "STOP")) {
		inputState = INPUT_STATE_COMMAND;
		goto line_processed;
	}

	if (!strcmp(inputScanner->value.v_string, "EXIT")) {
		sendLine("EXIT:OK Good Bye.\n");
		stayConnected = FALSE;
		goto line_processed;
	}

	sendLinef("%s:ERR Unknown command.\n", inputScanner->value.v_string);

line_processed:
	g_free(commandLine);
	return stayConnected;
}

static void sendDeleteStream(GString *buffer, jbase_stream *s) {
	g_string_append_printf(buffer, "SOOB:D %08x%08x\n", (unsigned int)(s->uid>>32), (unsigned int)(s->uid&0xffffffff));
}

#define SOOBU_MESSAGEFORMAT "SOOB:U $uid$\t$srcbytes$\t$dstbytes$\t$totalbytes$\t$srcpackets$\t$dstpackets$\t$totalpackets$\t$srcbps$\t$dstbps$\t$totalbps$\t$srcpps$\t$dstpps$\t$totalpps$\t$filterdataifchanged$"
#define SOOBN_MESSAGEFORMAT "SOOB:N $uid$\t$src$\t$dst$\t$proto$\t$srcport$\t$dstport$"

static void sendStatistics(GString *buffer) {
	g_string_append_printf(buffer, "SOOB:S %u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
		jprocessor_Stats.totalSrcBytes,
		jprocessor_Stats.totalDstBytes,
		jprocessor_Stats.totalBytes,
		jprocessor_Stats.totalSrcPackets,
		jprocessor_Stats.totalDstPackets,
		jprocessor_Stats.totalPackets,
		jprocessor_Stats.totalSrcBPS,
		jprocessor_Stats.totalDstBPS,
		jprocessor_Stats.totalBPS,
		jprocessor_Stats.totalSrcPPS,
		jprocessor_Stats.totalDstPPS,
		jprocessor_Stats.totalPPS);
}

static void sendUpdateStream(GString *buffer, jbase_stream *s) {
	jutil_InterpretStreamFormat(buffer, soobuMessageFormat, s);
	g_string_append_c(buffer, '\n');
	s->filterDataLastDisplayChangeCount = s->filterDataChangeCount;
}

static void sendNewStream(GString *buffer, jbase_stream *s) {
	jutil_InterpretStreamFormat(buffer, soobnMessageFormat, s);
	g_string_append_c(buffer, '\n');
}

static void resolvedNotifyFunc(jbase_resolv_entry *entry) {
	gchar addr[INET6_ADDRSTRLEN + 1];

	g_mutex_lock(runningMutex);
	if (runningState == RUNNING_STATE_RUNNING) {
		jutil_Address2String(entry->af, &entry->addr, addr, INET6_ADDRSTRLEN);
		sendLinef("SOOB:L %s\t%s\n", addr, entry->name);
	}
	g_mutex_unlock(runningMutex);
}

static void processStreamsFunc(GPtrArray * streamArray) {
	guint i;

	g_mutex_lock(runningMutex);
	if (runningState == RUNNING_STATE_RUNNING) {
		GString *buffer = g_string_sized_new(streamArray->len * 100);
		sendStatistics(buffer);
		for (i=0; i<streamArray->len; i++) {
			jbase_stream *s = (jbase_stream *)g_ptr_array_index(streamArray, i);
			if (s->dead && !s->displayed) {
				continue;
			}
			if (s->dead) {
				sendDeleteStream(buffer, s);
				s->displayed = 0;
				continue;
			}
			if (!s->displayed) {
				s->displayed = 1;
				sendNewStream(buffer, s);
			}
			sendUpdateStream(buffer, s);
		}
		sendLinef("%s", buffer->str);
		g_string_free(buffer, TRUE);
	}
	sendLinef("SOOB:E Update finished.\n");
	g_mutex_unlock(runningMutex);
}

static gboolean jnetdisplay_PreSetup() {
	return TRUE;
}

static void jnetdisplay_Setup() {
	setvbuf(stdin, NULL, _IOLBF, 0);
	setvbuf(stdout, NULL, _IOLBF, 0);

	inputScanner = g_scanner_new(&scannerConfig);
	outputMutex = g_mutex_new();
	runningMutex = g_mutex_new();
	stringBuffer = g_string_new("");

	soobuMessageFormat = g_strdup(SOOBU_MESSAGEFORMAT);
	soobnMessageFormat = g_strdup(SOOBN_MESSAGEFORMAT);

	jprocessor_Sorting = FALSE;

	jprocessor_SetProcessStreamsFunc((ProcessStreamsFunc) processStreamsFunc);
	jresolver_SetResolvedNotifyFunc((ResolvedNotifyFunc) resolvedNotifyFunc);
}

static gboolean jnetdisplay_PreRunSetup() {
	do {
		if (!processNextCommand()) {
			return FALSE;
		}
		if (inputState == INPUT_STATE_RUNNING) {
			return TRUE;
		}
	} while (TRUE);
}

static void jnetdisplay_PreRun() {
}

static gboolean jnetdisplay_Run() {
	sendLine("RUN:OK Running...\n");
	g_mutex_lock(runningMutex);
	runningState = RUNNING_STATE_RUNNING;
	g_mutex_unlock(runningMutex);
	while (inputState == INPUT_STATE_RUNNING && processNextCommand()) {
	}
	g_mutex_lock(runningMutex);
	runningState = RUNNING_STATE_DO_NOTHING;
	g_mutex_unlock(runningMutex);
	if (inputState == INPUT_STATE_COMMAND) {
		sendLine("STOP:OK Stopped.\n");
	}
	return inputState == INPUT_STATE_COMMAND;
}

static void jnetdisplay_Shutdown() {
}

static void jnetdisplay_DrawStatus(const gchar *msg) {
	sendLinef("STATUS:OOB %s\n", msg);
}

static int jnetdisplay_ProcessArgument(const gchar **arg, int argc) {
	return 0;
}

jbase_display	jnetdisplay_Functions = {
	TRUE,
	jnetdisplay_PreSetup,
	jnetdisplay_Setup,
	jnetdisplay_PreRunSetup,
	jnetdisplay_PreRun,
	jnetdisplay_Run,
	jnetdisplay_Shutdown,
	jnetdisplay_DrawStatus,
	jnetdisplay_ProcessArgument
};

#else

jbase_display	jnetdisplay_Functions = { FALSE };

#endif
