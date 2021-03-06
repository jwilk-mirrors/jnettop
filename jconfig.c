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
 *    $Header$
 *
 */

#include "jbase.h"
#include "jutil.h"
#include "jcapture.h"
#include "jprocessor.h"
#include "jresolver.h"
#include "jconfig.h"
#include "jdevice.h"

jconfig_settings	jconfig_Settings;

static int parse_boolean(GScanner *s) {
	GTokenType tt;
	tt = g_scanner_get_next_token(s);
	if (tt != G_TOKEN_IDENTIFIER || (strcmp(s->value.v_identifier, "on") && strcmp(s->value.v_identifier,"off"))) {
		return -1;
	}
	return strcmp(s->value.v_identifier, "off")?TRUE:FALSE;
}

static int parse_aggregation(GScanner *s) {
	GTokenType tt;
	tt = g_scanner_get_next_token(s);
	if (tt != G_TOKEN_IDENTIFIER) {
		return AGG_UNKNOWN;
	}
	return jutil_ParseAggregation(s->value.v_identifier);
}

static int parse_resolvertype(GScanner *s) {
	GTokenType tt;
	tt = g_scanner_get_next_token(s);
	if (tt != G_TOKEN_IDENTIFIER) {
		return LOOKUPTYPE_UNKNOWN;
	}
	if (strcmp(s->value.v_identifier, "normal") && strcmp(s->value.v_identifier, "external")) {
		return LOOKUPTYPE_UNKNOWN;
	}
	switch (s->value.v_identifier[0]) {
		case 'n': return LOOKUPTYPE_NORMAL;
		case 'e': return LOOKUPTYPE_EXTERNAL;
	}
	return LOOKUPTYPE_UNKNOWN;
}

static gboolean parse_ip(GScanner *s, jbase_mutableaddress *dest, int *af) {
	GTokenType tt;
	tt = g_scanner_get_next_token(s);
	if (tt != G_TOKEN_STRING) {
		return FALSE;
	}
	if (jutil_String2Address(s->value.v_string, dest, af)) {
		return TRUE;
	}
	return FALSE;
}

static gboolean parse_ip_with_netmask(GScanner *s, jbase_mutableaddress *dest, jbase_mutableaddress *netmask, int *af) {
	int oaf;
	GTokenType tt;
	tt = g_scanner_peek_next_token(s);
	if (tt != G_TOKEN_STRING) {
		return FALSE;
	}
	if (jutil_String2AddressAndNetmask(s->next_value.v_string, dest, netmask, af)) {
		g_scanner_get_next_token(s);
		return TRUE;
	}
	if (!parse_ip(s, dest, af)) {
		return FALSE;
	}
	if (!parse_ip(s, netmask, &oaf) || oaf != *af)
		return FALSE;
	return TRUE;
}


gboolean jconfig_Setup() {
	jconfig_Settings.deviceName = NULL;
	jconfig_Settings._bpfFilters = g_ptr_array_new();
	jconfig_Settings.onoffContentFiltering = -1;
	jconfig_Settings.onoffPromisc = -1;
	jconfig_Settings.onoffResolver = -1;
	jconfig_Settings.localAggregation = AGG_UNKNOWN;
	jconfig_Settings.remoteAggregation = AGG_UNKNOWN;
	jconfig_Settings._selectedBpfFilter = -1;
	jconfig_Settings._adHocBpfFilter = NULL;
	jconfig_Settings._networkMaskList = NULL;
	return TRUE;
}

gboolean jconfig_ParseFile(char *configFileName) {
	FILE *f;
	GScanner *s;
	GHashTable *variables;
	char *homeDir;

	variables = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	if (!configFileName) {
		homeDir = getenv("HOME");
		if (!homeDir) {
			configFileName = ".jnettop";
		} else {
			configFileName = g_new0(char, strlen(homeDir) + 10);
			sprintf(configFileName, "%s/.jnettop", homeDir);
		}
	}

	f = fopen(configFileName, "r");
	if (!f) {
		fprintf(stderr, "Could not read/find config file %s: %s.\n", configFileName, strerror(errno));
		return TRUE;
	}

	s = g_scanner_new(NULL);
	g_scanner_input_file(s, fileno(f));
	while (!g_scanner_eof(s)) {
		GTokenType tt;
		int line;

		line = s->line;
		tt = g_scanner_get_next_token(s);
		if (tt == G_TOKEN_EOF) {
			break;
		}
		if (tt != G_TOKEN_IDENTIFIER) {
			fprintf(stderr, "Parse error on line %d: identifier expected.\n", line);
			return FALSE;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "variable")) {
			char * variableName;
			char *c;
			GString *str;
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: variable name as string expected.\n", line);
				return FALSE;
			}
			variableName = g_strdup(s->value.v_string);
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: variable value as string expected.\n", line);
				return FALSE;
			}
			str = g_string_new("");
			for (c=s->value.v_string; *c; c++) {
				char * rightBracket;
				char * variableValue;
				if (*c == '$' && *(c+1) == '{') {
					rightBracket = strchr(c, '}');
					c += 2;
					if (!rightBracket) {
						fprintf(stderr, "Wrong variable substitution on line %d!\n", line);
						return FALSE;
					}
					*rightBracket = '\0';
					variableValue = g_hash_table_lookup(variables, c);
					if (!variableValue) {
						fprintf(stderr, "Undefined variable %s on line %d!\n", c, line);
						return FALSE;
					}
					g_string_append(str, variableValue);
					c = rightBracket;
				} else {
					g_string_append_c(str, *c);
				}
			}
			g_hash_table_insert(variables, variableName, str->str);
			g_string_free(str, FALSE);
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "rule")) {
			char * ruleName;
			char * c;
			GString *str;
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: rule name as string expected.\n", line);
				return FALSE;
			}
			ruleName = g_strdup(s->value.v_string);
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: rule expression as string expected.\n", line);
				return FALSE;
			}
			str = g_string_new("");
			for (c=s->value.v_string; *c; c++) {
				char * rightBracket;
				char * variableValue;
				if (*c == '$' && *(c+1) == '{') {
					rightBracket = strchr(c, '}');
					c += 2;
					if (!rightBracket) {
						fprintf(stderr, "Wrong variable substitution on line %d!\n", line);
						return FALSE;
					}
					*rightBracket = '\0';
					variableValue = g_hash_table_lookup(variables, c);
					if (!variableValue) {
						fprintf(stderr, "Undefined variable %s on line %d!\n", c, line);
						return FALSE;
					}
					g_string_append(str, variableValue);
					c = rightBracket;
				} else {
					g_string_append_c(str, *c);
				}
			}
			jconfig_AddBpfFilter(ruleName, str->str);
			g_string_free(str, FALSE);
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "interface")) {
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: interface name as string expected.\n", line);
				return FALSE;
			}
			if (jconfig_Settings.deviceName == NULL)
				jconfig_Settings.deviceName = g_strdup(s->value.v_string);
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "promisc")) {
			int val = parse_boolean(s);
			if (val == -1) {
				fprintf(stderr, "Parse error on line %d: expecting on or off value.\n", line);
				return FALSE;
			}
			if (jconfig_Settings.onoffPromisc == -1)
				jconfig_Settings.onoffPromisc = val;
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "local_aggregation")) {
			int val = parse_aggregation(s);
			if (val == AGG_UNKNOWN) {
				fprintf(stderr, "Parse error on line %d: expecting none or host or port.\n", line);
				return FALSE;
			}
			if (jconfig_Settings.localAggregation == AGG_UNKNOWN)
				jconfig_Settings.localAggregation = val;
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "remote_aggregation")) {
			int val = parse_aggregation(s);
			if (val == AGG_UNKNOWN) {
				fprintf(stderr, "Parse error on line %d: expecting none or host or port.\n", line);
				return FALSE;
			}
			if (jconfig_Settings.remoteAggregation == AGG_UNKNOWN)
				jconfig_Settings.remoteAggregation = val;
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "select_rule")) {
			int i;
			tt = g_scanner_get_next_token(s);
			if (tt != G_TOKEN_STRING) {
				fprintf(stderr, "Parse error on line %d: rule name as string expected.\n", line);
				return FALSE;
			}
			if (JCONFIG_BPFFILTERS_SELECTEDISNONE) {
				i = jconfig_FindBpfFilterByName(s->value.v_string);
				if (i==-1) {
					fprintf(stderr, "Parse error on line %d: rule %s not defined so far.\n", line, s->value.v_string);
					return FALSE;
				}
				JCONFIG_BPFFILTERS_SETSELECTEDFILTER(i);
			}
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "resolve")) {
			int val = parse_boolean(s);
			if (val == -1) {
				fprintf(stderr, "Parse error on line %d: expecting on or off value.\n", line);
				return FALSE;
			}
			if (jconfig_Settings.onoffResolver == -1)
				jconfig_Settings.onoffResolver = val;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "resolve_rule")) {
			int af;
			jbase_mutableaddress mask;
			jbase_mutableaddress value;
			int resolvertype;
			if (!parse_ip_with_netmask(s, &value, &mask, &af)) {
				fprintf(stderr, "Parse error on line %d: expecting ip address and mask.\n", line);
				return FALSE;
			}
			if ((resolvertype = parse_resolvertype(s)) == LOOKUPTYPE_UNKNOWN) {
				fprintf(stderr, "Parse error on line %d: expecint resolver type.\n", line);
				return FALSE;
			}
			switch (resolvertype) {
				case LOOKUPTYPE_NORMAL:
					jresolver_AddNormalLookup(af, &mask, &value);
					break;
				case LOOKUPTYPE_EXTERNAL:
					tt = g_scanner_get_next_token(s);
					if (tt != G_TOKEN_STRING) {
						fprintf(stderr, "Parse error on line %d: expecting external resolver path.\n", line);
						return FALSE;
					}
					jresolver_AddExternalLookupScript(af, &mask, &value, g_strdup(s->value.v_string));
					break;
			}
			continue;
		}
		if (!g_ascii_strcasecmp(s->value.v_identifier, "local_network")) {
			int af;
			jbase_mutableaddress mask;
			jbase_mutableaddress value;
			if (!parse_ip_with_netmask(s, &value, &mask, &af)) {
				fprintf(stderr, "Parse error on line %d: expecting ip address and mask.\n", line);
				return FALSE;
			}

			jconfig_AddLocalNetwork(&value, &mask, af);
			continue;
		}
	}

	g_hash_table_destroy(variables);
	return TRUE;
}

void jconfig_SetDefaults() {
	if (jconfig_Settings.onoffContentFiltering == -1)
		jconfig_Settings.onoffContentFiltering = TRUE;
	if (jconfig_Settings.onoffPromisc == -1)
		jconfig_Settings.onoffPromisc = FALSE;
	if (jconfig_Settings.onoffResolver == -1)
		jconfig_Settings.onoffResolver = TRUE;
	if (jconfig_Settings.localAggregation == AGG_UNKNOWN)
		jconfig_Settings.localAggregation = AGG_NONE;
	if (jconfig_Settings.remoteAggregation == AGG_UNKNOWN)
		jconfig_Settings.remoteAggregation = AGG_NONE;
}

void jconfig_ConfigureModules() {
	jcapture_SetPromisc(jconfig_Settings.onoffPromisc);
	jprocessor_SetLocalAggregation(jconfig_Settings.localAggregation);
	jprocessor_SetRemoteAggregation(jconfig_Settings.remoteAggregation);
	jprocessor_SetContentFiltering(jconfig_Settings.onoffContentFiltering);
	jresolver_SetEnabled(jconfig_Settings.onoffResolver);
}

const char * jconfig_GetSelectedBpfFilterText() {
	if (jconfig_Settings._selectedBpfFilter == -2 && jconfig_Settings._adHocBpfFilter)
		return jconfig_Settings._adHocBpfFilter;
	if (jconfig_Settings._selectedBpfFilter <= -1)
		return NULL;
	return (const char *) g_ptr_array_index(jconfig_Settings._bpfFilters, jconfig_Settings._selectedBpfFilter*2+1);
}

const char * jconfig_GetSelectedBpfFilterName() {
	if (jconfig_Settings._selectedBpfFilter == -2 && jconfig_Settings._adHocBpfFilter)
		return jconfig_Settings._adHocBpfFilter;
	if (jconfig_Settings._selectedBpfFilter <= -1)
		return "none";
	return (const char *) g_ptr_array_index(jconfig_Settings._bpfFilters, jconfig_Settings._selectedBpfFilter*2);
}

void jconfig_AddBpfFilter(char *filterName, char *filterText) {
	g_ptr_array_add(jconfig_Settings._bpfFilters, filterName);
	g_ptr_array_add(jconfig_Settings._bpfFilters, filterText);
}

int jconfig_FindBpfFilterByName(char *filterName) {
	int i;
	for (i=0; i<JCONFIG_BPFFILTERS_LEN; i++) {
		if (!strcmp(JCONFIG_BPFFILTERS_GETNAME(i), filterName)) {
			return i;
		}
	}
	return -1;
}

void jconfig_AddLocalNetwork(const jbase_mutableaddress *network, const jbase_mutableaddress *netmask, int af) {
	jbase_network_mask_list * current = NULL;
	current = g_new0(jbase_network_mask_list, 1);
	memcpy(&current->network, network, sizeof(jbase_mutableaddress));
	memcpy(&current->netmask, netmask, sizeof(jbase_mutableaddress));
	current->af = af;
	current->next = jconfig_Settings._networkMaskList;
	jconfig_Settings._networkMaskList = current;
}

int jconfig_FindMatchingLocalNetworkIndex(const jbase_mutableaddress *network, int af) {
	jbase_network_mask_list * current;
	int priority = 64000;

	current = jconfig_Settings._networkMaskList;
	while (current) {
		priority --;

		if (jutil_IsInNetwork(network, af, &current->network, &current->netmask, current->af)) {
			return priority;
		}

		current = current->next;
	}

	return 64000;
}

void jconfig_SelectDevice(const char *deviceName) {
	int i;

	jconfig_Settings.deviceName = deviceName;

	for (i=0; i<jdevice_DevicesCount; i++) {
		if (!strcmp(jdevice_Devices[i].name, jconfig_Settings.deviceName)) {
			jconfig_Settings.device = jdevice_Devices + i;
			break;
		}
	}

	if (i >= jdevice_DevicesCount) {
		jconfig_Settings.device = jdevice_CreateSingleDevice(jconfig_Settings.deviceName);
	}
}

