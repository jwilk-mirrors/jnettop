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

#ifndef __JCONFIG_H__
#define __JCONFIG_H__

#include "jbase.h"

typedef struct __jconfig_settings {
	const char	*deviceName;
	const jbase_device *device;
	gboolean	onoffContentFiltering;
	gboolean	onoffPromisc;
	gboolean	onoffResolver;
	guint		localAggregation;
	guint		remoteAggregation;

	GPtrArray	* _bpfFilters;
	int		_selectedBpfFilter;
	char		* _adHocBpfFilter;
	jbase_network_mask_list	* _networkMaskList;
} jconfig_settings;

gboolean jconfig_Setup();
gboolean jconfig_ParseFile(char *configFileName);
void jconfig_SetDefaults();
void jconfig_ConfigureModules();

const char * jconfig_GetSelectedBpfFilterText();
const char * jconfig_GetSelectedBpfFilterName();
void jconfig_AddBpfFilter(char *filterName, char *filterText);
int jconfig_FindBpfFilterByName(char *filterName);

void jconfig_AddLocalNetwork(const jbase_mutableaddress *network, const jbase_mutableaddress *netmask, int af);
int jconfig_FindMatchingLocalNetworkIndex(const jbase_mutableaddress *network, int af);

void jconfig_SelectDevice(const char *deviceName);

extern jconfig_settings	jconfig_Settings;

#define JCONFIG_BPFFILTERS_LEN	(jconfig_Settings._bpfFilters->len/2)
#define JCONFIG_BPFFILTERS_GETNAME(i) ((char*)g_ptr_array_index(jconfig_Settings._bpfFilters, (i)*2))
#define JCONFIG_BPFFILTERS_GETTEXT(i) ((char*)g_ptr_array_index(jconfig_Settings._bpfFilters, (i)*2+1))
#define JCONFIG_BPFFILTERS_SETSELECTEDFILTER(i) (jconfig_Settings._selectedBpfFilter = i)
#define JCONFIG_BPFFILTERS_SETNONE (jconfig_Settings._selectedBpfFilter = -1)
#define JCONFIG_BPFFILTERS_SELECTEDISNONE (jconfig_Settings._selectedBpfFilter == -1)

#endif
