#ifndef __JCONFIG_H__
#define __JCONFIG_H__

#include "jbase.h"

typedef struct __jconfig_settings {
	char		*deviceName;
	const jbase_device *device;
	gboolean	onoffContentFiltering;
	gboolean	onoffPromisc;
	guint		localAggregation;
	guint		remoteAggregation;

	GPtrArray	*_bpfFilters;
	int		_selectedBpfFilter;
	char		* _adHocBpfFilter;
} jconfig_settings;

gboolean jconfig_Setup();
gboolean jconfig_ParseFile(char *configFileName);
void jconfig_SetDefaults();
void jconfig_ConfigureModules();

const char * jconfig_GetSelectedBpfFilterText();
const char * jconfig_GetSelectedBpfFilterName();
void jconfig_AddBpfFilter(char *filterName, char *filterText);
int jconfig_FindBpfFilterByName(char *filterName);

extern jconfig_settings	jconfig_Settings;

#define JCONFIG_BPFFILTERS_LEN	(jconfig_Settings._bpfFilters->len/2)
#define JCONFIG_BPFFILTERS_GETNAME(i) ((char*)g_ptr_array_index(jconfig_Settings._bpfFilters, (i)*2))
#define JCONFIG_BPFFILTERS_GETTEXT(i) ((char*)g_ptr_array_index(jconfig_Settings._bpfFilters, (i)*2+1))
#define JCONFIG_BPFFILTERS_SETSELECTEDFILTER(i) (jconfig_Settings._selectedBpfFilter = i)
#define JCONFIG_BPFFILTERS_SETNONE (jconfig_Settings._selectedBpfFilter = -1)
#define JCONFIG_BPFFILTERS_SELECTEDISNONE (jconfig_Settings._selectedBpfFilter == -1)

#endif
