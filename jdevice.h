#ifndef __JDEVICE_H__
#define __JDEVICE_H__

#include "jbase.h"

gboolean jdevice_LookupDevices();
gboolean jdevice_CreateSingleDevice(const gchar *deviceName);

gboolean jdevice_CheckDevices();

extern gint jdevice_DevicesCount;
extern jbase_device *jdevice_Devices;

#endif
