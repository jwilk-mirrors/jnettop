#ifndef __JCAPTURE_H__
#define __JCAPTURE_H__

#include "jbase.h"
#include "jdevice.h"

gboolean	jcapture_Setup();
void		jcapture_SetPromisc(gboolean value);
gboolean	jcapture_SetDevice(const jbase_device *device);
gboolean	jcapture_SetBpfFilterText(const char *bpfFilter);
gboolean	jcapture_Start();
gboolean	jcapture_Kill();

void		jcapture_packet_Free(jbase_packet *packet);

extern const jbase_device	*jcapture_ActiveDevice;
extern const char		*jcapture_ActiveBpfFilterText;
extern GQueue			*jcapture_PacketQueue;
extern GMutex			*jcapture_PacketQueueMutex;
extern GCond			*jcapture_PacketQueueCond;
extern volatile gboolean	jcapture_IsRunning;

#endif
