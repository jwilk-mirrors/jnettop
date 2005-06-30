#ifndef __JRESOLVER_H__
#define __JRESOLVER_H__

#include "jbase.h"

gboolean		jresolver_Setup();
jbase_resolv_entry 	*jresolver_Lookup(int af, const jbase_mutableaddress *address);

#endif
