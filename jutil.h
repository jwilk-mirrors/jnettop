#ifndef __JUTIL_H__
#define __JUTIL_H__

#include "jbase.h"

const char * jutil_ValidateBPFFilter(char *filter);
int	jutil_IsHostAggregation(int af, const jbase_mutableaddress *addr);
const char * jutil_Address2String(int af, const jbase_mutableaddress *src, char *dst, size_t cnt);

#endif
