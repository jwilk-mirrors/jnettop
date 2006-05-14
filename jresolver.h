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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jresolver.h,v 1.5 2006-05-14 23:55:40 merunka Exp $
 *
 */

#ifndef __JRESOLVER_H__
#define __JRESOLVER_H__

#include "jbase.h"

#define LOOKUPTYPE_UNKNOWN	0
#define LOOKUPTYPE_NORMAL	1
#define LOOKUPTYPE_EXTERNAL	2

typedef struct __jresolver_resolvertype {
	int			af;
	jbase_mutableaddress	mask;
	jbase_mutableaddress	value;
	int			lookupType;
	char			*externalLookupScript;
} jresolver_resolvertype;

typedef void (*ResolvedNotifyFunc) (jbase_resolv_entry *entry);

gboolean		jresolver_Setup();
void			jresolver_Initialize();
void			jresolver_Shutdown();
void			jresolver_SetEnabled(gboolean isEnabled);
jbase_resolv_entry 	*jresolver_Lookup(int af, const jbase_mutableaddress *address);
void			jresolver_AddExternalLookupScript(int af, const jbase_mutableaddress *mask, const jbase_mutableaddress *value, char *lookupScriptName);
void			jresolver_AddNormalLookup(int af, const jbase_mutableaddress *mask, const jbase_mutableaddress *value);
void			jresolver_SetResolvedNotifyFunc(ResolvedNotifyFunc resolvedNotifyFunction);

extern gboolean			jresolver_IsEnabled;
extern ResolvedNotifyFunc	jresolver_ResolvedNotifyFunc;

#endif
