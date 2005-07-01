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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jresolver.c,v 1.4 2005-07-01 10:25:37 merunka Exp $
 *
 */

#include "jbase.h"
#include "jutil.h"
#include "jresolver.h"

gboolean	jresolver_IsEnabled;

GHashTable	*resolverCache;
GMutex		*resolverCacheMutex;
GThreadPool	*resolverThreadPool;

GMutex		*gethostbyaddrMutex;

GPtrArray	*resolverTypes;

jbase_resolv_entry *jresolver_Lookup(int af, const jbase_mutableaddress *address) {
	jbase_resolv_entry key;
	jbase_resolv_entry *rentry;

	memcpy(&key.addr, address, sizeof(jbase_mutableaddress));
	key.name = NULL;
	key.af = af;
	g_mutex_lock(resolverCacheMutex);
	rentry = g_hash_table_lookup(resolverCache, &key);
	if (rentry == NULL) {
		rentry = g_new0(jbase_resolv_entry, 1);
		memcpy(rentry, &key, sizeof(key));
		g_hash_table_insert(resolverCache, rentry, rentry);
		g_mutex_unlock(resolverCacheMutex);
		if (jresolver_IsEnabled)
			g_thread_pool_push(resolverThreadPool, rentry, NULL);
	} else {
		g_mutex_unlock(resolverCacheMutex);
	}

	return rentry;
}

static gboolean resolveNormal(jbase_resolv_entry *entry) {
	gchar buffer[4096];
	struct hostent shentry, *hentry;
	int  e, ret, size;
	gchar *name;
	gboolean found = FALSE;

#if !HAVE_GETHOSTBYADDR_R_8 && !HAVE_GETHOSTBYADDR_7
	g_mutex_lock(gethostbyaddrMutex);
#endif
	ret = 0; e=0;
	size = entry->af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
#if HAVE_GETHOSTBYADDR_R_8
	ret = gethostbyaddr_r(&entry->addr, size, entry->af, &shentry, buffer, 4096, &hentry, &e);
#elif HAVE_GETHOSTBYADDR_R_7
	hentry = gethostbyaddr_r(&entry->addr, size, entry->af, &shentry, buffer, 4096, &e);
#else
	hentry = gethostbyaddr(&entry->addr, size, entry->af);
#endif
	if (!hentry || ret || e) {
		goto resolverfailed;
	}
	name = g_strdup(hentry->h_name);
	entry->name = name;
	found = TRUE;
resolverfailed:
#if !HAVE_GETHOSTBYADDR_R_8 && !HAVE_GETHOSTBYADDR_7
	g_mutex_unlock(gethostbyaddrMutex);
#else
	name = name; // dummy to avoid deprecated warning on linux
#endif
	return found;
}

static gboolean resolveExternal(char *lookupScriptPath, jbase_resolv_entry *entry) {
	gchar *outname;
	gint outstatus;
	gchar **argv = (gchar **) g_new0(gchar *, 2);
	gchar *buffer = (gchar *) g_new0(gchar, 256);
	jutil_Address2String(entry->af, &entry->addr, buffer, 256);
	argv[0] = lookupScriptPath;
	argv[1] = buffer;
	if (g_spawn_sync(NULL, argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, &outname, NULL, &outstatus, NULL)) {
		if (!WEXITSTATUS(outstatus)) {
			g_strdelimit(outname, "\r\n\t", '\0');
			if (strlen(outname) > 0) {
				entry->name = outname;
				return TRUE;
			}
			// strip name
		}
	}
	g_free(buffer);
	return FALSE;
}

static void resolverThreadFunc(gpointer task, gpointer user_data) {
	int i;
	jbase_resolv_entry *entry = (jbase_resolv_entry *)task;

	for (i=0; i<resolverTypes->len; i++) {
		jresolver_resolvertype *type = (jresolver_resolvertype *)g_ptr_array_index(resolverTypes, i);
		jbase_mutableaddress	addr;
		if (type->af != entry->af)
			continue;
		memcpy(&addr, &entry->addr, JBASE_AF_SIZE(entry->af));
		memand((char *) &addr, (const char *) &type->mask, JBASE_AF_SIZE(entry->af));
		if (!memcmp(&addr, &type->value, JBASE_AF_SIZE(entry->af))) {
			switch (type->lookupType) {
				case LOOKUPTYPE_EXTERNAL:
					if (resolveExternal(type->externalLookupScript, entry))
						return;
					break;
				case LOOKUPTYPE_NORMAL:
					if (resolveNormal(entry))
						return;
					break;
			}
		}
	}

	resolveNormal(entry);
}

static void addZeroResolves() {
	jbase_resolv_entry *entry;
	entry = g_new0(jbase_resolv_entry, 1);
	entry->name = "UNKNOWNv4";
	entry->af = AF_INET;
	entry->addr.addr4.s_addr = 0x0;
	g_hash_table_insert(resolverCache, entry, entry);
	entry = g_new0(jbase_resolv_entry, 1);
	entry->name = "UNKNOWNv6";
	entry->af = AF_INET6;
	entry->addr.addr6.ntop_s6_addr32[0] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[1] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[2] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[3] = 0x0;
	g_hash_table_insert(resolverCache, entry, entry);
	entry = g_new0(jbase_resolv_entry, 1);
	entry->name = "AGGREGATEDv4";
	entry->af = AF_INET;
	entry->addr.addr4.s_addr = htonl(0x01000000);
	g_hash_table_insert(resolverCache, entry, entry);
	entry = g_new0(jbase_resolv_entry, 1);
	entry->name = "AGGREGATEDv6";
	entry->af = AF_INET6;
	entry->addr.addr6.ntop_s6_addr32[0] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[1] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[2] = 0x0;
	entry->addr.addr6.ntop_s6_addr32[3] = htonl(0x01000000);
	g_hash_table_insert(resolverCache, entry, entry);
}

static guint hashResolvEntry(gconstpointer key) {
	const jbase_resolv_entry *resolv = key;
	guint hash = 0;
	hash = resolv->addr.addr6.ntop_s6_addr32[0];
	hash ^= resolv->addr.addr6.ntop_s6_addr32[1];
	hash ^= resolv->addr.addr6.ntop_s6_addr32[2];
	hash ^= resolv->addr.addr6.ntop_s6_addr32[3];
	return hash;
}

static gboolean compareResolvEntry(gconstpointer a, gconstpointer b) {
	jbase_resolv_entry	*aa, *bb;
	if(a == b) return 1;
	aa = (jbase_resolv_entry *) a;
	bb = (jbase_resolv_entry *) b;
	if(aa->af != bb->af)
		return 0;
	return !memcmp(&aa->addr, &bb->addr, sizeof(aa->addr));
}

void jresolver_AddExternalLookupScript(int af, const jbase_mutableaddress *mask, const jbase_mutableaddress *value, char *lookupScriptName) {
	jresolver_resolvertype *type = g_new0(jresolver_resolvertype, 1);
	type->af = af;
	memcpy(&type->mask, mask, sizeof(jbase_mutableaddress));
	memcpy(&type->value, value, sizeof(jbase_mutableaddress));
	type->lookupType = LOOKUPTYPE_EXTERNAL;
	type->externalLookupScript = lookupScriptName;
	g_ptr_array_add(resolverTypes, type);
}

void jresolver_AddNormalLookup(int af, const jbase_mutableaddress *mask, const jbase_mutableaddress *value) {
	jresolver_resolvertype *type = g_new0(jresolver_resolvertype, 1);
	type->af = af;
	memcpy(&type->mask, mask, sizeof(jbase_mutableaddress));
	memcpy(&type->value, value, sizeof(jbase_mutableaddress));
	type->lookupType = LOOKUPTYPE_NORMAL;
	g_ptr_array_add(resolverTypes, type);
}

void jresolver_SetEnabled(gboolean isEnabled) {
	jresolver_IsEnabled = isEnabled;
}

gboolean jresolver_Setup() {
	resolverCache = g_hash_table_new((GHashFunc)hashResolvEntry, (GEqualFunc)compareResolvEntry);
	resolverCacheMutex = g_mutex_new();
	resolverThreadPool = g_thread_pool_new((GFunc)resolverThreadFunc, NULL, 5, FALSE, NULL);
	resolverTypes = g_ptr_array_new();
	gethostbyaddrMutex = g_mutex_new();

	jresolver_IsEnabled = TRUE;

	addZeroResolves();
	return TRUE;
}
