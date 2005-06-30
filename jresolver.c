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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jresolver.c,v 1.2 2005-06-30 19:55:19 merunka Exp $
 *
 */

#include "jbase.h"
#include "jresolver.h"

GHashTable	*resolverCache;
GMutex		*resolverCacheMutex;
GThreadPool	*resolverThreadPool;

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
		g_thread_pool_push(resolverThreadPool, rentry, NULL);
	} else {
		g_mutex_unlock(resolverCacheMutex);
	}

	return rentry;
}

static void resolverThreadFunc(gpointer task, gpointer user_data) {
	jbase_resolv_entry *entry = (jbase_resolv_entry *)task;
	gchar buffer[4096];
	struct hostent shentry, *hentry;
	int  e, ret, size;
	gchar *name;

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
resolverfailed:
#if !HAVE_GETHOSTBYADDR_R_8 && !HAVE_GETHOSTBYADDR_7
	g_mutex_unlock(gethostbyaddrMutex);
#else
	name = name; // dummy to avoid deprecated warning on linux
#endif
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

gboolean		jresolver_Setup() {
	resolverCache = g_hash_table_new((GHashFunc)hashResolvEntry, (GEqualFunc)compareResolvEntry);
	resolverCacheMutex = g_mutex_new();
	resolverThreadPool = g_thread_pool_new((GFunc)resolverThreadFunc, NULL, 5, FALSE, NULL);

	addZeroResolves();
	return TRUE;
}
