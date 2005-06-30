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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jfilter.c,v 1.5 2005-06-30 19:55:18 merunka Exp $
 * 
 */

#include "jbase.h"

static void freeGenericFilterData(struct __jbase_stream *stream) {
	g_free(stream->filterData);
}

/* BEGIN: filter HTTP func */
struct ___httpFilterData {
	guint		protocol;
	gboolean	direction;
};

static void filterHTTPFunc(struct __jbase_stream *stream, const struct __jbase_packet *packet, gboolean direction, const struct __jbase_payload_info *pi) {
	struct ___httpFilterData *fd = (struct ___httpFilterData *)stream->filterData;
	const gchar *data;
	guint len;
	if (direction == fd->direction)
		return;
	data = pi[fd->protocol].data;
	len  = pi[fd->protocol].len;
	if (!data || len<0)
		return;
	if (!strncmp(data, "GET ", 4) || !strncmp(data, "POST ", 5) || !strncmp(data, "HEAD ", 5)) {
		const gchar *space1, *space2;
		int i;
		space1 = strchr(data, ' ') + 1;
		len -= space1 - data;
		space2 = space1;
		for (i=0; i<len && *space2 != ' '; i++, space2++);
		if (i<len) {
			gchar url[BUFSIZ];
			memcpy(url, data, space2-data);
			url[space2-data] = '\0';
			SET_FILTER_DATA_STRING(stream, url);
		}
	}
}

static void assignHTTPFilter(jbase_stream *stream, gboolean direction) {
	struct ___httpFilterData *fd;
	stream->filterDataFunc = filterHTTPFunc;
	stream->filterData = (guchar*)(fd = g_new0(struct ___httpFilterData, 1));
	fd->direction = direction;
	fd->protocol = stream->proto;
	stream->filterDataFreeFunc = freeGenericFilterData;
}
/* END: filter HTTP func */

/* BEGIN: filter SMTP func */
struct ___smtpFilterData {
	guint		protocol;
	gboolean	direction;
	gchar		from[512], to[512];
};

static void filterSMTPFunc(struct __jbase_stream *stream, const struct __jbase_packet *packet, gboolean direction, const struct __jbase_payload_info *pi) {
	struct ___smtpFilterData *fd = (struct ___smtpFilterData *)stream->filterData;
	const gchar *data;
	guint len;
	if (direction == fd->direction)
		return;
	data = pi[fd->protocol].data;
	len  = pi[fd->protocol].len;
	if (!data || len<0)
		return;
	if (!g_strncasecmp(data, "MAIL FROM: ", 11)) {
		const gchar *space1, *space2;
		int i;
		space1 = data + 11;
		len -= space1 - data;
		space2 = space1;
		for (i=0; i<len && *space2 != '\r' && *space2 != '\n'; i++, space2++);
		if (i<len) {
			int l = space2-space1;
			if (l+1>sizeof(fd->from))
				l = sizeof(fd->from)-1;
			memcpy(fd->from, space1, l);
			fd->from[l] = '\0';
			fd->to[0] = '\0';
			SET_FILTER_DATA_STRING(stream, fd->from);
		}
	} else if (!fd->to[0] && !g_strncasecmp(data, "RCPT TO: ", 9)) {
		const gchar *space1, *space2;
		int i;
		space1 = data + 9;
		len -= space1 - data;
		space2 = space1;
		for (i=0; i<len && *space2 != '\r' && *space2 != '\n'; i++, space2++);
		if (i<len) {
			int l = space2-space1;
			if (l+1>sizeof(fd->to))
				l = sizeof(fd->to)-1;
			memcpy(fd->to, space1, l);
			fd->to[l] = '\0';
			SET_FILTER_DATA_STRING_2(stream, "%s -> %s", fd->from, fd->to);
		}
	}
}

static void assignSMTPFilter(jbase_stream *stream, gboolean direction) {
	struct ___smtpFilterData *fd;
	stream->filterDataFunc = filterSMTPFunc;
	stream->filterData = (guchar*) (fd = g_new0(struct ___smtpFilterData, 1));
	fd->direction = direction;
	fd->protocol = stream->proto;
	stream->filterDataFreeFunc = freeGenericFilterData;
}

#define IF_TCP_PORT_THEN_ASSIGN(port, assignFunc) \
	if ((stream->proto == JBASE_PROTO_TCP || stream->proto == JBASE_PROTO_TCP6) \
		&& (stream->srcport == port || stream->dstport == port)) { \
		assignFunc(stream, stream->dstport == port); \
		return; \
	}

void jfilter_AssignDataFilter(jbase_stream *stream) {
	IF_TCP_PORT_THEN_ASSIGN(80, assignHTTPFilter);
	IF_TCP_PORT_THEN_ASSIGN(8080, assignHTTPFilter);
	IF_TCP_PORT_THEN_ASSIGN(3128, assignHTTPFilter);
	IF_TCP_PORT_THEN_ASSIGN(25, assignSMTPFilter);
}
