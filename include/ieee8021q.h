/*
 *    jnettop, network online traffic visualiser
 *    Copyright (C) 2002-2006 Jakub Skopal
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
 *    $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/include/ieee8021q.h,v 1.1 2006-04-08 11:48:34 merunka Exp $
 *
 */

#define	NTOP_ETHERTYPE_802_1Q	0x8100
#define	NTOP_8021Q_HDRLEN	4

struct ntop_8021Q_header {
	guint16		priority_cfi_id;
	guint16		protocol_type;
};

