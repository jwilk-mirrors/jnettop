/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Structure of an icmp header.
 */
struct icmp {
	guint8  icmp_type;		/* type of message, see below */
	guint8  icmp_code;		/* type sub code */
	guint16 icmp_cksum;		/* ones complement cksum of struct */
	union {
		guint8 ih_pptr;			/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
		struct ih_idseq {
			guint16 icd_id;
			guint16 icd_seq;
		} ih_idseq;
		guint32 ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu {
			guint16 ipm_void;
			guint16 ipm_nextmtu;
		} ih_pmtu;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
	union {
		struct id_ts {
			guint32 its_otime;
			guint32 its_rtime;
			guint32 its_ttime;
		} id_ts;
		struct id_ip  {
			struct ip idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
                struct mpls_ext {
                    guint8 legacy_header[128]; /* extension header starts 128 bytes after ICMP header */
                    guint8 version_res[2];
                    guint8 checksum[2];
                    guint8 data[1];
                } mpls_ext;
		guint32 id_mask;
		guint8 id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
#define	icmp_mpls_ext_version	icmp_dun.mpls_ext.version_res
#define	icmp_mpls_ext_checksum	icmp_dun.mpls_ext.checksum
#define	icmp_mpls_ext_data	icmp_dun.mpls_ext.data
};
