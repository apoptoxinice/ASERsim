/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA

  $QuaggaId: $Format:%an, %ai, %h$ $
*/

#ifndef PIM_MROUTE_H
#define PIM_MROUTE_H
/*
  For msghdr.msg_control in Solaris 10
*/
#ifndef _XPG4_2
#define _XPG4_2
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

#include <netinet/ip6.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#endif


#include <netinet/in.h>
#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
#endif

#include "pimsm_define.h"

#include<linux/mroute.h>
#define PIM_MROUTE_MIN_TTL (1)

/*
  Below: from <linux/mroute.h>
*/

#ifndef MAXVIFS
#define MAXVIFS (32)
#endif

#ifndef SIOCGETVIFCNT
#define SIOCGETVIFCNT   SIOCPROTOPRIVATE        /* IP protocol privates */
#define SIOCGETSGCNT    (SIOCPROTOPRIVATE+1)
#define SIOCGETRPF      (SIOCPROTOPRIVATE+2)
#endif

#ifndef MRT_INIT
#define MRT_BASE     200
#define MRT_INIT     (MRT_BASE)      /* Activate the kernel mroute code      */
#define MRT_DONE     (MRT_BASE+1)    /* Shutdown the kernel mroute           */
#define MRT_ADD_VIF  (MRT_BASE+2)    /* Add a virtual interface              */
#define MRT_DEL_VIF  (MRT_BASE+3)    /* Delete a virtual interface           */
#define MRT_ADD_MFC  (MRT_BASE+4)    /* Add a multicast forwarding entry     */
#define MRT_DEL_MFC  (MRT_BASE+5)    /* Delete a multicast forwarding entry  */
#define MRT_VERSION  (MRT_BASE+6)    /* Get the kernel multicast version     */
#define MRT_ASSERT   (MRT_BASE+7)    /* Activate PIM assert mode             */
#define MRT_PIM      (MRT_BASE+8)    /* enable PIM code      */
#endif

#ifndef HAVE_VIFI_T
typedef uint16_t vifi_t;
#endif

#ifndef HAVE_STRUCT_VIFCTL
#if 0
struct vifctl
{
    vifi_t	vifc_vifi;		/* Index of VIF */
    uint8_t vifc_flags;	/* VIFF_ flags */
    uint8_t vifc_threshold;	/* ttl limit */
    uint32_t vifc_rate_limit;	/* Rate limiter values (NI) */
    struct in_addr vifc_lcl_addr;	/* Our address */
    struct in_addr vifc_rmt_addr;	/* IPIP tunnel addr */
};
#endif
#endif

#ifndef HAVE_STRUCT_MFCCTL
#if 0
struct mfcctl
{
    struct in_addr mfcc_origin;             /* Origin of mcast      */
    struct in_addr mfcc_mcastgrp;           /* Group in question    */
    vifi_t         mfcc_parent;             /* Where it arrived     */
    uint8_t  mfcc_ttls[MAXVIFS];      /* Where it is going    */
    uint32_t   mfcc_pkt_cnt;            /* pkt count for src-grp */
    uint32_t   mfcc_byte_cnt;
    uint32_t   mfcc_wrong_if;
    int            mfcc_expire;
};
#endif
#endif

/*
 *      Group count retrieval for mrouted
 */
/*
  struct sioc_sg_req sgreq;
  memset(&sgreq, 0, sizeof(sgreq));
  memcpy(&sgreq.src, &source_addr, sizeof(sgreq.src));
  memcpy(&sgreq.grp, &group_addr, sizeof(sgreq.grp));
  ioctl(mrouter_s4, SIOCGETSGCNT, &sgreq);
 */
#ifndef HAVE_STRUCT_SIOC_SG_REQ
#if 0
struct sioc_sg_req
{
    struct in_addr src;
    struct in_addr grp;
    unsigned long pktcnt;
    unsigned long bytecnt;
    unsigned long wrong_if;
};
#endif
#endif
#if 0
/*
 *   Group count retrieval for pim6sd
 */
struct sioc_sg_req6
{
    struct sockaddr_in6 src;
    struct sockaddr_in6 grp;
    unsigned long pktcnt;
    unsigned long bytecnt;
    unsigned long wrong_if;
};
#endif


/*
 *      To get vif packet counts
 */
/*
  struct sioc_vif_req vreq;
  memset(&vreq, 0, sizeof(vreq));
  vreq.vifi = vif_index;
  ioctl(mrouter_s4, SIOCGETVIFCNT, &vreq);
 */
#ifndef HAVE_STRUCT_SIOC_VIF_REQ
#if 0
struct sioc_vif_req
{
    vifi_t  vifi;           /* Which iface */
    unsigned long icount;   /* In packets */
    unsigned long ocount;   /* Out packets */
    unsigned long ibytes;   /* In bytes */
    unsigned long obytes;   /* Out bytes */
};
#endif
#endif

/*
 *      Pseudo messages used by mrouted
 */
#ifndef IGMPMSG_NOCACHE
#define IGMPMSG_NOCACHE         1               /* Kern cache fill request to mrouted */
#define IGMPMSG_WRONGVIF        2               /* For PIM assert processing (unused) */
#define IGMPMSG_WHOLEPKT        3               /* For PIM Register processing */
#endif

#ifndef HAVE_STRUCT_IGMPMSG
#if 0
struct igmpmsg
{
    uint32_t unused1,unused2;
    uint8_t im_msgtype;               /* What is this */
    uint8_t im_mbz;                   /* Must be zero */
    uint8_t im_vif;                   /* Interface (this ought to be a vifi_t!) */
    uint8_t unused3;
    struct in_addr im_src,im_dst;
};
#endif
#endif

/*
  Above: from <linux/mroute.h>
*/
struct pimsm_mf6cctl
{
    struct sockaddr_in6 mf6cc_origin;      /* Origin of mcast  */
    struct sockaddr_in6 mf6cc_mcastgrp;     /* Group in question    */
    mifi_t  mf6cc_parent;           /* Where it arrived */
    struct if_set mf6cc_ifset;      /* Where it is going */
    int topimsm;
};

int pim_mroute_socket_enable(void);
int pim_mroute_socket_disable(void);

int pim_mroute_add_vif(int vif_index, struct in6_addr ifaddr);
int pim_mroute_del_vif(int vif_index);

int pim_mroute_add(struct mfcctl *mc);
int pim_mroute_del(struct mfcctl *mc);

int pim_mroute_msg(int fd, const char *buf, int buf_size);

#if INCLUDE_PIMSM
int pimsm_mroute_add(struct pimsm_mf6cctl *mc);
int pimsm_mroute_del(struct pimsm_mf6cctl *mc);
#endif

#endif /* PIM_MROUTE_H */
