/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "routemap.h"

/* OSPFv3 top level data structure */
struct ospf6
{
    /* my router id */
    u_int32_t router_id;

    /* static router id */
    u_int32_t router_id_static;

    /* start time */
    struct timeval starttime;

    /* list of areas */
    struct list *area_list;
    struct ospf6_area *backbone;

    /* AS scope link state database */
    struct ospf6_lsdb *lsdb;
    struct ospf6_lsdb *lsdb_self;

    struct ospf6_route_table *route_table;
    struct ospf6_route_table *brouter_table;
#ifdef TWOD
    struct ospf6_route_table *route_table1;   // ��Ŷ�ά·��  add haozhiqiang 2016-2-2
#endif

    struct ospf6_route_table *external_table;
    struct route_table *external_id_table;
    u_int32_t external_id;

    /* redistribute route-map */
    struct
    {
        char *name;
        struct route_map *map;
    } rmap[ZEBRA_ROUTE_MAX];

    u_char flag;

    /* Configured flags */
    u_char config_flags;
#define OSPF6_LOG_ADJACENCY_CHANGES      (1 << 0)
#define OSPF6_LOG_ADJACENCY_DETAIL       (1 << 1)

    /* SPF parameters */
    unsigned int spf_delay;		/* SPF delay time. */
    unsigned int spf_holdtime;		/* SPF hold time. */
    unsigned int spf_max_holdtime;	/* SPF maximum-holdtime */
    unsigned int spf_hold_multiplier;	/* Adaptive multiplier for hold time */
    unsigned int spf_reason;              /* reason bits while scheduling SPF */

    struct timeval ts_spf;		/* SPF calculation time stamp. */
    struct timeval ts_spf_duration;	/* Execution time of last SPF */
    unsigned int last_spf_reason;         /* Last SPF reason */

    /* Threads */
    struct thread *t_spf_calc;	        /* SPF calculation timer. */
    struct thread *t_ase_calc;		/* ASE calculation timer. */
    struct thread *maxage_remover;

    u_int32_t ref_bandwidth;
};

typedef struct _VTY_PIP
{
    char dst_addr_pre[128];
    char sec_addr_pre[128];
    char next_hop[48];
    char ifiname[20];
    char flagval[128];
} vty_pip;

#define OSPF6_DISABLED    0x01
#define OSPF6_STUB_ROUTER 0x02

/* global pointer for OSPF top data structure */
extern struct ospf6 *ospf6;
#ifdef TWOD

/******************************************************************************/
/* ����ΰ   twod-cost   start                                                 */
/******************************************************************************/

//twod-cost ������Ϣ
typedef struct ospf6_lsa_twod
{

    u_int32_t operate;// 1 add, 0  del

    struct prefix_ipv6 dst_pre;

    struct prefix_ipv6 src_pre;

    u_int16_t cost;         /* cost value */
} OSPF6_LSA_TWOD;
#endif


/* prototypes */
extern void ospf6_top_init (void);
extern void ospf6_delete (struct ospf6 *o);

extern void ospf6_maxage_remove (struct ospf6 *o);
extern int ospf6_twod_route_add_xml(char *pDst,char *pSrc,char *pOut_if,char *pFlag,char *pNext_hop);
extern int ospf6_twod_route_del_xml(char *pDst,char *pSrc);
extern int ospf6_twod_parse_xml_file(void);
extern int ospf6_lookup_xml_twod_cfg_to_dpdk(void);

#endif /* OSPF6_TOP_H */


