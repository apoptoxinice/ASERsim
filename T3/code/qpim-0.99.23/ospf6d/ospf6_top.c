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

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "vty.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "command.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6_spf.h"
#include "ospf6d.h"

#include <pthread.h>
#define MAXNUM 10
#ifdef TWOD
unsigned int twod_colcu=0;
vty_pip vty_p[MAXNUM];
#endif
/* global ospf6d variable */
struct ospf6 *ospf6;
#ifdef TWOD
//zlw for twod-cost enable
int twod_enable = 0;
#endif

static void ospf6_disable (struct ospf6 *o);

#if 1 //add 2020
static void
ospf6_top_route_zone_hook_add (struct ospf6_route *route)
{
    struct ospf6_route *copy = ospf6_route_copy (route);
    ospf6_route_add (copy, ospf6->route_table);
}

static void
ospf6_top_route_zone_hook_remove (struct ospf6_route *route)
{
    struct ospf6_route *copy;

    copy = ospf6_route_lookup_identical (route, ospf6->route_table);
    if (copy)
        ospf6_route_remove (copy, ospf6->route_table);
}

#endif
static void
ospf6_top_lsdb_hook_add (struct ospf6_lsa *lsa)
{
    switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_add (lsa);
        break;
#if 1//add 2020
    case OSPF6_LSTYPE_ZONE:
        //DG("will call ospf6_spf_schedule_zone.\n");
        ospf6_spf_schedule_zone (OSPF6_PROCESS (lsa->lsdb->data),
                                 ospf6_lsadd_to_spf_reason(lsa));
        break;
#endif
    default:
        break;
    }
}

static void
ospf6_top_lsdb_hook_remove (struct ospf6_lsa *lsa)
{
    switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_remove (lsa);
        break;
#if 1 //add 2020
    case OSPF6_LSTYPE_ZONE:
        //DG("will call ospf6_spf_schedule_zone.\n");
        ospf6_spf_schedule_zone (OSPF6_PROCESS (lsa->lsdb->data),
                                 ospf6_lsremove_to_spf_reason(lsa));
        break;
#endif
    default:
        break;
    }
}

static void
ospf6_top_route_hook_add (struct ospf6_route *route)
{
#ifdef TWOD
    ospf6_print_one_route_to_huawei(route);
#endif
    ospf6_abr_originate_summary (route);
    ospf6_zebra_route_update_add (route);
}

static void
ospf6_top_route_hook_remove (struct ospf6_route *route)
{
#ifdef TWOD
    ospf6_print_one_route_to_huawei(route);
#endif
    ospf6_abr_originate_summary (route);
    ospf6_zebra_route_update_remove (route);
}

static void
ospf6_top_brouter_hook_add (struct ospf6_route *route)
{
    ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
    ospf6_asbr_lsentry_add (route);
    ospf6_abr_originate_summary (route);
}

static void
ospf6_top_brouter_hook_remove (struct ospf6_route *route)
{
    ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
    ospf6_asbr_lsentry_remove (route);
    ospf6_abr_originate_summary (route);
}

static struct ospf6 *
ospf6_create (void)
{
    struct ospf6 *o;

    o = XCALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));

    /* initialize */
    quagga_gettime (QUAGGA_CLK_MONOTONIC, &o->starttime);
    o->area_list = list_new ();
    o->area_list->cmp = ospf6_area_cmp;
    o->lsdb = ospf6_lsdb_create (o);
    o->lsdb_self = ospf6_lsdb_create (o);
    o->lsdb->hook_add = ospf6_top_lsdb_hook_add;
    o->lsdb->hook_remove = ospf6_top_lsdb_hook_remove;

    o->spf_delay = OSPF_SPF_DELAY_DEFAULT;
    o->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;
    o->spf_max_holdtime = OSPF_SPF_MAX_HOLDTIME_DEFAULT;
    o->spf_hold_multiplier = 1;

    o->route_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, ROUTES);
    o->route_table->scope = o;
    o->route_table->hook_add = ospf6_top_route_hook_add;
    o->route_table->hook_remove = ospf6_top_route_hook_remove;

#if 1 //add 2020
    o->self_area_id = 0;
    //o->neighbor_area_id = 0;
    o->router_pbr_flag = OSPF6_PBRDISABLED;
    o->zone_oa = NULL;
    o->lsdb_zone = ospf6_lsdb_create (o);
    o->lsdb_zone->hook_add = ospf6_top_lsdb_hook_add;
    o->lsdb_zone->hook_remove = ospf6_top_lsdb_hook_remove;

    o->spf_table_zone = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, SPF_RESULTS);
    o->spf_table_zone->scope = o;

    o->route_table_zone = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, ROUTES);
    o->route_table_zone->scope = o;
    o->route_table_zone->hook_add = ospf6_top_route_zone_hook_add;
    o->route_table_zone->hook_remove = ospf6_top_route_zone_hook_remove;
#endif

#ifdef TWOD
// add haozhiqiang   2016-2-2
    o->route_table1 = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, ROUTES);
    o->route_table1->scope = o;
    o->route_table1->hook_add = ospf6_top_route_hook_add;
    o->route_table1->hook_remove = ospf6_top_route_hook_remove;
#endif

    o->brouter_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, BORDER_ROUTERS);
    o->brouter_table->scope = o;
    o->brouter_table->hook_add = ospf6_top_brouter_hook_add;
    o->brouter_table->hook_remove = ospf6_top_brouter_hook_remove;

    o->external_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, EXTERNAL_ROUTES);
    o->external_table->scope = o;

    o->external_id_table = route_table_init ();

    o->ref_bandwidth = OSPF6_REFERENCE_BANDWIDTH;

    return o;
}

void
ospf6_delete (struct ospf6 *o)
{
    struct listnode *node, *nnode;
    struct ospf6_area *oa;

    ospf6_disable (ospf6);

    for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
        ospf6_area_delete (oa);


    list_delete (o->area_list);

    ospf6_lsdb_delete (o->lsdb);
    ospf6_lsdb_delete (o->lsdb_self);

#if 1//add 2020
    ospf6_lsdb_delete (o->lsdb_zone);
    ospf6_spf_table_finish(o->spf_table_zone);
    ospf6_route_table_delete (o->spf_table_zone);
    ospf6_route_table_delete (o->route_table_zone);
#endif

    ospf6_route_table_delete (o->route_table);
    ospf6_route_table_delete (o->brouter_table);

    ospf6_route_table_delete (o->external_table);
    route_table_finish (o->external_id_table);

    XFREE (MTYPE_OSPF6_TOP, o);
}

static void
ospf6_enable (struct ospf6 *o)
{
    struct listnode *node, *nnode;
    struct ospf6_area *oa;
    if (CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
        UNSET_FLAG (o->flag, OSPF6_DISABLED);
        for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
        {
            ospf6_area_enable (oa);
        }
    }
}

static void
ospf6_disable (struct ospf6 *o)
{
    struct listnode *node, *nnode;
    struct ospf6_area *oa;

    if (! CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
        SET_FLAG (o->flag, OSPF6_DISABLED);

        for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
            ospf6_area_disable (oa);

        /* XXX: This also changes persistent settings */
        ospf6_asbr_redistribute_reset();

        ospf6_lsdb_remove_all (o->lsdb);
        ospf6_route_remove_all (o->route_table);
#if 1//add 2020
        ospf6_route_remove_all (o->route_table_zone);
#endif
        ospf6_route_remove_all (o->brouter_table);

        THREAD_OFF(o->maxage_remover);
        THREAD_OFF(o->t_spf_calc);
        THREAD_OFF(o->t_ase_calc);
#if 1 //add 2020
        THREAD_OFF(o->t_spf_zone_calc);
#endif
    }
}

static int ospf6_maxage_remover (struct thread *thread)
{
    struct ospf6 *o = (struct ospf6 *) THREAD_ARG (thread);
    struct ospf6_area *oa;
    struct ospf6_interface *oi;
    struct ospf6_neighbor *on;
    struct listnode *i, *j, *k;
    int reschedule = 0;

    o->maxage_remover = (struct thread *) NULL;

    for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
        {
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
            {
                if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
                        on->state != OSPF6_NEIGHBOR_LOADING)
                    continue;

                ospf6_maxage_remove (o);
                return 0;
            }
        }
    }

    for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
        {
            if (ospf6_lsdb_maxage_remover (oi->lsdb))
            {
                reschedule = 1;
            }
        }

        if (ospf6_lsdb_maxage_remover (oa->lsdb))
        {
            reschedule = 1;
        }
    }

    if (ospf6_lsdb_maxage_remover (o->lsdb))
    {
        reschedule = 1;
    }
#if 1//add 2020
    if (ospf6_lsdb_maxage_remover (o->lsdb_zone))
    {
        reschedule = 1;
    }
#endif
    if (reschedule)
    {
        ospf6_maxage_remove (o);
    }

    return 0;
}

void
ospf6_maxage_remove (struct ospf6 *o)
{
    if (o && ! o->maxage_remover)
        o->maxage_remover = thread_add_timer (master, ospf6_maxage_remover, o,
                                              OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT);
}

/* start ospf6 */
DEFUN (router_ospf6,
       router_ospf6_cmd,
       "router ospf6",
       ROUTER_STR
       OSPF6_STR)
{
    if (ospf6 == NULL)
        ospf6 = ospf6_create ();
#if 0
    //0.99.21
    if (CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
    {
        ospf6_enable (ospf6);
        printf("%s()%d will enable ospf6.\n", __func__, __LINE__);
    }
    else
        printf("%s()%d  ospf6 already enable.\n", __func__, __LINE__);
#endif

    /* set current ospf point. */
    vty->node = OSPF6_NODE;
    vty->index = ospf6;

    return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN (no_router_ospf6,
       no_router_ospf6_cmd,
       "no router ospf6",
       NO_STR
       OSPF6_ROUTER_STR)
{
    if (ospf6 == NULL)
        vty_out (vty, "OSPFv3 is not running%s", VNL);
    else
    {
        ospf6_delete (ospf6);
        ospf6 = NULL;
    }

    /* return to config node . */
    vty->node = CONFIG_NODE;
    vty->index = NULL;

    return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (ospf6_router_id,
       ospf6_router_id_cmd,
       "router-id A.B.C.D",
       "Configure OSPF Router-ID\n"
       V4NOTATION_STR)
{
    int ret;
    u_int32_t router_id;
    struct ospf6 *o;

    o = (struct ospf6 *) vty->index;

    ret = inet_pton (AF_INET, argv[0], &router_id);
    if (ret == 0)
    {
        vty_out (vty, "malformed OSPF Router-ID: %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }

    o->router_id_static = router_id;
    if (o->router_id  == 0)
    {
        o->router_id  = router_id;
        /*202003 add*/
        if (o->drouter_id == 0)
            o->drouter_id = router_id;
    }

    return CMD_SUCCESS;
}
/* change Router_ID commands. */
DEFUN (no_ospf6_router_id,
       no_ospf6_router_id_cmd,
       "no router-id A.B.C.D",
       NO_STR
       "No configure OSPF Router-ID\n"
       V4NOTATION_STR)
{
    struct ospf6 *o;

    o = (struct ospf6 *) vty->index;
    o->router_id  = 0;
    o->router_id_static=0;


    return CMD_SUCCESS;
}


DEFUN (ospf6_log_adjacency_changes,
       ospf6_log_adjacency_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
    struct ospf6 *ospf6 = vty->index;

    SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
    return CMD_SUCCESS;
}

DEFUN (ospf6_log_adjacency_changes_detail,
       ospf6_log_adjacency_changes_detail_cmd,
       "log-adjacency-changes detail",
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
    struct ospf6 *ospf6 = vty->index;

    SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
    SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
    return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes,
       no_ospf6_log_adjacency_changes_cmd,
       "no log-adjacency-changes",
       NO_STR
       "Log changes in adjacency state\n")
{
    struct ospf6 *ospf6 = vty->index;

    UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
    UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
    return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes_detail,
       no_ospf6_log_adjacency_changes_detail_cmd,
       "no log-adjacency-changes detail",
       NO_STR
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
    struct ospf6 *ospf6 = vty->index;

    UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
    return CMD_SUCCESS;
}

DEFUN (ospf6_interface_area,
       ospf6_interface_area_cmd,
       "interface IFNAME area A.B.C.D",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
      )
{
    struct ospf6 *o;
    struct ospf6_area *oa;
    struct ospf6_interface *oi;
    struct interface *ifp;
    u_int32_t area_id;

    o = (struct ospf6 *) vty->index;

    /* find/create ospf6 interface */
    ifp = if_get_by_name (argv[0]);
    oi = (struct ospf6_interface *) ifp->info;
    if (oi == NULL)
        oi = ospf6_interface_create (ifp);
    if (oi->area)
    {
        vty_out (vty, "%s already attached to Area %s%s",
                 oi->interface->name, oi->area->name, VNL);
        return CMD_SUCCESS;
    }

    /* parse Area-ID */
    if (inet_pton (AF_INET, argv[1], &area_id) != 1)
    {
        vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
        return CMD_SUCCESS;
    }

    /* find/create ospf6 area */
    oa = ospf6_area_lookup (area_id, o);
    if (oa == NULL)
        oa = ospf6_area_create (area_id, o);

    /* attach interface to area */
    listnode_add (oa->if_list, oi); /* sort ?? */
    oi->area = oa;

    SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

    /* ospf6 process is currently disabled, not much more to do */
    if (CHECK_FLAG (o->flag, OSPF6_DISABLED))
        return CMD_SUCCESS;

    /* start up */
    ospf6_interface_enable (oi);

    /* If the router is ABR, originate summary routes */
    if (ospf6_is_router_abr (o))
        ospf6_abr_enable_area (oa);

    return CMD_SUCCESS;
}

DEFUN (no_ospf6_interface_area,
       no_ospf6_interface_area_cmd,
       "no interface IFNAME area A.B.C.D",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
      )
{
    struct ospf6 *o;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct interface *ifp;
    u_int32_t area_id;

    o = (struct ospf6 *) vty->index;

    ifp = if_lookup_by_name (argv[0]);
    if (ifp == NULL)
    {
        vty_out (vty, "No such interface %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }

    oi = (struct ospf6_interface *) ifp->info;
    if (oi == NULL)
    {
        vty_out (vty, "Interface %s not enabled%s", ifp->name, VNL);
        return CMD_SUCCESS;
    }

    /* parse Area-ID */
    if (inet_pton (AF_INET, argv[1], &area_id) != 1)
    {
        vty_out (vty, "Invalid Area-ID: %s%s", argv[1], VNL);
        return CMD_SUCCESS;
    }

    /* Verify Area */
    if (oi->area == NULL)
    {
        vty_out (vty, "No such Area-ID: %s%s", argv[1], VNL);
        return CMD_SUCCESS;
    }

    if (oi->area->area_id != area_id)
    {
        vty_out (vty, "Wrong Area-ID: %s is attached to area %s%s",
                 oi->interface->name, oi->area->name, VNL);
        return CMD_SUCCESS;
    }

    thread_execute (master, interface_down, oi, 0);

    oa = oi->area;
    listnode_delete (oi->area->if_list, oi);
    oi->area = (struct ospf6_area *) NULL;

    /* Withdraw inter-area routes from this area, if necessary */
    if (oa->if_list->count == 0)
    {
        UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);
        ospf6_abr_disable_area (oa);
#if 1//add 2020
        o->self_area_id = 0;
        o->zone_oa = NULL;
#endif
    }

    return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_admin,
       ospf6_stub_router_admin_cmd,
       "stub-router administrative",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Administratively applied, for an indefinite period\n")
{
    struct listnode *node;
    struct ospf6_area *oa;

    if (!CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
        for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
        {
            OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_V6);
            OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_R);
            OSPF6_ROUTER_LSA_SCHEDULE (oa);
        }
        SET_FLAG (ospf6->flag, OSPF6_STUB_ROUTER);
    }

    return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_admin,
       no_ospf6_stub_router_admin_cmd,
       "no stub-router administrative",
       NO_STR
       "Make router a stub router\n"
       "Advertise ability to be a transit router\n"
       "Administratively applied, for an indefinite period\n")
{
    struct listnode *node;
    struct ospf6_area *oa;

    if (CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
        for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
        {
            OSPF6_OPT_SET (oa->options, OSPF6_OPT_V6);
            OSPF6_OPT_SET (oa->options, OSPF6_OPT_R);
            OSPF6_ROUTER_LSA_SCHEDULE (oa);
        }
        UNSET_FLAG (ospf6->flag, OSPF6_STUB_ROUTER);
    }

    return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_startup,
       ospf6_stub_router_startup_cmd,
       "stub-router on-startup <5-86400>",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router on startup of OSPF6\n"
       "Time (seconds) to advertise self as stub-router\n")
{
    return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_startup,
       no_ospf6_stub_router_startup_cmd,
       "no stub-router on-startup",
       NO_STR
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router on startup of OSPF6\n"
       "Time (seconds) to advertise self as stub-router\n")
{
    return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_shutdown,
       ospf6_stub_router_shutdown_cmd,
       "stub-router on-shutdown <5-86400>",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router before shutdown\n"
       "Time (seconds) to advertise self as stub-router\n")
{
    return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_shutdown,
       no_ospf6_stub_router_shutdown_cmd,
       "no stub-router on-shutdown",
       NO_STR
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router before shutdown\n"
       "Time (seconds) to advertise self as stub-router\n")
{
    return CMD_SUCCESS;
}
static void ospf6_show_attached_area(struct vty *vty)
{
    struct listnode *node;
    struct listnode *nnode;
    struct pbr_list *plist;
    char buf[16];
    int i;

    for (ALL_LIST_ELEMENTS (pbr_list_head, node, nnode, plist))
    {
        memset(buf, 0x00, sizeof(buf));
        inet_ntop (AF_INET, &plist->neighbor_area_id,
                   buf, sizeof (buf));
        vty_out(vty, " attached aread id:%s, num:%d%s", buf, plist->attached_num, VNL);
        for(i = 0; i < MAX_ATTACHED_NUM; i++)
        {
            if (plist->pbr_id[i].router_id > 0)
            {
                memset(buf, 0x00, sizeof(buf));
                inet_ntop (AF_INET, &plist->pbr_id[i].router_id,
                           buf, sizeof (buf));
                vty_out(vty, "  attached router id:%s, state:%d%s", buf, plist->pbr_id[i].attached, VNL);
            }
        }
    }
    return;
}

static void
ospf6_show (struct vty *vty, struct ospf6 *o)
{
    struct listnode *n;
    struct ospf6_area *oa;
    char router_id[16], duration[32];
    struct timeval now, running, result;
    char buf[32], rbuf[32];

#if 1//add 2020
    if (o->router_pbr_flag == OSPF6_PBRENABLED)
        vty_out (vty, " This is a partition border router%s", VNL);
#endif
    /* process id, router id */
    inet_ntop (AF_INET, &o->router_id, router_id, sizeof (router_id));
    vty_out (vty, " OSPFv3 Routing Process (0) with Router-ID %s%s",
             router_id, VNL);

    memset(router_id, 0x00, sizeof(router_id));
    inet_ntop (AF_INET, &o->drouter_id, router_id, sizeof (router_id));
    vty_out (vty, " Self Originated ZONE lsa DROuter-ID %s%s",
             router_id, VNL);

#if 1//add 2020
    ospf6_show_attached_area(vty);
#endif
    /* running time */
    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    timersub (&now, &o->starttime, &running);
    timerstring (&running, duration, sizeof (duration));
    vty_out (vty, " Running %s%s", duration, VNL);

    /* Redistribute configuration */
    /* XXX */

    /* Show SPF parameters */
    vty_out(vty, " Initial SPF scheduling delay %d millisec(s)%s"
            " Minimum hold time between consecutive SPFs %d millsecond(s)%s"
            " Maximum hold time between consecutive SPFs %d millsecond(s)%s"
            " Hold time multiplier is currently %d%s",
            o->spf_delay, VNL,
            o->spf_holdtime, VNL,
            o->spf_max_holdtime, VNL,
            o->spf_hold_multiplier, VNL);

    vty_out(vty, " SPF algorithm ");
    if (o->ts_spf.tv_sec || o->ts_spf.tv_usec)
    {
        timersub(&now, &o->ts_spf, &result);
        timerstring(&result, buf, sizeof(buf));
        ospf6_spf_reason_string(o->last_spf_reason, rbuf, sizeof(rbuf));
        vty_out(vty, "last executed %s ago, reason %s%s", buf, rbuf, VNL);
        vty_out (vty, " Last SPF duration %ld sec %ld usec%s",
                 o->ts_spf_duration.tv_sec, o->ts_spf_duration.tv_usec, VNL);
    }
    else
        vty_out(vty, "has not been run$%s", VNL);
    threadtimer_string(now, o->t_spf_calc, buf, sizeof(buf));
    vty_out (vty, " SPF timer %s%s%s",
             (o->t_spf_calc ? "due in " : "is "), buf, VNL);

    if (CHECK_FLAG (o->flag, OSPF6_STUB_ROUTER))
        vty_out (vty, " Router Is Stub Router%s", VNL);

    /* LSAs */
    vty_out (vty, " Number of AS scoped LSAs is %u%s",
             o->lsdb->count, VNL);

    /* Areas */
    vty_out (vty, " Number of areas in this router is %u%s",
             listcount (o->area_list), VNL);

    if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_CHANGES))
    {
        if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_DETAIL))
            vty_out(vty, " All adjacency changes are logged%s",VTY_NEWLINE);
        else
            vty_out(vty, " Adjacency changes are logged%s",VTY_NEWLINE);
    }

    vty_out (vty, "%s",VTY_NEWLINE);

    for (ALL_LIST_ELEMENTS_RO (o->area_list, n, oa))
        ospf6_area_show (vty, oa);
}

/* show top level structures */
DEFUN (show_ipv6_ospf6,
       show_ipv6_ospf6_cmd,
       "show ipv6 ospf6",
       SHOW_STR
       IP6_STR
       OSPF6_STR)
{
    OSPF6_CMD_CHECK_RUNNING ();

    ospf6_show (vty, ospf6);
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_cmd,
       "show ipv6 ospf6 route",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
      )
{
    ospf6_route_table_show (vty, argc, argv, ospf6->route_table);
    return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_detail_cmd,
       "show ipv6 ospf6 route (X:X::X:X|X:X::X:X/M|detail|summary)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 address\n"
       "Specify IPv6 prefix\n"
       "Detailed information\n"
       "Summary of route table\n"
      )

DEFUN (show_ipv6_ospf6_route_match,
       show_ipv6_ospf6_route_match_cmd,
       "show ipv6 ospf6 route X:X::X:X/M match",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
      )
{
    const char *sargv[CMD_ARGC_MAX];
    int i, sargc;

    /* copy argv to sargv and then append "match" */
    for (i = 0; i < argc; i++)
        sargv[i] = argv[i];
    sargc = argc;
    sargv[sargc++] = "match";
    sargv[sargc] = NULL;

    ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route_match_detail,
       show_ipv6_ospf6_route_match_detail_cmd,
       "show ipv6 ospf6 route X:X::X:X/M match detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
       "Detailed information\n"
      )
{
    const char *sargv[CMD_ARGC_MAX];
    int i, sargc;

    /* copy argv to sargv and then append "match" and "detail" */
    for (i = 0; i < argc; i++)
        sargv[i] = argv[i];
    sargc = argc;
    sargv[sargc++] = "match";
    sargv[sargc++] = "detail";
    sargv[sargc] = NULL;

    ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
    return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_route_match,
       show_ipv6_ospf6_route_longer_cmd,
       "show ipv6 ospf6 route X:X::X:X/M longer",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes longer than the specified route\n"
      )

DEFUN (show_ipv6_ospf6_route_match_detail,
       show_ipv6_ospf6_route_longer_detail_cmd,
       "show ipv6 ospf6 route X:X::X:X/M longer detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes longer than the specified route\n"
       "Detailed information\n"
      );

ALIAS (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_type_cmd,
       "show ipv6 ospf6 route (intra-area|inter-area|external-1|external-2)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
      )

DEFUN (show_ipv6_ospf6_route_type_detail,
       show_ipv6_ospf6_route_type_detail_cmd,
       "show ipv6 ospf6 route (intra-area|inter-area|external-1|external-2) detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
       "Detailed information\n"
      )
{
    const char *sargv[CMD_ARGC_MAX];
    int i, sargc;

    /* copy argv to sargv and then append "detail" */
    for (i = 0; i < argc; i++)
        sargv[i] = argv[i];
    sargc = argc;
    sargv[sargc++] = "detail";
    sargv[sargc] = NULL;

    ospf6_route_table_show (vty, sargc, sargv, ospf6->route_table);
    return CMD_SUCCESS;
}

#ifdef TWOD
#if 1
int
ospf6_print_one_route_to_huawei(struct ospf6_route *route)
{
    char buf[64];// next hop
    int i =0,j=0;
    char nextaddr[64];

    int zhiflag = 0;
    int nextflag = 0;

    memset(buf,0,64);
    prefix2str(&route->prefix, buf, sizeof(buf));//zlw

    for(i=0; i<4; i++)
    {
        memset(nextaddr,0,64);
        inet_ntop(AF_INET6, &(route->nexthop[i].address), nextaddr, sizeof(nextaddr));

        if(strcmp("::1",nextaddr) !=0)
        {
            if(strcmp("::",nextaddr) ==0
                    && strcmp("unknown",ifindex2ifname(route->nexthop[i].ifindex))!=0)//zhi lian
            {
                zhiflag = 1;
                j=i;
            }

            //have next hop
            if(strncmp("fe80::",nextaddr,6) ==0)
            {
                nextflag = 1;
                j = i;
            }
        }
    }

    if(zhiflag== 1)//zhi lian
    {
        //del
        if(route->flag == 74)
        {
            //ospf6_parse_route_to_huawei(buf,NULL,route->nexthop[j].ifindex,0);

            //    ospf6_del_one_ipv6_route_xml(buf);
        }

        //add
        /*   if(route->flag == 10)
           {
               //ospf6_parse_route_to_huawei(buf,NULL,route->nexthop[j].ifindex,1);

               ospf6_write_one_ipv6_route_to_xml(buf,
                                           ifindex2ifname(route->nexthop[j].ifindex),
                                           "10",
                                           NULL);
           }
          */ //modify
        /*  if(route->flag == 9)
          {
              //ospf6_parse_route_to_huawei(buf,NULL,route->nexthop[j].ifindex,3);

              ospf6_write_one_ipv6_route_to_xml(buf,
                                          ifindex2ifname(route->nexthop[j].ifindex),
                                          "9",
                                          NULL);
          }
        */
    }

    if(nextflag == 1)
    {

        memset(nextaddr,0,64);
        inet_ntop(AF_INET6, &(route->nexthop[j].address), nextaddr, sizeof(nextaddr));

        //del one route
        if(route->flag == 74)
        {
            //ospf6_parse_route_to_huawei(buf,nextaddr,route->nexthop[j].ifindex,0);
            //     ospf6_del_one_ipv6_route_xml(buf);
        }
        //add one route
        /*  if(route->flag == 10)
          {
              //ospf6_parse_route_to_huawei(buf,nextaddr,route->nexthop[j].ifindex,1);
              ospf6_write_one_ipv6_route_to_xml(buf,
                                          ifindex2ifname(route->nexthop[j].ifindex),
                                          "10",
                                          nextaddr);
          }
          //mdy one route
          if(route->flag == 9)
          {
              //ospf6_parse_route_to_huawei(buf,nextaddr,route->nexthop[j].ifindex,3);
        //       ospf6_write_one_ipv6_route_to_xml(buf,
                                          ifindex2ifname(route->nexthop[j].ifindex),
                                          "9",
                                          nextaddr);
          }
        */
    }

    return 0;
}
#endif
static struct ospf6_lsa_twod *
ospf6_lsa_twod_lookup(struct prefix_ipv6 *pdst,struct prefix_ipv6 *psrc,
                      int cost,struct ospf6_area *oa)
{
    struct ospf6_lsa_twod *olt  = NULL; //twod-cost节点
    struct listnode       *node = NULL; //链表的移动节点


    char dst[50];
    char src[50];

    char dst2[50];
    char src2[50];
    memset(dst,0,50);
    memset(src,0,50);

    prefix2str(pdst, dst, sizeof(dst));//zlw
    prefix2str(psrc, src, sizeof(src));//zlw

    //遍历twod链表，查找是否存在相同的配置
    for(ALL_LIST_ELEMENTS_RO(oa->twod_list,node,olt))
    {
        memset(dst2,0,50);
        memset(src2,0,50);

        prefix2str(&olt->dst_pre, dst2, sizeof(dst));//zlw
        prefix2str(&olt->src_pre, src2, sizeof(src));//zlw

        if(   (strcmp((const char *)dst2,(const char *)dst)==0)
                && (strcmp((const char *)src2,(const char *)src)==0)
                &&(olt->cost == cost))
        {
            return olt;
        }
    }

    return NULL;
}

//只修改twod链表中的cost值
static struct ospf6_lsa_twod *
ospf6_lsa_twod_lookup_cost(struct prefix_ipv6 *pdst,struct prefix_ipv6 *psrc,
                           int cost,struct ospf6_area *oa)
{
    struct ospf6_lsa_twod *olt  = NULL; //twod-cost节点
    struct listnode       *node = NULL; //链表的移动节点


    char dst[50];
    char src[50];

    char dst2[50];
    char src2[50];

    memset(dst,0,50);
    memset(src,0,50);
    prefix2str(pdst, dst, sizeof(dst));//zlw
    prefix2str(psrc, src, sizeof(src));//zlw


    //遍历twod链表，查找是否存在相同的配置
    for(ALL_LIST_ELEMENTS_RO(oa->twod_list,node,olt))
    {
        memset(dst2,0,50);
        memset(src2,0,50);
        prefix2str(&olt->dst_pre, dst2, sizeof(dst));//zlw
        prefix2str(&olt->src_pre, src2, sizeof(src));//zlw

        if(   (strcmp((const char *)dst2,(const char *)dst)==0)
                && (strcmp((const char *)src2,(const char *)src)==0))
        {
            olt->cost = cost;
            return olt;
        }
    }

    return NULL;
}
#endif

#ifdef TWOD
//遍历twod-cost  查找待删除的节点
int
ospf6_lsa_twod_del_node(struct ospf6_area *oa ,struct ospf6_lsa_twod **twod)
{
    struct ospf6_lsa_twod *olt  = NULL; //twod-cost节点
    struct listnode       *node = NULL; //链表的移动节点

    //遍历twod链表，查找是否存在相同的配置
    for(ALL_LIST_ELEMENTS_RO(oa->twod_list,node,olt))
    {
        //printf("zlw==ospf6_lsa_twod_del_node 111\n");
        //找到待删除的节点
        if(olt->operate == 0)
        {
            //printf("zlw==ospf6_lsa_twod_del_node operate ==0\n");
            *twod = olt;
            return 0;
        }
    }
    twod = NULL;
    return 0;
}

//增加一条二维路由配置，并创建twod-cost节点
static int
ospf6_lsa_twod_create(struct vty *vty,struct prefix_ipv6 *dst,
                      struct prefix_ipv6 *src,int cost)
{
    struct ospf6          *op   = ospf6;    //赋值ospf6 全局变量
    struct ospf6_lsa_twod *olt  = NULL;     //新配置的twod-cost节点
    struct listnode       *node = NULL;     //链表的移动节点
    struct ospf6_area     *oa   = NULL;     //area 区域
    u_int32_t area_id_temp      = 0;        //area id 临时值

    int vtyflag = 1;

    if(NULL == vty)
    {
        vtyflag = 0;
    }
    //为twod-cost节点申请空间
    olt = XCALLOC(MTYPE_OSPF6_LSA_TWOD,sizeof(struct ospf6_lsa_twod));

    //判读区域号  临时定义区域为 0.0.0.0
    inet_pton(AF_INET,"0.0.0.0",&area_id_temp);

    //遍历区域链表，查找是否存在此区域
    oa = ospf6_area_lookup(area_id_temp,op);

    // 这个区域不存在
    if(NULL == oa)
    {
        if(1 == vtyflag)
            vty_out(vty,"  the area 0.0.0.0 not exist!\r\n");
        return -1;
    }

    //遍历指定区域的twod链表，查找是否相同配置的节点
#if 1 // del haozhiqiang 2016-1-27
    if(ospf6_lsa_twod_lookup(dst,src,cost,oa) != NULL)
    {
        if(1 == vtyflag)
            vty_out(vty,"  the twod-cost have exist!!!\r\n");
        return -1;
    }
#endif

    //如果只是cost值不同，则修改cost值
    if(ospf6_lsa_twod_lookup_cost(dst,src,cost,oa) == NULL)
    {
        //添加twod-cost节点
        olt->operate = 1;       // 1 增加节点  0 删除节点
        olt->dst_pre = *dst;    // 目的地址前缀
        olt->src_pre = *src;    // 源地址前缀
        olt->cost    = cost;    // 开销值

        //在此区域的twod链表中增加节点
        listnode_add(oa->twod_list,olt);

    }

    //郝志强 发送二维路由配置
    OSPF6_E_INTRA_PREFIX_LSA_SCHEDULE_STUB(oa);

    return 0;
}
//删除 twod-cost 节点
static int
ospf6_lsa_twod_del(struct vty *vty,struct prefix_ipv6 *dst,
                   struct prefix_ipv6 *src,int cost)
{
    struct ospf6          *op   = ospf6;    //赋值ospf6 全局变量
    struct ospf6_area     *oa   = NULL;     //area 区域
    struct ospf6_lsa_twod *olt  = NULL;     //twod-cost节点

    u_int32_t area_id_temp;//area id 临时值

    int vtyflag = 1;
    if(1 == vtyflag)
    {
        vtyflag = 0;
    }

    //判断区域号  临时定义为0.0.0.0
    inet_pton(AF_INET,"0.0.0.0",&area_id_temp);

    //遍历区域链表，判断是否存在此区域
    oa = ospf6_area_lookup(area_id_temp,op);
    // 这个区域不存在
    if(NULL == oa)
    {
        if(1 == vtyflag)
            vty_out(vty,"  the area 0.0.0.0 not exist!\r\n");
        return -1;
    }

    //遍历指定区域的twod链表，查找是否相同配置的节点
    olt = ospf6_lsa_twod_lookup(dst,src,cost,oa);
    if(olt == NULL)
    {
        if(1 == vtyflag)
            vty_out(vty,"  the twod-cost node not exist!!!\r\n");
        return -1;
    }

    olt->operate = 0;//删除节点

    //郝志强的删除节点函数
    OSPF6_E_INTRA_PREFIX_LSA_SCHEDULE_STUB(oa);

    return 0;
}

//zlw add for twod_cost  命令处理函数
static int
ospf6_twod_cost_addr_prefix(struct vty *vty,int flag,
                            char *dst_addr,char *src_addr,int cost)
{
    struct prefix_ipv6 dst_pre;  //destination address prefix
    struct prefix_ipv6 src_pre;  //source address prefix
    int ret;
    int vtyflag = 1; //临时添加这个flag 控制vty的 zlw
    int rtn_val = 0;

    if(NULL == vty)
    {
        vtyflag = 0;
    }

    //dst_prefix
    ret = str2prefix_ipv6(dst_addr,&dst_pre);
    if ((ret != 1)||(dst_pre.family != AF_INET6))
    {
        if(1 == vtyflag)
            vty_out(vty,"error:dst_addr=%s %s",dst_addr,VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    //src_prefix
    ret = str2prefix_ipv6(src_addr,&src_pre);
    if ((ret != 1)||(src_pre.family != AF_INET6))
    {
        if(1 == vtyflag)
            vty_out(vty,"error:src_addr=%s %s",src_addr,VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //如果twod-cost使能
    if(twod_enable == 1)
    {
        // flag == 1 增加配置
        if(flag ==1)
        {
            rtn_val = ospf6_lsa_twod_create(vty,&dst_pre,&src_pre,cost);

        }
        //flag == 0 删除配置
        if(flag == 0)
        {
            rtn_val = ospf6_lsa_twod_del(vty,&dst_pre,&src_pre,cost);
        }
    }
    //如果twod-cost非使能
    if(twod_enable == 0)
    {
        if(1 == vtyflag)
        {
            vty_out(vty,"twod-cost state is disable!!! %s",VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}
#if 1
int ospf6_twod_route_add_xml(char *pDst,char *pSrc,char *pOut_if,char *pFlag,char *pNext_hop)
{
    int fd;
    strcpy(vty_p[twod_colcu].dst_addr_pre,pDst);
    strcpy(vty_p[twod_colcu].sec_addr_pre,pSrc);
    strcpy(vty_p[twod_colcu].ifiname,pOut_if);
    strcpy(vty_p[twod_colcu].next_hop,pNext_hop);
    strcpy(vty_p[twod_colcu].flagval,pFlag);
    twod_colcu++;
    zlog_debug("the twod_colcu value is %d ",twod_colcu);
    return 0;
}
#endif
#if 1
int
ospf6_twod_route_del_xml(char *pDst,char *pSrc)
{

    zlog_debug("*****enter the delete twod route *********");

    int i=0;
    int j=0,cov;
    for(i=0; i<twod_colcu; i++)
    {
        if((strcmp(vty_p[i].dst_addr_pre,pDst)==0)&&(strcmp(vty_p[i].sec_addr_pre,pSrc)==0))
        {
            memset(&vty_p[i],0,sizeof(vty_pip));

            for(j=i+1; j<twod_colcu; j++)
            {

                strcpy(vty_p[j-1].dst_addr_pre,vty_p[j].dst_addr_pre);
                strcpy(vty_p[j-1].sec_addr_pre,vty_p[j].sec_addr_pre);
                strcpy(vty_p[j-1].ifiname,vty_p[j].ifiname);
                strcpy(vty_p[j-1].next_hop,vty_p[j].next_hop);
                strcpy(vty_p[j-1].flagval,vty_p[j].flagval);
                memset(&vty_p[j],0,sizeof( vty_pip));

            }
            if(twod_colcu>0)
                twod_colcu--;

        }

    }
}
#endif

//zlw for twod-cost dst-prefix src-prefix cost
DEFUN (ospf6_twod_dst_prefix_src_prefix_cost,
       ospf6_twod_dst_prefix_src_prefix_cost_cmd,
       "twod-cost X:X::X:X/M X:X::X:X/M M",
       "Extend LSA\n"
       "destination address (e.g. 2000::1/24)\n"
       "source address (e.g. 2001::1/48)\n"
       "cost value\n"
      )
{
    //第2个参数 为1 :添加
    return ospf6_twod_cost_addr_prefix(vty,1,argv[0],argv[1],atoi(argv[2]));
}

//zlw for no twod-cost
DEFUN (no_ospf6_twod_dst_prefix_src_prefix_cost,
       no_ospf6_twod_dst_prefix_src_prefix_cost_cmd,
       "no twod-cost X:X::X:X/M X:X::X:X/M M",
       "OSPFv6 area parameters\n"
       "Extend LSA\n"
       "destination address (e.g. 2000::1/24)\n"
       "source address (e.g. 2001::1/48)\n"
       "cost value\n"
      )
{
    //第2个参数 为0 :删除
    return ospf6_twod_cost_addr_prefix(vty,0,argv[0],argv[1],atoi(argv[2]));
}

//zlw for twod-cost enable
DEFUN (ospf6_twod_cost_enable,
       ospf6_twod_cost_enable_cmd,
       "twod-cost enable",
       "Extend LSA\n"
       "enable twod-cost\n"
      )
{
    vty_out(vty,"twod-cost enable %s",VTY_NEWLINE);

    twod_enable = 1;//twod-cost 使能
    return CMD_SUCCESS;
}

//zlw for no twod-cost enable
DEFUN (no_ospf6_twod_cost_enable,
       no_ospf6_twod_cost_enable_cmd,
       "no twod-cost enable",
       "OSPFv6 area parameters\n"
       "Extend LSA\n"
       "disable twod-cost\n"
      )
{
    vty_out(vty,"twod-cost disable %s",VTY_NEWLINE);

    //twod-cost 非使能
    twod_enable = 0;

    return CMD_SUCCESS;
}
#endif

/******************************************************************************/
/* zlw    twod-cost    end                                                    */
/******************************************************************************/
static void
ospf6_stub_router_config_write (struct vty *vty)
{
    if (CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
        vty_out (vty, " stub-router administrative%s", VNL);
    }
    return;
}

/* OSPF configuration write function. */
static int
config_write_ospf6 (struct vty *vty)
{
    char router_id[16];
    struct listnode *j, *k;
    struct ospf6_area *oa;
    struct ospf6_interface *oi;

    /* OSPFv6 configuration. */
    if (ospf6 == NULL)
        return CMD_SUCCESS;
#if 0
    //0.99.21
    if (CHECK_FLAG (ospf6->flag, OSPF6_DISABLED))
        return CMD_SUCCESS;
#endif

    inet_ntop (AF_INET, &ospf6->router_id_static, router_id, sizeof (router_id));
    vty_out (vty, "router ospf6%s", VNL);
    if (ospf6->router_id_static != 0)
        vty_out (vty, " router-id %s%s", router_id, VNL);

    /* log-adjacency-changes flag print. */
    if (CHECK_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES))
    {
        vty_out(vty, " log-adjacency-changes");
        if (CHECK_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL))
            vty_out(vty, " detail");
        vty_out(vty, "%s", VTY_NEWLINE);
    }

    if (ospf6->ref_bandwidth != OSPF6_REFERENCE_BANDWIDTH)
        vty_out (vty, " auto-cost reference-bandwidth %d%s", ospf6->ref_bandwidth / 1000,
                 VNL);

    ospf6_stub_router_config_write (vty);
    ospf6_redistribute_config_write (vty);
    ospf6_area_config_write (vty);
    ospf6_spf_config_write (vty);

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, j, oa))
    {
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
            vty_out (vty, " interface %s area %s%s",
                     oi->interface->name, oa->name, VNL);
    }
    vty_out (vty, "!%s", VNL);
    return 0;
}

/* OSPF6 node structure. */
static struct cmd_node ospf6_node =
{
    OSPF6_NODE,
    "%s(config-ospf6)# ",
    1 /* VTYSH */
};

/* Install ospf related commands. */
void
ospf6_top_init (void)
{
    /* Install ospf6 top node. */
    install_node (&ospf6_node, config_write_ospf6);

    install_element (VIEW_NODE, &show_ipv6_ospf6_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd);
    install_element (CONFIG_NODE, &router_ospf6_cmd);
    install_element (CONFIG_NODE, &no_router_ospf6_cmd);

    install_element (VIEW_NODE, &show_ipv6_ospf6_route_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_detail_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_longer_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_longer_detail_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_type_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_route_type_detail_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_detail_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_match_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_longer_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_longer_detail_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_type_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_route_type_detail_cmd);

    install_default (OSPF6_NODE);
    install_element (OSPF6_NODE, &ospf6_router_id_cmd);
    install_element (OSPF6_NODE, &no_ospf6_router_id_cmd);
    install_element (OSPF6_NODE, &ospf6_log_adjacency_changes_cmd);
    install_element (OSPF6_NODE, &ospf6_log_adjacency_changes_detail_cmd);
    install_element (OSPF6_NODE, &no_ospf6_log_adjacency_changes_cmd);
    install_element (OSPF6_NODE, &no_ospf6_log_adjacency_changes_detail_cmd);
    install_element (OSPF6_NODE, &ospf6_interface_area_cmd);
    install_element (OSPF6_NODE, &no_ospf6_interface_area_cmd);
    install_element (OSPF6_NODE, &ospf6_stub_router_admin_cmd);
#ifdef TWOD
    install_element (OSPF6_NODE, &ospf6_twod_dst_prefix_src_prefix_cost_cmd);//zlw
    install_element (OSPF6_NODE, &no_ospf6_twod_dst_prefix_src_prefix_cost_cmd);//zlw
    install_element (OSPF6_NODE, &ospf6_twod_cost_enable_cmd);//zlw
    install_element (OSPF6_NODE, &no_ospf6_twod_cost_enable_cmd);//zlw
    install_element (OSPF6_NODE, &no_ospf6_stub_router_admin_cmd);
#endif
    /* For a later time
    install_element (OSPF6_NODE, &ospf6_stub_router_startup_cmd);
    install_element (OSPF6_NODE, &no_ospf6_stub_router_startup_cmd);
    install_element (OSPF6_NODE, &ospf6_stub_router_shutdown_cmd);
    install_element (OSPF6_NODE, &no_ospf6_stub_router_shutdown_cmd);
    */
}

