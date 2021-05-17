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
#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6d.h"

int
ospf6_area_cmp (void *va, void *vb)
{
    struct ospf6_area *oa = (struct ospf6_area *) va;
    struct ospf6_area *ob = (struct ospf6_area *) vb;
    return (ntohl (oa->area_id) < ntohl (ob->area_id) ? -1 : 1);
}

/* schedule routing table recalculation */
static void
ospf6_area_lsdb_hook_add (struct ospf6_lsa *lsa)
{
    struct ospf6_area *oa;//hzq add for OSPF6_LSTYPE_E_INTRA_PREFIX

    switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_ROUTER:
    case OSPF6_LSTYPE_NETWORK:
        if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        {
            zlog_debug ("Examin %s", lsa->name);
            zlog_debug ("Schedule SPF Calculation for %s",
                        OSPF6_AREA (lsa->lsdb->data)->name);
        }
        ospf6_spf_schedule (OSPF6_AREA (lsa->lsdb->data));
        break;

    case OSPF6_LSTYPE_INTRA_PREFIX:
        ospf6_intra_prefix_lsa_add (lsa);
        break;
#if 1  //add haozhiqiang 2015-12-17
    case OSPF6_LSTYPE_E_INTRA_PREFIX:

        printf("zlw===ospf6_area_lsdb_hook_add :OSPF6_LSTYPE_E_INTRA_PREFIX \n\n");

        oa = OSPF6_AREA(lsa->lsdb->data);
        printf("zlw==ospf6_area_lsdb_hook_add 12\n");

        //copy LSDA
        oa->lsdb1= lsdb_cpy_router_network(oa);
        printf("zlw==ospf6_area_lsdb_hook_add 13\n");
        //modify the cost of LSA
        Change_Router_meritc(lsa, oa);
        printf("zlw==ospf6_area_lsdb_hook_add 14\n");
        //save src address and dst address
        save_source_addr_prefix(lsa,oa);
        printf("zlw==ospf6_area_lsdb_hook_add 15\n");
        //start the spf
        ospf6_spf_schedule_e(oa);

        printf("zlw==ospf6_area_lsdb_hook_add 16\n");
        break;
#endif
    case OSPF6_LSTYPE_INTER_PREFIX:
    case OSPF6_LSTYPE_INTER_ROUTER:
        ospf6_abr_examin_summary (lsa, (struct ospf6_area *) lsa->lsdb->data);
        break;

    default:
        break;
    }
}

static void
ospf6_area_lsdb_hook_remove (struct ospf6_lsa *lsa)
{
    switch (ntohs (lsa->header->type))
    {
    case OSPF6_LSTYPE_ROUTER:
    case OSPF6_LSTYPE_NETWORK:
        if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        {
            zlog_debug ("LSA disappearing: %s", lsa->name);
            zlog_debug ("Schedule SPF Calculation for %s",
                        OSPF6_AREA (lsa->lsdb->data)->name);
        }
        ospf6_spf_schedule (OSPF6_AREA (lsa->lsdb->data));
        break;

    case OSPF6_LSTYPE_INTRA_PREFIX:
        ospf6_intra_prefix_lsa_remove (lsa);
        break;

    case OSPF6_LSTYPE_INTER_PREFIX:
    case OSPF6_LSTYPE_INTER_ROUTER:
        ospf6_abr_examin_summary (lsa, (struct ospf6_area *) lsa->lsdb->data);
        break;

    default:
        break;
    }
}

static void
ospf6_area_route_hook_add (struct ospf6_route *route)
{
    struct ospf6_route *copy = ospf6_route_copy (route);
    ospf6_route_add (copy, ospf6->route_table);
}

static void
ospf6_area_route_hook_remove (struct ospf6_route *route)
{
    struct ospf6_route *copy;

    copy = ospf6_route_lookup_identical (route, ospf6->route_table);
    if (copy)
        ospf6_route_remove (copy, ospf6->route_table);
}

//add haozhiqiang  add route_table1
static void
ospf6_area_route_hook_add_e(struct ospf6_route *route)
{
    struct ospf6_route *copy = ospf6_route_copy (route);
    ospf6_route_add(copy, ospf6->route_table1);//route_table1   add by haozhiqiang
}
//add haozhiqiang  del route_table1
static void
ospf6_area_route_hook_remove_e(struct ospf6_route *route)
{
    struct ospf6_route *copy;

    copy = ospf6_route_lookup_identical (route, ospf6->route_table);
    if (copy)
        ospf6_route_remove(copy, ospf6->route_table1);
}

/* Make new area structure */
struct ospf6_area *
ospf6_area_create (u_int32_t area_id, struct ospf6 *o)
{
    struct ospf6_area *oa;
    struct ospf6_route *route;

    oa = XCALLOC (MTYPE_OSPF6_AREA, sizeof (struct ospf6_area));

    inet_ntop (AF_INET, &area_id, oa->name, sizeof (oa->name));
    oa->area_id = area_id;
    oa->if_list = list_new ();
    oa->twod_list = list_new(); //add by zlw

    oa->lsdb = ospf6_lsdb_create (oa);
    oa->lsdb->hook_add = ospf6_area_lsdb_hook_add;
    oa->lsdb->hook_remove = ospf6_area_lsdb_hook_remove;
    oa->lsdb_self = ospf6_lsdb_create (oa);

    oa->lsdb_bak = ospf6_lsdb_create (oa);
    oa->lsdb_bak->hook_add = NULL;
    oa->lsdb_bak->hook_remove = NULL;
    oa->lsdb1 = ospf6_lsdb_create(oa);//haozhiqiang


    oa->spf_table = OSPF6_ROUTE_TABLE_CREATE (AREA, SPF_RESULTS);
    oa->spf_table->scope = oa;
    oa->spf_table1 = OSPF6_ROUTE_TABLE_CREATE (AREA, SPF_RESULTS);
    oa->spf_table1->scope = oa;
    oa->route_table = OSPF6_ROUTE_TABLE_CREATE (AREA, ROUTES);
    oa->route_table->scope = oa;
    oa->route_table->hook_add = ospf6_area_route_hook_add;
    oa->route_table->hook_remove = ospf6_area_route_hook_remove;

    oa->range_table = OSPF6_ROUTE_TABLE_CREATE (AREA, PREFIX_RANGES);
    oa->range_table->scope = oa;
    oa->summary_prefix = OSPF6_ROUTE_TABLE_CREATE (AREA, SUMMARY_PREFIXES);
    oa->summary_prefix->scope = oa;
    oa->summary_router = OSPF6_ROUTE_TABLE_CREATE (AREA, SUMMARY_ROUTERS);
    oa->summary_router->scope = oa;

    /* set default options */
    OSPF6_OPT_SET (oa->options, OSPF6_OPT_V6);
    OSPF6_OPT_SET (oa->options, OSPF6_OPT_E);
    OSPF6_OPT_SET (oa->options, OSPF6_OPT_R);

    oa->ospf6 = o;
    listnode_add_sort (o->area_list, oa);

    /* import athoer area's routes as inter-area routes */
    for (route = ospf6_route_head (o->route_table); route;
            route = ospf6_route_next (route))
        ospf6_abr_originate_summary_to_area (route, oa);

    return oa;
}

void
ospf6_area_delete (struct ospf6_area *oa)
{
    struct listnode *n, *nnode;
    struct ospf6_interface *oi;

    ospf6_route_table_delete (oa->range_table);
    ospf6_route_table_delete (oa->summary_prefix);
    ospf6_route_table_delete (oa->summary_router);

    /* ospf6 interface list */
    for (ALL_LIST_ELEMENTS (oa->if_list, n, nnode, oi))
    {
        ospf6_interface_delete (oi);
    }
    list_delete (oa->if_list);

    ospf6_lsdb_delete (oa->lsdb);
    ospf6_lsdb_delete (oa->lsdb_self);

    ospf6_spf_table_finish (oa->spf_table);
    ospf6_route_table_delete (oa->spf_table);
    ospf6_route_table_delete (oa->route_table);

    THREAD_OFF (oa->thread_spf_calculation);
    THREAD_OFF (oa->thread_route_calculation);

    listnode_delete (oa->ospf6->area_list, oa);
    oa->ospf6 = NULL;

    /* free area */
    XFREE (MTYPE_OSPF6_AREA, oa);
}

struct ospf6_area *
ospf6_area_lookup (u_int32_t area_id, struct ospf6 *ospf6)
{
    struct ospf6_area *oa;
    struct listnode *n;

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, n, oa))
        if (oa->area_id == area_id)
            return oa;

    return (struct ospf6_area *) NULL;
}

static struct ospf6_area *
ospf6_area_get (u_int32_t area_id, struct ospf6 *o)
{
    struct ospf6_area *oa;
    oa = ospf6_area_lookup (area_id, o);
    if (oa == NULL)
        oa = ospf6_area_create (area_id, o);
    return oa;
}

void
ospf6_area_enable (struct ospf6_area *oa)
{
    struct listnode *node, *nnode;
    struct ospf6_interface *oi;

    SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
        ospf6_interface_enable (oi);
}

void
ospf6_area_disable (struct ospf6_area *oa)
{
    struct listnode *node, *nnode;
    struct ospf6_interface *oi;

    UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
        ospf6_interface_disable (oi);
}


void
ospf6_area_show (struct vty *vty, struct ospf6_area *oa)
{
    struct listnode *i;
    struct ospf6_interface *oi;

    vty_out (vty, " Area %s%s", oa->name, VNL);
    vty_out (vty, "     Number of Area scoped LSAs is %u%s",
             oa->lsdb->count, VNL);

    vty_out (vty, "     Interface attached to this area:");
    for (ALL_LIST_ELEMENTS_RO (oa->if_list, i, oi))
        vty_out (vty, " %s", oi->interface->name);

    vty_out (vty, "%s", VNL);
}


#define OSPF6_CMD_AREA_LOOKUP(str, oa)                     \
{                                                          \
  u_int32_t area_id = 0;                                   \
  if (inet_pton (AF_INET, str, &area_id) != 1)             \
    {                                                      \
      vty_out (vty, "Malformed Area-ID: %s%s", str, VNL);  \
      return CMD_SUCCESS;                                  \
    }                                                      \
  oa = ospf6_area_lookup (area_id, ospf6);                 \
  if (oa == NULL)                                          \
    {                                                      \
      vty_out (vty, "No such Area: %s%s", str, VNL);       \
      return CMD_SUCCESS;                                  \
    }                                                      \
}

#define OSPF6_CMD_AREA_GET(str, oa)                        \
{                                                          \
  u_int32_t area_id = 0;                                   \
  if (inet_pton (AF_INET, str, &area_id) != 1)             \
    {                                                      \
      vty_out (vty, "Malformed Area-ID: %s%s", str, VNL);  \
      return CMD_SUCCESS;                                  \
    }                                                      \
  oa = ospf6_area_get (area_id, ospf6);                    \
}

DEFUN (area_range,
       area_range_cmd,
       "area A.B.C.D range X:X::X:X/M",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
      )
{
    int ret;
    struct ospf6_area *oa;
    struct prefix prefix;
    struct ospf6_route *range;

    OSPF6_CMD_AREA_GET (argv[0], oa);
    argc--;
    argv++;

    ret = str2prefix (argv[0], &prefix);
    if (ret != 1 || prefix.family != AF_INET6)
    {
        vty_out (vty, "Malformed argument: %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }
    argc--;
    argv++;

    range = ospf6_route_lookup (&prefix, oa->range_table);
    if (range == NULL)
    {
        range = ospf6_route_create ();
        range->type = OSPF6_DEST_TYPE_RANGE;
        range->prefix = prefix;
    }

    if (argc)
    {
        if (! strcmp (argv[0], "not-advertise"))
            SET_FLAG (range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
        else if (! strcmp (argv[0], "advertise"))
            UNSET_FLAG (range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
    }

    if (range->rnode)
    {
        vty_out (vty, "Range already defined: %s%s", argv[-1], VNL);
        return CMD_WARNING;
    }

    ospf6_route_add (range, oa->range_table);
    return CMD_SUCCESS;
}

ALIAS (area_range,
       area_range_advertise_cmd,
       "area A.B.C.D range X:X::X:X/M (advertise|not-advertise)",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
      )

DEFUN (no_area_range,
       no_area_range_cmd,
       "no area A.B.C.D range X:X::X:X/M",
       "OSPF area parameters\n"
       OSPF6_AREA_ID_STR
       "Configured address range\n"
       "Specify IPv6 prefix\n"
      )
{
    int ret;
    struct ospf6_area *oa;
    struct prefix prefix;
    struct ospf6_route *range;

    OSPF6_CMD_AREA_GET (argv[0], oa);
    argc--;
    argv++;

    ret = str2prefix (argv[0], &prefix);
    if (ret != 1 || prefix.family != AF_INET6)
    {
        vty_out (vty, "Malformed argument: %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }

    range = ospf6_route_lookup (&prefix, oa->range_table);
    if (range == NULL)
    {
        vty_out (vty, "Range %s does not exists.%s", argv[0], VNL);
        return CMD_SUCCESS;
    }

    ospf6_route_remove (range, oa->range_table);
    return CMD_SUCCESS;
}

void
ospf6_area_config_write (struct vty *vty)
{
    struct listnode *node;
    struct ospf6_area *oa;
    struct ospf6_route *range;
    char buf[128];

    char dst_buf[128];//zlw
    char src_buf[128];//zlw

    struct listnode *t_node;//zlw
    struct ospf6_lsa_twod *olt;//zlw

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
        for (range = ospf6_route_head (oa->range_table); range;
                range = ospf6_route_next (range))
        {
            prefix2str (&range->prefix, buf, sizeof (buf));
            vty_out (vty, " area %s range %s%s", oa->name, buf, VNL);
        }
        if (PREFIX_NAME_IN (oa))
            vty_out (vty, " area %s filter-list prefix %s in%s",
                     oa->name, PREFIX_NAME_IN (oa), VNL);
        if (PREFIX_NAME_OUT (oa))
            vty_out (vty, " area %s filter-list prefix %s out%s",
                     oa->name, PREFIX_NAME_OUT (oa), VNL);
        if (IMPORT_NAME (oa))
            vty_out (vty, " area %s import-list %s%s",
                     oa->name, IMPORT_NAME (oa), VNL);
        if (EXPORT_NAME (oa))
            vty_out (vty, " area %s export-list %s%s",
                     oa->name, EXPORT_NAME (oa), VNL);

        //add by zlw
        for(ALL_LIST_ELEMENTS_RO(oa->twod_list,t_node,olt))
        {
            prefix2str((struct prefix *)&olt->dst_pre, dst_buf, sizeof(dst_buf));
            prefix2str((struct prefix *)&olt->src_pre, src_buf, sizeof(src_buf));
            vty_out(vty," twod-cost %s %s %d\r\n",dst_buf,src_buf,olt->cost);
        }

    }
}

DEFUN (area_filter_list,
       area_filter_list_cmd,
       "area A.B.C.D filter-list prefix WORD (in|out)",
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Filter networks between OSPFv6 areas\n"
       "Filter prefixes between OSPFv6 areas\n"
       "Name of an IPv6 prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
    struct ospf6_area *area;
    struct prefix_list *plist;

    OSPF6_CMD_AREA_GET (argv[0], area);
    argc--;
    argv++;

    plist = prefix_list_lookup (AFI_IP6, argv[0]);
    if (strncmp (argv[1], "in", 2) == 0)
    {
        PREFIX_LIST_IN (area) = plist;
        if (PREFIX_NAME_IN (area))
            free (PREFIX_NAME_IN (area));

        PREFIX_NAME_IN (area) = strdup (argv[0]);
        ospf6_abr_reimport (area);
    }
    else
    {
        PREFIX_LIST_OUT (area) = plist;
        if (PREFIX_NAME_OUT (area))
            free (PREFIX_NAME_OUT (area));

        PREFIX_NAME_OUT (area) = strdup (argv[0]);
        ospf6_abr_enable_area (area);
    }

    return CMD_SUCCESS;
}

DEFUN (no_area_filter_list,
       no_area_filter_list_cmd,
       "no area A.B.C.D filter-list prefix WORD (in|out)",
       NO_STR
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Filter networks between OSPFv6 areas\n"
       "Filter prefixes between OSPFv6 areas\n"
       "Name of an IPv6 prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
    struct ospf6_area *area;
    struct prefix_list *plist;

    OSPF6_CMD_AREA_GET (argv[0], area);
    argc--;
    argv++;

    plist = prefix_list_lookup (AFI_IP6, argv[0]);
    if (strncmp (argv[1], "in", 2) == 0)
    {
        if (PREFIX_NAME_IN (area))
            if (strcmp (PREFIX_NAME_IN (area), argv[0]) != 0)
                return CMD_SUCCESS;

        PREFIX_LIST_IN (area) = NULL;
        if (PREFIX_NAME_IN (area))
            free (PREFIX_NAME_IN (area));

        PREFIX_NAME_IN (area) = NULL;
        ospf6_abr_reimport (area);
    }
    else
    {
        if (PREFIX_NAME_OUT (area))
            if (strcmp (PREFIX_NAME_OUT (area), argv[0]) != 0)
                return CMD_SUCCESS;

        PREFIX_LIST_OUT (area) = NULL;
        if (PREFIX_NAME_OUT (area))
            free (PREFIX_NAME_OUT (area));

        PREFIX_NAME_OUT (area) = NULL;
        ospf6_abr_enable_area (area);
    }

    return CMD_SUCCESS;
}

DEFUN (area_import_list,
       area_import_list_cmd,
       "area A.B.C.D import-list NAME",
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the acess-list\n")
{
    struct ospf6_area *area;
    struct access_list *list;

    OSPF6_CMD_AREA_GET(argv[0], area);

    list = access_list_lookup (AFI_IP6, argv[1]);

    IMPORT_LIST (area) = list;

    if (IMPORT_NAME (area))
        free (IMPORT_NAME (area));

    IMPORT_NAME (area) = strdup (argv[1]);
    ospf6_abr_reimport (area);

    return CMD_SUCCESS;
}

DEFUN (no_area_import_list,
       no_area_import_list_cmd,
       "no area A.B.C.D import-list NAME",
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Unset the filter for networks announced to other areas\n"
       "NAme of the access-list\n")
{
    struct ospf6_area *area;

    OSPF6_CMD_AREA_GET(argv[0], area);

    IMPORT_LIST (area) = 0;

    if (IMPORT_NAME (area))
        free (IMPORT_NAME (area));

    IMPORT_NAME (area) = NULL;
    ospf6_abr_reimport (area);

    return CMD_SUCCESS;
}

DEFUN (area_export_list,
       area_export_list_cmd,
       "area A.B.C.D export-list NAME",
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the acess-list\n")
{
    struct ospf6_area *area;
    struct access_list *list;

    OSPF6_CMD_AREA_GET(argv[0], area);

    list = access_list_lookup (AFI_IP6, argv[1]);

    EXPORT_LIST (area) = list;

    if (EXPORT_NAME (area))
        free (EXPORT_NAME (area));

    EXPORT_NAME (area) = strdup (argv[1]);
    ospf6_abr_enable_area (area);

    return CMD_SUCCESS;
}

DEFUN (no_area_export_list,
       no_area_export_list_cmd,
       "no area A.B.C.D export-list NAME",
       "OSPFv6 area parameters\n"
       "OSPFv6 area ID in IP address format\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
    struct ospf6_area *area;

    OSPF6_CMD_AREA_GET(argv[0], area);

    EXPORT_LIST (area) = 0;

    if (EXPORT_NAME (area))
        free (EXPORT_NAME (area));

    EXPORT_NAME (area) = NULL;
    ospf6_abr_enable_area (area);

    return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_spf_tree,
       show_ipv6_ospf6_spf_tree_cmd,
       "show ipv6 ospf6 spf tree",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n")
{
    struct listnode *node;
    struct ospf6_area *oa;
    struct ospf6_vertex *root;
    struct ospf6_route *route;
    struct prefix prefix;

    ospf6_linkstate_prefix (ospf6->router_id, htonl (0), &prefix);

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
        route = ospf6_route_lookup (&prefix, oa->spf_table);
        if (route == NULL)
        {
            vty_out (vty, "LS entry for root not found in area %s%s",
                     oa->name, VNL);
            continue;
        }
        root = (struct ospf6_vertex *) route->route_option;
        ospf6_spf_display_subtree (vty, "", 0, root);
    }

    return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_area_spf_tree,
       show_ipv6_ospf6_area_spf_tree_cmd,
       "show ipv6 ospf6 area A.B.C.D spf tree",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n")
{
    u_int32_t area_id;
    struct ospf6_area *oa;
    struct ospf6_vertex *root;
    struct ospf6_route *route;
    struct prefix prefix;

    ospf6_linkstate_prefix (ospf6->router_id, htonl (0), &prefix);

    if (inet_pton (AF_INET, argv[0], &area_id) != 1)
    {
        vty_out (vty, "Malformed Area-ID: %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }
    oa = ospf6_area_lookup (area_id, ospf6);
    if (oa == NULL)
    {
        vty_out (vty, "No such Area: %s%s", argv[0], VNL);
        return CMD_SUCCESS;
    }

    route = ospf6_route_lookup (&prefix, oa->spf_table);
    if (route == NULL)
    {
        vty_out (vty, "LS entry for root not found in area %s%s",
                 oa->name, VNL);
        return CMD_SUCCESS;
    }
    root = (struct ospf6_vertex *) route->route_option;
    ospf6_spf_display_subtree (vty, "", 0, root);

    return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_simulate_spf_tree_root,
       show_ipv6_ospf6_simulate_spf_tree_root_cmd,
       "show ipv6 ospf6 simulate spf-tree A.B.C.D area A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Show SPF tree\n"
       "Specify root's router-id to calculate another router's SPF tree\n")
{
    u_int32_t area_id;
    struct ospf6_area *oa;
    struct ospf6_vertex *root;
    struct ospf6_route *route;
    struct prefix prefix;
    u_int32_t router_id;
    struct ospf6_route_table *spf_table;
    unsigned char tmp_debug_ospf6_spf = 0;

    inet_pton (AF_INET, argv[0], &router_id);
    ospf6_linkstate_prefix (router_id, htonl (0), &prefix);

    if (inet_pton (AF_INET, argv[1], &area_id) != 1)
    {
        vty_out (vty, "Malformed Area-ID: %s%s", argv[1], VNL);
        return CMD_SUCCESS;
    }
    oa = ospf6_area_lookup (area_id, ospf6);
    if (oa == NULL)
    {
        vty_out (vty, "No such Area: %s%s", argv[1], VNL);
        return CMD_SUCCESS;
    }

    tmp_debug_ospf6_spf = conf_debug_ospf6_spf;
    conf_debug_ospf6_spf = 0;

    spf_table = OSPF6_ROUTE_TABLE_CREATE (NONE, SPF_RESULTS);
    ospf6_spf_calculation (router_id, spf_table, oa);

    conf_debug_ospf6_spf = tmp_debug_ospf6_spf;

    route = ospf6_route_lookup (&prefix, spf_table);
    if (route == NULL)
    {
        ospf6_spf_table_finish (spf_table);
        ospf6_route_table_delete (spf_table);
        return CMD_SUCCESS;
    }
    root = (struct ospf6_vertex *) route->route_option;
    ospf6_spf_display_subtree (vty, "", 0, root);

    ospf6_spf_table_finish (spf_table);
    ospf6_route_table_delete (spf_table);

    return CMD_SUCCESS;
}

void
ospf6_area_init (void)
{
    install_element (VIEW_NODE, &show_ipv6_ospf6_spf_tree_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_simulate_spf_tree_root_cmd);

    install_element (ENABLE_NODE, &show_ipv6_ospf6_spf_tree_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_simulate_spf_tree_root_cmd);

    install_element (OSPF6_NODE, &area_range_cmd);
    install_element (OSPF6_NODE, &area_range_advertise_cmd);
    install_element (OSPF6_NODE, &no_area_range_cmd);

    install_element (OSPF6_NODE, &area_import_list_cmd);
    install_element (OSPF6_NODE, &no_area_import_list_cmd);
    install_element (OSPF6_NODE, &area_export_list_cmd);
    install_element (OSPF6_NODE, &no_area_export_list_cmd);

    install_element (OSPF6_NODE, &area_filter_list_cmd);
    install_element (OSPF6_NODE, &no_area_filter_list_cmd);

}


//拷贝lsdb   add by haozhiqiang 2016-1-26
struct ospf6_lsdb *
lsdb_cpy_router_network(struct ospf6_area *oa)
{
    u_int16_t type;
    struct ospf6_lsa *lsa;

    //copy Router-lsa to lsdb1
    type = htons(OSPF6_LSTYPE_ROUTER);
    for(lsa = ospf6_lsdb_type_head(type,oa->lsdb); lsa; lsa = ospf6_lsdb_type_next(type,lsa))
    {
        ospf6_lsdb_add(ospf6_lsa_copy(lsa), oa->lsdb1);
    }

    //copy Network-lsa to lsdb1
    type = htons (OSPF6_LSTYPE_NETWORK);
    for(lsa = ospf6_lsdb_type_head(type,oa->lsdb); lsa; lsa = ospf6_lsdb_type_next(type,lsa))
    {
        ospf6_lsdb_add(ospf6_lsa_copy(lsa), oa->lsdb1);
    }

    //copy intra-prefix-lsa to lsdb1  zlw 2016-4-21
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
    for(lsa = ospf6_lsdb_type_head(type,oa->lsdb); lsa; lsa = ospf6_lsdb_type_next(type,lsa))
    {
        ospf6_lsdb_add(ospf6_lsa_copy(lsa), oa->lsdb1);
    }

    return  oa->lsdb1;
}

// add by hzq 2016-1-26  modify cost of LSA
void
Change_Router_meritc(struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
    struct ospf6_lsdb *lsdb1 = oa->lsdb1;

    struct ospf6_prefix *op_orig;
    struct ospf6_lsa *self;
    char *start, *end, *current_e;
    char buf[32], name[32], bits[16], options[32];
    struct ospf6_router_lsa *router_lsa;
    struct ospf6_router_lsdesc *lsdesc;

    if(lsa->header->type == htons (OSPF6_LSTYPE_E_INTRA_PREFIX) )
    {
        op_orig = (struct ospf6_prefix *)((caddr_t)lsa->header + sizeof(struct ospf6_lsa_header)+OSPF6_INTRA_PREFIX_LSA_MIN_SIZE);

        //only modify router lsa
        self = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_ROUTER),lsa->header->id,
                                 lsa->header->adv_router, lsdb1);

        if(self != NULL)
        {
            router_lsa = (struct ospf6_router_lsa *)((char *) self->header + sizeof (struct ospf6_lsa_header));

            start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
            end = (char *) self->header + ntohs (self->header->length);

            for (current_e = start;
                    current_e + sizeof (struct ospf6_router_lsdesc) <= end;
                    current_e += sizeof (struct ospf6_router_lsdesc))
            {
                lsdesc = (struct ospf6_router_lsdesc *)current_e;
                if(ntohs(op_orig->prefix_metric)<1000)
                    memcpy(&(lsdesc->metric), &(op_orig->prefix_metric), sizeof(u_int16_t));

#if 0
                printf("lsdesc->metric========%d\n",ntohs(lsdesc->metric));
                printf("Interface ID: %s\n",inet_ntop (AF_INET, &lsdesc->interface_id, buf, sizeof (buf)));
                printf("Neighbor Interface ID: %s\n",inet_ntop (AF_INET, &lsdesc->neighbor_interface_id,
                        buf, sizeof (buf)));
                printf("Neighbor Router ID: %s\n",
                       inet_ntop(AF_INET, &lsdesc->neighbor_router_id,
                                 buf, sizeof (buf)));
#endif

            }

        }

    }
}

//创建router_table   add haozhiqiang 2016-1-26
struct ospf6_route_table *
Create_Router_table1(struct ospf6_area *oa)
{
    //创建Router_table1
    struct ospf6_route_table *route_table1 = OSPF6_ROUTE_TABLE_CREATE (AREA, ROUTES);
    route_table1->scope = oa;
    route_table1->hook_add = ospf6_area_route_hook_add_e;
    route_table1->hook_remove =ospf6_area_route_hook_remove_e;
    return route_table1;
}

//save src address by  hzq
void
save_source_addr_prefix(struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
    struct in6_addr in6;//src address
    struct in6_addr d_in6;//dst address
    struct ospf6_prefix *op;

    char *end;
    struct ospf6_source_addr_prefix_TLV * addr_source;
    char buf[128];

    end = (char *) lsa->header + ntohs (lsa->header->length)-24;
    addr_source = ( struct ospf6_source_addr_prefix_TLV *)end;  //current+ OSPF6_PREFIX_SIZE (prefix)+4;

    op = (struct ospf6_prefix *)((char *) lsa->header
                                 + sizeof (struct ospf6_lsa_header)
                                 + sizeof (struct ospf6_intra_prefix_lsa));

    //dst address
    memset(&d_in6,0,sizeof(d_in6));
    memcpy(&d_in6,OSPF6_PREFIX_BODY(op),OSPF6_PREFIX_SPACE (op->prefix_length));
    memset(buf,0,128);
    inet_ntop(AF_INET6,&d_in6,buf,sizeof(buf));
    //printf("zlw==save_source_addr_prefix0 :dst prefix :%s/%d\n",buf, (op->prefix_length));

    memset(&oa->d_prefix,0,sizeof(struct prefix));
    oa->d_prefix.family = AF_INET6;
    oa->d_prefix.prefixlen = op->prefix_length;
    memcpy(&oa->d_prefix.u.prefix6,&d_in6,OSPF6_PREFIX_SPACE(op->prefix_length));

    //src address
    memset (&in6, 0, sizeof (in6));
    memcpy (&in6, end+8,OSPF6_PREFIX_SPACE (addr_source->tlv_length));

    memset(buf,0,sizeof(buf));
    inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
    //printf("zlw==save_source_addr_prefix1 : Source Prefix: %s/%d\n", buf, addr_source->tlv_length);

    memset (&oa->s_prefix, 0, sizeof (struct prefix));
    oa->s_prefix.family=AF_INET6;
    oa->s_prefix.prefixlen=addr_source->tlv_length;
    memcpy(&(oa->s_prefix.u.prefix6), &in6, OSPF6_PREFIX_SPACE (addr_source->tlv_length));

}

