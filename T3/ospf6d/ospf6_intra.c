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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
//end add by myj for two demesion route

#include <zebra.h>

#include "log.h"
#include "linklist.h"
#include "thread.h"
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"

//add by myj for two demesion route
#include "zebra/zserv.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_flood.h"
#include "ospf6d.h"

#include "zebra/zserv.h"
unsigned char conf_debug_ospf6_brouter = 0;
u_int32_t conf_debug_ospf6_brouter_specific_router_id;
u_int32_t conf_debug_ospf6_brouter_specific_area_id;

/******************************/
/* RFC2740 3.4.3.1 Router-LSA */
/******************************/

static int ospf6_router_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
    char *start, *end, *current;
    char buf[32], name[32], bits[16], options[32];
    struct ospf6_router_lsa *router_lsa;
    struct ospf6_router_lsdesc *lsdesc;

    router_lsa = (struct ospf6_router_lsa *) ((char *) lsa->header + sizeof (struct ospf6_lsa_header));

    ospf6_capability_printbuf (router_lsa->bits, bits, sizeof (bits));
    ospf6_options_printbuf (router_lsa->options, options, sizeof (options));
    vty_out (vty, "    Bits: %s Options: %s%s", bits, options, VNL);

    start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
    end = (char *) lsa->header + ntohs (lsa->header->length);
    for (current = start; current + sizeof (struct ospf6_router_lsdesc) <= end; current += sizeof (struct ospf6_router_lsdesc))
    {
        lsdesc = (struct ospf6_router_lsdesc *) current;

        if (lsdesc->type == OSPF6_ROUTER_LSDESC_POINTTOPOINT)
            snprintf (name, sizeof (name), "Point-To-Point");
        else if (lsdesc->type == OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK)
            snprintf (name, sizeof (name), "Transit-Network");
        else if (lsdesc->type == OSPF6_ROUTER_LSDESC_STUB_NETWORK)
            snprintf (name, sizeof (name), "Stub-Network");
        else if (lsdesc->type == OSPF6_ROUTER_LSDESC_VIRTUAL_LINK)
            snprintf (name, sizeof (name), "Virtual-Link");
        else
            snprintf (name, sizeof (name), "Unknown (%#x)", lsdesc->type);

        vty_out (vty, "    Type: %s Metric: %d%s", name, ntohs (lsdesc->metric), VNL);
        vty_out (vty, "    Interface ID: %s%s", inet_ntop (AF_INET, &lsdesc->interface_id, buf, sizeof (buf)), VNL);
        vty_out (vty, "    Neighbor Interface ID: %s%s", inet_ntop (AF_INET, &lsdesc->neighbor_interface_id, buf, sizeof (buf)), VNL);
        vty_out (vty, "    Neighbor Router ID: %s%s", inet_ntop (AF_INET, &lsdesc->neighbor_router_id, buf, sizeof (buf)), VNL);
    }
    return 0;
}

int ospf6_router_lsa_originate_for_leaving (struct thread *thread)
{
    struct ospf6_area *oa;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *lsa;

    u_int32_t link_state_id = 0;
    struct listnode *node, *nnode;
    struct listnode *j;
    struct ospf6_interface *oi;
    struct ospf6_neighbor *on, *drouter = NULL;
    struct ospf6_router_lsa *router_lsa;
    struct ospf6_router_lsdesc *lsdesc;
    u_int16_t type;
    u_int32_t router;
    int count;
    struct ospf6_lsa *lsa_bak;

    oa = (struct ospf6_area *) THREAD_ARG (thread);
    oa->thread_router_lsa = NULL;

    if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
        zlog_debug ("Originate Router-LSA for Area %s", oa->name);

    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    router_lsa = (struct ospf6_router_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_V6);
    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_E);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_MC);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_N);
    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_R);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_DC);

    if (ospf6_is_router_abr (ospf6))
        SET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_B);
    else
        UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_B);
    if (ospf6_asbr_is_asbr (ospf6))
        SET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_E);
    else
        UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_E);
    UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_V);
    UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_W);

    /* describe links for each interfaces */
    lsdesc = (struct ospf6_router_lsdesc *) ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa));

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    {
        /* Interfaces in state Down or Loopback are not described */
        if (oi->state == OSPF6_INTERFACE_DOWN || oi->state == OSPF6_INTERFACE_LOOPBACK)
            continue;

        /* Nor are interfaces without any full adjacencies described */
        count = 0;
        for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
            if (on->state == OSPF6_NEIGHBOR_FULL)
            {
                count++;
            }

        if (count == 0)
            continue;

        /* Multiple Router-LSA instance according to size limit setting */
        if ((oa->router_lsa_size_limit != 0) && ((caddr_t) lsdesc + sizeof (struct ospf6_router_lsdesc) -
                /* XXX warning: comparison between signed and unsigned */
                (caddr_t) buffer > oa->router_lsa_size_limit))
        {
            if ((caddr_t) lsdesc == (caddr_t) router_lsa + sizeof (struct ospf6_router_lsa))
            {
                if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
                    zlog_debug ("Size limit setting for Router-LSA too short");
                return 0;
            }

            /* Fill LSA Header */
            lsa_header->age = 0;
            lsa_header->type = htons (OSPF6_LSTYPE_ROUTER);
            lsa_header->id = htonl (link_state_id);
            lsa_header->adv_router = oa->ospf6->router_id;
            lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
            lsa_header->length = htons ((caddr_t) lsdesc - (caddr_t) buffer);

            /* LSA checksum */
            ospf6_lsa_checksum (lsa_header);

            /* create LSA */
            lsa = ospf6_lsa_create (lsa_header);

            /* Originate */
            ospf6_lsa_originate_area (lsa, oa);

            /* Reset setting for consecutive origination */
            memset ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa), 0, (caddr_t) lsdesc - (caddr_t) router_lsa);
            lsdesc = (struct ospf6_router_lsdesc *) ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa));
            link_state_id++;
            //zlog_debug ("[%d]%s() link_state_id:%d", __LINE__, __func__, link_state_id);
        }

        /* Point-to-Point interfaces */
        if (if_is_pointopoint (oi->interface))
        {
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
            {
                if (on->state != OSPF6_NEIGHBOR_FULL)
                    continue;

                lsdesc->type = OSPF6_ROUTER_LSDESC_POINTTOPOINT;
                lsdesc->metric = htons (oi->cost);
                lsdesc->interface_id = htonl (oi->interface->ifindex);
                lsdesc->neighbor_interface_id = htonl (on->ifindex);
                lsdesc->neighbor_router_id = on->router_id;

                lsdesc++;

                zlog_debug ("[%d]%s() lsdesc++", __LINE__, __func__);
            }
        }

        /* Broadcast and NBMA interfaces */
        if (if_is_broadcast (oi->interface))
        {
            /* If this router is not DR,
               and If this router not fully adjacent with DR,
               this interface is not transit yet: ignore. */
            if (oi->state != OSPF6_INTERFACE_DR)
            {
                drouter = ospf6_neighbor_lookup (oi->drouter, oi);
                if (drouter == NULL || drouter->state != OSPF6_NEIGHBOR_FULL)
                    continue;
            }

            lsdesc->type = OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK;
            lsdesc->metric = htons (oi->cost);
            lsdesc->interface_id = htonl (oi->interface->ifindex);
            if (oi->state != OSPF6_INTERFACE_DR)
            {
                lsdesc->neighbor_interface_id = htonl (drouter->ifindex);
                lsdesc->neighbor_router_id = drouter->router_id;
            }
            else
            {
                lsdesc->neighbor_interface_id = htonl (oi->interface->ifindex);
                lsdesc->neighbor_router_id = oi->area->ospf6->router_id;
            }

            lsdesc++;
        }

        /* Virtual links */
        /* xxx */
        /* Point-to-Multipoint interfaces */
        /* xxx */
    }

    if ((caddr_t) lsdesc != (caddr_t) router_lsa + sizeof (struct ospf6_router_lsa))
    {
        /* Fill LSA Header */
        lsa_header->age = 0;
        lsa_header->type = htons (OSPF6_LSTYPE_ROUTER);
        lsa_header->id = htonl (link_state_id);
        lsa_header->adv_router = oa->ospf6->router_id;
        lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
        lsa_header->length = htons ((caddr_t) lsdesc - (caddr_t) buffer);

        /* LSA checksum */
        ospf6_lsa_checksum (lsa_header);

        /* create LSA */
        lsa = ospf6_lsa_create (lsa_header);


#ifdef OSPF6_DEBUG
        zlog_debug("[%d]%s() ospf6_lsa_create:%s:%u", __LINE__, __func__, lsa->name, ospf6_lsa_age_current(lsa));
        zlog_debug ("[%d]%s() ***************add lsa:%s to oa->lsdb_bak", __LINE__, __func__, lsa->name);
#endif
        //sangmeng add for storage lsa in oa->lsdb_bak
        lsa_bak = ospf6_lsa_copy (lsa);
        lsa_bak->lsdb = oa->lsdb_bak;
        ospf6_install_lsa_for_leaving (lsa_bak);

        /* Originate */
        ospf6_lsa_originate_area (lsa, oa);

        link_state_id++;
    }
    else
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
            zlog_debug ("Nothing to describe in Router-LSA, suppress");
    }

    /* Do premature-aging of rest, undesired Router-LSAs */
    type = ntohs (OSPF6_LSTYPE_ROUTER);
    router = oa->ospf6->router_id;
    for (lsa = ospf6_lsdb_type_router_head (type, router, oa->lsdb); lsa; lsa = ospf6_lsdb_type_router_next (type, router, lsa))
    {
        if (ntohl (lsa->header->id) < link_state_id)
            continue;
#ifdef OSPF6_DEBUG
        zlog_debug ("[%d]%s() ***************add lsa:%s to oa->lsdb_bak", __LINE__, __func__, lsa->name);
#endif
        //sangmeng add for storage lsa in oa->lsdb_bak
        lsa_bak = ospf6_lsa_copy (lsa);
        lsa_bak->lsdb = oa->lsdb_bak;
        ospf6_install_lsa_for_leaving (lsa_bak);

        ospf6_lsa_purge (lsa);
    }

    return 0;
}

int ospf6_router_lsa_originate (struct thread *thread)
{
    struct ospf6_area *oa;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *lsa;

    u_int32_t link_state_id = 0;
    struct listnode *node, *nnode;
    struct listnode *j;
    struct ospf6_interface *oi;
    struct ospf6_neighbor *on, *drouter = NULL;
    struct ospf6_router_lsa *router_lsa;
    struct ospf6_router_lsdesc *lsdesc;
    u_int16_t type;
    u_int32_t router;
    int count;
    struct ospf6_lsa *lsa_bak;

    oa = (struct ospf6_area *) THREAD_ARG (thread);
    oa->thread_router_lsa = NULL;

    if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
        zlog_debug ("Originate Router-LSA for Area %s", oa->name);

    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    router_lsa = (struct ospf6_router_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_V6);
    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_E);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_MC);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_N);
    OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_R);
    OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_DC);

    if (ospf6_is_router_abr (ospf6))
        SET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_B);
    else
        UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_B);
    if (ospf6_asbr_is_asbr (ospf6))
        SET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_E);
    else
        UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_E);
    UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_V);
    UNSET_FLAG (router_lsa->bits, OSPF6_ROUTER_BIT_W);

    /* describe links for each interfaces */
    lsdesc = (struct ospf6_router_lsdesc *) ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa));

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    {
        /* Interfaces in state Down or Loopback are not described */
        if (oi->state == OSPF6_INTERFACE_DOWN || oi->state == OSPF6_INTERFACE_LOOPBACK)
            continue;

        /* Nor are interfaces without any full adjacencies described */
        count = 0;
        for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
            if (on->state == OSPF6_NEIGHBOR_FULL)
                count++;

        if (count == 0)
            continue;

        /* Multiple Router-LSA instance according to size limit setting */
        if ((oa->router_lsa_size_limit != 0) && ((caddr_t) lsdesc + sizeof (struct ospf6_router_lsdesc) -
                /* XXX warning: comparison between signed and unsigned */
                (caddr_t) buffer > oa->router_lsa_size_limit))
        {
            if ((caddr_t) lsdesc == (caddr_t) router_lsa + sizeof (struct ospf6_router_lsa))
            {
                if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
                    zlog_debug ("Size limit setting for Router-LSA too short");
                return 0;
            }

            /* Fill LSA Header */
            lsa_header->age = 0;
            lsa_header->type = htons (OSPF6_LSTYPE_ROUTER);
            lsa_header->id = htonl (link_state_id);
            lsa_header->adv_router = oa->ospf6->router_id;
            lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
            lsa_header->length = htons ((caddr_t) lsdesc - (caddr_t) buffer);

            /* LSA checksum */
            ospf6_lsa_checksum (lsa_header);

            /* create LSA */
            lsa = ospf6_lsa_create (lsa_header);

            /* Originate */
            ospf6_lsa_originate_area (lsa, oa);

            /* Reset setting for consecutive origination */
            memset ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa), 0, (caddr_t) lsdesc - (caddr_t) router_lsa);
            lsdesc = (struct ospf6_router_lsdesc *) ((caddr_t) router_lsa + sizeof (struct ospf6_router_lsa));
            link_state_id++;
        }

        /* Point-to-Point interfaces */
        if (if_is_pointopoint (oi->interface))
        {
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
            {
                if (on->state != OSPF6_NEIGHBOR_FULL)
                    continue;

                lsdesc->type = OSPF6_ROUTER_LSDESC_POINTTOPOINT;
                lsdesc->metric = htons (oi->cost);
                lsdesc->interface_id = htonl (oi->interface->ifindex);
                lsdesc->neighbor_interface_id = htonl (on->ifindex);
                lsdesc->neighbor_router_id = on->router_id;

                lsdesc++;
            }
        }

        /* Broadcast and NBMA interfaces */
        if (if_is_broadcast (oi->interface))
        {
            /* If this router is not DR,
               and If this router not fully adjacent with DR,
               this interface is not transit yet: ignore. */
            if (oi->state != OSPF6_INTERFACE_DR)
            {
                drouter = ospf6_neighbor_lookup (oi->drouter, oi);
                if (drouter == NULL || drouter->state != OSPF6_NEIGHBOR_FULL)
                    continue;
            }

            lsdesc->type = OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK;
            lsdesc->metric = htons (oi->cost);
            lsdesc->interface_id = htonl (oi->interface->ifindex);
            if (oi->state != OSPF6_INTERFACE_DR)
            {
                lsdesc->neighbor_interface_id = htonl (drouter->ifindex);
                lsdesc->neighbor_router_id = drouter->router_id;
            }
            else
            {
                lsdesc->neighbor_interface_id = htonl (oi->interface->ifindex);
                lsdesc->neighbor_router_id = oi->area->ospf6->router_id;
            }

            lsdesc++;
        }

        /* Virtual links */
        /* xxx */
        /* Point-to-Multipoint interfaces */
        /* xxx */
    }

    if ((caddr_t) lsdesc != (caddr_t) router_lsa + sizeof (struct ospf6_router_lsa))
    {
        /* Fill LSA Header */
        lsa_header->age = 0;
        lsa_header->type = htons (OSPF6_LSTYPE_ROUTER);
        lsa_header->id = htonl (link_state_id);
        lsa_header->adv_router = oa->ospf6->router_id;
        lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
        lsa_header->length = htons ((caddr_t) lsdesc - (caddr_t) buffer);

        /* LSA checksum */
        ospf6_lsa_checksum (lsa_header);

        /* create LSA */
        lsa = ospf6_lsa_create (lsa_header);

        /* Originate */
        ospf6_lsa_originate_area (lsa, oa);

        link_state_id++;
    }
    else
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (ROUTER))
            zlog_debug ("Nothing to describe in Router-LSA, suppress");
    }

    /* Do premature-aging of rest, undesired Router-LSAs */
    type = ntohs (OSPF6_LSTYPE_ROUTER);
    router = oa->ospf6->router_id;
    for (lsa = ospf6_lsdb_type_router_head (type, router, oa->lsdb); lsa; lsa = ospf6_lsdb_type_router_next (type, router, lsa))
    {
        if (ntohl (lsa->header->id) < link_state_id)
            continue;
#ifdef OSPF6_DEBUG
        zlog_debug ("[%d]%s() ***************add lsa:%s to oa->lsdb_bak", __LINE__, __func__, lsa->name);
#endif
        //sangmeng add for storage lsa in oa->lsdb_bak
        lsa_bak = ospf6_lsa_copy (lsa);
        lsa_bak->lsdb = oa->lsdb_bak;
        ospf6_install_lsa_for_leaving (lsa_bak);
        ospf6_lsa_purge (lsa);
    }

    return 0;
}

/*******************************/
/* RFC2740 3.4.3.2 Network-LSA */
/*******************************/

static int ospf6_network_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
    char *start, *end, *current;
    struct ospf6_network_lsa *network_lsa;
    struct ospf6_network_lsdesc *lsdesc;
    char buf[128], options[32];

    network_lsa = (struct ospf6_network_lsa *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

    ospf6_options_printbuf (network_lsa->options, options, sizeof (options));
    vty_out (vty, "     Options: %s%s", options, VNL);

    start = (char *) network_lsa + sizeof (struct ospf6_network_lsa);
    end = (char *) lsa->header + ntohs (lsa->header->length);
    for (current = start; current + sizeof (struct ospf6_network_lsdesc) <= end; current += sizeof (struct ospf6_network_lsdesc))
    {
        lsdesc = (struct ospf6_network_lsdesc *) current;
        inet_ntop (AF_INET, &lsdesc->router_id, buf, sizeof (buf));
        vty_out (vty, "     Attached Router: %s%s", buf, VNL);
    }
    return 0;
}

int ospf6_network_lsa_originate (struct thread *thread)
{
    struct ospf6_interface *oi;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;

    int count;
    struct ospf6_lsa *old, *lsa;
    struct ospf6_network_lsa *network_lsa;
    struct ospf6_network_lsdesc *lsdesc;
    struct ospf6_neighbor *on;
    struct ospf6_link_lsa *link_lsa;
    struct listnode *i;
    u_int16_t type;

    oi = (struct ospf6_interface *) THREAD_ARG (thread);
    oi->thread_network_lsa = NULL;

    /* The interface must be enabled until here. A Network-LSA of a
       disabled interface (but was once enabled) should be flushed
       by ospf6_lsa_refresh (), and does not come here. */
    assert (oi->area);

    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_NETWORK), htonl (oi->interface->ifindex), oi->area->ospf6->router_id, oi->area->lsdb);

    /* Do not originate Network-LSA if not DR */
    if (oi->state != OSPF6_INTERFACE_DR)
    {
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    if (IS_OSPF6_DEBUG_ORIGINATE (NETWORK))
        zlog_debug ("Originate Network-LSA for Interface %s", oi->interface->name);

    /* If none of neighbor is adjacent to us */
    count = 0;

    for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, i, on))
        if (on->state == OSPF6_NEIGHBOR_FULL)
            count++;

    if (count == 0)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (NETWORK))
            zlog_debug ("Interface stub, ignore");
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    /* prepare buffer */
    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    network_lsa = (struct ospf6_network_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    /* Collect the interface's Link-LSAs to describe
       network's optional capabilities */
    type = htons (OSPF6_LSTYPE_LINK);
    for (lsa = ospf6_lsdb_type_head (type, oi->lsdb); lsa; lsa = ospf6_lsdb_type_next (type, lsa))
    {
        link_lsa = (struct ospf6_link_lsa *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));
        network_lsa->options[0] |= link_lsa->options[0];
        network_lsa->options[1] |= link_lsa->options[1];
        network_lsa->options[2] |= link_lsa->options[2];
    }

    lsdesc = (struct ospf6_network_lsdesc *) ((caddr_t) network_lsa + sizeof (struct ospf6_network_lsa));

    /* set Link Description to the router itself */
    lsdesc->router_id = oi->area->ospf6->router_id;
    lsdesc++;

    /* Walk through the neighbors */
    for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, i, on))
    {
        if (on->state != OSPF6_NEIGHBOR_FULL)
            continue;

        /* set this neighbor's Router-ID to LSA */
        lsdesc->router_id = on->router_id;
        lsdesc++;
    }

    /* Fill LSA Header */
    lsa_header->age = 0;
    lsa_header->type = htons (OSPF6_LSTYPE_NETWORK);
    lsa_header->id = htonl (oi->interface->ifindex);
    lsa_header->adv_router = oi->area->ospf6->router_id;
    lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oi->area->lsdb);
    lsa_header->length = htons ((caddr_t) lsdesc - (caddr_t) buffer);

    /* LSA checksum */
    ospf6_lsa_checksum (lsa_header);

    /* create LSA */
    lsa = ospf6_lsa_create (lsa_header);

#ifdef OSPF6_DEBUG
    zlog_debug("[%d]%s() lsa:%s, age:%u", __LINE__, __func__, lsa->name, ospf6_lsa_age_current(lsa));
#endif
    /* Originate */
    ospf6_lsa_originate_area (lsa, oi->area);

    return 0;
}

/****************************/
/* RFC2740 3.4.3.6 Link-LSA */
/****************************/

static int ospf6_link_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
    char *start, *end, *current;
    struct ospf6_link_lsa *link_lsa;
    int prefixnum;
    char buf[128], options[32];
    struct ospf6_prefix *prefix;
    const char *p, *mc, *la, *nu;
    struct in6_addr in6;

    link_lsa = (struct ospf6_link_lsa *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

    ospf6_options_printbuf (link_lsa->options, options, sizeof (options));
    inet_ntop (AF_INET6, &link_lsa->linklocal_addr, buf, sizeof (buf));
    prefixnum = ntohl (link_lsa->prefix_num);

    vty_out (vty, "     Priority: %d Options: %s%s", link_lsa->priority, options, VNL);
    vty_out (vty, "     LinkLocal Address: %s%s", buf, VNL);
    vty_out (vty, "     Number of Prefix: %d%s", prefixnum, VNL);

    start = (char *) link_lsa + sizeof (struct ospf6_link_lsa);
    end = (char *) lsa->header + ntohs (lsa->header->length);
    for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
        prefix = (struct ospf6_prefix *) current;
        if (prefix->prefix_length == 0 || current + OSPF6_PREFIX_SIZE (prefix) > end)
            break;

        p = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_P) ? "P" : "--");
        mc = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_MC) ? "MC" : "--");
        la = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_LA) ? "LA" : "--");
        nu = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_NU) ? "NU" : "--");
        vty_out (vty, "     Prefix Options: %s|%s|%s|%s%s", p, mc, la, nu, VNL);

        memset (&in6, 0, sizeof (in6));
        memcpy (&in6, OSPF6_PREFIX_BODY (prefix), OSPF6_PREFIX_SPACE (prefix->prefix_length));
        inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
        vty_out (vty, "     Prefix: %s/%d%s", buf, prefix->prefix_length, VNL);
    }

    return 0;
}

int ospf6_link_lsa_originate (struct thread *thread)
{
    struct ospf6_interface *oi;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *old, *lsa;

    struct ospf6_link_lsa *link_lsa;
    struct ospf6_route *route;
    struct ospf6_prefix *op;

    oi = (struct ospf6_interface *) THREAD_ARG (thread);
    oi->thread_link_lsa = NULL;

    assert (oi->area);

    /* find previous LSA */
    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_LINK), htonl (oi->interface->ifindex), oi->area->ospf6->router_id, oi->lsdb);

    if (CHECK_FLAG (oi->flag, OSPF6_INTERFACE_DISABLE))
    {
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    if (IS_OSPF6_DEBUG_ORIGINATE (LINK))
        zlog_debug ("Originate Link-LSA for Interface %s", oi->interface->name);

    /* can't make Link-LSA if linklocal address not set */
    if (oi->linklocal_addr == NULL)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (LINK))
            zlog_debug ("No Linklocal address on %s, defer originating", oi->interface->name);
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    /* prepare buffer */
    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    link_lsa = (struct ospf6_link_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    /* Fill Link-LSA */
    link_lsa->priority = oi->priority;
    memcpy (link_lsa->options, oi->area->options, 3);
    memcpy (&link_lsa->linklocal_addr, oi->linklocal_addr, sizeof (struct in6_addr));
    link_lsa->prefix_num = htonl (oi->route_connected->count);

    op = (struct ospf6_prefix *) ((caddr_t) link_lsa + sizeof (struct ospf6_link_lsa));

    /* connected prefix to advertise */
    for (route = ospf6_route_head (oi->route_connected); route; route = ospf6_route_next (route))
    {
        op->prefix_length = route->prefix.prefixlen;
        op->prefix_options = route->path.prefix_options;
        op->prefix_metric = htons (0);
        memcpy (OSPF6_PREFIX_BODY (op), &route->prefix.u.prefix6, OSPF6_PREFIX_SPACE (op->prefix_length));
        op = OSPF6_PREFIX_NEXT (op);
    }

    /* Fill LSA Header */
    lsa_header->age = 0;
    lsa_header->type = htons (OSPF6_LSTYPE_LINK);
    lsa_header->id = htonl (oi->interface->ifindex);
    lsa_header->adv_router = oi->area->ospf6->router_id;
    lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oi->lsdb);
    lsa_header->length = htons ((caddr_t) op - (caddr_t) buffer);

    /* LSA checksum */
    ospf6_lsa_checksum (lsa_header);

    /* create LSA */
    lsa = ospf6_lsa_create (lsa_header);

    /* Originate */
    ospf6_lsa_originate_interface (lsa, oi);

    return 0;
}

/*****************************************/
/* RFC2740 3.4.3.7 Intra-Area-Prefix-LSA */
/*****************************************/

static int ospf6_intra_prefix_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
    char *start, *end, *current;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    int prefixnum;
    char buf[128];
    struct ospf6_prefix *prefix;
    char id[16], adv_router[16];
    const char *p, *mc, *la, *nu;
    struct in6_addr in6;

    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

    prefixnum = ntohs (intra_prefix_lsa->prefix_num);

    vty_out (vty, "     Number of Prefix: %d%s", prefixnum, VNL);

    inet_ntop (AF_INET, &intra_prefix_lsa->ref_id, id, sizeof (id));
    inet_ntop (AF_INET, &intra_prefix_lsa->ref_adv_router, adv_router, sizeof (adv_router));
    vty_out (vty, "     Reference: %s Id: %s Adv: %s%s", ospf6_lstype_name (intra_prefix_lsa->ref_type), id, adv_router, VNL);

    start = (char *) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
    end = (char *) lsa->header + ntohs (lsa->header->length);
    for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
        prefix = (struct ospf6_prefix *) current;
        if (prefix->prefix_length == 0 || current + OSPF6_PREFIX_SIZE (prefix) > end)
            break;

        p = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_P) ? "P" : "--");
        mc = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_MC) ? "MC" : "--");
        la = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_LA) ? "LA" : "--");
        nu = (CHECK_FLAG (prefix->prefix_options, OSPF6_PREFIX_OPTION_NU) ? "NU" : "--");
        vty_out (vty, "     Prefix Options: %s|%s|%s|%s%s", p, mc, la, nu, VNL);

        memset (&in6, 0, sizeof (in6));
        memcpy (&in6, OSPF6_PREFIX_BODY (prefix), OSPF6_PREFIX_SPACE (prefix->prefix_length));
        inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
        vty_out (vty, "     Prefix: %s/%d%s", buf, prefix->prefix_length, VNL);
    }

    return 0;
}

//æ‰©å±•åŸŸå†…LSA add by haozhiqiang
int ospf6_extend_intra_prefix_lsa_originate_stub (struct thread *thread)
{
    struct ospf6_area *oa;
    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *old, *lsa;
    struct ospf6_source_addr_prefix_TLV *soure_addr;
    struct ospf6_lsa_twod *twod = NULL;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct ospf6_interface *oi;
    struct ospf6_neighbor *on;
    struct ospf6_route *route;
    struct ospf6_prefix *op;
    struct listnode *i, *j;
    int full_count = 0;
    unsigned short prefix_num = 0;
    char buf[BUFSIZ];
    struct ospf6_route_table *route_advertise;

    struct in6_addr in6;
    char bufff[128] = "";
    oa = (struct ospf6_area *) THREAD_ARG (thread);
    oa->thread_intra_prefix_lsa = NULL;

    /* find previous LSA */
    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_E_INTRA_PREFIX), htonl (0), oa->ospf6->router_id, oa->lsdb);
    if (!IS_AREA_ENABLED (oa))
    {
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }
    if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
        zlog_debug ("Originate Intra-Area-Prefix-LSA for area %s's stub prefix", oa->name);

    /* prepare buffer */
    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
    /* Fill Intra-Area-Prefix-LSA */
    intra_prefix_lsa->ref_type = htons (OSPF6_LSTYPE_ROUTER);
    intra_prefix_lsa->ref_id = htonl (0);
    intra_prefix_lsa->ref_adv_router = oa->ospf6->router_id;

    /* put prefixes to advertise */
    prefix_num = 0;
    op = (struct ospf6_prefix *) ((caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa));

    intra_prefix_lsa->prefix_num = htons (prefix_num + 1);
#if 1							// add haozhiqiang 2015-12-17
    ospf6_lsa_twod_del_node (oa, &twod);	//zlw 2016-4-7 å¥½å¥½çœ‹çœ‹è¿™é‡Œï¼Œç”¨returnå°±ä¸è¡?
    if (twod == NULL)			//å¢žåŠ æ“ä½œ
    {
        twod = (struct ospf6_lsa_twod *) oa->twod_list->tail->data;
    }

    op->prefix_length = twod->dst_pre.prefixlen;
    op->prefix_options = twod->operate;	// æ ‡å¿— å½“å‰æ˜?å¢žåŠ  è¿˜æ˜¯ åˆ é™¤
    op->prefix_metric = htons (twod->cost);

    memcpy (OSPF6_PREFIX_BODY (op), &(twod->dst_pre.prefix), OSPF6_PREFIX_SPACE (op->prefix_length));

    op = OSPF6_PREFIX_NEXT (op);

//æºåœ°å€
    soure_addr = (struct ospf6_source_addr_prefix_TLV *) ((caddr_t) op);
    soure_addr->type = htons (OSPF6_SOURCE_ADDR_TLV_TYPE);	//TLV type
    soure_addr->length = htons (OSPF6_SOURCE_ADDR_TLV_LENGTH);	//TLV length
    soure_addr->tlv_metric = 0;
    soure_addr->tlv_length = twod->src_pre.prefixlen;
    soure_addr->tlv_options = 0;
    memcpy ((caddr_t) soure_addr + sizeof (soure_addr), &(twod->src_pre.prefix), 16);	//OSPF6_PREFIX_SPACE (soure_addr->tlv_length));
    memset (&in6, 0, sizeof (in6));
    memcpy (&in6, (caddr_t) soure_addr + sizeof (soure_addr), 16);
    inet_ntop (AF_INET6, &in6, bufff, sizeof (bufff));
    printf ("Source Prefix: %s/%d\n", bufff, soure_addr->tlv_length);

#endif
    /* Fill LSA Header */
    lsa_header->age = 0;
    lsa_header->type = htons (OSPF6_LSTYPE_E_INTRA_PREFIX);
    lsa_header->id = htonl (0);
    lsa_header->adv_router = oa->ospf6->router_id;
    lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
    lsa_header->length = htons ((caddr_t) soure_addr - (caddr_t) lsa_header + 24);
    /* LSA checksum */
    ospf6_lsa_checksum (lsa_header);

    /* create LSA */
    lsa = ospf6_lsa_create (lsa_header);

    /* Originate */
    ospf6_lsa_originate_area (lsa, oa);

#if 1							// add haozhiqiang 2015-12-29
    if (twod->operate == 0)
    {
        //åˆ é™¤è¿™ä¸ªèŠ‚ç‚¹
        listnode_delete (oa->twod_list, twod);

    }
#endif

    return 0;
}

int ospf6_intra_prefix_lsa_originate_stub (struct thread *thread)
{
    struct ospf6_area *oa;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *old, *lsa;

    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct ospf6_interface *oi;
    struct ospf6_neighbor *on;
    struct ospf6_route *route;
    struct ospf6_prefix *op;
    struct listnode *i, *j;
    int full_count = 0;
    unsigned short prefix_num = 0;
    char buf[BUFSIZ];
    struct ospf6_route_table *route_advertise;

    oa = (struct ospf6_area *) THREAD_ARG (thread);
    oa->thread_intra_prefix_lsa = NULL;

    /* find previous LSA */
    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_INTRA_PREFIX), htonl (0), oa->ospf6->router_id, oa->lsdb);

    if (!IS_AREA_ENABLED (oa))
    {
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
        zlog_debug ("Originate Intra-Area-Prefix-LSA for area %s's stub prefix", oa->name);

    /* prepare buffer */
    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    /* Fill Intra-Area-Prefix-LSA */
    intra_prefix_lsa->ref_type = htons (OSPF6_LSTYPE_ROUTER);
    intra_prefix_lsa->ref_id = htonl (0);
    intra_prefix_lsa->ref_adv_router = oa->ospf6->router_id;

    route_advertise = ospf6_route_table_create (0, 0);

    for (ALL_LIST_ELEMENTS_RO (oa->if_list, i, oi))
    {
        if (oi->state == OSPF6_INTERFACE_DOWN)
        {
            if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
                zlog_debug ("  Interface %s is down, ignore", oi->interface->name);
            continue;
        }

        full_count = 0;

        for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
            if ((on->state == OSPF6_NEIGHBOR_FULL) || on->state == OSPF6_NEIGHBOR_LEAVING)	/*sangmeng add here */
                full_count++;

        if (oi->state != OSPF6_INTERFACE_LOOPBACK && oi->state != OSPF6_INTERFACE_POINTTOPOINT && full_count != 0)
        {
            if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
                zlog_debug ("  Interface %s is not stub, ignore", oi->interface->name);
            continue;
        }

        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("  Interface %s:", oi->interface->name);

        /* connected prefix to advertise */
        for (route = ospf6_route_head (oi->route_connected); route; route = ospf6_route_best_next (route))
        {
            if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            {
                prefix2str (&route->prefix, buf, sizeof (buf));
                zlog_debug ("    include %s", buf);
            }
            ospf6_route_add (ospf6_route_copy (route), route_advertise);
        }
    }

    if (route_advertise->count == 0)
    {
        if (old)
            ospf6_lsa_purge (old);
        ospf6_route_table_delete (route_advertise);
        return 0;
    }

    /* put prefixes to advertise */
    prefix_num = 0;
    op = (struct ospf6_prefix *) ((caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa));
    for (route = ospf6_route_head (route_advertise); route; route = ospf6_route_best_next (route))
    {
        op->prefix_length = route->prefix.prefixlen;
        op->prefix_options = route->path.prefix_options;
        op->prefix_metric = htons (route->path.cost);
        memcpy (OSPF6_PREFIX_BODY (op), &route->prefix.u.prefix6, OSPF6_PREFIX_SPACE (op->prefix_length));
        op = OSPF6_PREFIX_NEXT (op);
        prefix_num++;
    }

    ospf6_route_table_delete (route_advertise);

    if (prefix_num == 0)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("Quit to Advertise Intra-Prefix: no route to advertise");
        return 0;
    }

    intra_prefix_lsa->prefix_num = htons (prefix_num);

    /* Fill LSA Header */
    lsa_header->age = 0;
    lsa_header->type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
    lsa_header->id = htonl (0);
    lsa_header->adv_router = oa->ospf6->router_id;
    lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oa->lsdb);
    lsa_header->length = htons ((caddr_t) op - (caddr_t) lsa_header);

    /* LSA checksum */
    ospf6_lsa_checksum (lsa_header);

    /* create LSA */
    lsa = ospf6_lsa_create (lsa_header);

    /* Originate */
    ospf6_lsa_originate_area (lsa, oa);

    return 0;
}

int ospf6_intra_prefix_lsa_originate_transit (struct thread *thread)
{
    struct ospf6_interface *oi;

    char buffer[OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *old, *lsa;

    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct ospf6_neighbor *on;
    struct ospf6_route *route;
    struct ospf6_prefix *op;
    struct listnode *i;
    int full_count = 0;
    unsigned short prefix_num = 0;
    struct ospf6_route_table *route_advertise;
    struct ospf6_link_lsa *link_lsa;
    char *start, *end, *current;
    u_int16_t type;
    char buf[BUFSIZ];

    oi = (struct ospf6_interface *) THREAD_ARG (thread);
    oi->thread_intra_prefix_lsa = NULL;

    assert (oi->area);

    /* find previous LSA */
    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_INTRA_PREFIX), htonl (oi->interface->ifindex), oi->area->ospf6->router_id, oi->area->lsdb);

    if (CHECK_FLAG (oi->flag, OSPF6_INTERFACE_DISABLE))
    {
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
        zlog_debug ("Originate Intra-Area-Prefix-LSA for interface %s's prefix", oi->interface->name);

    /* prepare buffer */
    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;
    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));

    /* Fill Intra-Area-Prefix-LSA */
    intra_prefix_lsa->ref_type = htons (OSPF6_LSTYPE_NETWORK);
    intra_prefix_lsa->ref_id = htonl (oi->interface->ifindex);
    intra_prefix_lsa->ref_adv_router = oi->area->ospf6->router_id;

    if (oi->state != OSPF6_INTERFACE_DR)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("  Interface is not DR");
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    full_count = 0;
    for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, i, on))
        if (on->state == OSPF6_NEIGHBOR_FULL)
            full_count++;

    if (full_count == 0)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("  Interface is stub");
        if (old)
            ospf6_lsa_purge (old);
        return 0;
    }

    /* connected prefix to advertise */
    route_advertise = ospf6_route_table_create (0, 0);

    type = ntohs (OSPF6_LSTYPE_LINK);
    for (lsa = ospf6_lsdb_type_head (type, oi->lsdb); lsa; lsa = ospf6_lsdb_type_next (type, lsa))
    {
        if (OSPF6_LSA_IS_MAXAGE (lsa))
            continue;

        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("  include prefix from %s", lsa->name);

        if (lsa->header->adv_router != oi->area->ospf6->router_id)
        {
            on = ospf6_neighbor_lookup (lsa->header->adv_router, oi);
            if (on == NULL || on->state != OSPF6_NEIGHBOR_FULL)
            {
                if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
                    zlog_debug ("    Neighbor not found or not Full, ignore");
                continue;
            }
        }

        link_lsa = (struct ospf6_link_lsa *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));

        prefix_num = (unsigned short) ntohl (link_lsa->prefix_num);
        start = (char *) link_lsa + sizeof (struct ospf6_link_lsa);
        end = (char *) lsa->header + ntohs (lsa->header->length);
        for (current = start; current < end && prefix_num; current += OSPF6_PREFIX_SIZE (op))
        {
            op = (struct ospf6_prefix *) current;
            if (op->prefix_length == 0 || current + OSPF6_PREFIX_SIZE (op) > end)
                break;

            route = ospf6_route_create ();

            route->type = OSPF6_DEST_TYPE_NETWORK;
            route->prefix.family = AF_INET6;
            route->prefix.prefixlen = op->prefix_length;
            memset (&route->prefix.u.prefix6, 0, sizeof (struct in6_addr));
            memcpy (&route->prefix.u.prefix6, OSPF6_PREFIX_BODY (op), OSPF6_PREFIX_SPACE (op->prefix_length));

            route->path.origin.type = lsa->header->type;
            route->path.origin.id = lsa->header->id;
            route->path.origin.adv_router = lsa->header->adv_router;
            route->path.options[0] = link_lsa->options[0];
            route->path.options[1] = link_lsa->options[1];
            route->path.options[2] = link_lsa->options[2];
            route->path.prefix_options = op->prefix_options;
            route->path.area_id = oi->area->area_id;
            route->path.type = OSPF6_PATH_TYPE_INTRA;

            if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            {
                prefix2str (&route->prefix, buf, sizeof (buf));
                zlog_debug ("    include %s", buf);
            }

            ospf6_route_add (route, route_advertise);
            prefix_num--;
        }
        if (current != end && IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("Trailing garbage in %s", lsa->name);
    }

    op = (struct ospf6_prefix *) ((caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa));

    prefix_num = 0;
    for (route = ospf6_route_head (route_advertise); route; route = ospf6_route_best_next (route))
    {
        op->prefix_length = route->prefix.prefixlen;
        op->prefix_options = route->path.prefix_options;
        op->prefix_metric = htons (0);
        memcpy (OSPF6_PREFIX_BODY (op), &route->prefix.u.prefix6, OSPF6_PREFIX_SPACE (op->prefix_length));
        op = OSPF6_PREFIX_NEXT (op);
        prefix_num++;
    }

    ospf6_route_table_delete (route_advertise);

    if (prefix_num == 0)
    {
        if (IS_OSPF6_DEBUG_ORIGINATE (INTRA_PREFIX))
            zlog_debug ("Quit to Advertise Intra-Prefix: no route to advertise");
        return 0;
    }

    intra_prefix_lsa->prefix_num = htons (prefix_num);

    /* Fill LSA Header */
    lsa_header->age = 0;
    lsa_header->type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
    lsa_header->id = htonl (oi->interface->ifindex);
    lsa_header->adv_router = oi->area->ospf6->router_id;
    lsa_header->seqnum = ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id, lsa_header->adv_router, oi->area->lsdb);
    lsa_header->length = htons ((caddr_t) op - (caddr_t) lsa_header);

    /* LSA checksum */
    ospf6_lsa_checksum (lsa_header);

    /* create LSA */
    lsa = ospf6_lsa_create (lsa_header);

    /* Originate */
    ospf6_lsa_originate_area (lsa, oi->area);

    return 0;
}

//haozhiqiang  ç”Ÿæˆè·¯ç”±
void ospf6_intra_prefix_lsa_add_e (struct ospf6_lsa *lsa, struct ospf6_route_table *route_table1)
{
    struct ospf6_area *oa;
    struct ospf6_lsa *lsa_e = NULL;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa_e;
    struct ospf6_lsa_header *lsa_header_e;
    struct prefix ls_prefix;
    struct ospf6_route *route, *ls_entry;
    int i, prefix_num;
    struct ospf6_prefix *op;
    struct ospf6_prefix *op_e;
    char *start, *current, *end;
    char *des_p;
    u_int16_t type;
    char buf[64];

    if (OSPF6_LSA_IS_MAXAGE (lsa))
        return;

    if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("%s found", lsa->name);

    oa = OSPF6_AREA (lsa->lsdb->data);

    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) OSPF6_LSA_HEADER_END (lsa->header);
    if (intra_prefix_lsa->ref_type == htons (OSPF6_LSTYPE_ROUTER))
        ospf6_linkstate_prefix (intra_prefix_lsa->ref_adv_router, htonl (0), &ls_prefix);
    else if (intra_prefix_lsa->ref_type == htons (OSPF6_LSTYPE_NETWORK))
        ospf6_linkstate_prefix (intra_prefix_lsa->ref_adv_router, intra_prefix_lsa->ref_id, &ls_prefix);
    else
    {
        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
            zlog_debug ("Unknown reference LS-type: %#hx", ntohs (intra_prefix_lsa->ref_type));
        return;
    }

    ls_entry = ospf6_route_lookup (&ls_prefix, oa->spf_table1);
    if (ls_entry == NULL)
    {
        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        {
            ospf6_linkstate_prefix2str (&ls_prefix, buf, sizeof (buf));
            zlog_debug ("LS entry does not exist: %s", buf);
        }
        return;
    }
    prefix_num = ntohs (intra_prefix_lsa->prefix_num);
    start = (caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
    end = OSPF6_LSA_END (lsa->header);
    for (current = start; current < end; current += OSPF6_PREFIX_SIZE (op))
    {
        op = (struct ospf6_prefix *) current;
        if (prefix_num == 0)
            break;
        if (end < current + OSPF6_PREFIX_SIZE (op))
            break;

        route = ospf6_route_create ();

        memset (&route->prefix, 0, sizeof (struct prefix));
        route->prefix.family = AF_INET6;
        route->prefix.prefixlen = op->prefix_length;
        ospf6_prefix_in6_addr (&route->prefix.u.prefix6, op);
#if 1							// add haozhiqiang    2016-2-1
        memset (&route->s_prefix, 0, sizeof (struct prefix));
        route->s_prefix.family = AF_INET6;
        route->s_prefix.prefixlen = oa->s_prefix.prefixlen;
        memcpy (&route->s_prefix.u.prefix6, &(oa->s_prefix.u.prefix6), OSPF6_PREFIX_SPACE (oa->s_prefix.prefixlen));
#endif

        route->type = OSPF6_DEST_TYPE_NETWORK;
        route->path.origin.type = lsa->header->type;
        route->path.origin.id = lsa->header->id;
        route->path.origin.adv_router = lsa->header->adv_router;
        route->path.prefix_options = op->prefix_options;
        route->path.area_id = oa->area_id;
        route->path.type = OSPF6_PATH_TYPE_INTRA;
        route->path.metric_type = 1;
        route->path.cost = ls_entry->path.cost + ntohs (op->prefix_metric);

        for (i = 0; ospf6_nexthop_is_set (&ls_entry->nexthop[i]) && i < OSPF6_MULTI_PATH_LIMIT; i++)
            ospf6_nexthop_copy (&route->nexthop[i], &ls_entry->nexthop[i]);

        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        {
            prefix2str (&route->prefix, buf, sizeof (buf));
            zlog_debug ("  add %s", buf);
        }

        ospf6_route_add (route, route_table1);
        prefix_num--;
    }

    if (current != end && IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("Trailing garbage ignored");
}

void ospf6_intra_prefix_lsa_add (struct ospf6_lsa *lsa)
{
    struct ospf6_area *oa;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct prefix ls_prefix;
    struct ospf6_route *route, *ls_entry;
    int i, prefix_num;
    struct ospf6_prefix *op;
    char *start, *current, *end;
    char buf[64];

    if (OSPF6_LSA_IS_MAXAGE (lsa))
        return;

    if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("%s found", lsa->name);

    oa = OSPF6_AREA (lsa->lsdb->data);

    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) OSPF6_LSA_HEADER_END (lsa->header);
    if (intra_prefix_lsa->ref_type == htons (OSPF6_LSTYPE_ROUTER))
        ospf6_linkstate_prefix (intra_prefix_lsa->ref_adv_router, htonl (0), &ls_prefix);
    else if (intra_prefix_lsa->ref_type == htons (OSPF6_LSTYPE_NETWORK))
        ospf6_linkstate_prefix (intra_prefix_lsa->ref_adv_router, intra_prefix_lsa->ref_id, &ls_prefix);
    else
    {
        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
            zlog_debug ("Unknown reference LS-type: %#hx", ntohs (intra_prefix_lsa->ref_type));
        return;
    }

    ls_entry = ospf6_route_lookup (&ls_prefix, oa->spf_table);
    if (ls_entry == NULL)
    {
        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        {
            ospf6_linkstate_prefix2str (&ls_prefix, buf, sizeof (buf));
            zlog_debug ("LS entry does not exist: %s", buf);
        }
        return;
    }

    prefix_num = ntohs (intra_prefix_lsa->prefix_num);
    start = (caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
    end = OSPF6_LSA_END (lsa->header);
    for (current = start; current < end; current += OSPF6_PREFIX_SIZE (op))
    {
        op = (struct ospf6_prefix *) current;
        if (prefix_num == 0)
            break;
        if (end < current + OSPF6_PREFIX_SIZE (op))
            break;

        route = ospf6_route_create ();

        memset (&route->prefix, 0, sizeof (struct prefix));
        route->prefix.family = AF_INET6;
        route->prefix.prefixlen = op->prefix_length;
        ospf6_prefix_in6_addr (&route->prefix.u.prefix6, op);

        route->type = OSPF6_DEST_TYPE_NETWORK;
        route->path.origin.type = lsa->header->type;
        route->path.origin.id = lsa->header->id;
        route->path.origin.adv_router = lsa->header->adv_router;
        route->path.prefix_options = op->prefix_options;
        route->path.area_id = oa->area_id;
        route->path.type = OSPF6_PATH_TYPE_INTRA;
        route->path.metric_type = 1;
        route->path.cost = ls_entry->path.cost + ntohs (op->prefix_metric);

        for (i = 0; ospf6_nexthop_is_set (&ls_entry->nexthop[i]) && i < OSPF6_MULTI_PATH_LIMIT; i++)
            ospf6_nexthop_copy (&route->nexthop[i], &ls_entry->nexthop[i]);

        if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        {
            prefix2str (&route->prefix, buf, sizeof (buf));
            zlog_debug ("  add %s", buf);
        }

        ospf6_route_add (route, oa->route_table);
        prefix_num--;
    }

    if (current != end && IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("Trailing garbage ignored");
}

void ospf6_intra_prefix_lsa_remove (struct ospf6_lsa *lsa)
{
    struct ospf6_area *oa;
    struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
    struct prefix prefix;
    struct ospf6_route *route;
    int prefix_num;
    struct ospf6_prefix *op;
    char *start, *current, *end;
    char buf[64];

    if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("%s disappearing", lsa->name);

    oa = OSPF6_AREA (lsa->lsdb->data);

    intra_prefix_lsa = (struct ospf6_intra_prefix_lsa *) OSPF6_LSA_HEADER_END (lsa->header);

    prefix_num = ntohs (intra_prefix_lsa->prefix_num);
    start = (caddr_t) intra_prefix_lsa + sizeof (struct ospf6_intra_prefix_lsa);
    end = OSPF6_LSA_END (lsa->header);
    for (current = start; current < end; current += OSPF6_PREFIX_SIZE (op))
    {
        op = (struct ospf6_prefix *) current;
        if (prefix_num == 0)
            break;
        if (end < current + OSPF6_PREFIX_SIZE (op))
            break;
        prefix_num--;

        memset (&prefix, 0, sizeof (struct prefix));
        prefix.family = AF_INET6;
        prefix.prefixlen = op->prefix_length;
        ospf6_prefix_in6_addr (&prefix.u.prefix6, op);

        route = ospf6_route_lookup (&prefix, oa->route_table);
        if (route == NULL)
            continue;

        for (ospf6_route_lock (route); route && ospf6_route_is_prefix (&prefix, route); route = ospf6_route_next (route))
        {
            if (route->type != OSPF6_DEST_TYPE_NETWORK)
                continue;
            if (route->path.area_id != oa->area_id)
                continue;
            if (route->path.type != OSPF6_PATH_TYPE_INTRA)
                continue;
            if (route->path.origin.type != lsa->header->type || route->path.origin.id != lsa->header->id || route->path.origin.adv_router != lsa->header->adv_router)
                continue;

            if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
            {
                prefix2str (&route->prefix, buf, sizeof (buf));
                zlog_debug ("remove %s", buf);
            }
            ospf6_route_remove (route, oa->route_table);
        }
        if (route)
            ospf6_route_unlock (route);
    }

    if (current != end && IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("Trailing garbage ignored");
}

void ospf6_intra_route_calculation (struct ospf6_area *oa)
{
    struct ospf6_route *route;
    u_int16_t type;
    struct ospf6_lsa *lsa;
    void (*hook_add) (struct ospf6_route *) = NULL;
    void (*hook_remove) (struct ospf6_route *) = NULL;

    if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("Re-examin intra-routes for area %s", oa->name);

    hook_add = oa->route_table->hook_add;
    hook_remove = oa->route_table->hook_remove;
    oa->route_table->hook_add = NULL;
    oa->route_table->hook_remove = NULL;

    for (route = ospf6_route_head (oa->route_table); route; route = ospf6_route_next (route))
        route->flag = OSPF6_ROUTE_REMOVE;

    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
    for (lsa = ospf6_lsdb_type_head (type, oa->lsdb); lsa; lsa = ospf6_lsdb_type_next (type, lsa))
        ospf6_intra_prefix_lsa_add (lsa);

    oa->route_table->hook_add = hook_add;
    oa->route_table->hook_remove = hook_remove;

    for (route = ospf6_route_head (oa->route_table); route; route = ospf6_route_next (route))
    {
        if (CHECK_FLAG (route->flag, OSPF6_ROUTE_REMOVE) && CHECK_FLAG (route->flag, OSPF6_ROUTE_ADD))
        {
            UNSET_FLAG (route->flag, OSPF6_ROUTE_REMOVE);
            UNSET_FLAG (route->flag, OSPF6_ROUTE_ADD);
        }

        if (CHECK_FLAG (route->flag, OSPF6_ROUTE_REMOVE))
            ospf6_route_remove (route, oa->route_table);
        else if (CHECK_FLAG (route->flag, OSPF6_ROUTE_ADD) || CHECK_FLAG (route->flag, OSPF6_ROUTE_CHANGE))
        {
            if (hook_add)
                (*hook_add) (route);
        }

        route->flag = 0;
    }

    if (IS_OSPF6_DEBUG_EXAMIN (INTRA_PREFIX))
        zlog_debug ("Re-examin intra-routes for area %s: Done", oa->name);
}
//ÕÅÇì¾ý£¬Ìî³äacl_message½á¹¹Ìå
int
ospf6_build_acl_message(struct ospf6_acl_message *p_ospf6_acl,
                        char *src_buff,char *dst_buff, int fwd)
{
    char *cptr;
    unsigned short *sp;
    int i = 0, j, sum = 0;
    char *tmp;

    if((NULL==p_ospf6_acl) || (NULL==src_buff) || (NULL==dst_buff) || (fwd<0))
    {
        printf("ERROR\n");
        return 0;
    }
    cptr = src_buff;
    sp = p_ospf6_acl->src_addr.w_addr;
    i = j = sum = 0;
    while(*cptr != '\0')
    {
        if('/' == *cptr)
        {
            cptr++;
            while(*cptr != '\0')
            {
                if(0 != p_ospf6_acl->src_len)
                {
                    p_ospf6_acl->src_len *= 10;
                }
                p_ospf6_acl->src_len +=  *cptr++ - '0';
            }

        }
        else if(':' == *cptr)
        {
            cptr++;
            i++;
            if(':' == *cptr)
            {
                cptr++;
                tmp = cptr;
                if('/' != *cptr)
                {
                    sum++;
                }
                while(*cptr++ != '\0')
                {
                    if(':' == *cptr)
                    {
                        sum++;
                    }
                }
                cptr = tmp;
                j = i;
                for(; i < 8-sum; i++)
                {
                    sp[i] = 0;
                }

            }
        }
        else
        {
            if(0 != sp[i])
            {
                sp[i] *= 10;
            }
            sp[i] += *cptr++ - '0';
        }
    }


    cptr = dst_buff;
    sp = p_ospf6_acl->dst_addr.w_addr;
    i = j = sum = 0;

    while(*cptr != '\0')
    {
        if('/' == *cptr)
        {
            cptr++;
            while(*cptr != '\0')
            {
                if(0 != p_ospf6_acl->dst_len)
                {
                    p_ospf6_acl->dst_len *= 10;
                }
                p_ospf6_acl->dst_len +=  *cptr++ - '0';
            }

        }
        else if(':' == *cptr)
        {
            cptr++;
            i++;
            if(':' == *cptr)
            {
                cptr++;
                tmp = cptr;
                if('/' != *cptr)
                {
                    sum++;
                }
                while(*cptr++ != '\0')
                {
                    if(':' == *cptr)
                    {
                        sum++;
                    }
                }
                cptr = tmp;
                j = i;
                for(; i < 8-sum; i++)
                {
                    sp[i] = 0;
                }

            }
        }
        else
        {
            if(0 != sp[i])
            {
                sp[i] *= 10;
            }
            sp[i] += *cptr++ - '0';
        }
    }

    p_ospf6_acl->fwd = fwd;
}

//ÕÅÇì¾ýµÄ·¢ËÍÏûÏ¢µ½DPDKº¯Êý
int
ospf_client_connect(struct ospf_acl_message* p_ospf,int size)
{
    int ret = 0;

    /*start connect server*/

    int ospf_sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(ospf_sock <= 0)
        return -1;

    struct sockaddr_in socketaddress;
    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons(IVI_INET_PORT);
    socketaddress.sin_addr.s_addr = inet_addr(IVI_INET_ADDRESS);
    memset( &(socketaddress.sin_zero), 0, 8 );
    /*start connect*/
    ret = connect( ospf_sock,&socketaddress,sizeof(struct sockaddr) );
    if(ret < 0)
    {
        close(ospf_sock);
        return -1;
    }

    /*send ospf message*/
    char buf[1024] = "";
    memcpy(buf,p_ospf,sizeof(struct ospf_acl_message));

    if( (p_ospf->type == ADD_OSPF6_ACL )||(p_ospf->type == DEL_OSPF6_ACL) )
    {

        memcpy(buf+sizeof(struct ospf_acl_message),p_ospf->data,sizeof(struct ospf6_acl_message));
    }


    ret = send( ospf_sock, buf, size, 0 );

    if(ret < 0)
    {
        perror("send fail!!!!\n");
    }

    close(ospf_sock);

    return 0;
}
//°ÑÍø¿Ú×ª»¯³ÉÊý×Ö zlw
int interface_to_int(char *pstr)
{
    if(NULL == pstr)
    {
        return -1;
    }
    while(*pstr != '\0')
    {
        if((*pstr>='0') && (*pstr<='9'))
        {
            return *pstr - '0';
        }
        pstr++;
    }
}

//¹¹ÔìÕÅÇì¾ýËùÐèÒªµÄ½á¹¹Ìå£¬²¢·¢ËÍ¸øËû
int
ospf6_send_acl_msg(char *src,char *dst,char *port)
{
    //¶¨ÒåÕÅÇì¾ýËùÓÃµÄ½á¹¹
    struct ospf_acl_message *ospf6_msg = NULL;
    struct ospf6_acl_message *ospf6_acl_msg = NULL;
    int fwd = 0;

    ospf6_msg = (struct ospf_acl_message *)malloc(sizeof(struct ospf_acl_message));
    if(NULL == ospf6_msg)
    {
        return 0;
    }

    memset(ospf6_msg ,0, sizeof(struct ospf_acl_message));
    ospf6_msg->type = ADD_OSPF6_ACL;
    ospf6_msg->len = sizeof(struct ospf_acl_message) + sizeof(struct ospf6_acl_message);

    //Îªacl msgÉêÇë¿Õ¼ä
    ospf6_acl_msg = (struct ospf6_acl_message *)malloc(sizeof(struct ospf6_acl_message));
    ospf6_msg->data = ospf6_acl_msg;
    memset(ospf6_acl_msg,0,sizeof(struct ospf6_acl_message));

    //°ÑÍø¿Ú×ª»¯³ÉÊý×Ö
    fwd = interface_to_int(port);

    ospf6_build_acl_message(ospf6_acl_msg,src,dst,fwd);

    //ÕÅÇì¾ýµÄ·¢ËÍº¯Êý
    ospf_client_connect(ospf6_msg,ospf6_msg->len);

    return 0;
}


//¹¹ÔìÕÅÇì¾ýËùÐèÒªµÄ½á¹¹Ìå£¬²¢·¢ËÍ¸øËû  É¾³ý²Ù×÷ zlw
int
ospf6_send_del_acl_msg(char *src,char *dst,char *port)
{
    //¶¨ÒåÕÅÇì¾ýËùÓÃµÄ½á¹¹
    struct ospf_acl_message *ospf6_msg = NULL;
    struct ospf6_acl_message *ospf6_acl_msg = NULL;
    int fwd = 0;

    ospf6_msg = (struct ospf_acl_message *)malloc(sizeof(struct ospf_acl_message));
    if(NULL == ospf6_msg)
    {
        return 0;
    }

    memset(ospf6_msg ,0, sizeof(struct ospf_acl_message));
    ospf6_msg->type = DEL_OSPF6_ACL;
    ospf6_msg->len = sizeof(struct ospf_acl_message) + sizeof(struct ospf6_acl_message);

    //Îªacl msgÉêÇë¿Õ¼ä
    ospf6_acl_msg = (struct ospf6_acl_message *)malloc(sizeof(struct ospf6_acl_message));
    ospf6_msg->data = ospf6_acl_msg;
    memset(ospf6_acl_msg,0,sizeof(struct ospf6_acl_message));

    //ÕÅÇì¾ýµÄ·¢ËÍº¯Êý
    ospf_client_connect(ospf6_msg,ospf6_msg->len);

    return 0;
}

//add by wly
int str_at(char *input,char *ip_addr,int *length)
{
    if(input==NULL)
    {
        printf("the argument is error \n");
        return -1;
    }
    char *p;
    char *tmp=(char *)malloc(8);
    int len;
    p=strtok(input,"/");
    if(p)
    {
        memcpy(ip_addr,p,strlen(p));
        p=strtok(NULL,"/");
        strcpy(tmp,p);
        len=atoi(tmp);
        *length =len;
    }
    free(tmp);
    tmp=NULL;
}
//add by myj
#define MAX_PAYLOAD 1024
#define ROUT_DEL_MSG 4

struct dmesion2_ctrl_msg rout_dmesion;

int send_route_msg_kernel (int msg_count, int handl_flag)
{
    int sock_fd = socket (PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    struct msghdr msg;
    struct sockaddr_nl dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    memset (&msg, 0, sizeof (msg));

    memset (&dest_addr, 0, sizeof (dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;		//For Linux Kernel
    dest_addr.nl_groups = 0;	//unicast
    //dest_addr.nl_groups=1;//muticast
    bind (sock_fd, (struct sockaddr *) &dest_addr, sizeof (dest_addr));

    //memset(&src_addr, 0, sizeof(src_addr));
    //     src_addr.nl_family = AF_NETLINK;
    //    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    //     src_addr.nl_groups = 0;/* not in mcast groups */

    nlh = (struct nlmsghdr *) malloc (NLMSG_SPACE (MAX_PAYLOAD));
    if (!nlh)
    {
        //printf("malloc nlmsghdr error!\n");
        close (sock_fd);
        return -1;
    }
    memset (nlh, 0, NLMSG_SPACE (MAX_PAYLOAD));

    nlh->nlmsg_len = NLMSG_SPACE (MAX_PAYLOAD);
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_flags = 0;
    //Fill in the netlink message payload
    struct tlv_flow p;
    memset (&p, 0, sizeof (struct tlv_flow));
    p.type = handl_flag;
    // p.type =ROUT_CTRL_MSG;  //route contrl flags

    int count = 0;
    int bytes = sizeof (struct dmesion2_ctrl_msg);
    char control_rut_msg[MAX_PAYLOAD - sizeof (struct tlv_flow)] = "";
    for (count = 0; count < msg_count; count++)
    {
        memcpy ((control_rut_msg + bytes * count), &(rout_dmesion), bytes);
    }
    p.length = bytes * count;

    char msg_load[MAX_PAYLOAD] = "";
    memcpy ((msg_load), &p, sizeof (struct tlv_flow));
    memcpy ((msg_load + sizeof (struct tlv_flow)), &control_rut_msg, bytes * count);
    memcpy ((NLMSG_DATA (nlh)), msg_load, sizeof (struct tlv_flow) + bytes * count);
    printf ("length:%d,bytes:%d msg:%d\n", p.length, bytes, p.length / bytes);
    //iov
    memset (&iov, 0, sizeof (iov));
    iov.iov_base = (void *) nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset (&msg, 0, sizeof (msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg (sock_fd, &msg, 0);
    close (sock_fd);
    free (nlh);
    return 0;

}

void creat_rout_two_tb (struct in6_addr *src, unsigned char src_len, struct in6_addr *dst, unsigned char dst_len, struct in6_addr *next_hop, int ifindex, struct dmesion2_ctrl_msg *rout_dmesion)
{

    int i;
    char buf[50] = "";

    memset (rout_dmesion, 0, sizeof (struct dmesion2_ctrl_msg));

//  inet_pton(AF_INET6,src,&rout_dmesion->src_prefix);
//  inet_pton(AF_INET6,dst,&rout_dmesion->dst_prefix);
    rout_dmesion->src_prefix = *(src);
    rout_dmesion->dst_prefix = *(dst);
    rout_dmesion->next_hop = *(next_hop);
    rout_dmesion->src_prefixlen = src_len;
    rout_dmesion->dst_prefixlen = dst_len;
    rout_dmesion->ifindex = ifindex;
#if ROUT_DEBUG
    for (i = 0; i < 8; i++)
    {
        sprintf (buf + i * 5, "%02x%02x:", rout_dmesion->src_prefix.s6_addr[i * 2], rout_dmesion->src_prefix.s6_addr[i * 2 + 1]);

    }
    fprintf (stdout, "ipv6 src address:%s prefix:%d\n", buf, rout_dmesion->src_prefixlen);

    for (i = 0; i < 8; i++)
    {
        sprintf (buf + i * 5, "%02x%02x:", rout_dmesion->dst_prefix.s6_addr[i * 2], rout_dmesion->dst_prefix.s6_addr[i * 2 + 1]);

    }
    fprintf (stdout, "ipv6 dst address:%s prefix:%d\n", buf, rout_dmesion->dst_prefixlen);
#endif

}

void
ospf6_intra_route_calculation_e(struct ospf6_area *oa,struct ospf6_route_table *route_table1)
{
    struct ospf6_route *route;
    u_int16_t type;
    struct ospf6_lsa *lsa;
    void (*hook_add) (struct ospf6_route *) = NULL;
    void (*hook_remove) (struct ospf6_route *) = NULL;
    char dst_pre[128];//zlw
    char src_pre[128];//zlw
    char out_if[20];//zlw
    char next_hop_add[48];//zlw
    int i = 0,frequecy = 0;//zlw
    char *ifiret=NULL;
    char buf[64];//zlw

    char dst_str[16],src_str[16];
    int dst_len,src_len;
    struct in6_addr dst_addr,src_addr;

    //å…ˆæŠŠè¿™ä¸¤ä¸ªèµ‹å€¼æ¸…é›¶ï¼Œ
    hook_add = route_table1->hook_add;
    hook_remove = route_table1->hook_remove;
    route_table1->hook_add = NULL;
    route_table1->hook_remove = NULL;

#if 0
    prefix2str (&oa->d_prefix, buf, sizeof (buf));//zlw
    printf("zlw==ospf6_intra_route_calculation_e00 : dst=%s\n",buf);

    prefix2str (&oa->s_prefix, buf, sizeof (buf));//zlw
    printf("zlw==ospf6_intra_route_calculation_e00 : srt=%s\n",buf);
#endif


    //å…ˆæ¸…ç©ºè¿™ä¸ªtable1
    for(route = ospf6_route_head(route_table1); route; route = ospf6_route_next(route))
    {
        route->flag = OSPF6_ROUTE_REMOVE;
    }

    type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
    //æ‹·è´
    for(lsa = ospf6_lsdb_type_head(type, oa->lsdb1); lsa; lsa = ospf6_lsdb_type_next(type,lsa))
    {
        ospf6_intra_prefix_lsa_add_e(lsa,route_table1);//ç”Ÿæˆè·¯ç”±çš„å…³é”®ä¸€æ­?zlw
    }

    //åˆæŠŠè¿™ä¸ªä¸¤ä¸ªèµ‹å€¼å›žæ¥äº†
    route_table1->hook_add = hook_add;
    route_table1->hook_remove = hook_remove;

    //±äÁ¿Â·ÓÉ±ítable1ÖÐµÄÂ·ÓÉ£¬
    for(route = ospf6_route_head(route_table1); route; route = ospf6_route_next(route))
    {
        if(   CHECK_FLAG (route->flag, OSPF6_ROUTE_REMOVE)
                && CHECK_FLAG (route->flag, OSPF6_ROUTE_ADD))
        {
            UNSET_FLAG(route->flag, OSPF6_ROUTE_REMOVE);
            UNSET_FLAG(route->flag, OSPF6_ROUTE_ADD);
        }

        if(CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)) //è¦åˆ é™¤çš„è·¯ç”±
        {
            ospf6_route_remove (route, route_table1);
        }

        else if( CHECK_FLAG (route->flag, OSPF6_ROUTE_ADD)
                 || CHECK_FLAG (route->flag, OSPF6_ROUTE_CHANGE))
        {
            if(hook_add)
            {
                //æ¯”è¾ƒç›®çš„å‰ç¼€å’Œæºåœ°å€å‰ç¼€ï¼Œå¾—åˆ°éœ€è¦çš„è·¯ç”±  zlw
                if((!strcmp((const char *)&oa->s_prefix.u.prefix,(const char *)&route->s_prefix.u.prefix))
                        && (!strcmp((const char *)&oa->d_prefix.u.prefix,(const char *)&route->prefix.u.prefix)))
                {
                    //printf("zlw======================== dst %s  src %s\n",&oa->d_prefix.u.prefix,&oa->s_prefix.u.prefix);
                    //æŠŠè·¯ç”±è¡¨ä¸­çš„ç›®çš„å‰ç¼€å’Œæºå‰ç¼€æ‹·è´å‡ºæ¥
                    prefix2str(&route->prefix, dst_pre, sizeof(dst_pre));//zlw
                    prefix2str(&route->s_prefix, src_pre, sizeof(src_pre));//zlw



#if 1
                    for(i=0; i<4; i++) //zlw  æ‰¾åˆ°è¿™ä¸ªè·¯ç”±å¯¹åº”çš„ä¸‹ä¸€è·³åœ°å€
                    {
                        char buf[128];
                        inet_ntop(AF_INET6, &(route->nexthop[i].address), buf, sizeof(buf));


                        //ÕÒµ½ÏÂÒ»ÌøµØÖ·  Èç¹û²»Îª¿Õ::
                        if(strcmp("::",buf) != 0)
                        {
                            //ÕÅÇì¾ý µÄ·¢ËÍº¯Êý  ²ÎÊý:Ä¿µÄÇ°×º  Ô´Ç°×º  ³ö½Ó¿Ú
#if 1  //add by myj for two demesion route
                            ifiret=ifindex2ifname(route->nexthop[i].ifindex);

                            if(strcmp(ifiret,"unknown")==0)
                            {
                                continue;
                            }

                            ospf6_send_acl_msg(src_pre,
                                               dst_pre,
                                               ifiret);

                            if(frequecy < 1)
                            {

                                creat_rout_two_tb(&route->s_prefix.u.prefix6,route->s_prefix.prefixlen,
                                                  &route->prefix.u.prefix6,route->prefix.prefixlen,
                                                  &(route->nexthop[i].address),route->nexthop[i].ifindex,&rout_dmesion);

                                send_route_msg_kernel(1,ROUT_CTRL_MSG);
                                frequecy++;
                                printf("the frequecy%d,in function of ospf6_intra_route_calculation_e \n",frequecy);

                            }

#endif
                            ospf6_twod_route_add_xml(dst_pre,
                                                     src_pre,
                                                     ifindex2ifname(route->nexthop[i].ifindex),
                                                     "2",
                                                     buf);//flag
                        }

                    }
#endif

                }

            }

        }

        route->flag = 0;
    }
}

static void ospf6_brouter_debug_print (struct ospf6_route *brouter)
{
    u_int32_t brouter_id;
    char brouter_name[16];
    char area_name[16];
    char destination[64];
    char installed[16], changed[16];
    struct timeval now, res;
    char id[16], adv_router[16];
    char capa[16], options[16];

    brouter_id = ADV_ROUTER_IN_PREFIX (&brouter->prefix);
    inet_ntop (AF_INET, &brouter_id, brouter_name, sizeof (brouter_name));
    inet_ntop (AF_INET, &brouter->path.area_id, area_name, sizeof (area_name));
    ospf6_linkstate_prefix2str (&brouter->prefix, destination, sizeof (destination));

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    timersub (&now, &brouter->installed, &res);
    timerstring (&res, installed, sizeof (installed));

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    timersub (&now, &brouter->changed, &res);
    timerstring (&res, changed, sizeof (changed));

    inet_ntop (AF_INET, &brouter->path.origin.id, id, sizeof (id));
    inet_ntop (AF_INET, &brouter->path.origin.adv_router, adv_router, sizeof (adv_router));

    ospf6_options_printbuf (brouter->path.options, options, sizeof (options));
    ospf6_capability_printbuf (brouter->path.router_bits, capa, sizeof (capa));

    zlog_info ("Brouter: %s via area %s", brouter_name, area_name);
    zlog_info ("  memory: prev: %p this: %p next: %p parent rnode: %p", brouter->prev, brouter, brouter->next, brouter->rnode);
    zlog_info ("  type: %d prefix: %s installed: %s changed: %s", brouter->type, destination, installed, changed);
    zlog_info ("  lock: %d flags: %s%s%s%s", brouter->lock,
               (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_BEST) ? "B" : "-"),
               (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_ADD) ? "A" : "-"), (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_REMOVE) ? "R" : "-"), (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_CHANGE) ? "C" : "-"));
    zlog_info ("  path type: %s ls-origin %s id: %s adv-router %s", OSPF6_PATH_TYPE_NAME (brouter->path.type), ospf6_lstype_name (brouter->path.origin.type), id, adv_router);
    zlog_info ("  options: %s router-bits: %s metric-type: %d metric: %d/%d", options, capa, brouter->path.metric_type, brouter->path.cost, brouter->path.cost_e2);
}

void ospf6_intra_brouter_calculation (struct ospf6_area *oa)
{
    struct ospf6_route *brouter, *copy;
    void (*hook_add) (struct ospf6_route *) = NULL;
    void (*hook_remove) (struct ospf6_route *) = NULL;
    u_int32_t brouter_id;
    char brouter_name[16];

    if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID (oa->area_id))
        zlog_info ("border-router calculation for area %s", oa->name);

    hook_add = oa->ospf6->brouter_table->hook_add;
    hook_remove = oa->ospf6->brouter_table->hook_remove;
    oa->ospf6->brouter_table->hook_add = NULL;
    oa->ospf6->brouter_table->hook_remove = NULL;

    /* withdraw the previous router entries for the area */
    for (brouter = ospf6_route_head (oa->ospf6->brouter_table); brouter; brouter = ospf6_route_next (brouter))
    {
        brouter_id = ADV_ROUTER_IN_PREFIX (&brouter->prefix);
        inet_ntop (AF_INET, &brouter_id, brouter_name, sizeof (brouter_name));
        if (brouter->path.area_id != oa->area_id)
            continue;
        brouter->flag = OSPF6_ROUTE_REMOVE;

        if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID (brouter_id) || IS_OSPF6_DEBUG_ROUTE (MEMORY))
        {
            zlog_info ("%p: mark as removing: area %s brouter %s", brouter, oa->name, brouter_name);
            ospf6_brouter_debug_print (brouter);
        }
    }

    for (brouter = ospf6_route_head (oa->spf_table); brouter; brouter = ospf6_route_next (brouter))
    {
        brouter_id = ADV_ROUTER_IN_PREFIX (&brouter->prefix);
        inet_ntop (AF_INET, &brouter_id, brouter_name, sizeof (brouter_name));

        if (brouter->type != OSPF6_DEST_TYPE_LINKSTATE)
            continue;
        if (ospf6_linkstate_prefix_id (&brouter->prefix) != htonl (0))
            continue;
        if (!CHECK_FLAG (brouter->path.router_bits, OSPF6_ROUTER_BIT_E) && !CHECK_FLAG (brouter->path.router_bits, OSPF6_ROUTER_BIT_B))
            continue;

        copy = ospf6_route_copy (brouter);
        copy->type = OSPF6_DEST_TYPE_ROUTER;
        copy->path.area_id = oa->area_id;
        ospf6_route_add (copy, oa->ospf6->brouter_table);

        if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID (brouter_id) || IS_OSPF6_DEBUG_ROUTE (MEMORY))
        {
            zlog_info ("%p: transfer: area %s brouter %s", brouter, oa->name, brouter_name);
            ospf6_brouter_debug_print (brouter);
        }
    }

    oa->ospf6->brouter_table->hook_add = hook_add;
    oa->ospf6->brouter_table->hook_remove = hook_remove;

    for (brouter = ospf6_route_head (oa->ospf6->brouter_table); brouter; brouter = ospf6_route_next (brouter))
    {
        brouter_id = ADV_ROUTER_IN_PREFIX (&brouter->prefix);
        inet_ntop (AF_INET, &brouter_id, brouter_name, sizeof (brouter_name));

        if (brouter->path.area_id != oa->area_id)
            continue;

        if (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_WAS_REMOVED))
            continue;

        if (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_REMOVE) && CHECK_FLAG (brouter->flag, OSPF6_ROUTE_ADD))
        {
            UNSET_FLAG (brouter->flag, OSPF6_ROUTE_REMOVE);
            UNSET_FLAG (brouter->flag, OSPF6_ROUTE_ADD);
        }

        if (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_REMOVE))
        {
            if (IS_OSPF6_DEBUG_BROUTER || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID (brouter_id) || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID (oa->area_id))
                zlog_info ("brouter %s disappears via area %s", brouter_name, oa->name);
            ospf6_route_remove (brouter, oa->ospf6->brouter_table);
        }
        else if (CHECK_FLAG (brouter->flag, OSPF6_ROUTE_ADD) || CHECK_FLAG (brouter->flag, OSPF6_ROUTE_CHANGE))
        {
            if (IS_OSPF6_DEBUG_BROUTER || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID (brouter_id) || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID (oa->area_id))
                zlog_info ("brouter %s appears via area %s", brouter_name, oa->name);

            /* newly added */
            if (hook_add)
                (*hook_add) (brouter);
        }
        else
        {
            if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID (brouter_id) || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID (oa->area_id))
                zlog_info ("brouter %s still exists via area %s", brouter_name, oa->name);
        }

        brouter->flag = 0;
    }

    if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID (oa->area_id))
        zlog_info ("border-router calculation for area %s: done", oa->name);
}

struct ospf6_lsa_handler router_handler =
{
    OSPF6_LSTYPE_ROUTER,
    "Router",
    ospf6_router_lsa_show
};

struct ospf6_lsa_handler network_handler =
{
    OSPF6_LSTYPE_NETWORK,
    "Network",
    ospf6_network_lsa_show
};

struct ospf6_lsa_handler link_handler =
{
    OSPF6_LSTYPE_LINK,
    "Link",
    ospf6_link_lsa_show
};

struct ospf6_lsa_handler intra_prefix_handler =
{
    OSPF6_LSTYPE_INTRA_PREFIX,
    "Intra-Prefix",
    ospf6_intra_prefix_lsa_show
};

void ospf6_intra_init (void)
{
    ospf6_install_lsa_handler (&router_handler);
    ospf6_install_lsa_handler (&network_handler);
    ospf6_install_lsa_handler (&link_handler);
    ospf6_install_lsa_handler (&intra_prefix_handler);
}

DEFUN (debug_ospf6_brouter, debug_ospf6_brouter_cmd, "debug ospf6 border-routers", DEBUG_STR OSPF6_STR "Debug border router\n")
{
    OSPF6_DEBUG_BROUTER_ON ();
    return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter, no_debug_ospf6_brouter_cmd, "no debug ospf6 border-routers", NO_STR DEBUG_STR OSPF6_STR "Debug border router\n")
{
    OSPF6_DEBUG_BROUTER_OFF ();
    return CMD_SUCCESS;
}

DEFUN (debug_ospf6_brouter_router,
       debug_ospf6_brouter_router_cmd,
       "debug ospf6 border-routers router-id A.B.C.D", DEBUG_STR OSPF6_STR "Debug border router\n" "Debug specific border router\n" "Specify border-router's router-id\n")
{
    u_int32_t router_id;
    inet_pton (AF_INET, argv[0], &router_id);
    OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ON (router_id);
    return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter_router, no_debug_ospf6_brouter_router_cmd, "no debug ospf6 border-routers router-id", NO_STR DEBUG_STR OSPF6_STR "Debug border router\n" "Debug specific border router\n")
{
    OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_OFF ();
    return CMD_SUCCESS;
}

DEFUN (debug_ospf6_brouter_area,
       debug_ospf6_brouter_area_cmd, "debug ospf6 border-routers area-id A.B.C.D", DEBUG_STR OSPF6_STR "Debug border router\n" "Debug border routers in specific Area\n" "Specify Area-ID\n")
{
    u_int32_t area_id;
    inet_pton (AF_INET, argv[0], &area_id);
    OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ON (area_id);
    return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter_area,
       no_debug_ospf6_brouter_area_cmd, "no debug ospf6 border-routers area-id", NO_STR DEBUG_STR OSPF6_STR "Debug border router\n" "Debug border routers in specific Area\n")
{
    OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_OFF ();
    return CMD_SUCCESS;
}

int config_write_ospf6_debug_brouter (struct vty *vty)
{
    char buf[16];
    if (IS_OSPF6_DEBUG_BROUTER)
        vty_out (vty, "debug ospf6 border-routers%s", VNL);
    if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER)
    {
        inet_ntop (AF_INET, &conf_debug_ospf6_brouter_specific_router_id, buf, sizeof (buf));
        vty_out (vty, "debug ospf6 border-routers router-id %s%s", buf, VNL);
    }
    if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA)
    {
        inet_ntop (AF_INET, &conf_debug_ospf6_brouter_specific_area_id, buf, sizeof (buf));
        vty_out (vty, "debug ospf6 border-routers area-id %s%s", buf, VNL);
    }
    return 0;
}

void install_element_ospf6_debug_brouter (void)
{
    install_element (ENABLE_NODE, &debug_ospf6_brouter_cmd);
    install_element (ENABLE_NODE, &debug_ospf6_brouter_router_cmd);
    install_element (ENABLE_NODE, &debug_ospf6_brouter_area_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_brouter_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_brouter_router_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_brouter_area_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_brouter_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_brouter_router_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_brouter_area_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_brouter_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_brouter_router_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_brouter_area_cmd);
}
