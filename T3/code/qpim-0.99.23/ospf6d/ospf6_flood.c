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
//add by myj
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>


#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "memtypes.h"

#include "ospf6d.h"
#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"		//zlw
#include "ospf6_flood.h"
#include "ospf6_abr.h"

extern vty_pip vty_p[];
unsigned char conf_debug_ospf6_flooding;

struct ospf6_lsdb *
ospf6_get_scoped_lsdb (struct ospf6_lsa *lsa)
{
    struct ospf6_lsdb *lsdb = NULL;
    switch (OSPF6_LSA_SCOPE (lsa->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
        lsdb = OSPF6_INTERFACE (lsa->lsdb->data)->lsdb;
        break;
    case OSPF6_SCOPE_AREA:
        lsdb = OSPF6_AREA (lsa->lsdb->data)->lsdb;
        break;
    case OSPF6_SCOPE_AS:
#if 1 //add 2020
        if (ntohs(lsa->header->type) == OSPF6_LSTYPE_ZONE)
            lsdb = OSPF6_PROCESS (lsa->lsdb->data)->lsdb_zone;
        else
#endif
            lsdb = OSPF6_PROCESS (lsa->lsdb->data)->lsdb;
        break;
    default:
        assert (0);
        break;
    }
    return lsdb;
}

struct ospf6_lsdb *
ospf6_get_scoped_lsdb_self (struct ospf6_lsa *lsa)
{
    struct ospf6_lsdb *lsdb_self = NULL;
    switch (OSPF6_LSA_SCOPE (lsa->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
        lsdb_self = OSPF6_INTERFACE (lsa->lsdb->data)->lsdb_self;
        break;
    case OSPF6_SCOPE_AREA:
        lsdb_self = OSPF6_AREA (lsa->lsdb->data)->lsdb_self;
        break;
    case OSPF6_SCOPE_AS:
        lsdb_self = OSPF6_PROCESS (lsa->lsdb->data)->lsdb_self;
        break;
    default:
        assert (0);
        break;
    }
    return lsdb_self;
}

void
ospf6_lsa_originate (struct ospf6_lsa *lsa)
{
    struct ospf6_lsa *old;
    struct ospf6_lsdb *lsdb_self;

    /* find previous LSA */
    old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                             lsa->header->adv_router, lsa->lsdb);

    /* if the new LSA does not differ from previous,
       suppress this update of the LSA */
    if (old && ! OSPF6_LSA_IS_DIFFER (lsa, old))
    {
        if (IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
            zlog_debug ("Suppress updating LSA: %s", lsa->name);
        ospf6_lsa_delete (lsa);
        return;
    }

    /* store it in the LSDB for self-originated LSAs */
    lsdb_self = ospf6_get_scoped_lsdb_self (lsa);
    ospf6_lsdb_add (ospf6_lsa_copy (lsa), lsdb_self);

    lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                     OSPF_LS_REFRESH_TIME);

    if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
            IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
    {
        zlog_debug ("LSA Originate:");
        ospf6_lsa_header_print (lsa);
    }

    ospf6_install_lsa (lsa);
    ospf6_flood (NULL, lsa);
}
#if 1
static void ospf6_zone_lsa_originate (struct ospf6_lsa *lsa, int flood_flag)
{
    struct ospf6_lsa *old;
    struct ospf6_lsdb *lsdb_self;

    /* find previous LSA */
    old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                             lsa->header->adv_router, lsa->lsdb);

    /* if the new LSA does not differ from previous,
       suppress this update of the LSA */
    if (old && ! OSPF6_LSA_IS_DIFFER (lsa, old))
    {
        if (IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
            zlog_debug ("Suppress updating LSA: %s", lsa->name);
        ospf6_lsa_delete (lsa);
        return;
    }

    /* store it in the LSDB for self-originated LSAs */
    lsdb_self = ospf6_get_scoped_lsdb_self (lsa);
    ospf6_lsdb_add (ospf6_lsa_copy (lsa), lsdb_self);

    lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                     OSPF_LS_REFRESH_TIME);

    if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
            IS_OSPF6_DEBUG_ORIGINATE_TYPE (lsa->header->type))
    {
        zlog_debug ("LSA Originate:");
        ospf6_lsa_header_print (lsa);
    }
    ospf6_install_lsa (lsa);

    if (flood_flag)
        ospf6_flood (NULL, lsa);
}
#endif

void ospf6_lsa_originate_process (struct ospf6_lsa *lsa,
                                  struct ospf6 *process)
{
    lsa->lsdb = process->lsdb;
    ospf6_lsa_originate (lsa);
}

void ospf6_lsa_originate_area (struct ospf6_lsa *lsa,
                               struct ospf6_area *oa)
{
    lsa->lsdb = oa->lsdb;
    //DG("will call ospf6_lsa_originate.\n");
    ospf6_lsa_originate (lsa);
}
void ospf6_lsa_originate_zone (struct ospf6_lsa *lsa,
                               struct ospf6 *o, int flood_flag)
{
    lsa->lsdb = o->lsdb_zone;
    ospf6_zone_lsa_originate (lsa, flood_flag);
}


void
ospf6_lsa_originate_interface (struct ospf6_lsa *lsa,
                               struct ospf6_interface *oi)
{
    lsa->lsdb = oi->lsdb;
    ospf6_lsa_originate (lsa);
}

void
ospf6_lsa_purge (struct ospf6_lsa *lsa)
{
    struct ospf6_lsa *self;
    struct ospf6_lsdb *lsdb_self;

    /* remove it from the LSDB for self-originated LSAs */
    lsdb_self = ospf6_get_scoped_lsdb_self (lsa);
    self = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                              lsa->header->adv_router, lsdb_self);
    if (self)
    {
        THREAD_OFF (self->expire);
        THREAD_OFF (self->refresh);
        ospf6_lsdb_remove (self, lsdb_self);
    }

    ospf6_lsa_premature_aging (lsa);
}


void
ospf6_increment_retrans_count (struct ospf6_lsa *lsa)
{
    /* The LSA must be the original one (see the description
       in ospf6_decrement_retrans_count () below) */
    lsa->retrans_count++;
}

void
ospf6_decrement_retrans_count (struct ospf6_lsa *lsa)
{
    struct ospf6_lsdb *lsdb;
    struct ospf6_lsa *orig;

    /* The LSA must be on the retrans-list of a neighbor. It means
       the "lsa" is a copied one, and we have to decrement the
       retransmission count of the original one (instead of this "lsa"'s).
       In order to find the original LSA, first we have to find
       appropriate LSDB that have the original LSA. */
    lsdb = ospf6_get_scoped_lsdb (lsa);

    /* Find the original LSA of which the retrans_count should be decremented */
    orig = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                              lsa->header->adv_router, lsdb);
    if (orig)
    {
        if (orig->retrans_count > 0)
            orig->retrans_count--;
        else
            orig->retrans_count = 0;

        assert (orig->retrans_count >= 0);
    }
}
//add for OSPF+ 16.4.21
void ospf6_install_lsa_for_leaving (struct ospf6_lsa *lsa)
{
    struct ospf6_lsa *old;
    struct timeval now;

    if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
            IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        zlog_debug ("Install LSA: %s", lsa->name);

    /* Remove the old instance from all neighbors' Link state
       retransmission list (RFC2328 13.2 last paragraph) */
    old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                             lsa->header->adv_router, lsa->lsdb);
    if (old)
    {
        THREAD_OFF (old->expire);
        THREAD_OFF (old->refresh);
    }

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    if (! OSPF6_LSA_IS_MAXAGE (lsa))
        lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                        OSPF_LSA_MAXAGE + lsa->birth.tv_sec - now.tv_sec);
    else
        lsa->expire = NULL;

    if (OSPF6_LSA_IS_SEQWRAP(lsa) &&
            ! (CHECK_FLAG(lsa->flag,OSPF6_LSA_SEQWRAPPED) &&
               lsa->header->seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER)))
    {
        if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
            zlog_debug("lsa install wrapping: sequence 0x%x",
                       ntohl(lsa->header->seqnum));
        SET_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED);
        /* in lieu of premature_aging, since we do not want to recreate this lsa
         * and/or mess with timers etc, we just want to wrap the sequence number
         * and reflood the lsa before continuing.
         * NOTE: Flood needs to be called right after this function call, by the
         * caller
         */
        lsa->header->seqnum = htonl (OSPF_MAX_SEQUENCE_NUMBER);
        lsa->header->age = htons (OSPF_LSA_MAXAGE);
        ospf6_lsa_checksum (lsa->header);
    }

    /* actually install */
    lsa->installed = now;
    ospf6_lsdb_add_for_leaving (lsa, lsa->lsdb);

    return;
}
void ospf6_install_lsa_for_expire(struct ospf6_lsa *lsa)
{
    struct timeval now;
    struct ospf6_lsa *expire_lsa;
    struct ospf6_neighbor *on = NULL;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct listnode *i, *j, *k;
    char adv_router[32];

    expire_lsa = ospf6_lsa_copy(lsa);

#if 0
    char router_id1[32], router_id2[32];
    inet_ntop (AF_INET, &ospf6->router_id, router_id1,
               sizeof (router_id1));

    inet_ntop (AF_INET, &expire_lsa->header->adv_router, router_id2,
               sizeof (router_id2));
    printf(">>>>%s()%d ospf6 routeid:%s, lsa adv_router:%s.\n", __func__, __LINE__, router_id1, router_id2);
    /*don't install self originate lsa*/
#endif
    if (ospf6->router_id == expire_lsa->header->adv_router)
        return;

    if (IS_OSPF6_DEBUG_LSA_TYPE (expire_lsa->header->type) ||
            IS_OSPF6_DEBUG_EXAMIN_TYPE (expire_lsa->header->type))
        zlog_debug ("Install LSA: %s", expire_lsa->name);

    inet_ntop (AF_INET, &expire_lsa->header->adv_router, adv_router,
               sizeof (adv_router));

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
            {
#if 0
                inet_ntop (AF_INET, &on->router_id, router_id,
                           sizeof (router_id));
                zlog_debug("router_id:%s, adv_router:%s", router_id, adv_router);
                if (on->router_id == expire_lsa->header->adv_router)
                    break;
#endif
                if (on->state == OSPF6_NEIGHBOR_LEAVING)
                    break;
            }
    if (on == NULL)
        return;

    lsa->expire = NULL;
    expire_lsa->lsdb = on->lsexpire_list;

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    expire_lsa->expire = NULL;

    /* actually install */
    expire_lsa->installed = now;
    ospf6_lsdb_add_for_expire (expire_lsa, expire_lsa->lsdb);

    return;
}

/* RFC2328 section 13.2 Installing LSAs in the database */
void
ospf6_install_lsa (struct ospf6_lsa *lsa)
{
    struct timeval now;
    struct ospf6_lsa *old;

    if (IS_OSPF6_DEBUG_LSA_TYPE (lsa->header->type) ||
            IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
        zlog_debug ("Install LSA: %s", lsa->name);

    //DG ("Install LSA: %s, name:%d.\n", lsa->name, ntohs (lsa->header->age));

    /* Remove the old instance from all neighbors' Link state
       retransmission list (RFC2328 13.2 last paragraph) */
    old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                             lsa->header->adv_router, lsa->lsdb);
    if (old)
    {
        //DG("find old, THREAD_OFF some thread, old name:%s, age:%d.\n", old->name, ntohs (old->header->age));
        THREAD_OFF (old->expire);
        THREAD_OFF (old->refresh);
        ospf6_flood_clear (old);
    }

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    if (! OSPF6_LSA_IS_MAXAGE (lsa))
        lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                        OSPF_LSA_MAXAGE + lsa->birth.tv_sec - now.tv_sec);
    else
        lsa->expire = NULL;

    if (OSPF6_LSA_IS_SEQWRAP(lsa) &&
            ! (CHECK_FLAG(lsa->flag,OSPF6_LSA_SEQWRAPPED) &&
               lsa->header->seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER)))
    {
        if (IS_OSPF6_DEBUG_EXAMIN_TYPE (lsa->header->type))
            zlog_debug("lsa install wrapping: sequence 0x%x",
                       ntohl(lsa->header->seqnum));

        //DG("lsa install wrapping: sequence 0x%x.\n",
        //  ntohl(lsa->header->seqnum));

        SET_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED);
        /* in lieu of premature_aging, since we do not want to recreate this lsa
         * and/or mess with timers etc, we just want to wrap the sequence number
         * and reflood the lsa before continuing.
         * NOTE: Flood needs to be called right after this function call, by the
         * caller
         */
        lsa->header->seqnum = htonl (OSPF_MAX_SEQUENCE_NUMBER);
        lsa->header->age = htons (OSPF_LSA_MAXAGE);
        ospf6_lsa_checksum (lsa->header);
    }

    /* actually install */
    lsa->installed = now;
    //DG("will add lsa to lsdb, name:%s,age:%d.\n", lsa->name, ntohs (lsa->header->age));
    ospf6_lsdb_add (lsa, lsa->lsdb);

    return;
}
/* RFC2740 section 3.5.2. Sending Link State Update packets */
/* RFC2328 section 13.3 Next step in the flooding procedure */
static void
ospf6_flood_interface (struct ospf6_neighbor *from,
                       struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
    struct listnode *node, *nnode;
    struct ospf6_neighbor *on;
    struct ospf6_lsa *req;
    /*add */
    int retrans_added = 0;
    int is_debug = 0;

    if (IS_OSPF6_DEBUG_FLOODING ||
            IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
    {
        is_debug++;
        zlog_debug ("Flooding on %s: %s", oi->interface->name, lsa->name);
    }
#if 0
    //for test
    is_debug = 1;
    DG ("Flooding on %s: %s.\n\n", oi->interface->name, lsa->name);
#endif

    /* (1) For each neighbor */
    for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
        if (is_debug)
            zlog_debug ("To neighbor %s", on->name);

        /* (a) if neighbor state < Exchange, examin next */
        if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
        {
            if (is_debug)
                zlog_debug ("Neighbor state less than ExChange, next neighbor");
            continue;
        }
        //FIXME: save new lsas to on struct?
        if (on->state == OSPF6_NEIGHBOR_LEAVING)
        {
            continue;
        }

        /* (b) if neighbor not yet Full, check request-list */
        if (on->state != OSPF6_NEIGHBOR_FULL)
        {
            if (is_debug)
                zlog_debug ("Neighbor not yet Full");

            req = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                     lsa->header->adv_router, on->request_list);
            if (req == NULL)
            {
                if (is_debug)
                    zlog_debug ("Not on request-list for this neighbor");
                /* fall through */
            }
            else
            {
                //add 2020
                if (ntohs(lsa->header->type) != OSPF6_LSTYPE_ZONE)
                {
                    /* If new LSA less recent, examin next neighbor */
                    if (ospf6_lsa_compare (lsa, req) > 0)
                    {
                        if (is_debug)
                            zlog_debug ("Requesting is older, next neighbor");
                        continue;
                    }

                    /* If the same instance, delete from request-list and
                       examin next neighbor */
                    if (ospf6_lsa_compare (lsa, req) == 0)
                    {
                        if (is_debug)
                            zlog_debug ("Requesting the same, remove it, next neighbor");
                        if (req == on->last_ls_req)
                        {
                            ospf6_lsa_unlock (req);
                            on->last_ls_req = NULL;
                        }
                        ospf6_lsdb_remove (req, on->request_list);
                        ospf6_check_nbr_loading (on);
                        continue;
                    }

                    /* If the new LSA is more recent, delete from request-list */
                    if (ospf6_lsa_compare (lsa, req) < 0)
                    {
                        if (is_debug)
                            zlog_debug ("Received is newer, remove requesting");
                        if (req == on->last_ls_req)
                        {
                            ospf6_lsa_unlock (req);
                            on->last_ls_req = NULL;
                        }
                        ospf6_lsdb_remove (req, on->request_list);
                        ospf6_check_nbr_loading (on);
                        /* fall through */
                    }
                }
#if 1 //add 2020
                else
                {
                    if (ospf6_lsa_compare (lsa, req) == 0)
                    {
                        if (is_debug)
                            zlog_debug ("Zone lsa, received is same, remove requesting");
                        if (req == on->last_ls_req)
                        {
                            ospf6_lsa_unlock (req);
                            on->last_ls_req = NULL;
                        }
                        ospf6_lsdb_remove (req, on->request_list);
                        ospf6_check_nbr_loading (on);
                        /* fall through */
                    }
                }
#endif
            }
        }

        /* (c) If the new LSA was received from this neighbor,
           examin next neighbor */
        if (from == on)
        {
            if (is_debug)
                zlog_debug ("Received is from the neighbor, next neighbor");
            continue;
        }

        /* (d) add retrans-list, schedule retransmission */
        if (is_debug)
            zlog_debug ("Add retrans-list of this neighbor");
        ospf6_increment_retrans_count (lsa);
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        if (on->thread_send_lsupdate == NULL)
            on->thread_send_lsupdate =
                thread_add_timer (master, ospf6_lsupdate_send_neighbor,
                                  on, on->ospf6_if->rxmt_interval);
        retrans_added++;
    }

    /* (2) examin next interface if not added to retrans-list */
    if (retrans_added == 0)
    {
        if (is_debug)
            zlog_debug ("No retransmission scheduled, next interface");
        return;
    }

    /* (3) If the new LSA was received on this interface,
       and it was from DR or BDR, examin next interface */
    if (from && from->ospf6_if == oi &&
            (from->router_id == oi->drouter || from->router_id == oi->bdrouter))
    {
        if (is_debug)
            zlog_debug ("Received is from the I/F's DR or BDR, next interface");
        return;
    }

    /* (4) If the new LSA was received on this interface,
       and the interface state is BDR, examin next interface */
    if (from && from->ospf6_if == oi)
    {
        if (oi->state == OSPF6_INTERFACE_BDR)
        {
            if (is_debug)
                zlog_debug ("Received is from the I/F, itself BDR, next interface");
            return;
        }
        SET_FLAG(lsa->flag, OSPF6_LSA_FLOODBACK);
    }
    /* (5) flood the LSA out the interface. */
    if (is_debug)
        zlog_debug ("Schedule flooding for the interface");
    if ((oi->type == OSPF_IFTYPE_BROADCAST) ||
            (oi->type == OSPF_IFTYPE_POINTOPOINT))
    {
#ifdef TWOD
        ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), oi->lsupdate_list);  // haozhiqiang 2016-2-16
#else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
#endif
        if (oi->thread_send_lsupdate == NULL)
            oi->thread_send_lsupdate =
                thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
    }
    else
    {
        /* reschedule retransmissions to all neighbors */
        for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
        {
            THREAD_OFF (on->thread_send_lsupdate);
            on->thread_send_lsupdate =
                thread_add_event (master, ospf6_lsupdate_send_neighbor, on, 0);
        }
    }
}

static void
ospf6_flood_area (struct ospf6_neighbor *from,
                  struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
    struct listnode *node, *nnode;
    struct ospf6_interface *oi;
    struct ospf6_lsa *new_lsa;

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    {
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
                oi != OSPF6_INTERFACE (lsa->lsdb->data))
            continue;

#if 0
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AS &&
                ospf6_is_interface_virtual_link (oi))
            continue;
#endif/*0*/

        ospf6_flood_interface (from, lsa, oi);
        /*add 2019 install lsupdate to new_lsas_list*/
        if (from != NULL && oi->reference_count > 0)
        {
            if (ntohs(lsa->header->type) != OSPF6_LSTYPE_ZONE)
            {
                new_lsa = ospf6_lsa_copy_for_leaving(lsa, oi);
                ospf6_install_lsa_for_leaving (new_lsa);
            }
        }
    }
}

static void
ospf6_flood_process (struct ospf6_neighbor *from,
                     struct ospf6_lsa *lsa, struct ospf6 *process)
{
    struct listnode *node, *nnode;
    struct ospf6_area *oa;

    for (ALL_LIST_ELEMENTS (process->area_list, node, nnode, oa))
    {
#if 0
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AREA)
            DG("AS lsa->name:%s, oa->name:%s, oa name in lsa:%s.\n", lsa->name, oa->name, OSPF6_AREA (lsa->lsdb->data)->name);
#endif
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AREA &&
                oa != OSPF6_AREA (lsa->lsdb->data))
            continue;
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
                oa != OSPF6_INTERFACE (lsa->lsdb->data)->area)
            continue;

        if (ntohs (lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
                IS_AREA_STUB (oa))
            continue;
        ospf6_flood_area (from, lsa, oa);
    }
}

void
ospf6_flood (struct ospf6_neighbor *from, struct ospf6_lsa *lsa)
{
    ospf6_flood_process (from, lsa, ospf6);
}

static void
ospf6_flood_clear_interface (struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
    struct listnode *node, *nnode;
    struct ospf6_neighbor *on;
    struct ospf6_lsa *rem;

    for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
        if(on->state == OSPF6_NEIGHBOR_LEAVING)
            continue;
        rem = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                 lsa->header->adv_router, on->retrans_list);
        if (rem && ! ospf6_lsa_compare (rem, lsa))
        {
            if (IS_OSPF6_DEBUG_FLOODING ||
                    IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
                zlog_debug ("Remove %s from retrans_list of %s",
                            rem->name, on->name);
            ospf6_decrement_retrans_count (rem);
            ospf6_lsdb_remove (rem, on->retrans_list);
        }
    }
}

static void
ospf6_flood_clear_area (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
    struct listnode *node, *nnode;
    struct ospf6_interface *oi;

    for (ALL_LIST_ELEMENTS (oa->if_list, node, nnode, oi))
    {
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
                oi != OSPF6_INTERFACE (lsa->lsdb->data))
            continue;

#if 0
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AS &&
                ospf6_is_interface_virtual_link (oi))
            continue;
#endif/*0*/

        ospf6_flood_clear_interface (lsa, oi);
    }
}

static void
ospf6_flood_clear_process (struct ospf6_lsa *lsa, struct ospf6 *process)
{
    struct listnode *node, *nnode;
    struct ospf6_area *oa;

    for (ALL_LIST_ELEMENTS (process->area_list, node, nnode, oa))
    {
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_AREA &&
                oa != OSPF6_AREA (lsa->lsdb->data))
            continue;
        if (OSPF6_LSA_SCOPE (lsa->header->type) == OSPF6_SCOPE_LINKLOCAL &&
                oa != OSPF6_INTERFACE (lsa->lsdb->data)->area)
            continue;

        if (ntohs (lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
                IS_AREA_STUB (oa))
            continue;

        ospf6_flood_clear_area (lsa, oa);
    }
}

void
ospf6_flood_clear (struct ospf6_lsa *lsa)
{
    ospf6_flood_clear_process (lsa, ospf6);
}


/* RFC2328 13.5 (Table 19): Sending link state acknowledgements. */
static void
ospf6_acknowledge_lsa_bdrouter (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
{
    struct ospf6_interface *oi;
    int is_debug = 0;

    if (IS_OSPF6_DEBUG_FLOODING ||
            IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
        is_debug++;

    assert (from && from->ospf6_if);
    oi = from->ospf6_if;

    /* LSA is more recent than database copy, but was not flooded
       back out receiving interface. Delayed acknowledgement sent
       if advertisement received from Designated Router,
       otherwide do nothing. */
    if (ismore_recent < 0)
    {
        if (oi->drouter == from->router_id)
        {
            if (is_debug)
                zlog_debug ("Delayed acknowledgement (BDR & MoreRecent & from DR)");
            /* Delayed acknowledgement */
#ifdef TWOD
            ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), oi->lsack_list);	// haozhiqiang 2016-2-16
#else
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
#endif
            if (oi->thread_send_lsack == NULL)
                oi->thread_send_lsack =
                    thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
        }
        else
        {
            if (is_debug)
                zlog_debug ("No acknowledgement (BDR & MoreRecent & ! from DR)");
        }
        return;
    }

    /* LSA is a duplicate, and was treated as an implied acknowledgement.
       Delayed acknowledgement sent if advertisement received from
       Designated Router, otherwise do nothing */
    if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
            CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
        if (oi->drouter == from->router_id)
        {
            if (is_debug)
                zlog_debug ("Delayed acknowledgement (BDR & Duplicate & ImpliedAck & from DR)");
            /* Delayed acknowledgement */
#ifdef TWOD
            ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), oi->lsack_list);
#else
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
#endif
            if (oi->thread_send_lsack == NULL)
                oi->thread_send_lsack =
                    thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
        }
        else
        {
            if (is_debug)
                zlog_debug ("No acknowledgement (BDR & Duplicate & ImpliedAck & ! from DR)");
        }
        return;
    }

    /* LSA is a duplicate, and was not treated as an implied acknowledgement.
       Direct acknowledgement sent */
    if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
            ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
        if (is_debug)
            zlog_debug ("Direct acknowledgement (BDR & Duplicate)");
#ifdef TWOD
        ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), from->lsack_list);
#else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
#endif
        if (from->thread_send_lsack == NULL)
            from->thread_send_lsack =
                thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
        return;
    }

    /* LSA's LS age is equal to Maxage, and there is no current instance
       of the LSA in the link state database, and none of router's
       neighbors are in states Exchange or Loading */
    /* Direct acknowledgement sent, but this case is handled in
       early of ospf6_receive_lsa () */
}

static void
ospf6_acknowledge_lsa_allother (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
{
    struct ospf6_interface *oi;
    int is_debug = 0;

    if (IS_OSPF6_DEBUG_FLOODING ||
            IS_OSPF6_DEBUG_FLOOD_TYPE (lsa->header->type))
        is_debug++;

    assert (from && from->ospf6_if);
    oi = from->ospf6_if;

    /* LSA has been flood back out receiving interface.
       No acknowledgement sent. */
    if (CHECK_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK))
    {
        if (is_debug)
            zlog_debug ("No acknowledgement (AllOther & FloodBack)");
        return;
    }

    /* LSA is more recent than database copy, but was not flooded
       back out receiving interface. Delayed acknowledgement sent. */
    if (ismore_recent < 0)
    {
        if (is_debug)
            zlog_debug ("Delayed acknowledgement (AllOther & MoreRecent)");
        /* Delayed acknowledgement */
#ifdef TWOD
        ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), oi->lsack_list);	// haozhiqiang 2016-2-16
#else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);	// haozhiqiang 2016-2-16
#endif
        if (oi->thread_send_lsack == NULL)
            oi->thread_send_lsack =
                thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
        return;
    }

    /* LSA is a duplicate, and was treated as an implied acknowledgement.
       No acknowledgement sent. */
    if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
            CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
        if (is_debug)
            zlog_debug ("No acknowledgement (AllOther & Duplicate & ImpliedAck)");
        return;
    }

    /* LSA is a duplicate, and was not treated as an implied acknowledgement.
       Direct acknowledgement sent */
    if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
            ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
        if (is_debug)
            zlog_debug ("Direct acknowledgement (AllOther & Duplicate)");
#ifdef TWOD
        ospf6_lsdb_add_e (ospf6_lsa_copy (lsa), from->lsack_list);
#else
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
#endif
        if (from->thread_send_lsack == NULL)
            from->thread_send_lsack =
                thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
        return;
    }

    /* LSA's LS age is equal to Maxage, and there is no current instance
       of the LSA in the link state database, and none of router's
       neighbors are in states Exchange or Loading */
    /* Direct acknowledgement sent, but this case is handled in
       early of ospf6_receive_lsa () */
}

static void
ospf6_acknowledge_lsa (struct ospf6_lsa *lsa, int ismore_recent,
                       struct ospf6_neighbor *from)
{
    struct ospf6_interface *oi;

    assert (from && from->ospf6_if);
    oi = from->ospf6_if;

    if (oi->state == OSPF6_INTERFACE_BDR)
        ospf6_acknowledge_lsa_bdrouter (lsa, ismore_recent, from);
    else
        ospf6_acknowledge_lsa_allother (lsa, ismore_recent, from);
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading
   returns 1 if match this case, else returns 0 */
static int
ospf6_is_maxage_lsa_drop (struct ospf6_lsa *lsa, struct ospf6_neighbor *from)
{
    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct ospf6 *process = NULL;
    struct listnode *i, *j, *k;
    int count = 0;

    if (! OSPF6_LSA_IS_MAXAGE (lsa))
        return 0;

    if (ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsa->lsdb))
        return 0;

    process = from->ospf6_if->area->ospf6;

    for (ALL_LIST_ELEMENTS_RO (process->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
                if (on->state == OSPF6_NEIGHBOR_EXCHANGE ||
                        on->state == OSPF6_NEIGHBOR_LOADING)
                    count++;

    if (count == 0)
        return 1;
    return 0;
}

/* RFC2328 section 13 The Flooding Procedure */
#define ROUT_DEL_MSG 4
#ifdef TWOD
extern void reat_rout_two_tb (struct in6_addr *src, unsigned char src_len, struct in6_addr *dst, unsigned char dst_len, int ifindex, struct dmesion2_ctrl_msg *rout_dmesion);

extern int send_route_msg_kernel (int msg_count, int handl_flag);
extern struct dmesion2_ctrl_msg rout_dmesion;

//del the twod route from xml filer    by zlw
int remove_xml_twod_lsa (struct ospf6_lsa *lsa)
{
    struct in6_addr s_in6;		//src
    struct in6_addr d_in6;		//dst
    struct ospf6_prefix *op;
    static int flag1;

    char *end;
    struct ospf6_source_addr_prefix_TLV *addr_source;
    char buf[128];
    char dst_buf[128];
    char src_buf[128];


    end = (char *) lsa->header + ntohs (lsa->header->length) - 24;
    addr_source = (struct ospf6_source_addr_prefix_TLV *) end;	//current+ OSPF6_PREFIX_SIZE (prefix)+4;

    op = (struct ospf6_prefix *) ((char *) lsa->header + sizeof (struct ospf6_lsa_header) + sizeof (struct ospf6_intra_prefix_lsa));

    //目的地址
    memset (&d_in6, 0, sizeof (d_in6));
    memcpy (&d_in6, OSPF6_PREFIX_BODY (op), OSPF6_PREFIX_SPACE (op->prefix_length));
    memset (buf, 0, 128);
    inet_ntop (AF_INET6, &d_in6, buf, sizeof (buf));
    memset (dst_buf, 0, 128);
    sprintf (dst_buf, "%s/%d", buf, (op->prefix_length));


    //源地址
    memset (&s_in6, 0, sizeof (s_in6));
    memcpy (&s_in6, end + 8, OSPF6_PREFIX_SPACE (addr_source->tlv_length));

    memset (buf, 0, sizeof (buf));
    inet_ntop (AF_INET6, &s_in6, buf, sizeof (buf));
    memset (src_buf, 0, sizeof (src_buf));
    sprintf (src_buf, "%s/%d", buf, addr_source->tlv_length);
    printf ("zlw==remove_xml_twod_lsa : Source Prefix: %s\n", src_buf);

    if(flag1 == 0)
    {
        creat_rout_two_tb(&s_in6,addr_source->tlv_length,
                          &d_in6,op->prefix_length,&d_in6,0,&rout_dmesion);
        //               creat_rout_two_tb("1003::2",64,"1005::5",64,4,&rout_dmesion);
        printf("the program excute this 5\n");
        send_route_msg_kernel(1,ROUT_DEL_MSG);

    }
    flag1++;
    if(flag1 == 6)
        flag1 = 0;


    ospf6_twod_route_del_xml(dst_buf,src_buf);

    return 0;
}

// del one ipv6 route  haozhiqiang 2016-2-2
int remove_intra_lsa (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
    struct ospf6_prefix *op_orig;
    struct ospf6_lsa *self;
    int rtn = 0;
    if (lsa->header->type == htons (OSPF6_LSTYPE_E_INTRA_PREFIX))
    {
        op_orig = (struct ospf6_prefix *) ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header) + OSPF6_INTRA_PREFIX_LSA_MIN_SIZE);

        if (op_orig->prefix_options == 0)
        {
            self = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id, lsa->header->adv_router, lsdb);

            printf ("remove_intra_lsa program excute this 1\n");

            remove_xml_twod_lsa (lsa);
            if (self)
            {
                ospf6_lsdb_remove (self, lsdb);
                return -1;
            }
            return -1;
        }

        return 1;
    }

    return 1;
}
#endif
/*add for ospf+ 16.4.21*/
void ospf6_receive_lsa_for_leaving (struct ospf6_neighbor *from, struct ospf6_lsa_header *lsa_header)
{
    struct ospf6_lsa *new = NULL, *old = NULL;
    int ismore_recent;
    unsigned short cksum;
    int is_debug = 0;

    ismore_recent = 1;
    assert (from);

    /* make lsa structure for received lsa */
    new = ospf6_lsa_create (lsa_header);

    if (IS_OSPF6_DEBUG_FLOODING || IS_OSPF6_DEBUG_FLOOD_TYPE (new->header->type))
    {
        is_debug++;
        zlog_debug ("LSA Receive from %s", from->name);
        ospf6_lsa_header_print (new);
    }

    /* (1) LSA Checksum */
    cksum = ntohs (new->header->checksum);
    if (ntohs (ospf6_lsa_checksum (new->header)) != cksum)
    {
        if (is_debug)
            zlog_debug ("Wrong LSA Checksum, discard");
        ospf6_lsa_delete (new);
        return;
    }

    /* (2) Examine the LSA's LS type.
       RFC2470 3.5.1. Receiving Link State Update packets  */
    if (IS_AREA_STUB (from->ospf6_if->area) && OSPF6_LSA_SCOPE (new->header->type) == OSPF6_SCOPE_AS)
    {
        if (is_debug)
            zlog_debug ("AS-External-LSA (or AS-scope LSA) in stub area, discard");
        ospf6_lsa_delete (new);
        return;
    }

    /* (3) LSA which have reserved scope is discarded
       RFC2470 3.5.1. Receiving Link State Update packets  */
    /* Flooding scope check. LSAs with unknown scope are discarded here.
       Set appropriate LSDB for the LSA */
    if (OSPF6_LSA_SCOPE (new->header->type) == OSPF6_SCOPE_RESERVED)
    {
        ospf6_lsa_delete (new);
        return;
    }
    /*the new->lsdb is from->ospf6_if->new_lsas_list */
    new->lsdb = from->ospf6_if->new_lsas_list;

    /* (4) if MaxAge LSA and if we have no instance, and no neighbor
       is in states Exchange or Loading */
    if (ospf6_is_maxage_lsa_drop (new, from))
    {
        /* log */
        if (is_debug)
            zlog_debug ("Drop MaxAge LSA with direct acknowledgement.");
#if 0
        /* a) Acknowledge back to neighbor (Direct acknowledgement, 13.5) */
        ospf6_lsdb_add (ospf6_lsa_copy (new), from->lsack_list);
        if (from->thread_send_lsack == NULL)
            from->thread_send_lsack = thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
#endif
        /* b) Discard */
        ospf6_lsa_delete (new);
        return;
    }

    /* (5) */
    /* lookup the same database copy in lsdb */
    old = ospf6_lsdb_lookup (new->header->type, new->header->id, new->header->adv_router, new->lsdb);
    if (old)
    {
        ismore_recent = ospf6_lsa_compare (new, old);
        if (ntohl (new->header->seqnum) == ntohl (old->header->seqnum))
        {
            if (is_debug)
                zlog_debug ("Received is duplicated LSA");
            SET_FLAG (new->flag, OSPF6_LSA_DUPLICATE);
        }
    }

    /* if no database copy or received is more recent */
    if (old == NULL || ismore_recent < 0)
    {
        /* in case we have no database copy */
        ismore_recent = -1;

        /* (a) MinLSArrival check */
        if (old)
        {
            struct timeval now, res;
            quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
            timersub (&now, &old->installed, &res);
            if (res.tv_sec < MIN_LS_ARRIVAL)
            {
                if (is_debug)
                    zlog_debug ("LSA can't be updated within MinLSArrival, discard");
                ospf6_lsa_delete (new);
                return;			/* examin next lsa */
            }
        }

        /* (d), installing lsdb, which may cause routing
           table calculation (replacing database copy) */
#ifdef OSPF6_DEBUG
        zlog_debug ("%s()%d ospf6 install lsa to new lsas list, interface:%s", __func__, __LINE__, from->ospf6_if->interface->name);
#endif
        ospf6_install_lsa_for_leaving (new);

    }
    return;
}
u_char drouter_is_self(struct ospf6 *o)
{
    return ntohl(o->drouter_id) == ntohl(o->router_id) ? 1 : 0;
}

static u_char ospf6_drouter_area_eletcion(struct ospf6 *o, u_int32_t adv_router)
{
    if (ntohl (o->drouter_id) > ntohl (adv_router))
    {
#if 0
        if (drouter_is_self(o))
        {
            u_int16_t type;
            u_int32_t id;
            struct ospf6_lsa *lsa;
            //FIXME:purge all this router originated zone lsa
            type = ntohs (OSPF6_LSTYPE_ZONE);
            id = o->self_area_id;
            DG("This router is no longer a drouter, and its zone lsa expired.\n");
            lsa = ospf6_lsdb_lookup (type, id, htonl(0), ospf6->lsdb_zone);
            if (lsa)
            {
                DG("purge zone lsa:%s.\n", lsa->name);
                ospf6_lsa_purge (lsa);
            }
        }
#endif
        o->drouter_id =  adv_router;
    }
    return 0;
}
#if 1//add 2020
static int osfp6_orginate_zone_lsa (struct ospf6_area *oa)
{
    char buffer [OSPF6_MAX_LSASIZE];
    struct ospf6_lsa_header *lsa_header;
    struct ospf6_lsa *new_lsa;
    struct ospf6_zone_lsa *zone_lsa;
    struct ospf6_zone_aaidesc *aaidesc;
    int flood_flag = 0;
    int attached_num = 0;

    memset (buffer, 0, sizeof (buffer));
    lsa_header = (struct ospf6_lsa_header *) buffer;

    zone_lsa = (struct ospf6_zone_lsa *) ((caddr_t)lsa_header + sizeof(struct ospf6_lsa_header));
    zone_lsa->bits = 0;

    //TODO:options
    //bits
    //zone_lsa->options

    aaidesc = (struct ospf6_zone_aaidesc *)((caddr_t) zone_lsa + sizeof (struct ospf6_zone_lsa));

    struct listnode *node;
    struct listnode *nnode;
    struct  pbr_list *plist;

    for (ALL_LIST_ELEMENTS (pbr_list_head, node, nnode, plist))
    {
        /*
        * When one is added and there is only one,
        * or one is reduced, and there are 0 in the neighbor area after the reduction.
        */
        if ((plist->prev_attached_num == 0
                && plist->attached_num == 1)
                || (plist->prev_attached_num == 1
                    && plist->attached_num == 0))
            flood_flag = 1;

        if (plist->attached_num >= 1)
        {
#if 0//for debug
            char buf[64];
            memset(buf, 0x00, sizeof(buf));
            inet_ntop (AF_INET, &plist->neighbor_area_id,
                       buf, sizeof (buf));
            DG("neighbor attached area id is:%s, attached num:%d.\n", buf, plist->attached_num);
#endif
            aaidesc->area_id = plist->neighbor_area_id;
            aaidesc++;
            attached_num ++;
        }
    }

    //if (attached_num > 0)
    {
        /* Fill LSA Header */
        lsa_header->age = 0;
        lsa_header->type = htons (OSPF6_LSTYPE_ZONE);
        //FIXME:
        lsa_header->id = oa->area_id;
        //lsa_header->adv_router = oa->ospf6->drouter_id;
        lsa_header->adv_router = htonl(0);

        lsa_header->seqnum =
            ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
                                 lsa_header->adv_router, oa->ospf6->lsdb_zone);
        lsa_header->length = htons ((caddr_t) aaidesc - (caddr_t) buffer);

        /* LSA checksum */
        ospf6_lsa_checksum (lsa_header);

        /* create LSA */
        new_lsa = ospf6_lsa_create (lsa_header);

        DG("Originate zone lsa length:%u, flood flag:%d.\n", ntohs(lsa_header->length), flood_flag);
        /* Originate */
        ospf6_lsa_originate_zone (new_lsa, oa->ospf6, flood_flag);
        return 0;
    }
#if 0
    u_int16_t type;
    u_int32_t id;
    struct ospf6_lsa *lsa;
    type = ntohs (OSPF6_LSTYPE_ZONE);
    id = oa->ospf6->self_area_id;
    DG(">>>>>>This zone is not adjacent to any zone, and the zone-lsa generated by it is expired.\n");
    lsa = ospf6_lsdb_lookup (type, id, htonl(0), ospf6->lsdb_zone);
    if (lsa)
    {
        DG(">>>>purge zone lsa:%s.\n", lsa->name);
        ospf6_lsa_purge (lsa);
    }
#endif

    return 0;
}
static int ospf6_add_attached_num_to_list(u_int32_t adv_router, u_int32_t neighbor_area_id)
{
    int i, j;
    struct listnode *node;
    struct listnode *nnode;
    struct  pbr_list *plist, *plist_node;
#if 0
    char buf[64];
    memset(buf, 0x00, sizeof(buf));
    inet_ntop (AF_INET, &adv_router,
               buf, sizeof (buf));
    DG("adv router is:%s.\n", buf);
#endif

    for (ALL_LIST_ELEMENTS (pbr_list_head, node, nnode, plist))
    {
        if (plist->neighbor_area_id == neighbor_area_id)
        {
#if 0
            memset(buf, 0x00, sizeof(buf));
            inet_ntop (AF_INET, &plist->neighbor_area_id,
                       buf, sizeof (buf));
            DG("neighbor aread id:%s.\n", buf);
#endif
            for (i = 0, j = -1; i < MAX_ATTACHED_NUM; i++)
            {
                if (plist->pbr_id[i].router_id == 0)
                {
                    if (j == -1)
                        j = i; /*get an empty index*/

                    continue;
                }

                if (plist->pbr_id[i].router_id == adv_router)
                {
                    if (plist->pbr_id[i].attached == 0)
                    {
                        plist->pbr_id[i].attached = 1;
                        plist->prev_attached_num =  plist->attached_num;
                        plist->attached_num++;
#if 0
                        DG("again attached, attached num is:%d.\n", plist->attached_num);
#endif
                    }
                    return plist->attached_num;
                }
            }

            if ((i == MAX_ATTACHED_NUM) && (j != -1))
            {
                plist->pbr_id[j].router_id = adv_router;
                plist->pbr_id[j].attached = 1;
                plist->prev_attached_num =  plist->attached_num;
                plist->attached_num++;
#if 0
                memset(buf, 0x00, sizeof(buf));
                inet_ntop (AF_INET, &plist->pbr_id[j].router_id,
                           buf, sizeof (buf));
                DG("new br attached to area, adv_router:%s, attached num is:%d.\n", buf, plist->attached_num);
#endif
                return plist->attached_num;
            }
        }
    }

    plist_node = (struct  pbr_list *) XMALLOC(MTYPE_OSPF6_OTHER, sizeof(struct pbr_list));
    memset(plist_node, 0x00, sizeof(struct pbr_list));
    for (i = 0; i < MAX_ATTACHED_NUM; i++)
        memset(&plist_node->pbr_id, 0x00, sizeof(struct pbr_id));

    plist_node->prev_attached_num = 0;
    plist_node->attached_num = 1;
    DG("This is a new area, add it to list, attached num is:%d.\n", plist_node->attached_num);
    plist_node->neighbor_area_id = neighbor_area_id;
    plist_node->pbr_id[0].attached = 1;
    plist_node->pbr_id[0].router_id = adv_router;
    listnode_add (pbr_list_head, plist_node);

    return 1;
}
/*Considering that a border satellite may connect two areas,
* when the router lsa with B bit is sent again,
* it may bring the connection information of only one area.
* Then use this satellite as the traversal condition to find its adjacent area. Adjacent area's attached num minus 1
* */

/*
 *@param 1:advertisement router
 *@param 2:attached neighbor aread id
 *@function:iterate over all connected area linked lists. If it is a newly added connected area(neighbor_area_id), don't consider it. Otherwise, subtract this advertising router's connection from the connected area linked list
 * */
static int ospf6_maybe_del_attached_num_from_list(u_int32_t adv_router, u_int32_t neighbor_area_id)
{
    int i;
    struct listnode *node;
    struct listnode *nnode;
    struct  pbr_list *plist;

    for (ALL_LIST_ELEMENTS (pbr_list_head, node, nnode, plist))
    {
        if (plist->attached_num == 0
                || ((plist->attached_num > 0) && (plist->neighbor_area_id == neighbor_area_id)))
            continue;

        for (i = 0; i < MAX_ATTACHED_NUM; i++)
        {
            if (plist->pbr_id[i].router_id == 0)
                continue;

            if (plist->pbr_id[i].router_id == adv_router)
            {
                if (plist->pbr_id[i].attached == 1)
                {
                    plist->pbr_id[i].attached = 0;
                    plist->prev_attached_num =  plist->attached_num;
                    plist->attached_num--;
#if 0
                    DG(">>>>>del attached, now attached num is:%d.\n", plist->attached_num);
#endif
                }
                return plist->attached_num;
            }
        }
    }
    return 0;
}
static int ospf6_del_attached_num_from_list(u_int32_t adv_router)
{
    int i;
    struct listnode *node;
    struct listnode *nnode;
    struct  pbr_list *plist;

    for (ALL_LIST_ELEMENTS (pbr_list_head, node, nnode, plist))
    {
        if (plist->attached_num == 0)
            continue;

        for (i = 0; i < MAX_ATTACHED_NUM; i++)
        {
            if (plist->pbr_id[i].router_id == 0)
                continue;

            if (plist->pbr_id[i].router_id == adv_router)
            {
                if (plist->pbr_id[i].attached == 1)
                {
                    plist->pbr_id[i].attached = 0;
                    plist->prev_attached_num =  plist->attached_num;
                    plist->attached_num--;
#if 0
                    DG(">>>>>del attached, now attached num is:%d.\n", plist->attached_num);
#endif
                }
                return plist->attached_num;
            }
        }
    }
    return 0;
}

int ospf6_process_pbr_router_lsa (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
    char *start, *end, *current;
    struct ospf6_router_lsa *router_lsa;
    struct ospf6_router_lsdesc *lsdesc;
    int nai_num = 0; /*neighbor aread id num*/
    u_int32_t neighbor_area_id = 0;

    router_lsa = (struct ospf6_router_lsa *)
                 ((char *) lsa->header + sizeof (struct ospf6_lsa_header));

    if (!(router_lsa->bits & OSPF6_ROUTER_BIT_B))
        return 0;

    start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
    end = (char *) lsa->header + ntohs (lsa->header->length);
    for (current = start; current + sizeof (struct ospf6_router_lsdesc) <= end;
            current += sizeof (struct ospf6_router_lsdesc))
    {
        lsdesc = (struct ospf6_router_lsdesc *) current;

        if (lsdesc->type == OSPF6_ROUTER_LSDESC_PBRP2P_LINK)
        {
            ospf6_add_attached_num_to_list(lsa->header->adv_router, lsdesc->neighbor_interface_id);
            neighbor_area_id = lsdesc->neighbor_interface_id;
            nai_num ++;
        }
    }
    DG("nai num:%d.\n", nai_num);
    if (nai_num == 1) /*Filter out just added neighbor aread id*/
        ospf6_maybe_del_attached_num_from_list(lsa->header->adv_router, neighbor_area_id);
    else if (nai_num == 0) /*This is a router lsa with the B flag set, but there is no attached aread id*/
        ospf6_del_attached_num_from_list(lsa->header->adv_router);

    /*Iterate over all the zone connection lists. If the number of connections in a zone is 1 or 0, zone-lsa is generated and flooded.*/
    if (drouter_is_self(oa->ospf6))
        osfp6_orginate_zone_lsa(oa);

    return 0;
}
static void ospf6_originate_pbr_prefix(struct ospf6_interface *oi, struct in6_addr *linklocal_addr)
{
    char bit8;
    struct prefix prefix;

    memset(&prefix, 0x00, sizeof(prefix));

    bit8 = (oi->neighbor_area_id >> 24) & 0xFF;
    DG("high bit8:%d.\n", bit8);
    memcpy(&prefix, &g_global_prefix, sizeof(struct prefix));
    prefix.u.prefix6.s6_addr[(prefix.prefixlen)/8] = bit8;
    prefix.prefixlen += 8;

    memcpy(&oi->neighbor_prefix, &prefix, sizeof(struct prefix));
    memcpy(&oi->neighbor_linklocal_addr, linklocal_addr, sizeof(struct in6_addr));
    return;
}
/*The partition border router generates a route prefixed with the global_prefix of the adjacent area plus the area ID, and the next hop is the fe80 address of the interface of the adjacent area, and advertises it to its own area.*/
static int ospf6_originate_route_for_pbr_neighbor(struct ospf6_lsa *lsa, struct ospf6_interface *oi)
{
    struct ospf6_route *route;

    struct ospf6_link_lsa *link_lsa;
    link_lsa = (struct ospf6_link_lsa *)
               ((caddr_t) lsa->header + sizeof (struct ospf6_lsa_header));
#if 0
    char buf[64];
    memset(buf, 0x00, sizeof(buf));
    inet_ntop (AF_INET6, &link_lsa->linklocal_addr, buf, sizeof (buf));
    DG("LinkLocal Address: %s\n", buf);
#endif

    ospf6_originate_pbr_prefix(oi, &link_lsa->linklocal_addr);

    route = ospf6_route_create ();
    memcpy (&route->prefix, &oi->neighbor_prefix, sizeof (struct prefix));
    apply_mask (&route->prefix);
    route->type = OSPF6_DEST_TYPE_NETWORK;
    route->path.area_id = oi->area->area_id;
    route->path.type = OSPF6_PATH_TYPE_INTRA;
    route->path.cost = oi->cost;

    route->nexthop[0].ifindex = oi->interface->ifindex;
    memcpy(&route->nexthop[0].address, &link_lsa->linklocal_addr, sizeof(struct in6_addr));
    ospf6_route_add (route, oi->route_connected);

    OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (oi->area);
    return 0;
}
static int ospf6_process_pbr_link_lsa(struct ospf6_lsa *lsa , struct ospf6_area *oa)
{
    struct listnode *i, *j;
    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    for (ALL_LIST_ELEMENTS_RO (oa->if_list, i, oi))
    {
        if (oi->type != OSPF_IFTYPE_POINTOPOINT)
            continue;

        for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on))
        {
            if ((on->neighbor_pbr_flag == 1) && (on->router_id == lsa->header->adv_router))
            {
                ospf6_originate_route_for_pbr_neighbor(lsa, oi);
                return 0;
            }
        }
    }
    return 0;
}
#endif

/* RFC2328 section 13 The Flooding Procedure */
void
ospf6_receive_lsa (struct ospf6_neighbor *from,
                   struct ospf6_lsa_header *lsa_header)
{
    struct ospf6_lsa *new = NULL, *old = NULL, *rem = NULL;
    int ismore_recent;
    int is_debug = 0;

    ismore_recent = 1;
    assert (from);

    /* make lsa structure for received lsa */
    new = ospf6_lsa_create (lsa_header);

    if (IS_OSPF6_DEBUG_FLOODING ||
            IS_OSPF6_DEBUG_FLOOD_TYPE (new->header->type))
    {
        is_debug++;
        zlog_debug ("LSA Receive from %s", from->name);
        ospf6_lsa_header_print (new);
    }

    /* (1) LSA Checksum */
    if (! ospf6_lsa_checksum_valid (new->header))
    {
        if (is_debug)
            zlog_debug ("Wrong LSA Checksum, discard");
        ospf6_lsa_delete (new);
        return;
    }

    /* (2) Examine the LSA's LS type.
       RFC2470 3.5.1. Receiving Link State Update packets  */
    if (IS_AREA_STUB (from->ospf6_if->area) &&
            OSPF6_LSA_SCOPE (new->header->type) == OSPF6_SCOPE_AS)
    {
        if (is_debug)
            zlog_debug ("AS-External-LSA (or AS-scope LSA) in stub area, discard");
        ospf6_lsa_delete (new);
        return;
    }

    /* (3) LSA which have reserved scope is discarded
       RFC2470 3.5.1. Receiving Link State Update packets  */
    /* Flooding scope check. LSAs with unknown scope are discarded here.
       Set appropriate LSDB for the LSA */
    switch (OSPF6_LSA_SCOPE (new->header->type))
    {
    case OSPF6_SCOPE_LINKLOCAL:
        new->lsdb = from->ospf6_if->lsdb;
        break;
    case OSPF6_SCOPE_AREA:
        new->lsdb = from->ospf6_if->area->lsdb;
        break;
    case OSPF6_SCOPE_AS:
#if 1 //add 2020
        if (ntohs(new->header->type) == OSPF6_LSTYPE_ZONE)
        {
            //DG("receive zone lsa, age:%d.\n", ospf6_lsa_age_current (new));
            new->lsdb = from->ospf6_if->area->ospf6->lsdb_zone;
        }
        else
#endif
            new->lsdb = from->ospf6_if->area->ospf6->lsdb;
        break;
    default:
        if (is_debug)
            zlog_debug ("LSA has reserved scope, discard");
        ospf6_lsa_delete (new);
        return;
    }

    /* (4) if MaxAge LSA and if we have no instance, and no neighbor
           is in states Exchange or Loading */
    if (ospf6_is_maxage_lsa_drop (new, from))
    {
        /* log */
        if (is_debug)
            zlog_debug ("Drop MaxAge LSA with direct acknowledgement.");

        /* a) Acknowledge back to neighbor (Direct acknowledgement, 13.5) */
        ospf6_lsdb_add (ospf6_lsa_copy (new), from->lsack_list);
        if (from->thread_send_lsack == NULL)
            from->thread_send_lsack =
                thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);

        /* b) Discard */
        ospf6_lsa_delete (new);
        return;
    }

#if 0//add 2020.04
    if (drouter_is_self(from->ospf6_if->area->ospf6)
            && (ntohs(new->header->type) == OSPF6_LSTYPE_ZONE)
            && OSPF6_LSA_IS_MAXAGE (new))
    {
        if (from->ospf6_if->area->ospf6->self_area_id == new->header->id )
        {
            /* a) Acknowledge back to neighbor (Direct acknowledgement, 13.5) */
            ospf6_lsdb_add (ospf6_lsa_copy (new), from->lsack_list);
            if (from->thread_send_lsack == NULL)
                from->thread_send_lsack =
                    thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);

            /* b) again flood zone-lsa*/
            /* find previous LSA */

            struct ospf6_lsa *zone_lsa;
            zone_lsa = ospf6_lsdb_lookup (new->header->type, new->header->id,
                                          new->header->adv_router, new->lsdb);

            if (zone_lsa)
            {
                DG("will flood zone lsa again, age:%d.\n", ospf6_lsa_age_current (new));
                ospf6_flood (NULL, zone_lsa);
            }

            /* c) Discard */
            ospf6_lsa_delete (new);
            return;
        }
    }
#endif

    /* (5) */
    /* lookup the same database copy in lsdb */
    old = ospf6_lsdb_lookup (new->header->type, new->header->id,
                             new->header->adv_router, new->lsdb);
    if (old)
    {
        ismore_recent = ospf6_lsa_compare (new, old);
        if (ntohl (new->header->seqnum) == ntohl (old->header->seqnum))
        {
            if (is_debug)
                zlog_debug ("Received is duplicated LSA");
            SET_FLAG (new->flag, OSPF6_LSA_DUPLICATE);
        }
    }

    /* if no database copy or received is more recent */
    if (old == NULL || ismore_recent < 0)
    {

        //DG("recent:%d.\n", ismore_recent);
        /* in case we have no database copy */
        ismore_recent = -1;

        /* (a) MinLSArrival check */
        if (old)
        {
            struct timeval now, res;
            quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
            timersub (&now, &old->installed, &res);
            if (res.tv_sec < OSPF_MIN_LS_ARRIVAL)
            {
                if (is_debug)
                    zlog_debug ("LSA can't be updated within MinLSArrival, discard");
                ospf6_lsa_delete (new);
                return;   /* examin next lsa */
            }
        }

        quagga_gettime (QUAGGA_CLK_MONOTONIC, &new->received);

        if (is_debug)
            zlog_debug ("Install, Flood, Possibly acknowledge the received LSA");

        /* Remove older copies of this LSA from retx lists */
        if (old)
        {
            //DG("find old lsa, will flood clear:%s, age:%d.\n", old->name, ntohs (old->header->age));
            ospf6_flood_clear (old);
        }

        /* (b) immediately flood and (c) remove from all retrans-list */
        /* Prevent self-originated LSA to be flooded. this is to make
        reoriginated instance of the LSA not to be rejected by other routers
        due to MinLSArrival. */
        if (new->header->adv_router != from->ospf6_if->area->ospf6->router_id)
        {
            //DG("will call ospf6_flood clear, name:%s.\n", new->name);
            ospf6_flood (from, new);

            //add 2020
            if ((new->header->type == htons (OSPF6_LSTYPE_ROUTER) || new->header->type == htons (OSPF6_LSTYPE_NETWORK))
                    && (ntohs (new->header->age) < OSPF_LSA_MAXAGE))
                ospf6_drouter_area_eletcion(from->ospf6_if->area->ospf6, new->header->adv_router);

            /*If you are a partition border router, you will be processed when you receive a link lsa that you did not announce yourself.*/
            if ((ospf6_is_router_pbr(from->ospf6_if->area->ospf6)) && (new->header->type == htons(OSPF6_LSTYPE_LINK)))
                ospf6_process_pbr_link_lsa(new, from->ospf6_if->area);
        }
        /* (d), installing lsdb, which may cause routing
                table calculation (replacing database copy) */
        //DG("will call ospf6_install_lsa, new name:%s, age:%d.\n", new->name, ntohs (new->header->age));
        ospf6_install_lsa (new);
#if 1
        //add 2020
        if (new->header->type == htons (OSPF6_LSTYPE_ROUTER))
            ospf6_process_pbr_router_lsa(new, from->ospf6_if->area);
#endif
        /* (e) possibly acknowledge */
        ospf6_acknowledge_lsa (new, ismore_recent, from);

        /* (f) Self Originated LSA, section 13.4 */
        if (new->header->adv_router == from->ospf6_if->area->ospf6->router_id)
        {
            /* Self-originated LSA (newer than ours) is received from
               another router. We have to make a new instance of the LSA
               or have to flush this LSA. */
            if (is_debug)
            {
                zlog_debug ("Newer instance of the self-originated LSA");
                zlog_debug ("Schedule reorigination");
            }
            new->refresh = thread_add_event (master, ospf6_lsa_refresh, new, 0);
        }
        return;
    }

    /* (6) if there is instance on sending neighbor's request list */
    if (ospf6_lsdb_lookup (new->header->type, new->header->id,
                           new->header->adv_router, from->request_list))
    {
        /* if no database copy, should go above state (5) */
        assert (old);

        if (is_debug)
        {
            zlog_debug ("Received is not newer, on the neighbor's request-list");
            zlog_debug ("BadLSReq, discard the received LSA");
        }

        /* BadLSReq */
        thread_add_event (master, bad_lsreq, from, 0);

        ospf6_lsa_delete (new);
        return;
    }

    /* (7) if neither one is more recent */
    if (ismore_recent == 0)
    {
        if (is_debug)
            zlog_debug ("The same instance as database copy (neither recent)");

        /* (a) if on retrans-list, Treat this LSA as an Ack: Implied Ack */
        rem = ospf6_lsdb_lookup (new->header->type, new->header->id,
                                 new->header->adv_router, from->retrans_list);
        if (rem)
        {
            if (is_debug)
            {
                zlog_debug ("It is on the neighbor's retrans-list.");
                zlog_debug ("Treat as an Implied acknowledgement");
            }
            SET_FLAG (new->flag, OSPF6_LSA_IMPLIEDACK);
            ospf6_decrement_retrans_count (rem);
            ospf6_lsdb_remove (rem, from->retrans_list);
        }

        if (is_debug)
            zlog_debug ("Possibly acknowledge and then discard");

        /* (b) possibly acknowledge */
        ospf6_acknowledge_lsa (new, ismore_recent, from);

        ospf6_lsa_delete (new);
        return;
    }

    /* (8) previous database copy is more recent */
    {
        assert (old);

        /* If database copy is in 'Seqnumber Wrapping',
           simply discard the received LSA */
        if (OSPF6_LSA_IS_MAXAGE (old) &&
                old->header->seqnum == htonl (OSPF_MAX_SEQUENCE_NUMBER))
        {
            if (is_debug)
            {
                zlog_debug ("The LSA is in Seqnumber Wrapping");
                zlog_debug ("MaxAge & MaxSeqNum, discard");
            }
            ospf6_lsa_delete (new);
            return;
        }

        /* Otherwise, Send database copy of this LSA to this neighbor */
        {
            if (is_debug)
            {
                zlog_debug ("Database copy is more recent.");
                zlog_debug ("Send back directly and then discard");
            }

            /* XXX, MinLSArrival check !? RFC 2328 13 (8) */

            ospf6_lsdb_add (ospf6_lsa_copy (old), from->lsupdate_list);
            if (from->thread_send_lsupdate == NULL)
            {
                from->thread_send_lsupdate =
                    thread_add_event (master, ospf6_lsupdate_send_neighbor, from, 0);
            }
            ospf6_lsa_delete (new);
            return;
        }
        return;
    }
}


DEFUN (debug_ospf6_flooding,
       debug_ospf6_flooding_cmd,
       "debug ospf6 flooding",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
    OSPF6_DEBUG_FLOODING_ON ();
    return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_flooding,
       no_debug_ospf6_flooding_cmd,
       "no debug ospf6 flooding",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
    OSPF6_DEBUG_FLOODING_OFF ();
    return CMD_SUCCESS;
}

int
config_write_ospf6_debug_flood (struct vty *vty)
{
    if (IS_OSPF6_DEBUG_FLOODING)
        vty_out (vty, "debug ospf6 flooding%s", VNL);
    return 0;
}

void
install_element_ospf6_debug_flood (void)
{
    install_element (ENABLE_NODE, &debug_ospf6_flooding_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_flooding_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_flooding_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_flooding_cmd);
}
