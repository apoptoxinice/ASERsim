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
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_flood.h"
#include "ospf6d.h"


#define INIT_CONNECTION_PERIOD  365*24*60*60
#define INIT_CIRCLE_PERIOD 365*24*60*60

unsigned char conf_debug_ospf6_neighbor = 0;
//add here for OSPF+
const char *ospf6_neighbor_state_str[] = { "None", "Down", "Attempt", "Init", "Twoway", "ExStart", "ExChange",
                                           "Loading", "Full", "Leaving", NULL
                                         };
int
ospf6_neighbor_cmp (void *va, void *vb)
{
    struct ospf6_neighbor *ona = (struct ospf6_neighbor *) va;
    struct ospf6_neighbor *onb = (struct ospf6_neighbor *) vb;
    return (ntohl (ona->router_id) < ntohl (onb->router_id) ? -1 : 1);
}

struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t router_id,
                       struct ospf6_interface *oi)
{
    struct listnode *n;
    struct ospf6_neighbor *on;

    for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, n, on))
        if (on->router_id == router_id)
            return on;

    return (struct ospf6_neighbor *) NULL;
}

/* create ospf6_neighbor */
struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t router_id, struct ospf6_interface *oi)
{
    struct ospf6_neighbor *on;
    char buf[16];

    on = (struct ospf6_neighbor *)
         XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct ospf6_neighbor));
    if (on == NULL)
    {
        zlog_warn ("neighbor: malloc failed");
        return NULL;
    }

    memset (on, 0, sizeof (struct ospf6_neighbor));
    inet_ntop (AF_INET, &router_id, buf, sizeof (buf));
    snprintf (on->name, sizeof (on->name), "%s%%%s",
              buf, oi->interface->name);
    on->ospf6_if = oi;
    on->state = OSPF6_NEIGHBOR_DOWN;
    quagga_gettime (QUAGGA_CLK_MONOTONIC, &on->last_changed);
    on->router_id = router_id;

    on->summary_list = ospf6_lsdb_create (on);
    on->request_list = ospf6_lsdb_create (on);
    on->retrans_list = ospf6_lsdb_create (on);

    on->dbdesc_list = ospf6_lsdb_create (on);
    on->lsreq_list = ospf6_lsdb_create (on);
    on->lsupdate_list = ospf6_lsdb_create (on);
    on->lsack_list = ospf6_lsdb_create (on);

    listnode_add_sort (oi->neighbor_list, on);
    return on;
}

void
ospf6_neighbor_delete (struct ospf6_neighbor *on)
{
    struct ospf6_lsa *lsa;

    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }

    ospf6_lsdb_remove_all (on->dbdesc_list);
    ospf6_lsdb_remove_all (on->lsreq_list);
    ospf6_lsdb_remove_all (on->lsupdate_list);
    ospf6_lsdb_remove_all (on->lsack_list);

    ospf6_lsdb_delete (on->summary_list);
    ospf6_lsdb_delete (on->request_list);
    ospf6_lsdb_delete (on->retrans_list);

    ospf6_lsdb_delete (on->dbdesc_list);
    ospf6_lsdb_delete (on->lsreq_list);
    ospf6_lsdb_delete (on->lsupdate_list);
    ospf6_lsdb_delete (on->lsack_list);

    THREAD_OFF (on->inactivity_timer);
#ifdef OSPF6_DEBUG
    //add debug
    zlog_debug("%s()%d thread off connection_period_timer, circle_period_timer", __func__, __LINE__);
#endif
    //add
    THREAD_OFF (on->connection_period_timer);
    THREAD_OFF (on->circle_period_timer);

    THREAD_OFF (on->thread_send_dbdesc);
    THREAD_OFF (on->thread_send_lsreq);
    THREAD_OFF (on->thread_send_lsupdate);
    THREAD_OFF (on->thread_send_lsack);

    XFREE (MTYPE_OSPF6_NEIGHBOR, on);
}

static void
ospf6_neighbor_delete_for_leaving (struct ospf6_neighbor *on)
{
    struct ospf6_lsa *lsa;

    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }
#if 0
    ospf6_lsdb_delete (on->summary_list);
    ospf6_lsdb_delete (on->request_list);
    ospf6_lsdb_delete (on->retrans_list);
#endif
}

static void
ospf6_neighbor_state_change (u_char next_state, struct ospf6_neighbor *on)
{
    u_char prev_state;

    prev_state = on->state;
    on->state = next_state;

    if (prev_state == next_state)
        return;

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &on->last_changed);

    /* log */
    if (IS_OSPF6_DEBUG_NEIGHBOR (STATE))
    {
        zlog_debug ("Neighbor state change %s: [%s]->[%s]", on->name,
                    ospf6_neighbor_state_str[prev_state],
                    ospf6_neighbor_state_str[next_state]);
    }

    //if ((prev_state == OSPF6_NEIGHBOR_FULL) && (next_state == OSPF6_NEIGHBOR_LEAVING))
    //	return;


    if ((prev_state == OSPF6_NEIGHBOR_FULL || next_state == OSPF6_NEIGHBOR_FULL) || (prev_state == OSPF6_NEIGHBOR_LEAVING && next_state == OSPF6_NEIGHBOR_DOWN))
    {
        if (next_state == OSPF6_NEIGHBOR_LEAVING)
            OSPF6_ROUTER_LSA_SCHEDULE_FOR_LEAVING (on->ospf6_if->area);
        else
        {
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
            if (on->ospf6_if->state == OSPF6_INTERFACE_DR)
            {
                OSPF6_NETWORK_LSA_SCHEDULE (on->ospf6_if);
                OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (on->ospf6_if);
            }
            OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (on->ospf6_if->area);
        }
    }

    if ((prev_state == OSPF6_NEIGHBOR_EXCHANGE ||
            prev_state == OSPF6_NEIGHBOR_LOADING) &&
            (next_state != OSPF6_NEIGHBOR_EXCHANGE &&
             next_state != OSPF6_NEIGHBOR_LOADING))
        ospf6_maxage_remove (on->ospf6_if->area->ospf6);
}

/* RFC2328 section 10.4 */
static int
need_adjacency (struct ospf6_neighbor *on)
{
    if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT ||
            on->ospf6_if->state == OSPF6_INTERFACE_DR ||
            on->ospf6_if->state == OSPF6_INTERFACE_BDR)
        return 1;

    if (on->ospf6_if->drouter == on->router_id ||
            on->ospf6_if->bdrouter == on->router_id)
        return 1;

    return 0;
}
static int ospf6_fill_summary_list(struct ospf6_neighbor *on)
{
    struct ospf6_lsa *lsa;
    if (on->state != OSPF6_NEIGHBOR_LEAVING)
        return 0;

    for (lsa = ospf6_lsdb_head (on->ospf6_if->new_lsas_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_print_lsa_header_type(lsa->header);

        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

    return 0;
}

#if 0
static int ospf6_fill_update_list(struct ospf6_neighbor *on)
{
    struct ospf6_lsa *lsa;
    if (on->state != OSPF6_NEIGHBOR_LEAVING)
        return 0;

    for (lsa = ospf6_lsdb_head (on->ospf6_if->new_lsas_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->lsupdate_list);
        //ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

    return 0;
}
#endif
static float get_seconds_has_gone_today(void)
{
    time_t now = time(NULL);
    struct tm today = *localtime(&now);
    float seconds;
    today.tm_hour = 0;
    today.tm_min = 0;
    today.tm_sec = 0;

    seconds = difftime(now,mktime(&today));


    return seconds;
}
int
hello_received (struct thread *thread)
{
    struct ospf6_neighbor *on;
    float seconds_gone;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *HelloReceived*", on->name);

    /* reset Inactivity Timer */
    THREAD_OFF (on->inactivity_timer);
    on->inactivity_timer = thread_add_timer (master, inactivity_timer, on, on->ospf6_if->dead_interval);
    seconds_gone = get_seconds_has_gone_today ();
#ifdef OSPF6_DEBUG
    printf(" %.f secondes has gone today, on->first_hello_state is:%d\n", seconds_gone, on->first_hello_state);
    //add for debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    if (on->state == OSPF6_NEIGHBOR_LEAVING)
    {
        on->connection_period_timer_state = 0;
    }
#ifdef OSPF6_DEBUG
    zlog_debug ("on->connection_period_timer_state:%d, on->first_hello_state:%d,ifname:%s, neighbor ipv6 address:%s", on->connection_period_timer_state, on->first_hello_state, on->ospf6_if->interface->name, ipv6_string);
#endif

    /*when connection period state is 0, get the statellite info from list, and add connection period timer */
    if (on->connection_period_timer_state == 0)
    {
#ifdef OSPF6_DEBUG
        zlog_debug ("recv hello packet, add connection period timer, ifname:%s, neighbor ipv6 address:%s", on->ospf6_if->interface->name, ipv6_string);
#endif
        stl_link_list p;
        p = stl_link_head;
        while (p)
        {
            if (!memcmp (&p->stl_msg_all.neighbor_ipv6_address, &on->linklocal_addr, sizeof (struct in6_addr)))
            {
                zlog_debug("***in list find neigh, connection period is:%f circle_period:%f", p->stl_msg_all.connection_period, p->stl_msg_all.circle_period);
                if ((p->stl_msg_all.connection_period == 0) && (p->stl_msg_all.start_time == 0) && (p->stl_msg_all.end_time == 0))
                {
#ifdef OSPF6_DEBUG
                    zlog_debug ("neighbor:%s start_time, end_time, connection_period is all zero, don't update", ipv6_string);
#endif
                    return 0;
                }
                else
                {
                    if ((seconds_gone < p->stl_msg_all.start_time) || (seconds_gone > p->stl_msg_all.end_time))
                    {
#ifdef OSPF6_DEBUG
                        zlog_debug ("neighbor:%s start time big than now time or end time less then now time, start time:%f end time:%f seconds has gone:%f", ipv6_string, p->stl_msg_all.start_time,
                                    p->stl_msg_all.end_time, seconds_gone);
#endif
                        return 0;
                    }
                    /*add */
                    /*
                    *chek the first_hello_state
                    * if first_hello_state is 0, fill the first_hello_time
                    * then flip it
                    * */
                    if (on->first_hello_state == 0)
                    {
                        on->first_hello_time = seconds_gone;
                        on->first_hello_state = 1;
                    }

                    if (p->stl_msg_all.connection_period < (seconds_gone - on->first_hello_time))
                    {
#ifdef OSPF6_DEBUG
                        zlog_debug ("neighbor:%s connection period less then used time", ipv6_string);
#endif
                        return 0;
                    }

                    on->connection_period = p->stl_msg_all.connection_period - (seconds_gone - on->first_hello_time);
                    on->circle_period = p->stl_msg_all.circle_period;
#ifdef OSPF6_DEBUG
                    zlog_debug ("neighbor:%s connection period is:%f circle_period:%f", ipv6_string, on->connection_period, on->circle_period);
#endif
                    break;
                }
            }
            p = p->next;
        }
        if (p == NULL)
        {
#ifdef OSPF6_DEBUG
            zlog_debug ("In list, don't find the neighbor:%s", ipv6_string);
#endif
            on->connection_period = INIT_CONNECTION_PERIOD;
            on->circle_period = INIT_CIRCLE_PERIOD;

            //return 0;
        }

#ifdef OSPF6_DEBUG
        zlog_debug ("add connection period timer success, connection timer is:%f, neighbor ipv6_address:%s\n", on->connection_period, ipv6_string);
#endif
        on->connection_period_timer = thread_add_timer (master, connection_period_timer, on, on->connection_period);

        on->connection_period_timer_state = 1;
    }

#if 1
    //add for OSPF+
    /*a) judge the neighbor state is in the leaving */
    if (on->state == OSPF6_NEIGHBOR_LEAVING)
    {
        /*del circle period timer */
        THREAD_OFF (on->circle_period_timer);
        /*reset the connection period timer state */
        //on->connection_period_timer_state = 0;


        /*judge the new lsas list is null?*/
        if (on->ospf6_if->new_lsas_list->count)
        {
            ospf6_fill_summary_list(on);
            ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on);

#ifdef OSPF6_DEBUG
            zlog_debug("new lsas list is not null,  ospf6 neighbor state change to EXCHANGE, now is:%s, ipv6 addr:%s", ospf6_neighbor_state_str[on->state], ipv6_string);
#endif
        }
        else
        {
            //ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on);
            ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on);
            //ospf6_lsdb_remove_all (on->summary_list);
#ifdef OSPF6_DEBUG
            zlog_debug("new lsas list is null,  ospf6 neighbor state change to EXCHANGE, now is:%s, ipv6 addr:%s", ospf6_neighbor_state_str[on->state], ipv6_string);
#endif
        }

        /*send new lsas list to neighbor*/
        THREAD_OFF (on->thread_send_dbdesc);
        on->thread_send_dbdesc = thread_add_event (master, ospf6_dbdesc_send_new_lsas_list, on, 0);
#if 1
        THREAD_OFF (on->thread_send_lsupdate);
        on->thread_send_lsupdate = thread_add_event (master, ospf6_lsupdate_send_neighbor_for_new_lsas, on, 0);
#endif

        if (on->ospf6_if->reference_count > 0)
        {
#ifdef OSPF6_DEBUG
            zlog_debug("%s() reference count --", __func__);
#endif
            on->ospf6_if->reference_count--;
            if (on->ospf6_if->reference_count == 0)
            {
                /*if the new lsas list is not null, empty it */
                if (on->ospf6_if->new_lsas_list->count)
                    ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
            }
        }
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d summary_list_count:%d", __func__, __LINE__, on->summary_list->count);
#endif

        /*leaving to exchamge state flip to 1 */
        on->leaving_exchange_state = 1;
    }
    else if (on->state ==OSPF6_NEIGHBOR_INIT)
    {
        if (on->ospf6_if->reference_count == 0)
        {
            /*if the new lsas list is not null, empty it */
            if (on->ospf6_if->new_lsas_list->count)
                ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
        }
        if (on->ospf6_if->area->lsdb_bak->count)
            ospf6_lsdb_remove_all (on->ospf6_if->area->lsdb_bak);
    }

#endif
    if (on->state <= OSPF6_NEIGHBOR_DOWN)
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d ospf6 neighbor state change to INIT, neighbor ipv6 address:%s", __func__, __LINE__,  ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on);
    }

    return 0;
}

int
twoway_received (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state > OSPF6_NEIGHBOR_INIT)
        return 0;

#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *2Way-Received*", on->name);

    thread_add_event (master, neighbor_change, on->ospf6_if, 0);

    if (! need_adjacency (on))
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d ospf6 neighbor state change to TWOWAY, neighbor ipv6 address:%s", __func__, __LINE__, ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
        return 0;
    }

#ifdef OSPF6_DEBUG
    zlog_debug("%s()%d ospf6 neighbor state change to EXSTART, neighbor ipv6 address:%s", __func__, __LINE__, ipv6_string);
#endif
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

    THREAD_OFF (on->thread_send_dbdesc);
    on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);

    return 0;
}

int
negotiation_done (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state != OSPF6_NEIGHBOR_EXSTART)
        return 0;


#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *NegotiationDone*", on->name);

    /* clear ls-list */
    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }

    /* Interface scoped LSAs */
    for (lsa = ospf6_lsdb_head (on->ospf6_if->lsdb); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
            ospf6_increment_retrans_count (lsa);
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
        else
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

    /* Area scoped LSAs */
    for (lsa = ospf6_lsdb_head (on->ospf6_if->area->lsdb); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
            ospf6_increment_retrans_count (lsa);
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
        else
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

    /* AS scoped LSAs */
    for (lsa = ospf6_lsdb_head (on->ospf6_if->area->ospf6->lsdb); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        if (OSPF6_LSA_IS_MAXAGE (lsa))
        {
            ospf6_increment_retrans_count (lsa);
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
        }
        else
            ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->summary_list);
    }

    UNSET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

#ifdef OSPF6_DEBUG
    zlog_debug("%s()ospf6 change state to EXCHANGE, ifname:%s neighbor ipv6 address:%s", __func__, on->ospf6_if->interface->name, ipv6_string);
#endif
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on);

#ifdef OSPF6_DEBUG
    zlog_debug("ospf6 neighbor state must be EXCHANGE, now is:%s", ospf6_neighbor_state_str[on->state]);
#endif

    return 0;
}

int
exchange_done (struct thread *thread)
{
    struct ospf6_neighbor *on;
    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state != OSPF6_NEIGHBOR_EXCHANGE)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *ExchangeDone*", on->name);

    THREAD_OFF (on->thread_send_dbdesc);
    ospf6_lsdb_remove_all (on->dbdesc_list);

#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    /* XXX
      thread_add_timer (master, ospf6_neighbor_last_dbdesc_release, on,
                        on->ospf6_if->dead_interval);
    */

    if (on->request_list->count == 0)
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()ospf6 neighbor state change to FULL, neighbor ipv6 address:%s", __func__, ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on);

    }
    else
    {

#ifdef OSPF6_DEBUG
        zlog_debug("%s()ospf6 neighbor state change to LOADING, neighbor ipv6 address:%s", __func__, ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LOADING, on);
    }

#if 1
    //add for OSPF+
    if (on->leaving_exchange_state == 1)
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()This sate is Leaving---->Exchange---->Full/Loading, neighbor ipv6 address:%s", __func__, ipv6_string);
#endif
#if 1
        /*a) restore oa->lsdb_bak to oa->lsdb*/
        u_int16_t type = ntohs (OSPF6_LSTYPE_ROUTER);
        u_int32_t router = on->ospf6_if->area->ospf6->router_id;
        struct ospf6_lsa *lsa;
        struct ospf6_lsa *lsa_bak;
        for (lsa = ospf6_lsdb_type_router_head (type, router, on->ospf6_if->area->lsdb_bak); lsa;
                lsa = ospf6_lsdb_type_router_next (type, router, lsa))
        {
#ifdef OSPF6_DEBUG
            zlog_debug("%s()%d  lsa->name:%s", __func__, __LINE__, lsa->name);
#endif
            lsa_bak = ospf6_lsa_copy(lsa);
            lsa_bak->lsdb = on->ospf6_if->area->lsdb;
            ospf6_install_lsa (lsa_bak);

        }
        /*b) if the lsdb_bak list is not null, empty it */
        if (on->ospf6_if->area->lsdb_bak->count)
            ospf6_lsdb_remove_all (on->ospf6_if->area->lsdb_bak);

#endif
        on->leaving_exchange_state = 0;

        if (on->ospf6_if->reference_count > 0)
        {
#ifdef OSPF6_DEBUG
            zlog_debug("%s()reference count --", __func__);
#endif
            on->ospf6_if->reference_count--;
            if (on->ospf6_if->reference_count == 0)
            {
                /*if the new lsas list is not null, empty it */
                if (on->ospf6_if->new_lsas_list->count)
                    ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
            }
        }
    }
#endif
    return 0;
}

int
loading_done (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    if (on->state != OSPF6_NEIGHBOR_LOADING)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *LoadingDone*", on->name);

    assert (on->request_list->count == 0);

#ifdef OSPF6_DEBUG
    zlog_debug("%s()%d ospf6 neighbor state change to FULL, neighbor ipv6 address:%s",  __func__, __LINE__,ipv6_string);
#endif
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on);

    return 0;
}

int
adj_ok (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *AdjOK?*", on->name);

#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));

    zlog_debug ("adj_ok, neighbor ipv6 address:%s", ipv6_string);
#endif
    if (on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency (on))
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d ospf6 neighbor state change to EXSTART, neighbor ipv6 address:%s", __func__, __LINE__, ipv6_string);
#endif

        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
        SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
        SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
        SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

        THREAD_OFF (on->thread_send_dbdesc);
        on->thread_send_dbdesc =
            thread_add_event (master, ospf6_dbdesc_send, on, 0);

    }
    else if (on->state >= OSPF6_NEIGHBOR_EXSTART &&
             ! need_adjacency (on))
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d ospf6 neighbor state change to TWOWAY, neighbor ipv6 address:%s", __func__, __LINE__, ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on);
        ospf6_lsdb_remove_all (on->summary_list);
        ospf6_lsdb_remove_all (on->request_list);
        for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
                lsa = ospf6_lsdb_next (lsa))
        {
            ospf6_decrement_retrans_count (lsa);
            ospf6_lsdb_remove (lsa, on->retrans_list);
        }
    }

    return 0;
}

int
seqnumber_mismatch (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif

    if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *SeqNumberMismatch*", on->name);

#ifdef OSPF6_DEBUG
    zlog_debug("%s()neighbor state change to EXSTART, ifname:%s, neighbor ipv6 address:%s", __func__, on->ospf6_if->interface->name, ipv6_string);
#endif
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
#if 1
    /*add for OSPF+ */
    if (on->leaving_exchange_state == 1)
    {
#ifdef OSPF6_DEBUG
        zlog_debug ("%s()neighbor Leaving---->Exchange----->Exstart and set leaving_exchange_state to 0, neighbor ipv6 address:%s", __func__, ipv6_string);
#endif
        on->leaving_exchange_state = 0;

        if (on->ospf6_if->reference_count > 0)
        {
#ifdef OSPF6_DEBUG
            zlog_debug("%s()reference count --", __func__);
#endif
            on->ospf6_if->reference_count--;
            if (on->ospf6_if->reference_count == 0)
            {
                /*if the new lsas list is not nll, empty it */
                if (on->ospf6_if->new_lsas_list->count)
                    ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
            }
        }
    }
#endif
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }

    THREAD_OFF (on->thread_send_dbdesc);
    on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);

    return 0;
}

int
bad_lsreq (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *BadLSReq*", on->name);

    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT);
    SET_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT);

    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }

    THREAD_OFF (on->thread_send_dbdesc);
    on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);

    return 0;
}

int
oneway_received (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state < OSPF6_NEIGHBOR_TWOWAY)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *1Way-Received*", on->name);

    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on);
    thread_add_event (master, neighbor_change, on->ospf6_if, 0);

    ospf6_lsdb_remove_all (on->summary_list);
    ospf6_lsdb_remove_all (on->request_list);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
    {
        ospf6_decrement_retrans_count (lsa);
        ospf6_lsdb_remove (lsa, on->retrans_list);
    }

    THREAD_OFF (on->thread_send_dbdesc);
    THREAD_OFF (on->thread_send_lsreq);
    THREAD_OFF (on->thread_send_lsupdate);
    THREAD_OFF (on->thread_send_lsack);

    return 0;
}

int
inactivity_timer (struct thread *thread)
{
    struct ospf6_neighbor *on;
    //struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *InactivityTimer*", on->name);


#ifdef OSPF6_DEBUG
    //add debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));
#endif


    on->inactivity_timer = NULL;
#if 1
    if (on->state == OSPF6_NEIGHBOR_FULL)
    {
        THREAD_OFF (on->connection_period_timer);
        /*del inactivity timer*/
        THREAD_OFF (on->inactivity_timer);

#ifdef OSPF6_DEBUG
        zlog_debug("del connection period timer, change neighbor state to LEAVING, add circle period timer,neighbor ipv6 string:%s", ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LEAVING, on);

#if 0/*delete 16.9.9*/
        quagga_gettime(QUAGGA_CLK_MONOTONIC, &on->last_leaving);
#ifdef OSPF6_DEBUG
        zlog_debug("because inactivity is active, now is leaving,time is:%ld, neighbor ipv6 string:%s", on->last_leaving.tv_sec, ipv6_string);
#endif
#endif /*end delete*/
        /*the leaving reference count +1 */
        on->ospf6_if->reference_count++;

#ifdef OSPF6_DEBUG
        zlog_debug("inactivity timer is active, on->state is FULL, neighbor ipv6 address:%s", ipv6_string);
#endif
#if 0
        /* clear ls-list */
        ospf6_lsdb_remove_all (on->summary_list);
        ospf6_lsdb_remove_all (on->request_list);
        for (lsa = ospf6_lsdb_head (on->retrans_list); lsa; lsa = ospf6_lsdb_next (lsa))
        {
            ospf6_decrement_retrans_count (lsa);
            ospf6_lsdb_remove (lsa, on->retrans_list);
        }
#endif

        /*add, when neighbor is leaving, del route*/
#if 1/*add here*/
        ospf6_neighbor_delete_for_leaving (on);
#endif
        zlog_debug("%s()%d ospf6 neighbor state must be Leaving, now is:%s", __func__, __LINE__, ospf6_neighbor_state_str[on->state]);

        /*add circle period timer */
        on->circle_period_timer = thread_add_timer (master, circle_period_timer, on, on->circle_period);
    }
    else
#endif
    {
        on->drouter = on->prev_drouter = 0;
        on->bdrouter = on->prev_bdrouter = 0;

#ifdef OSPF6_DEBUG
        zlog_debug("inactivity time is active ,buf ospf6 is not FULL, change neighbor state to DOWN,neighbor ipv6 string:%s", ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_DOWN, on);
        thread_add_event (master, neighbor_change, on->ospf6_if, 0);

        listnode_delete (on->ospf6_if->neighbor_list, on);
        ospf6_neighbor_delete (on);
    }

    return 0;
}
//change for OSPF+ 17.2.14
int connection_to_leaving (struct thread *thread)
{

    struct ospf6_neighbor *on;
    //struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state != OSPF6_NEIGHBOR_FULL)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *single hello timer*", on->name);

    /*change the neighbor to Leaving */
    zlog_debug("connection period timer is active, change neighbor state to LEAVING, ifname:%s", on->ospf6_if->interface->name);
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LEAVING, on);

    zlog_debug("ospf6 neighbor state must be LEAVING, now is:%s", ospf6_neighbor_state_str[on->state]);
    /*leaving reference count + 1 */
    on->ospf6_if->reference_count++;

    zlog_debug("reference_count:%d", on->ospf6_if->reference_count);

    //on->drouter = on->prev_drouter = 0;
    //on->bdrouter = on->prev_bdrouter = 0;

    //thread_add_event (master, neighbor_change, on->ospf6_if, 0);

    ospf6_neighbor_delete_for_leaving (on);
    //add here
    on->first_hello_state = 0;

    zlog_debug("empty list, add circle period timer");
    /*add circle period timer */
    on->circle_period_timer = thread_add_timer (master, circle_period_timer, on, on->circle_period);

    return 0;
}

//add for OSPF+ 16.4.21
int connection_period_timer (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *connection period timer*", on->name);

    zlog_debug("Connection period timer is active, add single hello timer");
    on->connection_period_timer = NULL;
    /*del inactivity timer */
    if (on->inactivity_timer)
        THREAD_OFF (on->inactivity_timer);
    /*add a single hello timer */

    /*change state Full to Leaving*/
    connection_to_leaving (thread);

    return 0;
}


//add for OSPF+
int circle_period_timer (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *circle period timer*", on->name);

    on->circle_period_timer = NULL;
    on->drouter = on->prev_drouter = 0;
    on->bdrouter = on->prev_bdrouter = 0;

    zlog_debug("Circle period timer is active, change neighbor state to DOWN, ifname:%s", on->ospf6_if->interface->name);
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_DOWN, on);
    /*when the state is leaving to down, reference count -1 */
    if (on->ospf6_if->reference_count > 0)
    {
        on->ospf6_if->reference_count--;
        if (on->ospf6_if->reference_count == 0)
        {
            /*clear new lsas list */
            if (on->ospf6_if->new_lsas_list->count)
                ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
        }
    }
    thread_add_event (master, neighbor_change, on->ospf6_if, 0);

    listnode_delete (on->ospf6_if->neighbor_list, on);
    ospf6_neighbor_delete (on);
    return 0;
}
/* vty functions */
/* show neighbor structure */
static void
ospf6_neighbor_show (struct vty *vty, struct ospf6_neighbor *on)
{
    char router_id[16];
    char duration[16];
    struct timeval now, res;
    char nstate[16];
    char deadtime[16];
    long h, m, s;

    /* Router-ID (Name) */
    inet_ntop (AF_INET, &on->router_id, router_id, sizeof (router_id));
#ifdef HAVE_GETNAMEINFO
    {
    }
#endif /*HAVE_GETNAMEINFO*/

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);

    /* Dead time */
    h = m = s = 0;
    if (on->inactivity_timer)
    {
        s = on->inactivity_timer->u.sands.tv_sec - recent_relative_time().tv_sec;
        h = s / 3600;
        s -= h * 3600;
        m = s / 60;
        s -= m * 60;
    }
    snprintf (deadtime, sizeof (deadtime), "%02ld:%02ld:%02ld", h, m, s);

    /* Neighbor State */
    if (if_is_pointopoint (on->ospf6_if->interface))
        snprintf (nstate, sizeof (nstate), "PointToPoint");
    else
    {
        if (on->router_id == on->drouter)
            snprintf (nstate, sizeof (nstate), "DR");
        else if (on->router_id == on->bdrouter)
            snprintf (nstate, sizeof (nstate), "BDR");
        else
            snprintf (nstate, sizeof (nstate), "DROther");
    }

    /* Duration */
    timersub (&now, &on->last_changed, &res);
    timerstring (&res, duration, sizeof (duration));

    /*
    vty_out (vty, "%-15s %3d %11s %6s/%-12s %11s %s[%s]%s",
             "Neighbor ID", "Pri", "DeadTime", "State", "", "Duration",
             "I/F", "State", VNL);
    */

    vty_out (vty, "%-15s %3d %11s %6s/%-12s %11s %s[%s]%s",
             router_id, on->priority, deadtime,
             ospf6_neighbor_state_str[on->state], nstate, duration,
             on->ospf6_if->interface->name,
             ospf6_interface_state_str[on->ospf6_if->state], VNL);
}

static void
ospf6_neighbor_show_drchoice (struct vty *vty, struct ospf6_neighbor *on)
{
    char router_id[16];
    char drouter[16], bdrouter[16];
    char duration[16];
    struct timeval now, res;

    /*
        vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
                 "RouterID", "State", "Duration", "DR", "BDR", "I/F",
                 "State", VNL);
    */

    inet_ntop (AF_INET, &on->router_id, router_id, sizeof (router_id));
    inet_ntop (AF_INET, &on->drouter, drouter, sizeof (drouter));
    inet_ntop (AF_INET, &on->bdrouter, bdrouter, sizeof (bdrouter));

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    timersub (&now, &on->last_changed, &res);
    timerstring (&res, duration, sizeof (duration));

    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
             router_id, ospf6_neighbor_state_str[on->state],
             duration, drouter, bdrouter, on->ospf6_if->interface->name,
             ospf6_interface_state_str[on->ospf6_if->state],
             VNL);
}

static void
ospf6_neighbor_show_detail (struct vty *vty, struct ospf6_neighbor *on)
{
    char drouter[16], bdrouter[16];
    char linklocal_addr[64], duration[32];
    struct timeval now, res;
    struct ospf6_lsa *lsa;

    inet_ntop (AF_INET6, &on->linklocal_addr, linklocal_addr,
               sizeof (linklocal_addr));
    inet_ntop (AF_INET, &on->drouter, drouter, sizeof (drouter));
    inet_ntop (AF_INET, &on->bdrouter, bdrouter, sizeof (bdrouter));

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);
    timersub (&now, &on->last_changed, &res);
    timerstring (&res, duration, sizeof (duration));

    vty_out (vty, " Neighbor %s%s", on->name,
             VNL);
    vty_out (vty, "    Area %s via interface %s (ifindex %d)%s",
             on->ospf6_if->area->name,
             on->ospf6_if->interface->name,
             on->ospf6_if->interface->ifindex,
             VNL);
    vty_out (vty, "    His IfIndex: %d Link-local address: %s%s",
             on->ifindex, linklocal_addr,
             VNL);
    vty_out (vty, "    State %s for a duration of %s%s",
             ospf6_neighbor_state_str[on->state], duration,
             VNL);
    vty_out (vty, "    His choice of DR/BDR %s/%s, Priority %d%s",
             drouter, bdrouter, on->priority,
             VNL);
    vty_out (vty, "    DbDesc status: %s%s%s SeqNum: %#lx%s",
             (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_IBIT) ? "Initial " : ""),
             (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MBIT) ? "More " : ""),
             (CHECK_FLAG (on->dbdesc_bits, OSPF6_DBDESC_MSBIT) ?
              "Master" : "Slave"), (u_long) ntohl (on->dbdesc_seqnum),
             VNL);

    vty_out (vty, "    Summary-List: %d LSAs%s", on->summary_list->count,
             VNL);
    for (lsa = ospf6_lsdb_head (on->summary_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    vty_out (vty, "    Request-List: %d LSAs%s", on->request_list->count,
             VNL);
    for (lsa = ospf6_lsdb_head (on->request_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    vty_out (vty, "    Retrans-List: %d LSAs%s", on->retrans_list->count,
             VNL);
    for (lsa = ospf6_lsdb_head (on->retrans_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    timerclear (&res);
    if (on->thread_send_dbdesc)
        timersub (&on->thread_send_dbdesc->u.sands, &now, &res);
    timerstring (&res, duration, sizeof (duration));
    vty_out (vty, "    %d Pending LSAs for DbDesc in Time %s [thread %s]%s",
             on->dbdesc_list->count, duration,
             (on->thread_send_dbdesc ? "on" : "off"),
             VNL);
    for (lsa = ospf6_lsdb_head (on->dbdesc_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    timerclear (&res);
    if (on->thread_send_lsreq)
        timersub (&on->thread_send_lsreq->u.sands, &now, &res);
    timerstring (&res, duration, sizeof (duration));
    vty_out (vty, "    %d Pending LSAs for LSReq in Time %s [thread %s]%s",
             on->lsreq_list->count, duration,
             (on->thread_send_lsreq ? "on" : "off"),
             VNL);
    for (lsa = ospf6_lsdb_head (on->lsreq_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    timerclear (&res);
    if (on->thread_send_lsupdate)
        timersub (&on->thread_send_lsupdate->u.sands, &now, &res);
    timerstring (&res, duration, sizeof (duration));
    vty_out (vty, "    %d Pending LSAs for LSUpdate in Time %s [thread %s]%s",
             on->lsupdate_list->count, duration,
             (on->thread_send_lsupdate ? "on" : "off"),
             VNL);
    for (lsa = ospf6_lsdb_head (on->lsupdate_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

    timerclear (&res);
    if (on->thread_send_lsack)
        timersub (&on->thread_send_lsack->u.sands, &now, &res);
    timerstring (&res, duration, sizeof (duration));
    vty_out (vty, "    %d Pending LSAs for LSAck in Time %s [thread %s]%s",
             on->lsack_list->count, duration,
             (on->thread_send_lsack ? "on" : "off"),
             VNL);
    for (lsa = ospf6_lsdb_head (on->lsack_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);

}
void ospf6_neighbor_show_period(struct vty *vty, struct ospf6_neighbor *on)
{

    float seconds_gone;
    char ipv6_string[128];

    float diff_connection;
    float diff_circle;
    if (on == NULL)
        return;
    //link local address, connection periond,  circle period, state, remaining connection/circle period
    memset (ipv6_string, 0, sizeof (ipv6_string));
    inet_ntop (AF_INET6, &on->linklocal_addr, ipv6_string, sizeof (ipv6_string));


    seconds_gone = get_seconds_has_gone_today ();
    diff_connection = on->connection_period - (seconds_gone - on->first_hello_time);

    vty_out(vty, "peer link local address:%s%s", ipv6_string, VNL);
    vty_out(vty, "neighbor connection period:%f%s", on->connection_period, VNL);
    vty_out(vty, "neighbor circle period:%f%s", on->circle_period, VNL);
    if (diff_connection > 0)
        vty_out(vty, "remaining connection period :%f%s", diff_connection, VNL);
    else
    {
        diff_connection = on->circle_period - (seconds_gone - on->first_hello_time);
        vty_out(vty, "remaining circle period :%f%s", diff_connection, VNL);
    }

    return;
}


DEFUN (show_ipv6_ospf6_neighbor_period,
       show_ipv6_ospf6_neighbor_period_cmd,
       "show ipv6 ospf6 neighbor period",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Satellite orbit parameters\n"
      )
{

    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct listnode *i, *j, *k;
    void (*showfunc) (struct vty *, struct ospf6_neighbor *);
    OSPF6_CMD_CHECK_RUNNING ();
    showfunc = ospf6_neighbor_show_period;

    //vty_out (vty, "%-15s %11s %11s ",
    //          "Neighbor link address", "connection period", "circle period");

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
                (*showfunc) (vty, on);

}
DEFUN (show_ipv6_ospf6_packet_stats,
       show_ipv6_ospf6_packet_stats_cmd,
       "show ipv6 ospf6 packet stats",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "recv and send packet\n"
       "packet stats\n"
      )
{

    int i;
    char name[INTERFACE_NAMSIZ + 1];
    for (i = 0; i < MAXINTERFACENUM; i++)
    {
        if (ostats[i].ifindex == 0)
            continue;

        memset(name, 0x00, sizeof(name));

        if_indextoname(ostats[i].ifindex, name);
        zlog_debug("%sinterface name:%s%s", VNL, name, VNL);
        zlog_debug("hello recv nums:%ld bytes:%ld%s", ostats[i].hello_recv_nums, ostats[i].hello_recv_bytes, VNL);
        zlog_debug("dbdesc recv nums:%ld bytes:%ld%s", ostats[i].dbdesc_recv_nums, ostats[i].dbdesc_recv_bytes, VNL);
        zlog_debug("lsreq recv nums:%ld bytes:%ld%s", ostats[i].lsreq_recv_nums, ostats[i].lsreq_recv_bytes, VNL);
        zlog_debug("lsupdate recv nums:%ld bytes:%ld%s", ostats[i].lsupdate_recv_nums, ostats[i].lsupdate_recv_bytes, VNL);
        zlog_debug("lsack recv nums:%ld bytes:%ld%s", ostats[i].lsack_recv_nums, ostats[i].lsack_recv_bytes, VNL);

        zlog_debug("hello send nums:%ld bytes:%ld%s", ostats[i].hello_send_nums, ostats[i].hello_send_bytes, VNL);
        zlog_debug("dbdesc send nums:%ld bytes:%ld%s", ostats[i].dbdesc_send_nums, ostats[i].dbdesc_send_bytes, VNL);
        zlog_debug("lsreq send nums:%ld bytes:%ld%s", ostats[i].lsreq_send_nums, ostats[i].lsreq_send_bytes, VNL);
        zlog_debug("lsupdate send nums:%ld bytes:%ld%s", ostats[i].lsupdate_send_nums, ostats[i].lsupdate_send_bytes, VNL);
        zlog_debug("lsack send nums:%ld bytes:%ld%s", ostats[i].lsack_send_nums, ostats[i].lsack_send_bytes, VNL);
    }

    return CMD_SUCCESS;
}
DEFUN (show_ipv6_ospf6_neighbor,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
      )
{
    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct listnode *i, *j, *k;
    void (*showfunc) (struct vty *, struct ospf6_neighbor *);

    OSPF6_CMD_CHECK_RUNNING ();
    showfunc = ospf6_neighbor_show;

    if (argc)
    {
        if (! strncmp (argv[0], "de", 2))
            showfunc = ospf6_neighbor_show_detail;
        else if (! strncmp (argv[0], "dr", 2))
            showfunc = ospf6_neighbor_show_drchoice;
    }

    if (showfunc == ospf6_neighbor_show)
        vty_out (vty, "%-15s %3s %11s %6s/%-12s %11s %s[%s]%s",
                 "Neighbor ID", "Pri", "DeadTime", "State", "IfState", "Duration",
                 "I/F", "State", VNL);
    else if (showfunc == ospf6_neighbor_show_drchoice)
        vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
                 "RouterID", "State", "Duration", "DR", "BDR", "I/F",
                 "State", VNL);

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
                (*showfunc) (vty, on);

    return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_neighbor,
       show_ipv6_ospf6_neighbor_detail_cmd,
       "show ipv6 ospf6 neighbor (detail|drchoice)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Display details\n"
       "Display DR choices\n"
      )

DEFUN (show_ipv6_ospf6_neighbor_one,
       show_ipv6_ospf6_neighbor_one_cmd,
       "show ipv6 ospf6 neighbor A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Specify Router-ID as IPv4 address notation\n"
      )
{
    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    struct ospf6_area *oa;
    struct listnode *i, *j, *k;
    void (*showfunc) (struct vty *, struct ospf6_neighbor *);
    u_int32_t router_id;

    OSPF6_CMD_CHECK_RUNNING ();
    showfunc = ospf6_neighbor_show_detail;

    if ((inet_pton (AF_INET, argv[0], &router_id)) != 1)
    {
        vty_out (vty, "Router-ID is not parsable: %s%s", argv[0],
                 VNL);
        return CMD_SUCCESS;
    }

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
                (*showfunc) (vty, on);

    return CMD_SUCCESS;
}

void
ospf6_neighbor_init (void)
{
    install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_packet_stats_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_period_cmd);
    install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_detail_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_packet_stats_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_period_cmd);
    install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_detail_cmd);
}

DEFUN (debug_ospf6_neighbor,
       debug_ospf6_neighbor_cmd,
       "debug ospf6 neighbor",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
      )
{
    unsigned char level = 0;
    if (argc)
    {
        if (! strncmp (argv[0], "s", 1))
            level = OSPF6_DEBUG_NEIGHBOR_STATE;
        if (! strncmp (argv[0], "e", 1))
            level = OSPF6_DEBUG_NEIGHBOR_EVENT;
    }
    else
        level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

    OSPF6_DEBUG_NEIGHBOR_ON (level);
    return CMD_SUCCESS;
}

ALIAS (debug_ospf6_neighbor,
       debug_ospf6_neighbor_detail_cmd,
       "debug ospf6 neighbor (state|event)",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n"
      )

DEFUN (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_cmd,
       "no debug ospf6 neighbor",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
      )
{
    unsigned char level = 0;
    if (argc)
    {
        if (! strncmp (argv[0], "s", 1))
            level = OSPF6_DEBUG_NEIGHBOR_STATE;
        if (! strncmp (argv[0], "e", 1))
            level = OSPF6_DEBUG_NEIGHBOR_EVENT;
    }
    else
        level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

    OSPF6_DEBUG_NEIGHBOR_OFF (level);
    return CMD_SUCCESS;
}

ALIAS (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_detail_cmd,
       "no debug ospf6 neighbor (state|event)",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n"
      )

int
config_write_ospf6_debug_neighbor (struct vty *vty)
{
    if (IS_OSPF6_DEBUG_NEIGHBOR (STATE) &&
            IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        vty_out (vty, "debug ospf6 neighbor%s", VNL);
    else if (IS_OSPF6_DEBUG_NEIGHBOR (STATE))
        vty_out (vty, "debug ospf6 neighbor state%s", VNL);
    else if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        vty_out (vty, "debug ospf6 neighbor event%s", VNL);
    return 0;
}

void
install_element_ospf6_debug_neighbor (void)
{
    install_element (ENABLE_NODE, &debug_ospf6_neighbor_cmd);
    install_element (ENABLE_NODE, &debug_ospf6_neighbor_detail_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_neighbor_cmd);
    install_element (ENABLE_NODE, &no_debug_ospf6_neighbor_detail_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_neighbor_cmd);
    install_element (CONFIG_NODE, &debug_ospf6_neighbor_detail_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_neighbor_cmd);
    install_element (CONFIG_NODE, &no_debug_ospf6_neighbor_detail_cmd);
}



