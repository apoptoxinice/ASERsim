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
#include "ospf6_route.h"
#include "ospf6_spf.h"

#define INIT_CONNECTION_PERIOD  365*24*60*60
#define INIT_CIRCLE_PERIOD 365*24*60*60

unsigned char conf_debug_ospf6_neighbor = 0;

const char *ospf6_neighbor_state_str[] =
{
    "None", "Down", "Attempt", "Init", "Twoway", "ExStart", "ExChange",
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
    on->state_change = 0;
#if 1 //add 2020
    on->neighbor_pbr_flag = 0;
#endif
    quagga_gettime (QUAGGA_CLK_MONOTONIC, &on->last_changed);
    on->router_id = router_id;

    on->summary_list = ospf6_lsdb_create (on);
    on->request_list = ospf6_lsdb_create (on);
    on->retrans_list = ospf6_lsdb_create (on);

    on->dbdesc_list = ospf6_lsdb_create (on);
    on->lsupdate_list = ospf6_lsdb_create (on);
#if 1//add 2019.11.29
    on->lsexpire_list = ospf6_lsdb_create (on);
#endif
    on->lsack_list = ospf6_lsdb_create (on);
    /*add 2020*/
#if 1
    on->leaving_exchange_state = 0;
    on->update_nb_period_timer_state = 0;
    on->start_time = 0;
    on->end_time = 0;
    on->connection_period = 0;
    on->circle_period = 0;
#endif

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
    ospf6_lsdb_remove_all (on->lsupdate_list);
#if 1//add 2019.11.29
    ospf6_lsdb_remove_all (on->lsexpire_list);
#endif
    ospf6_lsdb_remove_all (on->lsack_list);

    ospf6_lsdb_delete (on->summary_list);
    ospf6_lsdb_delete (on->request_list);
    ospf6_lsdb_delete (on->retrans_list);

    ospf6_lsdb_delete (on->dbdesc_list);
    ospf6_lsdb_delete (on->lsupdate_list);
#if 1 //add 2019.11.29
    ospf6_lsdb_delete (on->lsexpire_list);
#endif
    ospf6_lsdb_delete (on->lsack_list);

    THREAD_OFF (on->inactivity_timer);

#if 1 //add 2020
    on->neighbor_pbr_flag = 0;
#endif
    //add
    on->leaving_exchange_state = 0;
    on->update_nb_period_timer_state = 0;
    on->start_time = 0;
    on->end_time = 0;
    on->connection_period = 0;
    on->circle_period = 0;

    //add
    THREAD_OFF (on->speed_up_hello_msg_detection_timer);
    THREAD_OFF (on->inactivity_timer_2);
    THREAD_OFF (on->circle_period_timer);
    THREAD_OFF (on->exchange_to_exstart_timer);

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

    /*202003 add*/
    THREAD_OFF (on->thread_send_dbdesc);
    THREAD_OFF (on->thread_send_lsreq);
    THREAD_OFF (on->thread_send_lsupdate);
    THREAD_OFF (on->thread_send_lsack);
}

#if 0
void
ospf6_neighbor_add_for_leaving (struct ospf6_neighbor *on)
{

    ospf6_lsdb_add_all_for_leaving (on->dbdesc_list);
    ospf6_lsdb_add_all_for_leaving (on->lsreq_list);
    ospf6_lsdb_add_all_for_leaving (on->lsupdate_list);
    ospf6_lsdb_add_all_for_leaving (on->lsack_list);

}
#endif /*if 0*/

static const char *ospf6_neighbor_event_str[] =
{
    "NoEvent",
    "HelloReceived",
    "2-WayReceived",
    "NegotiationDone",
    "ExchangeDone",
    "LoadingDone",
    "AdjOK?",
    "SeqNumberMismatch",
    "BadLSReq",
    "1-WayReceived",
    "InactivityTimer",
    "CirclePeriodTimer",
    "ConnectionToLeaving",
};

static const char *ospf6_neighbor_event_string (int event)
{
#define OSPF6_NEIGHBOR_UNKNOWN_EVENT_STRING "UnknownEvent"

    if (event < OSPF6_NEIGHBOR_EVENT_MAX_EVENT)
        return ospf6_neighbor_event_str[event];
    return OSPF6_NEIGHBOR_UNKNOWN_EVENT_STRING;
}

static void
ospf6_neighbor_state_change (u_char next_state, struct ospf6_neighbor *on, int event)
{
    u_char prev_state;

    prev_state = on->state;
    on->state = next_state;

    if (prev_state == next_state)
        return;

    on->state_change++;
    quagga_gettime (QUAGGA_CLK_MONOTONIC, &on->last_changed);

    /* log */
    if (IS_OSPF6_DEBUG_NEIGHBOR (STATE))
    {
        zlog_debug ("Neighbor state change %s: [%s]->[%s] (%s)", on->name,
                    ospf6_neighbor_state_str[prev_state],
                    ospf6_neighbor_state_str[next_state],
                    ospf6_neighbor_event_string(event));
    }

    /* Optionally notify about adjacency changes */
    if (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
                   OSPF6_LOG_ADJACENCY_CHANGES) &&
            (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
                        OSPF6_LOG_ADJACENCY_DETAIL) ||
             (next_state == OSPF6_NEIGHBOR_FULL) || (next_state < prev_state)))
        zlog_notice("AdjChg: Nbr %s: %s -> %s (%s)", on->name,
                    ospf6_neighbor_state_str[prev_state],
                    ospf6_neighbor_state_str[next_state],
                    ospf6_neighbor_event_string(event));

    if ((prev_state == OSPF6_NEIGHBOR_FULL || next_state == OSPF6_NEIGHBOR_FULL) || (prev_state == OSPF6_NEIGHBOR_LEAVING && next_state == OSPF6_NEIGHBOR_DOWN))
    {
#if 0
        if (next_state == OSPF6_NEIGHBOR_LEAVING)
            OSPF6_ROUTER_LSA_SCHEDULE_FOR_LEAVING (on->ospf6_if->area);
        else
#endif
        {
            OSPF6_ROUTER_LSA_SCHEDULE (on->ospf6_if->area);
            if (on->ospf6_if->state == OSPF6_INTERFACE_DR)
            {
                OSPF6_NETWORK_LSA_SCHEDULE (on->ospf6_if);
                OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT (on->ospf6_if);
            }
            OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB (on->ospf6_if->area);
#if 0//add 2020
            DG("will call ospf6_spf_schedule_zone.\n");
            ospf6_spf_schedule_zone (on->ospf6_if->area->ospf6, OSPF6_SPF_FLAGS_ZONE_LSA_ADDED);
#endif
        }
    }

    if ((prev_state == OSPF6_NEIGHBOR_EXCHANGE ||
            prev_state == OSPF6_NEIGHBOR_LOADING) &&
            (next_state != OSPF6_NEIGHBOR_EXCHANGE &&
             next_state != OSPF6_NEIGHBOR_LOADING))
        ospf6_maxage_remove (on->ospf6_if->area->ospf6);

#ifdef HAVE_SNMP
    /* Terminal state or regression */
    if ((next_state == OSPF6_NEIGHBOR_FULL)  ||
            (next_state == OSPF6_NEIGHBOR_TWOWAY) ||
            (next_state < prev_state))
        ospf6TrapNbrStateChange (on);
#endif

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
static float seconds_from_morning(void)
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
static int ospf6_exchange_to_exstart_timer (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *leaving->exchange->exstart*", on->name);

    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on,
                                 OSPF6_NEIGHBOR_EVENT_SEQNUMBER_MISMATCH);
    /*add for OSPF+ */
    if (on->leaving_exchange_state == 1)
    {
        on->leaving_exchange_state = 0;

        if (on->ospf6_if->reference_count > 0)
        {
            on->ospf6_if->reference_count--;
            if (on->ospf6_if->reference_count == 0)
            {
                /*if the new lsas list is not nll, empty it */
                if (on->ospf6_if->new_lsas_list->count)
                    ospf6_lsdb_remove_all (on->ospf6_if->new_lsas_list);
            }
        }
    }

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
    on->dbdesc_seqnum++;		/* Incr seqnum as per RFC2328, sec 10.3 */

    on->thread_send_dbdesc =
        thread_add_event (master, ospf6_dbdesc_send, on, 0);

    return 0;
}
static void update_period_for_neighbor(struct ospf6_neighbor *on)
{
    float seconds;

    seconds = seconds_from_morning ();
    //printf("%.f seconds from this mornig.\n", seconds);

    //add for debug
    char ipv6_string[128];
    memset(ipv6_string, 0, sizeof(ipv6_string));
    inet_ntop(AF_INET6, &on->linklocal_addr, ipv6_string, sizeof(ipv6_string));


#ifdef OSPF6_DEBUG
    zlog_debug ("on->update_nb_period_timer_state:%d, ifname:%s, neighbor ipv6 address:%s", on->update_nb_period_timer_state, on->ospf6_if->interface->name, ipv6_string);
#endif

    if (on->update_nb_period_timer_state == 1)
    {
        zlog_debug ("recv hello packet, add connection period timer, ifname:%s, neighbor ipv6 address:%s", on->ospf6_if->interface->name, ipv6_string);
        stl_link_list p;
        p = stl_link_head;
        while (p)
        {
            if (!memcmp (&p->stl_msg_all.neighbor_ipv6_address, &on->linklocal_addr, sizeof (struct in6_addr)))
            {
                zlog_debug("in list find neigh, connection period is:%f circle_period:%f", p->stl_msg_all.connection_period, p->stl_msg_all.circle_period);
                if ((p->stl_msg_all.connection_period == 0) && (p->stl_msg_all.start_time == 0) && (p->stl_msg_all.end_time == 0))
                {
                    zlog_debug ("neighbor:%s start_time, end_time, connection_period is all zero, don't update", ipv6_string);
                    return;
                }
                else
                {
#if 0
                    if (p->stl_msg_all.connection_period < (seconds - on->first_hello_time))
                    {
                        zlog_debug ("neighbor:%s connection period less then used time:%f.", ipv6_string, seconds - on->first_hello_time);
                        return;
                    }
#endif

                    on->start_time = p->stl_msg_all.start_time;
                    on->end_time = p->stl_msg_all.end_time;
                    printf(">>>>%.f seconds from this mornig, on->start_time:%f\n", seconds, on->start_time);

                    if (seconds > p->stl_msg_all.start_time)
                        on->connection_period = p->stl_msg_all.connection_period - (seconds - on->start_time);
                    else
                        on->connection_period = p->stl_msg_all.connection_period + (on->start_time - seconds);

                    on->circle_period = p->stl_msg_all.circle_period;
                    zlog_debug ("update neighbor:%s connection period is:%f circle_period:%f", ipv6_string, on->connection_period, on->circle_period);
                    break;
                }
            }
            p = p->next;
        }
#if 0
        if (p == NULL)
        {
#ifdef OSPF6_DEBUG
            zlog_debug ("In list, don't find the neighbor:%s", ipv6_string);
#endif
            on->connection_period = INIT_CONNECTION_PERIOD;
            on->circle_period = INIT_CIRCLE_PERIOD;
        }
#endif
        if (p)
        {
            on->speed_up_hello_msg_detection_timer = thread_add_timer (master, speed_up_hello_msg_detection_timer, on, on->connection_period - HELLO_ADVANCE_PACKET_DETECTION_TIME);
            on->update_nb_period_timer_state = 0;
        }
    }
    return;
}

int hello_received (struct thread *thread)
{
    struct ospf6_neighbor *on;
    struct ospf6_lsa *lsa;
    struct ospf6_lsa *copy;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *HelloReceived*", on->name);

#if 0
    if (on->state == OSPF6_NEIGHBOR_LEAVING && on->update_nb_period_timer_state == 1)
    {
        on->first_hello_state = 0;
#if 0
        /*Recover Hello message sending interval*/
        if (on->ospf6_if->hello_interval_bak != 0)
        {
            on->ospf6_if->hello_interval = on->ospf6_if->hello_interval_bak;
            on->ospf6_if->hello_interval_bak = 0;
            zlog_debug("recover hello message sending interval:%d.\n", on->ospf6_if->hello_interval);
        }
#endif
    }
#endif

    /*
     * 	If the state triggered by the inactivity timer changes to leaving, you need to accept the Hello message when receiving the Hello message again.
     * 	If the state triggered by inactivity timer 2 changes to leaving, the Hello message will be accepted only when a new link connection parameter is received.
     */
    if (on->state == OSPF6_NEIGHBOR_LEAVING && on->inactivity_timer_state == 1)
    {
        on->inactivity_timer_state = 0;
    }
    else if (on->state == OSPF6_NEIGHBOR_LEAVING && on->inactivity_timer_2_state == 1)
    {
        zlog_debug("now neighbor state is leaving, don't recv hello msg.\n");
        return 0;
    }
#if 0
    if (on->first_hello_state == 0)
    {
        on->first_hello_time = seconds_from_morning();
        on->first_hello_state = 1;
    }
#endif
    update_period_for_neighbor(on);

    if (on->inactivity_timer_2_state == 0)
    {
        /* reset Inactivity Timer */
        THREAD_OFF (on->inactivity_timer);
        on->inactivity_timer = thread_add_timer (master, inactivity_timer, on,
                               on->ospf6_if->dead_interval);
    }
    else
    {
        zlog_debug("reset inactivity_timer_2");
        /* reset Inactivity Timer 2*/
        THREAD_OFF (on->inactivity_timer_2);
        on->inactivity_timer_2 = thread_add_timer (master, inactivity_timer_2, on, DEAD_INTERVAL_2);
    }

#if 1
    /*a) judge the neighbor state in the leaving */
    if (on->state == OSPF6_NEIGHBOR_LEAVING)
    {
        /*del circle period timer */
        THREAD_OFF (on->circle_period_timer);

        /*judge the new lsas list is null?*/
        if (on->ospf6_if->new_lsas_list->count)
        {
            ospf6_fill_summary_list(on);
            ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on, OSPF6_NEIGHBOR_EVENT_HELLO_RCVD);

#ifdef OSPF6_DEBUG
            zlog_debug("new lsas list is not null,  ospf6 neighbor state change to EXCHANGE, now is:%s, ipv6 addr:%s", ospf6_neighbor_state_str[on->state], ipv6_string);
#endif
        }
        else
        {
            ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on, OSPF6_NEIGHBOR_EVENT_HELLO_RCVD);
#ifdef OSPF6_DEBUG
            zlog_debug("new lsas list is null,  ospf6 neighbor state change to EXCHANGE, now is:%s, ipv6 addr:%s", ospf6_neighbor_state_str[on->state], ipv6_string);
#endif
        }

#if 1 //reinstall expire lsa to lsdb
        zlog_debug("%s()%d will install expire lsa to lsdb.", __func__, __LINE__);
        for (lsa = ospf6_lsdb_head (on->lsexpire_list); lsa; lsa = ospf6_lsdb_next (lsa))
        {
            /*set birth age*/
            copy = ospf6_lsa_copy_for_expire (lsa);
            /*choose lsdb*/
            switch (OSPF6_LSA_SCOPE (copy->header->type))
            {
            case OSPF6_SCOPE_LINKLOCAL:
                copy->lsdb = on->ospf6_if->lsdb;
                break;
            case OSPF6_SCOPE_AREA:
                copy->lsdb = on->ospf6_if->area->lsdb;
                break;
            case OSPF6_SCOPE_AS:
                copy->lsdb = on->ospf6_if->area->ospf6->lsdb;
                break;
            default:
                zlog_debug ("LSA has reserved scope, discard");
                ospf6_lsa_delete (copy);
                continue;
            }
            //zlog_debug("%s()%d will call ospf6_install_lsa.", __func__, __LINE__);
            /*install to lsdb*/
            //ospf6_lsdb_add (copy, copy->lsdb);
            ospf6_install_lsa (copy);
            /*remove form list*/
            ospf6_lsdb_remove_for_expire (lsa, on->lsexpire_list);
        }
#endif

        //add 30 seconds timer, state leaving --- exchange --- exstart
        zlog_debug("%s()%d will add exchange to exstart timer, time:30s.", __func__, __LINE__);
        on->exchange_to_exstart_timer = thread_add_timer (master, ospf6_exchange_to_exstart_timer, on, 30);
        /*send new lsas list to neighbor*/
        THREAD_OFF (on->thread_send_dbdesc);
        on->thread_send_dbdesc = thread_add_event (master, ospf6_dbdesc_send_newone_for_leaving_to_exchange, on, 0);

        THREAD_OFF (on->thread_send_lsupdate);
        printf(">>>>%s()%d will call ospf6_lsupdate_send_for_new_lsas.\n", __func__, __LINE__);
        on->thread_send_lsupdate = thread_add_event (master, ospf6_lsupdate_send_neighbor_for_new_lsas, on, 0);

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
//remove 20191122
#if 0
        if (on->ospf6_if->area->lsdb_bak->count)
            ospf6_lsdb_remove_all (on->ospf6_if->area->lsdb_bak);
#endif
    }

#endif
    if (on->state <= OSPF6_NEIGHBOR_DOWN)
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()%d ospf6 neighbor state change to INIT, neighbor ipv6 address:%s", __func__, __LINE__,  ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on, OSPF6_NEIGHBOR_EVENT_HELLO_RCVD);
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
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on,
                                     OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
        return 0;
    }

#ifdef OSPF6_DEBUG
    zlog_debug("%s()%d ospf6 neighbor state change to EXSTART, neighbor ipv6 address:%s", __func__, __LINE__, ipv6_string);
#endif
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on,
                                 OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
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
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXCHANGE, on,
                                 OSPF6_NEIGHBOR_EVENT_NEGOTIATION_DONE);
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
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on,
                                     OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);
        /*202003 add*/
#if 1
        struct ospf6_interface *oi = on->ospf6_if;
        if (oi->hello_interval_bak != 0)
        {
            oi->hello_interval = oi->hello_interval_bak;
            oi->hello_interval_bak = 0;

            if (oi->thread_send_hello)
                THREAD_OFF (oi->thread_send_hello);

            oi->thread_send_hello =
                thread_add_event (master, ospf6_hello_send, oi, oi->hello_interval);
            zlog_debug("recover hello message sending interval:%d.\n", oi->hello_interval);

        }
#endif

    }
    else
    {
#ifdef OSPF6_DEBUG
        zlog_debug("%s()ospf6 neighbor state change to LOADING, neighbor ipv6 address:%s", __func__, ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LOADING, on,
                                     OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);

        if (on->thread_send_lsreq == NULL)
            on->thread_send_lsreq =
                thread_add_event (master, ospf6_lsreq_send, on, 0);
    }

    //add for OSPF+
    if (on->leaving_exchange_state == 1)
    {
        zlog_debug("%s()%d will del exchange to exstart timer, time:30s.", __func__, __LINE__);
        THREAD_OFF (on->exchange_to_exstart_timer);
#ifdef OSPF6_DEBUG
        zlog_debug("%s()This sate is Leaving---->Exchange---->Full/Loading, neighbor ipv6 address:%s", __func__, ipv6_string);
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
    return 0;
}

/* Check loading state. */
void
ospf6_check_nbr_loading (struct ospf6_neighbor *on)
{

    /* RFC2328 Section 10.9: When the neighbor responds to these requests
       with the proper Link State Update packet(s), the Link state request
       list is truncated and a new Link State Request packet is sent.
    */
    if ((on->state == OSPF6_NEIGHBOR_LOADING) ||
            (on->state == OSPF6_NEIGHBOR_EXCHANGE))
    {
        if (on->request_list->count == 0)
            thread_add_event (master, loading_done, on, 0);
        else if (on->last_ls_req == NULL)
        {
            if (on->thread_send_lsreq != NULL)
                THREAD_OFF (on->thread_send_lsreq);
            on->thread_send_lsreq =
                thread_add_event (master, ospf6_lsreq_send, on, 0);
        }
    }
}

int
loading_done (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

#ifdef OSPF6_DEBUG
    //sangmeng add debug
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
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_FULL, on,
                                 OSPF6_NEIGHBOR_EVENT_LOADING_DONE);
    /*202003 add*/
#if 1
    struct ospf6_interface *oi = on->ospf6_if;
    if (oi->hello_interval_bak != 0)
    {
        oi->hello_interval = oi->hello_interval_bak;
        oi->hello_interval_bak = 0;

        if (oi->thread_send_hello)
            THREAD_OFF (oi->thread_send_hello);

        oi->thread_send_hello =
            thread_add_event (master, ospf6_hello_send, oi, oi->hello_interval);
        zlog_debug("recover hello message sending interval:%d.\n", oi->hello_interval);

    }
#endif

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
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on,
                                     OSPF6_NEIGHBOR_EVENT_ADJ_OK);
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
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_TWOWAY, on,
                                     OSPF6_NEIGHBOR_EVENT_ADJ_OK);
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
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on,
                                 OSPF6_NEIGHBOR_EVENT_SEQNUMBER_MISMATCH);
#if 1
    /*add for OSPF+ */
    if (on->leaving_exchange_state == 1)
    {
        zlog_debug("%s()%d will del exchange to exstart timer, time:30s.", __func__, __LINE__);
        THREAD_OFF (on->exchange_to_exstart_timer);

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
    on->dbdesc_seqnum++;		/* Incr seqnum as per RFC2328, sec 10.3 */

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

    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_EXSTART, on,
                                 OSPF6_NEIGHBOR_EVENT_BAD_LSREQ);
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
    on->dbdesc_seqnum++;		/* Incr seqnum as per RFC2328, sec 10.3 */

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

    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_INIT, on,
                                 OSPF6_NEIGHBOR_EVENT_ONEWAY_RCVD);
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
        /*del inactivity timer*/
        THREAD_OFF (on->inactivity_timer);

#ifdef OSPF6_DEBUG
        zlog_debug("change neighbor state to LEAVING, add circle period timer,neighbor ipv6 string:%s", ipv6_string);
#endif
        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LEAVING, on, OSPF6_NEIGHBOR_EVENT_INACTIVITY_TIMER);
        on->inactivity_timer_state = 1;
        on->ospf6_if->reference_count++;
        ospf6_neighbor_delete_for_leaving (on);

        if (on->circle_period == 0)
            on->circle_period_timer = thread_add_timer (master, circle_period_timer, on, INIT_CIRCLE_PERIOD);
        else
            /*add circle period timer */
            on->circle_period_timer = thread_add_timer (master, circle_period_timer, on, on->circle_period);
    }
    else
#endif
    {
        on->drouter = on->prev_drouter = 0;
        on->bdrouter = on->prev_bdrouter = 0;

        ospf6_neighbor_state_change (OSPF6_NEIGHBOR_DOWN, on,
                                     OSPF6_NEIGHBOR_EVENT_INACTIVITY_TIMER);
        thread_add_event (master, neighbor_change, on->ospf6_if, 0);

        listnode_delete (on->ospf6_if->neighbor_list, on);
        ospf6_neighbor_delete (on);
    }

    return 0;
}

int inactivity_timer_2 (struct thread *thread)
{

    struct ospf6_neighbor *on;
    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (on->state != OSPF6_NEIGHBOR_FULL)
        return 0;

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *InactivityTimer2*", on->name);

    /*change the neighbor state to Leaving */
    zlog_debug("inactivity timer 2 is active, change neighbor state to LEAVING, ifname:%s", on->ospf6_if->interface->name);
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_LEAVING, on, OSPF6_NEIGHBOR_EVENT_LEAVING);

    /*202003 del hello send thread*/
    THREAD_OFF (on->ospf6_if->thread_send_hello);

    zlog_debug("ospf6 neighbor state must be LEAVING, now is:%s", ospf6_neighbor_state_str[on->state]);
    /*leaving reference count + 1 */
    on->ospf6_if->reference_count++;

    zlog_debug("reference_count:%d", on->ospf6_if->reference_count);

    ospf6_neighbor_delete_for_leaving (on);

    zlog_debug("empty list, del thread, add circle period timer");
    /*add circle period timer */
    on->circle_period_timer = thread_add_timer (master, circle_period_timer, on, on->circle_period);
    //on->inactivity_timer_2_state = 0;

    on->inactivity_timer_2 = NULL;
    THREAD_OFF (on->inactivity_timer_2);

    return 0;
}

//add  202003
int speed_up_hello_msg_detection_timer (struct thread *thread)
{
    struct ospf6_neighbor *on;

    on = (struct ospf6_neighbor *) THREAD_ARG (thread);
    assert (on);

    if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        zlog_debug ("Neighbor Event %s: *speed up hello msg detection timer*", on->name);

    zlog_debug("%f speed up hello msg detection timer is active", seconds_from_morning());
    on->speed_up_hello_msg_detection_timer = NULL;
    /*del inactivity timer */
    if (on->inactivity_timer)
        THREAD_OFF (on->inactivity_timer);
    /*Change and backup Hello message sending interval*/
    on->ospf6_if->hello_interval_bak = on->ospf6_if->hello_interval;
    on->ospf6_if->hello_interval = MIN_HELLO_DETECTION_TIME;

    /*Delete Hello message sending thread and add new Hello message sending thread*/
    THREAD_OFF (on->ospf6_if->thread_send_hello);
    on->ospf6_if->thread_send_hello =
        thread_add_event (master, ospf6_hello_send, on->ospf6_if, on->ospf6_if->hello_interval);
#if 0
    /*add for test (ip6tables)*/
    printf(">>>>>>>>will add ip6tables.\n");
    char *cmd = "ip6tables -A OUTPUT -d ff02::5 -j DROP";
    system(cmd);
#endif
    on->inactivity_timer_2 = thread_add_timer (master, inactivity_timer_2, on, DEAD_INTERVAL_2);
    on->inactivity_timer_2_state = 1;

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
    ospf6_neighbor_state_change (OSPF6_NEIGHBOR_DOWN, on, OSPF6_NEIGHBOR_EVENT_CIRCLE_PERIOD_TIMER);
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
    else if (on->inactivity_timer_2)
    {
        s = on->inactivity_timer_2->u.sands.tv_sec - recent_relative_time().tv_sec;
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

#if 1
    vty_out (vty, "    Lsnewlsas-List: %d LSAs%s", on->ospf6_if->new_lsas_list->count,
             VNL);
    for (lsa = ospf6_lsdb_head (on->ospf6_if->new_lsas_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);
#endif

#if 1
    vty_out (vty, "    >>>Lsexpire-List: %d LSAs%s", on->lsexpire_list->count,
             VNL);
    for (lsa = ospf6_lsdb_head (on->lsexpire_list); lsa;
            lsa = ospf6_lsdb_next (lsa))
        vty_out (vty, "      %s%s", lsa->name, VNL);
#endif

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
             on->request_list->count, duration,
             (on->thread_send_lsreq ? "on" : "off"),
             VNL);
    for (lsa = ospf6_lsdb_head (on->request_list); lsa;
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
static void ospf6_neighbor_show_period(struct vty *vty, struct ospf6_neighbor *on)
{
    float seconds;
    char ipv6_string[128];

    float diff_connection;
    if (on == NULL)
        return;
    //link local address, connection periond,  circle period, state, remaining connection/circle period
    memset (ipv6_string, 0, sizeof (ipv6_string));
    inet_ntop (AF_INET6, &on->linklocal_addr, ipv6_string, sizeof (ipv6_string));


    seconds = seconds_from_morning ();
    if (on->connection_period > 0)
    {
        if (seconds < on->end_time)
            diff_connection = on->connection_period - (seconds - on->start_time);
        else
            diff_connection = 0;
    }
    else
        diff_connection = 0;

    vty_out(vty, "peer link local address:%s%s", ipv6_string, VNL);
    vty_out(vty, "neighbor connection period:%f%s", on->connection_period, VNL);
    vty_out(vty, "neighbor circle period:%f%s", on->circle_period, VNL);
    if (diff_connection > 0)
        vty_out(vty, "remaining connection period :%f%s", diff_connection, VNL);
    else
    {
        if (on->circle_period == 0)
        {
            vty_out(vty, "connection period, circle period don't recv%s", VNL);
        }
        else
        {
            diff_connection = on->circle_period - (seconds - on->start_time);
            vty_out(vty, "remaining circle period :%f%s", diff_connection, VNL);
        }
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

    for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, i, oa))
        for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
            for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
                (*showfunc) (vty, on);

    return CMD_SUCCESS;
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
