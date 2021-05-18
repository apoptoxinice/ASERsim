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

#include <zebra.h>


#include "if.h"
#include "log.h"
#include "vty.h"
#include "memory.h"
#include "prefix.h"

#include "pimd.h"
#include "pim_iface.h"
#include "pim_igmp.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_pim.h"
#include "pim_neighbor.h"
#include "pim_ifchannel.h"
#include "pim_rand.h"
#include "pim_sock.h"
#include "pim_time.h"
#include "pim_ssmpingd.h"

#include "pimsm_define.h"
#if INCLUDE_PIMSM
//extern
extern struct pimsm_interface_entry *g_pimsm_interface_list;
extern uint8_t g_root_cbsr_ifindex;
extern struct pimsm_encoded_unicast_addr g_root_cbsr_id;
extern struct hash *g_group_hash;
#include "pimsm_mrtmgt.h"
#endif

static void pim_if_igmp_join_del_all(struct interface *ifp);

void pim_if_init()
{
    if_init();
}

static void *if_list_clean(struct pim_interface *pim_ifp)
{
    if (pim_ifp->igmp_join_list)
    {
        list_delete(pim_ifp->igmp_join_list);
    }

    if (pim_ifp->igmp_socket_list)
    {
        list_delete(pim_ifp->igmp_socket_list);
    }

    if (pim_ifp->pim_neighbor_list)
    {
        list_delete(pim_ifp->pim_neighbor_list);
    }

    if (pim_ifp->pim_ifchannel_list)
    {
        list_delete(pim_ifp->pim_ifchannel_list);
    }

    XFREE(MTYPE_PIM_INTERFACE, pim_ifp);

    return 0;
}

struct pim_interface *pim_if_new(struct interface *ifp, int igmp, int pim)
{
    struct pim_interface *pim_ifp;

    zassert(ifp);
    zassert(!ifp->info);

    pim_ifp = XMALLOC(MTYPE_PIM_INTERFACE, sizeof(*pim_ifp));
    if (!pim_ifp)
    {
        zlog_err("PIM XMALLOC(%zu) failure", sizeof(*pim_ifp));
        return 0;
    }

    pim_ifp->options                           = 0;
    pim_ifp->mroute_vif_index                  = -1;

    pim_ifp->igmp_default_robustness_variable           = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
    pim_ifp->igmp_default_query_interval                = IGMP_GENERAL_QUERY_INTERVAL;
    pim_ifp->igmp_query_max_response_time_dsec          = IGMP_QUERY_MAX_RESPONSE_TIME_DSEC;
    pim_ifp->igmp_specific_query_max_response_time_dsec = IGMP_SPECIFIC_QUERY_MAX_RESPONSE_TIME_DSEC;

    /*
      RFC 3376: 8.3. Query Response Interval
      The number of seconds represented by the [Query Response Interval]
      must be less than the [Query Interval].
     */
    zassert(pim_ifp->igmp_query_max_response_time_dsec < pim_ifp->igmp_default_query_interval);

    if (pim)
        PIM_IF_DO_PIM(pim_ifp->options);
    if (igmp)
        PIM_IF_DO_IGMP(pim_ifp->options);

#if 0
    /* FIXME: Should join? */
    PIM_IF_DO_IGMP_LISTEN_ALLROUTERS(pim_ifp->options);
#endif

    pim_ifp->igmp_join_list = 0;
    pim_ifp->igmp_socket_list = 0;
    pim_ifp->pim_neighbor_list = 0;
    pim_ifp->pim_ifchannel_list = 0;

    /* list of struct igmp_sock */
    pim_ifp->igmp_socket_list = list_new();
    if (!pim_ifp->igmp_socket_list)
    {
        zlog_err("%s %s: failure: igmp_socket_list=list_new()",
                 __FILE__, __PRETTY_FUNCTION__);
        return if_list_clean(pim_ifp);
    }
    pim_ifp->igmp_socket_list->del = (void (*)(void *)) igmp_sock_free;

    /* list of struct pim_neighbor */
    pim_ifp->pim_neighbor_list = list_new();
    if (!pim_ifp->pim_neighbor_list)
    {
        zlog_err("%s %s: failure: pim_neighbor_list=list_new()",
                 __FILE__, __PRETTY_FUNCTION__);
        return if_list_clean(pim_ifp);
    }
    pim_ifp->pim_neighbor_list->del = (void (*)(void *)) pim_neighbor_free;

    /* list of struct pim_ifchannel */
    pim_ifp->pim_ifchannel_list = list_new();
    if (!pim_ifp->pim_ifchannel_list)
    {
        zlog_err("%s %s: failure: pim_ifchannel_list=list_new()",
                 __FILE__, __PRETTY_FUNCTION__);
        return if_list_clean(pim_ifp);
    }
    pim_ifp->pim_ifchannel_list->del = (void (*)(void *)) pim_ifchannel_free;

    ifp->info = pim_ifp;

    pim_sock_reset(ifp);

    zassert(PIM_IF_TEST_PIM(pim_ifp->options) || PIM_IF_TEST_IGMP(pim_ifp->options));

    if (PIM_MROUTE_IS_ENABLED)
    {
        pim_if_add_vif(ifp);
    }

    return pim_ifp;
}

void pim_if_delete(struct interface *ifp)
{
    struct pim_interface *pim_ifp;

    zassert(ifp);
    pim_ifp = ifp->info;
    zassert(pim_ifp);

    if (pim_ifp->igmp_join_list)
    {
        pim_if_igmp_join_del_all(ifp);
    }
    zassert(!pim_ifp->igmp_join_list);

    zassert(pim_ifp->igmp_socket_list);
    zassert(!listcount(pim_ifp->igmp_socket_list));

    zassert(pim_ifp->pim_neighbor_list);
    zassert(!listcount(pim_ifp->pim_neighbor_list));

    zassert(pim_ifp->pim_ifchannel_list);
    zassert(!listcount(pim_ifp->pim_ifchannel_list));

    if (PIM_MROUTE_IS_ENABLED)
    {
        pim_if_del_vif(ifp);
    }

    list_delete(pim_ifp->igmp_socket_list);
    list_delete(pim_ifp->pim_neighbor_list);
    list_delete(pim_ifp->pim_ifchannel_list);

    XFREE(MTYPE_PIM_INTERFACE, pim_ifp);

    ifp->info = 0;
}

void pim_if_update_could_assert(struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct listnode      *node;
    struct listnode      *next_node;
    struct pim_ifchannel *ch;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, node, next_node, ch))
    {
        pim_ifchannel_update_could_assert(ch);
    }
}

static void pim_if_update_my_assert_metric(struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct listnode      *node;
    struct listnode      *next_node;
    struct pim_ifchannel *ch;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, node, next_node, ch))
    {
        pim_ifchannel_update_my_assert_metric(ch);
    }
}

static void pim_addr_change(struct interface *ifp)
{
    struct pim_interface *pim_ifp;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    pim_if_dr_election(ifp); /* router's own DR Priority (addr) changes -- Done TODO T30 */
    pim_if_update_join_desired(pim_ifp); /* depends on DR */
    pim_if_update_could_assert(ifp); /* depends on DR */
    pim_if_update_my_assert_metric(ifp); /* depends on could_assert */
    pim_if_update_assert_tracking_desired(ifp); /* depends on DR, join_desired */

    /*
      RFC 4601: 4.3.1.  Sending Hello Messages

      1) Before an interface goes down or changes primary IP address, a
      Hello message with a zero HoldTime should be sent immediately
      (with the old IP address if the IP address changed).
      -- FIXME See CAVEAT C13

      2) After an interface has changed its IP address, it MUST send a
      Hello message with its new IP address.
      -- DONE below

      3) If an interface changes one of its secondary IP addresses, a
      Hello message with an updated Address_List option and a non-zero
      HoldTime should be sent immediately.
      -- FIXME See TODO T31
     */
    pim_ifp->pim_ifstat_hello_sent = 0; /* reset hello counter */
    if (pim_ifp->pim_sock_fd < 0)
        return;
    pim_hello_restart_now(ifp);         /* send hello and restart timer */
}

static void on_primary_address_change(struct interface *ifp,
                                      const char *caller,
                                      struct in_addr old_addr,
                                      struct in_addr new_addr)
{
    struct pim_interface *pim_ifp;

    {
        char old_str[100];
        char new_str[100];
        pim_inet4_dump("<old?>", old_addr, old_str, sizeof(old_str));
        pim_inet4_dump("<new?>", new_addr, new_str, sizeof(new_str));
        zlog_info("%s: %s: primary address changed from %s to %s on interface %s",
                  __PRETTY_FUNCTION__, caller,
                  old_str, new_str, ifp->name);
    }

    pim_ifp = ifp->info;
    if (!pim_ifp)
    {
        return;
    }

    if (!PIM_IF_TEST_PIM(pim_ifp->options))
    {
        return;
    }

    pim_addr_change(ifp);
}

static int detect_primary_address_change(struct interface *ifp,
        int force_prim_as_any,
        const char *caller)
{
    struct pim_interface *pim_ifp;
    struct in_addr new_prim_addr;
    int changed;

    pim_ifp = ifp->info;
    if (!pim_ifp)
        return 0;

    if (force_prim_as_any)
        new_prim_addr = qpim_inaddr_any;
    else
        new_prim_addr = pim_find_primary_addr(ifp);

    changed = new_prim_addr.s_addr != pim_ifp->primary_address.s_addr;

    if (PIM_DEBUG_ZEBRA)
    {
        char new_prim_str[100];
        char old_prim_str[100];
        pim_inet4_dump("<new?>", new_prim_addr, new_prim_str, sizeof(new_prim_str));
        pim_inet4_dump("<old?>", pim_ifp->primary_address, old_prim_str, sizeof(old_prim_str));
        zlog_debug("%s: old=%s new=%s on interface %s: %s",
                   __PRETTY_FUNCTION__,
                   old_prim_str, new_prim_str, ifp->name,
                   changed ? "changed" : "unchanged");
    }

    if (changed)
    {
        struct in_addr old_addr = pim_ifp->primary_address;
        pim_ifp->primary_address = new_prim_addr;

        on_primary_address_change(ifp, caller, old_addr, new_prim_addr);
    }

    return changed;
}

static void detect_secondary_address_change(struct interface *ifp,
        const char *caller)
{
    struct pim_interface *pim_ifp;
    int changed;

    pim_ifp = ifp->info;
    if (!pim_ifp)
        return;

    changed = 1; /* true */
    zlog_debug("FIXME T31 C15 %s: on interface %s: acting on any addr change",
               __PRETTY_FUNCTION__, ifp->name);

    if (PIM_DEBUG_ZEBRA)
    {
        zlog_debug("%s: on interface %s: %s",
                   __PRETTY_FUNCTION__,
                   ifp->name, changed ? "changed" : "unchanged");
    }

    if (!changed)
    {
        return;
    }

    if (!PIM_IF_TEST_PIM(pim_ifp->options))
    {
        return;
    }

    pim_addr_change(ifp);
}

static void detect_address_change(struct interface *ifp,
                                  int force_prim_as_any,
                                  const char *caller)
{
    int prim_changed;

    prim_changed = detect_primary_address_change(ifp, force_prim_as_any, caller);
    if (prim_changed)
    {
        /* no need to detect secondary change because
           the reaction would be the same */
        return;
    }

    detect_secondary_address_change(ifp, caller);
}

void pim_if_addr_add(struct connected *ifc)
{
    struct pim_interface *pim_ifp;
    struct interface *ifp;
    struct in_addr ifaddr;

    zassert(ifc);

    ifp = ifc->ifp;
    zassert(ifp);
    pim_ifp = ifp->info;
    if (!pim_ifp)
        return;

    if (!if_is_operative(ifp))
        return;

    /* if (PIM_DEBUG_ZEBRA) */
    {
        char buf[BUFSIZ];
        prefix2str(ifc->address, buf, BUFSIZ);
        zlog_debug("%s: %s ifindex=%d connected IP address %s %s",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, buf,
                   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ?
                   "secondary" : "primary");
    }

    ifaddr = ifc->address->u.prefix4;

    detect_address_change(ifp, 0, __PRETTY_FUNCTION__);

    if (PIM_IF_TEST_IGMP(pim_ifp->options))
    {
        struct igmp_sock *igmp;

        /* lookup IGMP socket */
        igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->igmp_socket_list,
                                           ifaddr);
        if (!igmp)
        {
            /* if addr new, add IGMP socket */
            pim_igmp_sock_add(pim_ifp->igmp_socket_list, ifaddr, ifp);
        }
    } /* igmp */

    if (PIM_IF_TEST_PIM(pim_ifp->options))
    {

        /* Interface has a valid primary address ? */
        if (PIM_INADDR_ISNOT_ANY(pim_ifp->primary_address))
        {

            /* Interface has a valid socket ? */
            if (pim_ifp->pim_sock_fd < 0)
            {
                if (pim_sock_add(ifp))
                {
                    zlog_warn("Failure creating PIM socket for interface %s",
                              ifp->name);
                }
            }

        }
    } /* pim */

    if (PIM_MROUTE_IS_ENABLED)
    {
        /*
          PIM or IGMP is enabled on interface, and there is at least one
          address assigned, then try to create a vif_index.
        */
        if (pim_ifp->mroute_vif_index < 0)
        {
            pim_if_add_vif(ifp);
        }
    }
}

static void pim_if_addr_del_igmp(struct connected *ifc)
{
    struct pim_interface *pim_ifp = ifc->ifp->info;
    struct igmp_sock *igmp;
    struct in_addr ifaddr;

    if (ifc->address->family != AF_INET)
    {
        /* non-IPv4 address */
        return;
    }

    if (!pim_ifp)
    {
        /* IGMP not enabled on interface */
        return;
    }

    ifaddr = ifc->address->u.prefix4;

    /* lookup IGMP socket */
    igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->igmp_socket_list,
                                       ifaddr);
    if (igmp)
    {
        /* if addr found, del IGMP socket */
        igmp_sock_delete(igmp);
    }
}

static void pim_if_addr_del_pim(struct connected *ifc)
{
    struct pim_interface *pim_ifp = ifc->ifp->info;

    if (ifc->address->family != AF_INET)
    {
        /* non-IPv4 address */
        return;
    }

    if (!pim_ifp)
    {
        /* PIM not enabled on interface */
        return;
    }

    if (PIM_INADDR_ISNOT_ANY(pim_ifp->primary_address))
    {
        /* Interface keeps a valid primary address */
        return;
    }

    if (pim_ifp->pim_sock_fd < 0)
    {
        /* Interface does not hold a valid socket any longer */
        return;
    }

    /*
      pim_sock_delete() closes the socket, stops read and timer threads,
      and kills all neighbors.
     */
    pim_sock_delete(ifc->ifp, "last address has been removed from interface");
}

void pim_if_addr_del(struct connected *ifc, int force_prim_as_any)
{
    struct interface *ifp;

    zassert(ifc);
    ifp = ifc->ifp;
    zassert(ifp);

    /* if (PIM_DEBUG_ZEBRA) */
    {
        char buf[BUFSIZ];
        prefix2str(ifc->address, buf, BUFSIZ);
        zlog_debug("%s: %s ifindex=%d disconnected IP address %s %s",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, buf,
                   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ?
                   "secondary" : "primary");
    }

    detect_address_change(ifp, force_prim_as_any, __PRETTY_FUNCTION__);

    pim_if_addr_del_igmp(ifc);
    pim_if_addr_del_pim(ifc);
}

void pim_if_addr_add_all(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;

    /* PIM/IGMP enabled ? */
    if (!ifp->info)
        return;

    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pim_if_addr_add(ifc);
    }
}

void pim_if_addr_del_all(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;

    /* PIM/IGMP enabled ? */
    if (!ifp->info)
        return;

    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pim_if_addr_del(ifc, 1 /* force_prim_as_any=true */);
    }
}

void pim_if_addr_del_all_igmp(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;

    /* PIM/IGMP enabled ? */
    if (!ifp->info)
        return;

    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pim_if_addr_del_igmp(ifc);
    }
}

void pim_if_addr_del_all_pim(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;

    /* PIM/IGMP enabled ? */
    if (!ifp->info)
        return;

    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pim_if_addr_del_pim(ifc);
    }
}

static struct in_addr find_first_nonsec_addr(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct in_addr addr;

    for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        if (PIM_INADDR_IS_ANY(p->u.prefix4))
        {
            zlog_warn("%s: null IPv4 address connected to interface %s",
                      __PRETTY_FUNCTION__, ifp->name);
            continue;
        }

        if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
            continue;

        return p->u.prefix4;
    }

    addr.s_addr = PIM_NET_INADDR_ANY;

    return addr;
}

struct in_addr pim_find_primary_addr(struct interface *ifp)
{
    return find_first_nonsec_addr(ifp);
}

/*
  pim_if_add_vif() uses ifindex as vif_index

  see also pim_if_find_vifindex_by_ifindex()
 */
int pim_if_add_vif(struct interface *ifp)
{
    struct pim_interface *pim_ifp = ifp->info;
    struct in_addr ifaddr;
    struct pimsm_interface_entry *pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);

    zassert(pim_ifp);

    if (pim_ifp->mroute_vif_index > 0)
    {
        zlog_warn("%s: vif_index=%d > 0 on interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  pim_ifp->mroute_vif_index, ifp->name, ifp->ifindex);
        return -1;
    }

    if (ifp->ifindex < 1)
    {
        zlog_warn("%s: ifindex=%d < 1 on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->ifindex, ifp->name);
        return -2;
    }

    if (ifp->ifindex >= MAXVIFS)
    {
        zlog_warn("%s: ifindex=%d >= MAXVIFS=%d on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->ifindex, MAXVIFS, ifp->name);
        return -3;
    }

    ifaddr = pim_ifp->primary_address;
    if (PIM_INADDR_IS_ANY(ifaddr))
    {
        zlog_warn("%s: could not get address for interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  ifp->name, ifp->ifindex);
        return -4;
    }

    if(pimsm_ifp == NULL || pimsm_ifp->mroute_vif_index <= 0)
    {
        if (pim_mroute_add_vif(ifp->ifindex, ifaddr))
        {
            /* pim_mroute_add_vif reported error */
            return -5;
        }
    }

    pim_ifp->mroute_vif_index = ifp->ifindex;

    /*
      Update highest vif_index
     */
    if (pim_ifp->mroute_vif_index > qpim_mroute_oif_highest_vif_index)
    {
        qpim_mroute_oif_highest_vif_index = pim_ifp->mroute_vif_index;
    }

    return 0;
}


static int iflist_find_highest_vif_index()
{
    struct listnode      *ifnode;
    struct interface     *ifp;
    struct pim_interface *pim_ifp;
    int                   highest_vif_index = -1;

    for (ALL_LIST_ELEMENTS_RO(iflist, ifnode, ifp))
    {
        pim_ifp = ifp->info;
        if (!pim_ifp)
            continue;

        if (pim_ifp->mroute_vif_index > highest_vif_index)
        {
            highest_vif_index = pim_ifp->mroute_vif_index;
        }
    }

    return highest_vif_index;
}

int pim_if_del_vif(struct interface *ifp)
{
    struct pim_interface *pim_ifp = ifp->info;
    int old_vif_index;

    if (pim_ifp->mroute_vif_index < 1)
    {
        zlog_warn("%s: vif_index=%d < 1 on interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  pim_ifp->mroute_vif_index, ifp->name, ifp->ifindex);
        return -1;
    }

    if (pim_mroute_del_vif(pim_ifp->mroute_vif_index))
    {
        /* pim_mroute_del_vif reported error */
        return -2;
    }

    /*
      Update highest vif_index
     */

    /* save old vif_index in order to compare with highest below */
    old_vif_index = pim_ifp->mroute_vif_index;

    pim_ifp->mroute_vif_index = -1;

    if (old_vif_index == qpim_mroute_oif_highest_vif_index)
    {
        qpim_mroute_oif_highest_vif_index = iflist_find_highest_vif_index();
    }

    return 0;
}

void pim_if_add_vif_all()
{
    struct listnode  *ifnode;
    struct listnode  *ifnextnode;
    struct interface *ifp;

    for (ALL_LIST_ELEMENTS(iflist, ifnode, ifnextnode, ifp))
    {
        if (!ifp->info)
            continue;

        pim_if_add_vif(ifp);
    }
}

void pim_if_del_vif_all()
{
    struct listnode  *ifnode;
    struct listnode  *ifnextnode;
    struct interface *ifp;

    for (ALL_LIST_ELEMENTS(iflist, ifnode, ifnextnode, ifp))
    {
        if (!ifp->info)
            continue;

        pim_if_del_vif(ifp);
    }
}

struct interface *pim_if_find_by_vif_index(int vif_index)
{
    struct listnode  *ifnode;
    struct interface *ifp;

    for (ALL_LIST_ELEMENTS_RO(iflist, ifnode, ifp))
    {
        if (ifp->info)
        {
            struct pim_interface *pim_ifp;
            pim_ifp = ifp->info;
            if (vif_index == pim_ifp->mroute_vif_index)
                return ifp;
        }
    }

    return 0;
}

/*
  pim_if_add_vif() uses ifindex as vif_index
 */
int pim_if_find_vifindex_by_ifindex(int ifindex)
{
    return ifindex;
}

int pim_if_lan_delay_enabled(struct interface *ifp)
{
    struct pim_interface *pim_ifp;

    pim_ifp = ifp->info;
    zassert(pim_ifp);
    zassert(pim_ifp->pim_number_of_nonlandelay_neighbors >= 0);

    return pim_ifp->pim_number_of_nonlandelay_neighbors == 0;
}

uint16_t pim_if_effective_propagation_delay_msec(struct interface *ifp)
{
    if (pim_if_lan_delay_enabled(ifp))
    {
        struct pim_interface *pim_ifp;
        pim_ifp = ifp->info;
        return pim_ifp->pim_neighbors_highest_propagation_delay_msec;
    }
    else
    {
        return PIM_DEFAULT_PROPAGATION_DELAY_MSEC;
    }
}

uint16_t pim_if_effective_override_interval_msec(struct interface *ifp)
{
    if (pim_if_lan_delay_enabled(ifp))
    {
        struct pim_interface *pim_ifp;
        pim_ifp = ifp->info;
        return pim_ifp->pim_neighbors_highest_override_interval_msec;
    }
    else
    {
        return PIM_DEFAULT_OVERRIDE_INTERVAL_MSEC;
    }
}

int pim_if_t_override_msec(struct interface *ifp)
{
    int effective_override_interval_msec;
    int t_override_msec;

    effective_override_interval_msec =
        pim_if_effective_override_interval_msec(ifp);

    t_override_msec = pim_rand_next(0, effective_override_interval_msec);

    return t_override_msec;
}

uint16_t pim_if_jp_override_interval_msec(struct interface *ifp)
{
    return pim_if_effective_propagation_delay_msec(ifp) +
           pim_if_effective_override_interval_msec(ifp);
}

/*
  RFC 4601: 4.1.6.  State Summarization Macros

  The function NBR( I, A ) uses information gathered through PIM Hello
  messages to map the IP address A of a directly connected PIM
  neighbor router on interface I to the primary IP address of the same
  router (Section 4.3.4).  The primary IP address of a neighbor is the
  address that it uses as the source of its PIM Hello messages.
*/
struct pim_neighbor *pim_if_find_neighbor(struct interface *ifp,
        struct in_addr addr)
{
    struct listnode *neighnode;
    struct pim_neighbor *neigh;
    struct pim_interface *pim_ifp;

    zassert(ifp);

    pim_ifp = ifp->info;
    if (!pim_ifp)
    {
        zlog_warn("%s: multicast not enabled on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->name);
        return 0;
    }

    for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode, neigh))
    {

        /* primary address ? */
        if (neigh->source_addr.s_addr == addr.s_addr)
            return neigh;

        /* secondary address ? */
        if (pim_neighbor_find_secondary(neigh, addr))
            return neigh;
    }

    if (PIM_DEBUG_PIM_TRACE)
    {
        char addr_str[100];
        pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
        zlog_debug("%s: neighbor not found for address %s on interface %s",
                   __PRETTY_FUNCTION__,
                   addr_str, ifp->name);
    }

    return 0;
}

long pim_if_t_suppressed_msec(struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    long t_suppressed_msec;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    /* join suppression disabled ? */
    if (PIM_IF_TEST_PIM_CAN_DISABLE_JOIN_SUPRESSION(pim_ifp->options))
        return 0;

    /* t_suppressed = t_periodic * rand(1.1, 1.4) */

    t_suppressed_msec = qpim_t_periodic * pim_rand_next(1100, 1400);

    return t_suppressed_msec;
}

static void igmp_join_free(struct igmp_join *ij)
{
    XFREE(MTYPE_PIM_IGMP_JOIN, ij);
}

static struct igmp_join *igmp_join_find(struct list *join_list,
                                        struct in_addr group_addr,
                                        struct in_addr source_addr)
{
    struct listnode *node;
    struct igmp_join *ij;

    zassert(join_list);

    for (ALL_LIST_ELEMENTS_RO(join_list, node, ij))
    {
        if ((group_addr.s_addr == ij->group_addr.s_addr) &&
                (source_addr.s_addr == ij->source_addr.s_addr))
            return ij;
    }

    return 0;
}

static int igmp_join_sock(const char *ifname,
                          int ifindex,
                          struct in_addr group_addr,
                          struct in_addr source_addr)
{
    int join_fd;

    join_fd = pim_socket_raw(IPPROTO_IGMP);
    if (join_fd < 0)
    {
        return -1;
    }

    if (pim_socket_join_source(join_fd, ifindex, group_addr, source_addr, ifname))
    {
        close(join_fd);
        return -2;
    }

    return join_fd;
}

static struct igmp_join *igmp_join_new(struct interface *ifp,
                                       struct in_addr group_addr,
                                       struct in_addr source_addr)
{
    struct pim_interface *pim_ifp;
    struct igmp_join *ij;
    int join_fd;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    join_fd = igmp_join_sock(ifp->name, ifp->ifindex, group_addr, source_addr);
    if (join_fd < 0)
    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_warn("%s: igmp_join_sock() failure for IGMP group %s source %s on interface %s",
                  __PRETTY_FUNCTION__,
                  group_str, source_str, ifp->name);
        return 0;
    }

    ij = XMALLOC(MTYPE_PIM_IGMP_JOIN, sizeof(*ij));
    if (!ij)
    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_err("%s: XMALLOC(%zu) failure for IGMP group %s source %s on interface %s",
                 __PRETTY_FUNCTION__,
                 sizeof(*ij), group_str, source_str, ifp->name);
        close(join_fd);
        return 0;
    }

    ij->sock_fd       = join_fd;
    ij->group_addr    = group_addr;
    ij->source_addr   = source_addr;
    ij->sock_creation = pim_time_monotonic_sec();

    listnode_add(pim_ifp->igmp_join_list, ij);

    return ij;
}

int pim_if_igmp_join_add(struct interface *ifp,
                         struct in_addr group_addr,
                         struct in_addr source_addr)
{
    struct pim_interface *pim_ifp;
    struct igmp_join *ij;

    pim_ifp = ifp->info;
    if (!pim_ifp)
    {
        zlog_warn("%s: multicast not enabled on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->name);
        return -1;
    }

    if (!pim_ifp->igmp_join_list)
    {
        pim_ifp->igmp_join_list = list_new();
        if (!pim_ifp->igmp_join_list)
        {
            zlog_err("%s %s: failure: igmp_join_list=list_new()",
                     __FILE__, __PRETTY_FUNCTION__);
            return -2;
        }
        pim_ifp->igmp_join_list->del = (void (*)(void *)) igmp_join_free;
    }

    ij = igmp_join_find(pim_ifp->igmp_join_list, group_addr, source_addr);
    if (ij)
    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_warn("%s: can't re-join existing IGMP group %s source %s on interface %s",
                  __PRETTY_FUNCTION__,
                  group_str, source_str, ifp->name);
        return -3;
    }

    ij = igmp_join_new(ifp, group_addr, source_addr);
    if (!ij)
    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_warn("%s: igmp_join_new() failure for IGMP group %s source %s on interface %s",
                  __PRETTY_FUNCTION__,
                  group_str, source_str, ifp->name);
        return -4;
    }

    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_debug("%s: issued static igmp join for channel (S,G)=(%s,%s) on interface %s",
                   __PRETTY_FUNCTION__,
                   source_str, group_str, ifp->name);
    }

    return 0;
}



int pim_if_igmp_join_del(struct interface *ifp,
                         struct in_addr group_addr,
                         struct in_addr source_addr)
{
    struct pim_interface *pim_ifp;
    struct igmp_join *ij;

    pim_ifp = ifp->info;
    if (!pim_ifp)
    {
        zlog_warn("%s: multicast not enabled on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->name);
        return -1;
    }

    if (!pim_ifp->igmp_join_list)
    {
        zlog_warn("%s: no IGMP join on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->name);
        return -2;
    }

    ij = igmp_join_find(pim_ifp->igmp_join_list, group_addr, source_addr);
    if (!ij)
    {
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_warn("%s: could not find IGMP group %s source %s on interface %s",
                  __PRETTY_FUNCTION__,
                  group_str, source_str, ifp->name);
        return -3;
    }

    if (close(ij->sock_fd))
    {
        int e = errno;
        char group_str[100];
        char source_str[100];
        pim_inet4_dump("<grp?>", group_addr, group_str, sizeof(group_str));
        pim_inet4_dump("<src?>", source_addr, source_str, sizeof(source_str));
        zlog_warn("%s: failure closing sock_fd=%d for IGMP group %s source %s on interface %s: errno=%d: %s",
                  __PRETTY_FUNCTION__,
                  ij->sock_fd, group_str, source_str, ifp->name, e, safe_strerror(e));
        /* warning only */
    }
    listnode_delete(pim_ifp->igmp_join_list, ij);
    igmp_join_free(ij);
    if (listcount(pim_ifp->igmp_join_list) < 1)
    {
        list_delete(pim_ifp->igmp_join_list);
        pim_ifp->igmp_join_list = 0;
    }

    return 0;
}

static void pim_if_igmp_join_del_all(struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct listnode *node;
    struct listnode *nextnode;
    struct igmp_join *ij;

    pim_ifp = ifp->info;
    if (!pim_ifp)
    {
        zlog_warn("%s: multicast not enabled on interface %s",
                  __PRETTY_FUNCTION__,
                  ifp->name);
        return;
    }

    if (!pim_ifp->igmp_join_list)
        return;

    for (ALL_LIST_ELEMENTS(pim_ifp->igmp_join_list, node, nextnode, ij))
        pim_if_igmp_join_del(ifp, ij->group_addr, ij->source_addr);
}

/*
  RFC 4601

  Transitions from "I am Assert Loser" State

  Current Winner's GenID Changes or NLT Expires

  The Neighbor Liveness Timer associated with the current winner
  expires or we receive a Hello message from the current winner
  reporting a different GenID from the one it previously reported.
  This indicates that the current winner's interface or router has
  gone down (and may have come back up), and so we must assume it no
  longer knows it was the winner.
 */
void pim_if_assert_on_neighbor_down(struct interface *ifp,
                                    struct in_addr neigh_addr)
{
    struct pim_interface *pim_ifp;
    struct listnode      *node;
    struct listnode      *next_node;
    struct pim_ifchannel *ch;

    pim_ifp = ifp->info;
    zassert(pim_ifp);

    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, node, next_node, ch))
    {
        /* Is (S,G,I) assert loser ? */
        if (ch->ifassert_state != PIM_IFASSERT_I_AM_LOSER)
            continue;
        /* Dead neighbor was winner ? */
        if (ch->ifassert_winner.s_addr != neigh_addr.s_addr)
            continue;

        assert_action_a5(ch);
    }
}

void pim_if_update_join_desired(struct pim_interface *pim_ifp)
{
    struct listnode      *ch_node;
    struct pim_ifchannel *ch;

    /* clear off flag from interface's upstreams */
    for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_ifchannel_list, ch_node, ch))
    {
        PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(ch->upstream->flags);
    }

    /* scan per-interface (S,G,I) state on this I interface */
    for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_ifchannel_list, ch_node, ch))
    {
        struct pim_upstream *up = ch->upstream;

        if (PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED_UPDATED(up->flags))
            continue;

        /* update join_desired for the global (S,G) state */
        pim_upstream_update_join_desired(up);
        PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(up->flags);
    }
}

void pim_if_update_assert_tracking_desired(struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct listnode      *node;
    struct listnode      *next_node;
    struct pim_ifchannel *ch;

    pim_ifp = ifp->info;
    if (!pim_ifp)
        return;

    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, node, next_node, ch))
    {
        pim_ifchannel_update_assert_tracking_desired(ch);
    }
}
#if INCLUDE_PIMSM
int pimsm_if_find_by_vif_index(int vif_index)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        if (vif_index == pimsm_ifp->mroute_vif_index)
        {
            return pimsm_ifp->mroute_vif_index;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    return 0;
}

static void pimsm_on_primary_address_change(struct interface *ifp,
        const char *caller,
        struct in_addr old_addr,
        struct in_addr new_addr)
{
    struct pimsm_interface_entry *pimsm_ifp;

    {
        char old_str[100];
        char new_str[100];
        pim_inet4_dump("<old?>", old_addr, old_str, sizeof(old_str));
        pim_inet4_dump("<new?>", new_addr, new_str, sizeof(new_str));
        zlog_info("%s: %s: primary address changed from %s to %s on interface %s",
                  __PRETTY_FUNCTION__, caller,
                  old_str, new_str, ifp->name);
    }

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if (!pimsm_ifp)
    {
        return;
    }

#if 0
    if (!PIM_IF_TEST_PIM(pim_ifp->options))
    {
        return;
    }
    //sangmeng FIXME:20190410
    pim_addr_change(ifp);
#endif
}

static int pimsm_detect_primary_address_change(struct interface *ifp,
        int force_prim_as_any,
        const char *caller)
{
    struct pimsm_interface_entry *pimsm_ifp;
    struct in_addr new_prim_addr;
    struct in_addr old_prim_addr;
    int changed;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if (!pimsm_ifp)
        return 0;

    if (force_prim_as_any)
        new_prim_addr = qpim_inaddr_any;
    else
        new_prim_addr = pim_find_primary_addr(ifp);

    changed = new_prim_addr.s_addr != pimsm_ifp->primary_address.u32_addr[0];

    if (PIM_DEBUG_ZEBRA)
    {
        char new_prim_str[100];
        char old_prim_str[100];
        pim_inet4_dump("<new?>", new_prim_addr, new_prim_str, sizeof(new_prim_str));
        old_prim_addr.s_addr = pimsm_ifp->primary_address.u32_addr[0];
        pim_inet4_dump("<old?>", old_prim_addr, old_prim_str, sizeof(old_prim_str));
        zlog_debug("%s: old=%s new=%s on interface %s: %s",
                   __PRETTY_FUNCTION__,
                   old_prim_str, new_prim_str, ifp->name,
                   changed ? "changed" : "unchanged");
    }

    if (changed)
    {
        struct in_addr old_addr;
        old_addr.s_addr = pimsm_ifp->primary_address.u32_addr[0];
        pimsm_ifp->primary_address.u32_addr[0] = new_prim_addr.s_addr;

        pimsm_on_primary_address_change(ifp, caller, old_addr, new_prim_addr);
    }

    return changed;
}

static void pimsm_detect_address_change(struct interface *ifp,
                                        int force_prim_as_any,
                                        const char *caller)
{
    int prim_changed;

    prim_changed = pimsm_detect_primary_address_change(ifp, force_prim_as_any, caller);
    if (prim_changed)
    {
        /* no need to detect secondary change because
           the reaction would be the same */
        return;
    }

#if 0 /*sangmeng FIXME: 20190410*/
    detect_secondary_address_change(ifp, caller);
#endif
}
static int pimsm_if_add_vif(struct pimsm_interface_entry *pimsm_ifp)
{
    struct in_addr ifaddr;

    struct interface *ifp = NULL;
    struct pim_interface *pim_ifp = NULL;

    zassert(pimsm_ifp);

    ifp = if_lookup_by_index(pimsm_ifp->ifindex);
    if(ifp != NULL)
        pim_ifp = ifp->info;

    if (pimsm_ifp->mroute_vif_index > 0)
    {
        zlog_warn("%s: vif_index=%d > 0 on interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  pimsm_ifp->mroute_vif_index, ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->ifindex);
        return -1;
    }

    if (pimsm_ifp->ifindex < 1)
    {
        zlog_warn("%s: ifindex=%d < 1 on interface %s",
                  __PRETTY_FUNCTION__,
                  pimsm_ifp->ifindex, ifindex2ifname(pimsm_ifp->ifindex));
        return -2;
    }

    if (pimsm_ifp->ifindex >= MAXVIFS)
    {
        zlog_warn("%s: ifindex=%d >= MAXVIFS=%d on interface %s",
                  __PRETTY_FUNCTION__,
                  pimsm_ifp->ifindex, MAXVIFS, ifindex2ifname(pimsm_ifp->ifindex));
        return -3;
    }

    ifaddr.s_addr = pimsm_ifp->primary_address.u32_addr[0];

    if (PIM_INADDR_IS_ANY(ifaddr))
    {
        zlog_warn("%s: could not get address for interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->ifindex);
        return -4;
    }

    if(pim_ifp == NULL || pim_ifp->mroute_vif_index <= 0)
    {
        if (pim_mroute_add_vif(pimsm_ifp->ifindex, ifaddr))
        {
            /* pim_mroute_add_vif reported error */
            return -5;
        }
    }

    pimsm_ifp->mroute_vif_index = pimsm_ifp->ifindex;
    /*
      Update highest vif_index
     */
    if (pimsm_ifp->mroute_vif_index > qpim_mroute_oif_highest_vif_index)
    {
        qpim_mroute_oif_highest_vif_index = pimsm_ifp->mroute_vif_index;
    }

    return 0;
}
static int pimsm_if_del_vif(struct pimsm_interface_entry *pimsm_ifp)
{
    int old_vif_index;

    zassert(pimsm_ifp);

    if (pimsm_ifp->mroute_vif_index < 1)
    {
        zlog_warn("%s: vif_index=%d < 1 on interface %s ifindex=%d",
                  __PRETTY_FUNCTION__,
                  pimsm_ifp->mroute_vif_index, ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->ifindex);
        return -1;
    }

    if (pim_mroute_del_vif(pimsm_ifp->mroute_vif_index))
    {
        /* pim_mroute_del_vif reported error */
        return -2;
    }

    /*
      Update highest vif_index
     */

    /* save old vif_index in order to compare with highest below */
    old_vif_index = pimsm_ifp->mroute_vif_index;

    pimsm_ifp->mroute_vif_index = -1;

    if (old_vif_index == qpim_mroute_oif_highest_vif_index)
    {
        qpim_mroute_oif_highest_vif_index = iflist_find_highest_vif_index();
    }

    return 0;
}


void pimsm_if_addr_add(struct connected *ifc)
{
    struct pimsm_interface_entry *pimsm_ifp;
    struct interface *ifp;
    struct in_addr ifaddr;

    zassert(ifc);

    ifp = ifc->ifp;
    zassert(ifp);

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);

    if (!pimsm_ifp)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found, enable pimsm failed!\n", ifp->ifindex, ifp->name);
        return;
    }

    if (!if_is_operative(ifp))
        return;

    /* if (PIM_DEBUG_ZEBRA) */
    {
        char buf[BUFSIZ];
        prefix2str(ifc->address, buf, BUFSIZ);
        zlog_debug("%s: %s ifindex=%d connected IP address %s %s",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, buf,
                   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ?
                   "secondary" : "primary");
    }

    ifaddr = ifc->address->u.prefix4;

    pimsm_detect_address_change(ifp, 0, __PRETTY_FUNCTION__);

    if (VOS_OK != pimsm_Create())
    {
        PIM_DEBUG("Pimsm create invalid , the interface(%d %s) enable pimsm failed!\n", ifp->ifindex, ifp->name);
        return;
    }
    if ((0 == (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)) && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP)))
    {
        struct in_addr addr;
        addr.s_addr = pimsm_ifp->primary_address.u32_addr[0];
        /* Interface has a valid socket ? */
        if (PIM_INADDR_ISNOT_ANY(addr))
        {
            if (pimsm_ifp->pimsm_sock_fd < 0)
            {
                if (pimsm_sock_add(pimsm_ifp))
                {
                    zlog_warn("Failure creating PIM socket for interface %s",
                              ifp->name);
                }
                pimsm_IfStart(ifp->ifindex);
            }
        }
        PIM_DEBUG("pimsm create socket for interface %s success, socket:%d.\n", ifp->name, pimsm_ifp->pimsm_sock_fd);
        if (PIM_MROUTE_IS_ENABLED)
        {
            /*
              PIM or IGMP is enabled on interface, and there is at least one
              address assigned, then try to create a vif_index.
             */
            if (pimsm_ifp->mroute_vif_index < 0)
            {
                pimsm_if_add_vif(pimsm_ifp);
            }
        }
    }

    if (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
    {
        PIM_DEBUG("interface(%d %s) enable pimsm ok.\n", ifp->ifindex, ifp->name);
    }
    else
    {
        PIM_DEBUG("interface(%d %s) is already enable pimsm.\n", ifp->ifindex, ifp->name);
    }
    pimsm_ifp->options |= PIMSM_IF_FLAG_ENABLE;

    return;
}


void pimsm_if_addr_add_all(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if (!pimsm_ifp)
    {
        PIM_DEBUG("PIMSM creat interface(%d %s) fail.\n", ifp->ifindex, ifp->name);
        return ;
    }


    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pimsm_if_addr_add(ifc);
    }
    if(g_root_cbsr_ifindex == pimsm_ifp->ifindex)
    {

        g_root_cbsr_id.unicast_addr.u32_addr[0] = pimsm_ifp->primary_address.u32_addr[0];
    }
}
static void pimsm_if_addr_del_pim(struct connected *ifc)
{
    struct in_addr addr;
    struct pimsm_interface_entry *pimsm_ifp;

    if (ifc->address->family != AF_INET)
    {
        /* non-IPv4 address */
        return;
    }

    pimsm_ifp = pimsm_SearchInterface(ifc->ifp->ifindex);
    if (!pimsm_ifp)
    {
        /* PIM not enabled on interface */
        return;
    }

    addr.s_addr = pimsm_ifp->primary_address.u32_addr[0];
    if (PIM_INADDR_ISNOT_ANY(addr))
    {
        /* Interface keeps a valid primary address */
        return;
    }

    if (pimsm_ifp->pimsm_sock_fd < 0)
    {
        /* Interface does not hold a valid socket any longer */
        return;
    }
#if 1 //sangmeng will add code here
    struct pimsm_mrt_entry *pstStarGrpEntry = NULL;
    struct pimsm_mrt_entry *pstSrcGrpEntry = NULL;
    struct pimsm_mrt_entry *pstSrcGrpNextEntry = NULL;
    struct pimsm_grp_entry *pstGroupEntry = NULL;
    struct pimsm_updownstream_if_entry *pstDownIf;
    if (g_group_hash)
    {
        hash_traversal_start(g_group_hash, pstGroupEntry);
        if(NULL != pstGroupEntry)
        {
            /* (*,G) */
            pstStarGrpEntry = pstGroupEntry->pstStarMrtLink;
            if (NULL != pstStarGrpEntry)
            {
                pstDownIf = pimsm_SearchDownstreamIfByIndex(pstStarGrpEntry->downstream_if, ifc->ifp->ifindex);
                if (NULL != pstDownIf)
                {
                    pimsm_DownstreamStateMachineEventProc(pstStarGrpEntry, pstDownIf, PimsmReceivePruneStarGrpEvent, NULL);
                }
            }

            // All (S,G)
            pstSrcGrpEntry = pstGroupEntry->pstSrcMrtLink;
            while(NULL != pstSrcGrpEntry)
            {
                pstSrcGrpNextEntry = pstSrcGrpEntry->samegrpnext;

                if (PIMSM_MRT_TYPE_SG == pstSrcGrpEntry->type)
                {
                    pstDownIf = pimsm_SearchDownstreamIfByIndex(pstSrcGrpEntry->downstream_if, ifc->ifp->ifindex);
                    if (NULL != pstDownIf)
                    {

                        pimsm_DownstreamStateMachineEventProc(pstSrcGrpEntry, pstDownIf, PimsmReceivePruneSrcGrpEvent, NULL);
                    }
                }

                pstSrcGrpEntry = pstSrcGrpNextEntry;
            }
        }
        hash_traversal_end();
    }
#endif
    if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
    {
        pimsm_IfStop(ifc->ifp->ifindex);
        /*
          pimsm_sock_delete() closes the socket, stops read and timer threads,
          and kills all neighbors.
         */
        pimsm_sock_delete(ifc->ifp, "last address has been removed from interface");
        PIM_DEBUG("Interface(%d %s) is disable pimsm ok.\n", ifc->ifp->ifindex, ifc->ifp->name);
    }
    else
    {
        PIM_DEBUG("Interface(%d %s) is already disable pimsm.\n", ifc->ifp->ifindex, ifc->ifp->name);
    }

    pimsm_ifp->options &= (~PIMSM_IF_FLAG_ENABLE);

    if (0 == (g_stPimsm.wFlags & PIMSM_FLAG_CONFIG))
    {
        if (!pimsm_ExistIfEnable())
        {
            pimsm_Destroy();
        }
    }
    return;
}

void pimsm_if_addr_del(struct connected *ifc, int force_prim_as_any)
{
    struct interface *ifp;

    zassert(ifc);
    ifp = ifc->ifp;
    zassert(ifp);

    /* if (PIM_DEBUG_ZEBRA) */
    {
        char buf[BUFSIZ];
        prefix2str(ifc->address, buf, BUFSIZ);
        zlog_debug("%s: %s ifindex=%d disconnected IP address %s %s",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, buf,
                   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ?
                   "secondary" : "primary");
    }

    pimsm_detect_address_change(ifp, force_prim_as_any, __PRETTY_FUNCTION__);


#if 0 //sangmeng FIXME: 20190410 igmp
    pim_if_addr_del_igmp(ifc);
#endif
    pimsm_if_addr_del_pim(ifc);
}

void pimsm_if_addr_del_all(struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node;
    struct listnode *nextnode;
    struct pimsm_interface_entry *pimsm_ifp;

    /* PIM/IGMP enabled ? */
    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if (!pimsm_ifp)
    {
        return;
    }

    for (ALL_LIST_ELEMENTS(ifp->connected, node, nextnode, ifc))
    {
        struct prefix *p = ifc->address;

        if (p->family != AF_INET)
            continue;

        pimsm_if_addr_del(ifc, 1 /* force_prim_as_any=true */);
    }
}


void pimsm_if_add_vif_all(void)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        pimsm_if_add_vif(pimsm_ifp);
        pimsm_ifp = pimsm_ifp->next;
    }
}
void pimsm_if_del_vif_all(void)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        pimsm_if_del_vif(pimsm_ifp);
        pimsm_ifp = pimsm_ifp->next;
    }
}
struct pimsm_interface_entry *pimsm_if_new(struct interface *ifp, int igmp, int pim)
{
    int ifindex;
    struct pimsm_interface_entry *pimsm_ifp;

    zassert(ifp);

    ifindex = if_nametoindex(ifp->name);
    if(ifindex == 0)
    {
        zlog_err("PIMSM Interface %s : No such device",ifp->name);
        return NULL;
    }


    pimsm_ifp = XMALLOC(MTYPE_PIM_INTERFACE, sizeof(struct pimsm_interface_entry));
    if(pimsm_ifp == NULL)
    {
        zlog_err("PIM XMALLOC(%zu) failure", sizeof(*pimsm_ifp));
        return NULL;
    }
    memset(pimsm_ifp, 0, sizeof(struct pimsm_interface_entry));

    pimsm_ifp->options = 0;
    pimsm_ifp->mroute_vif_index = -1;
    pimsm_ifp->ifindex = ifindex;
    //pimsm_ifp->primary_address.u32_addr[0];
    ifp->ifindex = ifindex;

    /* insert to interface list on head */
    if (NULL != g_pimsm_interface_list)
    {
        pimsm_ifp->next = g_pimsm_interface_list;
        g_pimsm_interface_list->prev = pimsm_ifp;
    }
    g_pimsm_interface_list = pimsm_ifp;

    pimsm_sock_reset(ifp);

    if (PIM_MROUTE_IS_ENABLED)
    {
        pimsm_if_add_vif(pimsm_ifp);
    }
    return pimsm_ifp;
}
void pimsm_if_delete(struct interface *ifp)
{
    struct pimsm_interface_entry *pimsm_ifp;
    struct pimsm_prefix_ipv4_list *pstSecondryAddr = NULL;
    struct pimsm_prefix_ipv4_list *pstSecondryAddrNext = NULL;

    zassert(ifp);

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if (!pimsm_ifp)
    {
        return;
    }
    if (PIM_MROUTE_IS_ENABLED)
    {
        pimsm_if_del_vif(pimsm_ifp);
    }

    /* destroy member list */
    pimsm_DestroyIfAllMember(pimsm_ifp);

    /* delete Secondary address list */
    pstSecondryAddrNext = pimsm_ifp->pstSecondaryAddr;
    while (NULL != pstSecondryAddrNext)
    {
        pstSecondryAddr = pstSecondryAddrNext;
        pstSecondryAddrNext = pstSecondryAddr->next;
        XFREE(MTYPE_PIM_ADDR_PREFIXLEN_LIST, pstSecondryAddr);
    }

    /* delete this interface */
    if (NULL != pimsm_ifp->next)
    {
        pimsm_ifp->next->prev = pimsm_ifp->prev;
    }
    if (NULL != pimsm_ifp->prev)
    {
        pimsm_ifp->prev->next = pimsm_ifp->next;
    }
    else
    {
        g_pimsm_interface_list = pimsm_ifp->next;
    }
    XFREE(MTYPE_PIM_INTERFACE, pimsm_ifp);
    PIM_DEBUG("Pimsm delete interface(%d %s) ok.\n", ifp->ifindex, ifp->name);
}


#endif
