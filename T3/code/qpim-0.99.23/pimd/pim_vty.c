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
#include "linklist.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_iface.h"
#include "pim_cmd.h"
#include "pim_str.h"
#include "pim_ssmpingd.h"

#include "pimsm_interface.h"
#include "pimsm_rp.h"

#include "pim_pim.h"
#include "pimsm_timer.h"


int pim_debug_config_write(struct vty *vty)
{
    int writes = 0;

    if (PIM_DEBUG_IGMP_EVENTS)
    {
        vty_out(vty, "debug igmp events%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_IGMP_PACKETS)
    {
        vty_out(vty, "debug igmp packets%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_IGMP_TRACE)
    {
        vty_out(vty, "debug igmp trace%s", VTY_NEWLINE);
        ++writes;
    }

    if (PIM_DEBUG_MROUTE)
    {
        vty_out(vty, "debug mroute%s", VTY_NEWLINE);
        ++writes;
    }

    if (PIM_DEBUG_PIM_EVENTS)
    {
        vty_out(vty, "debug pim events%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_PIM_PACKETS)
    {
        vty_out(vty, "debug pim packets%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_PIM_PACKETDUMP_SEND)
    {
        vty_out(vty, "debug pim packet-dump send%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_PIM_PACKETDUMP_RECV)
    {
        vty_out(vty, "debug pim packet-dump receive%s", VTY_NEWLINE);
        ++writes;
    }
    if (PIM_DEBUG_PIM_TRACE)
    {
        vty_out(vty, "debug pim trace%s", VTY_NEWLINE);
        ++writes;
    }

    if (PIM_DEBUG_ZEBRA)
    {
        vty_out(vty, "debug pim zebra%s", VTY_NEWLINE);
        ++writes;
    }

    if (PIM_DEBUG_SSMPINGD)
    {
        vty_out(vty, "debug ssmpingd%s", VTY_NEWLINE);
        ++writes;
    }

    return writes;
}

int pimsm_global_config_write(struct vty *vty);
int pimsm_config_write(struct vty *vty)
{
    int write = 0;

    write  += pimsm_global_config_write(vty);
    vty_out(vty,"!%s",VTY_NEWLINE);


    write  += pimsm_globalenableconfig(vty);
    vty_out(vty,"!%s",VTY_NEWLINE);

    write  += pimsm_staticrpconfig(vty);
    vty_out(vty,"!%s",VTY_NEWLINE);

    write  += pimsm_acceptsourceconfig(vty);
    vty_out(vty,"!%s",VTY_NEWLINE);

    write  += pimsm_bootstrapconfig(vty);
    vty_out(vty,"!%s",VTY_NEWLINE);

    return write;
}

int pimsm_global_config_write(struct vty *vty)
{
    int writes = 0;

    if (PIM_MROUTE_IS_ENABLED)
    {
        //vty_out(vty, "%s%s", PIM_CMD_IP_MULTICAST_ROUTING, VTY_NEWLINE);
        vty_out(vty, "%s%s", PIM_CMD_IPV6_MULTICAST_ROUTING, VTY_NEWLINE);
        ++writes;
    }

    return writes;
}


int pim_global_config_write(struct vty *vty)
{
    int writes = 0;

    PIM_DEBUG("show run here.\n");
    if (PIM_MROUTE_IS_ENABLED)
    {
        vty_out(vty, "%s%s", PIM_CMD_IP_MULTICAST_ROUTING, VTY_NEWLINE);
        ++writes;
    }

    if (qpim_ssmpingd_list)
    {
        struct listnode *node;
        struct ssmpingd_sock *ss;
        vty_out(vty, "!%s", VTY_NEWLINE);
        ++writes;
        for (ALL_LIST_ELEMENTS_RO(qpim_ssmpingd_list, node, ss))
        {
            char source_str[100];
            pim_inet_dump("<src?>", ss->source_addr, source_str, sizeof(source_str));
            vty_out(vty, "ip ssmpingd %s%s", source_str, VTY_NEWLINE);
            ++writes;
        }
    }

    return writes;
}


int pimsm_interface_config_write(struct vty *vty)
{

    int write = 0;
#if 1
    write  += pimsm_if_config_write(vty); /*pim-ssm config wrtie at pim_inteface_config_write*/
    vty_out(vty,"!%s",VTY_NEWLINE);
#endif

    return write;
}


int pim_interface_config_write(struct vty *vty)
{
    int writes = 0;
    struct listnode *node;
    struct interface *ifp;
    struct pimsm_interface_entry  *pimsm_ifp = NULL;

    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
    {

        /* IF name */
        vty_out(vty, "interface %s%s", ifp->name, VTY_NEWLINE);
        ++writes;

        if (ifp->info)
        {
            struct mld_interface *pim_ifp = ifp->info;

            /* IF ip pim ssm */
            if (PIM_IF_TEST_PIM(pim_ifp->options))
            {
                vty_out(vty, " ipv6 pim ssm%s", VTY_NEWLINE);
                ++writes;
            }

            /* IF ip igmp */
            if (PIM_IF_TEST_MLD(pim_ifp->options))
            {
                vty_out(vty, " ipv6 mld%s", VTY_NEWLINE);
                ++writes;
            }
#if 0
            /* IF ip igmp query-interval */
            vty_out(vty, " %s %d%s",
                    PIM_CMD_IP_MLD_QUERY_INTERVAL,
                    pim_ifp->mld_default_query_interval,
                    VTY_NEWLINE);
            ++writes;

            /* IF ip igmp query-max-response-time */
            vty_out(vty, " %s %d%s",
                    PIM_CMD_IP_MLD_QUERY_MAX_RESPONSE_TIME_DSEC,
                    pim_ifp->mld_query_max_response_time_dsec,
                    VTY_NEWLINE);
            ++writes;
#endif
#if 0
            /* IF ip igmp join */
            if (pim_ifp->igmp_join_list)
            {
                struct listnode *node;
                struct igmp_join *ij;
                for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_join_list, node, ij))
                {
                    char group_str[100];
                    char source_str[100];
                    pim_inet_dump("<grp?>", ij->group_addr, group_str, sizeof(group_str));
                    pim_inet_dump("<src?>", ij->source_addr, source_str, sizeof(source_str));
                    vty_out(vty, " ip igmp join %s %s%s",
                            group_str, source_str,
                            VTY_NEWLINE);
                    ++writes;
                }
            }
#endif


        }

        pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
        if(pimsm_ifp != NULL)
        {
            if((pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE) != 0)
            {
                vty_out(vty," ipv6 pim-sm enable %s",VTY_NEWLINE);
                ++writes;
            }
            if(pimsm_ifp->pimsm_hello_period != PIM_DEFAULT_HELLO_PERIOD)
            {
                vty_out(vty," ipv6 pim-sm hello-interval %d %s",pimsm_ifp->pimsm_hello_period,VTY_NEWLINE);
                ++writes;
            }
            if(pimsm_ifp->pimsm_dr_priority !=PIM_DEFAULT_DR_PRIORITY)
            {
                vty_out(vty," ipv6 pim-sm dr-priority %d %s",pimsm_ifp->pimsm_dr_priority,VTY_NEWLINE);
                ++writes;
            }
            if(pimsm_ifp->dwJoinPruneInterval !=PIM_JOIN_PRUNE_PERIOD )
            {
                vty_out(vty," ipv6 pim-sm join-prune-interval %d %s",pimsm_ifp->dwJoinPruneInterval,VTY_NEWLINE);
                ++writes;
            }

        }

        vty_out(vty, "!%s", VTY_NEWLINE);
        ++writes;
    }

    return writes;
}
