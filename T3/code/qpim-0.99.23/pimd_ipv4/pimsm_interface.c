#include "pimsm_define.h"
#if INCLUDE_PIMSM

#include <zebra.h>
#include "if.h"
#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "pim_rand.h"
#include "vty.h"
#include "log.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_iface.h"
#include "pim_str.h"
#include "pim_time.h"

#include "vos_types.h"
#include "interface_define.h"
#include "pimsm_rp.h"
#include "pimsm.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_msg.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"
#include "pimsm_igmp.h"
#include "pim_pim.h"

extern struct hash *g_group_hash;
extern uint32_t g_root_cbsr_ifindex;
extern uint32_t g_root_crp_ifindex;
extern uint8_t g_root_cbsr_priority;
extern uint8_t g_root_crp_priority;
extern uint8_t g_cbsr_enable;
extern uint8_t g_crp_enable;
extern struct pimsm_encoded_unicast_addr g_root_cbsr_id;

int pimsm_DisplayIfMember(struct pimsm_interface_entry *pimsm_ifp);
int pimsm_DisplayAllIfMember(void);
int pim_PrintIfNeighbor(void);

struct pimsm_interface_entry *g_pimsm_interface_list;
uint8_t pimsm_ExistIfEnable(void);
uint8_t pimsm_DRisBetter(struct pimsm_neighbor_entry *pstNbrA,struct pimsm_neighbor_entry *pstNbrB,struct pimsm_interface_entry *pimsm_ifp);
int pimsm_DRChoose(struct pimsm_interface_entry *pimsm_ifp, VOS_IP_ADDR *pstDrAddr);
struct pimsm_interface_member *pimsm_FindIfMember(struct pimsm_interface_entry *pimsm_ifp,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType);

int pimsm_DestroyIfAllMember(struct pimsm_interface_entry *pimsm_ifp);

uint8_t pimsm_AllNbrPriorityPresent(struct pimsm_interface_entry *pimsm_ifp);
#if 1 //sangmeng
uint32_t pim_GetIntfNameFromLogicID(int LogicID,char *name)
{
    const char *ifname = NULL;
    ifname = ifindex2ifname(LogicID);
    strcpy(name, ifname);
    return VOS_OK;
}
#endif

#define eventt

int pimsm_zebra_if_add(int command, struct zclient *zclient,zebra_size_t length)
{
    struct interface *ifp;

    /*
     zebra api adds/dels interfaces using the same call
     interface_add_read below, see comments in lib/zclient.c
    */
    ifp = zebra_interface_add_read(zclient->ibuf);
    if (!ifp)
        return 0;

    if (PIM_DEBUG_ZEBRA)
    {
        zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
                   ifp->mtu, if_is_operative(ifp));
    }

    if (if_is_operative(ifp))
        pimsm_if_addr_add_all(ifp);

#if 0
    if (!if_is_operative(ifp))
        return VOS_ERROR;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if  (pimsm_ifp == NULL)
    {
        if (pimsm_if_new(ifp, 0, 1) == NULL)
        {
            PIM_DEBUG("Could not enable pim-sm on interface %s\n",ifp->name);
            return VOS_ERROR;
        }
    }

    PIM_DEBUG("Pimsm add interface(%d %s) ok.\n", ifp->ifindex, ifp->name);
#endif
    return VOS_OK;
}

int pimsm_zebra_if_del(int command, struct zclient *zclient,zebra_size_t length)
{
    struct interface *ifp;

    /*
     zebra api adds/dels interfaces using the same call
     interface_add_read below, see comments in lib/zclient.c

     comments in lib/zclient.c seem to indicate that calling
     zebra_interface_add_read is the correct call, but that
     results in an attemted out of bounds read which causes
     pimd to assert. Other clients use zebra_interface_state_read
     and it appears to work just fine.
     */
    ifp = zebra_interface_state_read(zclient->ibuf);
    if (!ifp)
        return 0;

    if (PIM_DEBUG_ZEBRA)
    {
        zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
                   ifp->mtu, if_is_operative(ifp));
    }
    if (!if_is_operative(ifp))
        pimsm_if_delete(ifp);

#if 0
    if (if_is_operative(ifp))
        return 0;

    ifindex = ifp->ifindex;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (pimsm_ifp == NULL)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found, the delete event to be ignored by Pimsm.\n", ifindex, ifindex2ifname(ifindex));
        return VOS_ERROR;
    }

    if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
    {
        if (VOS_OK != pimsm_IfDisable(ifp))
        {
            PIM_DEBUG("Pimsm disable interface(%d %s) failed, when delete it.\n", ifindex, ifindex2ifname(ifindex));
            return VOS_ERROR;
        }
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

    PIM_DEBUG("Pimsm delete interface(%d %s) ok.\n", ifindex, ifindex2ifname(ifindex));
#endif
    return VOS_OK;
}

int pimsm_zebra_if_state_up(int command, struct zclient *zclient,zebra_size_t length)
{
    uint32_t ifindex;
    struct interface *ifp;
    struct pimsm_interface_entry *pimsm_ifp;

    /*
     zebra api notifies interface up/down events by using the same call
     zebra_interface_state_read below, see comments in lib/zclient.c
    */
    ifp = zebra_interface_state_read(zclient->ibuf);
    if (!ifp)
        return 0;

    zlog_info("INTERFACE UP: %s ifindex=%d", ifp->name, ifp->ifindex);

    if (PIM_DEBUG_ZEBRA)
    {
        zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
                   ifp->mtu, if_is_operative(ifp));
    }

    if (if_is_operative(ifp))
        pimsm_if_addr_add_all(ifp);
#if 0
    if (if_is_operative(ifp))
    {
        ifindex = ifp->ifindex;

        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("The interface(%d %s) cann't be found, the up event to be ignored by Pimsm.\n", ifindex, ifindex2ifname(ifindex));
            return VOS_ERROR;
        }

        pimsm_ifp->options |= PIMSM_IF_FLAG_UP;
        PIM_DEBUG("The interface(%d %s) is up.\n", ifindex, ifindex2ifname(ifindex));

        if (0 != (g_stPimsm.wFlags & PIMSM_FLAG_CONFIG))
        {
            pimsm_ifp->options |= PIMSM_IF_FLAG_ENABLE;
        }

        if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
        {
            pimsm_IfStart(pimsm_ifp->ifindex);
        }
    }
#endif

    return VOS_OK;
}

int pimsm_zebra_if_state_down(int command, struct zclient *zclient,zebra_size_t length)
{
    uint32_t ifindex;
    struct interface *ifp;
    struct pimsm_interface_entry *pimsm_ifp;

    /*
     zebra api notifies interface up/down events by using the same call
     zebra_interface_state_read below, see comments in lib/zclient.c
     */
    ifp = zebra_interface_state_read(zclient->ibuf);
    if (!ifp)
        return 0;

    zlog_info("INTERFACE DOWN: %s ifindex=%d", ifp->name, ifp->ifindex);

    if (PIM_DEBUG_ZEBRA)
    {
        zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
                   __PRETTY_FUNCTION__,
                   ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
                   ifp->mtu, if_is_operative(ifp));
    }
    if (!if_is_operative(ifp))
        pimsm_if_addr_del_all(ifp);

#if 0
    if (!if_is_operative(ifp))
    {
        ifindex = ifp->ifindex;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(NULL == pimsm_ifp)
        {
            PIM_DEBUG("The interface(%d %s) cann't be found, the down event to be ignored by Pimsm.\n", ifindex, ifp->name);
            return VOS_ERROR;
        }

        if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
        {
            pimsm_IfStop(ifindex);
            pimsm_sock_delete(ifp, "link down");
        }

        pimsm_ifp->options &= (~PIMSM_IF_FLAG_UP);
        PIM_DEBUG("The interface(%d %s) is down.\n", ifindex, ifp->name);
    }
#endif
    return VOS_OK;
}

int pimsm_zebra_if_address_add(int command, struct zclient *zclient,zebra_size_t length)
{
    struct connected *c;
    struct prefix *p;

    uint8_t prefixlen;
    uint32_t addr_type;
    VOS_IP_ADDR addr;
    uint32_t ifindex;
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    PIM_DEBUG(">>>>ener pimsm_zebra_if_address_add.\n");

    zassert(command == ZEBRA_INTERFACE_ADDRESS_ADD);

    /*
     zebra api notifies address adds/dels events by using the same call
     interface_add_read below, see comments in lib/zclient.c

     zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
     will add address to interface list by calling
     connected_add_by_prefix()
     */
    c = zebra_interface_address_read(command, zclient->ibuf);
    if (!c)
        return 0;

    p = c->address;
    if (p->family != AF_INET)
        return 0;

    if (PIM_DEBUG_ZEBRA)
    {
        char buf[BUFSIZ];
        prefix2str(p, buf, BUFSIZ);
        zlog_debug("%s: %s connected IP address %s flags %u %s",
                   __PRETTY_FUNCTION__,
                   c->ifp->name, buf, c->flags,
                   CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY) ? "secondary" : "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
        dump_if_address(c->ifp);
#endif
    }
    if (!CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY))
    {
        /* trying to add primary address */

        struct in_addr primary_addr = pim_find_primary_addr(c->ifp);
        if (primary_addr.s_addr != p->u.prefix4.s_addr)
        {
            /* but we had a primary address already */

            char buf[BUFSIZ];
            char old[100];

            prefix2str(p, buf, BUFSIZ);
            pim_inet4_dump("<old?>", primary_addr, old, sizeof(old));

            zlog_warn("%s: %s primary addr old=%s: forcing secondary flag on new=%s",
                      __PRETTY_FUNCTION__,
                      c->ifp->name, old, buf);
            SET_FLAG(c->flags, ZEBRA_IFA_SECONDARY);
        }
    }

    ifindex = c->ifp->ifindex;
    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found, the address add event to be ignored by Pimsm.\n", ifindex, c->ifp->name);
        return VOS_ERROR;
    }

    /* IP Address */
    addr.u32_addr[0] = p->u.prefix4.s_addr;
    prefixlen = p->prefixlen;

    addr_type = pim_addr_type(&addr);
    if (( 0 == (addr_type & PIM_IP_ADDR_LOOPBACK)) &&
            (0 == (addr_type & PIM_IP_ADDR_ANY)) &&
            (0 == (addr_type & PIM_IP_ADDR_MULTICAST)))
    {
        pimsm_ifp->primary_address = addr;
        pimsm_ifp->prefixlen = prefixlen;

        if (INTERFACE_LOOPBACK != pimsm_ifp->dwIfType)
        {
            if((0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)) && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP)))
            {
                pimsm_SendHello(ifindex, 3.5 * (pimsm_ifp->pimsm_hello_period), NULL);
            }
            pimsm_DRElection(pimsm_ifp);
        }
    }
#if 1 /*wjh for igmp*/
    pim_if_addr_add(c);
#endif
    pimsm_if_addr_add(c);
    if(g_cbsr_enable == TRUE && g_root_cbsr_ifindex == pimsm_ifp->ifindex)
    {
        //g_root_cbsr_id.unicast_addr.u32_addr[0] = pimsm_ifp->primary_address.u32_addr[0];
        pim_BootstrapCbsrEnable(pimsm_ifp->ifindex,g_root_cbsr_priority);
    }
    if(g_crp_enable == TRUE && g_root_crp_ifindex == pimsm_ifp->ifindex )
    {
        pim_BootstrapCrpEnable(g_root_crp_ifindex,g_root_crp_priority);
    }


    return VOS_OK;
}

int pimsm_zebra_if_address_del(int command, struct zclient *client,zebra_size_t length)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    uint32_t addr_type;
    VOS_IP_ADDR addr;
    uint32_t ifindex;

    struct connected *c;
    struct prefix *p;

    zassert(command == ZEBRA_INTERFACE_ADDRESS_DELETE);

    /*
      zebra api notifies address adds/dels events by using the same call
      interface_add_read below, see comments in lib/zclient.c

      zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
      will remove address from interface list by calling
      connected_delete_by_prefix()
    */
    c = zebra_interface_address_read(command, client->ibuf);
    if (!c)
        return 0;

    p = c->address;
    if (p->family != AF_INET)
        return 0;

    if (PIM_DEBUG_ZEBRA)
    {
        char buf[BUFSIZ];
        prefix2str(p, buf, BUFSIZ);
        zlog_debug("%s: %s disconnected IP address %s flags %u %s",
                   __PRETTY_FUNCTION__,
                   c->ifp->name, buf, c->flags,
                   CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY) ? "secondary" : "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
        dump_if_address(c->ifp);
#endif
    }

    ifindex = c->ifp->ifindex;
    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(NULL == pimsm_ifp)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found, the address delete event to be ignored by Pimsm.\n", ifindex, ifindex2ifname(ifindex));
        return VOS_ERROR;
    }

    /* IP Address */
    addr.u32_addr[0] = p->u.prefix4.s_addr;

    addr_type = pim_addr_type(&addr);
    if((0 == (addr_type & PIM_IP_ADDR_LOOPBACK)) &&
            ( 0 == (addr_type & PIM_IP_ADDR_ANY)) &&
            (0 == (addr_type & PIM_IP_ADDR_MULTICAST)))
    {
        if (0 == ip_AddressCompare(&(pimsm_ifp->primary_address), &addr))
        {
            if (INTERFACE_LOOPBACK != pimsm_ifp->dwIfType)
            {
                if ((0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)) && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP)))
                {
                    pimsm_SendHello(ifindex, 0, NULL);
                }
            }
            memset(&(pimsm_ifp->primary_address), 0x00, sizeof(VOS_IP_ADDR));
            PIM_DEBUG("The interface(%d %s) delete address %s .\n", ifindex, ifindex2ifname(ifindex), pim_InetFmt(&pimsm_ifp->primary_address));
        }
    }

#if 1 /*wjh for igmp*/
    pim_if_addr_del(c, 0);
#endif
    pimsm_if_addr_del(c, 0);

    if(g_root_cbsr_ifindex == pimsm_ifp->ifindex)
    {
        g_root_cbsr_id.unicast_addr.u32_addr[0] = pimsm_ifp->primary_address.u32_addr[0];
    }

    return VOS_OK;
}

int pimsm_IfMtuUpdate(m_CfmToPimsm_t *pstCfmMsg)
{
    PIM_DEBUG("Not support update MTU.\n");
    return VOS_OK;
}

#define nbr

struct pimsm_neighbor_entry *pimsm_SearchNeighbor(struct pimsm_interface_entry *pimsm_ifp, VOS_IP_ADDR *pstNbrAddr)
{
    struct pimsm_prefix_ipv4_list *pstSecondaryAddr = NULL;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;

    if (NULL == pimsm_ifp || NULL == pstNbrAddr)
    {
        return NULL;
    }

    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    while (pimsm_neigh != NULL)
    {
        if (0 == ip_AddressCompare(&(pimsm_neigh->source_addr), pstNbrAddr))
        {
            return pimsm_neigh;
        }

        pstSecondaryAddr = pimsm_neigh->pstSecondaryAddrList;
        while(NULL != pstSecondaryAddr)
        {
            if (0 == ip_AddressCompare(&(pstSecondaryAddr->addr), pstNbrAddr))
            {
                return pimsm_neigh;
            }

            pstSecondaryAddr = pstSecondaryAddr->next;
        }

        pimsm_neigh = pimsm_neigh->next;
    }

    return NULL;
}

uint32_t pimsm_GetNeighborCount(struct pimsm_interface_entry *pimsm_ifp)
{
    struct pimsm_neighbor_entry *pstNeighbor;
    uint32_t count = 0;

    if (NULL == pimsm_ifp)
    {
        return 0;
    }

    pstNeighbor = pimsm_ifp->pimsm_neigh;
    while(pstNeighbor != NULL)
    {
        count++;

        pstNeighbor=pstNeighbor->next;
    }

    return count;
}

#define other

int pimsm_DelNbr(struct pimsm_interface_entry *pimsm_ifp, struct pimsm_neighbor_entry *pimsm_neigh)
{
    struct pimsm_prefix_ipv4_list *pstAddrPrefixToFree;
    struct pimsm_prefix_ipv4_list *pstAddrPrefix;
    struct pimsm_grp_entry *pstGrpEntry;
    struct pimsm_mrt_entry *mrt_entry;
    uint8_t byNbrIsDR = FALSE;

    if(pimsm_ifp == NULL || pimsm_neigh == NULL)
    {
        return VOS_ERROR;
    }

    byNbrIsDR = (0 == ip_AddressCompare(&pimsm_ifp->pimsm_dr_addr, &pimsm_neigh->source_addr)) ? TRUE : FALSE;

    if (NULL != g_group_hash)
    {
        hash_traversal_start(g_group_hash, pstGrpEntry);
        /* (*,G) entry process */
        mrt_entry = pstGrpEntry->pstStarMrtLink;
        if (NULL != mrt_entry)
        {
            if(!pimsm_IamRP(&pstGrpEntry->address)
                    && 0 == ip_AddressCompare(&mrt_entry->upstream_if.up_stream_nbr, &(pimsm_neigh->source_addr)))
            {
                memset(&mrt_entry->upstream_if.up_stream_nbr, 0x00, sizeof(VOS_IP_ADDR));
            }
        }

        /* (S,G) entry process */
        mrt_entry = pstGrpEntry->pstSrcMrtLink;
        while (NULL != mrt_entry)
        {
            if (!pimsm_IamRP(&pstGrpEntry->address) &&
                    (0 == ip_AddressCompare(&mrt_entry->upstream_if.up_stream_nbr, &pimsm_neigh->source_addr)))
            {
                memset(&mrt_entry->upstream_if.up_stream_nbr, 0x00, sizeof(VOS_IP_ADDR));
            }

            mrt_entry = mrt_entry->samegrpnext;
        }
        hash_traversal_end();
    }


    if (pimsm_neigh->t_expire_timer)
        THREAD_OFF(pimsm_neigh->t_expire_timer);

    /* free neighbor secondary address list */
    pstAddrPrefix = pimsm_neigh->pstSecondaryAddrList;
    while(pstAddrPrefix != NULL)
    {
        pstAddrPrefixToFree = pstAddrPrefix;
        pstAddrPrefix = pstAddrPrefix->next;
        XFREE(MTYPE_PIM_ADDR_PREFIXLEN_LIST, pstAddrPrefixToFree);
    }
    pimsm_neigh->pstSecondaryAddrList = NULL;


    /* free neighbor entry */
    if (NULL != pimsm_neigh->next)
    {
        pimsm_neigh->next->prev = pimsm_neigh->prev;
    }
    if (NULL != pimsm_neigh->prev)
    {
        pimsm_neigh->prev->next = pimsm_neigh->next;
    }
    else
    {
        pimsm_ifp->pimsm_neigh = pimsm_neigh->next;
    }
    XFREE(MTYPE_PIM_NEIGHBOR, pimsm_neigh);

    /* If the interface have no neighbor, sign it */
    if (NULL == pimsm_ifp->pimsm_neigh)
    {
        pimsm_ifp->options |= PIMSM_IF_FLAG_NONBRS;
    }

    /* If the neighbor is DR, restart choose DR */
    if(byNbrIsDR)
    {
        PIM_DEBUG("There should choose new DR , need add corresponding code.\n");
        /* pimsm_DRChoose(pimsm_ifp, &stDrAddr); */
    }

    return VOS_OK;
}
#if 0 /*dlete this func*/
struct pimsm_interface_entry *pimsm_SearchInterfacebyname(char *ifname)
{
    struct pimsm_interface_entry *pstFoundIf = NULL;

    if(g_pimsm_interface_list == NULL)
    {
        return NULL;
    }

    pstFoundIf = g_pimsm_interface_list;
    while(pstFoundIf != NULL)
    {
        if(!strcmp(ifname,pstFoundIf->name))
        {
            return pstFoundIf;
        }

        pstFoundIf = pstFoundIf->next;
    }

    return NULL;

}
#endif
struct pimsm_interface_entry *pimsm_SearchInterface(uint32_t ifindex)
{
    struct pimsm_interface_entry *pstFoundIf = NULL;

    if(g_pimsm_interface_list == NULL)
    {
        return NULL;
    }

    pstFoundIf = g_pimsm_interface_list;
    while(pstFoundIf != NULL)
    {
        if(ifindex == pstFoundIf->ifindex)
        {
            return pstFoundIf;
        }

        pstFoundIf = pstFoundIf->next;
    }

    return NULL;
}

uint8_t pimsm_IsLocalAddress(VOS_IP_ADDR *pstAddr)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    zassert(NULL != pstAddr);

    pimsm_ifp = g_pimsm_interface_list;

    while (NULL != pimsm_ifp)
    {
        if (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_UP))
        {
            pimsm_ifp = pimsm_ifp->next;
            continue;
        }

        if (0 == ip_AddressCompare(pstAddr, &pimsm_ifp->primary_address))
        {
            return TRUE;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    return FALSE;
}

uint8_t pimsm_IsLocalIfAddress(uint32_t ifindex, VOS_IP_ADDR *pstAddr)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    zassert(NULL != pstAddr);

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("pimsm_IsLocalIfAddress: Can't find the IF by index!\n");
        return FALSE;
    }

    if (0 == ip_AddressCompare(pstAddr, &pimsm_ifp->primary_address))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t pimsm_IsMyNeighbor(uint32_t ifindex, VOS_IP_ADDR *pstNbrAddr)
{
    struct pimsm_prefix_ipv4_list *pstScndaryAddrList = NULL;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    zassert(NULL != pstNbrAddr);

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("pimsm_IsMyNeighbor: Interface(%d) not find!\n", ifindex);
        return FALSE;
    }

    for (pimsm_neigh = pimsm_ifp->pimsm_neigh; NULL != pimsm_neigh; pimsm_neigh = pimsm_neigh->next)
    {
        if (0 == ip_AddressCompare(pstNbrAddr, &pimsm_neigh->source_addr))
        {
            return TRUE;
        }
        for (pstScndaryAddrList = pimsm_neigh->pstSecondaryAddrList;
                NULL != pstScndaryAddrList;
                pstScndaryAddrList = pstScndaryAddrList->next)
        {
            if (0 == ip_AddressCompare(pstNbrAddr, &pstScndaryAddrList->addr))
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

uint8_t pimsm_ExistIfEnable(void)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    pimsm_ifp = g_pimsm_interface_list;

    while (NULL != pimsm_ifp)
    {
        if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
        {
            return TRUE;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    return FALSE;
}

uint32_t pimsm_DirectIfSearch(VOS_IP_ADDR *pstAddr)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    zassert(NULL != pstAddr);

    pimsm_ifp = g_pimsm_interface_list;
    while (NULL != pimsm_ifp)
    {
        if ((PIMSM_IF_FLAG_UP | PIMSM_IF_FLAG_ENABLE) != (pimsm_ifp->options & (PIMSM_IF_FLAG_UP | PIMSM_IF_FLAG_ENABLE)) )
        {
            pimsm_ifp = pimsm_ifp->next;
            continue;
        }
        if((pimsm_ifp->primary_address.u32_addr != 0) && (pimsm_ifp->prefixlen != 0))
        {
            if (pim_MatchPrefix(pstAddr, &pimsm_ifp->primary_address, pimsm_ifp->prefixlen))
            {
                return(pimsm_ifp->ifindex);
            }
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    return PIMSM_NO_IF;
}

#define itf

int pimsm_IfStart(uint32_t ifindex)
{
    struct pimsm_timer_para_hello *hello_para;
    uint32_t tmHelloDelay;
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found, start pimsm failed!\n", ifindex, ifindex2ifname(ifindex));
        return VOS_ERROR;
    }

    /* Before start interface , i have no neighbor and i'm DR */
    pimsm_ifp->options |= PIMSM_IF_FLAG_NONBRS;
    pimsm_ifp->options |= PIMSM_IF_FLAG_DR;
    pimsm_ifp->pimsm_generation_id = pim_rand() & (int64_t) 0xFFFFFFFF;

    hello_para = XMALLOC(MTYPE_PIM_HELLO_PARA, sizeof(struct pimsm_timer_para_hello));
    memset(hello_para, 0x00, sizeof(hello_para));

    /* Send Hello message after a few seconds */
    if ((0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP)) && (INTERFACE_LOOPBACK != pimsm_ifp->dwIfType))
    {
        if (pimsm_ifp->t_pimsm_hello_timer)
            THREAD_OFF(pimsm_ifp->t_pimsm_hello_timer);

        tmHelloDelay = (uint32_t)(rand() % (PIMSM_TIMER_VALUE_TRIGGER_HELLO_DELAY + 1));

        hello_para->ifindex = pimsm_ifp->ifindex;

        THREAD_TIMER_ON(master, pimsm_ifp->t_pimsm_hello_timer,
                        on_pimsm_hello_send,
                        hello_para, tmHelloDelay);
    }

    PIM_DEBUG("interface(%d %s) start pimsm ok.\n", ifindex, ifindex2ifname(ifindex));

    return VOS_OK;
}

int pimsm_IfStop(uint32_t ifindex)
{
    struct pimsm_neighbor_entry *pstNbrToBeFree = NULL;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found , stop pimsm failed!\n", ifindex, ifindex2ifname(ifindex));
        return VOS_ERROR;
    }

#if 0 //sangmeng FIXME:
    vid = switch_TableLif2VlanId(pimsm_ifp->ifindex, NULL);
    if (dal_l3if_mcast_enable(vid, FALSE) < 0)// 1: enable 0: disable
    {
        PIM_DEBUG("When stop interface(%d %s) pimsm , hardware disable mulicast failed.\n", ifindex, ifindex2ifname(ifindex));
    }

    /* ipf enable pimsm , ipf will send multicast data to pimsm */
    if (VOS_OK != ipf_EnablePimSM(pimsm_ifp->ifindex, FALSE))
    {
        PIM_DEBUG("When stop interface(%d %s) pimsm , ipf disable pimsm failed.\n", ifindex, ifindex2ifname(ifindex));
    }
#endif

    /* After stop pimsm , i have no neighbor */
    pimsm_ifp->options |= PIMSM_IF_FLAG_NONBRS;

    /* free neighbor list */
    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    while(pimsm_neigh != NULL)
    {
        pstNbrToBeFree = pimsm_neigh;
        pimsm_neigh = pimsm_neigh->next;
        pimsm_DelNbr(pimsm_ifp, pstNbrToBeFree);
    }
    pimsm_ifp->pimsm_neigh = NULL;

    /* stop Hello timer */
    if (pimsm_ifp->t_pimsm_hello_timer)
        THREAD_OFF(pimsm_ifp->t_pimsm_hello_timer);

    /* stop igmp report timer */
    if (pimsm_ifp->t_pimsm_igmp_timer)
        THREAD_OFF(pimsm_ifp->t_pimsm_igmp_timer);

    /* send Hello message */
    if ((0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP)) && (INTERFACE_LOOPBACK != pimsm_ifp->dwIfType))
    {
        pimsm_SendHello(pimsm_ifp->ifindex, 0, NULL);
    }

    return VOS_OK;
}
static int pimsm_one_interface_config_write(struct vty *vty,struct pimsm_interface_entry *pimsm_ifp)
{

    zassert(pimsm_ifp != NULL);

    vty_out(vty,"interface %s %s",ifindex2ifname(pimsm_ifp->ifindex),VTY_NEWLINE);
    if((pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE) != 0)
    {
        vty_out(vty," ip pim-sm enable %s",VTY_NEWLINE);
    }
    if(pimsm_ifp->pimsm_hello_period != PIM_DEFAULT_HELLO_PERIOD)
    {
        vty_out(vty," ip pim-sm hello-interval %d %s",pimsm_ifp->pimsm_hello_period,VTY_NEWLINE);
    }
    if(pimsm_ifp->pimsm_dr_priority !=PIM_DEFAULT_DR_PRIORITY)
    {
        vty_out(vty," ip pim-sm dr-priority %d %s",pimsm_ifp->pimsm_dr_priority,VTY_NEWLINE);
    }
    if(pimsm_ifp->dwJoinPruneInterval !=PIM_JOIN_PRUNE_PERIOD )
    {
        vty_out(vty," ip pim-sm join-prune-interval %d %s",pimsm_ifp->dwJoinPruneInterval,VTY_NEWLINE);
    }


    vty_out(vty,"!%s",VTY_NEWLINE);

    return VOS_OK;
}
int pimsm_if_config_write(struct vty *vty)
{
    struct pimsm_interface_entry  *pstIf = NULL;

    pstIf = g_pimsm_interface_list;
    while(pstIf != NULL)
    {
        pimsm_one_interface_config_write(vty, pstIf);
        pstIf = pstIf->next;
    }

    return VOS_OK;

}
#if 0
int pimsm_IfEnable(struct interface *ifp)
{
    pimsm_if_addr_add_all(ifp);

    return VOS_OK;
}

int pimsm_IfDisable(struct interface *ifp)
{
#if 0
    uint32_t ifindex;
    struct pimsm_interface_entry *pimsm_ifp;

#endif
    pimsm_if_addr_del_all(ifp);

#if 0
    ifindex = ifp->ifindex;
    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("The interface(%d %s) cann't be found , disable pimsm failed!\n", ifindex, ifindex2ifname(ifindex));
        return VOS_ERROR;
    }

    if (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
    {
        pimsm_IfStop(ifindex);

        pimsm_sock_delete(ifp, "pim unconfigured on interface");
        PIM_DEBUG("Interface(%d %s) is disable pimsm ok.\n", ifindex, ifindex2ifname(ifindex));
    }
    else
    {
        PIM_DEBUG("Interface(%d %s) is already disable pimsm.\n", ifindex, ifindex2ifname(ifindex));
    }

    pimsm_ifp->options &= (~PIMSM_IF_FLAG_ENABLE);

    if (0 == (g_stPimsm.wFlags & PIMSM_FLAG_CONFIG))
    {
        if (!pimsm_ExistIfEnable())
        {
            pimsm_Destroy();
        }
    }

#endif
    return VOS_OK;
}
#endif

#if 0
int pimsm_IfEnableAll (void)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        pimsm_IfEnable(pimsm_ifp->ifindex);

        pimsm_ifp = pimsm_ifp->next;
    }

    return VOS_OK;
}

int pimsm_IfDisableAll (void)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        pimsm_IfDisable(pimsm_ifp->ifindex);

        pimsm_ifp = pimsm_ifp->next;
    }

    return VOS_OK;
}
#endif

int pimsm_SetHelloInterval(struct vty *vty, struct interface *ifp, uint32_t dwSeconds)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if(pimsm_ifp == NULL)
    {
        vty_out(vty,"The interface(%d %s) cann't be found , set hello interval  failed!\n", ifp->ifindex, ifp->name);
        return VOS_ERROR;
    }
    pimsm_ifp->pimsm_hello_period = dwSeconds;
    return VOS_OK;

}

int pimsm_SetJoinPruneInterval(struct vty *vty, struct interface *ifp, uint32_t dwSeconds)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if(pimsm_ifp == NULL)
    {
        vty_out(vty,"The interface(%d %s) cann't be found !\n", ifp->ifindex, ifp->name);
        return VOS_ERROR;
    }

    pimsm_ifp->dwJoinPruneInterval = dwSeconds;
    return VOS_OK;

}
int pimsm_SetDRPriority(struct vty *vty, struct interface *ifp, uint32_t dwSeconds)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
    if(pimsm_ifp == NULL)
    {
        vty_out(vty,"The interface(%d %s) cann't be found !\n", ifp->ifindex, ifp->name);
        return VOS_ERROR;
    }


    if (pimsm_ifp->pimsm_dr_priority != dwSeconds)
    {
        pimsm_ifp->pimsm_dr_priority = dwSeconds;
        if((INTERFACE_LOOPBACK != pimsm_ifp->dwIfType)
                && (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_P2P)) /* p2p链路不需要DR选举 */
                && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP))
                && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)))
        {
            pimsm_DRElection(pimsm_ifp);
            pimsm_SendHello(ifp->ifindex, 3.5 * (pimsm_ifp->pimsm_hello_period), NULL);
        }
    }

    return VOS_OK;

}
static int pimsm_ShowOneInterface(struct vty *vty,struct pimsm_interface_entry *pimsm_ifp)
{
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;
    char s[PIMSM_IF_NAME_MAX_LEN];
    uint32_t dwNbrCount;
    char uptime[10];
    char sss[5];
    time_t now;

    zassert(pimsm_ifp != NULL);

    now = pim_time_monotonic_sec();
    pim_GetIntfNameFromLogicID(pimsm_ifp->ifindex, s);
    if((pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE) != 0)
    {
        sprintf(sss, "%s", "on");
    }
    else
    {
        sprintf(sss, "%s", "off");
    }

    dwNbrCount = 0;
    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    while(pimsm_neigh != NULL)
    {
        pimsm_neigh = pimsm_neigh->next;
        dwNbrCount++;
    }
    pim_time_uptime(uptime, sizeof(uptime), now - pimsm_ifp->pimsm_sock_creation);

    //vty_out(vty, "%-30s  %-10s  %-15d  %-15d  %-15d\n", s, sss, dwNbrCount, pimsm_ifp->pimsm_hello_period, pimsm_ifp->pimsm_dr_priority);
    //vty_out(vty, "%-15s  %-7d  %-6d  %-8s  %-10s  %-15d  %-15d  %-15d\n", s, pimsm_ifp->ifindex,  pimsm_ifp->pimsm_sock_fd, uptime, sss, dwNbrCount, pimsm_ifp->pimsm_hello_period, pimsm_ifp->pimsm_dr_priority);
    vty_out(vty, "%-15s %-7d %-6d %-8s %-10s %-15d %-15d %-15d %-15d \n", s, pimsm_ifp->ifindex,  pimsm_ifp->pimsm_sock_fd, uptime, sss, dwNbrCount, pimsm_ifp->pimsm_hello_period, pimsm_ifp->pimsm_dr_priority, pimsm_ifp->dwJoinPruneInterval);
    ip_printAddress(&(pimsm_ifp->primary_address), s, sizeof(s));
    vty_out(vty, "     %-7s:   %s\n", "Address", s);
    if((pimsm_ifp->options & PIMSM_IF_FLAG_DR) != 0)
    {
        sprintf(s, "This System");
    }
    else
    {
        ip_printAddress(&(pimsm_ifp->pimsm_dr_addr), s, sizeof(s));
    }
    vty_out(vty, "     %-7s:   %s\n", "DR ", s);

    return VOS_OK;
}
int pimsm_ShowInterface(struct vty *vty, uint32_t ifindex)
{
    struct pimsm_interface_entry  *pimsm_ifp = NULL;

    if(ifindex != 0)
    {
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            //oam_OutputToDevice (0, "% Invaild interface!\n");
            return VOS_ERROR;
        }

        pimsm_ShowOneInterface(vty,pimsm_ifp);
    }
    return VOS_OK;
}
/* 显示PIM邻居信息 */
static int pimsm_ShowOneIfNbr(struct vty *vty,struct pimsm_interface_entry *pimsm_ifp,uint8_t *pbExistNbr)
{
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;
    char neighbor_address[200];
    char interface_name[200];
    char uptime[10];
    time_t            now;

    if(pimsm_ifp == NULL)
    {
        return VOS_ERROR;
    }

    now = pim_time_monotonic_sec();

    memset(uptime, 0, sizeof(uptime));
    memset(interface_name, 0, sizeof(interface_name));
    memset(neighbor_address, 0, sizeof(neighbor_address));
    *pbExistNbr = FALSE;

    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    pim_GetIntfNameFromLogicID(pimsm_ifp->ifindex, interface_name);

    while(pimsm_neigh != NULL)
    {
        *pbExistNbr = TRUE;
        ip_printAddress(&(pimsm_neigh->source_addr), neighbor_address, sizeof(neighbor_address));
        pim_time_uptime(uptime, sizeof(uptime), now - pimsm_neigh->creation);
        vty_out(vty, "%-35s  %-30s  %-15s  %-15d\n", neighbor_address, interface_name, uptime, pimsm_neigh->dr_priority);
        pimsm_neigh = pimsm_neigh->next;
    }

    return VOS_OK;
}

int pimsm_ShowNeighbor(struct vty *vty,struct interface *ifp)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    uint8_t bExistNbr = FALSE;
    char print_buf[SS_DEB_lENTH];

    memset(print_buf, 0, SS_DEB_lENTH);

    if(ifp->ifindex > 0)
    {
        pimsm_ifp = pimsm_SearchInterface(ifp->ifindex);
        if(pimsm_ifp == NULL)
        {
            return VOS_ERROR;
        }
        pimsm_ShowOneIfNbr(vty,pimsm_ifp,&bExistNbr);
        if (!bExistNbr)
        {
            vty_out(vty, "  (%s no pim neighbor!)\n", ifp->name);
        }
        printf(print_buf);
    }

    return VOS_OK;
}

#define dr

uint8_t pimsm_IamDR(uint32_t ifindex)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        return FALSE;
    }

    if(0 == ip_AddressCompare(&(pimsm_ifp->pimsm_dr_addr), &(pimsm_ifp->primary_address)))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/* 如果当前接口下所有邻居的priority都存在返回TRUE, 否则返回FALSE */
uint8_t pimsm_AllNbrPriorityPresent(struct pimsm_interface_entry *pimsm_ifp)
{
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;

    if(pimsm_ifp == NULL)
    {
        return FALSE;
    }

    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    while(pimsm_neigh != NULL)
    {
        if(!(pimsm_neigh->bPriorityPresent))
        {
            return FALSE;
        }
        pimsm_neigh = pimsm_neigh->next;
    }

    return TRUE;
}

//以下个函数根据协议 draft-ietf-pim-sm-v2-new-10.txt 第32页
/* If NbrA is better than NbrB return TRUE otherwise return FALSE */
uint8_t pimsm_DRisBetter(struct pimsm_neighbor_entry *pstNbrA,struct pimsm_neighbor_entry *pstNbrB,struct pimsm_interface_entry *pimsm_ifp)
{
    int iBigOrNot;

    if (pimsm_AllNbrPriorityPresent(pimsm_ifp))
    {
        if(pstNbrA->dr_priority == pstNbrB->dr_priority)
        {
            iBigOrNot = memcmp(&(pstNbrA->source_addr), &(pstNbrB->source_addr), sizeof(VOS_IP_ADDR));
            if(iBigOrNot > 0)
            {
                return TRUE;
            }
            else if(iBigOrNot < 0)
            {
                return FALSE;
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            if(pstNbrA->dr_priority > pstNbrB->dr_priority)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
    }
    else
    {
        iBigOrNot = memcmp(&(pstNbrA->source_addr), &(pstNbrB->source_addr), sizeof(VOS_IP_ADDR));
        if(iBigOrNot > 0)
        {
            return TRUE;
        }
        else if(iBigOrNot < 0)
        {
            return FALSE;
        }
        else
        {
            return FALSE;
        }
    }

}

int pimsm_DRChoose(struct pimsm_interface_entry *pimsm_ifp, VOS_IP_ADDR *pstDrAddr)
{
    struct pimsm_neighbor_entry stDR;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;

    if ((pimsm_ifp == NULL) || (pstDrAddr == NULL))
    {
        return VOS_ERROR;
    }

    //dr = me
    stDR.bPriorityPresent = TRUE;
    stDR.dr_priority = pimsm_ifp->pimsm_dr_priority;
    stDR.source_addr = pimsm_ifp->primary_address;
    pimsm_neigh = pimsm_ifp->pimsm_neigh;
    while(pimsm_neigh != NULL)
    {
        if(pimsm_DRisBetter(pimsm_neigh, &stDR, pimsm_ifp) == TRUE)
        {
            //dr = neighbor
            memcpy(&stDR, pimsm_neigh, sizeof(struct pimsm_neighbor_entry));
        }
        pimsm_neigh = pimsm_neigh->next;
    }
    memcpy(pstDrAddr, &stDR.source_addr, sizeof(VOS_IP_ADDR));

    pimsm_ifp->pimsm_dr_addr = stDR.source_addr;

    return VOS_OK;
}

int pimsm_DRElection(struct pimsm_interface_entry *pimsm_ifp)
{
    VOS_IP_ADDR pimsm_dr_addr;
    uint32_t ifindex;
    uint8_t byIamDROld;
    uint8_t byNowIamDR;

    zassert(NULL != pimsm_ifp);

    ifindex = pimsm_ifp->ifindex;
    byIamDROld = (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_DR));

    if(VOS_OK != pimsm_DRChoose(pimsm_ifp, &pimsm_dr_addr))
    {
        return VOS_ERROR;
    }

    byNowIamDR = pimsm_IamDR(ifindex);

    if (!byIamDROld && byNowIamDR)
    {
        /* set DR flag */
        pimsm_ifp->options |= PIMSM_IF_FLAG_DR;

        /* 把此接口添加到各个组 */
        //pimsm_IfAddedToMemberEntry(pimsm_ifp);

        if ((NULL != pimsm_ifp->pstMemberList) && (!pimsm_ifp->t_pimsm_igmp_timer))
        {
#if 0//sangmeng mark FIXME
            THREAD_TIMER_ON(master, pimsm_ifp->t_pimsm_igmp_timer,
                            on_pimsm_hello_send,
                            &ifindex, PIM_MLD_REPORT_PERIOD);
#endif

        }
    }
    else if (byIamDROld && !byNowIamDR)
    {
        /* set DR flag */
        pimsm_ifp->options &= ~PIMSM_IF_FLAG_DR;

        /* 把此接口从各个组项中删除 */
        //pimsm_IfRemovedFromMemberEntry(pimsm_ifp);

        if (pimsm_ifp->t_pimsm_igmp_timer)
            THREAD_OFF(pimsm_ifp->t_pimsm_igmp_timer);
    }
    else
    {
        return VOS_OK;
    }

    return VOS_OK;
}

#define member

struct pimsm_interface_member *pimsm_FindIfMember(struct pimsm_interface_entry *pimsm_ifp,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType)
{
    struct pimsm_interface_member *pstIfMember;
    PIMSM_ADDR_LIST_T *pstSrcNode;

    if ((NULL == pimsm_ifp) || (NULL == pstGrpAddr))
    {
        return NULL;
    }

    pstIfMember = pimsm_ifp->pstMemberList;

    while (NULL != pstIfMember)
    {
        if ((emType == pstIfMember->type) && (0 == ip_AddressCompare(pstGrpAddr, &pstIfMember->grp_addr)))
        {
            if ((PIMSM_IF_INCLUDE == emType || PIMSM_IF_EXCLUDE == emType) && (NULL != src_addr))
            {
                pstSrcNode = pstIfMember->pSrcAddrList;
                while (NULL != pstSrcNode)
                {
                    if (0 == ip_AddressCompare(src_addr, &pstSrcNode->addr))
                    {
                        return pstIfMember;
                    }
                    pstSrcNode = pstSrcNode->pstNext;
                }
                return NULL;
            }
            else
            {
                return pstIfMember;
            }
        }

        pstIfMember = pstIfMember->next;
    }

    return NULL;
}

struct pimsm_interface_member *pimsm_CreateIfMember(struct pimsm_interface_entry *pimsm_ifp, VOS_IP_ADDR *src_addr, VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType)
{
    struct pimsm_interface_member *pstIfMember;
    PIMSM_ADDR_LIST_T *pstSrcNode;

    if ((NULL == pimsm_ifp) || (NULL == pstGrpAddr))
    {
        return NULL;
    }

    if ((PIMSM_IF_IGMPv1 != emType) && (PIMSM_IF_IGMPv2 != emType) &&
            (PIMSM_IF_INCLUDE != emType) && (PIMSM_IF_EXCLUDE != emType))
    {
        return NULL;
    }

    /* 先根据emType查找 , 不考虑pstSrcAddr */
    pstIfMember = pimsm_FindIfMember(pimsm_ifp, NULL, pstGrpAddr, emType);
    if (NULL == pstIfMember)
    {
        pstIfMember = XMALLOC(MTYPE_PIM_INTERFACE_MEMBER, sizeof(struct pimsm_interface_member));
        if (NULL == pstIfMember)
        {
            return NULL;
        }
        memset(pstIfMember, 0, sizeof(struct pimsm_interface_member));
        pstIfMember->type = emType;
        memcpy(&pstIfMember->grp_addr, pstGrpAddr, sizeof(VOS_IP_ADDR));
        pstIfMember->next = NULL;
        pstIfMember->prev = NULL;

        if (((PIMSM_IF_INCLUDE == emType) || (PIMSM_IF_EXCLUDE == emType)) && (NULL != src_addr))
        {
            pstSrcNode = XMALLOC(MTYPE_PIM_ADDR_LIST, sizeof(PIMSM_ADDR_LIST_T));
            if (NULL == pstSrcNode)
            {
                XFREE(MTYPE_PIM_INTERFACE_MEMBER, pstIfMember);
                return NULL;
            }
            memset(pstSrcNode, 0, sizeof(PIMSM_ADDR_LIST_T));
            memcpy(&pstSrcNode->addr, src_addr, sizeof(VOS_IP_ADDR));
            pstSrcNode->pstNext = NULL;
            pstIfMember->pSrcAddrList = pstSrcNode;
        }
        else
        {
            pstIfMember->pSrcAddrList = NULL;
        }

        pstIfMember->next = pimsm_ifp->pstMemberList;
        if (NULL != pimsm_ifp->pstMemberList)
        {
            pimsm_ifp->pstMemberList->prev = pstIfMember;
        }
        pimsm_ifp->pstMemberList = pstIfMember;

        return pstIfMember;
    }

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType) || (NULL == src_addr))
    {
        return pstIfMember;
    }
    else /* PIMSM_IF_INCLUDE and PIMSM_IF_EXCLUDE need compare source address. */
    {
        pstSrcNode = pstIfMember->pSrcAddrList;
        while(NULL != pstSrcNode)
        {
            if (0 == ip_AddressCompare(src_addr, &pstSrcNode->addr))
            {
                return pstIfMember; /* Find , return entry. */
            }

            pstSrcNode = pstSrcNode->pstNext;
        }
        pstSrcNode = XMALLOC(MTYPE_PIM_ADDR_LIST, sizeof(PIMSM_ADDR_LIST_T));
        if (NULL == pstSrcNode)
        {
            return NULL;
        }
        memset(pstSrcNode, 0, sizeof(PIMSM_ADDR_LIST_T));
        memcpy(&pstSrcNode->addr, src_addr, sizeof(VOS_IP_ADDR));
        pstSrcNode->pstNext = pstIfMember->pSrcAddrList;
        pstIfMember->pSrcAddrList = pstSrcNode;
    }

    return pstIfMember;
}

int pimsm_DestroyIfMember(struct pimsm_interface_entry *pimsm_ifp,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType)
{
    struct pimsm_interface_member *pstIfMember;
    PIMSM_ADDR_LIST_T *pstSrcNodeCurr;
    PIMSM_ADDR_LIST_T *pstSrcNodePrev;
    PIMSM_ADDR_LIST_T *pstSrcNodeNext;

    pstIfMember = pimsm_FindIfMember(pimsm_ifp, NULL, pstGrpAddr, emType);
    if (NULL == pstIfMember)
    {
        return VOS_ERROR;
    }

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType))
    {
        if (NULL != pstIfMember->next)
        {
            pstIfMember->next->prev = pstIfMember->prev;
        }
        if (NULL != pstIfMember->prev)
        {
            pstIfMember->prev->next = pstIfMember->next;
        }
        if (pimsm_ifp->pstMemberList == pstIfMember)
        {
            pimsm_ifp->pstMemberList = pstIfMember->next;
        }
        XFREE(MTYPE_PIM_INTERFACE_MEMBER, pstIfMember);
    }
    else
    {
        if (NULL == src_addr)
        {
            /* Destroy all source first. */
            pstSrcNodeCurr = pstIfMember->pSrcAddrList;
            while(NULL != pstSrcNodeCurr)
            {
                pstSrcNodeNext = pstSrcNodeCurr->pstNext;
                XFREE(MTYPE_PIM_ADDR_LIST, pstSrcNodeCurr);
                pstSrcNodeCurr = pstSrcNodeNext;
            }
            pstIfMember->pSrcAddrList = NULL;

            /* The current member node need to destroy. */
            if (NULL != pstIfMember->next)
            {
                pstIfMember->next->prev = pstIfMember->prev;
            }
            if (NULL != pstIfMember->prev)
            {
                pstIfMember->prev->next = pstIfMember->next;
            }
            if (pimsm_ifp->pstMemberList == pstIfMember)
            {
                pimsm_ifp->pstMemberList = pstIfMember->next;
            }
            XFREE(MTYPE_PIM_INTERFACE_MEMBER, pstIfMember);
        }
        else
        {
            /* Destroy special source first. */
            pstSrcNodeCurr = pstIfMember->pSrcAddrList;
            pstSrcNodePrev = pstSrcNodeCurr;
            while(NULL != pstSrcNodeCurr)
            {
                if (0 == ip_AddressCompare(src_addr, &pstSrcNodeCurr->addr))
                {
                    if (pstSrcNodeCurr == pstSrcNodePrev) /* first node */
                    {
                        pstIfMember->pSrcAddrList = pstSrcNodeCurr->pstNext;
                    }
                    else
                    {
                        pstSrcNodePrev->pstNext = pstSrcNodeCurr->pstNext;
                    }
                    XFREE(MTYPE_PIM_ADDR_LIST, pstSrcNodeCurr);
                    break;
                }

                pstSrcNodePrev = pstSrcNodeCurr;
                pstSrcNodeCurr = pstSrcNodeCurr->pstNext;
            }

            /* If the member type is INCLUDE and it's source address list is NULL , that need to destroy. */
            if ((PIMSM_IF_INCLUDE == pstIfMember->type) && (NULL == pstIfMember->pSrcAddrList))
            {
                if (NULL != pstIfMember->next)
                {
                    pstIfMember->next->prev = pstIfMember->prev;
                }
                if (NULL != pstIfMember->prev)
                {
                    pstIfMember->prev->next = pstIfMember->next;
                }
                if (pimsm_ifp->pstMemberList == pstIfMember)
                {
                    pimsm_ifp->pstMemberList = pstIfMember->next;
                }
                XFREE(MTYPE_PIM_INTERFACE_MEMBER, pstIfMember);
            }
        }
    }

    return VOS_OK;
}

int pimsm_DestroyIfAllMember(struct pimsm_interface_entry *pimsm_ifp)
{
    struct pimsm_interface_member *pstIfMemberCurr;
    struct pimsm_interface_member *pstIfMemberNext;

    if (NULL == pimsm_ifp)
    {
        return VOS_ERROR;
    }

    pstIfMemberCurr = pimsm_ifp->pstMemberList;
    while(pstIfMemberCurr)
    {
        pstIfMemberNext = pstIfMemberCurr->next;
        pimsm_DestroyIfMember(pimsm_ifp, NULL, &pstIfMemberCurr->grp_addr, pstIfMemberCurr->type);
        pstIfMemberCurr = pstIfMemberNext;
    }

    return VOS_OK;
}

int pimsm_DisplayIfMember(struct pimsm_interface_entry *pimsm_ifp)
{
    struct pimsm_interface_member *pstIfMember;
    PIMSM_ADDR_LIST_T *pstSrcNode;

    if (NULL == pimsm_ifp)
    {
        return VOS_ERROR;
    }

    PIM_DEBUG("%s Include:\n", ifindex2ifname(pimsm_ifp->ifindex));
    pstIfMember = pimsm_ifp->pstMemberList;
    while(NULL != pstIfMember)
    {
        if (PIMSM_IF_IGMPv1 == pstIfMember->type)
        {
            PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv1_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        }
        else if (PIMSM_IF_IGMPv2 == pstIfMember->type)
        {
            PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv2_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        }
        else if (PIMSM_IF_INCLUDE == pstIfMember->type)
        {
            PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv3_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
            pstSrcNode = pstIfMember->pSrcAddrList;
            while(NULL != pstSrcNode)
            {
                PIM_DEBUG("\t\tSrcAddr: %s\n", pim_InetFmt(&pstSrcNode->addr));
                pstSrcNode = pstSrcNode->pstNext;
            }
        }
        /*
        else if (PIMSM_IF_EXCLUDE == pstIfMember->type)
        {
        	PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv3_EXCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        	pstSrcNode = pstIfMember->pSrcAddrList;
        	while(NULL != pstSrcNode)
        	{
        		PIM_DEBUG("\t\tSrcAddr: %s\n", pim_InetFmt(&pstSrcNode->addr));
        		pstSrcNode = pstSrcNode->pstNext;
        	}
        }
        */

        pstIfMember = pstIfMember->next;
    }

    PIM_DEBUG("%s Exclude:\n", ifindex2ifname(pimsm_ifp->ifindex));
    pstIfMember = pimsm_ifp->pstMemberList;
    while(NULL != pstIfMember)
    {
        /*
        if (PIMSM_IF_IGMPv1 == pstIfMember->type)
        {
        	PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv1_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        }
        else if (PIMSM_IF_IGMPv2 == pstIfMember->type)
        {
        	PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv2_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        }
        else if (PIMSM_IF_INCLUDE == pstIfMember->type)
        {
        	PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv3_INCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
        	pstSrcNode = pstIfMember->pSrcAddrList;
        	while(NULL != pstSrcNode)
        	{
        		PIM_DEBUG("\t\tSrcAddr: %s\n", pim_InetFmt(&pstSrcNode->addr));
        		pstSrcNode = pstSrcNode->pstNext;
        	}
        }
        else */if (PIMSM_IF_EXCLUDE == pstIfMember->type)
        {
            PIM_DEBUG("\tGrpAddr: %s, Type: IGMPv3_EXCLUDE\n", pim_InetFmt(&pstIfMember->grp_addr));
            pstSrcNode = pstIfMember->pSrcAddrList;
            while(NULL != pstSrcNode)
            {
                PIM_DEBUG("\t\tSrcAddr: %s\n", pim_InetFmt(&pstSrcNode->addr));
                pstSrcNode = pstSrcNode->pstNext;
            }
        }

        pstIfMember = pstIfMember->next;
    }

    return VOS_OK;
}

int pimsm_DisplayAllIfMember(void)
{
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = g_pimsm_interface_list;

    PIM_DEBUG("==================================================\n");
    while(pimsm_ifp)
    {
        pimsm_DisplayIfMember(pimsm_ifp);
        pimsm_ifp = pimsm_ifp->next;
    }
    PIM_DEBUG("==================================================\n");

    return VOS_OK;
}


#define AAAAA

#if 0
static uint8_t pimsm_LanDelayEnabled(uint32_t ifindex)
{
    PIM_INTERFACE *pimsm_ifp = NULL;
    PIM_NEIGHBOR  *pimsm_neigh = NULL;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return FALSE;
    }

    for (pimsm_neigh = pimsm_ifp->pimsm_neigh;
            NULL != pimsm_neigh;
            pimsm_neigh = pimsm_neigh->next)
    {
        if (!pimsm_neigh->bLanPruneDelayPresent) /* 如果为FALSE */
        {
            return FALSE;
        }
    }

    return TRUE;

}

/* 注意:返回为毫秒 */
uint32_t pimsm_EffectivePropagationDelay(uint32_t ifindex)
{
    PIM_INTERFACE *pimsm_ifp = NULL;
    PIM_NEIGHBOR  *pimsm_neigh = NULL;
    uint16_t   wDelay;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return 0xffffffff; /* 无效值 */
    }

    if (!pimsm_LanDelayEnabled(ifindex)) /* 如果为FALSE */
    {
        return PIM_PROPAGATION_DELAY; /* 0.5s */
    }

    wDelay = pimsm_ifp->pimsm_propagation_delay_msec;
    for (pimsm_neigh = pimsm_ifp->pimsm_neigh;
            NULL != pimsm_neigh;
            pimsm_neigh = pimsm_neigh->next)
    {
        if (pimsm_neigh->pimsm_propagation_delay_msec > wDelay) /* 如果为FALSE */
        {
            wDelay =  pimsm_neigh->pimsm_propagation_delay_msec;
        }
    }

    return (uint32_t) wDelay;
}

/* 注意:返回为毫秒 */
uint32_t pimsm_EffectiveOverridInterval(uint32_t ifindex)
{
    PIM_INTERFACE *pimsm_ifp = NULL;
    PIM_NEIGHBOR  *pimsm_neigh = NULL;
    uint16_t   wDelay;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return 0xffffffff; /* 无效值 */
    }

    if (!pimsm_LanDelayEnabled(ifindex)) /* 如果为FALSE */
    {
        return PIM_OVERRIDE_INTERVAL; /* 2.5s */
    }

    wDelay = pimsm_ifp->pimsm_override_interval_msec;
    for (pimsm_neigh = pimsm_ifp->pimsm_neigh;
            NULL != pimsm_neigh;
            pimsm_neigh = pimsm_neigh->next)
    {
        if (pimsm_neigh->pimsm_override_interval_msec > wDelay) /* 如果为FALSE */
        {
            wDelay =  pimsm_neigh->pimsm_override_interval_msec;
        }
    }

    return (uint32_t) wDelay;
}


/********************************************************************
FuncName: pimsm_IfAddedToMemberEntry
Description: add a pimsm interface to it's entries
Input:
    Interface
Output:
    N/A.
Returns:
    VOS_OK, if succeed;
    VOS_ERROR, if fail.
********************************************************************/
int pimsm_IfAddedToMemberEntry(PIM_INTERFACE *pimsm_ifp)
{
    PIM_IFMEMBER *pstMem = NULL;
    PIM_ADDRLIST *pstSrcList = NULL;

    zassert(NULL != pimsm_ifp);

    /* 包含模式 */
    pstMem = pimsm_ifp->pstIncludeMember;
    while (NULL != pstMem)
    {
        if (PIM_IF_MLDv1 == pstMem->emType)
        {
            pimsm_AddLeaveOifToEntry(NULL,
                                     &pstMem->grpAddr,
                                     pimsm_ifp->ifindex,
                                     OIF_IMMEDIATE);
        }
        else if (PIM_IF_INCLUDE == pstMem->emType)
        {
            pstSrcList = pstMem->pSrcAddrList;
            while (NULL != pstSrcList)
            {
                pimsm_AddLeaveOifToEntry(&pstSrcList->addr,
                                         &pstMem->grpAddr,
                                         pimsm_ifp->ifindex,
                                         OIF_IMMEDIATE);

                pstSrcList = pstSrcList->pstNext;
            }
        }
        else
        {
            return VOS_ERROR;
        }

        pstMem = pstMem->next;
    }


    /* 排除模式 */
    pstMem = pimsm_ifp->pstExcludeMember;
    while (NULL != pstMem)
    {
        if (PIM_IF_EXCLUDE == pstMem->emType)
        {
            pstSrcList = pstMem->pSrcAddrList;
            /* 排除为空时要把接口添加到(*,G)和所有的(S,G) */
            if (NULL == pstSrcList)
            {
                pimsm_AddLeaveOifToEntry(NULL,
                                         &pstMem->grpAddr,
                                         pimsm_ifp->ifindex,
                                         OIF_IMMEDIATE);
            }
            else
            {
                /*把此接口只添加到(*,G)*/
                pimsm_AddLeaveOifToOnlyStarGEntry(&pstMem->grpAddr, pimsm_ifp->ifindex);

                /* 把此接口从指定的(S,G) or (S,G,rpt)项中删除 */
                while (NULL != pstSrcList)
                {
                    pimsm_DelLeaveOifFromSGEntry(&pstSrcList->addr,
                                                 &pstMem->grpAddr,
                                                 pimsm_ifp->ifindex);

                    pstSrcList = pstSrcList->pstNext;
                }
            }
        }
        else
        {
            return VOS_ERROR;
        }

        pstMem = pstMem->next;
    }

    return VOS_OK;
}

/********************************************************************
FuncName: pimsm_IfRemovedFromMemberEntry
Description: remove a pimsm interface from it's entries
Input:
    Interface
Output:
    N/A.
Returns:
    VOS_OK, if succeed;
    VOS_ERROR, if fail.
********************************************************************/
int pimsm_IfRemovedFromMemberEntry(PIM_INTERFACE *pimsm_ifp)
{
    PIM_IFMEMBER *pstMem = NULL;
    PIM_ADDRLIST *pstSrcList = NULL;

    zassert(NULL != pimsm_ifp);

    /* 包含模式 */
    pstMem = pimsm_ifp->pstIncludeMember;
    while (NULL != pstMem)
    {
        if (PIM_IF_MLDv1 == pstMem->emType)
        {
            pimsm_DelOifFromMrtEntry(NULL,
                                     &pstMem->grpAddr,
                                     EM_OIL_LEAVE,
                                     pimsm_ifp->ifindex,
                                     OIF_IMMEDIATE,
                                     MRTF_WC);
        }
        else if (PIM_IF_INCLUDE == pstMem->emType)
        {
            pstSrcList = pstMem->pSrcAddrList;
            while (NULL != pstSrcList)
            {
                pimsm_DelOifFromMrtEntry(&pstSrcList->addr,
                                         &pstMem->grpAddr,
                                         EM_OIL_LEAVE,
                                         pimsm_ifp->ifindex,
                                         OIF_IMMEDIATE,
                                         MRTF_SG);
                pstSrcList = pstSrcList->pstNext;
            }
        }
        else
        {
            return VOS_ERROR;
        }

        pstMem = pstMem->next;
    }


    /* 排除模式 */
    pstMem = pimsm_ifp->pstExcludeMember;
    while (NULL != pstMem)
    {
        if (PIM_IF_EXCLUDE == pstMem->emType)
        {
            /* 把此接口添加到指定的(S,G) or (S,G,rpt)项中 */
            pstSrcList = pstMem->pSrcAddrList;
            while (NULL != pstSrcList)
            {
                pimsm_AddLeaveOifToEntry(&pstSrcList->addr,
                                         &pstMem->grpAddr,
                                         pimsm_ifp->ifindex,
                                         OIF_INHERITED);

                pstSrcList = pstSrcList->pstNext;
            }

            /*把此接口从(*,G)中删除*/
            pimsm_DelOifFromMrtEntry(NULL,
                                     &pstMem->grpAddr,
                                     EM_OIL_LEAVE,
                                     pimsm_ifp->ifindex,
                                     OIF_IMMEDIATE,
                                     MRTF_WC);
        }
        else
        {
            return VOS_ERROR;
        }

        pstMem = pstMem->next;
    }

    return VOS_OK;
}
#endif

int pim_PrintIfNeighbor(void)
{
    struct pimsm_interface_entry *pstInterface = NULL;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;

    pstInterface = g_pimsm_interface_list;

    printf("\n==============================================\n");
    printf("Interface information:\n");
    while(pstInterface != NULL)
    {
        pimsm_neigh = pstInterface->pimsm_neigh;
        if(pimsm_neigh != NULL) printf("[%d]\n", pstInterface->ifindex);
        while(pimsm_neigh != NULL)
        {
            printf("\tNeighbor Primary Address %s .\n", pim_InetFmt(&pimsm_neigh->source_addr));
            pimsm_neigh = pimsm_neigh->next;
        }
        pstInterface = pstInterface->next;
    }
    printf("\n----------------------------------------------\n");

    return 0;
}

#endif

