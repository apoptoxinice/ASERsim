/****************************************************************
 Copyright (C)  2005 by  Tsinghua Bitway Co, Ltd.
 File:          pim_datagramproc.c
 Author:        xjy
 Version:       0.1
 Date:          2005.1
 Description:   pim datagram process
 Others:
 Function List:
 History:
*****************************************************************/

#include "pimsm_define.h"

#if INCLUDE_PIMSM

#include <zebra.h>
#include "thread.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "hash.h"

#include "pimd.h"
#include "pim_str.h"
#include "pim_util.h"
#include "pim_pim.h"
#include "pim_msg.h"
#include "pim_iface.h"
#include "pim_time.h"
#include "pim_rpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>


#include "vos_types.h"
#include "interface_define.h"
#include "pimsm_rp.h"
#include "pimsm.h"
#include "pimsm_inet.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_msg.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_register.h"
#include "pimsm_bootstrap.h"
#include "pimsm_msg.h"
#include "pimsm_mrtmgt.h"


int pimsm_ReceiveJoinPrune(uint32_t ifindex, VOS_IP_ADDR *src_addr, uint8_t *pim_msg, uint32_t pim_msg_size);
int pimsm_ReceiveAssert(uint32_t ifindex,VOS_IP_ADDR *src_addr,uint8_t *pim_msg,uint32_t pim_msg_size);

static char *get_msg_type(int type, char *msg)
{
    switch(type)
    {
    case PIM_TYPE_HELLO:
        sprintf(msg,"%s","PIMSM_TYPE_HELLO");
        break;
    case PIM_TYPE_REGISTER:
        sprintf(msg,"%s","PIMSM_TYPE_REGISTER");
        break;
    case PIM_TYPE_REGISTER_STOP:
        sprintf(msg,"%s","PIMSM_TYPE_REGISTER_STOP");
        break;
    case PIM_TYPE_JOIN_PRUNE:
        sprintf(msg,"%s","PIMSM_TYPE_JOIN_PRUNE");
        break;
    case PIM_TYPE_BOOTSTRAP:
        sprintf(msg,"%s","PIMSM_TYPE_BOOTSTRAP");
        break;
    case PIM_TYPE_ASSERT:
        sprintf(msg,"%s","PIMSM_TYPE_ASSERT");
        break;
    case PIM_TYPE_GRAFT:
        sprintf(msg,"%s","PIMSM_TYPE_GRAFT");
        break;
    case PIM_TYPE_GRAFT_ACK:
        sprintf(msg,"%s","PIMSM_TYPE_GRAFT_ACK");
        break;
    case PIM_TYPE_CAND_RP_ADV:
        sprintf(msg,"%s","PIMSM_TYPE_CAND_RP_ADV");
        break;
    default:
        sprintf(msg,"%s","UNKNOW_MSG_TYPE");
        break;
    }

    return msg;
}

#if 0
/*  IP???????????????????????????  */
uint16_t pimsm_CheckSum (uint16_t *buf, int nwords)
{
    uint32_t sum = 0;
    int loop = 0;

    if (nwords < 0)
    {
        return -1;
    }

    for(loop = 0; loop < nwords; loop++)
    {
        sum += (uint16_t)(*buf++);

        if (sum & 0xFFFF0000)
        {
            sum = (sum>>16) + (sum & 0x0000ffff);
        }

    }

    sum = (sum>>16) + (sum & 0xffff);
    sum += (sum>>16);

    return ((uint16_t)(~sum));
}
#endif

static int pimsm_SendTrafficStatistics(struct pimsm_interface_entry *pimsm_ifp,int type,int flags)
{

    switch(type)
    {
    case PIM_TYPE_HELLO:
        if(flags == VOS_OK)
            pimsm_ifp->pimsm_ifstat.hello_send++;
        else
            pimsm_ifp->pimsm_ifstat.hello_sendfail++;
        break;
    case PIM_TYPE_REGISTER:
        g_stPimsm.dwOutPimsmRegister++;
        break;
    case PIM_TYPE_REGISTER_STOP:
        g_stPimsm.dwOutPimsmRegisterStop++;
        break;
    case PIM_TYPE_JOIN_PRUNE:
        if(flags == VOS_OK)
            pimsm_ifp->pimsm_ifstat.join_prune_send++;
        else
            pimsm_ifp->pimsm_ifstat.join_prune_sendfail++;
        break;
    case PIM_TYPE_BOOTSTRAP:
        if(flags == VOS_OK)
            pimsm_ifp->pimsm_ifstat.bootstrap_send++;
        else
            pimsm_ifp->pimsm_ifstat.bootstrap_sendfail++;
        break;
    case PIM_TYPE_ASSERT:
        if(flags == VOS_OK)
            pimsm_ifp->pimsm_ifstat.assert_send++;
        else
            pimsm_ifp->pimsm_ifstat.assert_sendfail++;
        break;
    case PIM_TYPE_GRAFT:
        if(flags == VOS_OK)
            pimsm_ifp->pimsm_ifstat.graft_send++;
        else
            pimsm_ifp->pimsm_ifstat.graft_sendfail++;
        break;
    case PIM_TYPE_GRAFT_ACK:
        g_stPimsm.dwOutPimsmGraftAck++;
        break;
    case PIM_TYPE_CAND_RP_ADV:
        g_stPimsm.dwOutPimsmCandRpAdv++;
        break;
    }
    return VOS_OK;
}

/*pim_msg?????????????????????pim?????????, ??????pim???*/
/*pim_tlv_size???pim??????????????????, ?????????pim??????*/
int pimsm_SendPimPacket(uint8_t *pim_msg, uint32_t ifindex, VOS_IP_ADDR *pstSrc, VOS_IP_ADDR *pstDst, int type, uint32_t pim_tlv_size)
{
    int pim_msg_size;
    struct pimsm_interface_entry *pimsm_ifp;
    VOS_IP_ADDR dst_addr;
    VOS_IP_ADDR src_addr;
    char msg_type[128];
    int outif;
    //struct pim_nexthop nexthop;
    struct pimsm_rpf nexthop;
    struct in_addr addr;

    if((pim_msg == NULL) || (pstDst == NULL))
    {
        if(pim_msg == NULL)
        {
            PIM_DEBUG("pim send fail, pim_msg == NULL\n");
        }
        if(pstDst == NULL)
        {
            PIM_DEBUG("pim send fail, pstDst == NULL\n");
        }
        return VOS_ERROR;
    }

    outif = ifindex;
    if ((0 == ifindex) || !ip_isMulticastAddress(pstDst))
    {
        outif = -1;//??????
    }

    if (NULL != pstSrc)
    {
        if (pstSrc->u32_addr[0] == 0 /*|| ifindex == 0*/)
        {
            PIM_DEBUG("pim send fail, src:%s, ifinde:%d.\n", pim_InetFmt(pstSrc), ifindex);
            return VOS_ERROR;
        }
        if(outif == -1)
        {
            PIM_DEBUG("pstDst:%s\n", pim_InetFmt(pstDst));
            memset(&addr, 0, sizeof(struct in_addr));
            addr.s_addr = pstDst->u32_addr[0];

            //pim_nexthop_lookup(&nexthop,pstDst);
            pimsm_nexthop_lookup(&nexthop,addr);
            //pimsm_ifp = pimsm_SearchInterface(nexthop.interface->ifindex);
            pimsm_ifp = pimsm_SearchInterface(nexthop.rpf_if);
        }
        else
        {
            pimsm_ifp = pimsm_SearchInterface(ifindex);
        }
        if (NULL == pimsm_ifp)
        {
            PIM_DEBUG("can't get pimsm_ifp, src:%s, ifinde:%d ,pstDst:%s.\n", pim_InetFmt(pstSrc), ifindex,pim_InetFmt(pstDst));
            return VOS_ERROR;
        }

        memcpy(&src_addr, pstSrc, sizeof(VOS_IP_ADDR));
    }
    else
    {
        if (-1 != outif)
        {
            pimsm_ifp = pimsm_SearchInterface(outif);
        }
        else
        {
            pimsm_ifp = pimsm_SearchInterface(pimsm_RpfInterface(pstDst));
        }
        if (NULL != pimsm_ifp)
        {
            memcpy(&src_addr, &pimsm_ifp ->primary_address, sizeof(VOS_IP_ADDR));
        }
        else
        {
            PIM_DEBUG("can't get pimsm_ifp, src:%s, ifinde:%d.\n", pim_InetFmt(pstSrc), ifindex);
            PIM_DEBUG("pim send fail pim send fail\n");
            return VOS_ERROR;
        }
    }
    memcpy(&dst_addr, pstDst, sizeof(VOS_IP_ADDR));


    if (PIM_TYPE_HELLO != type)
    {
        PIM_DEBUG("Pimsm Send %s message , IntName:%s, SrcAddr:%s, DstAddr:%s.\n",
                  get_msg_type(type, msg_type),
                  pimsm_GetIfName(pimsm_ifp->ifindex),
                  pim_InetFmt(&src_addr),
                  pim_InetFmt(&dst_addr));
    }

    /* ip packet */
    pim_msg_size = pim_tlv_size + PIM_PIM_MIN_LEN;
    pim_msg_build_header(pim_msg, pim_msg_size,
                         type);

    struct in_addr dst;
    dst.s_addr = *(in_addr_t *)pstDst;

    if (pimsm_msg_send(pimsm_ifp->pimsm_sock_fd, dst, pim_msg, pim_msg_size, ifindex2ifname(pimsm_ifp->ifindex)) != VOS_OK)
    {
        pimsm_SendTrafficStatistics(pimsm_ifp,type,VOS_ERROR);
        PIM_DEBUG("pim send fail return VOS_ERROR\n");
        return VOS_ERROR;
    }

    pimsm_SendTrafficStatistics(pimsm_ifp,type,VOS_OK);

    return VOS_OK;
}

int pimsm_SendHello(uint32_t ifindex, uint16_t hold_time, VOS_IP_ADDR *nbr_primary_addr)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    struct pimsm_timer_para_hello *hello_para;
    struct pimsm_neighbor_entry *pimsm_neigh;
    uint8_t *pucDataPtr = NULL;
    uint8_t *pucBuf = NULL;
    uint32_t data_len;


    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pucBuf = g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN;
    pucDataPtr = pucBuf;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        return VOS_ERROR;
    }

    if (ip_isAnyAddress(&pimsm_ifp->primary_address))
    {
        return VOS_OK;
    }

    /* ??????holdtime?????? */
    PUT_HOSTSHORT(PIM_HELLO_HOLDTIME_OPTION, pucDataPtr);
    PUT_HOSTSHORT(PIM_HELLO_HOLDTIME_LEN, pucDataPtr);
    PUT_HOSTSHORT(hold_time, pucDataPtr);

    /* ??????prune delay?????? */
    PUT_HOSTSHORT(PIM_HELLO_PRUNE_DELAY, pucDataPtr);
    PUT_HOSTSHORT(PIM_HELLO_PRUNE_DELAY_LEN, pucDataPtr);
    PUT_HOSTSHORT(pimsm_ifp->pimsm_propagation_delay_msec, pucDataPtr);
    PUT_HOSTSHORT(pimsm_ifp->pimsm_override_interval_msec, pucDataPtr);

    /* ??????DR Priority?????? */
    PUT_HOSTSHORT(PIM_HELLO_DR_PRIORITY, pucDataPtr);
    PUT_HOSTSHORT(PIM_HELLO_DR_PRIORITY_LEN, pucDataPtr);
    PUT_HOSTLONG(pimsm_ifp->pimsm_dr_priority, pucDataPtr);

    /* ??????GenId?????? */
    PUT_HOSTSHORT(PIM_HELLO_GENERATION_ID, pucDataPtr);
    PUT_HOSTSHORT(PIM_HELLO_GENERATION_ID_LEN, pucDataPtr);
    PUT_HOSTLONG(pimsm_ifp->pimsm_generation_id, pucDataPtr);

    data_len = pucDataPtr - pucBuf;

    if (pimsm_SendPimPacket(g_stPimsm.pucSendBuf,ifindex,NULL,(VOS_IP_ADDR*)&(g_stPimsm.stAllPimRouters),PIM_TYPE_HELLO,data_len) == VOS_ERROR)
    {
        zlog_warn("Could not send PIM hello on interface %s",
                  ifindex2ifname(pimsm_ifp->ifindex));

        return -1;
    }


    if(nbr_primary_addr != NULL)
    {
        if (!ip_isMulticastAddress(nbr_primary_addr))
        {
            pimsm_neigh = pimsm_SearchNeighbor(pimsm_ifp, nbr_primary_addr);
            if(pimsm_neigh != NULL)
            {
                pimsm_neigh->send_hello_already = TRUE;
            }
        }
    }

    /* restart hello period timer */
    if (0 != hold_time)
    {
        if (pimsm_ifp->t_pimsm_hello_timer)
            THREAD_OFF(pimsm_ifp->t_pimsm_hello_timer);

        hello_para =  XMALLOC(MTYPE_PIM_HELLO_PARA, sizeof(struct pimsm_timer_para_hello));

        hello_para->ifindex = ifindex;

        memset(&hello_para->neighbor_addr, 0x00, sizeof(VOS_IP_ADDR));

        THREAD_TIMER_ON(master, pimsm_ifp->t_pimsm_hello_timer,
                        on_pimsm_hello_send,
                        hello_para, pimsm_ifp->pimsm_hello_period);
    }
    return VOS_OK;
}

#define pim_protocol_packet_process

/*PIM receive hello*/
static int pimsm_ReceiveHello(uint32_t ifindex, VOS_IP_ADDR *src_addr, uint8_t *pim_msg, uint32_t pim_msg_size)
{
    struct pimsm_prefix_ipv4_list *pstSecondaryAddrToBeFree;
    struct pimsm_prefix_ipv4_list *pstSecondaryAddr;
    struct pimsm_neighbor_entry *pimsm_neigh = NULL;
    struct pimsm_neighbor_entry *pstNeighborNew = NULL;
    struct pimsm_neighbor_entry stNeighborInfo;
    struct pimsm_encoded_unicast_addr stEnUniAddr;
    struct pimsm_timer_para_hello *hello_para;
    struct pimsm_timer_para_neighbor *neigh_para;
    struct pimsm_interface_entry *pimsm_ifp;
    uint8_t bHoldTimePresent = FALSE;
    uint8_t bNeedSendHello = FALSE;
    uint16_t pimsm_propagation_delay_msec;
    uint16_t pimsm_override_interval_msec;
    uint8_t *pucEndOfMessage;
    uint8_t *pucEndOfAddrList;
    uint8_t *pucData = NULL;
    uint32_t dwHelloDelay;
    uint16_t wOptionType;
    uint16_t wOptionLenth;
    uint16_t hold_time;
    uint32_t dr_priority;
    uint32_t dwGenid;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("Can't find the interface(%d %s)!\n", ifindex, pimsm_GetIfName(ifindex));
        return VOS_OK;
    }

    /* If source address is local address */
    if(pimsm_IsLocalAddress(src_addr))
    {
        PIM_DEBUG("Receive a hello message with source address is my local address from interface(%d %s)!\n", ifindex, pimsm_GetIfName(ifindex));
        return VOS_OK;
    }

    pimsm_ifp->pimsm_ifstat.hello_recv++;

    /* init neighbor information */
    memset(&stNeighborInfo, 0, sizeof(struct pimsm_neighbor_entry));
    memcpy(&stNeighborInfo.source_addr, src_addr, sizeof(VOS_IP_ADDR));
    stNeighborInfo.version = (*pim_msg & 0xf0) >> 4;
    stNeighborInfo.mode = PIM_MODE_SM;

    /*
    The Holdtime option MUST be implemented;
    the DR Priority and Generation ID options SHOULD be implemented.
    The Address List option MUST be implemented for IPv6.(RFC7761 page:137)
    */
    pucEndOfMessage = (uint8_t *)(pim_msg + pim_msg_size);
    pucData = pim_msg + PIM_MSG_HEADER_LEN;
    while((pucData + PIM_OPTION_HEADER_LEN) <= pucEndOfMessage)
    {
        /* Ignore any data if shorter than (pim_hello header) */
        GET_HOSTSHORT(wOptionType, pucData);
        GET_HOSTSHORT(wOptionLenth, pucData);
        switch (wOptionType)
        {
        case PIM_HELLO_HOLDTIME_OPTION:
            if (wOptionLenth != PIM_HELLO_HOLDTIME_LEN)
            {
                PIM_DEBUG("Holdtime option with wrong lenth(%d)!\n", wOptionLenth);
                return VOS_ERROR;
            }
            GET_HOSTSHORT(hold_time, pucData);
            bHoldTimePresent = TRUE;
            break;
        case PIM_HELLO_ADDR_LIST:
            for (pucEndOfAddrList = pucData + wOptionLenth; pucData < pucEndOfAddrList; )
            {
                if (pucData + sizeof(struct pimsm_encoded_unicast_addr) > pucEndOfAddrList)
                {
                    PIM_DEBUG("Address List option with wrong address lenth!\n");
                    return VOS_ERROR;
                }

                GET_EUADDR(&stEnUniAddr, pucData);
                if (ADDRF_IPv4 != stEnUniAddr.family)
                {
                    PIM_DEBUG("Address List option with wrong address family(%d)!\n", stEnUniAddr.family);
                    continue;
                }

                //???????????????????????????????????????,???????????????????????????
                if (0 == ip_AddressCompare(&(stEnUniAddr.unicast_addr), src_addr))
                {
                    PIM_DEBUG("Address List option with a address same as the neighbor's primary address and ignored)!\n");
                    continue;
                }
                pstSecondaryAddr = XMALLOC(MTYPE_PIM_ADDR_PREFIXLEN_LIST, sizeof(struct pimsm_prefix_ipv4_list));

                memset(pstSecondaryAddr, 0, sizeof(struct pimsm_prefix_ipv4_list));
                pstSecondaryAddr->addr = stEnUniAddr.unicast_addr;

                if(stNeighborInfo.pstSecondaryAddrList != NULL)
                {
                    pstSecondaryAddr->next = stNeighborInfo.pstSecondaryAddrList;
                    stNeighborInfo.pstSecondaryAddrList->prev = pstSecondaryAddr;
                    stNeighborInfo.pstSecondaryAddrList = pstSecondaryAddr;
                }
                else
                {
                    stNeighborInfo.pstSecondaryAddrList = pstSecondaryAddr;
                }
            }
            break;
        case PIM_HELLO_GENERATION_ID:
            if (wOptionLenth != PIM_HELLO_GENERATION_ID_LEN)
            {
                PIM_DEBUG("Generation ID option with wrong lenth(%d)!\n", wOptionLenth);
                return VOS_ERROR;
            }
            GET_HOSTLONG(dwGenid, pucData);
            stNeighborInfo.pimsm_generation_id = dwGenid;
            break;
        case PIM_HELLO_DR_PRIORITY:
            if (wOptionLenth != PIM_HELLO_DR_PRIORITY_LEN)
            {
                PIM_DEBUG("DR priority option with wrong lenth(%d)!\n", wOptionLenth);
                return VOS_ERROR;
            }
            GET_HOSTLONG(dr_priority, pucData);
            stNeighborInfo.dr_priority = dr_priority;
            stNeighborInfo.bPriorityPresent = TRUE;
            break;
        case PIM_HELLO_PRUNE_DELAY:
            if (wOptionLenth != PIM_HELLO_PRUNE_DELAY_LEN)
            {
                PIM_DEBUG("Prune delay option with wrong lenth(%d)!\n", wOptionLenth);
                return VOS_ERROR;
            }
            GET_HOSTSHORT(pimsm_propagation_delay_msec, pucData);
            GET_HOSTSHORT(pimsm_override_interval_msec, pucData);
            stNeighborInfo.pimsm_override_interval_msec = pimsm_override_interval_msec;
            stNeighborInfo.pimsm_propagation_delay_msec = (pimsm_propagation_delay_msec & ~PIM_TRACKING_SUPPORT_BIT);
            stNeighborInfo.bLanPruneDelayPresent = TRUE;
            if (0 != (ntohl(pimsm_propagation_delay_msec) & PIM_TRACKING_SUPPORT_BIT))
            {
                stNeighborInfo.bTrackingSupport = TRUE;
            }
            break;
        default:
            /* Unknow options MUST be ignored and MUST NOT prevent a neighbor relationship from being formed. */
            PIM_DEBUG("Hello was recieved with unknown option(%d)!\n", wOptionType);
            pucData += wOptionLenth;
            break;
            return VOS_ERROR;
        }
    }

    /* The Holdtime option MUST be implemented. */
    if (!bHoldTimePresent)
    {
        return VOS_OK;
    }

    pimsm_neigh = pimsm_SearchNeighbor(pimsm_ifp, src_addr);
    if (NULL != pimsm_neigh)
    {
        if (0 == hold_time)
        {
            /* delete the neighbor */
            if(VOS_OK != pimsm_DelNbr(pimsm_ifp, pimsm_neigh))
            {
                return VOS_ERROR;
            }
            return VOS_OK;
        }
        pimsm_neigh->bPriorityPresent = stNeighborInfo.bPriorityPresent;
        /* DR priority changed */
        if(pimsm_neigh->dr_priority != stNeighborInfo.dr_priority)
        {
            pimsm_neigh->dr_priority = stNeighborInfo.dr_priority;
            PIM_DEBUG("Neighbor DR Priority changed, need do something.\n");
        }
        /* Generation ID changed */
        if(pimsm_neigh->pimsm_generation_id != stNeighborInfo.pimsm_generation_id)
        {
            pimsm_neigh->pimsm_generation_id = stNeighborInfo.pimsm_generation_id;
            PIM_DEBUG("Neighbor Generation ID changed, need do something.\n");
        }
        pimsm_neigh->version = stNeighborInfo.version;

        pstSecondaryAddr = pimsm_neigh->pstSecondaryAddrList;
        while (NULL != pstSecondaryAddr)
        {
            pstSecondaryAddrToBeFree = pstSecondaryAddr;
            pstSecondaryAddr = pstSecondaryAddr->next;
            XFREE(MTYPE_PIM_ADDR_PREFIXLEN_LIST, pstSecondaryAddrToBeFree);
        }
        pimsm_neigh->pstSecondaryAddrList = stNeighborInfo.pstSecondaryAddrList;

        /* need restart neighbor KeepAlive timer */
        if (pimsm_neigh->t_expire_timer)
            THREAD_OFF(pimsm_neigh->t_expire_timer);
    }
    else
    {
        if(PIMSM_NEIGHBOR_MAX_NUM_PER_INTERFACE <= pimsm_GetNeighborCount(pimsm_ifp))
        {
            PIM_DEBUG("The neighbor max count is %d per-interface, can't accept more.\n", PIMSM_NEIGHBOR_MAX_NUM_PER_INTERFACE);
            return VOS_ERROR;
        }

        pstNeighborNew = XMALLOC(MTYPE_PIM_NEIGHBOR, sizeof(struct pimsm_neighbor_entry));
        memset(pstNeighborNew, 0, sizeof(struct pimsm_neighbor_entry));
        memcpy(pstNeighborNew, &(stNeighborInfo), sizeof(struct pimsm_neighbor_entry));

        pstNeighborNew->creation = pim_time_monotonic_sec();

        pstNeighborNew->next = pimsm_ifp->pimsm_neigh;
        if(pimsm_ifp->pimsm_neigh != NULL)
        {
            pimsm_ifp->pimsm_neigh->prev = pstNeighborNew;
        }
        pimsm_ifp->pimsm_neigh = pstNeighborNew;
        pimsm_ifp->options &= ~PIMSM_IF_FLAG_NONBRS;

        /* beging: added by xjy 2005.5.31 */
        /* ??????????????????????????????????????????????????????????????????????????????join/prune??????
        ??????????????????????????????????????????????????????????????????hello???0-5??????,??????
        ?????????????????????????????????????????????????????????????????????????????????????????????
        join/prune?????? */
        /* end   : added by xjy 2005.5.31 */

        //bDRSelOrNot = TRUE;
        bNeedSendHello = TRUE;
        pimsm_neigh = pstNeighborNew;
        /*??????????????????bsr?????? add by hgx*/
        pim_SendBootstrapMsg(src_addr);
    }

    /*If the Holdtime is set to`0xffff', the receiver of this message
    never times out the neighbor. This may be used with ISDN lines,
    to avoid keeping the link up with periodic Hello messages.*/
    if (PIM_HELLO_HOLDTIME_FOREVER > hold_time)
    {
        neigh_para = XMALLOC(MTYPE_PIM_NEIGH_PARA, sizeof(struct pimsm_timer_para_neighbor));

        neigh_para->ifindex = ifindex;
        neigh_para->source_addr.u32_addr[0] = stNeighborInfo.source_addr.u32_addr[0];

        THREAD_TIMER_ON(master, pimsm_neigh->t_expire_timer,
                        pimsm_on_neighbor_timer,
                        neigh_para, (uint32_t)hold_time);

    }

    /* ???????????????0???5??????????????????hello?????? */
    if(bNeedSendHello)
    {
        hello_para =  XMALLOC(MTYPE_PIM_HELLO_PARA, sizeof(struct pimsm_timer_para_hello));

        hello_para->ifindex = ifindex;
        hello_para->neighbor_addr.u32_addr[0] = stNeighborInfo.source_addr.u32_addr[0];

        dwHelloDelay = (uint32_t)(rand() % (PIM_TRIGGER_HELLO_DELAY + 1));

        if (pimsm_ifp->t_pimsm_hello_timer)
            THREAD_OFF(pimsm_ifp->t_pimsm_hello_timer);

        THREAD_TIMER_ON(master, pimsm_ifp->t_pimsm_hello_timer,
                        on_pimsm_hello_send,
                        hello_para, dwHelloDelay);
    }

    pimsm_DRElection(pimsm_ifp);

    return VOS_OK;
}

static int pimsm_ReceiveRegister(uint32_t ifindex,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstDstAddr,uint8_t *pim_msg,uint32_t pim_msg_size)
{
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_register *pstRegister = NULL;
    struct ip *ip_hdr;
    uint32_t dwNullRegisterBit = 0;
    uint8_t bySendRegStop = FALSE;
    uint32_t dwBorderBit = 0;
    VOS_IP_ADDR stInnerGrp;
    VOS_IP_ADDR stInnerSrc;
    VOS_IP_ADDR rp_addr;
    uint32_t packet_len;
    int ret;

    g_stPimsm.dwInPimsmRegister++;

    if (!pimsm_IsLocalAddress(pstDstAddr))
    {
        PIM_DEBUG("Receive register packet but destination address(%s) is invalid, Not local address.\n", pim_InetFmt(pstDstAddr));
        return VOS_ERROR;
    }

    if ((PIM_MSG_HEADER_LEN + PIM_REGISTER_HEADER_LEN + sizeof(VOS_IP_ADDR)) > pim_msg_size)
    {
        PIM_DEBUG("Register packet error, Incorrect packet length (%d) from source (%s)!\n", pim_msg_size, pim_InetFmt(src_addr));
        return VOS_ERROR;
    }

    pstRegister = (struct pimsm_register *)(pim_msg + PIM_MSG_HEADER_LEN);

    /*BorderBit And NullRegisterBit */
    dwBorderBit = ntohl(pstRegister->flags) & PIM_REG_BORDER_BIT;
    dwNullRegisterBit = ntohl(pstRegister->flags) & PIM_REG_NULL_REGISTER_BIT;

    ip_hdr = (struct ip *)((char *)pstRegister + PIM_REGISTER_HEADER_LEN);
    if (IP_VERSION != ip_hdr->ip_v)
    {
        PIM_DEBUG("Register packet error, Incorrect IP version (%d) of the inner from source (%s)!\n", ip_hdr->ip_v, pim_InetFmt(src_addr));
        return VOS_ERROR;
    }
    packet_len = pim_msg_size - (PIM_MSG_HEADER_LEN + PIM_REGISTER_HEADER_LEN);

    stInnerSrc.u32_addr[0] = ip_hdr->ip_src.s_addr;
    stInnerGrp.u32_addr[0] = ip_hdr->ip_dst.s_addr;

    if (!pimsm_AcceptRegist(&stInnerSrc))
    {
        char ss[SS_DEB_lENTH];
        uint8_t blRetval;

        blRetval = Debug_Common_Func();
        if(blRetval)
        {
            sprintf(ss, "SOURCE(%s) COULD NOT ACCEPT!\n",
                    pim_InetFmt(&stInnerSrc));
            zlog_debug(ss);
        }

        pimsm_SendRegisterStop(src_addr, pstDstAddr, &stInnerSrc, &stInnerGrp);
        return VOS_OK;
    }

    if (!ip_isMulticastAddress(&stInnerGrp)
            || ip_isMulticastLocalAddr(&stInnerGrp))
    {
        PIM_DEBUG("Register packet error, Inner group(%s) has invalid scope!\n", pim_InetFmt(&stInnerGrp));
        return VOS_ERROR;
    }

    if (pimsm_IsSsmRangeAddr(&stInnerGrp))
    {
        pimsm_SendRegisterStop(src_addr, pstDstAddr, &stInnerSrc, &stInnerGrp);
        return VOS_OK;
    }

    memset(&rp_addr, 0x00, sizeof(VOS_IP_ADDR));
    ret = pimsm_RpSearch(&stInnerGrp, &rp_addr);
    if (VOS_ERROR == ret)
    {
        PIM_DEBUG("Register packet error, Group(%s) no match Rp address!\n", pim_InetFmt(&stInnerGrp));
        return VOS_ERROR;
    }

    if(!pimsm_IamRP(&stInnerGrp) || (pstDstAddr->u32_addr[0] != rp_addr.u32_addr[0]))
    {
        //send Register-Stop(S,G) to src
        pimsm_SendRegisterStop(pstDstAddr, src_addr, &stInnerSrc, &stInnerGrp);
        return VOS_ERROR;
    }

    src_grp_entry = pimsm_SearchMrtEntry(&stInnerSrc, &stInnerGrp, PIMSM_MRT_TYPE_SG);
    if ((0 != dwNullRegisterBit) && ( NULL == src_grp_entry))
    {
        PIM_DEBUG("Receive NULL-REGISTER but no corresponding (S,G) entry,the packet is dropped!\n");
        return VOS_OK;
    }

    if (NULL == src_grp_entry)
    {
        PIM_DEBUG("create mrt entry, src:%s grp:%s.\n", pim_InetFmt(&stInnerSrc), pim_InetFmt(&stInnerGrp));
        src_grp_entry = pimsm_CreateMrtEntry(&stInnerSrc, &stInnerGrp, PIMSM_MRT_TYPE_SG, 0);
        if (NULL == src_grp_entry)
        {
            PIM_DEBUG("Receive register and Create (S,G) Entry invalid (S=%s,G=%s)!\n", pim_InetFmt(&stInnerSrc), pim_InetFmt(&stInnerGrp));
            return VOS_ERROR;
        }
    }
    src_grp_entry->flags |= PIMSM_MRT_FLAG_REG;

    bySendRegStop = FALSE;
    if(pimsm_SptBit(&stInnerSrc, &stInnerGrp) ||
            (pimsm_SwitchToSptDesired(&stInnerGrp) && (NULL == pimsm_InheritedOlist(src_grp_entry, FALSE))))
    {
        //send Register-Stop(S,G) to src
        pimsm_SendRegisterStop(pstDstAddr, src_addr, &stInnerSrc, &stInnerGrp);
        bySendRegStop = TRUE;
    }

    if(pimsm_SptBit(&stInnerSrc, &stInnerGrp) || pimsm_SwitchToSptDesired(&stInnerGrp))
    {
        if(bySendRegStop == TRUE)
        {
            //set KeepaliveTimer(S,G) to RP_Keepalive_Period
            pimsm_KeepAliveTimerStart(src_grp_entry, PIMSM_TIMER_VALUE_RP_KEEPALIVE_PERIOD);
        }
        else
        {
            //set KeepaliveTimer(S,G) to Keepalive_Period
            pimsm_KeepAliveTimerStart(src_grp_entry, PIMSM_TIMER_KEEPALIVE_PERIOD);
        }
    }

    if(!pimsm_SptBit(&stInnerSrc, &stInnerGrp) && !dwNullRegisterBit)
    {
        //decapsulate and forward the inner packet to inherited_olist(S,G,rpt) #Note (+)
        pimsm_SetCopyToCpu(src_grp_entry, TRUE);
    }

    if (pimsm_JoinDesired(src_grp_entry))
    {
        pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
    }

    return VOS_OK;
}

int pimsm_ReceiveRegisterStop(uint32_t ifindex,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstDstAddr,uint8_t *pim_msg,uint32_t pim_msg_size)
{
    struct pimsm_register_stop *pstRegisterStop = NULL;
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_encoded_unicast_addr stEncodUniSrc;
    struct pimsm_encoded_grp_addr stEncodGrp;
    VOS_IP_ADDR rp_addr;
    uint32_t dwDirectIf;
    int ret;

    g_stPimsm.dwInPimsmRegisterStop++;

    if (PIM_MSG_HEADER_LEN + sizeof(struct pimsm_register_stop) > pim_msg_size)
    {
        PIM_DEBUG("Receive register stop packet, incorrect pack length (%d) from source (%s) !\n", pim_msg_size, pim_InetFmt(src_addr));
        return VOS_ERROR;
    }

    /* ??????????????????????????? */
    pstRegisterStop = (struct pimsm_register_stop *)(pim_msg + PIM_MSG_HEADER_LEN);
    memcpy(&stEncodGrp, &(pstRegisterStop->stEncodGrpAddr), sizeof(struct pimsm_encoded_grp_addr));
    memcpy(&stEncodUniSrc, &(pstRegisterStop->stEncodSrcAddr), sizeof(struct pimsm_encoded_unicast_addr));

    /* ???????????????????????????????????? */
    dwDirectIf = pimsm_DirectIfSearch(&(stEncodUniSrc.unicast_addr));
    if (PIMSM_NO_IF == dwDirectIf)
    {
        PIM_DEBUG("Received struct pimsm_register_stop from RP for a non direct-connect source %s.\n", pim_InetFmt(&(stEncodUniSrc.unicast_addr)));
        return VOS_ERROR;
    }

    src_grp_entry = pimsm_SearchMrtEntry(&stEncodUniSrc.unicast_addr, &stEncodGrp.grp_addr, PIMSM_MRT_TYPE_SG);
    if (NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    memset(&rp_addr, 0x00, sizeof(VOS_IP_ADDR));
    ret = pimsm_RpSearch(&src_grp_entry->group->address, &rp_addr);
    if (VOS_ERROR == ret)
    {
        PIM_DEBUG("Group(%s) no match Rp address!\n", pim_InetFmt(&src_grp_entry->group->address));
        return VOS_ERROR;
    }

    if (0 != ip_AddressCompare(&rp_addr, src_addr))
    {
        PIM_DEBUG("Receive struct pimsm_register_stop from non RP(%s)!", pim_InetFmt(src_addr));
        return VOS_ERROR;
    }

    //pimsm_RegisterStopReceiveEvent(src_grp_entry);
    pimsm_RegisterStateMachineEventProc(src_grp_entry, PimsmRegEventRegStopRecv);

    return VOS_OK;
}

int pimsm_ReceiveJoinPrune(uint32_t ifindex, VOS_IP_ADDR *src_addr, uint8_t *pim_msg, uint32_t pim_msg_size)
{
    struct pimsm_updown_state_machine_event_para stEventPara;
    struct pimsm_encoded_grp_addr *pstEncodedGrpAddr = NULL;
    struct pimsm_encoded_src_addr *pstEncodedSrcAddr = NULL;
    struct pimsm_updownstream_if_entry *downstream_if = NULL;
    struct pimsm_encoded_unicast_addr stTarget;
    struct pimsm_mrt_entry *pstSrcGrpRptEntry = NULL;
    struct pimsm_mrt_entry *pstSrcGrpEntryNext = NULL;
    struct pimsm_mrt_entry *start_grp_entry = NULL;
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_grp_entry *pstGrpEntry = NULL;
    struct pimsm_jp_header *pstJPHead = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    struct pimsm_jp_grp *pstJPGrp = NULL;
    uint32_t dwJPGrpsLen;
    uint16_t wNumPruneSrc;
    uint16_t wNumJoinSrc;
    uint16_t hold_time;
    uint8_t byNumGrps;
    uint32_t dwSrcLen;
    uint8_t byPruneSrcGrpRptExist = FALSE;
    uint8_t byJoinStarGrpExist = FALSE;
    int i;
    int j;

    zassert((NULL != src_addr) && (NULL != pim_msg));

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("pimsm_ReceiveJoinPrune: Can't find the Interface by index(%d)!\n", ifindex);
        return VOS_ERROR;
    }

    /*
    if (!pimsm_IsMyNeighbor(ifindex, src_addr))
    {
    	PIM_DEBUG("pimsm_ReceiveJoinPrune: Data from unknown neighbor(%s) from interface(%x)!\n", pim_InetFmt(src_addr), ifindex);
    	return VOS_ERROR;
    }
    */

    pimsm_ifp->pimsm_ifstat.join_prune_recv++;

    /* check message length */
    if (PIM_JP_MINLEN > pim_msg_size)
    {
        PIM_DEBUG("pimsm_ReceiveJoinPrune: Invalid message len(%d)\n", pim_msg_size);
        return VOS_ERROR;
    }

    pstJPHead = (struct pimsm_jp_header *)(pim_msg + PIM_MSG_HEADER_LEN);

    stTarget = pstJPHead->encod_upstream_nbr; /* Upstream Neighbor Address */
    byNumGrps = pstJPHead->num_groups; /* Number of groups */
    hold_time = ntohs(pstJPHead->hold_time); /* Hold time */

    if (0 == byNumGrps)
    {
        PIM_DEBUG("pimsm_ReceiveJoinPrune: No indication for groups in the message!\n");
        return VOS_ERROR;
    }
    if (0 == hold_time)
    {
        PIM_DEBUG("pimsm_ReceiveJoinPrune: The hold time is zero of this message!\n");
        return VOS_ERROR;
    }

    /* check message data */
    dwJPGrpsLen = pim_msg_size - PIM_JP_MINLEN;
    pstJPGrp = (struct pimsm_jp_grp *)(pim_msg + PIM_JP_MINLEN);
    for (i = 0; i < byNumGrps; ++i)
    {
        if (dwJPGrpsLen < sizeof(struct pimsm_jp_grp))
        {
            PIM_DEBUG("Join/Prune message too short to contain enough data!\n");
            return VOS_ERROR;
        }
        dwJPGrpsLen -= sizeof(struct pimsm_jp_grp);

        wNumJoinSrc = ntohs(pstJPGrp->wNumJoin);
        wNumPruneSrc = ntohs(pstJPGrp->wNumPrune);
        dwSrcLen = (wNumJoinSrc + wNumPruneSrc) * sizeof(struct pimsm_encoded_src_addr);
        if (dwJPGrpsLen < dwSrcLen)
        {
            PIM_DEBUG("Join/Prune message too short to contain enough data!\n");
            return VOS_ERROR;
        }
        dwJPGrpsLen -= dwSrcLen;

        pstJPGrp = (struct pimsm_jp_grp *)((char *)pstJPGrp + sizeof(struct pimsm_jp_grp) + dwSrcLen);
    }

    dwJPGrpsLen = pim_msg_size - PIM_JP_MINLEN;
    pstJPGrp = (struct pimsm_jp_grp *)(pim_msg + PIM_JP_MINLEN);

    memset(&stEventPara, 0, sizeof(stEventPara));
    stEventPara.hold_time = hold_time;

    if(!pimsm_IsLocalIfAddress(ifindex, &stTarget.unicast_addr))
    {
        if (!pimsm_IsMyNeighbor(ifindex, &stTarget.unicast_addr))
        {
            PIM_DEBUG("pimsm_ReceiveJoinPrune: The upstream neighbor address(%s) is not my address and not my neighbor address on interface(0x%x)!\n", pim_InetFmt(&stTarget.unicast_addr), ifindex);
            return VOS_ERROR;
        }

        /* (*,G) Upstream Events */
        /* 1. JoinDesired(*,G) --> True */
        /* 2. JoinDesired(*,G) --> False */
        /* 3. See Join(*,G) to RPF'(*,G) */
        /* 4. See Prune(*,G) to RPF'(*,G) */

        /* (S,G) Upstream Events */
        /* 1. JoinDesired(S,G) --> True */
        /* 2. JoinDesired(S,G) --> False */
        /* 3. See Join(S,G) to RPF'(S,G) */
        /* 4. See Prune(S,G) to RPF'(S,G) */
        /* 5. See Prune(S,G,rpt) to RPF'(S,G) */
        /* 6. See Prune(*,G) to RPF'(S,G) */

        /* (S,G,rpt) Upstream Events */
        /* 1. PruneDesired(S,G,rpt) --> True */
        /* 2. PruneDesired(S,G,rpt) --> False */
        /* 3. RPTJoinDesired(G) --> False */
        /* 4. inherited_olist(S,G,rpt) --> non-NULL */
        /* 5. See Prune(S,G,rpt) to RPF'(S,G,rpt) */
        /* 6. See Join(S,G,rpt) to RPF'(S,G,rpt) */
        /* 7. See Prune(S,G) to RPF'(S,G,rpt) */

        /* (S,G) Assert State Machine Events */
        /* 1. Receive Join(S,G) on interface I */

        /* (*,G) Assert State Machine Events */
        /* 1. Receive Join(*,G) on interface I */
    }
    else
    {
        /* (*,G) Downstream Events */
        /* 1. Receive Join(*,G) */
        /* 2. Receive Prune(*,G) */

        /* (S,G) Downstream Events */
        /* 1. Receive Join(S,G) */
        /* 2. Receive Prune(S,G) */

        /* (S,G,rpt) Downstream Events */
        /* 1. Receive Join(*,G) */
        /* 2. Receive Join(S,G,rpt) */
        /* 3. Receive Prune(S,G,rpt) */
        /* 4. End of Message */

        /* (S,G) Assert State Machine Events */
        /* 1. Receive Join(S,G) on interface I */

        /* (*,G) Assert State Machine Events */
        /* 1. Receive Join(*,G) on interface I */

        for (i = 0; i < byNumGrps; ++i)
        {
            pstEncodedGrpAddr = &(pstJPGrp->stEncodGrpAddr);
            wNumJoinSrc = ntohs(pstJPGrp->wNumJoin);
            wNumPruneSrc = ntohs(pstJPGrp->wNumPrune);
            pstEncodedSrcAddr = (struct pimsm_encoded_src_addr*)((char*)pstJPGrp + sizeof(struct pimsm_jp_grp));

            /* check group address */
            if( (SINGLE_GRP_MSK6LEN < pstEncodedGrpAddr->mask_len) ||
                    (!ip_isMulticastAddress(&pstEncodedGrpAddr->grp_addr)) ||
                    ip_isMulticastLocalAddr(&pstEncodedGrpAddr->grp_addr) )
            {
                pstJPGrp = (struct pimsm_jp_grp *)((char *)pstJPGrp + sizeof(struct pimsm_jp_grp) +
                                                   ((wNumJoinSrc + wNumPruneSrc) * sizeof(struct pimsm_encoded_src_addr)) );
                continue;
            }

            /* (*,*,RP) */
            if( (0 == ip_AddressCompare(&g_stPimsm.stSockAddr6d, &pstEncodedGrpAddr->grp_addr)) &&
                    (STAR_STAR_RP_MSK6LEN == pstEncodedGrpAddr->mask_len) )
            {
                /* (*,*,RP) not support */
                pstJPGrp = (struct pimsm_jp_grp *)((char *)pstJPGrp + sizeof(struct pimsm_jp_grp) +
                                                   ((wNumJoinSrc + wNumPruneSrc) * sizeof(struct pimsm_encoded_src_addr)) );
                continue;
            }

            /* Join */
            for(j = 0; j < wNumJoinSrc; ++j, pstEncodedSrcAddr++)
            {
                /* check source address */
                if ((SINGLE_SRC_MSK6LEN < pstEncodedSrcAddr->mask_len) ||
                        (ip_isMulticastAddress(&pstEncodedSrcAddr->src_addr)))
                {
                    continue;
                }

                /* RPT=1 , WC=1 , Join(*,G) */
                if ((0 != (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                        (0 != (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Join(*,G) */
                    printf("Receive Join(*, %s).\n", pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (*,G) downstream machine */
                    downstream_if = pimsm_CreateDownstreamIf(NULL,
                                    &pstEncodedGrpAddr->grp_addr,
                                    PIMSM_MRT_TYPE_WC,
                                    0, ifindex);
                    if(NULL == downstream_if)
                    {
                        continue;
                    }
                    start_grp_entry = pimsm_SearchMrtEntry(NULL, &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_WC);
                    if(NULL != start_grp_entry)
                    {
                        pimsm_UpdownstreamStateMachineEventProc(
                            start_grp_entry,
                            PIMSM_DOWNSTREAM_IF,
                            ifindex,
                            PimsmReceiveJoinStarGrpEvent,
                            &stEventPara);

                        byJoinStarGrpExist = TRUE;

                        pimsm_AssertStateMachineEventProc(start_grp_entry,
                                                          ifindex,
                                                          PimsmAssertEvent_20,
                                                          NULL);
                    }

                    pstGrpEntry = pimsm_SearchGrpEntry(&pstEncodedGrpAddr->grp_addr);
                    if (NULL != pstGrpEntry)
                    {
                        /* All (S,G) */
                        src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                        while (NULL != src_grp_entry)
                        {
                            pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                            if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                            {
                                pimsm_UpdownstreamStateMachineEventProc(
                                    src_grp_entry,
                                    PIMSM_DOWNSTREAM_IF,
                                    ifindex,
                                    PimsmReceiveJoinStarGrpEvent,
                                    &stEventPara);
                            }

                            src_grp_entry = pstSrcGrpEntryNext;
                        }
                    }

                }
                /* RPT=0 , WC=0 , Join(S,G) */
                else if ((0 == (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                         (0 == (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Join(S,G) */
                    printf("Receive Join(%s, %s).\n", pim_InetFmt(&pstEncodedSrcAddr->src_addr),
                           pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (S,G) downstream machine */
                    downstream_if = pimsm_CreateDownstreamIf(&pstEncodedSrcAddr->src_addr,
                                    &pstEncodedGrpAddr->grp_addr,
                                    PIMSM_MRT_TYPE_SG,
                                    0, ifindex);
                    if(NULL == downstream_if)
                    {
                        continue;
                    }
                    src_grp_entry = pimsm_SearchMrtEntry(&pstEncodedSrcAddr->src_addr,
                                                         &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_SG);
                    if(NULL != src_grp_entry)
                    {
                        pimsm_UpdownstreamStateMachineEventProc(
                            src_grp_entry,
                            PIMSM_DOWNSTREAM_IF,
                            ifindex,
                            PimsmReceiveJoinSrcGrpEvent,
                            &stEventPara);

                        pimsm_AssertStateMachineEventProc(src_grp_entry,
                                                          ifindex,
                                                          PimsmAssertEvent_19,
                                                          NULL);

                        //pimsm_CheckMrtEntryValid(src_grp_entry);
                    }
                }
                /* RPT=1 , WC=0 , Join(S,G,rpt) */
                else if ((0 != (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                         (0 == (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Join(S,G,rpt) */
                    printf("Receive Join(%s, %s, rpt).\n", pim_InetFmt(&pstEncodedSrcAddr->src_addr),
                           pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (S,G,rpt) downstream machine */
                    downstream_if = pimsm_CreateDownstreamIf(&pstEncodedSrcAddr->src_addr,
                                    &pstEncodedGrpAddr->grp_addr,
                                    PIMSM_MRT_TYPE_SGRPT,
                                    0, ifindex);
                    if(NULL == downstream_if)
                    {
                        continue;
                    }
                    pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&pstEncodedSrcAddr->src_addr,
                                        &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_SGRPT);
                    if(NULL != pstSrcGrpRptEntry)
                    {
                        pimsm_UpdownstreamStateMachineEventProc(
                            pstSrcGrpRptEntry,
                            PIMSM_DOWNSTREAM_IF,
                            ifindex,
                            PimsmReceiveJoinSrcGrpRptEvent,
                            &stEventPara);

                        //pimsm_CheckMrtEntryValid(pstSrcGrpRptEntry);
                    }
                }
                else
                {
                    /* Unknow type , do nothing. */
                }
            }

            /* Prune */
            for(j = 0; j < wNumPruneSrc; ++j, pstEncodedSrcAddr++)
            {
                /* check source address */
                if ((SINGLE_SRC_MSK6LEN < pstEncodedSrcAddr->mask_len) ||
                        (ip_isMulticastAddress(&pstEncodedSrcAddr->src_addr)))
                {
                    continue;
                }

                /* RPT=1 , WC=1 , Prune(*,G) */
                if ((0 != (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                        (0 != (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Prune(*,G) */
                    printf("Receive Prune(*, %s).\n", pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (*,G) downstream machine */
                    start_grp_entry = pimsm_SearchMrtEntry(NULL, &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_WC);
                    if(NULL != start_grp_entry)
                    {
                        downstream_if = pimsm_SearchDownstreamIfByIndex(start_grp_entry->downstream_if, ifindex);
                        if(NULL != downstream_if)
                        {
                            pimsm_UpdownstreamStateMachineEventProc(
                                start_grp_entry,
                                PIMSM_DOWNSTREAM_IF,
                                ifindex,
                                PimsmReceivePruneStarGrpEvent,
                                &stEventPara);
                        }

                        //pimsm_CheckMrtEntryValid(start_grp_entry);
                    }
                }
                /* RPT=0 , WC=0 , Prune(S,G) */
                else if ((0 == (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                         (0 == (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Prune(S,G) */
                    PIM_DEBUG("Receive Prune(%s, %s).\n", pim_InetFmt(&pstEncodedSrcAddr->src_addr),
                              pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (S,G) downstream machine */
                    src_grp_entry = pimsm_SearchMrtEntry(&pstEncodedSrcAddr->src_addr,
                                                         &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_SG);
                    if(NULL != src_grp_entry)
                    {
                        PIM_DEBUG("src_grp_entry is not null.\n");
                        downstream_if = pimsm_SearchDownstreamIfByIndex(src_grp_entry->downstream_if, ifindex);
                        if(NULL != downstream_if)
                        {
                            PIM_DEBUG("downstream_if is not null.\n");
                            pimsm_UpdownstreamStateMachineEventProc(
                                src_grp_entry,
                                PIMSM_DOWNSTREAM_IF,
                                ifindex,
                                PimsmReceivePruneSrcGrpEvent,
                                &stEventPara);
                        }

                        //pimsm_CheckMrtEntryValid(src_grp_entry);
                    }
                }
                /* RPT=1 , WC=0 , Prune(S,G,rpt) */
                else if ((0 != (pstEncodedSrcAddr->flags & PIM_USADDR_RP)) &&
                         (0 == (pstEncodedSrcAddr->flags & PIM_USADDR_WC)))
                {
                    /* Event: Receive Prune(S,G,rpt) */
                    printf("Receive Prune(%s, %s, rpt).\n", pim_InetFmt(&pstEncodedSrcAddr->src_addr),
                           pim_InetFmt(&pstEncodedGrpAddr->grp_addr));

                    /* (S,G,rpt) downstream machine */
                    downstream_if = pimsm_CreateDownstreamIf(&pstEncodedSrcAddr->src_addr,
                                    &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_SGRPT, 0, ifindex);
                    if (NULL != downstream_if)
                    {
                        pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&pstEncodedSrcAddr->src_addr,
                                            &pstEncodedGrpAddr->grp_addr, PIMSM_MRT_TYPE_SGRPT);
                        pimsm_UpdownstreamStateMachineEventProc(
                            pstSrcGrpRptEntry,
                            PIMSM_DOWNSTREAM_IF,
                            ifindex,
                            PimsmReceivePruneSrcGrpRptEvent,
                            &stEventPara);

                        byPruneSrcGrpRptExist = TRUE;

                        //pimsm_CheckMrtEntryValid(pstSrcGrpRptEntry);
                    }
                }
                else
                {
                    /* Unknow type , do nothing. */
                }
            }

            pstJPGrp = (struct pimsm_jp_grp *)((char *)pstJPGrp + sizeof(struct pimsm_jp_grp) +
                                               ((wNumJoinSrc + wNumPruneSrc) * sizeof(struct pimsm_encoded_src_addr)) );
        }

        if (byJoinStarGrpExist && !byPruneSrcGrpRptExist)
        {
            pstGrpEntry = pimsm_SearchGrpEntry(&pstEncodedGrpAddr->grp_addr);
            if (NULL != pstGrpEntry)
            {
                /* All (S,G) */
                src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                while (NULL != src_grp_entry)
                {
                    pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                    if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                    {
                        pimsm_UpdownstreamStateMachineEventProc(
                            src_grp_entry,
                            PIMSM_DOWNSTREAM_IF,
                            ifindex,
                            PimsmEndOfMessageEvent,
                            &stEventPara);
                    }

                    src_grp_entry = pstSrcGrpEntryNext;
                }
            }
            printf("Pimsm receive Join(*,G) without Prune(S,G,rpt).\n");
        }
        else if (byJoinStarGrpExist && byPruneSrcGrpRptExist)
        {
            printf("Pimsm receive Join(*,G) with Prune(S,G,rpt).\n");
        }
    }

    return VOS_OK;
}

int pimsm_ReceiveAssert(uint32_t ifindex,VOS_IP_ADDR *src_addr,uint8_t *pim_msg,uint32_t pim_msg_size)
{
    struct pimsm_assert_state_machine_event_para stAssertEventPara;
    struct pimsm_mrt_entry *start_grp_entry = NULL;
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    struct pimsm_assert *pstAssertMsg = NULL;
    struct pimsm_assert_if * pimsmassert_if;
    VOS_IP_ADDR stAssertSrcAddr;
    VOS_IP_ADDR stAssertGrpAddr;
    uint32_t   preference;
    uint32_t   metric;
    struct pimsm_assert_metric stTargetMetric;
    uint8_t byRPTbit = 0;

    if((src_addr == NULL) || (pim_msg == NULL))
    {
        return VOS_ERROR;
    }

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("pimsm_ReceiveAssert: Can't find the Interface by index(%d)!\n", ifindex);
        return VOS_ERROR;
    }

    if (!pimsm_IsMyNeighbor(ifindex, src_addr))
    {
        //PIM_DEBUG("pimsm_ReceiveAssert: Assert from an unknown neighbor(%s) from %s!\n", pim_InetFmt(src_addr), pimsm_GetIfName(ifindex));
        //return VOS_ERROR;
    }

    pimsm_ifp->pimsm_ifstat.assert_recv++;

    pstAssertMsg = (struct pimsm_assert *)(pim_msg + PIM_MSG_HEADER_LEN);
    memcpy(&stAssertSrcAddr, &pstAssertMsg->stEncodSrcAddr.unicast_addr, sizeof(VOS_IP_ADDR));
    memcpy(&stAssertGrpAddr, &pstAssertMsg->stEncodGrpAddr.grp_addr, sizeof(VOS_IP_ADDR));
    preference = (ntohl(pstAssertMsg->preference) & ~PIMSM_ASSERT_RPTBIT);
    metric = ntohl(pstAssertMsg->metric);
    byRPTbit = (ntohl(pstAssertMsg->preference) & PIMSM_ASSERT_RPTBIT) ? 1 : 0;

    stTargetMetric.byRptBit = byRPTbit;
    stTargetMetric.dwMetricPref = preference;
    stTargetMetric.dwRouteMetric = metric;
    memcpy(&stTargetMetric.address, src_addr, sizeof(VOS_IP_ADDR));

    memcpy(&stAssertEventPara.stAssertMetric, &stTargetMetric, sizeof(struct pimsm_assert_metric));

    /* RPTbit is a 1-bit value. The RPTbit is set to 1 for Assert(*,G) messages and 0 for Assert(S,G) messages */
    if (0 == byRPTbit)
    {
        src_grp_entry = pimsm_SearchMrtEntry(&stAssertSrcAddr, &stAssertGrpAddr, PIMSM_MRT_TYPE_SG);
    }
    else
    {
        start_grp_entry = pimsm_SearchMrtEntry(NULL, &stAssertGrpAddr, PIMSM_MRT_TYPE_WC);
    }

    if (NULL != src_grp_entry)
    {
        pimsmassert_if = pimsm_SearchAssertIfByIndex(src_grp_entry->pimsmassert_if, ifindex);

        /* (S,G) Assert State Machine Events */
        /* 1. Receive Inferior Assert with RPTbit clear */
        if ((0 == byRPTbit) && pimsm_AssertMetricInferior(&stTargetMetric, src_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(src_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_04,
                                              &stAssertEventPara);
        }

        /* 2. Receive Assert with RPTbit set and CouldAssert(S,G,I) */
        if ((0 != byRPTbit) && pimsm_CouldAssert(src_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(src_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_14,
                                              &stAssertEventPara);
        }

        /* 3. Receive Acceptable Assert with RPTbit Clear and ASSTrDes(S,G,I) */
        if ((0 != byRPTbit) && pimsm_AssertMetricAcceptable(&stTargetMetric, src_grp_entry, ifindex) &&
                pimsm_AssertTrackingDesired(src_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(src_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_10,
                                              &stAssertEventPara);
        }

        /* 4. Receive Inferior Assert */
        if (pimsm_AssertMetricInferior(&stTargetMetric, src_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(src_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_03,
                                              &stAssertEventPara);
        }

        if (NULL != pimsmassert_if)
        {
            /* 5. Receive Preferred Assert */
            if(pimsm_AssertMetricPreferred(&stTargetMetric, src_grp_entry, ifindex))
            {
                pimsm_AssertStateMachineEventProc(src_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_08,
                                                  &stAssertEventPara);
            }

            /* 6. Receive Acceptable Assert with RPTbit clear from Current Winner */
            if ((0 == byRPTbit) && pimsm_AssertMetricAcceptable(&stTargetMetric, src_grp_entry, ifindex) &&
                    (0 == ip_AddressCompare(src_addr, &pimsmassert_if->stAssertStateMachine.stAssertWinner.address)))
            {
                pimsm_AssertStateMachineEventProc(src_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_11,
                                                  &stAssertEventPara);
            }

            /* 7. Receive Inferior Assert from Current Winner */
            /* 8. Receive Inferior Assert Cancel from Current Winner */
            if (pimsm_AssertMetricInferior(&stTargetMetric, src_grp_entry, ifindex) &&
                    (0 == ip_AddressCompare(src_addr, &pimsmassert_if->stAssertStateMachine.stAssertWinner.address)))
            {
                pimsm_AssertStateMachineEventProc(src_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_06,
                                                  &stAssertEventPara);
            }
        }

    }

    if(NULL != start_grp_entry)
    {
        //pimsmassert_if = pimsm_SearchDownstreamIfByIndex(start_grp_entry->pimsmassert_if, ifindex);
        pimsmassert_if = pimsm_SearchAssertIfByIndex(start_grp_entry->pimsmassert_if, ifindex);

        /* (*,G) Assert State Machine Events */
        /* 1. Receive Inferior Assert with RPTbit Set and CouldAssert(*,G,I) */
        if ((0 != byRPTbit) && pimsm_AssertMetricInferior(&stTargetMetric, start_grp_entry, ifindex) &&
                pimsm_CouldAssert(start_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(start_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_05,
                                              &stAssertEventPara);
        }

        /* 2. Receive Acceptable Assert with RPTbit set and AssTrDes(*,G,I) */
        if ((0 != byRPTbit) && pimsm_AssertMetricAcceptable(&stTargetMetric, start_grp_entry, ifindex) &&
                pimsm_AssertTrackingDesired(start_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(start_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_12,
                                              &stAssertEventPara);
        }

        /* 3. Receive Inferior Assert */
        if (pimsm_AssertMetricInferior(&stTargetMetric, start_grp_entry, ifindex))
        {
            pimsm_AssertStateMachineEventProc(start_grp_entry,
                                              ifindex,
                                              PimsmAssertEvent_03,
                                              &stAssertEventPara);
        }

        if (NULL != pimsmassert_if)
        {
            /* 4. Receive Preferred Assert */
            if (pimsm_AssertMetricPreferred(&stTargetMetric, start_grp_entry, ifindex))
            {
                pimsm_AssertStateMachineEventProc(start_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_08,
                                                  &stAssertEventPara);
            }

            /* 5. Receive Preferred Assert with RPTbit set */
            if ((0 != byRPTbit) && pimsm_AssertMetricPreferred(&stTargetMetric, start_grp_entry, ifindex))
            {
                pimsm_AssertStateMachineEventProc(start_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_09,
                                                  &stAssertEventPara);
            }

            /* 6. Receive Acceptable Assert from Current Winner with RPTbit set */
            if ((0 != byRPTbit) && pimsm_AssertMetricAcceptable(&stTargetMetric, start_grp_entry, ifindex) &&
                    (0 == ip_AddressCompare(src_addr, &pimsmassert_if->stAssertStateMachine.stAssertWinner.address)))
            {
                pimsm_AssertStateMachineEventProc(start_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_13,
                                                  &stAssertEventPara);
            }

            /* 7. Receive Inferior Assert from Current Winner */
            /* 8. Receive Inferior Assert Cancel from Current Winner */
            if (pimsm_AssertMetricInferior(&stTargetMetric, start_grp_entry, ifindex) &&
                    (0 == ip_AddressCompare(src_addr, &pimsmassert_if->stAssertStateMachine.stAssertWinner.address)))
            {
                pimsm_AssertStateMachineEventProc(start_grp_entry,
                                                  ifindex,
                                                  PimsmAssertEvent_06,
                                                  &stAssertEventPara);
            }
        }

    }

    return VOS_OK;
}

#define pim_packet_process
int pimsm_ReceiveProtocolDatagram(int ifindex, uint8_t *buf, size_t len)
{
    size_t ip_hlen; /* ip header length in bytes */
    char src_str[100];
    char dst_str[100];
    uint8_t *pim_msg;
    int pim_msg_len;
    uint8_t pim_version;
    uint8_t pim_type;
    uint16_t pim_checksum; /* received checksum */
    uint16_t checksum;     /* computed checksum */
    VOS_IP_ADDR dst_addr;
    VOS_IP_ADDR src_addr;
    char acMsgTypeStr[100];
    struct ip *ip_hdr;
    struct pimsm_interface_entry *pstFoundIf = NULL;

    if(NULL == buf)
        return -1;

    if (len < sizeof(*ip_hdr))
    {
        zlog_warn("PIM packet size=%zu shorter than minimum=%zu",
                  len, sizeof(*ip_hdr));
        return -1;
    }

    ip_hdr = (struct ip *) buf;

    pim_inet4_dump("<src?>", ip_hdr->ip_src, src_str, sizeof(src_str));
    pim_inet4_dump("<dst?>", ip_hdr->ip_dst, dst_str, sizeof(dst_str));

    ip_hlen = ip_hdr->ip_hl << 2; /* ip_hl gives length in 4-byte words */
    if (PIM_DEBUG_PIM_PACKETS)
    {
        zlog_debug("Recv IP packet from %s to %s on %s: size=%zu ip_header_size=%zu ip_proto=%d",
                   src_str, dst_str, ifindex2ifname(ifindex), len, ip_hlen, ip_hdr->ip_p);
    }

    if (ip_hdr->ip_p != PIM_IP_PROTO_PIM)
    {
        zlog_warn("IP packet protocol=%d is not PIM=%d",
                  ip_hdr->ip_p, PIM_IP_PROTO_PIM);
        return -1;
    }
    if (ip_hlen < PIM_IP_HEADER_MIN_LEN)
    {
        zlog_warn("IP packet header size=%zu shorter than minimum=%d",
                  ip_hlen, PIM_IP_HEADER_MIN_LEN);
        return -1;
    }
    if (ip_hlen > PIM_IP_HEADER_MAX_LEN)
    {
        zlog_warn("IP packet header size=%zu greater than maximum=%d",
                  ip_hlen, PIM_IP_HEADER_MAX_LEN);
        return -1;
    }
    pim_msg = buf + ip_hlen;
    pim_msg_len = len - ip_hlen;
    if (PIM_DEBUG_PIM_PACKETDUMP_RECV)
    {
        pim_pkt_dump(__PRETTY_FUNCTION__, pim_msg, pim_msg_len);
    }

    if (pim_msg_len < PIM_PIM_MIN_LEN)
    {
        zlog_warn("PIM message size=%d shorter than minimum=%d",
                  pim_msg_len, PIM_PIM_MIN_LEN);
        return -1;
    }

    pim_version = PIM_MSG_HDR_GET_VERSION(pim_msg);
    pim_type    = PIM_MSG_HDR_GET_TYPE(pim_msg);

    if (pim_version != PIM_PROTO_VERSION)
    {
        zlog_warn("Ignoring PIM pkt from %s with unsupported version: %d",
                  ifindex2ifname(ifindex), pim_version);
        return -1;
    }

    /* save received checksum */
    pim_checksum = PIM_MSG_HDR_GET_CHECKSUM(pim_msg);

    /* for computing checksum */
    *(uint16_t *) PIM_MSG_HDR_OFFSET_CHECKSUM(pim_msg) = 0;

    checksum = in_cksum(pim_msg, pim_msg_len);
    if (checksum != pim_checksum)
    {
        zlog_warn("Ignoring PIM pkt from %s with invalid checksum: received=%x calculated=%x",
                  ifindex2ifname(ifindex), pim_checksum, checksum);
        return -1;
    }
    if (PIM_DEBUG_PIM_PACKETS)
    {
        zlog_debug("Recv PIM packet from %s to %s on %s: ttl=%d pim_version=%d pim_type=%d pim_msg_size=%d checksum=%x",
                   src_str, dst_str, ifindex2ifname(ifindex), ip_hdr->ip_ttl,
                   pim_version, pim_type, pim_msg_len, checksum);
    }
    src_addr.u32_addr[0] = ip_hdr->ip_src.s_addr;
    dst_addr.u32_addr[0] = ip_hdr->ip_dst.s_addr;

    pstFoundIf = pimsm_SearchInterface(ifindex);
    if (pstFoundIf == NULL)
    {
        return VOS_ERROR;
    }
    else if((pstFoundIf->options & PIMSM_IF_FLAG_ENABLE) == 0 ||
            (pstFoundIf->options & PIMSM_IF_FLAG_UP) == 0)
    {
        return VOS_ERROR;
    }

    memset(acMsgTypeStr, 0, sizeof(acMsgTypeStr));
    get_msg_type(pim_type, acMsgTypeStr);

    switch (pim_type)
    {
    case PIM_TYPE_HELLO:
        //PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pimsm_ReceiveHello(ifindex, &src_addr, pim_msg, pim_msg_len);
        break;
    case PIM_TYPE_REGISTER:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pimsm_ReceiveRegister(ifindex, &src_addr, &dst_addr, pim_msg, pim_msg_len);
        break;
    case PIM_TYPE_REGISTER_STOP:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pimsm_ReceiveRegisterStop(ifindex, &src_addr, &dst_addr, pim_msg, pim_msg_len);
        break;
    case PIM_TYPE_JOIN_PRUNE:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pimsm_ReceiveJoinPrune(ifindex, &src_addr, pim_msg, pim_msg_len);
        break;
    case PIM_TYPE_BOOTSTRAP:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pim_ReceiveBootstrap(ifindex, &src_addr, pim_msg, pim_msg_len);
        pstFoundIf->pimsm_ifstat.bootstrap_recv++;
        break;
    case PIM_TYPE_ASSERT:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pimsm_ReceiveAssert(ifindex, &src_addr, pim_msg, pim_msg_len);
        break;
    case PIM_TYPE_GRAFT:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pstFoundIf->pimsm_ifstat.graft_recv++;
        break;
    case PIM_TYPE_GRAFT_ACK:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        g_stPimsm.dwInPimsmGraftAck++;
        break;
    case PIM_TYPE_CAND_RP_ADV:
        PIM_DEBUG("Pim receive a %s message ifname:%s, SrcAddr:%s, DstAddr:%s.\n", acMsgTypeStr, ifindex2ifname(ifindex), src_str, dst_str);
        pim_ReceiveCandRpAdv(ifindex, &src_addr, pim_msg, pim_msg_len);
        g_stPimsm.dwInPimsmCandRpAdv++;
        break;
    default:
        PIM_DEBUG("Ignore unknown PIM message code %u from %s.\n",pim_type, src_str);
        break;
    }

    return VOS_OK;
}
#if 0
int pimsm_if_connected_to_source(struct interface *ifp, struct in_addr src)
{
    struct listnode *cnode;
    struct connected *c;
    struct prefix p;

    if (!ifp)
        return 0;

    p.family = AF_INET;
    p.u.prefix4 = src;
    p.prefixlen = IPV4_MAX_BITLEN;

    for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c))
    {
        if ((c->address->family == AF_INET)
                && prefix_match(CONNECTED_PREFIX(c), &p))
        {
            return 1;
        }
    }
    return 0;
}
static int pimsm_mroute_msg_nocache(struct pimsm_interface_entry *pimsm_ifp, int fd,
                                    const struct igmpmsg *msg)
{
    struct interface *ifp;
    struct prefix_sg sg;

    ifp = if_lookup_by_index(pimsm_ifp->ifindex);
    if (ifp == NULL)
        return -1;
    /*
     *   If we've received a multicast packet that isn't connected to
     *   us
     */
    if (!pimsm_if_connected_to_source(ifp, msg->im_src))
    {
        zlog_debug(
            "%s: Received incoming packet that doesn't originate on our seg",
            __PRETTY_FUNCTION__);
        return 0;
    }
    memset(&sg, 0, sizeof(struct prefix_sg));
    sg.src = msg->im_src;
    sg.grp = msg->im_dst;
    if (!(pimsm_IamDR(pimsm_ifp->ifindex)))
    {
        //FIXME:
#if 0
        struct channel_oil *c_oil;

        if (PIM_DEBUG_MROUTE_DETAIL)
            zlog_debug("%s: Interface is not the DR blackholing incoming traffic for %s",
                       __PRETTY_FUNCTION__, pim_str_sg_dump(&sg));

        /*
         * We are not the DR, but we are still receiving packets
         * Let's blackhole those packets for the moment
         * As that they will be coming up to the cpu
         * and causing us to consider them.
         */
        c_oil = pim_channel_oil_add(pim_ifp->pim, &sg,
                                    pim_ifp->mroute_vif_index);
        pim_mroute_add(c_oil, __PRETTY_FUNCTION__);
#endif

        return 0;
    }

}
#endif
int pimsm_ReceiveMulticastDatagram(int fd, const char *buf, int buf_size)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    PIMSM_COULD_REGISTER_T emCheckState;
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_mrt_entry *mrt_entry;
    uint8_t rpf_check_error = FALSE;
    VOS_IP_ADDR up_nbr_addr;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;
    struct pimsm_oif *oif;
    int input_ifindex;

    const struct ip      *ip_hdr;
    const struct igmpmsg *msg;
    const char *upcall;
    char src_str[100];
    char grp_str[100];

    ip_hdr = (const struct ip *) buf;

    /* kernel upcall must have protocol=0 */
    if (ip_hdr->ip_p)
    {
        /* this is not a kernel upcall */
#ifdef PIM_UNEXPECTED_KERNEL_UPCALL
        PIM_DEBUG("not a kernel upcall proto=%d msg_size=%d.\n",
                  ip_hdr->ip_p, buf_size);
#endif
        return 0;
    }

    msg = (const struct igmpmsg *)buf;
    switch (msg->im_msgtype)
    {
    case IGMPMSG_NOCACHE:
        upcall = "NOCACHE";
        break;
    case IGMPMSG_WRONGVIF:
        upcall = "WRONGVIF";
        break;
    case IGMPMSG_WHOLEPKT:
        upcall = "WHOLEPKT";
        break;
    default:
        upcall = "<unknown_upcall?>";
        PIM_DEBUG("********************************************************************.\n");
    }

#if 1 //for test
    PIM_DEBUG("in pimsm_ReceiveMulticastDatagram upcall:%s.\n", upcall);
    //pim_pkt_dump(__PRETTY_FUNCTION__, (uint8_t *)buf, buf_size);
#endif

    input_ifindex = pimsm_if_find_by_vif_index(msg->im_vif);


    pim_inet4_dump("<src?>", msg->im_src, src_str, sizeof(src_str));
    pim_inet4_dump("<grp?>", msg->im_dst, grp_str, sizeof(grp_str));

    src_addr.u32_addr[0] = msg->im_src.s_addr;
    grp_addr.u32_addr[0] = msg->im_dst.s_addr;

    pimsm_ifp = pimsm_SearchInterface(input_ifindex);
    if (NULL == pimsm_ifp)
    {
        PIM_DEBUG("pimsm_ifp is NULL, input_ifindex:%d.\n", input_ifindex);
        return VOS_ERROR;
    }
    else if (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE))
    {
        PIM_DEBUG("options is not PIMSM_IF_FLAG_ENABLE.\n");
        return VOS_ERROR;
    }

#if 0
    if (ID_PROTOCOL_PIM != pucPktMsg->dwProtocolID)
    {
        return VOS_ERROR;
    }
#endif

    PIM_DEBUG(">>>>>>>>>>>>>>>>>>>>>>recv MulticastDatagram (S,G)%s %s, input name:%s.\n", src_str, grp_str, ifindex2ifname(input_ifindex));
    start_grp_entry = pimsm_SearchMrtEntry(NULL, &grp_addr, PIMSM_MRT_TYPE_WC);
    src_grp_entry = pimsm_SearchMrtEntry(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG);
    if ((NULL == start_grp_entry) && (NULL == src_grp_entry))
    {
        PIM_DEBUG("s,g is null.\n");
        /* Multicast entry not found */
        emCheckState = pimsm_CouldRegister(&src_addr, &grp_addr, input_ifindex);
        PIM_DEBUG("pimsm_CouldRegister return:%d.\n", emCheckState);
        if ((PimsmRegCheckCouldRegister == emCheckState) ||(PimsmRegCheckIamDrAndRp == emCheckState))
        {
            PIM_DEBUG("create mrt entry, src:%s grp:%s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr));
            src_grp_entry = pimsm_CreateMrtEntry(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG, PIMSM_MRT_FLAG_NUL);
            if(NULL == src_grp_entry)
            {
                return VOS_ERROR;
            }

            if (PimsmRegCheckCouldRegister == emCheckState)
            {
                PIM_DEBUG("pimsm register state machine event proc")
                pimsm_RegisterStateMachineEventProc(src_grp_entry, PimsmRegEventCouldRegToTrue);
                pimsm_DataForwardingOnRegTunnel((const char *)msg, buf_size, src_grp_entry->stRegStateMachine.pstRegisterTunnel);
            }
        }
        else if(PimsmRegCheckCouldNotRegister == emCheckState)
        {
            return VOS_ERROR;
        }

        return VOS_OK;
    }

    mrt_entry = src_grp_entry ? src_grp_entry : start_grp_entry;
    //RPF check
    if ((int)mrt_entry->upstream_if.ifindex != input_ifindex)
    {
        if ((NULL != src_grp_entry) && (!pimsm_SptBit(&src_addr, &grp_addr)))
        {
            if (NULL == start_grp_entry)
            {
                rpf_check_error = TRUE;
            }
            else if ((int)start_grp_entry->upstream_if.ifindex != input_ifindex)
            {
                rpf_check_error = TRUE;
            }
        }
        else
        {
            rpf_check_error = TRUE;
        }
    }
    PIM_DEBUG("here rpf_check_error:%d.\n", rpf_check_error);
    if (rpf_check_error)
    {
        if (NULL != src_grp_entry)
        {
            if (pimsm_CouldAssert(src_grp_entry, input_ifindex))
            {
                pimsm_AssertStateMachineEventProc(src_grp_entry, input_ifindex, PimsmAssertEvent_21, NULL);
            }
        }
        if (NULL != start_grp_entry)
        {
            if (pimsm_CouldAssert(start_grp_entry, input_ifindex))
            {
                pimsm_AssertStateMachineEventProc(start_grp_entry, input_ifindex, PimsmAssertEvent_22, NULL);
            }
        }
        return VOS_OK;
    }

    if (NULL != src_grp_entry)
    {
        PIM_DEBUG(">>>>>>>>enter here, src_grp_entry is not null.\n");
        //register tunnel exist
        if (NULL != src_grp_entry->stRegStateMachine.pstRegisterTunnel)
        {
            pimsm_DataForwardingOnRegTunnel((const char *)msg, buf_size, src_grp_entry->stRegStateMachine.pstRegisterTunnel);
        }
        else
        {
            emCheckState = pimsm_CouldRegister(&src_addr, &grp_addr, input_ifindex);
            if (PimsmRegCheckCouldRegister == emCheckState)
            {
                pimsm_RegisterStateMachineEventProc(src_grp_entry, PimsmRegEventCouldRegToTrue);
                if (NULL != src_grp_entry->stRegStateMachine.pstRegisterTunnel)
                {
                    pimsm_DataForwardingOnRegTunnel((const char *)msg, buf_size, src_grp_entry->stRegStateMachine.pstRegisterTunnel);
                }
            }
        }

        if (!pimsm_SptBit(&src_addr, &grp_addr) && ((int)src_grp_entry->upstream_if.ifindex == input_ifindex))
        {
            PIM_DEBUG("will set SPT flag.\n");
            //set SPT flag
            pimsm_SetSptBit(&src_grp_entry->source->address, &src_grp_entry->group->address, TRUE);
            if (NULL != start_grp_entry)
            {
                if (pimsm_JoinDesired(start_grp_entry))
                {
                    pimsm_RpfNeighborAddr(start_grp_entry, &up_nbr_addr);
                    pimsm_SendJoin(start_grp_entry, &up_nbr_addr);
                    //pimsm_UpdownstreamStateMachineEventProc(start_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToTrueEvent, NULL);
                }
            }
            return VOS_OK;
        }

        if (!pimsm_SptBit(&src_addr, &grp_addr) && (NULL != start_grp_entry))
        {
            oif = pimsm_ImmediateOlist(start_grp_entry, TRUE);
            //forward packet
            pimsm_FreeOil(oif);
        }
    }

    PIM_DEBUG("next to Switch to SPT.\n");
    //Switch to SPT
    if ((NULL != start_grp_entry) && (NULL == src_grp_entry))
    {
        PIM_DEBUG("Switch to SPT start.\n");
        //switch to spt
        if (pimsm_SwitchToSptDesired(&start_grp_entry->group->address) &&
                pimsm_LocalReceiverExist(start_grp_entry))
        {
            PIM_DEBUG("Switch to SPT step 1.\n");
            if (NULL == src_grp_entry)
            {
                PIM_DEBUG("create mrt entry, src:%s grp:%s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr));
                src_grp_entry = pimsm_CreateMrtEntry(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG, PIMSM_MRT_FLAG_NUL);
                if (NULL == src_grp_entry)
                {
                    PIM_DEBUG("src grp entry is null.\n");
                    return VOS_ERROR;
                }

                if (pimsm_JoinDesired(src_grp_entry) &&
                        (PimsmUpstreamStateNotJoined == src_grp_entry->upstream_if.stUpstreamStateMachine.emUpstreamState))
                {
                    PIM_DEBUG("pimsm join.\n");
                    pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                }
                PIM_DEBUG("Switch to SPT end.\n");

                /*
                if (pimsm_JoinDesired(start_grp_entry))
                {
                	pimsm_RpfNeighborAddr(start_grp_entry, &up_nbr_addr);
                	pimsm_SendJoin(start_grp_entry, &up_nbr_addr);
                	//pimsm_UpdownstreamStateMachineEventProc(start_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToTrueEvent, NULL);
                }
                */
            }
        }
        return VOS_OK;
    }
    return VOS_OK;
}

#endif
