#include "pimsm_define.h"
#if INCLUDE_PIMSM
#include <zebra.h>
#include "memory.h"
#include "thread.h"

#include "pimd.h"

#include "vos_types.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_register.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"
#include "pimsm_jp.h"

const char *pimsm_GetDownstreamStateString(PIMSM_DOWNSTREAM_STATE_T emState)
{
    const char *pca_down_state_string[] = {PIMSM_DOWNSTREAM_STATE_STR};

    if ((0 > emState) || (PimsmDownstreamStateEnd <= emState))
    {
        return "nul";
    }

    return pca_down_state_string[emState];
}

const char *pimsm_GetUpstreamStateString(PIMSM_UPSTREAM_STATE_T emState)
{
    const char *pca_up_state_string[] = {PIMSM_UPSTREAM_STATE_STR};

    if ((0 > emState) || (PimsmUpstreamStateEnd <= emState))
    {
        return "nul";
    }

    return pca_up_state_string[emState];
}

/* (*,G) AND (S,G) */
uint8_t pimsm_JoinDesired(struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_oif *pstOil1;
    struct pimsm_oif *pstOil2;

    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        //bool JoinDesired(S,G) {
        //	return ( immediate_olist(S,G) != NULL
        //		OR ( KeepaliveTimer(S,G) is running
        //			AND inherited_olist(S,G) != NULL ))
        //}
        pstOil1 = pimsm_ImmediateOlist(mrt_entry, FALSE);
        pstOil2 = pimsm_InheritedOlist(mrt_entry, FALSE);
        return ((NULL != pstOil1) || ((NULL != mrt_entry->t_pimsm_keep_alive_timer) && (NULL != pstOil2)));
    }
    else if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        //bool JoinDesired(*,G) {
        //	if(immediate_olist(*,G) != NULL)
        //		return TRUE
        //	else
        //		return FALSE
        //}
        if(NULL == pimsm_ImmediateOlist(mrt_entry, FALSE))
        {
            return FALSE;
        }
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

/* Just For (S,G,rpt) */
uint8_t pimsm_PruneDesired(struct pimsm_mrt_entry *mrt_entry)
{
    VOS_IP_ADDR stRpfNbrToSrc;
    VOS_IP_ADDR stRpfNbrToRp;

    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        if (pimsm_RPTJoinDesired(&mrt_entry->group->address))
        {
            if (NULL == pimsm_InheritedOlist(mrt_entry, FALSE))
            {
                return TRUE;
            }

            pimsm_RpfNeighborAddr(mrt_entry, &stRpfNbrToSrc);
            pimsm_RpfNeighborAddr(mrt_entry, &stRpfNbrToRp);
            if (!ip_isAnyAddress(&stRpfNbrToSrc) && !ip_isAnyAddress(&stRpfNbrToRp))
            {
                if (pimsm_SptBit(&mrt_entry->source->address, &mrt_entry->group->address) &&
                        (0 != ip_AddressCompare(&stRpfNbrToSrc, &stRpfNbrToRp)) )
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}
#if 0
uint8_t pimsm_PruneDesired(struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_rpf_entry *pstRpfToSrc;
    struct pimsm_rpf_entry *pstRpfToRp;

    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        if (pimsm_RPTJoinDesired(&mrt_entry->group->address))
        {
            if (NULL == pimsm_InheritedOlist(mrt_entry, FALSE))
            {
                return TRUE;
            }

            pstRpfToSrc = pimsm_SearchRpf(&mrt_entry->source->address);
            pstRpfToRp = pimsm_SearchRpf(&mrt_entry->group->rp_addr);
            if ((NULL != pstRpfToRp) && (NULL != pstRpfToSrc))
            {
                if (pimsm_SptBit(&mrt_entry->source->address, &mrt_entry->group->address) &&
                        (0 != ip_AddressCompare(&pstRpfToRp->stRpfNbr, &pstRpfToSrc->stRpfNbr)) )
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}
#endif

uint8_t pimsm_RPTJoinDesired(VOS_IP_ADDR *pstGrpAddr)
{
    struct pimsm_mrt_entry *mrt_entry;

    zassert(NULL != pstGrpAddr);

    mrt_entry = pimsm_SearchMrtEntry(NULL, pstGrpAddr, PIMSM_MRT_TYPE_WC);
    if (NULL == mrt_entry)
    {
        return FALSE;
    }

    return pimsm_JoinDesired(mrt_entry);
}

/*
mrt_entry: multicast route entry, (*,G) or (S,G) or (S,G,rpt)
pstUpstreamNeighborAddr: upstream neighbor address to RP or Source
*/
int pimsm_SendJoin(struct pimsm_mrt_entry *mrt_entry,VOS_IP_ADDR *pstUpstreamNbrAddr)
{
    struct pimsm_mrt_entry *pstSrcGrpRptEntry = NULL;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_interface_entry *pimsm_ifp;
    VOS_IP_ADDR stSrcGrpRptNbrAddr;
    VOS_IP_ADDR stStarGrpNbrAddr;
    VOS_IP_ADDR stSrcGrpNbrAddr;
    struct pimsm_jp_header *pstJPHead;
    struct pimsm_jp_grp *pstJPGrp;
    VOS_IP_ADDR up_nbr_addr;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;
    uint16_t wPruneSrcNum;
    uint16_t wJoinSrcNum;
    //struct pimsm_rpf *pstRpf;
    uint8_t *pucBuf = NULL;
    uint32_t pim_msg_size;

    zassert(NULL != mrt_entry);
    zassert(NULL != pstUpstreamNbrAddr);

    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pucBuf = (uint8_t *)g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN;
    pstJPHead = (struct pimsm_jp_header *)pucBuf;

    memcpy(&up_nbr_addr, pstUpstreamNbrAddr, sizeof(up_nbr_addr));
    PUT_EUADDR(up_nbr_addr, pucBuf); //Add upstream neighbor address
    pstJPHead->num_groups = 1;
    pstJPHead->reserved = 0;

    pimsm_ifp = pimsm_SearchInterface(mrt_entry->upstream_if.ifindex);
    if (NULL == pimsm_ifp)
    {
        return VOS_ERROR;
    }
    pstJPHead->hold_time = htons((uint16_t)(3.5 * pimsm_ifp->dwJoinPruneInterval));

    pstJPGrp = (struct pimsm_jp_grp *)(pstJPHead + 1);
    pucBuf = (uint8_t *)pstJPGrp;
    memcpy(&grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    PUT_EGADDR(grp_addr, SINGLE_GRP_MSK6LEN, 0, pucBuf);
    pucBuf = (uint8_t *)(pstJPGrp + 1);

    pim_msg_size = sizeof(struct pimsm_jp_header) + sizeof(struct pimsm_jp_grp);

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {

        printf("pimsm_SendJoin: Need to send a Join(*,G) message to %s with G=%s, Prune(S,G,rpt) exist or not.\n",
               pim_InetFmt(pstUpstreamNbrAddr),
               pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 0;
        wJoinSrcNum = 1;

        memset(&src_addr, 0, sizeof(VOS_IP_ADDR));
        memcpy(&src_addr, &mrt_entry->group->rp_addr, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_WC|PIM_USADDR_RP), pucBuf);

        src_grp_entry = mrt_entry->group->pstSrcMrtLink;
        while(NULL != src_grp_entry)
        {

            if(PIMSM_MRT_TYPE_SG == src_grp_entry->type && pimsm_SptBit(&src_grp_entry->source->address, &src_grp_entry->group->address))
            {
                memset(&stStarGrpNbrAddr, 0, sizeof(stStarGrpNbrAddr));
                memset(&stSrcGrpNbrAddr, 0, sizeof(stSrcGrpNbrAddr));
                pimsm_RpfNeighborAddr(mrt_entry, &stStarGrpNbrAddr);
                pimsm_RpfNeighborAddr(src_grp_entry, &stSrcGrpNbrAddr);
                if(stStarGrpNbrAddr.u32_addr[0] != stSrcGrpNbrAddr.u32_addr[0])
                {
                    /* add Prune(S,G,rpt) to compound message */
                    wPruneSrcNum++;
                    memcpy(&src_addr, &src_grp_entry->source->address, sizeof(VOS_IP_ADDR));
                    PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
                }

            }
            else if(PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
            {
                if(NULL == pimsm_SearchMrtEntry(&src_grp_entry->source->address, &src_grp_entry->group->address, PIMSM_MRT_TYPE_SG))
                {
                    if (NULL == pimsm_InheritedOlist(src_grp_entry, FALSE))
                    {
                        /* add Prune(S,G,rpt) to compound message */
                        wPruneSrcNum++;
                        memcpy(&src_addr, &src_grp_entry->source->address, sizeof(VOS_IP_ADDR));
                        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
                    }
                    else
                    {
                        memset(&stStarGrpNbrAddr, 0, sizeof(stStarGrpNbrAddr));
                        memset(&stSrcGrpRptNbrAddr, 0, sizeof(stSrcGrpRptNbrAddr));
                        pimsm_RpfNeighborAddr(mrt_entry, &stStarGrpNbrAddr);
                        pimsm_RpfNeighborAddr(src_grp_entry, &stSrcGrpRptNbrAddr);
                        if(stStarGrpNbrAddr.u32_addr[0] != stSrcGrpRptNbrAddr.u32_addr[0])
                        {
                            /* add Prune(S,G,rpt) to compound message */
                            wPruneSrcNum++;
                            memcpy(&src_addr, &src_grp_entry->source->address, sizeof(VOS_IP_ADDR));
                            PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
                        }
                    }
                }
            }
            else
            {
                pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&src_grp_entry->source->address, &src_grp_entry->group->address, PIMSM_MRT_TYPE_SGRPT);
                if(NULL != pstSrcGrpRptEntry)
                {
                    if (NULL == pimsm_InheritedOlist(pstSrcGrpRptEntry, FALSE))
                    {
                        /* add Prune(S,G,rpt) to compound message */
                        wPruneSrcNum++;
                        memcpy(&src_addr, &pstSrcGrpRptEntry->source->address, sizeof(VOS_IP_ADDR));
                        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
                    }
                    else
                    {
                        memset(&stStarGrpNbrAddr, 0, sizeof(stStarGrpNbrAddr));
                        memset(&stSrcGrpRptNbrAddr, 0, sizeof(stSrcGrpRptNbrAddr));
                        pimsm_RpfNeighborAddr(mrt_entry, &stStarGrpNbrAddr);
                        pimsm_RpfNeighborAddr(pstSrcGrpRptEntry, &stSrcGrpRptNbrAddr);
                        if(stStarGrpNbrAddr.u32_addr[0] != stSrcGrpRptNbrAddr.u32_addr[0])
                        {
                            /* add Prune(S,G,rpt) to compound message */
                            wPruneSrcNum++;
                            memcpy(&src_addr, &pstSrcGrpRptEntry->source->address, sizeof(VOS_IP_ADDR));
                            PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
                        }
                    }
                }
            }
            src_grp_entry = src_grp_entry->samegrpnext;
        }
    }
    else if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        PIM_DEBUG("pimsm_SendJoin: Need to send a Join(S,G) message to %s with S=%s G=%s.\n",
                  pim_InetFmt(pstUpstreamNbrAddr),
                  pim_InetFmt(&mrt_entry->source->address),
                  pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 0;
        wJoinSrcNum = 1;

        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, PIM_USADDR_S, pucBuf);
    }
    else if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        PIM_DEBUG("pimsm_SendJoin: Need to send a Join(S,G,rpt) message to %s with S=%s G=%s.\n",
                  pim_InetFmt(pstUpstreamNbrAddr),
                  pim_InetFmt(&mrt_entry->source->address),
                  pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 0;
        wJoinSrcNum = 1;

        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S|PIM_USADDR_RP), pucBuf);
    }
    else
    {
        return VOS_ERROR;
    }

    pstJPGrp->wNumJoin = htons(wJoinSrcNum);
    pstJPGrp->wNumPrune = htons(wPruneSrcNum);

    pim_msg_size += (wJoinSrcNum + wPruneSrcNum) * sizeof(struct pimsm_encoded_src_addr);
    pimsm_SendPimPacket(g_stPimsm.pucSendBuf,
                        mrt_entry->upstream_if.ifindex,
                        NULL,
                        pstUpstreamNbrAddr,
                        PIM_TYPE_JOIN_PRUNE,
                        pim_msg_size);

    return VOS_OK;
}

/*
mrt_entry: multicast route entry, (*,G) or (S,G) or (S,G,rpt)
pstUpstreamNeighborAddr: upstream neighbor address to RP or Source
*/
int pimsm_SendPrune(struct pimsm_mrt_entry *mrt_entry,VOS_IP_ADDR *pstUpstreamNbrAddr)
{
    struct pimsm_jp_header *pstJPHead;
    VOS_IP_ADDR up_nbr_addr;
    VOS_IP_ADDR grp_addr;
    struct pimsm_jp_grp *pstJPGrp;
    VOS_IP_ADDR src_addr;
    uint8_t *pucBuf = NULL;
    uint16_t wPruneSrcNum;
    uint16_t wJoinSrcNum;
    uint32_t pim_msg_size;

    zassert(NULL != mrt_entry);
    zassert(NULL != pstUpstreamNbrAddr);

    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pucBuf = (uint8_t *)(g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN);
    pstJPHead = (struct pimsm_jp_header *)pucBuf;

    memcpy(&up_nbr_addr, pstUpstreamNbrAddr, sizeof(up_nbr_addr));
    PUT_EUADDR(up_nbr_addr, pucBuf); //Add upstream neighbor address
    pstJPHead->num_groups = 1;
    pstJPHead->reserved = 0;
    pstJPHead->hold_time = htons(PIMSM_TIMER_VALUE_JOIN_PERIODIC); //default

    pstJPGrp = (struct pimsm_jp_grp *)(pstJPHead + 1);
    pucBuf = (uint8_t *)pstJPGrp;
    memcpy(&grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    PUT_EGADDR(grp_addr, SINGLE_GRP_MSK6LEN, 0, pucBuf);
    pucBuf = (uint8_t *)(pstJPGrp + 1);

    pim_msg_size = sizeof(struct pimsm_jp_header) + sizeof(struct pimsm_jp_grp);

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("pimsm_SendPrune: Need to send a Prune(*,G) message to %s with G=%s.\n",
               pim_InetFmt(pstUpstreamNbrAddr),
               pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 1;
        wJoinSrcNum = 0;

        memset(&src_addr, 0, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_WC |PIM_USADDR_RP) , pucBuf);
    }
    else if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        printf("pimsm_SendPrune: Need to send a Prune(S,G) message to %s with S=%s G=%s.\n",
               pim_InetFmt(pstUpstreamNbrAddr),
               pim_InetFmt(&mrt_entry->source->address),
               pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 1;
        wJoinSrcNum = 0;

        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, PIM_USADDR_S, pucBuf);
    }
    else if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        printf("pimsm_SendPrune: Need to send a Prune(S,G,rpt) message to %s with S=%s G=%s.\n",
               pim_InetFmt(pstUpstreamNbrAddr),
               pim_InetFmt(&mrt_entry->source->address),
               pim_InetFmt(&mrt_entry->group->address));

        wPruneSrcNum = 1;
        wJoinSrcNum = 0;

        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        PUT_ESADDR(src_addr, SINGLE_SRC_MSK6LEN, (PIM_USADDR_S | PIM_USADDR_RP), pucBuf);
    }
    else
    {
        return VOS_ERROR;
    }

    pstJPGrp->wNumJoin = htons(wJoinSrcNum);
    pstJPGrp->wNumPrune = htons(wPruneSrcNum);

    pim_msg_size += (wJoinSrcNum + wPruneSrcNum) * sizeof(struct pimsm_encoded_src_addr);

    pimsm_SendPimPacket(g_stPimsm.pucSendBuf,
                        mrt_entry->upstream_if.ifindex,
                        NULL,
                        pstUpstreamNbrAddr,
                        PIM_TYPE_JOIN_PRUNE,
                        pim_msg_size);

    return VOS_OK;
}

/* The action "Send PruneEcho(S,G)" is triggered whe the router stops forwarding on an interface as a result
of a prune. */
/*
mrt_entry: multicast route entry, (*,G) or (S,G) or (S,G,rpt)
pstUpstreamNeighborAddr: this address should be my downstream interface address
*/
static int pimsm_SendPruneEcho(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    zassert(NULL != mrt_entry);

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("pimsm_SendPruneEcho: Need to send a PruneEcho(*,G) message to downstream interface %s with G=%s.\n",
               ifindex2ifname(ifindex),
               pim_InetFmt(&mrt_entry->group->address));
    }
    else if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        printf("pimsm_SendPruneEcho: Need to send a PruneEcho(S,G) message to downstream interface %s with S=%s G=%s.\n",
               ifindex2ifname(ifindex),
               pim_InetFmt(&mrt_entry->source->address),
               pim_InetFmt(&mrt_entry->group->address));
    }
    else if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        printf("pimsm_SendPruneEcho: Need to PruneEcho(S,G,rpt) message to downstream interface %s with S=%s G=%s.\n",
               ifindex2ifname(ifindex),
               pim_InetFmt(&mrt_entry->source->address),
               pim_InetFmt(&mrt_entry->group->address));
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

#define up

static int pimsm_UpstreamIfStateChange(struct pimsm_mrt_entry *mrt_entry,PIMSM_UPSTREAM_STATE_T emStateFrom,PIMSM_UPSTREAM_STATE_T emStateTo)
{
    struct pimsm_updownstream_if_entry *pstDownIf = NULL;
    struct pimsm_assert_if *pimsmassert_if = NULL;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;

    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    memset(&src_addr, 0, sizeof(VOS_IP_ADDR));
    memset(&grp_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("(*, %s) upstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&grp_addr),
               pimsm_GetIfName(mrt_entry->upstream_if.ifindex),
               pimsm_GetUpstreamStateString(emStateFrom),
               pimsm_GetUpstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmUpstreamStateNotJoined:
            if (PimsmUpstreamStateJoined == emStateTo)
            {
                return VOS_OK;
            }
            break;
        case PimsmUpstreamStateJoined:
            if (PimsmUpstreamStateNotJoined == emStateTo)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(NULL != pstDownIf)
                {
                    if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                    {
                        return VOS_OK;
                    }
                    pstDownIf = pstDownIf->next;
                }
                pimsmassert_if = mrt_entry->pimsmassert_if;
                while (NULL != pimsmassert_if)
                {
                    if (PimsmAssertStateNoInfo != pimsmassert_if->stAssertStateMachine.emAssertState)
                    {
                        return VOS_OK;
                    }
                    pimsmassert_if = pimsmassert_if->next;
                }
                pimsm_DestroyMrtEntry(mrt_entry);
                //pimsm_MrtSetValid(mrt_entry, FALSE);
                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        printf("(%s, %s) upstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr),
               pimsm_GetIfName(mrt_entry->upstream_if.ifindex),
               pimsm_GetUpstreamStateString(emStateFrom),
               pimsm_GetUpstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmUpstreamStateNotJoined:
            if (PimsmUpstreamStateJoined == emStateTo)
            {
                return VOS_OK;
            }
            break;
        case PimsmUpstreamStateJoined:
            if (PimsmUpstreamStateNotJoined == emStateTo)
            {
                if((PIMSM_MRT_FLAG_REG != (mrt_entry->flags & PIMSM_MRT_FLAG_REG))	&&
                        (PimsmRegStateNoInfo == mrt_entry->stRegStateMachine.emRegisterState))
                {
                    pstDownIf = mrt_entry->downstream_if;
                    while(NULL != pstDownIf)
                    {
                        if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                        {
                            return VOS_OK;
                        }
                        pstDownIf = pstDownIf->next;
                    }
                    pimsmassert_if = mrt_entry->pimsmassert_if;
                    while (NULL != pimsmassert_if)
                    {
                        if (PimsmAssertStateNoInfo != pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            return VOS_OK;
                        }
                        pimsmassert_if = pimsmassert_if->next;
                    }
                    pimsm_DestroyMrtEntry(mrt_entry);
                    //pimsm_MrtSetValid(mrt_entry, FALSE);
                }
                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        printf("(%s, %s, rpt) upstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr),
               pimsm_GetIfName(mrt_entry->upstream_if.ifindex),
               pimsm_GetUpstreamStateString(emStateFrom),
               pimsm_GetUpstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmUpstreamStatePruned:
            if (PimsmUpstreamStateNotPruned == emStateTo)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(NULL != pstDownIf)
                {
                    if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                    {
                        return VOS_OK;
                    }
                    pstDownIf = pstDownIf->next;
                }
                pimsm_DestroyMrtEntry(mrt_entry);
                //pimsm_MrtSetValid(mrt_entry, FALSE);
                return VOS_OK;
            }
            else if (PimsmUpstreamStateRptNotJoined == emStateTo)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(NULL != pstDownIf)
                {
                    if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                    {
                        return VOS_OK;
                    }
                    pstDownIf = pstDownIf->next;
                }
                pimsm_DestroyMrtEntry(mrt_entry);
                //pimsm_MrtSetValid(mrt_entry, FALSE);
                return VOS_OK;
            }
            break;
        case PimsmUpstreamStateNotPruned:
            if (PimsmUpstreamStatePruned == emStateTo)
            {
                return VOS_OK;
            }
            else if (PimsmUpstreamStateRptNotJoined == emStateTo)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(NULL != pstDownIf)
                {
                    if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                    {
                        return VOS_OK;
                    }
                    pstDownIf = pstDownIf->next;
                }
                pimsm_DestroyMrtEntry(mrt_entry);
                //pimsm_MrtSetValid(mrt_entry, FALSE);
                return VOS_OK;
            }
            break;
        case PimsmUpstreamStateRptNotJoined:
            if (PimsmUpstreamStatePruned == emStateTo)
            {
                return VOS_OK;
            }
            else if (PimsmUpstreamStateNotPruned == emStateTo)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(NULL != pstDownIf)
                {
                    if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
                    {
                        return VOS_OK;
                    }
                    pstDownIf = pstDownIf->next;
                }
                pimsm_DestroyMrtEntry(mrt_entry);
                //pimsm_MrtSetValid(mrt_entry, FALSE);
                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

static int pimsm_StarGrpUpstreamEventProc(struct pimsm_mrt_entry *mrt_entry,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    PIMSM_UPSTREAM_STATE_T stUpstreamState;
    PIMSM_TIMER_PARA_JOIN_T *stJoinPara;
    VOS_IP_ADDR up_stream_nbr;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    stJoinPara = XMALLOC(MTYPE_PIM_JOIN_PARA, sizeof(PIMSM_TIMER_PARA_JOIN_T));

    memset(&stJoinPara->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&stJoinPara->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    stJoinPara->type = PIMSM_MRT_TYPE_WC;
    pimsm_RpfNeighborAddr(mrt_entry, &up_stream_nbr);

    stUpstreamState = mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState;
    switch(stUpstreamState)
    {
    case PimsmUpstreamStateNotJoined:
        if(PimsmJoinDesiredStarGrpToTrueEvent == byEventType)
        {
            /* The upstream (*,G) state mechaine transitions to the Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Send Join(*,G) to the appropriate upstream neighbor, which is RPF'(*,G). */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            /* Set the Join Timer(JT) to expire after t_periodic seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateNotJoined, PimsmUpstreamStateJoined);
        }
        break;
    case PimsmUpstreamStateJoined:
        if(PimsmJoinDesiredStarGrpToFalseEvent == byEventType)
        {
            /* The upstream (*,G) state machine transitions to the NotJoined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotJoined;
            /* Send Prune(*,G) to the appropriate upstream neighbor. */
            pimsm_SendPrune(mrt_entry, &up_stream_nbr);
            /* Cancel the Join Timer(JT). */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateNotJoined);
        }
        else if(PimsmJoinTimerExpiresEvent == byEventType)
        {
            /* Send Join(*,G) to the appropriate upstream neighbor, which is RPF'(*,G). */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            /* Restart the Join Timer(JT) to expire after t_periodic seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);

        }
        else if(PimsmSeeJoinStarGrpToRpfaStarGrpEvent == byEventType)
        {
            /* The upstream (*,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Increase Join Timer to t_joinsuppress. Let t_joinsuppress be the minimum of t_suppressed and the
            HoldTime from the Join/Prune message triggering this event. If the Join Timer is set to expire in less than
            t_joinsuppress seconds, reset it so that it expires after t_joinsuppress seconds. If the Join Timer is set to expire
            in more than t_joinsuppress seconds, leave it unchanged. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_SUPPRESSED);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmSeePruneStarGrpToRpfaStarGrpEvent == byEventType)
        {
            /* The upstream (*,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. If the Join Timer is set to expire in less than t_override seconds, leave
            it unchanged. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaStarGrpChangesDueAssertEvent == byEventType)
        {
            /* The upstream (*,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override senconds, reset
            it so that it expires after t_override seconds. If the Join Timer is set to expire in less than t_override seconds, leave
            it unchanged. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaStarGrpChangesNotAssertEvent == byEventType)
        {
            /* The upstream (*,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Send Join(*,G) to new upstream neighbor, which is the new value of RPF'(*,G). */
            pimsm_SendJoin(mrt_entry, &event_para->new_upstream_nbr_addr);
            /* Send Prune(*,G) to the old uppstream neighbor, which is the old value of RPF'(*,G). Use the new value of RP(G)
            in the Prune(*,G) message or all zeros if RP(G) becomes unknown (old value of RP(G) may be used instead to improve
            behavior in routers implementing older versions of this specification). */
            pimsm_SendPrune(mrt_entry, &event_para->old_upstream_nbr_addr);
            /* Set Join Timer(JT) to expire after t_periodic seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaStarGrpGenidChangesEvent == byEventType)
        {
            /* The upstream (*,G) state mcahine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        break;
    default:
        break;
    }

    return iResult;
}

static int pimsm_SrcGrpUpstreamEventProc(struct pimsm_mrt_entry *mrt_entry,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    PIMSM_UPSTREAM_STATE_T stUpstreamState;
    PIMSM_TIMER_PARA_JOIN_T *stJoinPara;
    VOS_IP_ADDR up_stream_nbr;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    stJoinPara = XMALLOC(MTYPE_PIM_JOIN_PARA, sizeof(PIMSM_TIMER_PARA_JOIN_T));

    memcpy(&stJoinPara->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&stJoinPara->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    stJoinPara->type = PIMSM_MRT_TYPE_SG;
    pimsm_RpfNeighborAddr(mrt_entry, &up_stream_nbr);

    stUpstreamState = mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState;
    switch(stUpstreamState)
    {
    case PimsmUpstreamStateNotJoined:
        if(PimsmJoinDesiredSrcGrpToTrueEvent == byEventType)
        {
            /* The upstream (S,G) state machine transitions to the Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Send Join(S,G) to the appropriate upstream neighbor, which is RPF'(S,G). */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            /* Set Join Timer(JT) to expire after t_periodic senconds. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateNotJoined, PimsmUpstreamStateJoined);
        }
        break;
    case PimsmUpstreamStateJoined:
        if(PimsmJoinDesiredSrcGrpToFalseEvent == byEventType)
        {
            /* The upstream (S,G) state machine transitions to the NotJoined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotJoined;
            /* Send Prune(S,G) to the appropriate upstream neighbor, which is RPF'(S,G). */
            pimsm_SendPrune(mrt_entry, &up_stream_nbr);
            /* Set SPTbit(S,G) to FALSE. */
            pimsm_SetSptBit(&mrt_entry->source->address, &mrt_entry->group->address, FALSE);
            /* Cancel the Join Timer(JT). */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateNotJoined);
        }
        else if(PimsmJoinTimerExpiresEvent == byEventType)
        {
            /* Send Join(S,G) to the appropriate upstream neighbor, which is RPF'(S,G). */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            /* Restart the Join Timer(JT) to expire after t_periodic seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);

        }
        else if(PimsmSeeJoinSrcGrpToRpfaSrcGrpEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Increase Join Timer to t_joinsuppress. Let t_joinsuppress be the minimum of t_suppressed and the
            HoldTime from the Join/Prune message triggering this event. If the Join Timer is set to expire in less than
            t_Joinsuppress seconds, reset it so that it expire after t_joinsuppress seconds. If the Join Timer is set to expire
            in more than t_joinsuppress seconds, leave it unchanged. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_SUPPRESSED);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmSeePruneSrcGrpToRpfaSrcGrpEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmSeePruneSrcGrpRptToRpfaSrcGrpEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expire after t_override seconds. */

            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmSeePruneStarGrpToRpfaSrcGrpEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaSrcGrpChangesNotAssertEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Send Join(S,G) to the new upstream neighbor, which is the new value of RPF'(S,G). */
            pimsm_SendJoin(mrt_entry, &event_para->new_upstream_nbr_addr);
            /* Send Prune(S,G) to the old upstream neighbor, which is the old value of RPF'(S,G). */
            pimsm_SendPrune(mrt_entry, &event_para->old_upstream_nbr_addr);
            /* Set the Join Timer(JT) to expire after t_periodic seconds. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_JOIN_PERIODIC);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaSrcGrpGenidChangesEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        else if(PimsmRpfaSrcGrpChangesDueAssertEvent == byEventType)
        {
            /* The upstream (S,G) state machine remains in Joined state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateJoined;
            /* Decrease Join Timer to t_override. If the Join Timer is set to expire in more than t_override seconds, reset
            it so that it expires after t_override seconds. If the Join Timer is set to expire in less than t_override seconds, leave
            it unchanged. */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateJoined, PimsmUpstreamStateJoined);
        }
        break;
    default:
        break;
    }

    return iResult;
}

static int pimsm_SrcGrpRptUpstreamEventProc(struct pimsm_mrt_entry *mrt_entry,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    PIMSM_UPSTREAM_STATE_T stUpstreamState;
    PIMSM_TIMER_PARA_JOIN_T *stJoinPara;
    VOS_IP_ADDR up_stream_nbr;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    stJoinPara = XMALLOC(MTYPE_PIM_JOIN_PARA, sizeof(PIMSM_TIMER_PARA_JOIN_T));

    memcpy(&stJoinPara->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&stJoinPara->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    stJoinPara->type = PIMSM_MRT_TYPE_SGRPT;
    pimsm_RpfNeighborAddr(mrt_entry, &up_stream_nbr);

    stUpstreamState = mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState;
    switch(stUpstreamState)
    {
    case PimsmUpstreamStatePruned:
        if(PimsmPruneDesiredSrcGrpRptToFalseEvent == byEventType)
        {
            /* NotPruned state */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotPruned;
            /* Send Join(S,G,rpt) */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStatePruned, PimsmUpstreamStateNotPruned);
        }
        else if(PimsmRptJoinDesiredGrpToFalse == byEventType)
        {
            /* RPTNotJoined state. The router no longer wishes to receive any traffic destined for G on the RP Tree. This
            causes a transition to the RPTNotJoined(G) state, and the Override Timer is canceled if it was running. Any
            further actions are handled by the appropriate upstream state machine for (*,G). */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateRptNotJoined;
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStatePruned, PimsmUpstreamStateRptNotJoined);
        }
        break;
    case PimsmUpstreamStateNotPruned:
        if(PimsmPruneDesiredSrcGrpRptToTrueEvent == byEventType)
        {
            /* The router wishes to receive traffic for G but does not wish to receive traffic from S destined for G. This causes
            the router to transition in to the Pruned state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStatePruned;
            /* If the router was previously in NotPruned state, then the action is to send a Prune(S,G,rpt) to RPF'(S,G,rpt), and
            to cancel the Override Timer. */
            pimsm_SendPrune(mrt_entry, &up_stream_nbr);
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateNotPruned, PimsmUpstreamStatePruned);
        }
        else if(PimsmRptJoinDesiredGrpToFalse == byEventType)
        {
            /* RPTNotJoined state. The router no longer wishes to receive any traffic destined for G on the RP Tree. This
            causes a transition to the RPTNotJoined(G) state, and the Override Timer is canceled if it was running. Any
            further actions are handled by the appropriate upstream state machine for (*,G). */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateRptNotJoined;
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);

            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateNotPruned, PimsmUpstreamStateRptNotJoined);
        }
        else if(PimsmOverrideTimerExpires == byEventType)
        {
            /* Send Join(S,G,rpt) */
            pimsm_SendJoin(mrt_entry, &up_stream_nbr);
            /* Leave Override Timer unset */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);
        }
        else if(PimsmSeePruneSrcGrpRptToRpfaSrcGrpRptEvent == byEventType)
        {
            /* Override Timer = min(Override Timer, t_override) */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
        }
        else if(PimsmSeeJoinSrcGrpRptToRpfaSrcGrpRptEvent == byEventType)
        {
            /* Cancel Override Timer */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);
        }
        else if(PimsmSeePruneSrcGrpToRpfaSrcGrpRptEvent == byEventType)
        {
            /* Override Timer = min(Override Timer, t_override) */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
        }
        else if(PimsmRpfaSrcGrpRptToRpfaStarGrpEvent == byEventType)
        {
            /* Override Timer = min(Override Timer, t_override) */
            if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
                THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);
            THREAD_TIMER_ON(master, mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer,
                            pimsm_TimeroutJoin,
                            stJoinPara, PIMSM_TIMER_VALUE_OVERRIDE);
        }
        break;
    case PimsmUpstreamStateRptNotJoined:
        if(PimsmPruneDesiredSrcGrpRptToTrueEvent == byEventType)
        {
            /* Pruned state */
            /* If the router was previously in RPTNotJoined(G) state, then there is no need to trigger an action
            in this state machine bucause sending a Prune(S,G,rpt) is handled by the rules for sending the Join(*,G). */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStatePruned;
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateRptNotJoined, PimsmUpstreamStatePruned);
        }
        else if(PimsmInheritedOlistSrcGrpRptToNonNullEvent == byEventType)
        {
            /* This does not trigger any events in this state machine, but causes a transition to the NotPruned(S,G,rpt) state. */
            mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotPruned;
            pimsm_UpstreamIfStateChange(mrt_entry, PimsmUpstreamStateRptNotJoined, PimsmUpstreamStateNotPruned);
        }
        break;
    default:
        break;
    }

    return iResult;
}

#define down

static int pimsm_DownstreamIfStateChange(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *pstDownIf,PIMSM_DOWNSTREAM_STATE_T emStateFrom,PIMSM_DOWNSTREAM_STATE_T emStateTo)
{
    struct pimsm_mrt_entry *pstSrcGrpEntryNext;
    //struct pimsm_mrt_entry *pstSrcGrpRptEntry;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_grp_entry *pstGrpEntry;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;


    if ((NULL == mrt_entry) || (NULL == pstDownIf))
    {
        return VOS_ERROR;
    }


    memset(&src_addr, 0, sizeof(VOS_IP_ADDR));
    memset(&grp_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    if ((PIMSM_MRT_TYPE_SG == mrt_entry->type) || (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type))
    {
        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    }

    // (*,G)
    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("(*, %s) downstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&grp_addr),
               pimsm_GetIfName(pstDownIf->ifindex),
               pimsm_GetDownstreamStateString(emStateFrom),
               pimsm_GetDownstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmDownstreamStateNoInfo:
            // NoInfo  -->	Join/Prune-Pending
            // From no forwarding to forwarding in the interface
            if ((PimsmDownstreamStateJoin == emStateTo) ||
                    (PimsmDownstreamStatePrunePending == emStateTo))
            {
                if (pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToTrueEvent, NULL);
                }

                pstGrpEntry = pimsm_SearchGrpEntry(&grp_addr);
                if (NULL != pstGrpEntry)
                {
                    /* All (S,G) */
                    src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                    while (NULL != src_grp_entry)
                    {
                        pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                        if (PIMSM_MRT_TYPE_SG == src_grp_entry->type)
                        {
                            if (pimsm_JoinDesired(src_grp_entry))
                            {
                                pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                            }
                        }
                        else if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                        {
                            if (NULL != pimsm_InheritedOlist(src_grp_entry, FALSE))
                            {
                                pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmInheritedOlistSrcGrpRptToNonNullEvent, NULL);
                            }
                        }

                        src_grp_entry = pstSrcGrpEntryNext;
                    }
                }
                return VOS_OK;
            }
            break;
        case PimsmDownstreamStateJoin:
        case PimsmDownstreamStatePrunePending:
            // Join/Prune-Pending  -->  NoInfo
            // From forwarding to no forwarding in the interface
            if (PimsmDownstreamStateNoInfo == emStateTo)
            {
                if ((PimsmAssertStateNoInfo == pimsm_AssertState(mrt_entry,  pstDownIf->ifindex)) &&
                        (PimsmDownstreamStateNoInfo == pstDownIf->down_stream_state_mchine.emDownstreamState) &&
                        (!pstDownIf->byLocalReceiverInclude))
                {
                    pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);
                }

                if (!pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToFalseEvent, NULL);
                }

                pstGrpEntry = pimsm_SearchGrpEntry(&grp_addr);
                if (NULL != pstGrpEntry)
                {
                    /* All (S,G) */
                    src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                    while (NULL != src_grp_entry)
                    {
                        pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                        if (PIMSM_MRT_TYPE_SG == src_grp_entry->type)
                        {
                            if (!pimsm_JoinDesired(src_grp_entry))
                            {
                                pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                            }
                        }
                        else if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                        {
                            if (!pimsm_RPTJoinDesired(&grp_addr))
                            {
                                pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmRptJoinDesiredGrpToFalse, NULL);
                            }
                        }

                        src_grp_entry = pstSrcGrpEntryNext;
                    }
                }
                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    // (S,G)
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        PIM_DEBUG("(%s, %s) downstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr),
                  pimsm_GetIfName(pstDownIf->ifindex),
                  pimsm_GetDownstreamStateString(emStateFrom),
                  pimsm_GetDownstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmDownstreamStateNoInfo:
            // NoInfo  -->	Join/Prune-Pending
            // From no forwarding to forwarding in the interface
            if ((PimsmDownstreamStateJoin == emStateTo) ||
                    (PimsmDownstreamStatePrunePending == emStateTo))
            {
                if (pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                }
                return VOS_OK;
            }
            break;
        case PimsmDownstreamStateJoin:
        case PimsmDownstreamStatePrunePending:
            // Join/Prune-Pending  -->  NoInfo
            // From forwarding to no forwarding in the interface
            if (PimsmDownstreamStateNoInfo == emStateTo)
            {
                if ((PimsmAssertStateNoInfo == pimsm_AssertState(mrt_entry,  pstDownIf->ifindex)) &&
                        (PimsmDownstreamStateNoInfo == pstDownIf->down_stream_state_mchine.emDownstreamState) &&
                        (!pstDownIf->byLocalReceiverInclude))
                {
                    pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);
                }

                if (!pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                }

                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    // (S,G,rpt)
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        printf("(%s, %s, rpt) downstream interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&src_addr), pim_InetFmt(&grp_addr),
               pimsm_GetIfName(pstDownIf->ifindex),
               pimsm_GetDownstreamStateString(emStateFrom),
               pimsm_GetDownstreamStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmDownstreamStateNoInfo:
        case PimsmDownstreamStatePrunePending:
        case PimsmDownstreamStatePrunePendingTmp:
            // NoInfo/Prune-Pending/Prune-Pending-Tmp  -->	Prune/PruneTmp
            if ((PimsmDownstreamStatePrune == emStateTo) ||
                    (PimsmDownstreamStatePruneTmp == emStateTo))
            {
                if (pimsm_PruneDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmPruneDesiredSrcGrpRptToTrueEvent, NULL);
                }

                src_grp_entry = pimsm_SearchMrtEntry(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG);
                if (NULL != src_grp_entry)
                {
                    if (!pimsm_JoinDesired(src_grp_entry))
                    {
                        pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                    }
                }
                return VOS_OK;
            }
            break;
        case PimsmDownstreamStatePrune:
        case PimsmDownstreamStatePruneTmp:
            // Prune/PruneTmp  -->	NoInfo/Prune-Pending/Prune-Pending-Tmp
            if ((PimsmDownstreamStateNoInfo == emStateTo) ||
                    (PimsmDownstreamStatePrunePending == emStateTo) ||
                    (PimsmDownstreamStatePrunePendingTmp == emStateTo))
            {
                if ((PimsmAssertStateNoInfo == pimsm_AssertState(mrt_entry,  pstDownIf->ifindex)) &&
                        (PimsmDownstreamStateNoInfo == pstDownIf->down_stream_state_mchine.emDownstreamState) &&
                        (!pstDownIf->byLocalReceiverInclude))
                {
                    pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);
                }

                if (!pimsm_PruneDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmPruneDesiredSrcGrpRptToFalseEvent, NULL);
                }

                src_grp_entry = pimsm_SearchMrtEntry(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG);
                if (NULL != src_grp_entry)
                {
                    if (pimsm_JoinDesired(src_grp_entry))
                    {
                        pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                    }
                }
                return VOS_OK;
            }
            break;
        default:
            break;
        }
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

static int pimsm_StarGrpDownstreamEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *downstream_if,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_prune_pending *prune_pending_para;
    PIMSM_DOWNSTREAM_STATE_T stDownstreamState;
    struct pimsm_timer_para_downif_expiry *expiry_para;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }
    expiry_para = XMALLOC(MTYPE_PIM_EXPIRY_PARA, sizeof(struct pimsm_timer_para_downif_expiry));
    prune_pending_para = XMALLOC(MTYPE_PIM_PRUNEPEND_PARA, sizeof(struct pimsm_timer_para_prune_pending));

    memset(&prune_pending_para->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&prune_pending_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    prune_pending_para->type = PIMSM_MRT_TYPE_WC;
    prune_pending_para->ifindex = downstream_if->ifindex;

    memset(&expiry_para->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&expiry_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    expiry_para->type = PIMSM_MRT_TYPE_WC;
    expiry_para->ifindex = downstream_if->ifindex;

    stDownstreamState = downstream_if->down_stream_state_mchine.emDownstreamState;
    switch(stDownstreamState)
    {
    case PimsmDownstreamStateNoInfo:
        if(PimsmReceiveJoinStarGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* start expiry timer , Set to the HoldTime from the triggering Join/Prune message. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateNoInfo, PimsmDownstreamStateJoin);
        }
        else if(PimsmReceivePruneStarGrpEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateNoInfo, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStateJoin:
        if(PimsmReceiveJoinStarGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* restart Expiry Timer , Set to the maxinum of its current value and the HoldTime from the triggering Join/Prune message. */

            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStateJoin);
        }
        else if (PimsmReceivePruneStarGrpEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            /* start Prune-Pending timer , It is set to the J/P_Override_Interval(I) if the router has more than one neighbor on that interface;
            otherwise, it is set to zero, causing it to expire immediately. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer);
            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer,
                            pimsm_TimeroutPrunePending,
                            prune_pending_para, PIMSM_TIMER_VALUE_JOIN_PRUNE_OVERRIDE);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStatePrunePending);
        }
        else if (PimsmDownIfTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStatePrunePending:
        if(PimsmReceiveJoinStarGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* The Prune-Pending Timer is canceled (without triggering an expiry event). */
            if (downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer);

            /* restart Expiry Timer , Set to the maxinum of its current value and the HoldTime from the triggering Join/Prune message. */

            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateJoin);
        }
        else if (PimsmReceivePruneStarGrpEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStatePrunePending);
        }
        else if (PimsmPrunePendingTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            /* Send Prune-Echo(*,G) */
            pimsm_SendPruneEcho(mrt_entry, downstream_if->ifindex);
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateNoInfo);
        }
        else if (PimsmDownIfTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateNoInfo);
        }
        break;
    default:
        break;
    }

    return iResult;
}

static int pimsm_SrcGrpDownstreamEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *downstream_if,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_prune_pending *prune_pending_para;
    PIMSM_DOWNSTREAM_STATE_T stDownstreamState;
    struct pimsm_timer_para_downif_expiry *expiry_para;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    expiry_para = XMALLOC(MTYPE_PIM_EXPIRY_PARA, sizeof(struct pimsm_timer_para_downif_expiry));
    prune_pending_para = XMALLOC(MTYPE_PIM_PRUNEPEND_PARA, sizeof(struct pimsm_timer_para_prune_pending));

    memcpy(&prune_pending_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&prune_pending_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    prune_pending_para->type = PIMSM_MRT_TYPE_SG;
    prune_pending_para->ifindex = downstream_if->ifindex;

    PIM_DEBUG("prune src:%s, grp:%s, ifindex:%d.\n", pim_InetFmt(&prune_pending_para->src_addr), pim_InetFmt(&prune_pending_para->grp_addr), downstream_if->ifindex);

    memcpy(&expiry_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&expiry_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    expiry_para->type = PIMSM_MRT_TYPE_SG;
    expiry_para->ifindex = downstream_if->ifindex;

    stDownstreamState = downstream_if->down_stream_state_mchine.emDownstreamState;
    switch(stDownstreamState)
    {
    case PimsmDownstreamStateNoInfo:
        if (PimsmReceiveJoinSrcGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* start Expiry Timer */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateNoInfo, PimsmDownstreamStateJoin);
        }
        else if (PimsmReceivePruneSrcGrpEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateNoInfo, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStateJoin:
        if (PimsmReceiveJoinSrcGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* restart Expiry Timer , Set to the maxinum of its current value and the HoldTime from the triggering Join/Prune message. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStateJoin);
        }
        else if (PimsmReceivePruneSrcGrpEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            /* start Prune-Pending Timer , It is set to the J/P_Override_Interval(I) if the router has more than one neighbor on that interface;
            otherwise, it is set to zero, causing it to expire immediately. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer,
                            pimsm_TimeroutPrunePending,
                            prune_pending_para, PIMSM_TIMER_VALUE_JOIN_PRUNE_OVERRIDE);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStatePrunePending);
        }
        else if (PimsmDownIfTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateJoin, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStatePrunePending:
        if (PimsmReceiveJoinSrcGrpEvent == byEventType)
        {
            /* Join state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateJoin;
            /* The Prune-Pending Timer is canceled (without triggering an expiry event). */
            if (downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer);

            /* restart Expiry Timer , Set to the maxinum of its current value and the HoldTime from the triggering Join/Prune message. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);


            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateJoin);
        }
        else if (PimsmReceivePruneSrcGrpEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStatePrunePending);
        }
        else if (PimsmPrunePendingTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            /* Send Prune-Echo(S,G) */
            pimsm_SendPruneEcho(mrt_entry, downstream_if->ifindex);
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateNoInfo);
        }
        else if (PimsmDownIfTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateNoInfo);
        }
        break;
    default:
        break;
    }

    return iResult;
}

static int pimsm_SrcGrpRptDownstreamEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *downstream_if,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_prune_pending *prune_pending_para;
    struct pimsm_timer_para_downif_expiry *expiry_para;
    PIMSM_DOWNSTREAM_STATE_T stDownstreamState;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    expiry_para = XMALLOC(MTYPE_PIM_EXPIRY_PARA, sizeof(struct pimsm_timer_para_downif_expiry));
    prune_pending_para = XMALLOC(MTYPE_PIM_PRUNEPEND_PARA, sizeof(struct pimsm_timer_para_prune_pending));

    memcpy(&prune_pending_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&prune_pending_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    prune_pending_para->type = PIMSM_MRT_TYPE_SGRPT;
    prune_pending_para->ifindex = downstream_if->ifindex;

    memcpy(&expiry_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&expiry_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    expiry_para->type = PIMSM_MRT_TYPE_SGRPT;
    expiry_para->ifindex = downstream_if->ifindex;

    stDownstreamState = downstream_if->down_stream_state_mchine.emDownstreamState;
    switch(stDownstreamState)
    {
    case PimsmDownstreamStateNoInfo:
        if(PimsmReceivePruneSrcGrpRptEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            /* start Prune-Pending Timer , It is set to the J/P_Override_Interval(I) if the router has more than one neighbor on that interface;
            otherwise, it is set to zero, causing it to expire immediately. */
            if (downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_prunpend_timer,
                            pimsm_TimeroutPrunePending,
                            prune_pending_para, PIMSM_TIMER_VALUE_JOIN_PRUNE_OVERRIDE);

            /* start Expiry Timer , Set to the HoldTime from the triggering Join/Prune message. */

            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStateNoInfo, PimsmDownstreamStatePrunePending);
        }
        break;
    case PimsmDownstreamStatePrune:
        if(PimsmReceiveJoinStarGrpEvent == byEventType)
        {
            /* PruneTmp state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePruneTmp;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrune, PimsmDownstreamStatePruneTmp);
        }
        else if(PimsmReceiveJoinSrcGrpRptEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrune, PimsmDownstreamStateNoInfo);
        }
        else if(PimsmReceivePruneSrcGrpRptEvent == byEventType)
        {
            /* Prune state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrune;
            /* restart Expiry Timer */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrune, PimsmDownstreamStatePrune);
        }
        else if(PimsmDownIfTimerExpiresEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrune, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStatePrunePending:
        if(PimsmReceiveJoinStarGrpEvent == byEventType)
        {
            /* Prune-Pending-Tmp state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePendingTmp;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStatePrunePendingTmp);
        }
        else if(PimsmReceiveJoinSrcGrpRptEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStateNoInfo);
        }
        else if(PimsmPrunePendingTimerExpiresEvent == byEventType)
        {
            /* Prune state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrune;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePending, PimsmDownstreamStatePrune);
        }
        break;
    case PimsmDownstreamStatePruneTmp:
        if(PimsmReceivePruneSrcGrpRptEvent == byEventType)
        {
            /* Prune state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrune;
            /* restart Expiry Timer */
            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);
            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePruneTmp, PimsmDownstreamStatePrune);
        }
        else if(PimsmEndOfMessageEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePruneTmp, PimsmDownstreamStateNoInfo);
        }
        break;
    case PimsmDownstreamStatePrunePendingTmp:
        if(PimsmReceivePruneSrcGrpRptEvent == byEventType)
        {
            /* Prune-Pending state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStatePrunePending;
            /* restart Expiry Timer */

            if (downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer)
                THREAD_OFF(downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer);

            THREAD_TIMER_ON(master, downstream_if->down_stream_state_mchine.t_pimsm_expiry_timer,
                            pimsm_TimeroutDownIfExpiry,
                            expiry_para, event_para->hold_time);

            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePendingTmp, PimsmDownstreamStatePrunePending);
        }
        else if(PimsmEndOfMessageEvent == byEventType)
        {
            /* NoInfo state */
            downstream_if->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;
            pimsm_DownstreamIfStateChange(mrt_entry, downstream_if, PimsmDownstreamStatePrunePendingTmp, PimsmDownstreamStateNoInfo);
        }
        break;
    default:
        break;
    }

    return iResult;
}

#define ud

int pimsm_UpstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    switch(mrt_entry->type)
    {
    case PIMSM_MRT_TYPE_WC:
        iResult = pimsm_StarGrpUpstreamEventProc(mrt_entry, byEventType, event_para);
        break;
    case PIMSM_MRT_TYPE_SG:
        iResult = pimsm_SrcGrpUpstreamEventProc(mrt_entry, byEventType, event_para);
        break;
    case PIMSM_MRT_TYPE_SGRPT:
        iResult = pimsm_SrcGrpRptUpstreamEventProc(mrt_entry, byEventType, event_para);
        break;
    default:
        break;
    }

    return iResult;
}

int pimsm_DownstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *downstream_if,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para)
{
    int iResult = VOS_OK;


    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    switch(mrt_entry->type)
    {
    case PIMSM_MRT_TYPE_WC:
        iResult = pimsm_StarGrpDownstreamEventProc(mrt_entry, downstream_if, byEventType, event_para);
        break;
    case PIMSM_MRT_TYPE_SG:
        iResult = pimsm_SrcGrpDownstreamEventProc(mrt_entry, downstream_if, byEventType, event_para);
        break;
    case PIMSM_MRT_TYPE_SGRPT:
        iResult = pimsm_SrcGrpRptDownstreamEventProc(mrt_entry, downstream_if, byEventType, event_para);
        break;
    default:
        break;
    }

    return iResult;
}

#define ev

/*
mrt_entry: multicast router entry, (*,G) OR (S,G) OR (S,G,rpt)
byUpOrDown: upstream or downstream state machine
ifindex: the interface of upstream or downstream
byEventType: state machine event type
event_para: event parameter
*/
int pimsm_UpdownstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry, uint8_t byUpOrDown, uint32_t ifindex, uint8_t byEventType, struct pimsm_updown_state_machine_event_para *event_para)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    int iResult = VOS_OK;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    switch(byUpOrDown)
    {
    case PIMSM_UPSTREAM_IF:
        iResult = pimsm_UpstreamStateMachineEventProc(mrt_entry, byEventType, event_para);
        break;
    case PIMSM_DOWNSTREAM_IF:
        downstream_if = pimsm_SearchDownstreamIfByIndex(mrt_entry->downstream_if, ifindex);
        if(NULL == downstream_if)
        {
            return VOS_ERROR;
        }
        iResult = pimsm_DownstreamStateMachineEventProc(mrt_entry, downstream_if, byEventType, event_para);
        break;
    default:
        break;
    }

    return iResult;
}

#endif
