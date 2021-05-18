#include "pimsm_define.h"
#if INCLUDE_PIMSM
#include <zebra.h>
#include "thread.h"
#include "memory.h"

#include "pimd.h"

#include "vos_types.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_register.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"
#include "pimsm_rp.h"


int pimsm_SendNullRegister(struct pimsm_mrt_entry *src_grp_entry);
#define register_check

const char *pimsm_GetRegStateString(PIMSM_REG_STATE_T emState)
{
    const char *pca_reg_state_string[] = {PIMSM_REG_STATE_STR};

    if ((0 > emState) || (PimsmRegStateEnd <= emState))
    {
        return "nul";
    }

    return pca_reg_state_string[emState];
}

uint8_t pimsm_AcceptRegist(VOS_IPV6_ADDR *pstSrc)
{
    if (NULL == pstSrc)
    {
        return FALSE;
    }

    if (pimsm_IsAcceptSource(pstSrc))
    {
        return TRUE;
    }

    return FALSE;
}

PIMSM_COULD_REGISTER_T pimsm_CouldRegister(VOS_IPV6_ADDR *src_addr,VOS_IPV6_ADDR *pstGrpAddr,uint32_t ifindex)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    struct pimsm_rpf *pstRpfToSrc;
    uint32_t dwSrcRpfIfIndex;
    //VOS_IPV6_ADDR rp_addr;
    //int ret;

    if ((NULL == src_addr) || (NULL == pstGrpAddr))
    {
        return PimsmRegCheckCouldNotRegister;
    }

    if (pimsm_IsSsmRangeAddr(pstGrpAddr))
    {
        PIM_DEBUG("The group address(%s) is in SSM range, Couldn't register.\n", pim_InetFmt(pstGrpAddr));
        return PimsmRegCheckCouldNotRegister;
    }

    if (!pimsm_IsAcceptSource(src_addr))
    {
        PIM_DEBUG("The source(%s) not accept, Couldn't register.\n", pim_InetFmt(src_addr));
        return PimsmRegCheckCouldNotRegister;
    }

    dwSrcRpfIfIndex = pimsm_DirectIfSearch(src_addr);
    if (PIMSM_NO_IF == dwSrcRpfIfIndex)
    {
        PIM_DEBUG("The source(%s) not direct link, Couldn't register.\n", pim_InetFmt(src_addr));
        return PimsmRegCheckCouldNotRegister;
    }
    else if (dwSrcRpfIfIndex != ifindex)
    {
        PIM_DEBUG("The source(%s) not RPF check error, Couldn't register.\n", pim_InetFmt(src_addr));
        return PimsmRegCheckCouldNotRegister;
    }

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return PimsmRegCheckCouldNotRegister;
    }
    else if (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_DR))
    {
        PIM_DEBUG("I'am not DR in interface %d, Couldn't register.\n", pimsm_ifp->ifindex);
        return PimsmRegCheckCouldNotRegister;
    }

    pstRpfToSrc = pimsm_SearchRpf(src_addr);
    if(NULL == pstRpfToSrc)
    {
        PIM_DEBUG("The source(%s) not RPF check error, Couldn't register.\n", pim_InetFmt(src_addr));
        return PimsmRegCheckCouldNotRegister;
    }
    if (MRTMGT_RPF_CTL_INVALID_INTF == pstRpfToSrc->rpf_if)
    {
        PIM_DEBUG("The source(%s) not RPF check error, Couldn't register.\n", pim_InetFmt(src_addr));
        return PimsmRegCheckCouldNotRegister;
    }

    if (pimsm_IamRP(pstGrpAddr))
    {
        return PimsmRegCheckIamDrAndRp;
    }

    return PimsmRegCheckCouldRegister;
}

#define tunnel_process
static int pimsm_RemoveRegisterTunnel(struct pimsm_mrt_entry *src_grp_entry)
{
    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if(NULL != src_grp_entry->stRegStateMachine.pstRegisterTunnel)
    {
        XFREE(MTYPE_PIM_OTHER, src_grp_entry->stRegStateMachine.pstRegisterTunnel);
        src_grp_entry->stRegStateMachine.pstRegisterTunnel = NULL;
    }

    //pimsm_DelOiToRtmgt(src_grp_entry, PIMSM_INTERFACE_COPY_TO_CPU);
    PIM_DEBUG("will set s,g tocpu false.\n");
    pimsm_SetCopyToCpu(src_grp_entry, FALSE);

    return VOS_OK;
}

static int pimsm_AddRegisterTunnel(struct pimsm_mrt_entry *src_grp_entry)
{
    VOS_IPV6_ADDR grp_addr;
    VOS_IPV6_ADDR rp_addr;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if(NULL == src_grp_entry->group)
    {
        return VOS_ERROR;
    }

    memcpy(&grp_addr, &src_grp_entry->group->address, sizeof(VOS_IPV6_ADDR));
    memset(&rp_addr, 0, sizeof(VOS_IPV6_ADDR));

    if(VOS_ERROR == pimsm_RpSearch(&grp_addr, &rp_addr))
    {
        return VOS_ERROR;
    }

    if(NULL != src_grp_entry->stRegStateMachine.pstRegisterTunnel)
    {
        pimsm_RemoveRegisterTunnel(src_grp_entry);
    }

    src_grp_entry->stRegStateMachine.pstRegisterTunnel = XMALLOC(MTYPE_PIM_OTHER, sizeof(PIMSM_REG_TUNNEL_T));
    if(NULL == src_grp_entry->stRegStateMachine.pstRegisterTunnel)
    {
        return VOS_ERROR;
    }
    memcpy(&src_grp_entry->stRegStateMachine.pstRegisterTunnel->rp_addr, &rp_addr, sizeof(VOS_IPV6_ADDR));

    //pimsm_AddOiToRtmgt(src_grp_entry, PIMSM_INTERFACE_COPY_TO_CPU);
    pimsm_SetCopyToCpu(src_grp_entry, TRUE);

    return VOS_OK;
}

static int pimsm_UpdateRegisterTunnel(struct pimsm_mrt_entry *src_grp_entry)
{
    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if (NULL != src_grp_entry->stRegStateMachine.pstRegisterTunnel)
    {
        pimsm_RemoveRegisterTunnel(src_grp_entry);
        pimsm_AddRegisterTunnel(src_grp_entry);
    }

    return VOS_OK;
}

#define send_register_message
int pimsm_SendRegisterStop(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstDstAddr, VOS_IPV6_ADDR *pstInnerSrc, VOS_IPV6_ADDR *pstInnerGrp)
{
    uint8_t *pucBuf = NULL;
    uint8_t *pucDataPtr = NULL;
    uint32_t dwRegStopMsgLen;

    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pucBuf = g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN;
    pucDataPtr = pucBuf;

    PUT_EGADDR(*pstInnerGrp, SINGLE_GRP_MSK6LEN, 0, pucDataPtr);
    PUT_EUADDR(*((struct in_addr *)pstInnerSrc), pucDataPtr);

    dwRegStopMsgLen = sizeof(struct pimsm_register_stop);

    PIM_DEBUG("will call pimsm_SendPimPacket.\n");
    pimsm_SendPimPacket(g_stPimsm.pucSendBuf,
                        0,
                        src_addr,
                        pstDstAddr,
                        PIM_TYPE_REGISTER_STOP,
                        dwRegStopMsgLen);


    return VOS_OK;
}

int pimsm_SendNullRegister(struct pimsm_mrt_entry *src_grp_entry)
{
    struct pimsm_register *pstNullRegMsg = NULL;
    uint32_t dwNullRegMsgLen;
    VOS_IPV6_ADDR rp_addr;
    struct ipv6 *pstIp = NULL;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }
    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pstNullRegMsg = (struct pimsm_register *)(g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN);
    pstNullRegMsg->flags = 0;
    pstNullRegMsg->flags = htonl(pstNullRegMsg->flags | PIM_REG_NULL_REGISTER_BIT);
    PIM_DEBUG(" pstNullRegMsg->flags:%0x.\n",  pstNullRegMsg->flags);

    /* 填写ipv6头 */
    pstIp = (struct ipv6 *)pstNullRegMsg->data;
    pstIp->ipv6_ver = htonl(0x60000000);
    pstIp->ipv6_len = 0;
    pstIp->ipv6_nexthead = IPPROTO_PIM;
    pstIp->ipv6_hoplimit = 0xff;
    memcpy(&pstIp->ipv6_src, &src_grp_entry->source->address, sizeof(VOS_IPV6_ADDR));
    memcpy(&pstIp->ipv6_dst, &src_grp_entry->group->address, sizeof(VOS_IPV6_ADDR));

    /* 不包含PIM头长度 */
    dwNullRegMsgLen = PIM_REGISTER_HEADER_LEN + sizeof(struct ipv6);

    pimsm_RpSearch(&src_grp_entry->group->address, &rp_addr);

#if 0
    printf("\n***********************************************************************\n");
    pim_pkt_dump(__PRETTY_FUNCTION__,g_stPimsm.pucSendBuf , dwNullRegMsgLen);
    printf("\n***********************************************************************\n");
#endif
    pimsm_SendPimPacket(g_stPimsm.pucSendBuf,
                        0,
                        NULL,
                        &rp_addr,
                        PIM_TYPE_REGISTER,
                        dwNullRegMsgLen);

    return VOS_OK;
}

int pimsm_DataForwardingOnRegTunnel(const char *pkt, uint32_t len, PIMSM_REG_TUNNEL_T *pstRegTunnel)
{
    struct pimsm_register *pstRegHead;
    struct ipv6 *pstIp = NULL;
    const struct mrt6msg *msg;
    struct in6_addr src_addr;
    struct in6_addr grp_addr;

    if((NULL == pkt) || (NULL == pstRegTunnel))
    {
        return VOS_ERROR;
    }

    msg = (const struct mrt6msg *)pkt;
    memcpy(&src_addr, &msg->im6_src, sizeof(struct in6_addr));
    memcpy(&grp_addr, &msg->im6_dst, sizeof(struct in6_addr));

    pstRegHead = (struct pimsm_register *)(g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN);
    pstRegHead->flags = 0;
    pstRegHead->flags = htonl(pstRegHead->flags | PIM_REG_BORDER_BIT);

    /* 填写ipv6头 */
    pstIp = (struct ipv6 *)pstRegHead->data;
    pstIp->ipv6_ver = htonl(0x60000000);
    pstIp->ipv6_len = htons(len);
    pstIp->ipv6_nexthead = IPPROTO_PIM;
    pstIp->ipv6_hoplimit = 0xff;
    memcpy(&pstIp->ipv6_src, &src_addr, sizeof(VOS_IPV6_ADDR));
    memcpy(&pstIp->ipv6_dst, &grp_addr, sizeof(VOS_IPV6_ADDR));

    pimsm_SendPimPacket(g_stPimsm.pucSendBuf, 0, NULL, &pstRegTunnel->rp_addr, PIM_TYPE_REGISTER, (PIM_REGISTER_HEADER_LEN + len));

    return VOS_OK;
}

#define register_event

static int pimsm_RegisterStopTimerExpireEvent(struct pimsm_mrt_entry *src_grp_entry)
{
    PIMSM_TIMER_PARA_REGISTER_STOP_T *registerStopPara;
    PIMSM_REG_STATE_T emCurRegState;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    registerStopPara = XMALLOC(MTYPE_PIM_REGISTERSTOP_PARA, sizeof(PIMSM_TIMER_PARA_REGISTER_STOP_T));
    memset(registerStopPara, 0, sizeof(PIMSM_TIMER_PARA_REGISTER_STOP_T));
    memcpy(&registerStopPara->src_addr, &src_grp_entry->source->address, sizeof(VOS_IPV6_ADDR));
    memcpy(&registerStopPara->grp_addr, &src_grp_entry->group->address, sizeof(VOS_IPV6_ADDR));

    emCurRegState = src_grp_entry->stRegStateMachine.emRegisterState;
    switch(emCurRegState)
    {
    case PimsmRegStateNoInfo:
        //Do nothing
        break;
    case PimsmRegStateJoin:
        //Do nothing
        break;
    case PimsmRegStateJoinPending:
        //Switch to Join state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoin;
        //Add register tunnel
        pimsm_AddRegisterTunnel(src_grp_entry);
        break;
    case PimsmRegStatePrune:
        //Switch to Join Pending state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoinPending;
        //Set register stop timer(**)

        if (src_grp_entry->stRegStateMachine.t_pimsm_register_timer)
            THREAD_OFF(src_grp_entry->stRegStateMachine.t_pimsm_register_timer);

        THREAD_TIMER_ON(master, src_grp_entry->stRegStateMachine.t_pimsm_register_timer,
                        pimsm_TimeroutRegisterStop,
                        registerStopPara, PIMSM_TIMER_VALUE_REGISTER_PROBE);

        //Send Null-Register
        pimsm_SendNullRegister(src_grp_entry);
        break;
    default:
        break;
    }

    return VOS_OK;
}


static int pimsm_CouldRegisterToTrueEvent(struct pimsm_mrt_entry *src_grp_entry)
{
    PIMSM_REG_STATE_T emCurRegState;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    emCurRegState = src_grp_entry->stRegStateMachine.emRegisterState;
    switch(emCurRegState)
    {
    case PimsmRegStateNoInfo:
        //Switch to Join state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoin;
        //Add register tunnel
        pimsm_AddRegisterTunnel(src_grp_entry);
        break;
    case 	PimsmRegStateJoin:
        //Do nothing
        break;
    case PimsmRegStateJoinPending:
        //Do nothing
        break;
    case PimsmRegStatePrune:
        //Do nothing
        break;
    default:
        break;
    }

    return VOS_OK;
}

static int pimsm_CouldRegisterToFalseEvent(struct pimsm_mrt_entry *src_grp_entry)
{
    PIMSM_REG_STATE_T emCurRegState;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    emCurRegState = src_grp_entry->stRegStateMachine.emRegisterState;
    switch(emCurRegState)
    {
    case PimsmRegStateNoInfo:
        //Do nothing
        break;
    case 	PimsmRegStateJoin:
        //Switch to NoInfo state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateNoInfo;
        //Remove register tunnel
        pimsm_RemoveRegisterTunnel(src_grp_entry);
        break;
    case PimsmRegStateJoinPending:
        //Switch to NoInfo state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateNoInfo;
        break;
    case PimsmRegStatePrune:
        //Switch to NoInfo state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateNoInfo;
        break;
    default:
        break;
    }

    return VOS_OK;
}

static int pimsm_RegisterStopReceiveEvent(struct pimsm_mrt_entry *src_grp_entry)
{
    PIMSM_TIMER_PARA_REGISTER_STOP_T *registerStopPara;
    PIMSM_REG_STATE_T emCurRegState;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    registerStopPara = XMALLOC(MTYPE_PIM_REGISTERSTOP_PARA, sizeof(PIMSM_TIMER_PARA_REGISTER_STOP_T));

    memset(registerStopPara, 0, sizeof(PIMSM_TIMER_PARA_REGISTER_STOP_T));
    memcpy(&registerStopPara->src_addr, &src_grp_entry->source->address, sizeof(VOS_IPV6_ADDR));
    memcpy(&registerStopPara->grp_addr, &src_grp_entry->group->address, sizeof(VOS_IPV6_ADDR));

    emCurRegState = src_grp_entry->stRegStateMachine.emRegisterState;
    switch(emCurRegState)
    {
    case PimsmRegStateNoInfo:
        //Do nothing
        break;
    case PimsmRegStateJoin:
        //Switch to Prune state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStatePrune;
        //Remove register tunnel
        PIM_DEBUG("pimsm here wil call pimsm_RemoveRegisterTunnel.\n");
        pimsm_RemoveRegisterTunnel(src_grp_entry);
        //Set register stop timer(*)
        if (src_grp_entry->stRegStateMachine.t_pimsm_register_timer)
            THREAD_OFF(src_grp_entry->stRegStateMachine.t_pimsm_register_timer);

        THREAD_TIMER_ON(master, src_grp_entry->stRegStateMachine.t_pimsm_register_timer,
                        pimsm_TimeroutRegisterStop,
                        registerStopPara, PIMSM_TIMER_VALUE_REGISTER_SUPPRESSION);
        break;
    case PimsmRegStateJoinPending:
        //Switch to Prune state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStatePrune;
        //Set register stop timer(*)
        if (src_grp_entry->stRegStateMachine.t_pimsm_register_timer)
            THREAD_OFF(src_grp_entry->stRegStateMachine.t_pimsm_register_timer);

        THREAD_TIMER_ON(master, src_grp_entry->stRegStateMachine.t_pimsm_register_timer,
                        pimsm_TimeroutRegisterStop,
                        registerStopPara, PIMSM_TIMER_VALUE_REGISTER_SUPPRESSION);
        break;
    case PimsmRegStatePrune:
        //Do nothing
        break;
    default:
        break;
    }

    return VOS_OK;
}


static int pimsm_RpChangedEvent(struct pimsm_mrt_entry *src_grp_entry)
{
    PIMSM_REG_STATE_T emCurRegState;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    emCurRegState = src_grp_entry->stRegStateMachine.emRegisterState;
    switch(emCurRegState)
    {
    case PimsmRegStateNoInfo:
        //Do nothing
        break;
    case	PimsmRegStateJoin:
        //Switch to Join state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoin;
        //Update register tunnel
        pimsm_UpdateRegisterTunnel(src_grp_entry);
        break;
    case PimsmRegStateJoinPending:
        //Switch to Join state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoin;
        //Add register tunnel
        pimsm_AddRegisterTunnel(src_grp_entry);
        //Cancel register stop timer
        if (src_grp_entry->stRegStateMachine.t_pimsm_register_timer)
            THREAD_OFF(src_grp_entry->stRegStateMachine.t_pimsm_register_timer);
        break;
    case PimsmRegStatePrune:
        //Switch to Join state
        src_grp_entry->stRegStateMachine.emRegisterState = PimsmRegStateJoin;
        //Add register tunnel
        pimsm_AddRegisterTunnel(src_grp_entry);
        //Cancel register stop timer
        if (src_grp_entry->stRegStateMachine.t_pimsm_register_timer)
            THREAD_OFF(src_grp_entry->stRegStateMachine.t_pimsm_register_timer);
        break;
    default:
        break;
    }

    return VOS_OK;
}

int pimsm_RegisterStateMachineEventProc(struct pimsm_mrt_entry *src_grp_entry,PIMSM_REG_STATE_MACHINE_EVENT_T emRegisterEventType)
{
    if (NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    switch(emRegisterEventType)
    {
    case PimsmRegEventRegStopTimerExpires:
        pimsm_RegisterStopTimerExpireEvent(src_grp_entry);
        break;
    case PimsmRegEventCouldRegToTrue:
        pimsm_CouldRegisterToTrueEvent(src_grp_entry);
        break;
    case PimsmRegEventCouldRegToFalse:
        pimsm_CouldRegisterToFalseEvent(src_grp_entry);
        break;
    case PimsmRegEventRegStopRecv:
        pimsm_RegisterStopReceiveEvent(src_grp_entry);
        break;
    case PimsmRegEventRpChanged:
        pimsm_RpChangedEvent(src_grp_entry);
        break;
    }

    return VOS_OK;
}

#endif
