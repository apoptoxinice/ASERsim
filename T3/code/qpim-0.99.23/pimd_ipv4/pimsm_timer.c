#include "pimsm_define.h"
#if INCLUDE_PIMSM

#include <zebra.h>
#include "memory.h"
#include "thread.h"
#include "hash.h"

#include "pimd.h"
#include "pim_str.h"

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
#include "pimsm_bootstrap.h"

uint32_t g_msg_pim2rtmgt_timer = 0;
uint32_t g_mrt_manage_timer = 0;


#define timer_function

#if 0
//sangmeng FIXME: will use THREAD_TIMER_ON
uint32_t Pimsm_TimerCreate(uint32_t timer_type, uint32_t seconds, void *p_para, uint32_t para_len)
{
    uint32_t timer_id = 0;
#if 0

    timer_id = vos_TmCreate(TASK_ID_PIMSM,
                            timer_type,
                            (seconds) * VOS_TICKS_PER_SEC,
                            p_para,
                            para_len);
#endif

    return timer_id;
}
//sangmeng FIXME: will use THREAD_OFF
int Pimsm_TimerCancel(uint32_t *p_timer_id, uint32_t timer_type)
{
    int ret = 0;

#if 0
    ret = vos_TmCancel(*p_timer_id);
    *p_timer_id = 0;
#endif

    return ret;
}
//sangmeng FIXME: will first use THREAD_OFF, then use THREAD_TIMER_ON
int Pimsm_TimerReset(uint32_t timer_id, uint32_t timer_type)
{
    int ret = 0;
#if 0
    ret = vos_TmReset(timer_id);
#endif
    return ret;
}
//sangmeng FIXME: will use thread_timer_remain_second
int Pimsm_TimerGetRemain(uint32_t timer_id)
{
    int ret;
#if 0
    ret = (vos_TmGetRemain(timer_id))/VOS_TICKS_PER_SEC;
#endif
    return ret = 0;
}
#endif
//sangmeng FIXME: will use pimsm_TimeroutHello
int on_pimsm_hello_send(struct thread *t)
{
    int ret;
    uint16_t hold_time;
    struct pimsm_timer_para_hello *hello_para = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    zassert(t);

    hello_para = (struct pimsm_timer_para_hello *)THREAD_ARG(t);

    pimsm_ifp = pimsm_SearchInterface(hello_para->ifindex);
    if(pimsm_ifp == NULL)
    {
        XFREE(MTYPE_PIM_HELLO_PARA, hello_para);
        return VOS_ERROR;
    }

    pimsm_ifp->t_pimsm_hello_timer = 0;
    hold_time = 3.5 * (pimsm_ifp->pimsm_hello_period);

    ret = pimsm_SendHello(hello_para->ifindex, hold_time, &hello_para->neighbor_addr);
    if(ret != VOS_OK)
    {
        PIM_DEBUG("Pimsm send Hello message error.\n");
    }
    XFREE(MTYPE_PIM_HELLO_PARA, hello_para);

    return ret;
}
//sangmeng FIXME: will use on_neighbor_timer
int pimsm_on_neighbor_timer(struct thread *t)
{
    struct pimsm_timer_para_neighbor *neigh_para = NULL;
    struct pimsm_neighbor_entry *pimsm_neigh;
    struct pimsm_interface_entry *pimsm_ifp;
    VOS_IP_ADDR neigh_addr;

    zassert(t);
    neigh_para = THREAD_ARG(t);

    pimsm_ifp = pimsm_SearchInterface(neigh_para->ifindex);
    if(pimsm_ifp == NULL)
    {
        XFREE(MTYPE_PIM_NEIGH_PARA, neigh_para);
        return VOS_ERROR;
    }

    neigh_addr = neigh_para->source_addr;
    pimsm_neigh = pimsm_SearchNeighbor(pimsm_ifp, &neigh_addr);
    if(pimsm_neigh == NULL)
    {
        XFREE(MTYPE_PIM_NEIGH_PARA, neigh_para);
        return VOS_ERROR;
    }

    pimsm_neigh->t_expire_timer = 0;
    pimsm_DelNbr(pimsm_ifp, pimsm_neigh);

    XFREE(MTYPE_PIM_NEIGH_PARA, neigh_para);
    return VOS_OK;
}

int pimsm_TimeroutMsgRepost(struct thread *t)
{
    zassert(t);

    pimsm_MrtUpdateMsgRepostProcess();


    if (g_pimsm_msg_pim2rtmgt_timer)
        THREAD_OFF(g_pimsm_msg_pim2rtmgt_timer);

    THREAD_TIMER_ON(master, g_pimsm_msg_pim2rtmgt_timer,
                    pimsm_TimeroutMsgRepost,
                    NULL, 1);
    return VOS_OK;
}

int pimsm_TimeroutMrtManage(struct thread *t)
{
    zassert(t);
    pimsm_MrtManagePeriod();


    if (g_pimsm_mrt_manage_timer)
        THREAD_OFF(g_pimsm_mrt_manage_timer);

    THREAD_TIMER_ON(master, g_pimsm_mrt_manage_timer,
                    pimsm_TimeroutMrtManage,
                    NULL, 1);
    return VOS_OK;
}

int pimsm_TimeroutRegisterStop(struct thread *t)
{
    PIMSM_TIMER_PARA_REGISTER_STOP_T *pstRegisterStopPara;
    struct pimsm_mrt_entry *mrt_entry;
    int ret = VOS_OK;

    zassert(t);
    pstRegisterStopPara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstRegisterStopPara->src_addr, &pstRegisterStopPara->grp_addr, PIMSM_MRT_TYPE_SG);
    if (NULL != mrt_entry)
    {
        ret = pimsm_RegisterStateMachineEventProc(mrt_entry, PimsmRegEventRegStopTimerExpires);
    }

    XFREE(MTYPE_PIM_REGISTERSTOP_PARA, pstRegisterStopPara);
    return ret;
}
//sangmeng 20190423
int pimsm_TimeroutKeepAlive(struct thread *t)
{
    int ret = VOS_OK;
    PIMSM_TIMER_PARA_KEEPALIVE_T *pstKeepAlivePara;
    struct pimsm_mrt_entry *mrt_entry;
    char group_str[100];
    char source_str[100];

    struct sioc_sg_req sgreq;

    zassert(t);
    pstKeepAlivePara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstKeepAlivePara->src_addr, &pstKeepAlivePara->grp_addr, pstKeepAlivePara->type);
    if (mrt_entry == NULL)
    {
        PIM_DEBUG("Can't find (%s, %s) entry when process keep alive timerout.\n",
                  pim_InetFmt(&pstKeepAlivePara->src_addr),
                  pim_InetFmt(&pstKeepAlivePara->grp_addr));

        XFREE(MTYPE_PIM_KEEPALIVE_PARA, pstKeepAlivePara);
        return VOS_ERROR;
    }

    memset(&sgreq, 0, sizeof(sgreq));
    sgreq.src.s_addr = pstKeepAlivePara->src_addr.u32_addr[0];
    sgreq.grp.s_addr = pstKeepAlivePara->grp_addr.u32_addr[0];

    pim_inet4_dump("<group?>", sgreq.grp, group_str, sizeof(group_str));
    pim_inet4_dump("<source?>", sgreq.src, source_str, sizeof(source_str));

    if (ioctl(qpim_mroute_socket_fd, SIOCGETSGCNT, &sgreq))
    {
        int e = errno;
        PIM_DEBUG("ioctl(SIOCGETSGCNT=%d) failure for (S,G)=(%s,%s): errno=%d: %s\n",
                  SIOCGETSGCNT,
                  source_str,
                  group_str,
                  e,
                  safe_strerror(e));
        return VOS_ERROR;
    }
    if (sgreq.pktcnt != mrt_entry->packet_match_count)
    {
        mrt_entry->packet_match_count = sgreq.pktcnt;
        //reset timer
        PIM_DEBUG("reset pimsm_KeepAliveTimerStart here, %d.\n", PIMSM_TIMER_KEEPALIVE_PERIOD);
        pimsm_KeepAliveTimerStart(mrt_entry, PIMSM_TIMER_KEEPALIVE_PERIOD);
    }
    else
    {
        PIM_DEBUG("Entry(%s, %s) timer out, delete!!!\n",
                  pim_InetFmt(&pstKeepAlivePara->src_addr),
                  pim_InetFmt(&pstKeepAlivePara->grp_addr));
        pimsm_DestroyMrtEntry(mrt_entry);

    }

#if 0//sangmeng FIXME:20190403
    dwSrcAddr = htonl(pstKeepAlivePara->src_addr.u32_addr[0]);
    dwGrpAddr = htonl(pstKeepAlivePara->grp_addr.u32_addr[0]);
    lPktCount = dal_GetL3MCastCnt(dwGrpAddr, dwSrcAddr);
    printf("pimsm_TimeroutKeepAlive: (%s, %s), oldPktCount = %d, newPktCount = %d.\n",
           pim_InetFmt(&pstKeepAlivePara->src_addr),
           pim_InetFmt(&pstKeepAlivePara->grp_addr),
           mrt_entry->packet_match_count,
           lPktCount);

    if(lPktCount != mrt_entry->packet_match_count)
    {
        mrt_entry->packet_match_count = lPktCount;
        //reset timer
        pimsm_KeepAliveTimerStart(mrt_entry, PIMSM_TIMER_KEEPALIVE_PERIOD);
    }
    else
    {
        printf("Entry(%s, %s) timer out, delete!!!\n",
               pim_InetFmt(&pstKeepAlivePara->src_addr),
               pim_InetFmt(&pstKeepAlivePara->grp_addr));
        pimsm_DestroyMrtEntry(mrt_entry);
    }
#endif

    XFREE(MTYPE_PIM_KEEPALIVE_PARA, pstKeepAlivePara);
    return ret;
}

int pimsm_TimeroutAssert(struct thread *t)
{
    struct pimsm_assert_state_machine_event_para stEventPara;
    struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_timer_para_assert *pstAssertPara;
    int ret = VOS_OK;

    zassert(t);
    pstAssertPara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstAssertPara->src_addr, &pstAssertPara->grp_addr, pstAssertPara->type);
    if (NULL != mrt_entry)
    {
        ret = pimsm_AssertStateMachineEventProc(mrt_entry,
                                                pstAssertPara->ifindex,
                                                PimsmAssertEvent_01,
                                                &stEventPara);
    }
    XFREE(MTYPE_PIM_ASSERT_PARA, pstAssertPara);
    return ret;
}

int pimsm_TimeroutDownIfExpiry(struct thread *t)
{
    struct pimsm_timer_para_downif_expiry *pstDownIfExpiryPara;
    struct pimsm_updown_state_machine_event_para stEventPara;
    struct pimsm_mrt_entry *mrt_entry;
    int ret = VOS_OK;

    zassert(t);
    pstDownIfExpiryPara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstDownIfExpiryPara->src_addr, &pstDownIfExpiryPara->grp_addr, pstDownIfExpiryPara->type);
    if (NULL != mrt_entry)
    {
        ret = pimsm_UpdownstreamStateMachineEventProc(mrt_entry,
                PIMSM_DOWNSTREAM_IF,
                pstDownIfExpiryPara->ifindex,
                PimsmDownIfTimerExpiresEvent,
                &stEventPara);
    }
    XFREE(MTYPE_PIM_EXPIRY_PARA, pstDownIfExpiryPara);
    return ret;
}

int pimsm_TimeroutPrunePending(struct thread *t)
{
    struct pimsm_timer_para_prune_pending *prune_pending_para;
    struct pimsm_updown_state_machine_event_para stEventPara;
    struct pimsm_mrt_entry *mrt_entry;
    int ret = VOS_OK;

    zassert(t);
    prune_pending_para = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&prune_pending_para->src_addr, &prune_pending_para->grp_addr, prune_pending_para->type);
    if (NULL != mrt_entry)
    {
        ret = pimsm_UpdownstreamStateMachineEventProc(mrt_entry,
                PIMSM_DOWNSTREAM_IF,
                prune_pending_para->ifindex,
                PimsmPrunePendingTimerExpiresEvent,
                &stEventPara);
    }

    XFREE(MTYPE_PIM_PRUNEPEND_PARA, prune_pending_para);
    return ret;
}

int pimsm_TimeroutJoin(struct thread *t)
{
    PIMSM_TIMER_PARA_JOIN_T *pstJoinPara;
    struct pimsm_updown_state_machine_event_para stEventPara;
    struct pimsm_mrt_entry *mrt_entry;
    int ret = VOS_OK;


    zassert(t);
    pstJoinPara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstJoinPara->src_addr, &pstJoinPara->grp_addr, pstJoinPara->type);
    if (NULL != mrt_entry)
    {
        ret = pimsm_UpdownstreamStateMachineEventProc(mrt_entry,
                PIMSM_UPSTREAM_IF,
                pstJoinPara->ifindex,
                PimsmJoinTimerExpiresEvent,
                &stEventPara);
    }

    XFREE(MTYPE_PIM_JOIN_PARA, pstJoinPara);
    return ret;
}

int pimsm_TimeroutOverride(struct thread *t)
{
    PIMSM_TIMER_PARA_OVERRIDE_T *pstOverridePara;
    struct pimsm_updown_state_machine_event_para stEventPara;
    struct pimsm_mrt_entry *mrt_entry;
    int ret = VOS_OK;

    zassert(t);
    pstOverridePara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstOverridePara->src_addr, &pstOverridePara->grp_addr, pstOverridePara->type);
    if (NULL != mrt_entry)
    {
        ret = pimsm_UpdownstreamStateMachineEventProc(mrt_entry,
                PIMSM_UPSTREAM_IF,
                pstOverridePara->ifindex,
                PimsmOverrideTimerExpires,
                &stEventPara);
    }

    return ret;
}

int pimsm_TimeroutMrtExpiry(struct thread *t)
{
    PIMSM_TIMER_PARA_MRT_EXPIRY_T *pstMrtExpiryPara;
    struct pimsm_mrt_entry *mrt_entry;

    zassert(t);
    pstMrtExpiryPara = THREAD_ARG(t);

    mrt_entry = pimsm_SearchMrtEntry(&pstMrtExpiryPara->src_addr, &pstMrtExpiryPara->grp_addr, pstMrtExpiryPara->type);
    if (mrt_entry == NULL)
    {
        XFREE(MTYPE_PIM_MRTEXPIRY_PARA, pstMrtExpiryPara);
        return VOS_ERROR;
    }

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("Entry(*, %s) timer out, delete!!!\n", pim_InetFmt(&pstMrtExpiryPara->grp_addr));
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        printf("Entry(%s, %s) timer out, delete!!!\n",
               pim_InetFmt(&pstMrtExpiryPara->src_addr),
               pim_InetFmt(&pstMrtExpiryPara->grp_addr));
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        printf("Entry(%s, %s, rpt) timer out, delete!!!\n",
               pim_InetFmt(&pstMrtExpiryPara->src_addr),
               pim_InetFmt(&pstMrtExpiryPara->grp_addr));
    }

    pimsm_DestroyMrtEntry(mrt_entry);

    XFREE(MTYPE_PIM_MRTEXPIRY_PARA, pstMrtExpiryPara);
    return VOS_OK;
}

#define AAAAAA

#if 0
//需求分析中"针对(S,G,I) 项的其他触发状态跃迁的事件总结"中的事件5处理过程中需要用到的小函数
int pimsm_AssertEvent5Func(PIM_MRTENTRY *mrt_entry, PIM_INTERFACE *pimsm_ifp, VOS_IP_ADDR *pstTheNbrPriAddr)
{
    int           ret;
    int           iRetval2;
    PIM_OIF        *pstAssertLoserOif = NULL;
    int             iEqOrNot;
    VOS_IP_ADDR   stRpfStrokePre;
    VOS_IP_ADDR   stRpfStrokeCur;
    uint32_t    dwRemainValue;
    uint32_t    dwOverride;

    if((mrt_entry == NULL) && (pimsm_ifp == NULL) && (pstTheNbrPriAddr == NULL))
    {
        /*printf("pimsm_AssertEvent5Func : parameter is NULL!\n");*/
        return VOS_ERROR;
    }
    //对于(*,G)或(S,G)项的入接口
    if(mrt_entry->stIif.ifindex == pimsm_ifp->ifindex)
    {
        if(mrt_entry->stIif.emState == PIM_ASSERT_LOSER)
        {
            //如果当前断言胜利者就是到时或者更改GENID的邻居
            iEqOrNot = ip_AddressCompare(pstTheNbrPriAddr, &(mrt_entry->stIif.stAssertWinner.stIpv6Addr));
            if(iEqOrNot == 0)
            {
                zassert(pimsm_RpfStroke(mrt_entry, &stRpfStrokePre) == VOS_OK);
                mrt_entry->stIif.emState = PIM_ASSERT_NOINFO;
                //如果是(*,G)项
                if((mrt_entry->flags & MRTF_WC) != 0)
                {
                    ret = pimsm_AssertActionGA5(mrt_entry, pimsm_ifp, FALSE);
                    pimsm_AssertDebugPrint(PIM_ASSERT_LOSER, PIM_ASSERT_NOINFO, pimsm_ifp->ifindex, MRTF_WC, NULL, &(mrt_entry->source->address), "GA5");
                    zassert(pimsm_RpfStroke(mrt_entry, &stRpfStrokeCur) == VOS_OK);
                    iRetval2 = ip_AddressCompare(&stRpfStrokePre, &stRpfStrokeCur);
                    if(iRetval2 != 0)
                    {
                        dwOverride = (uint32_t)(rand() % (pimsm_EffectiveOverridInterval(mrt_entry->stIif.ifindex)+ 1)); /* mm */
                        dwRemainValue = vos_TmGetRemain(mrt_entry->tmJPPeriodTimer) / VOS_TICKS_PER_SEC;
                        if((dwRemainValue * 1000) > dwOverride)
                        {
                            /* 修改加枝定时器 */
                            vos_TmChangeInterval(mrt_entry->tmJPPeriodTimer, dwOverride/10);
                            vos_TmReset(mrt_entry->tmJPPeriodTimer);

                            return VOS_OK;
                        }

                    }
                }
                //如果是(S,G)项
                else if((mrt_entry->flags & MRTF_SG) != 0)
                {
                    ret = pimsm_AssertActionSA5(mrt_entry, pimsm_ifp, FALSE);
                    pimsm_AssertDebugPrint(PIM_ASSERT_LOSER, PIM_ASSERT_NOINFO, pimsm_ifp->ifindex, MRTF_SG, &(mrt_entry->source->address), &(mrt_entry->source->address), "SA5");
                    zassert(pimsm_RpfStroke(mrt_entry, &stRpfStrokeCur) == VOS_OK);
                    iRetval2 = ip_AddressCompare(&stRpfStrokePre, &stRpfStrokeCur);
                    if(iRetval2 != 0)
                    {
                        dwOverride = (uint32_t)(rand() % (pimsm_EffectiveOverridInterval(mrt_entry->stIif.ifindex)+ 1)); /* mm */
                        dwRemainValue = vos_TmGetRemain(mrt_entry->tmJPPeriodTimer) / VOS_TICKS_PER_SEC;
                        if((dwRemainValue * 1000) > dwOverride)
                        {
                            /* 修改加枝定时器 */
                            vos_TmChangeInterval(mrt_entry->tmJPPeriodTimer, dwOverride/10);
                            vos_TmReset(mrt_entry->tmJPPeriodTimer);

                            return VOS_OK;
                        }
                    }
                }
                //如果两者都不是就肯定有错误了
                else
                {
                    printf("pimsm_AssertEvent5Func : neither (*,G) nor (S,G) error!\n");
                }
                if(ret != VOS_OK)
                {
                    /*printf("pimsm_AssertEvent5Func : call pimsm_AssertActionGA5 return error for input interface!\n");*/
                    return VOS_ERROR;
                }
            }
        }
    }
    //对于(*,G)或(S,G)项的出接口
    else
    {
        pstAssertLoserOif = pimsm_FindOifByIndex(mrt_entry->pstAssertedOil, pimsm_ifp->ifindex);
        if(pstAssertLoserOif != NULL)
        {
            //如果当前断言胜利者就是到时或者更改GENID的邻居
            iEqOrNot = ip_AddressCompare(pstTheNbrPriAddr, &(pstAssertLoserOif->stAssertWinner.stIpv6Addr));
            if(iEqOrNot == 0)
            {
                pstAssertLoserOif->emState = PIM_ASSERT_NOINFO;
                //如果是(*,G)项
                if((mrt_entry->flags & MRTF_WC) != 0)
                {
                    ret = pimsm_AssertActionGA5(mrt_entry, pimsm_ifp, TRUE);
                    pimsm_AssertDebugPrint(PIM_ASSERT_LOSER, PIM_ASSERT_NOINFO, pimsm_ifp->ifindex, MRTF_WC, NULL, &(mrt_entry->source->address), "GA5");
                }
                //如果是(S,G)项
                else if((mrt_entry->flags & MRTF_SG) != 0)
                {
                    ret = pimsm_AssertActionSA5(mrt_entry, pimsm_ifp, TRUE);
                    pimsm_AssertDebugPrint(PIM_ASSERT_LOSER, PIM_ASSERT_NOINFO, pimsm_ifp->ifindex, MRTF_SG, &(mrt_entry->source->address), &(mrt_entry->source->address), "SA5");
                }
                //如果两者都不是就肯定有错误了
                else
                {
                    printf("pimsm_AssertEvent5Func : neither (*,G) nor (S,G) error!\n");
                }
                if(ret != VOS_OK)
                {
                    printf("pimsm_AssertEvent5Func : call pimsm_AssertActionGA5 return error for output interface!\n");
                    return VOS_ERROR;
                }
            }
        }
    }

    return VOS_OK;
}

//需求分析中"针对(S,G,I)以及 (*,G,I)项的其他触发状态跃迁的事件总结"中的事件5处理函数
int pimsm_AssertEvent5(PIM_INTERFACE *pimsm_ifp, VOS_IP_ADDR *pstTheNbrPriAddr)
{
    struct hash             *pstGrpHash     = NULL;
    struct hash_backet      *mp             = NULL;
    struct hash_backet      *next           = NULL;
    PIM_GRPENTRY           *pstGrpEntry    = NULL;
    PIM_MRTENTRY           *mrt_entry    = NULL;
    int                   ret;
    int                     i;

    if((pimsm_ifp == NULL) && (pstTheNbrPriAddr == NULL))
    {
        /*printf("pimsm_AssertEvent5 : parameter is NULL!\n");*/
        return VOS_ERROR;
    }
    pstGrpHash = g_stPimsm.pstGrpHash;
    if(pstGrpHash == NULL)
    {
        return VOS_OK;
    }
    for (i = 0; i < HASHTABSIZE; i++)
    {
        for (mp = hash_head (pstGrpHash, i); mp; mp = next)
        {
            next = mp->next;
            pstGrpEntry = (PIM_GRPENTRY*)(mp->data);
            //先搞(*,G)项
            mrt_entry = pstGrpEntry->pstMrt;
            if (NULL != mrt_entry)
            {
                ret = pimsm_AssertEvent5Func(mrt_entry, pimsm_ifp, pstTheNbrPriAddr);
                if(ret != VOS_OK)
                {
                    printf("pimsm_AssertEvent5 : call pimsm_AssertEvent5Func return error!\n");
                }
            }
            //再循环遍历(*,G)下面挂的(S,G)项
            mrt_entry = pstGrpEntry->pstSrcMrtLink;
            while(mrt_entry != NULL)
            {
                ret = pimsm_AssertEvent5Func(mrt_entry, pimsm_ifp, pstTheNbrPriAddr);
                if(ret != VOS_OK)
                {
                    printf("pimsm_AssertEvent5 : call pimsm_AssertEvent5Func return error!\n");
                }
                mrt_entry = mrt_entry->samegrpnext;
            }
        }
    }
    return VOS_OK;
}


/* PIM neighbor liveness timeout */
/* 定时器类型为:PIM_TIMER_NEIGHBOR_LIVENESS 超时后的响应函数*/



/********************************************************************
  Func Name     :   pimsm_TimeoutMldReport
  Description   :   PIM mld report timeout
                    定时器类型为:PIM_TIMER_MLD_REPORT 超时后的响应函数
  Input         :   pcPara -- MldReport定时器超时后的参数(在建立定时器时指定)
  Output        :
  Return        :   VOS_OK -- 成功
                    VOS_ERROR -- 失败
  Author        :   xjy
  Create date   :   2005.1
*********************************************************************/
int pimsm_TimeoutMldReport(uint8_t *pucPara)
{
    uint32_t   ifindex;
    PIM_INTERFACE  *pimsm_ifp = NULL;

    ifindex = *(uint32_t *)pucPara;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("Can't find the interface!\n");
        return VOS_ERROR;
    }

    pimsm_ifp->tmMldTimer = 0;

    pimsm_IfAddedToMemberEntry(pimsm_ifp);

    if (NULL != pimsm_ifp->pstIncludeMember
            || NULL != pimsm_ifp->pstExcludeMember)
    {
        pimsm_ifp->tmMldTimer = vos_TmCreate(TASK_ID_PIMSM,
                                             PIM_TIMER_MLD_REPORT,
                                             PIM_MLD_REPORT_PERIOD * VOS_TICKS_PER_SEC,
                                             &ifindex,
                                             sizeof(uint32_t));
    }

    return VOS_OK;
}


#endif

/* PIM timer out */
int pimsm_TimerOutProc(m_VosTmServToPimsm_t *pstTimeOutMsg)
{
    int ret = 0;

    return ret;
}

#endif
