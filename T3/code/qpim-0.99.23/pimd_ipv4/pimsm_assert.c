#include "pimsm_define.h"
#if INCLUDE_PIMSM
#include <zebra.h>
#include "memory.h"
#include "thread.h"
#include "log.h"

#include "pimd.h"

#include "pimsm_mrtmgt.h"
#include "pimsm_register.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"

uint8_t pimsm_CouldAssert(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
struct pimsm_assert_metric pimsm_SptAssertMetric(VOS_IP_ADDR *src_addr, uint32_t ifindex);
struct pimsm_assert_metric pimsm_RptAssertMetric(VOS_IP_ADDR *pstGrpAddr, uint32_t ifindex);
struct pimsm_assert_metric pimsm_InfiniteAssertMetric(void);
struct pimsm_assert_metric pimsm_MyAssertMetric(struct pimsm_mrt_entry * mrt_entry, uint32_t ifindex);
int pimsm_AssertIfStateChange(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,PIMSM_ASSERT_STATE_T emStateFrom,PIMSM_ASSERT_STATE_T emStateTo);

const char *pimsm_GetAssertStateString(PIMSM_ASSERT_STATE_T emState)
{
    const char *pca_assert_state_string[] = {PIMSM_ASSERT_STATE_STR};

    if ((0 > emState) || (PimsmAssertStateEnd <= emState))
    {
        return "nul";
    }

    return pca_assert_state_string[emState];
}

/********************************************************************
  Func Name     :   pimsm_MetricCompare
  Description   :   比较两个综合花费值的大小
  Input         :   pstMetric1 -- 综合花费1
                    pstMetric2 -- 综合花费2
  Output        :   无
  Return        :   >0 -- 综合花费1 胜出
                    <0 -- 综合花费2 胜出
                    =0 -- 参数错误
*********************************************************************/
int pimsm_MetricCompare(struct pimsm_assert_metric *pstMetric1, struct pimsm_assert_metric *pstMetric2)
{
    if ((NULL == pstMetric1) || (NULL == pstMetric2))
    {
        return 0;
    }

    /* When comparing assert_metric, the rpt_bit_flag, metric_preference, and route_metric fields are compared in order, where
        the first lower value wins. If all fields are equal, the primary IP address of the router that sourced the Assert message is used
        as a tie-breaker, with the highest IP address winning. [RFC7761 page 93]*/

    if (pstMetric1->byRptBit > pstMetric2->byRptBit)
    {
        return -1;
    }
    else if (pstMetric1->byRptBit < pstMetric2->byRptBit)
    {
        return 1;
    }

    if (pstMetric1->dwMetricPref > pstMetric2->dwMetricPref)
    {
        return -1;
    }
    else if (pstMetric1->dwMetricPref < pstMetric2->dwMetricPref)
    {
        return 1;
    }

    if (pstMetric1->dwRouteMetric > pstMetric2->dwRouteMetric)
    {
        return -1;
    }
    else if (pstMetric1->dwRouteMetric < pstMetric2->dwRouteMetric)
    {
        return 1;
    }

    if (0 > memcmp((const void *)(&(pstMetric1->address)), (const void *)(&(pstMetric2->address)), sizeof(VOS_IP_ADDR)))
    {
        return -1;
    }
    else
    {
        return 1;
    }
}

struct pimsm_assert_metric pimsm_SptAssertMetric(VOS_IP_ADDR *src_addr, uint32_t ifindex)
{
    struct pimsm_assert_metric stAssertMetric;
    struct pimsm_interface_entry *pimsm_ifp;
    struct pimsm_rpf *pstRpf;

    /*
    assert_metric
    spt_assert_metric(S,I) {
    	return {0, MRIB.pref(S), MRIB.metric(S), my_ip_address(I)}
    }
    */
    memset(&stAssertMetric, 0, sizeof(stAssertMetric));
    pstRpf = pimsm_SearchRpf(src_addr);
    if (NULL == pstRpf)
    {
        return stAssertMetric;
    }
    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return stAssertMetric;
    }
    stAssertMetric.byRptBit = 0;
    stAssertMetric.dwMetricPref = pstRpf->preference;
    stAssertMetric.dwRouteMetric = pstRpf->metric;
    memcpy(&stAssertMetric.address, &pimsm_ifp->primary_address, sizeof(VOS_IP_ADDR));

    return stAssertMetric;
}

struct pimsm_assert_metric pimsm_RptAssertMetric(VOS_IP_ADDR *pstGrpAddr, uint32_t ifindex)
{
    struct pimsm_assert_metric stAssertMetric;
    struct pimsm_interface_entry *pimsm_ifp;
    struct pimsm_rpf *pstRpf;

    /*
    assert_metric
    rpt_assert_metric(G,I) {
    	return {1, MRIB.pref(G), MRIB.metric(G), my_ip_address(I)}
    }
    */
    memset(&stAssertMetric, 0, sizeof(stAssertMetric));
    pstRpf = pimsm_SearchRpf(pstGrpAddr);
    if (NULL == pstRpf)
    {
        return stAssertMetric;
    }
    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if (NULL == pimsm_ifp)
    {
        return stAssertMetric;
    }
    stAssertMetric.byRptBit = 1;
    stAssertMetric.dwMetricPref = pstRpf->preference;
    stAssertMetric.dwRouteMetric = pstRpf->metric;
    memcpy(&stAssertMetric.address, &pimsm_ifp->primary_address, sizeof(VOS_IP_ADDR));

    return stAssertMetric;
}

struct pimsm_assert_metric pimsm_InfiniteAssertMetric(void)
{
    struct pimsm_assert_metric stAssertMetric;

    /*
    assert_metric
    sinfinite_assert_metric(G,I) {
    	return {1, infinity, infinity, 0}
    }
    */
    stAssertMetric.byRptBit = 1;
    stAssertMetric.dwMetricPref = PIMSM_ASSERT_PREFERENCE_INFINITY;
    stAssertMetric.dwRouteMetric = PIMSM_ASSERT_METRIC_INFINITY;
    memset(&stAssertMetric.address, 0, sizeof(VOS_IP_ADDR));

    return stAssertMetric;
}
struct pimsm_assert_metric pimsm_MyAssertMetric(struct pimsm_mrt_entry * mrt_entry, uint32_t ifindex)
{
    /*
    assert_metric
    my_assert_metric(S,G,I) {
    	if( CouldAssert(S,G,I) == TRUE){
    		return spt_assert_metric(S,I)
    	} else if ( CouldAssert(*,G,I) == TRUE) {
    		return rpt_assert_metric(G,I)
    	} else {
    		return infinite_assert_metric()
    	}
    }
    */
    if (NULL == mrt_entry)
    {
        return pimsm_InfiniteAssertMetric();
    }

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        if (pimsm_CouldAssert(mrt_entry, ifindex))
        {
            return pimsm_RptAssertMetric(&mrt_entry->group->address, ifindex);
        }
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        if (pimsm_CouldAssert(mrt_entry, ifindex))
        {
            return pimsm_SptAssertMetric(&mrt_entry->source->address, ifindex);
        }
    }

    return pimsm_InfiniteAssertMetric();
}


/* Terminology: */
/*		   A "preferred assert" is one with a better metric than the current winner. */
/*		   An "acceptable assert" is one that has a better metric than my_assert_metric(S,G,I)/(*,G,I). An
			  assert is never considered acceptable if its metric is infinite. */
/*		   An "inferior assert" is one with a worse metric than my_assert_metric(S,G,I)/(*,G,I). An assert
			  is never considered inferior if my_assert_metric(S,G,I)/(*,G,I) is infinite. */
uint8_t pimsm_AssertMetricPreferred(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_assert_metric stWinnerMetric;
    struct pimsm_assert_if *pimsmassert_if;

    if ((NULL == pstTargetMetric) || (NULL == mrt_entry))
    {
        return FALSE;
    }

    pimsmassert_if = pimsm_SearchAssertIfByIndex(mrt_entry->pimsmassert_if, ifindex);
    if (NULL != pimsmassert_if)
    {
        stWinnerMetric = pimsmassert_if->stAssertStateMachine.stAssertWinner;
    }
    else
    {
        stWinnerMetric = pimsm_InfiniteAssertMetric();
    }

    if (0 > pimsm_MetricCompare(&stWinnerMetric, pstTargetMetric))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t pimsm_AssertMetricAcceptable(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_assert_metric stMyMetric;

    if ((NULL == pstTargetMetric) || (NULL == mrt_entry))
    {
        return FALSE;
    }

    stMyMetric = pimsm_MyAssertMetric(mrt_entry, ifindex);

    if (0 > pimsm_MetricCompare(&stMyMetric, pstTargetMetric))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t pimsm_AssertMetricInferior(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_assert_metric stMyMetric;

    if ((NULL == pstTargetMetric) || (NULL == mrt_entry))
    {
        return FALSE;
    }

    stMyMetric = pimsm_MyAssertMetric(mrt_entry, ifindex);

    if (0 < pimsm_MetricCompare(&stMyMetric, pstTargetMetric))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t pimsm_CouldAssert(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_mrt_entry *pstSrcGrpRptEntry;
    struct pimsm_oif *pstOilPimIncludeStarGrp;
    struct pimsm_oif *pstOilPimExcludeSrcGrp;
    struct pimsm_oif *pstOilPimIncludeSrcGrp;
    struct pimsm_oif *pstOilLostAssertStarGrp;
    struct pimsm_oif *pstOilPruneSrcGrpRpt;
    struct pimsm_oif *pstOilJoinsStarGrp;
    struct pimsm_oif *pstOilJoinsSrcGrp;
    struct pimsm_oif *pstOilTmp1;
    struct pimsm_oif *pstOilTmp2;
    struct pimsm_oif *pstOilTmp3;
    struct pimsm_oif *pstOilTmp4;
    struct pimsm_oif *pstOilTmp5;
    struct pimsm_oif *pstOilTmp6;
    struct pimsm_oif *pstOilTmp7;

    if (NULL == mrt_entry)
    {
        return FALSE;
    }

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        /*
        CouldAssert(*,G,I) =
        	(  I  in  (  joins(*,G) (+) pim_include(*,G) )	)  AND
        	(RPF_interface(RP(G))  !=  I )
        */
        pstOilJoinsStarGrp = pimsm_Joins(mrt_entry, TRUE);
        pstOilPimIncludeStarGrp = pimsm_PimInclude(mrt_entry, TRUE);

        pstOilTmp1 = pimsm_OilAddOilFree(pstOilJoinsStarGrp, pstOilPimIncludeStarGrp);

        pstOilTmp2 = pimsm_SearchOifByIndex(pstOilTmp1, ifindex);
        pimsm_FreeOil(pstOilTmp1);
        if(NULL == pstOilTmp2)
        {
            return FALSE;
        }

        if(ifindex != mrt_entry->upstream_if.ifindex)
        {
            return TRUE;
        }
        /*
        memset(&rp_addr, 0, sizeof(rp_addr));
        pimsm_RpSearch(&mrt_entry->group->address, &rp_addr);
        if(ifindex != pimsm_RpfInterface(&mrt_entry->group->rp_addr))
        {
        	return TRUE;
        }
        */

        return FALSE;
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        /*
        CouldAssert(S,G,I) =
        	SPTbit(S,G) == TRUE AND
        	(RPF_interface(S) != I) AND
        	(I in (   (joins(*,G) (-) prunes(S,G,rpt))
        		(+) (pim_include(*,G) (-) pim_exclude(S,G))
        		(+) lost_assert(*,G)
        		(+) joins(S,G) (+) pim_include(S,G)  )	)
        */
        if (!pimsm_SptBit(&mrt_entry->source->address, &mrt_entry->group->address))
        {
            return FALSE;
        }

        if (ifindex == mrt_entry->upstream_if.ifindex)
        {
            return FALSE;
        }
        /*
        if (ifindex == pimsm_RpfInterface(&mrt_entry->source->address))
        {
        	return FALSE;
        }
        */

        pstOilJoinsStarGrp = pimsm_Joins(mrt_entry->group->pstStarMrtLink, TRUE);
        pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SGRPT);
        pstOilPruneSrcGrpRpt = pimsm_Prunes(pstSrcGrpRptEntry, TRUE);
        pstOilPimIncludeStarGrp = pimsm_PimInclude(mrt_entry->group->pstStarMrtLink, TRUE);
        pstOilPimExcludeSrcGrp = pimsm_PimExclude(mrt_entry, TRUE);
        pstOilLostAssertStarGrp = pimsm_LostAssert(mrt_entry->group->pstStarMrtLink, TRUE);
        pstOilJoinsSrcGrp = pimsm_Joins(mrt_entry, TRUE);
        pstOilPimIncludeSrcGrp = pimsm_PimInclude(mrt_entry, TRUE);

        pstOilTmp1 = pimsm_OilSubOilFree(pstOilJoinsStarGrp, pstOilPruneSrcGrpRpt);
        pstOilTmp2 = pimsm_OilSubOilFree(pstOilPimIncludeStarGrp, pstOilPimExcludeSrcGrp);
        pstOilTmp3 = pimsm_OilAddOilFree(pstOilTmp1, pstOilTmp2);
        pstOilTmp4 = pimsm_OilAddOilFree(pstOilTmp3, pstOilLostAssertStarGrp);
        pstOilTmp5 = pimsm_OilAddOilFree(pstOilTmp4, pstOilJoinsSrcGrp);
        pstOilTmp6 = pimsm_OilAddOilFree(pstOilTmp5, pstOilPimIncludeSrcGrp);

        pstOilTmp7 = pimsm_SearchOifByIndex(pstOilTmp6, ifindex);
        pimsm_FreeOil(pstOilTmp6);
        if(NULL != pstOilTmp7)
        {
            return TRUE;
        }

        return FALSE;
    }
    else
    {
        return FALSE;
    }

    return FALSE;
}

static int pimsm_SendAssert(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex,uint8_t blAssertCancel)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    uint32_t preference = 0;
    uint8_t *pucBuf = NULL;
    VOS_IP_ADDR stIpAddr;
    uint32_t metric = 0;

    if(mrt_entry == NULL)
    {
        return PimsmAssertResultError;
    }

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        return VOS_ERROR;
    }

    memset(g_stPimsm.pucSendBuf, 0x00, PIM_SEND_PACK_BUFFER_SIZE);
    pucBuf = g_stPimsm.pucSendBuf + PIM_MSG_HEADER_LEN;

    memcpy(&(stIpAddr), &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    PUT_EGADDR(stIpAddr, SINGLE_GRP_MSK6LEN, 0, pucBuf);

    if(blAssertCancel == TRUE)
    {
        preference = PIMSM_ASSERT_PREFERENCE_INFINITY;
        metric = PIMSM_ASSERT_METRIC_INFINITY;
    }
    else
    {
        preference = mrt_entry->preference;
        metric = mrt_entry->metric;
    }

    /* 如果匹配表项的入接口是朝RP方向 */
    if ((PIMSM_MRT_TYPE_WC == mrt_entry->type) ||
            (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type))
    {
        /* 计算metric和preference向RP方向 */
        preference |= PIMSM_ASSERT_RPTBIT; //why?

        memset(&stIpAddr, 0, sizeof(VOS_IP_ADDR));
        PUT_EUADDR(stIpAddr, pucBuf);
    }
    else
    {
        /* metric和preference向S方向 */
        memcpy(&stIpAddr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        PUT_EUADDR(stIpAddr, pucBuf);
    }

    PUT_HOSTLONG(preference, pucBuf);
    PUT_HOSTLONG(metric, pucBuf);

    if (pimsm_SendPimPacket(g_stPimsm.pucSendBuf,ifindex,NULL,&(g_stPimsm.stAllPimRouters),PIM_TYPE_ASSERT,PIM_ASSERT_MSG_LENTH) == VOS_ERROR)
    {
        zlog_warn("%s: could not send PIM message on interface %s",
                  __PRETTY_FUNCTION__, ifindex2ifname(pimsm_ifp->ifindex));
    }

    return VOS_OK;
}

uint8_t pimsm_AssertTrackingDesired(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_mrt_entry *pstSrcGrpRptEntry;
    struct pimsm_oif *pstOilPimIncludeStarGrp;
    struct pimsm_oif *pstOilPimExcludeSrcGrp;
    struct pimsm_oif *pstOilLostAssertStarGrp;
    struct pimsm_oif *pstOilPruneSrcGrpRpt;
    struct pimsm_oif *pstOilJoinsStarGrp;
    struct pimsm_oif *pstOilJoinsSrcGrp;
    struct pimsm_oif *pstOilTmp1;
    struct pimsm_oif *pstOilTmp2;
    struct pimsm_oif *pstOilTmp3;
    struct pimsm_oif *pstOilTmp4;
    struct pimsm_oif *pstOilTmp5;
    struct pimsm_oif *pstOilTmp6;
    //VOS_IP_ADDR rp_addr;

    zassert(NULL != mrt_entry);

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        /*
        AssertTrackingDesired(*,G,I) =
        	CouldAssert(*,G,I)
        	OR  (local_receiver_include(*,G,I) == TRUE
        		AND (I_am_DR(I) OR AssertWinner(*,G,I) == me))
        	OR  (RPF_interface(RP(G)) == I AND RPTJoinDesired(G))
        */
        if(pimsm_CouldAssert(mrt_entry, ifindex))
        {
            return TRUE;
        }

        if(pimsm_LocalReceiverInclude(mrt_entry, ifindex) &&
                (pimsm_IamDR(ifindex) || pimsm_InterfaceWinAssert(mrt_entry, ifindex)))
        {
            return TRUE;
        }

        //will begin
        if((ifindex == mrt_entry->upstream_if.ifindex) && pimsm_RPTJoinDesired(&mrt_entry->group->address))
        {
            return TRUE;
        }
        /*
        memset(&rp_addr, 0, sizeof(rp_addr));
        pimsm_RpSearch(&mrt_entry->group->address, &rp_addr);
        if((ifindex == pimsm_RpfInterface(&rp_addr)) && pimsm_JoinDesired(mrt_entry))
        {
        	return TRUE;
        }
        */
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        /*
        AssertTrackingDesired(S,G,I) =
        	(I  in  (  joins(*,G) (-) prunes(S,G,rpt)
        		(+)  (  pim_include(*,G) (-)  pim_exclude(S,G)  )
        		(-)  lost_assert(*,G)
        		(+)  joins(S,G)  )  )
        	OR  (local_receiver_include(S,G,I) == TRUE
        		AND (I_am_DR(I)  OR  (AssertWinner(S,G,I)  == me)))
        	OR  ((RPF_interface(S) == I) AND (JoinDesired(S,G) == TRUE))
        	OR  ((RPF_interface(RP(G)) == I) AND (JoinDesired(*,G) == TRUE)
        		AND (SPTbit(S,G) == FALSE))
        */
        pstOilJoinsStarGrp = pimsm_Joins(mrt_entry->group->pstStarMrtLink, TRUE);
        pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SGRPT);
        pstOilPruneSrcGrpRpt = pimsm_Prunes(pstSrcGrpRptEntry, TRUE);
        pstOilPimIncludeStarGrp = pimsm_PimInclude(mrt_entry->group->pstStarMrtLink, TRUE);
        pstOilPimExcludeSrcGrp = pimsm_PimExclude(mrt_entry, TRUE);
        pstOilLostAssertStarGrp = pimsm_LostAssert(mrt_entry->group->pstStarMrtLink, TRUE);
        pstOilJoinsSrcGrp = pimsm_Joins(mrt_entry, TRUE);

        pstOilTmp1 = pimsm_OilSubOilFree(pstOilJoinsStarGrp, pstOilPruneSrcGrpRpt);
        pstOilTmp2 = pimsm_OilSubOilFree(pstOilPimIncludeStarGrp, pstOilPimExcludeSrcGrp);
        pstOilTmp3 = pimsm_OilAddOilFree(pstOilTmp1, pstOilTmp2);
        pstOilTmp4 = pimsm_OilSubOilFree(pstOilTmp3, pstOilLostAssertStarGrp);
        pstOilTmp5 = pimsm_OilAddOilFree(pstOilTmp4, pstOilJoinsSrcGrp);

        pstOilTmp6 = pimsm_SearchOifByIndex(pstOilTmp5, ifindex);
        if(NULL != pstOilTmp6)
        {
            pimsm_FreeOil(pstOilTmp5);
            return TRUE;
        }
        pimsm_FreeOil(pstOilTmp5);

        if(pimsm_LocalReceiverInclude(mrt_entry, ifindex) &&
                (pimsm_IamDR(ifindex) || pimsm_InterfaceWinAssert(mrt_entry, ifindex)))
        {
            return TRUE;
        }

        if((ifindex == mrt_entry->upstream_if.ifindex) &&
                pimsm_JoinDesired(mrt_entry))
        {
            return TRUE;
        }
        /*
        if((ifindex == pimsm_RpfInterface(&mrt_entry->source->address)) &&
        	pimsm_JoinDesired(mrt_entry))
        {
        	return TRUE;
        }
        */

        if((ifindex == mrt_entry->upstream_if.ifindex) &&
                pimsm_JoinDesired(mrt_entry->group->pstStarMrtLink) &&
                pimsm_SptBit(&mrt_entry->source->address, &mrt_entry->group->address))
        {
            return TRUE;
        }
        /*
        pimsm_RpSearch(&mrt_entry->group->address, &rp_addr);
        if((ifindex == pimsm_RpfInterface(&rp_addr)) &&
        	pimsm_JoinDesired(mrt_entry->group->pstStarMrtLink) &&
        	pimsm_SptBit(&mrt_entry->source->address, &mrt_entry->group->address))
        {
        	return TRUE;
        }
        */
    }
    else
    {
        return FALSE;
    }

    return FALSE;
}

static int pimsm_AssertActionSA1(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;
    uint8_t blIsAssertCancel = FALSE;

    /* 1. Send Assert(S,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Set Assert Timer to (Assert_Time - Assert_Override_Interval). */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memcpy(&assert_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_SG;
    assert_para->ifindex= pimsmassert_if->ifindex;

    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER - PIMSM_TIMER_VALUE_ASSERT_OVERRIDE);

    /* 3. Store self as AssertWinner(S,G,I). */
    /* 4. Store spt_assert_metric(S,I) as AssertWinnerMetric(S,G,I). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_MyAssertMetric(mrt_entry, pimsmassert_if->ifindex);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionSA2(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;

    /* 1. Store new assert winner as AssertWinner(S,G,I) and assert winner metric as AssertWinnerMetric(S,G,I). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = event_para->stAssertMetric;

    /* 2. Set Assert Timer to Assert_Time. */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memcpy(&assert_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_SG;
    assert_para->ifindex= pimsmassert_if->ifindex;

    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionSA3(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;
    uint8_t blIsAssertCancel = FALSE;

    /* 1. Send Assert(S,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Set Assert Timer to (Assert_Time - Assert_Override_Interval). */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memcpy(&assert_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_SG;
    assert_para->ifindex= pimsmassert_if->ifindex;

    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER - PIMSM_TIMER_VALUE_ASSERT_OVERRIDE);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionSA4(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    uint8_t blIsAssertCancel = TRUE;

    /* 1. Send AssertCancel(S,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Delete assert information (AssertWinner(S,G,I) and AssertWinnerMetric(S,G,I) will then return to their default values). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_InfiniteAssertMetric();

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionSA5(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    /* 1. Delete assert information (AssertWinner(S,G,I) and AssertWinnerMetric(S,G,I) will then return to their default values. */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_InfiniteAssertMetric();

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionSA6(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;
    struct pimsm_rpf *pstRpf;

    /* 1. Store new assert winner as AssertWinner(S,G,I) and assert winner metric as AssertWinnermetric(S,G,I). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = event_para->stAssertMetric;

    /* 2. Set Assert Timer to Assert_Time. */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memcpy(&assert_para->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_SG;
    assert_para->ifindex= pimsmassert_if->ifindex;

    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER);

    /* 3. If (I is RPF_interface(S)) AND (UpstreamJPState(S,G) == Joined) set SPTbit(S,G) to TRUE. */
    pstRpf = pimsm_SearchRpf(&mrt_entry->source->address);
    if(NULL != pstRpf)
    {
        if((pimsmassert_if->ifindex == pstRpf->rpf_if) &&
                (PimsmUpstreamStateJoined == mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState))
        {
            pimsm_SetSptBit(&mrt_entry->source->address, &mrt_entry->group->address, TRUE);
        }
    }

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionGA1(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;
    uint8_t blIsAssertCancel = FALSE;
    //struct pimsm_interface_entry *pimsm_ifp;

    /* 1. Send Assert(*,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Set Assert Timer to (Assert_Time - Assert_Override_Interval). */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memset(&assert_para->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_WC;
    assert_para->ifindex= pimsmassert_if->ifindex;
    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER - PIMSM_TIMER_VALUE_ASSERT_OVERRIDE);

    /* 3. Store self as AssertWinner(*,G,I). */
    /* 4. Store rpt_assert_metric(G,I) as AssertWinnerMetric(*,G,I). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_MyAssertMetric(mrt_entry, pimsmassert_if->ifindex);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionGA2(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;

    /* 1. Store new assert winner as AssertWinner(*,G,I) and assert winner metric as AssertWinnerMetric(*,G,I). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = event_para->stAssertMetric;

    /* 2. Set Assert Timer to Assert_Time. */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memset(&assert_para->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_WC;
    assert_para->ifindex= pimsmassert_if->ifindex;
    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionGA3(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_timer_para_assert *assert_para;
    uint8_t blIsAssertCancel = FALSE;

    /* 1. Send Assert(*,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Set Assert Timer to (Assert_Time - Assert_Override_Interval). */
    if (pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer);

    assert_para = XMALLOC(MTYPE_PIM_ASSERT_PARA, sizeof(struct pimsm_timer_para_assert));

    memset(&assert_para->src_addr, 0, sizeof(VOS_IP_ADDR));
    memcpy(&assert_para->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    assert_para->type = PIMSM_MRT_TYPE_WC;
    assert_para->ifindex= pimsmassert_if->ifindex;

    THREAD_TIMER_ON(master, pimsmassert_if->stAssertStateMachine.t_pimsm_assert_timer,
                    pimsm_TimeroutAssert,
                    assert_para, PIMSM_TIMER_VALUE_ASSERT_TIMER - PIMSM_TIMER_VALUE_ASSERT_OVERRIDE);

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionGA4(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    uint8_t blIsAssertCancel = TRUE;

    /* 1. Send AssertCancel(*,G). */
    pimsm_SendAssert(mrt_entry, pimsmassert_if->ifindex, blIsAssertCancel);

    /* 2. Delete assert information (AssertWinner(*,G,I) and AssertWinnerMetric(*,G,I) will then return to their default values). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_InfiniteAssertMetric();

    return PimsmAssertResultOk;
}

static int pimsm_AssertActionGA5(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,struct pimsm_assert_state_machine_event_para *event_para)
{
    /* 1. Delete assert information (AssertWinner(*,G,I) and AssertWinnerMetric(*,G,I) will then return to their default values). */
    pimsmassert_if->stAssertStateMachine.stAssertWinner = pimsm_InfiniteAssertMetric();

    return PimsmAssertResultOk;
}

int pimsm_AssertIfStateChange(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,PIMSM_ASSERT_STATE_T emStateFrom,PIMSM_ASSERT_STATE_T emStateTo)
{
    struct pimsm_mrt_entry *pstSrcGrpEntryNext;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_grp_entry *pstGrpEntry;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;

    if ((NULL == mrt_entry) || (NULL == pimsmassert_if))
    {
        return VOS_ERROR;
    }

    memcpy(&grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        printf("(*,%s) Assert Interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&grp_addr),
               pimsm_GetIfName(pimsmassert_if->ifindex),
               pimsm_GetAssertStateString(emStateFrom),
               pimsm_GetAssertStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmAssertStateNoInfo:
            if (PimsmAssertStateLoser == emStateTo)
            {
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
            }
            else if (PimsmAssertStateWinner == emStateTo)
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
            }
            break;
        case PimsmAssertStateWinner:
            if ((PimsmAssertStateLoser == emStateTo) || (PimsmAssertStateNoInfo == emStateTo))
            {
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
            }
            break;
        case PimsmAssertStateLoser:
            if ((PimsmAssertStateNoInfo == emStateTo) || (PimsmAssertStateWinner == emStateTo))
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
            }
            break;
        default:
            break;
        }
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        memcpy(&src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
        printf("(%s,%s) Assert Interface %s state changed , %s  -->  %s.\n", pim_InetFmt(&src_addr),
               pim_InetFmt(&grp_addr),
               pimsm_GetIfName(pimsmassert_if->ifindex),
               pimsm_GetAssertStateString(emStateFrom),
               pimsm_GetAssertStateString(emStateTo));
        switch(emStateFrom)
        {
        case PimsmAssertStateNoInfo:
            if (PimsmAssertStateLoser == emStateTo)
            {
                if (!pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                }
            }
            else if (PimsmAssertStateWinner == emStateTo)
            {
                if (pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                }
            }
            break;
        case PimsmAssertStateWinner:
            if ((PimsmAssertStateLoser == emStateTo) || (PimsmAssertStateNoInfo == emStateTo))
            {
                if (!pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                }
            }
            break;
        case PimsmAssertStateLoser:
            if ((PimsmAssertStateNoInfo == emStateTo) || (PimsmAssertStateWinner == emStateTo))
            {
                if (pimsm_JoinDesired(mrt_entry))
                {
                    pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                }
            }
            break;
        default:
            break;
        }
    }

    return VOS_OK;
}

static int pimsm_SrcGrpAssertEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,uint8_t byEventType,struct pimsm_assert_state_machine_event_para *event_para)
{
    int result = PimsmAssertResultError;
    //PIMSM_ASSERT_STATE_T emAssertState;
    int emAssertState;

    emAssertState = pimsmassert_if->stAssertStateMachine.emAssertState;
    switch(emAssertState)
    {
    case PimsmAssertStateNoInfo:
        if ( (PimsmAssertEvent_04 == byEventType) ||
                (PimsmAssertEvent_14 == byEventType) ||
                (PimsmAssertEvent_21 == byEventType) )
        {
            /* 1. Winner State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateWinner;
            /* 2. Actions A1 */
            pimsm_AssertActionSA1(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateNoInfo, PimsmAssertStateWinner);
            result = PimsmAssertResultNoInfoToWinner;
        }
        else if (PimsmAssertEvent_10 == byEventType)
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A6 */
            pimsm_AssertActionSA6(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateNoInfo, PimsmAssertStateLoser);
            result = PimsmAssertResultNoInfoToLoser;
        }
        break;
    case PimsmAssertStateWinner:
        if ( (PimsmAssertEvent_01 == byEventType) ||
                (PimsmAssertEvent_03 == byEventType) )
        {
            /* 1. Winner State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateWinner;
            /* 2. Actions A3 */
            pimsm_AssertActionSA3(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateWinner);
            result = PimsmAssertResultOk;
        }
        else if (PimsmAssertEvent_08 == byEventType)
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A2 */
            pimsm_AssertActionSA2(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateLoser);
            result = PimsmAssertResultWinnerToLoser;
        }
        else if (PimsmAssertEvent_15 == byEventType)
        {
            /* 1. NoInfo State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;
            /* 2. Actions A4 */
            pimsm_AssertActionSA4(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateNoInfo);
            result = PimsmAssertResultWinnerToNoInfo;
        }
        break;
    case PimsmAssertStateLoser:
        if ( (PimsmAssertEvent_08 == byEventType) ||
                (PimsmAssertEvent_11 == byEventType) )
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A2 */
            pimsm_AssertActionSA2(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateLoser, PimsmAssertStateLoser);
            result = PimsmAssertResultOk;
        }
        else if ( (PimsmAssertEvent_06 == byEventType) ||
                  (PimsmAssertEvent_07 == byEventType) ||
                  (PimsmAssertEvent_01 == byEventType) ||
                  (PimsmAssertEvent_23 == byEventType) ||
                  (PimsmAssertEvent_02 == byEventType) ||
                  (PimsmAssertEvent_17 == byEventType) ||
                  (PimsmAssertEvent_24 == byEventType) ||
                  (PimsmAssertEvent_25 == byEventType) ||
                  (PimsmAssertEvent_19 == byEventType) )
        {
            /* 1. NoInfo State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;
            /* 2. Actions A5 */
            pimsm_AssertActionSA5(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateLoser, PimsmAssertStateNoInfo);
            result = PimsmAssertResultLoserToNoInfo;
        }
        break;
    }

    if (PimsmAssertStateNoInfo == pimsmassert_if->stAssertStateMachine.emAssertState)
    {
        pimsm_DestroyAssertIf(mrt_entry, pimsmassert_if->ifindex);
    }

    return result;
}

static int pimsm_StarGrpAssertEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_assert_if *pimsmassert_if,uint8_t byEventType,struct pimsm_assert_state_machine_event_para *event_para)
{
    int result = PimsmAssertResultError;
    //PIMSM_ASSERT_STATE_T emAssertState;
    int emAssertState;

    emAssertState = pimsmassert_if->stAssertStateMachine.emAssertState;
    switch(emAssertState)
    {
    case PimsmAssertStateNoInfo:
        if ( (PimsmAssertEvent_05 == byEventType) ||
                (PimsmAssertEvent_22 == byEventType) )
        {
            /* 1. Winner State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateWinner;
            /* 2. Actions A1 */
            pimsm_AssertActionGA1(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateNoInfo, PimsmAssertStateWinner);
            result = PimsmAssertResultNoInfoToWinner;
        }
        else if (PimsmAssertEvent_12 == byEventType)
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A2 */
            pimsm_AssertActionGA2(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateNoInfo, PimsmAssertStateLoser);
            result = PimsmAssertResultNoInfoToLoser;
        }
        break;
    case PimsmAssertStateWinner:
        if ( (PimsmAssertEvent_01 == byEventType) ||
                (PimsmAssertEvent_03 == byEventType) )
        {
            /* 1. Winner State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateWinner;
            /* 2. Actions A3 */
            pimsm_AssertActionGA3(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateWinner);
            result = PimsmAssertResultOk;
        }
        else if (PimsmAssertEvent_08 == byEventType)
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A2 */
            pimsm_AssertActionGA2(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateLoser);
            result = PimsmAssertResultWinnerToLoser;
        }
        else if (PimsmAssertEvent_16 == byEventType)
        {
            /* 1. NoInfo State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;
            /* 2. Actions A4 */
            pimsm_AssertActionGA4(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateWinner, PimsmAssertStateNoInfo);
            result = PimsmAssertResultWinnerToNoInfo;
        }
        break;
    case PimsmAssertStateLoser:
        if ( (PimsmAssertEvent_09 == byEventType) ||
                (PimsmAssertEvent_13 == byEventType) )
        {
            /* 1. Loser State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateLoser;
            /* 2. Actions A2 */
            pimsm_AssertActionGA2(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateLoser, PimsmAssertStateLoser);
            result = PimsmAssertResultOk;
        }
        else if ( (PimsmAssertEvent_06 == byEventType) ||
                  (PimsmAssertEvent_07 == byEventType) ||
                  (PimsmAssertEvent_01 == byEventType) ||
                  (PimsmAssertEvent_23 == byEventType) ||
                  (PimsmAssertEvent_02 == byEventType) ||
                  (PimsmAssertEvent_18 == byEventType) ||
                  (PimsmAssertEvent_24 == byEventType) ||
                  (PimsmAssertEvent_26 == byEventType) ||
                  (PimsmAssertEvent_20 == byEventType) )
        {
            /* 1. NoInfo State */
            pimsmassert_if->stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;
            /* 2. Actions A5 */
            pimsm_AssertActionGA5(mrt_entry, pimsmassert_if, event_para);
            pimsm_AssertIfStateChange(mrt_entry, pimsmassert_if, PimsmAssertStateLoser, PimsmAssertStateNoInfo);
            result = PimsmAssertResultLoserToNoInfo;
        }
        break;
    }

    if (PimsmAssertStateNoInfo == pimsmassert_if->stAssertStateMachine.emAssertState)
    {
        pimsm_DestroyAssertIf(mrt_entry, pimsmassert_if->ifindex);
    }

    return result;
}

int pimsm_AssertStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex, uint8_t byEventType, struct pimsm_assert_state_machine_event_para *event_para)
{
    struct pimsm_assert_if *pimsmassert_if = NULL;
    int result = PimsmAssertResultError;


    if(NULL == mrt_entry)
    {
        return result;
    }

    switch(mrt_entry->type)
    {
    case PIMSM_MRT_TYPE_WC:
        pimsmassert_if = pimsm_CreateAssertIf(NULL, &mrt_entry->group->address, mrt_entry->type, 0, ifindex);
        if (NULL != pimsmassert_if)
        {
            result = pimsm_StarGrpAssertEventProc(mrt_entry, pimsmassert_if, byEventType, event_para);
        }
        break;
    case PIMSM_MRT_TYPE_SG:
        pimsmassert_if = pimsm_CreateAssertIf(&mrt_entry->source->address, &mrt_entry->group->address, mrt_entry->type, 0, ifindex);
        if (NULL != pimsmassert_if)
        {
            result = pimsm_SrcGrpAssertEventProc(mrt_entry, pimsmassert_if, byEventType, event_para);
        }
        break;
    default:
        break;
    }

    return result;
}

#endif
