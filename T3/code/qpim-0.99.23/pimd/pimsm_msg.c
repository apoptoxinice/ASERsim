#include "pimsm_define.h"
#if INCLUDE_PIMSM

#include <stdio.h>
#include <stdlib.h>

#include <zebra.h>
#include "memory.h"
#include "hash.h"
#include "log.h"


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
#include "pimsm_igmp.h"
#include "vty.h"
#include "prefix.h"

extern struct pimsm_encoded_unicast_addr g_root_cbsr_id;
extern struct pimsm_encoded_unicast_addr g_root_crp_id;
extern uint8_t g_root_cbsr_priority;
extern uint8_t g_root_crp_priority;
extern uint8_t g_cbsr_enable;
extern uint8_t g_crp_enable;
extern struct pimsm_crp_group_policy_list *g_crp_group_policy_list;
extern struct pimsm_interface_entry *g_pimsm_interface_list;

uint8_t Debug_Common_Func(void)
{
    return TRUE;
}
int pimsm_ToCliPrint(char *pcBuf)
{

    //sangmeng FIXME: will use vty_out
#if 0
    uint32_t  bNeedPrint;
    char *pcOutBuf = NULL;
    int iResult;

    if (0 != data_len)
    {
        pcOutBuf = XMALLOC(MTYPE_BUFFER, data_len + 1);
        if (NULL == pcOutBuf)
        {
            return VOS_ERROR;
        }
        memset(pcOutBuf, 0x00, data_len + 1);
        memcpy(pcOutBuf, pcBuf, data_len);

        bNeedPrint = TRUE;
    }
    else
    {
        bNeedPrint = FALSE;
    }

    printf(pcOutBuf);

    iResult = g_stCliModuleEntry.ack(pstCliHead->dwIODevNo,
                                     TRUE,
                                     FALSE,//bNeedPrint,
                                     data_len,
                                     pcOutBuf,
                                     0,0);

    if (iResult != VOS_OK)
    {
        vos_printf ("Invoke cli ack function failed!\n");
    }
#endif
    return VOS_OK;
}

int pimsm_ShowTraffic(struct vty *vty)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    uint32_t dwInHelloCount = 0;
    uint32_t dwOutHelloCount = 0;
    uint32_t dwInJPCount = 0;
    uint32_t dwOutJPCount = 0;
    uint32_t dwInAssertCount = 0;
    uint32_t dwOutAssertCount = 0;
    uint32_t dwInRegCount = 0;
    uint32_t dwOutRegCount = 0;
    uint32_t dwInRegStopCount = 0;
    uint32_t dwOutRegStopCount = 0;
    uint32_t dwInBootStpCount = 0;
    uint32_t dwOutBootStpCount = 0;
    uint32_t dwInGraftCount = 0;
    uint32_t dwOutGraftCount = 0;
    uint32_t dwInGraftAckCount = 0;
    uint32_t dwOutGraftAckCount = 0;
    uint32_t dwInCandRpAdvCount = 0;
    uint32_t dwOutCandRpAdvCount = 0;
    uint32_t dwInValidCount = 0;
    uint32_t dwOutValidCount = 0;
    char print_buf[SS_DEB_lENTH];
    int len = 0;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        dwInHelloCount      += pimsm_ifp->pimsm_ifstat.hello_recv;
        dwOutHelloCount     += pimsm_ifp->pimsm_ifstat.hello_send;

        dwInJPCount         += pimsm_ifp->pimsm_ifstat.join_prune_recv;
        dwOutJPCount        += pimsm_ifp->pimsm_ifstat.join_prune_send;

        dwInAssertCount     += pimsm_ifp->pimsm_ifstat.assert_recv;
        dwOutAssertCount    += pimsm_ifp->pimsm_ifstat.assert_send;

        dwInBootStpCount    += pimsm_ifp->pimsm_ifstat.bootstrap_recv;
        dwOutBootStpCount   += pimsm_ifp->pimsm_ifstat.bootstrap_send;

        dwInGraftCount      += pimsm_ifp->pimsm_ifstat.graft_recv;
        dwOutGraftCount     += pimsm_ifp->pimsm_ifstat.graft_send;

        pimsm_ifp = pimsm_ifp->next;
    }

    dwInRegCount = g_stPimsm.dwInPimsmRegister;
    dwOutRegCount = g_stPimsm.dwOutPimsmRegister;

    dwInRegStopCount = g_stPimsm.dwInPimsmRegisterStop;
    dwOutRegStopCount = g_stPimsm.dwOutPimsmRegisterStop;

    dwInGraftAckCount   = g_stPimsm.dwInPimsmGraftAck;
    dwOutGraftAckCount  = g_stPimsm.dwOutPimsmGraftAck;

    dwInCandRpAdvCount  = g_stPimsm.dwInPimsmCandRpAdv;
    dwOutCandRpAdvCount = g_stPimsm.dwOutPimsmCandRpAdv;


    dwInValidCount = dwInHelloCount
                     + dwInJPCount
                     + dwInAssertCount
                     + dwInBootStpCount
                     + dwInCandRpAdvCount
                     + dwInGraftAckCount
                     + dwInGraftCount
                     + dwInRegCount
                     + dwInRegStopCount;

    dwOutValidCount = dwOutHelloCount
                      + dwOutJPCount
                      + dwOutAssertCount
                      + dwOutBootStpCount
                      + dwOutCandRpAdvCount
                      + dwOutGraftAckCount
                      + dwOutGraftCount
                      + dwOutRegCount
                      + dwOutRegStopCount;

    memset(print_buf, 0, SS_DEB_lENTH);

    len += sprintf(print_buf + len, "PIM Traffic Counters\n\n");
    len += sprintf(print_buf + len, "%52s", "Received     Sent\n");/*空35列*/
    len += sprintf(print_buf + len, "%-34s", "Valid PIM Packets");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInValidCount, dwOutValidCount);
    len += sprintf(print_buf + len, "----------------------------------------------------\n");
    len += sprintf(print_buf + len, "%-34s", "Hello");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInHelloCount, dwOutHelloCount);
    len += sprintf(print_buf + len, "%-34s", "Register");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInRegCount, dwOutRegCount);
    len += sprintf(print_buf + len, "%-34s", "Register-Stop");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInRegStopCount, dwOutRegStopCount);
    len += sprintf(print_buf + len, "%-34s", "Join/Prune");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInJPCount, dwOutJPCount);
    len += sprintf(print_buf + len, "%-34s", "Bootstrap");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInBootStpCount, dwOutBootStpCount);
    len += sprintf(print_buf + len, "%-34s", "Assert");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInAssertCount, dwOutAssertCount);
    len += sprintf(print_buf + len, "%-34s", "Graft(PIM-DM)");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInGraftCount, dwOutGraftCount);
    len += sprintf(print_buf + len, "%-34s", "Graft-Ack(PIM-DM)");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInGraftAckCount, dwOutGraftAckCount);
    len += sprintf(print_buf + len, "%-34s", "Candidate-RP-Advertisement");
    len += sprintf(print_buf + len, "%-13u%u\n", dwInCandRpAdvCount, dwOutCandRpAdvCount);

    //pimsm_ToCliPrint(print_buf);
    vty_out(vty,"%s",print_buf);

    return VOS_OK;
}








int pimsm_ClearCounters(void)
{
    struct pimsm_interface_entry  *pimsm_ifp = NULL;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        memset(&pimsm_ifp->pimsm_ifstat, 0x00, sizeof(pimsm_ifp->pimsm_ifstat));
        pimsm_ifp = pimsm_ifp->next;
    }

    g_stPimsm.dwInPimsmRegister = 0;
    g_stPimsm.dwInPimsmRegisterStop = 0;
    g_stPimsm.dwInPimsmGraftAck = 0;
    g_stPimsm.dwInPimsmCandRpAdv = 0;

    g_stPimsm.dwOutPimsmRegister = 0;
    g_stPimsm.dwOutPimsmRegisterStop = 0;
    g_stPimsm.dwOutPimsmGraftAck = 0;
    g_stPimsm.dwOutPimsmCandRpAdv = 0;

    return VOS_OK;
}

#define free_msg

static int pimsm_FreeRecordList(PIMSM_RECORD_LIST_T *pstRecordListHead)
{
    PIMSM_RECORD_LIST_T *pstRecordToFree = NULL;
    PIMSM_RECORD_LIST_T *pstRecord = NULL;
    PIMSM_ADDR_LIST_T *pstSrcToFree = NULL;
    PIMSM_ADDR_LIST_T *pstSrc = NULL;

    pstRecord = pstRecordListHead;
    while(NULL != pstRecord)
    {
        pstSrc = pstRecord->pstSourListHead;
        while(pstSrc != NULL)
        {
            pstSrcToFree = pstSrc;
            pstSrc = pstSrc->pstNext;
            XFREE(MTYPE_PIM_ADDR_LIST, pstSrcToFree);
        }
        pstRecordToFree = pstRecord;
        pstRecord = pstRecord->pstNext;
        XFREE(MTYPE_PIM_RECORD, pstRecordToFree);
    }

    return VOS_OK;
}

static int pimsm_FreeGroupList(PIMSM_ADDR_LIST_T *pstGroupListHead)
{
    PIMSM_ADDR_LIST_T *pstGrpToFree = NULL;
    PIMSM_ADDR_LIST_T *pstGrp = NULL;

    pstGrp = pstGroupListHead;
    while(pstGrp != NULL)
    {
        pstGrpToFree = pstGrp;
        pstGrp = pstGrp->pstNext;
        XFREE(MTYPE_PIM_ADDR_LIST, pstGrpToFree);
    }

    return VOS_OK;
}
#define mmIgmpMsgHeader                     	0x06f0
#define mmIgmpv1ToPim                           (mmIgmpMsgHeader + 1)  //added by hgx
#define mmIgmpv2ToPim                           (mmIgmpMsgHeader + 2)
#define mmIgmpv3ToPim                           (mmIgmpMsgHeader + 3)
int pimsm_MsgProcIgmp(PIMSM_MSG_T *pstPimsmMsg)
{
    m_Igmpv1ToPimsm_t *pstIgmpv1ToPimsm = NULL;
    m_Igmpv2ToPimsm_t *pstIgmpv2ToPimsm = NULL;
    m_Igmpv3ToPimsm_t *pstIgmpv3ToPimsm = NULL;
    PIMSM_ADDR_LIST_T *pstGroupListHead = NULL;
    PIMSM_ADDR_LIST_T *pstGroupListNode = NULL;
    PIMSM_ADDR_LIST_T *pstSourceListNode = NULL;
    PIMSM_RECORD_LIST_T *pstRecordListCurr = NULL;
    PIMSM_RECORD_LIST_T *pstRecordListNext = NULL;
    const char *acFilterModeString[] = {"", "Include", "Exclude"};
    char ss[SS_DEB_lENTH];
    uint8_t blRetval;
    int ret;

    VOS_IPV6_ADDR any_src_addr;
    memset(&any_src_addr,0,sizeof(VOS_IPV6_ADDR));

    printf("Pimsm receive a message from IGMPv%d.\n", pstPimsmMsg->stCommonHead.wMsgType - mmIgmpMsgHeader);

    switch(pstPimsmMsg->stCommonHead.wMsgType)
    {
    case mmIgmpv1ToPim:
        pstIgmpv1ToPimsm = &(pstPimsmMsg->u_msg.mIgmpToPimsm.u_version.stIgmpv1ToPimsm);
        pstGroupListHead = pstIgmpv1ToPimsm->pstGrpListHead;
        switch(pstIgmpv1ToPimsm->dwType)
        {
        case IGMP_TO_PIMSM_ADD_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM receive IGMPv1 message of IGMP_TO_PIMSM_ADD_ADDR \n");
            blRetval = Debug_Common_Func();
            if (blRetval)
            {
                //SendDebugMessage(e_debug_ip_pim, ss);
                //zlog_debug(ss);
            }

            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv1 message IGMP_TO_PIMSM_ADD_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstIgmpv1ToPimsm->ifindex, pstIgmpv1ToPimsm->wGrpNum);
            pstGroupListNode = pstGroupListHead;
            while(pstGroupListNode != NULL)
            {
                PIM_DEBUG("%s \n", pim_InetFmt(&pstGroupListNode->addr));
                pstGroupListNode = pstGroupListNode->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            ret = pimsm_IgmpGrpMemberProc(pstIgmpv1ToPimsm->ifindex, pstGroupListHead, PIMSM_OUT_SSM_RANGE_IGMPv1_ADD);
            if(ret != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIM_OUT_SSM_RANGE_IGMPv1_ADD)!\n");
            }
            break;
        case IGMP_TO_PIMSM_CANCEL_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM receive IGMPv1 message of IGMP_TO_PIMSM_CANCEL_ADDR \n");
            blRetval = Debug_Common_Func();
            if (blRetval)
            {
                //SendDebugMessage(e_debug_ip_pim, ss);
                //zlog_debug(ss);
            }

            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv1 message IGMP_TO_PIMSM_CANCEL_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstIgmpv1ToPimsm->ifindex, pstIgmpv1ToPimsm->wGrpNum);
            pstGroupListNode = pstGroupListHead;
            while(pstGroupListNode != NULL)
            {
                PIM_DEBUG("%s  \n", pim_InetFmt(&pstGroupListNode->addr));
                pstGroupListNode = pstGroupListNode->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            ret = pimsm_IgmpGrpMemberProc(pstIgmpv1ToPimsm->ifindex, pstGroupListHead, PIMSM_OUT_SSM_RANGE_IGMPv1_DEL);
            if(ret != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIM_OUT_SSM_RANGE_IGMPv1_DEL)!\n");
            }
            break;
        default:
            PIM_DEBUG("The IGMPv1 message type(%d) error!\n", pstIgmpv1ToPimsm->dwType);
            return VOS_ERROR;
        }

        /* Free Group List */
        pimsm_FreeGroupList(pstIgmpv1ToPimsm->pstGrpListHead);
        pstIgmpv1ToPimsm->pstGrpListHead = NULL;
        break;
    case mmIgmpv2ToPim:
        pstIgmpv2ToPimsm = &(pstPimsmMsg->u_msg.mIgmpToPimsm.u_version.stIgmpv2ToPimsm);
        pstGroupListHead = pstIgmpv2ToPimsm->pstGrpListHead;
        switch (pstIgmpv2ToPimsm->dwType)
        {
        case IGMP_TO_PIMSM_ADD_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM receive IGMPv2 message of IGMP_TO_PIMSM_ADD_ADDR \n");
            blRetval = Debug_Common_Func();
            if (blRetval)
            {
                //SendDebugMessage(e_debug_ip_pim, ss);
                //zlog_debug(ss);
            }

            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv2 message IGMP_TO_PIMSM_ADD_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstIgmpv2ToPimsm->ifindex, pstIgmpv2ToPimsm->wGrpNum);
            pstGroupListNode = pstGroupListHead;
            while(pstGroupListNode != NULL)
            {
                PIM_DEBUG("%s  \n", pim_InetFmt(&pstGroupListNode->addr));
                pstGroupListNode = pstGroupListNode->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            ret = pimsm_IgmpGrpMemberProc(pstIgmpv2ToPimsm->ifindex, pstGroupListHead, PIMSM_OUT_SSM_RANGE_IGMPv2_ADD);
            if(ret != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIM_OUT_SSM_RANGE_IGMPv2_ADD)!\n");
            }
            break;
        case IGMP_TO_PIMSM_CANCEL_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM receive IGMPv2 message of IGMP_TO_PIMSM_CANCEL_ADDR \n");
            blRetval = Debug_Common_Func();
            if (blRetval)
            {
                //SendDebugMessage(e_debug_ip_pim, ss);
                //zlog_debug(ss);
            }

            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv2 message IGMP_TO_PIMSM_CANCEL_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstIgmpv2ToPimsm->ifindex, pstIgmpv2ToPimsm->wGrpNum);
            pstGroupListNode = pstGroupListHead;
            while(pstGroupListNode != NULL)
            {
                PIM_DEBUG("%s  \n", pim_InetFmt(&pstGroupListNode->addr));
                pstGroupListNode = pstGroupListNode->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            ret = pimsm_IgmpGrpMemberProc(pstIgmpv2ToPimsm->ifindex, pstGroupListHead, PIMSM_OUT_SSM_RANGE_IGMPv2_DEL);
            if(ret != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIM_OUT_SSM_RANGE_IGMPv2_DEL)!\n");
            }
            break;
        default:
            PIM_DEBUG("The IGMPv2 message type(%d) error!\n", pstIgmpv2ToPimsm->dwType);
            return VOS_ERROR;
        }

        /* Free Group List */
        pimsm_FreeGroupList(pstIgmpv2ToPimsm->pstGrpListHead);
        pstIgmpv2ToPimsm->pstGrpListHead = NULL;
        break;
    case mmIgmpv3ToPim:
    case mmMldv2ToPim:
        memset(ss, 0x00, SS_DEB_lENTH);
        sprintf(ss, "PIM receive IGMPv3 message!\n");
        blRetval = Debug_Common_Func();
        if (blRetval)
        {
            //SendDebugMessage(e_debug_ip_pim, ss);
            //zlog_debug(ss);
        }

        pstIgmpv3ToPimsm = &(pstPimsmMsg->u_msg.mIgmpToPimsm.u_version.mIgmpv3ToPimsm);
        pstRecordListCurr = pstIgmpv3ToPimsm->pstRecordListHead;
        switch (pstIgmpv3ToPimsm->dwType)
        {
        case IGMP_TO_PIMSM_ADD_ADDR:
            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv3 message IGMP_TO_PIMSM_ADD_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, McAddrNum: %d.\n", pstIgmpv3ToPimsm->ifindex, pstIgmpv3ToPimsm->wGrpNum);
            pstRecordListNext = pstRecordListCurr;
            while(pstRecordListNext != NULL)
            {
                PIM_DEBUG("FilterMode: %s , GrpAddr: %s , SrcList: ", acFilterModeString[pstRecordListNext->wFilterMode], pim_InetFmt(&pstRecordListNext->grp_addr));
                pstSourceListNode = pstRecordListNext->pstSourListHead;
                while(pstSourceListNode)
                {
                    printf("%s , ", pim_InetFmt(&pstSourceListNode->addr));
                    pstSourceListNode = pstSourceListNode->pstNext;
                }
                printf("\n");
                pstRecordListNext = pstRecordListNext->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            while (NULL != pstRecordListCurr)
            {
                pstRecordListNext = pstRecordListCurr->pstNext;
                blRetval = pimsm_IsSsmRangeAddr(&(pstRecordListCurr->grp_addr));
                if (blRetval)
                {
                    //如果是包含模式
                    if (IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /* 至此,此消息为组播地址在SSM范围内的包含模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_IN_SSM_RANGE_INCLUDE_ADD);
                    }
                    else // SSM范围内没有其它模式
                    {
                        PIM_DEBUG("There are error mode in igmp msg to pim!\n");
                    }
                }
                else /*组地址在SSM范围外*/
                {
                    if (IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围外的包含模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_INCLUDE_ADD);
                    }
                    else if (IGMPv3_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此组播地址在SSM范围外的排除模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }
                }
                /* 释放消息中本组*/
                pstRecordListCurr = pstRecordListNext;
            }

            break;
        case IGMP_TO_PIMSM_CANCEL_ADDR:
            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive IGMPv3 message IGMP_TO_PIMSM_CANCEL_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, McAddrNum: %d.\n", pstIgmpv3ToPimsm->ifindex, pstIgmpv3ToPimsm->wGrpNum);
            pstRecordListNext = pstRecordListCurr;
            while(pstRecordListNext != NULL)
            {
                PIM_DEBUG("FilterMode: %s , GrpAddr: %s , SrcList: ", acFilterModeString[pstRecordListNext->wFilterMode], pim_InetFmt(&pstRecordListNext->grp_addr));
                pstSourceListNode = pstRecordListNext->pstSourListHead;
                while(pstSourceListNode)
                {
                    printf("%s , ", pim_InetFmt(&pstSourceListNode->addr));
                    pstSourceListNode = pstSourceListNode->pstNext;
                }
                printf("\n");
                pstRecordListNext = pstRecordListNext->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            /* 同上面'IGMP_TO_PIM_ADD_ADDR'流程 */
            while (NULL != pstRecordListCurr)
            {
                pstRecordListNext = pstRecordListCurr->pstNext;
                blRetval = pimsm_IsSsmRangeAddr(&(pstRecordListCurr->grp_addr));
                //如果在范围内
                if (blRetval)
                {
                    //如果是包含模式
                    if (IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围内的包含模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_IN_SSM_RANGE_INCLUDE_DEL);
                    }
                    else if (IGMPv3_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*范围突然改变时，有些处于排除模式的组播组的时候会运行到此处
                        此时虽然通过blRetval看出是范围内，但其实MLD发该撤销消息过来
                        时还是范围外，因此要按照范围外排除模式撤销的消息处理*/
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }

                }
                else /*组地址在SSM范围外*/
                {
                    if (IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围外的包含模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_INCLUDE_DEL);
                    }
                    else if (IGMPv3_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此组播地址在SSM范围外的排除模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstIgmpv3ToPimsm->ifindex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }
                }
                pstRecordListCurr = pstRecordListNext;
            }
            break;
        default :
            PIM_DEBUG("The IGMPv3 message type(%d) error!\n", pstIgmpv3ToPimsm->dwType);
            return VOS_ERROR;
        }

        /* Free Record List */
        pimsm_FreeRecordList(pstIgmpv3ToPimsm->pstRecordListHead);
        pstIgmpv3ToPimsm->pstRecordListHead = NULL;
        break;
    default:
        PIM_DEBUG("The message type(%d) error!\n", pstPimsmMsg->stCommonHead.wMsgType);
        return VOS_ERROR;
    }
    return VOS_OK;
}

static PIMSM_ADDR_LIST_T * pimsm_ConvertGroupList(uint8_t byAddrFamily, void *data)
{
    return NULL;
}
static PIMSM_RECORD_LIST_T * pimsm_ConvertRecordList(uint8_t byAddrFamily, void *data)
{

    return NULL;
}

int pimsm_MsgProcMld(PIMSM_MSG_T *pstPimsmMsg)
{
    PIMSM_RECORD_LIST_T *pstRecordListHead;
    PIMSM_RECORD_LIST_T *pstRecordListCurr = NULL;
    PIMSM_RECORD_LIST_IPV6_T *pstRecordListHeadIpv6 = NULL;
    PIMSM_RECORD_LIST_IPV6_T *pstRecordListNextIpv6 = NULL;
    PIMSM_ADDR_LIST_IPV6_T *pstGrpListHeadIpv6 = NULL;
    PIMSM_ADDR_LIST_IPV6_T *pstGrpListNodeIpv6 = NULL;
    PIMSM_ADDR_LIST_NODE_IPV6_T *pstSrcListNodeIpv6 = NULL;
    const char *acFilterModeString[] = {"", "Include", "Exclude"};
    m_Mldv1ToPimsm_t *pstMldv1ToPimsm = NULL;
    m_Mldv2ToPimsm_t *pstMldv2ToPimsm = NULL;
    PIMSM_ADDR_LIST_T *pstGrpListHead = NULL;
    uint8_t byAddrFamily = ADDRF_IPV6;
    int iRetval = VOS_ERROR;
    char ss[SS_DEB_lENTH];
    uint8_t blRetval;
#if 0
    PIMSM_ADDR_LIST_NODE_IPV6_T any_src_addr_list;
    memset(&any_src_addr_list,0,sizeof(PIMSM_ADDR_LIST_NODE_IPV6_T));
    pstSrcListNodeIpv6 = &any_src_addr_list;
#endif
    PIM_DEBUG("Pimsm receive a message from MLDv%d.\n", pstPimsmMsg->stCommonHead.wMsgType - mmMldMsgHeader);

    switch(pstPimsmMsg->stCommonHead.wMsgType)
    {
    case mmMldv1ToPim:
        pstMldv1ToPimsm = &(pstPimsmMsg->u_msg.mMldToPimsm.stMldv1ToPimsm);
        pstGrpListHeadIpv6 = pstMldv1ToPimsm->pstGrpListHead;
        switch(pstMldv1ToPimsm->dwType)
        {
        case MLD_TO_PIMSM_ADD_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM-SM receive MLDv1 message of MLD_TO_PIMSM_ADD_ADDR \n");
#if 0
            blRetval = Debug_Common_Func(LEVEL_DEBUG, e_debug_ip_pimsm_mrt);
            if (blRetval)
            {
                SendDebugMessage(e_debug_ip_pimsm_mrt, ss);
            }
#endif

            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive MLDv1 message MLD_TO_PIMSM_ADD_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstMldv1ToPimsm->dwIfIndex, pstMldv1ToPimsm->wGrpNum);
            pstGrpListNodeIpv6 = pstGrpListHeadIpv6;
            while(pstGrpListNodeIpv6 != NULL)
            {
                //PIM_DEBUG("%s \n", inet6_ntoa(pstGrpListNodeIpv6->stAddr));
                pstGrpListNodeIpv6 = pstGrpListNodeIpv6->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            pstGrpListHead = pimsm_ConvertGroupList(byAddrFamily, pstGrpListHeadIpv6); //This will free pstGrpListHeadIpv6
            iRetval = pimsm_IgmpGrpMemberProc(pstMldv1ToPimsm->dwIfIndex, pstGrpListHead, PIMSM_OUT_SSM_RANGE_MLDv1_ADD);
            if(iRetval != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIMSM_OUT_SSM_RANGE_MLDv1_ADD)!\n");
            }
            break;
        case MLD_TO_PIMSM_CANCEL_ADDR:
            memset(ss, 0x00, SS_DEB_lENTH);
            sprintf(ss, "PIM-SM receive MLDv1 message of MLD_TO_PIMSM_CANCEL_ADDR \n");
#if 0
            blRetval = Debug_Common_Func(LEVEL_DEBUG, e_debug_ip_pimsm_mrt);
            if (blRetval)
            {
                SendDebugMessage(e_debug_ip_pimsm_mrt, ss);
            }
#endif
            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive MLDv1 message MLD_TO_PIMSM_CANCEL_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, GroupNum: %d.\n", pstMldv1ToPimsm->dwIfIndex, pstMldv1ToPimsm->wGrpNum);
            pstGrpListNodeIpv6 = pstGrpListHeadIpv6;
            while(pstGrpListNodeIpv6 != NULL)
            {
                PIM_DEBUG("%s  \n", /*pimsm_InetFmtIpv6(&pstGrpListNodeIpv6->stAddr)*/inet6_ntoa(*((struct in6_addr *)(&(pstGrpListNodeIpv6->stAddr)))));
                pstGrpListNodeIpv6 = pstGrpListNodeIpv6->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            pstGrpListHead = pimsm_ConvertGroupList(byAddrFamily, pstGrpListHeadIpv6); //This will free pstGrpListHeadIpv6
            iRetval = pimsm_IgmpGrpMemberProc(pstMldv1ToPimsm->dwIfIndex, pstGrpListHead, PIMSM_OUT_SSM_RANGE_MLDv1_DEL);
            if(iRetval != VOS_OK)
            {
                PIM_DEBUG("Call pim_IgmpGrpMemberProc error(PIMSM_OUT_SSM_RANGE_MLDv1_DEL)!\n");
            }
            break;
        default:
            PIM_DEBUG("The MLDv1 message type(%d) error!\n", pstMldv1ToPimsm->dwType);
            return VOS_ERROR;
        }

        /* Free Group List */
        pimsm_FreeGroupList(pstGrpListHead);
        pstGrpListHead = NULL;
        break;
    case mmMldv2ToPim:
        memset(ss, 0x00, SS_DEB_lENTH);
        sprintf(ss, "PIM-SM receive MLDv2 message!\n");
#if 0
        blRetval = Debug_Common_Func(LEVEL_DEBUG, e_debug_ip_pimsm_mrt);
        if (blRetval)
        {
            SendDebugMessage(e_debug_ip_pimsm_mrt, ss);
        }
#endif
        pstMldv2ToPimsm = &(pstPimsmMsg->u_msg.mMldToPimsm.stMldv2ToPimsm);
        pstRecordListHeadIpv6 = pstMldv2ToPimsm->pstRecordListHead;
        switch (pstMldv2ToPimsm->dwType)
        {
        case MLD_TO_PIMSM_ADD_ADDR:
            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive MLDv2 message MLD_TO_PIMSM_ADD_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, McAddrNum: %d.\n", pstMldv2ToPimsm->dwIfIndex, pstMldv2ToPimsm->wGrpNum);
            pstRecordListNextIpv6 = pstRecordListHeadIpv6;
            while (pstRecordListNextIpv6 != NULL)
            {

                PIM_DEBUG("FilterMode: %s , GrpAddr: %s , SrcList: ",
                          acFilterModeString[pstRecordListNextIpv6->wFilterMode],
                          /*pimsm_InetFmtIpv6(&pstRecordListNextIpv6->stGrpAddr)*/inet6_ntoa(*((struct in6_addr *)(&(pstRecordListNextIpv6->stGrpAddr)))));
                pstSrcListNodeIpv6 = pstRecordListNextIpv6->pstSourListHead;

                //pstRecordListNextIpv6->pstSourListHead = &any_src_addr_list;
                while (pstSrcListNodeIpv6)
                {
                    printf("%s , ", /*pimsm_InetFmtIpv6(&pstSrcListNodeIpv6->stAddr)*/inet6_ntoa(*((struct in6_addr *)(&pstSrcListNodeIpv6->stAddr))));
                    pstSrcListNodeIpv6 = pstSrcListNodeIpv6->pstNext;
                }
                printf("\n");
                pstRecordListNextIpv6 = pstRecordListNextIpv6->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            //pstRecordListHead = pimsm_ConvertRecordList(byAddrFamily, pstRecordListHeadIpv6); //this will free pstRecordListHeadIpv6
            for (pstRecordListCurr = /*pstRecordListHead*/pstRecordListHeadIpv6; NULL != pstRecordListCurr; pstRecordListCurr = pstRecordListCurr->pstNext)
            {
                blRetval = pimsm_IsSsmRangeAddr(&(pstRecordListCurr->grp_addr));
                if (blRetval)
                {
                    //如果是包含模式
                    if (MLDv2_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /* 至此,此消息为组播地址在SSM范围内的包含模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_IN_SSM_RANGE_INCLUDE_ADD);
                    }
                    else // SSM范围内没有其它模式
                    {
                        PIM_DEBUG("There are error mode in igmp msg to pim!\n");
                    }
                }
                else /*组地址在SSM范围外*/
                {
                    if (MLDv2_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围外的包含模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_INCLUDE_ADD);
                    }
                    else if (MLDv2_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此组播地址在SSM范围外的排除模式增加消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }
                }
            }
            break;
        case MLD_TO_PIMSM_CANCEL_ADDR:
            PIM_DEBUG("===========================================================\n");
            PIM_DEBUG("Receive MLDv2 message MLD_TO_PIMSM_CANCEL_ADDR !\n");
            PIM_DEBUG("IfIndex: %d, McAddrNum: %d.\n", pstMldv2ToPimsm->dwIfIndex, pstMldv2ToPimsm->wGrpNum);
            pstRecordListNextIpv6 = pstRecordListHeadIpv6;
            while(pstRecordListNextIpv6 != NULL)
            {
                PIM_DEBUG("FilterMode: %s , GrpAddr: %s , SrcList: ",
                          acFilterModeString[pstRecordListNextIpv6->wFilterMode],
                          /*pimsm_InetFmtIpv6(&pstRecordListNextIpv6->stGrpAddr)*/inet6_ntoa(*((struct in6_addr *)(&(pstRecordListNextIpv6->stGrpAddr)))));
                pstSrcListNodeIpv6 = pstRecordListNextIpv6->pstSourListHead;
                //pstRecordListNextIpv6->pstSourListHead = &any_src_addr_list;
                while(pstSrcListNodeIpv6)
                {
                    printf("%s , ", /*pimsm_InetFmtIpv6(&pstSrcListNodeIpv6->stAddr)*/inet6_ntoa(*((struct in6_addr *)(&pstSrcListNodeIpv6->stAddr))));
                    pstSrcListNodeIpv6 = pstSrcListNodeIpv6->pstNext;
                }
                printf("\n");
                pstRecordListNextIpv6 = pstRecordListNextIpv6->pstNext;
            }
            PIM_DEBUG("===========================================================\n");

            /* 同上面'MLD_TO_PIM_ADD_ADDR'流程 */
            pstRecordListHead = pimsm_ConvertRecordList(byAddrFamily, pstRecordListHeadIpv6); //this will free pstRecordListHeadIpv6
            for (pstRecordListCurr = pstRecordListHead; NULL != pstRecordListCurr; pstRecordListCurr = pstRecordListCurr->pstNext)
            {
                blRetval = pimsm_IsSsmRangeAddr(&(pstRecordListCurr->grp_addr));
                //如果在范围内
                if (blRetval)
                {
                    //如果是包含模式
                    if (MLDv2_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围内的包含模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_IN_SSM_RANGE_INCLUDE_DEL);
                    }
                    else if (MLDv2_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*范围突然改变时，有些处于排除模式的组播组的时候会运行到此处
                        此时虽然通过blRetval看出是范围内，但其实MLD发该撤销消息过来
                        时还是范围外，因此要按照范围外排除模式撤销的消息处理*/
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }

                }
                else /*组地址在SSM范围外*/
                {
                    if (MLDv2_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此消息为组播地址在SSM范围外的包含模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_INCLUDE_DEL);
                    }
                    else if (MLDv2_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListCurr->wFilterMode)
                    {
                        /*至此,此组播地址在SSM范围外的排除模式删除消息*/
                        //处理每个源之后释放消息中源列表内存
                        pimsm_IgmpGrpMemberProc(pstMldv2ToPimsm->dwIfIndex, pstRecordListCurr, PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL);
                    }
                    else
                    {
                        return VOS_ERROR;
                    }
                }
            }
            break;
        default :
            PIM_DEBUG("The MLDv2 message type(%d) error!\n", pstMldv2ToPimsm->dwType);
            return VOS_ERROR;
        }

        /* Free Record List */
        pimsm_FreeRecordList(pstRecordListHead);
        pstRecordListHead = NULL;
        break;
    default:
        PIM_DEBUG("The message type(%d) error!\n", pstPimsmMsg->stCommonHead.wMsgType);
        return VOS_ERROR;
    }

    return iRetval;
}


#endif
