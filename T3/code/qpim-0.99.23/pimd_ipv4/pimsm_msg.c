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

#define running

#if 0//sangmeng FIXME:
int pimsm_CfmRunningDataMsgProc(CliHead *pstCliHead)
{
    PIMSM_GLOBAL_RUNNING_DATA_T *pstGlRunningData = NULL;
    struct pimsm_crp_group_policy_list *pstCrpGroupPolicyEntryNew = NULL;
    struct pimsm_crp_group_policy_list *pstCrpGroupPolicyEntry = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstAcptRegEntryNew = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstAcptRegEntry = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntryNew = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntry = NULL;
    PIMSM_IF_RUNNING_DATA_T *pstIfRunningData = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    PIMSM_MSG_T stPimsmToCfmMsg;
    uint16_t wIfCount = 0;

    if(pstCliHead == NULL)
    {
        return VOS_ERROR;
    }

    //alloc memroy
    pimsm_ifp = g_pimsm_interface_list;
    if(pimsm_ifp == NULL)
    {
        stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData = XMALLOC(MTYPE_BUFFER, sizeof(PIMSM_GLOBAL_RUNNING_DATA_T));
        memset(stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData, 0, sizeof(PIMSM_GLOBAL_RUNNING_DATA_T));
        stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.dwDataSize = sizeof(PIMSM_GLOBAL_RUNNING_DATA_T);
    }
    else
    {
        while(pimsm_ifp != NULL)
        {
            wIfCount++;
            pimsm_ifp = pimsm_ifp->next;
        }
        stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.dwDataSize = sizeof(PIMSM_GLOBAL_RUNNING_DATA_T) + wIfCount * sizeof(PIMSM_IF_RUNNING_DATA_T);
        stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData = XMALLOC(MTYPE_BUFFER, stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.dwDataSize);
        memset(stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData, 0x00, stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.dwDataSize);
    }

    //GlobalRunning Configure
    pstGlRunningData = (PIMSM_GLOBAL_RUNNING_DATA_T *)(stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData);
    pstGlRunningData->wIfNum = wIfCount;
    if(0 != ((g_stPimsm.wFlags) & PIMSM_FLAG_CONFIG))
    {
        pstGlRunningData->blGlobalEnable = TRUE;
    }
    else
    {
        pstGlRunningData->blGlobalEnable = FALSE;
    }

    pstGlRunningData->dwBsrRootID = g_root_cbsr_id.unicast_addr;
    pstGlRunningData->bCbsrEnable = g_cbsr_enable;
    pstGlRunningData->wCbsrPriority = g_root_cbsr_priority;
    pstGlRunningData->bCrpEnable = g_crp_enable;
    pstGlRunningData->dwRpRootID = g_root_crp_id.unicast_addr;
    pstGlRunningData->wCrpPriority = g_root_crp_priority;
    pstGlRunningData->bSptThresholdInfinity = g_stPimsm.bSptThresholdInfinity;

    //Static RP List
    pstStaticRpEntry = g_stPimsm.pstStaticRpList;
    while(pstStaticRpEntry != NULL)
    {
        pstStaticRpEntryNew = XMALLOC(MTYPE_PIM_STATIC_RP, sizeof(PIMSM_STATIC_RP_ENTRY_T));
        memset(pstStaticRpEntryNew, 0, sizeof(PIMSM_STATIC_RP_ENTRY_T));

        pstStaticRpEntryNew->group_addr = pstStaticRpEntry->group_addr;
        pstStaticRpEntryNew->group_masklen = pstStaticRpEntry->group_masklen;
        pstStaticRpEntryNew->stRPAddress = pstStaticRpEntry->stRPAddress;
        pstStaticRpEntryNew->pstNext = pstGlRunningData->pstStaticRpList;
        pstGlRunningData->pstStaticRpList = pstStaticRpEntryNew;

        pstStaticRpEntry = pstStaticRpEntry->pstNext;
    }

    //Accept Source List
    pstAcptRegEntry = g_stPimsm.pstAcceptRegisterList;
    while(pstAcptRegEntry != NULL)
    {
        pstAcptRegEntryNew = XMALLOC(MTYPE_PIM_ACCEPT_REGISTER, sizeof(PIMSM_ACCEPT_REGISTER_ENTRY_T));
        memset(pstAcptRegEntryNew, 0, sizeof(PIMSM_ACCEPT_REGISTER_ENTRY_T));

        pstAcptRegEntryNew->stSourceAddr = pstAcptRegEntry->stSourceAddr;
        pstAcptRegEntryNew->wSourceMaskLen = pstAcptRegEntry->wSourceMaskLen;
        pstAcptRegEntryNew->pstNext = pstGlRunningData->pstAcceptRegList;
        pstGlRunningData->pstAcceptRegList = pstAcptRegEntryNew;

        pstAcptRegEntry = pstAcptRegEntry->pstNext;
    }

    //Crp Group Policy List
    pstCrpGroupPolicyEntry = g_crp_group_policy_list;
    while(pstCrpGroupPolicyEntry != NULL)
    {
        pstCrpGroupPolicyEntryNew = XMALLOC(MTYPE_PIM_CRP_GROUP_POLICY_LIST, sizeof(struct pimsm_crp_group_policy_list));
        memset(pstCrpGroupPolicyEntryNew, 0, sizeof(struct pimsm_crp_group_policy_list));

        pstCrpGroupPolicyEntryNew->group_addr = pstCrpGroupPolicyEntry->group_addr;
        pstCrpGroupPolicyEntryNew->group_masklen = pstCrpGroupPolicyEntry->group_masklen;
        pstCrpGroupPolicyEntryNew->pstNext = pstGlRunningData->pstCrpGroupPolicyList;
        pstGlRunningData->pstCrpGroupPolicyList = pstCrpGroupPolicyEntryNew;

        pstCrpGroupPolicyEntry = pstCrpGroupPolicyEntry->pstNext;
    }

    if(pstGlRunningData->wIfNum == 0)
    {
        return VOS_OK;
    }

    pstIfRunningData = (PIMSM_IF_RUNNING_DATA_T *)(stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.pData + sizeof(PIMSM_GLOBAL_RUNNING_DATA_T));

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp != NULL)
    {
        pstIfRunningData->ifindex = pimsm_ifp->ifindex;
        pstIfRunningData->pimsm_hello_period = pimsm_ifp->pimsm_hello_period;
        pstIfRunningData->dwDrPriority = pimsm_ifp->pimsm_dr_priority;
        pstIfRunningData->dwJoinPruneInterval = pimsm_ifp->dwJoinPruneInterval;

        if((pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE) == 0)
        {
            pstIfRunningData->wPimsmEnableFlag = FALSE;
        }
        else
        {
            pstIfRunningData->wPimsmEnableFlag = TRUE;
        }

        pstIfRunningData++;

        pimsm_ifp = pimsm_ifp->next;
    }

    stPimsmToCfmMsg.stCommonHead.wSourTaskID = TASK_ID_PIMSM;
    stPimsmToCfmMsg.stCommonHead.wDestTaskID = TASK_ID_CFM;
    stPimsmToCfmMsg.stCommonHead.wMsgLength  = sizeof(PIMSM_MSG_T);
    stPimsmToCfmMsg.stCommonHead.wMsgType    = mm_RunningDataResponse_ALLtoCFM;
    stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.bDataFlag = TRUE;
    memcpy(&(stPimsmToCfmMsg.u_msg.mPimsmToCfm.stRunningDataResponse.stCliHead), pstCliHead, sizeof(CliHead));

#if 0//FIXME: will use socket
    if(vos_MsgPost(TASK_ID_CFM, (char *)&stPimsmToCfmMsg, WAIT_FOREVER) != VOS_OK)
    {
        return VOS_ERROR;
    }
#endif

    return VOS_OK;
}
#endif

#if 0
//sangmeng FIXME: show running-config
void pimsm_show_run(char* pData,CliHead* pCliHead,CFM_HEAD* pCfmHead)
{
    PIMSM_GLOBAL_RUNNING_DATA_T *pstGlRunningData = NULL;
    struct pimsm_crp_group_policy_list *pstCrpGroupPolicyEntryToFree = NULL;
    struct pimsm_crp_group_policy_list *pstCrpGroupPolicyEntry = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstAcptRegEntryToFree = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstAcptRegEntry = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntryToFree = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntry = NULL;
    PIMSM_IF_RUNNING_DATA_T *pstIfRunningData = NULL;
    char cIpv4Addr1[PIMSM_IP_ADDR_STRING_LEN];
    char cIpv4Addr2[PIMSM_IP_ADDR_STRING_LEN];
    char cIpv4Addr3[PIMSM_IP_ADDR_STRING_LEN];
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    VOS_IP_ADDR stSourceMask;
    VOS_IP_ADDR stGroupMask;
    char cInterfaceName[200];
    uint32_t iCmdLineID;
    char *buffer = NULL;
    uint32_t ifindex;
    uint16_t wIfCount;
    int len = 0;
    int i;

    if((pData == NULL) || (pCliHead == NULL))
    {
        return;
    }

    pstGlRunningData = (PIMSM_GLOBAL_RUNNING_DATA_T *)pData;
    wIfCount = pstGlRunningData->wIfNum;

    buffer = XMALLOC(MTYPE_BUFFER, PIM_MAX_BUF);
    if(NULL == buffer)
    {
        return;
    }
    memset(buffer, 0, PIM_MAX_BUF);

    len = len + sprintf(buffer + len, "\n!");
    //Global About
    if(pstGlRunningData->blRpEmbeded)
    {
        len = len + sprintf(buffer + len, "\nip pim-sm rp embedded");//unused
    }

    //C-BSR
    if(pstGlRunningData->bCbsrEnable)
    {
        memset(cInterfaceName, 0, sizeof(cInterfaceName));
        pimsm_ifp = g_pimsm_interface_list;
        while(pimsm_ifp)
        {
            if(0 == memcmp(&pstGlRunningData->dwBsrRootID, &pimsm_ifp->primary_address, sizeof(pstGlRunningData->dwBsrRootID)))
            {
                ifindex = pimsm_ifp->ifindex;
                break;
            }

            pimsm_ifp = pimsm_ifp->next;
        }
        if(pim_GetIntfNameFromLogicID(ifindex, cInterfaceName))
        {
            len = len + sprintf(buffer + len, "\nip pim-sm c-bsr interface %s priority %d", cInterfaceName, pstGlRunningData->wCbsrPriority);
        }
    }

    /*
    //BSR Send Interval
    if(PIM_TIMER_SEND_INTERVAL != pstGlRunningData->dwBsrSendInterval)
    {
    	len = len + sprintf(buffer + len, "\nip pim-sm c-bsr interval %d", pstGlRunningData->dwBsrSendInterval);
    }
    */

    //C-RP
    if(pstGlRunningData->bCrpEnable)
    {
        memset(cInterfaceName, 0, sizeof(cInterfaceName));
        pimsm_ifp = g_pimsm_interface_list;
        while(pimsm_ifp)
        {
            if(0 == memcmp(&pstGlRunningData->dwRpRootID, &pimsm_ifp->primary_address, sizeof(pstGlRunningData->dwRpRootID)))
            {
                ifindex = pimsm_ifp->ifindex;
                break;
            }

            pimsm_ifp = pimsm_ifp->next;
        }
        if(pim_GetIntfNameFromLogicID(ifindex, cInterfaceName))
        {
            len = len + sprintf(buffer + len, "\nip pim-sm c-rp interface %s priority %d", cInterfaceName, pstGlRunningData->wCrpPriority);
        }
    }

    //Static RP
    if(pstGlRunningData->pstStaticRpList != NULL)
    {
        pstStaticRpEntry = pstGlRunningData->pstStaticRpList;
        while(pstStaticRpEntry != NULL)
        {
            memset(cIpv4Addr1, 0, PIMSM_IP_ADDR_STRING_LEN);
            memset(cIpv4Addr2, 0, PIMSM_IP_ADDR_STRING_LEN);
            memset(cIpv4Addr3, 0, PIMSM_IP_ADDR_STRING_LEN);
            MASKLEN_TO_MASK6(pstStaticRpEntry->group_masklen, stGroupMask);
            ip_printAddress(&(pstStaticRpEntry->group_addr), cIpv4Addr1, sizeof(cIpv4Addr1));
            ip_printAddress(&stGroupMask, cIpv4Addr2, sizeof(cIpv4Addr2));
            ip_printAddress(&(pstStaticRpEntry->stRPAddress), cIpv4Addr3, sizeof(cIpv4Addr3));
            if(0 == pstStaticRpEntry->group_masklen)
            {
                len = len + sprintf(buffer + len, "\nip pim-sm rp-address %s", cIpv4Addr3);
            }
            else
            {
                len = len + sprintf(buffer + len, "\nip pim-sm rp-address %s %s %s", cIpv4Addr3, cIpv4Addr1, cIpv4Addr2);
            }

            pstStaticRpEntryToFree = pstStaticRpEntry;
            pstStaticRpEntry = pstStaticRpEntry->pstNext;
            XFREE(MTYPE_PIM_STATIC_RP, pstStaticRpEntryToFree);
        }
    }

    if(!pstGlRunningData->bSptThresholdInfinity)
    {
        len = len + sprintf(buffer + len, "\nno ip pim-sm spt-threshold");
    }

    //[no] ip pim-sm accept-register A.B.C.D A.B.C.D
    if(pstGlRunningData->pstAcceptRegList != NULL)
    {
        pstAcptRegEntry = pstGlRunningData->pstAcceptRegList;
        while(pstAcptRegEntry != NULL)
        {
            memset(cIpv4Addr1, 0, PIMSM_IP_ADDR_STRING_LEN);
            memset(cIpv4Addr2, 0, PIMSM_IP_ADDR_STRING_LEN);
            MASKLEN_TO_MASK6(pstAcptRegEntry->wSourceMaskLen, stSourceMask);
            ip_printAddress(&(pstAcptRegEntry->stSourceAddr), cIpv4Addr1, sizeof(cIpv4Addr1));
            ip_printAddress(&stSourceMask, cIpv4Addr2, sizeof(cIpv4Addr2));
            len = len + sprintf(buffer + len, "\nip pim-sm accept-register %s %s", cIpv4Addr1, cIpv4Addr2);

            pstAcptRegEntryToFree = pstAcptRegEntry;
            pstAcptRegEntry = pstAcptRegEntry->pstNext;
            XFREE(MTYPE_PIM_ACCEPT_REGISTER, pstAcptRegEntryToFree);
        }
    }

    //[no] ip pim-sm c-rp group-policy A.B.C.D A.B.C.D
    if(pstGlRunningData->pstCrpGroupPolicyList != NULL)
    {
        pstCrpGroupPolicyEntry = pstGlRunningData->pstCrpGroupPolicyList;
        while(pstCrpGroupPolicyEntry != NULL)
        {
            memset(cIpv4Addr1, 0, PIMSM_IP_ADDR_STRING_LEN);
            memset(cIpv4Addr2, 0, PIMSM_IP_ADDR_STRING_LEN);
            MASKLEN_TO_MASK6(pstCrpGroupPolicyEntry->group_masklen, stGroupMask);
            ip_printAddress(&(pstCrpGroupPolicyEntry->group_addr), cIpv4Addr1, sizeof(cIpv4Addr1));
            ip_printAddress(&stGroupMask, cIpv4Addr2, sizeof(cIpv4Addr2));
            len = len + sprintf(buffer + len, "\nip pim-sm c-rp group-policy %s %s", cIpv4Addr1, cIpv4Addr2);

            pstCrpGroupPolicyEntryToFree = pstCrpGroupPolicyEntry;
            pstCrpGroupPolicyEntry = pstCrpGroupPolicyEntry->pstNext;
            XFREE(MTYPE_PIM_CRP_GROUP_POLICY_LIST, pstCrpGroupPolicyEntryToFree);
        }
    }

    //生成全局的show run信息命令行
    iCmdLineID = CFM_CMD_LINE_MAKE(CFM_CMD_LINE_PIM_MAIN_BASE, CFM_CMD_LINE_COMMON);
    cfm_InsertCmdLine(INTERFACE_DEFAULT_LOGICID, iCmdLineID, buffer, (int)strlen(buffer));

    if(wIfCount == 0)
    {
        XFREE(MTYPE_BUFFER, buffer);
        return;
    }

    //Interface About
    pstIfRunningData = (PIMSM_IF_RUNNING_DATA_T *)(pData + sizeof(PIMSM_GLOBAL_RUNNING_DATA_T));
    for(i = 0; i < wIfCount; i++)
    {
        len = 0;
        memset(buffer, 0, PIM_MAX_BUF);

        if(TRUE == pstIfRunningData->wPimsmEnableFlag)
        {
            len = len + sprintf(buffer + len, "\n ip pim-sm enable");
        }

        if(pstIfRunningData->pimsm_hello_period != PIM_HELLO_PERIOD)
        {
            len = len + sprintf(buffer + len, "\n ip pim-sm hello-interval %ld", pstIfRunningData->pimsm_hello_period);
        }

        if(pstIfRunningData->dwJoinPruneInterval != PIM_JOIN_PRUNE_PERIOD)
        {
            len = len + sprintf(buffer + len, "\n ip pim-sm join-prune-interval %ld", pstIfRunningData->dwJoinPruneInterval);
        }

        if(pstIfRunningData->dwDrPriority != PIMSM_DR_PRIORITY_DEFAULT)
        {
            len = len + sprintf(buffer + len, "\n ip pim-sm dr-priority %ld", pstIfRunningData->dwDrPriority);
        }

        iCmdLineID = CFM_CMD_LINE_MAKE(CFM_CMD_LINE_NI_PIM, CFM_CMD_LINE_NI_CMD);
        cfm_InsertCmdLine(pstIfRunningData->ifindex, iCmdLineID, buffer, (int)strlen(buffer));
        pstIfRunningData++;
    }

    XFREE(MTYPE_BUFFER, buffer);

    return;
}
#endif


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

#define message_process

#if 0
static int pimsm_MsgProcCli(PIMSM_MSG_T *pstPimsmMsg)
{
    VOS_IP_ADDR *pstGroupAddr = NULL;
    VOS_IP_ADDR *pstGroupMask = NULL;
    VOS_IP_ADDR *pstSourceAddr = NULL;
    VOS_IP_ADDR *pstSourceMask = NULL;
    VOS_IP_ADDR *pstRpAddr = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    m_CliToPimsm_t *pstCliMsg;
    uint32_t dwCmdType;
    uint32_t ifindex;

    if(pstPimsmMsg == NULL)
    {
        return VOS_ERROR;
    }

    pstCliMsg = &pstPimsmMsg->u_msg.mCliToPimsm;

    dwCmdType = pstCliMsg->subclihead.dwCmdType;
    switch(dwCmdType)
    {
        /* 全局配置模式的命令 */
    case CLI_CMD_PIMSM_GLOBAL_ENABLE:
        pimsm_GlobalEnable();
        break;
    case CLI_CMD_PIMSM_NO_GLOBAL_ENABLE:
        pimsm_GlobalDisable();
        break;

    case CLI_CMD_PIMSM_RP_ADDRESS:
        pstRpAddr = &(pstCliMsg->u_cmd.stRp.stRpAddress);
        pstGroupAddr = &(pstCliMsg->u_cmd.stRp.group_addr);
        pstGroupMask = &(pstCliMsg->u_cmd.stRp.stGroupMask);
        pimsm_StaticRpAdd(pstGroupAddr, pstGroupMask, pstRpAddr);
        break;
    case CLI_CMD_PIMSM_NO_RP_ADDRESS:
        pstRpAddr = &(pstCliMsg->u_cmd.stRp.stRpAddress);
        pstGroupAddr = &(pstCliMsg->u_cmd.stRp.group_addr);
        pstGroupMask = &(pstCliMsg->u_cmd.stRp.stGroupMask);
        pimsm_StaticRpDel(pstGroupAddr, pstGroupMask, pstRpAddr);
        break;

    case CLI_CMD_PIMSM_ACCEPT_REGISTER:
        pstSourceAddr = &(pstCliMsg->u_cmd.stAcceptSource.stSourceAddr);
        pstSourceMask = &(pstCliMsg->u_cmd.stAcceptSource.stSourceMask);
        pimsm_AcceptSourceAdd(pstSourceAddr, pstSourceMask);
        break;
    case CLI_CMD_PIMSM_NO_ACCEPT_REGISTER:
        pstSourceAddr = &(pstCliMsg->u_cmd.stAcceptSource.stSourceAddr);
        pstSourceMask = &(pstCliMsg->u_cmd.stAcceptSource.stSourceMask);
        pimsm_AcceptSourceDel(pstSourceAddr, pstSourceMask);
        break;

    case CLI_CMD_PIMSM_SPT_THRESHOLD_INFINITY:
        pimsm_SetSptThresholdInfinity(TRUE);
        //g_stPimsm.bSptThresholdInfinity = 1;
        break;
    case CLI_CMD_PIMSM_NO_SPT_THRESHOLD_INFINITY:
        pimsm_SetSptThresholdInfinity(FALSE);
        //g_stPimsm.bSptThresholdInfinity = 0;
        break;

    case CLI_CMD_PIMSM_SSM_ACCESS_GROUP:
        break;
    case CLI_CMD_PIMSM_NO_SSM_ACCESS_GROUP:
        break;

#if 0
        /* 接口模式的命令 */
    case CLI_CMD_PIMSM_INTERFACE_ENABLE:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        PIM_DEBUG("%s receive command pimsm enable.\n", pimsm_GetIfName(ifindex));
        pimsm_IfEnable(ifindex);
        break;
    case CLI_CMD_PIMSM_NO_INTERFACE_ENABLE:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        PIM_DEBUG("%s receive command pimsm disable.\n", pimsm_GetIfName(ifindex));
        pimsm_IfDisable(ifindex);
        break;
#endif

    case CLI_CMD_PIMSM_HELLO_INTERVAL:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer the hello interval!\n");
            return VOS_ERROR;
        }
        pimsm_ifp->pimsm_hello_period = pstCliMsg->u_cmd.dwSeconds;
        break;
    case CLI_CMD_PIMSM_NO_HELLO_INTERVAL:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer no hello interval!\n");
            return VOS_ERROR;
        }
        pimsm_ifp->pimsm_hello_period = PIM_HELLO_PERIOD;
        break;

    case CLI_CMD_PIMSM_JOIN_PRUNE_INTERVAL:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer j/p interval!\n");
            return VOS_ERROR;
        }
        pimsm_ifp->dwJoinPruneInterval = pstCliMsg->u_cmd.dwSeconds;
        break;
    case CLI_CMD_PIMSM_NO_JOIN_PRUNE_INTERVAL:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer no j/p interval!\n");
            return VOS_ERROR;
        }
        pimsm_ifp->dwJoinPruneInterval = PIM_JOIN_PRUNE_PERIOD;
        break;

    case CLI_CMD_PIMSM_DR_PRIORITY:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer DR priority!\n");
            return VOS_ERROR;
        }

        if (pimsm_ifp->pimsm_dr_priority != pstCliMsg->u_cmd.dwPrValue)
        {
            pimsm_ifp->pimsm_dr_priority = pstCliMsg->u_cmd.dwPrValue;
            if((INTERFACE_LOOPBACK != pimsm_ifp->dwIfType)
                    && (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_P2P)) /* p2p链路不需要DR选举 */
                    && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP))
                    && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)))
            {
                pimsm_DRElection(pimsm_ifp);
                pimsm_SendHello(ifindex, 3.5 * (pimsm_ifp->pimsm_hello_period), NULL);
            }
        }
        break;
    case CLI_CMD_PIMSM_NO_DR_PRIORITY:
        ifindex = pstCliMsg->stCfmHead.iLogicID;
        pimsm_ifp = pimsm_SearchInterface(ifindex);
        if(pimsm_ifp == NULL)
        {
            PIM_DEBUG("Can't find the interface while configer no DR priority!\n");
            return VOS_ERROR;
        }

        if (PIMSM_DR_PRIORITY_DEFAULT != pimsm_ifp->pimsm_dr_priority)
        {
            pimsm_ifp->pimsm_dr_priority = PIMSM_DR_PRIORITY_DEFAULT;
            if((INTERFACE_LOOPBACK != pimsm_ifp->dwIfType)
                    && (0 == (pimsm_ifp->options & PIMSM_IF_FLAG_P2P)) /* p2p链路不需要DR选举 */
                    && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_UP))
                    && (0 != (pimsm_ifp->options & PIMSM_IF_FLAG_ENABLE)))
            {
                pimsm_DRElection(pimsm_ifp);
                pimsm_SendHello(ifindex, 3.5 * (pimsm_ifp->pimsm_hello_period), NULL);
            }
        }
        break;

        //show命令
    case CLI_CMD_PIMSM_SHOW_INTERFACE:
        pimsm_ShowInterface(pstCliMsg);
        break;
    case CLI_CMD_PIMSM_SHOW_NEIGHBOR:
        pimsm_ShowNeighbor(pstCliMsg);
        break;
    case CLI_CMD_PIMSM_SHOW_TOPOLOGY:
        //sangmeng FIXME:
        //pimsm_ShowTopology(pstCliMsg);
        break;
    case CLI_CMD_PIMSM_SHOW_TRAFFIC:
        pimsm_ShowTraffic();
        break;
    case CLI_CMD_PIMSM_SHOW_RPF_PREFIX:
        pimsm_ShowRpf(pstCliMsg);
        break;
    case CLI_CMD_PIMSM_CLEAR_COUNTERS:
        pimsm_ClearCounters();
        break;

        /*bootstrap 命令*/
    case CLI_CMD_PIMSM_BOOTSTRAP_ENABLE:
        //使能cbsr
        pim_BootstrapCbsrEnable(pstCliMsg->u_cmd.stEnableCbsr.iIfIndex, pstCliMsg->u_cmd.stEnableCbsr.dr_priority);
        break;
    case CLI_CMD_PIMSM_NO_BOOTSTRAP_ENABLE:
        //取消cbsr
        pim_BootstrapCbsrDisable();
        break;
    case CLI_CMD_PIMSM_BOOTSTRAP_CRP_ENABLE:
        //使能crp
        pim_BootstrapCrpEnable(pstCliMsg->u_cmd.stEnableCrp.iIfIndex, pstCliMsg->u_cmd.stEnableCrp.dr_priority);
        break;
    case CLI_CMD_PIMSM_NO_BOOTSTRAP_CRP_ENABLE:
        //取消crp
        pim_BootstrapCrpDisable();
        break;
    case CLI_CMD_PIMSM_CRP_GROUP_POLICY:
        //配置crp组服务范围
        pstGroupAddr = &(pstCliMsg->u_cmd.stCrpGroupPolicy.group_addr);
        pstGroupMask = &(pstCliMsg->u_cmd.stCrpGroupPolicy.stGroupMask);
        pim_CrpGroupPolicyAdd(pstGroupAddr, pstGroupMask);
        break;
    case CLI_CMD_PIMSM_NO_CRP_GROUP_POLICY:
        //取消crp组服务范围
        pstGroupAddr = &(pstCliMsg->u_cmd.stCrpGroupPolicy.group_addr);
        pstGroupMask = &(pstCliMsg->u_cmd.stCrpGroupPolicy.stGroupMask);
        pim_CrpGroupPolicyDel(pstGroupAddr, pstGroupMask);
        break;
    case CLI_CMD_PIMSM_SHOW_BOOTSTRAP:
        //显示bsr
        pim_BootstrapBsrShow();
        break;
    case CLI_CMD_PIMSM_SHOW_BOOTSTRAP_RP:
        //显示rp
        pim_BootstrapRpShow();
        break;
    default:
        break;
    }

    return VOS_OK;
}

static int pimsm_MsgProcCfm(PIMSM_MSG_T *pstPimsmMsg)
{
    //uint32_t dwIfModifyFlag;
    int ret = VOS_OK;

//sangmeng FIXME:pim_zebra_init
#if 0
    zassert(NULL != pstPimsmMsg);

    switch (pstPimsmMsg->stCommonHead.wMsgType)
    {
    case mm_RequestRunningData_CFMtoALL:
        ret = pimsm_CfmRunningDataMsgProc(&(pstPimsmMsg->u_msg.mCfmToPimsm.stCliHead));
        break;
    case mm_CfgLogicIntf_CFMtoALL:
        dwIfModifyFlag = pstPimsmMsg->u_msg.mCfmToPimsm.stModify.dwModifyFlag;
        switch(dwIfModifyFlag)
        {
        case CFM_ONLY_ADD_LOGIC_INTF:
            ret  = pimsm_IfAdd(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_DELETE_LOGIC_INTF:
            ret = pimsm_IfDelete(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_NOTIFY_PORT_RUNNING_STATUS_UP:
            ret = pimsm_zebra_if_state_up(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_NOTIFY_PORT_RUNNING_STATUS_DOWN:
            ret = pimsm_IfDown(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_UPDATE_IP_ADDR:
            ret = pimsm_IfAddrAdd(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_NO_IP_ADDR:
            ret = pimsm_IfAddrDel(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        case CFM_UPDATE_MTU:
            ret = pimsm_IfMtuUpdate(&pstPimsmMsg->u_msg.mCfmToPimsm);
            break;
        }
        break;
    }
#endif

    return ret;
}

/* PIM timer out process */
static int pimsm_MsgProcTimer(PIMSM_MSG_T *pstPimsmMsg)
{
    int ret = VOS_ERROR;

    zassert(NULL != pstPimsmMsg);

    switch (pstPimsmMsg->stCommonHead.wMsgType)
    {
    case mmTimeOut_VOStoALL:
        ret = pimsm_TimerOutProc(&(pstPimsmMsg->u_msg.mVosTmServToPimsm));
        break;
    }

    return ret;
}
#endif
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

#if 0
static int pimsm_MsgProcIpf(PIMSM_MSG_T *pstPimsmMsg)
{
    int ret = VOS_ERROR;
#if 0
    zassert(NULL != pstPimsmMsg);

    switch( pstPimsmMsg->stCommonHead.wMsgType )
    {
    case mmProtocolPkt_IpfToPimsm:
        //ret = pimsm_ReceiveProtocolDatagram(&pstPimsmMsg->u_msg.mIpfToPimsm.mIpfPktToPimsm);
        XFREE(MTYPE_BUFFER, pstPimsmMsg->u_msg.mIpfToPimsm.mIpfPktToPimsm.byPkt);
        break;
    case mmMulticastData_IpfToPimsm:
        //ret = pimsm_ReceiveMulticastDatagram(&pstPimsmMsg->u_msg.mIpfToPimsm.mIpfPktToPimsm);
        XFREE(MTYPE_BUFFER, pstPimsmMsg->u_msg.mIpfToPimsm.mIpfPktToPimsm.byPkt);
        break;
    }
#endif

    return ret;
}
#define mmGetRpf				0x000d


/* PIM Rtmgt process */
static int pimsm_MsgProcRtmgt(PIMSM_MSG_T *pstPimsmMsg)
{
    struct rtmgt_to_pimsm stRpf;
    int ret = VOS_ERROR;
    char acTempBuf[200];

    zassert(NULL != pstPimsmMsg);

    switch (pstPimsmMsg->stCommonHead.wMsgType)
    {
    case mmGetRpf:
        if (NULL == pstPimsmMsg->u_msg.mRtMrtToPimsm.pstRpf)
        {
            ret = VOS_ERROR;
            break;
        }
        memcpy(&stRpf, pstPimsmMsg->u_msg.mRtMrtToPimsm.pstRpf, sizeof(stRpf));
        stRpf.source = htonl(stRpf.source);
        stRpf.rpf_nbr_addr = htonl(stRpf.rpf_nbr_addr);
        if( MRTMGT_MSG_GET_RPF_REPLY == pstPimsmMsg->u_msg.mRtMrtToPimsm.type )
        {
            memset(acTempBuf, 0, sizeof(acTempBuf));
            if ( pim_GetIntfNameFromLogicID(stRpf.iif, acTempBuf) == FALSE )
            {
                printf("UpdateRpf: Source = 0x%x, Neighbor = 0x%x, Iif = %d, Metric = %d, Preference = %d\n",
                       stRpf.source, stRpf.rpf_nbr_addr,
                       stRpf.iif, stRpf.metric,
                       stRpf.preference);
            }
            else
            {
                printf("UpdateRpf: Source = 0x%x, Neighbor = 0x%x, Iif = %s, Metric = %d, Preference = %d\n",
                       stRpf.source, stRpf.rpf_nbr_addr,
                       acTempBuf, stRpf.metric,
                       stRpf.preference);
            }
            ret = pimsm_UpdateRpf(&stRpf);
        }
        if (NULL != pstPimsmMsg->u_msg.mRtMrtToPimsm.pstRpf)
        {
            XFREE(MTYPE_PIM_OTHER, pstPimsmMsg->u_msg.mRtMrtToPimsm.pstRpf);
        }
        break;
    }

    return ret;
}
#endif

#define message_distribute

#if 0
int pimsm_MsgProc(PIMSM_MSG_T *pstPimsmMsg)
{
    int ret = VOS_ERROR;
    uint16_t wSourTaskID = 0;

    if (NULL == pstPimsmMsg)
    {
        return VOS_ERROR;
    }

    wSourTaskID = 0x00ff & pstPimsmMsg->stCommonHead.wSourTaskID;
    switch(wSourTaskID)
    {
    case TASK_ID_CLI_SHELL:
        ret = pimsm_MsgProcCli(pstPimsmMsg);
        break;

    case TASK_ID_CFM:
        ret = pimsm_MsgProcCfm(pstPimsmMsg);
        break;

    case TASK_ID_VOS_TM_SERV:
        ret = pimsm_MsgProcTimer(pstPimsmMsg);
        break;

    case TASK_ID_IGMP:
        ret = pimsm_MsgProcIgmp(pstPimsmMsg);
        break;
#if 0
    case TASK_ID_IPF:
        ret = pimsm_MsgProcIpf(pstPimsmMsg);
        break;

    case TASK_ID_RT_MGT:
        ret = pimsm_MsgProcRtmgt(pstPimsmMsg);
        break;
#endif
    }

    return ret;
}
#endif

#endif
