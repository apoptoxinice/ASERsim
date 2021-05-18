#include "pimsm_define.h"

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
#include "pimsm_igmp_taskmain.h"
#if 0
void MLD_WriteMsgHeadToPim(MLD_MSG *pstMsgToPim, uint32_t dwMsgType, uint16_t wAddrNum, uint32_t dwIfIndex, uint16_t wVersion)
{
    if(pstMsgToPim == NULL)
    {
#ifdef MLD_DEBUG
        oam_OutputToDevice(0, "MLD_WriteMsgHeadToPim : parameter is NULL!\n");
#endif
        return;
    }
    switch(wVersion)
    {
        //added by hgx
    case IGMP_VERSION_1:
        pstMsgToPim->CommonHead.wDestTaskID		  = TASK_ID_PIMSM;
        pstMsgToPim->CommonHead.wSourTaskID		  = TASK_ID_IGMP;
        pstMsgToPim->CommonHead.wMsgType		  = mmIgmpv1ToPim;
        pstMsgToPim->CommonHead.wMsgLength		  = sizeof(MLD_MSG);
        pstMsgToPim->u_msg.mIGMPv1ToPim.dwType     = dwMsgType;
        pstMsgToPim->u_msg.mIGMPv1ToPim.dwIfIndex  = dwIfIndex;
        pstMsgToPim->u_msg.mIGMPv1ToPim.wMcAddrNum = wAddrNum;
        return;
        //add end
    case IGMP_VERSION_2:
        pstMsgToPim->CommonHead.wDestTaskID		  = TASK_ID_PIMSM;
        pstMsgToPim->CommonHead.wSourTaskID		  = TASK_ID_IGMP;
        pstMsgToPim->CommonHead.wMsgType		  = mmIgmpv2ToPim;
        pstMsgToPim->CommonHead.wMsgLength		  = sizeof(MLD_MSG);
        pstMsgToPim->u_msg.mMldv1ToPim.dwType     = dwMsgType;
        pstMsgToPim->u_msg.mMldv1ToPim.dwIfIndex  = dwIfIndex;
        pstMsgToPim->u_msg.mMldv1ToPim.wMcAddrNum = wAddrNum;
        return;
    case IGMP_VERSION_3:
        pstMsgToPim->CommonHead.wDestTaskID	= TASK_ID_PIMSM;
        pstMsgToPim->CommonHead.wSourTaskID	= TASK_ID_IGMP;
        pstMsgToPim->CommonHead.wMsgType	= mmIgmpv3ToPim;
        pstMsgToPim->CommonHead.wMsgLength	= sizeof(MLD_MSG);
        pstMsgToPim->u_msg.mMldv2ToPim.dwType	  = dwMsgType;
        pstMsgToPim->u_msg.mMldv2ToPim.wMcAddrNum = wAddrNum;
        pstMsgToPim->u_msg.mMldv2ToPim.dwIfIndex  = dwIfIndex;
        return;
    }
}

#endif
#define MLD_VERSION_1               1
#define MLD_VERSION_2               2
void MLD_WriteMsgHeadToPim(MLD_MSG *pstMsgToPim, uint32_t dwMsgType, uint16_t wAddrNum, uint32_t dwIfIndex, uint16_t wVersion)
{
    if(pstMsgToPim == NULL)
    {
        printf("MLD_WriteMsgHeadToPim : parameter is NULL!\n");
        return;
    }
    switch(wVersion)
    {
    case MLD_VERSION_1:
        pstMsgToPim->CommonHead.wDestTaskID       = TASK_ID_PIMSM;
        pstMsgToPim->CommonHead.wSourTaskID       = TASK_ID_MLD;
        pstMsgToPim->CommonHead.wMsgType          = mmMldv1ToPim;
        pstMsgToPim->CommonHead.wMsgLength        = sizeof(MLD_MSG);
        pstMsgToPim->u_msg.mMldv1ToPim.dwType     = dwMsgType;
        pstMsgToPim->u_msg.mMldv1ToPim.dwIfIndex  = dwIfIndex;
        pstMsgToPim->u_msg.mMldv1ToPim.wMcAddrNum = wAddrNum;
        return;
    case MLD_VERSION_2:
        //填写消息公共头
        pstMsgToPim->CommonHead.wDestTaskID   = TASK_ID_PIMSM;
        pstMsgToPim->CommonHead.wSourTaskID   = TASK_ID_MLD;
        pstMsgToPim->CommonHead.wMsgType  = mmMldv2ToPim;
        pstMsgToPim->CommonHead.wMsgLength    = sizeof(MLD_MSG);
        //填写部分消息体
        pstMsgToPim->u_msg.mMldv2ToPim.dwType   = dwMsgType;
        pstMsgToPim->u_msg.mMldv2ToPim.wMcAddrNum = wAddrNum;
        pstMsgToPim->u_msg.mMldv2ToPim.dwIfIndex  = dwIfIndex;
        return;
    }
}
