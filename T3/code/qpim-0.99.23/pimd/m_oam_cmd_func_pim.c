#include "pimsm_define.h"
#if ((INCLUDE_CLI) && (INCLUDE_PIMSM))

#include "pimsm.h"
#include "pimsm_msg.h"
#include "pimsm_igmp.h"

#define OAM_CLI_USED        0
#define OAM_CFM_USED		1

extern CFM_HEAD cfm_MatchInterfaceType(int,t_oam_cmd_buf *, int);
extern CFM_HEAD cfm_CreateCfmHeadUnderInterfaceStatus(int iIODevice);

//sangmeng FIXME:will use vty_out
int oam_OutputToDevice(uint32_t dwIODeviceNO, const char *szInChar)
{
    return 1;
}
static void MakeCliToPimsmMsg(PIMSM_MSG_T *pstCliMsgToPimsm, uint32_t dwCmdType, uint32_t dwIODevNo)
{
    time_t stTime;

    pstCliMsgToPimsm->stCommonHead.wDestTaskID = TASK_ID_PIMSM;
    pstCliMsgToPimsm->stCommonHead.wSourTaskID = TASK_ID_CLI_SHELL;//TASK_ID_CLI_KERNEL;
    pstCliMsgToPimsm->stCommonHead.wMsgType    = mm_Cmd_CLItoPIM;
    pstCliMsgToPimsm->stCommonHead.wMsgLength  = sizeof(PIMSM_MSG_T);
    time( &stTime );
    pstCliMsgToPimsm->u_msg.mCliToPimsm.subclihead.dwCmdType = dwCmdType;
    pstCliMsgToPimsm->u_msg.mCliToPimsm.subclihead.dwIODevNo    = dwIODevNo;
    pstCliMsgToPimsm->u_msg.mCliToPimsm.subclihead.dwCreateTime = stTime;

    return;
}

/*
	写 OAM_CMD_FUNC 的说明：

 各种模式下都可以使用的命令，使用用oam_ArrangeStatusByMode来调整目标状态。
  如果需要模式转换,将全局设备表中globalIODevTab[iIODevice].settingMode.mode置为目标状态.  要达到指定的目标状态，需要让result不等于OAM_NOERROR。
  这个函数头的宏定义中隐藏了iIODevice，用他对globalIODevTab进行索引可以同“终端”交互。
  进入这些函数的时候，终端被阻塞，不能输入，只有调用了OAM_ACK时才能给出提示符，继续接收用户的输入。所以可以在这些函数中
  适当的地方（通常是末尾）来调用OAM_ACK，当然，也可以让协议去调用。不过，终端阻塞5秒左右会超时，继续接收输入。
*/

//ip pim-sm enable
//no ip pim-sm enable
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_ip_pim_sm_enable)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_GLOBAL_ENABLE, iIODevice);
    }
    else
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_GLOBAL_ENABLE, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}
#if 0
//ip pim-sm enable
//no ip pim-sm enable
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_interface_ifnum_ip_pim)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_INTERFACE_ENABLE, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
        if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_INTERFACE_ENABLE, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
        if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}
#endif

//ip pim-sm rp-address A.B.C.D [A.B.C.D A.B.C.D]
//no ip pim-sm rp-address A.B.C.D [A.B.C.D A.B.C.D]
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_ip_pim_rp_address)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    VOS_IPV6_ADDR stGroupMask;
    VOS_IPV6_ADDR group_addr;
    VOS_IPV6_ADDR rp_addr;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        rp_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);
        if(pCmdBuf->count > 5)
        {
            group_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[5]);
            stGroupMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[6]);
        }
        else
        {
            memset(&group_addr, 0, sizeof(group_addr));
            memset(&stGroupMask, 0, sizeof(stGroupMask));
        }

        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_RP_ADDRESS, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.stRpAddress = rp_addr;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.group_addr = group_addr;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.stGroupMask = stGroupMask;
    }
    else
    {
        rp_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[3]);
        if(pCmdBuf->count > 4)
        {
            group_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);
            stGroupMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[5]);
        }
        else
        {
            memset(&group_addr, 0, sizeof(group_addr));
            memset(&stGroupMask, 0, sizeof(stGroupMask));
        }

        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_RP_ADDRESS, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.stRpAddress = rp_addr;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.group_addr = group_addr;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRp.stGroupMask = stGroupMask;
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm accept-register A.B.C.D A.B.C.D
//no ip pim-sm accept-register A.B.C.D A.B.C.D
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_ip_pim_accept_register)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stAcceptSource.stSourceAddr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stAcceptSource.stSourceMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[5]);
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_ACCEPT_REGISTER, iIODevice);
    }
    else
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stAcceptSource.stSourceAddr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[3]);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stAcceptSource.stSourceMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_ACCEPT_REGISTER, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm spt-threshold infinity
//no ip pim-sm spt-threshold
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_ip_pim_spt_threshold)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_SPT_THRESHOLD_INFINITY, iIODevice);
    }
    else
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SPT_THRESHOLD_INFINITY, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm dr-priority <1-65535>
//no ip pim-sm dr-priority
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_interface_ifnum_ip_pim_dr_priority)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    uint32_t dwPrValue;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_DR_PRIORITY, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
        if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        dwPrValue = *( (uint32_t *)(pCmdBuf->buf[3]) );
        if (dwPrValue < 1 || dwPrValue > 65535)
        {
            oam_OutputToDevice(iIODevice, "invalid pim dr-priority value(1, 65535)!\n");
            OAM_ACK;
            OAM_RETURN;
        }
        else
        {
            MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_DR_PRIORITY, iIODevice);
            stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
            if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
            {
                oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
                result = OAM_CMD_UPLEVEL;
                OAM_ACK;
                OAM_RETURN;
            }
            stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.dwPrValue = dwPrValue;
        }
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm hello-interval <1-65535>
//no ip pim-sm hello-interval
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_interface_ifnum_ip_pim_hello_interval)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    uint32_t dwSeconds;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_HELLO_INTERVAL, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
        if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        dwSeconds = *( (uint32_t *)(pCmdBuf->buf[3]) );
        if (dwSeconds < 1 || dwSeconds > 65535)
        {
            oam_OutputToDevice(iIODevice, "invalid pim hello-interval value(1, 65535)!\n");
            OAM_ACK;
            OAM_RETURN;
        }
        else
        {
            MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_HELLO_INTERVAL, iIODevice);
            stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
            if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
            {
                oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
                result = OAM_CMD_UPLEVEL;
                OAM_ACK;
                OAM_RETURN;
            }
            stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.dwSeconds = dwSeconds;
        }
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm join-prune-interval <1-65535>
//no ip pim-sm join-prune-interval
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_interface_ifnum_ip_pim_join_prune_interval)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    uint32_t dwSeconds;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_JOIN_PRUNE_INTERVAL, iIODevice);
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
        if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        dwSeconds = *( (uint32_t *)(pCmdBuf->buf[3]) );
        if (dwSeconds < 1 || dwSeconds > 65535)
        {
            oam_OutputToDevice(iIODevice, "invalid pim join-prune-interval value(1, 65535)!\n");
            OAM_ACK;
            OAM_RETURN;
        }
        else
        {
            MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_JOIN_PRUNE_INTERVAL, iIODevice);
            stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_CreateCfmHeadUnderInterfaceStatus(iIODevice);
            if(INTERFACE_DEFAULT_LOGICID == stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID)
            {
                oam_ArrangeStatusByMode (iIODevice);
                result = OAM_CMD_UPLEVEL;
                OAM_ACK;
                OAM_RETURN;
            }
            stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.dwSeconds = dwSeconds;
        }
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm c-bsr interface { Loopback <0-65534> | VLAN <1-4094> } priority <0-255>
//no ip pim-sm c-bsr
OAM_CMD_FUNC(oam_cmd_proc_enable_config_terminal_ip_pim_cbsr)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    CFM_HEAD stInterfaceType;
    OAM_RESULT;
    int iIfNum;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCbsr.iIfIndex = -1;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCbsr.dr_priority = 0;
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_BOOTSTRAP_ENABLE, iIODevice);
    }
    else
    {
        stInterfaceType = cfm_MatchInterfaceType (iIODevice , pCmdBuf, TRUE);
        iIfNum = stInterfaceType.iLogicID;
        if(iIfNum < 0)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            OAM_ACK;
            OAM_RETURN;
        }
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCbsr.iIfIndex = iIfNum;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCbsr.dr_priority = *( (uint32_t *)(pCmdBuf->buf[7]) );
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_BOOTSTRAP_ENABLE, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm c-rp interface { Loopback <0-65534> | VLAN <1-4094> } priority <0-255>
//no ip pim-sm c-rp
OAM_CMD_FUNC (oam_cmd_proc_enable_config_terminal_ip_pim_crp)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    CFM_HEAD stInterfaceType;
    OAM_RESULT;
    int iIfNum;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCrp.iIfIndex = -1;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCrp.dr_priority = 0;
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_BOOTSTRAP_CRP_ENABLE, iIODevice);
    }
    else
    {
        stInterfaceType = cfm_MatchInterfaceType (iIODevice , pCmdBuf, TRUE);
        iIfNum = stInterfaceType.iLogicID;
        if(iIfNum < 0)
        {
            oam_OutputToDevice(iIODevice, "The interface is not exist !\n");
            OAM_ACK;
            OAM_RETURN;
        }
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCrp.iIfIndex = iIfNum;
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stEnableCrp.dr_priority = *( (uint32_t *)(pCmdBuf->buf[7]) );
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_BOOTSTRAP_CRP_ENABLE, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm c-rp group-policy A.B.C.D A.B.C.D
//no ip pim-sm c-rp group-policy A.B.C.D A.B.C.D
OAM_CMD_FUNC(oam_cmd_proc_enable_config_terminal_ip_pim_crp_group_policy)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stCrpGroupPolicy.group_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[5]);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stCrpGroupPolicy.stGroupMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[6]);
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_NO_CRP_GROUP_POLICY, iIODevice);
    }
    else
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stCrpGroupPolicy.group_addr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);
        stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stCrpGroupPolicy.stGroupMask = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[5]);
        MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_CRP_GROUP_POLICY, iIODevice);
    }

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}


//show ip pim-sm bsr-info
OAM_CMD_FUNC (oam_cmd_proc_show_ip_pim_bsr)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_BOOTSTRAP, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//show ip pim-sm rp-info
OAM_CMD_FUNC (oam_cmd_proc_show_ip_pim_rp)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_BOOTSTRAP_RP, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//show ip pim-sm interface [VLAN <1-4094>]
OAM_CMD_FUNC ( oam_cmd_proc_show_ip_pim_interface)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (pCmdBuf->count > 4)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_MatchInterfaceType(iIODevice, pCmdBuf, OAM_CFM_USED);
        if(stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID == INTERFACE_DEFAULT_LOGICID)
        {
            oam_OutputToDevice (iIODevice,"% Invaild interface\n");
            oam_ArrangeStatusByMode (iIODevice);
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID = 0;
    }

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_INTERFACE, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_RETURN;
}

//show ip pim-sm neighbor [VLAN <1-4094>]
OAM_CMD_FUNC ( oam_cmd_proc_show_ip_pim_neighbor)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));
    if (pCmdBuf->count > 4)
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead = cfm_MatchInterfaceType(iIODevice, pCmdBuf, OAM_CFM_USED);
        if(stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID == INTERFACE_DEFAULT_LOGICID)
        {
            oam_OutputToDevice (iIODevice,"% Invaild interface\n");
            oam_ArrangeStatusByMode (iIODevice);
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
    }
    else
    {
        stCliMsgToPimsm.u_msg.mCliToPimsm.stCfmHead.iLogicID = 0;
    }

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_NEIGHBOR, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//show ip pim-sm topology
OAM_CMD_FUNC ( oam_cmd_proc_show_ip_pim_topology)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_TOPOLOGY, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//show ip pim-sm traffic
OAM_CMD_FUNC ( oam_cmd_proc_show_ip_pim_traffic)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_TRAFFIC, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//show ip pim-sm rpf A.B.C.D
OAM_CMD_FUNC ( oam_cmd_proc_show_ip_pim_rpf)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_SHOW_RPF_PREFIX, iIODevice);

    stCliMsgToPimsm.u_msg.mCliToPimsm.u_cmd.stRpfDestAddr = *(VOS_IPV6_ADDR *)(pCmdBuf->buf[4]);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//clear ip pim-sm counters
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_clear_ip_pim_counters)
{
    PIMSM_MSG_T stCliMsgToPimsm;
    OAM_RESULT;

    memset(&(stCliMsgToPimsm), 0, sizeof(PIMSM_MSG_T));

    MakeCliToPimsmMsg(&(stCliMsgToPimsm), CLI_CMD_PIMSM_CLEAR_COUNTERS, iIODevice);

#if 0//FIXME: will use socket
    vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPimsm), WAIT_FOREVER);
#endif
    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

//ip pim-sm ssm <uint16_t>
OAM_CMD_FUNC ( oam_cmd_proc_enable_config_terminal_ip_pim_ssm_acl)
{
    OAM_RESULT;
#if 0
    PIM_MSG        stCliMsgToPim;
    MLD_MSG         stCliMsgToMld;
    m_CliToPim6_t   *pstPimMsg = NULL;
    m_CliToMld_t    *pstMldMsg = NULL;
    uint32_t           dwPrValue;
    char            *pcName = NULL;
    uint16_t            wNameLen;
    char            aAclNameString[ACL_NAMEMAXLENTH];

    memset(&(stCliMsgToPim), 0, sizeof(PIM_MSG));
    memset(&(stCliMsgToMld), 0, sizeof(MLD_MSG));
    //如果是no命令:
    if (strcmp(pCmdBuf->buf[0], "no") == 0)
    {
        //no ip pim ssm
        //构造消息
        MakeCliToPimsmMsg(&(stCliMsgToPim), CLI_CMD_PIM_NO_SSM_ACCESS_GROUP, iIODevice);
        //MakeMldCliMsg(&(stCliMsgToMld), CLI_CMD_MLD_NO_IPV6_PIM_SSM_ACCESS_GROUP, iIODevice);
        //发送消息
#if 0//FIXME: will use socket
        vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPim), WAIT_FOREVER);
#endif
    }
    else
    {
        //ip pim ssm <access-list>
        pcName = ((char *)(pCmdBuf->buf[3]));
        wNameLen = strlen(pcName);
        //此处一定要保证输入的acl名字不能超过79，因为如果是80的话就没有空间存储结束符'/0'了
        if(wNameLen > (ACL_NAMEMAXLENTH - 1))
        {
            oam_OutputToDevice(iIODevice, "invalid access-list-name lenth(1,79)!\n");

            oam_ArrangeStatusByMode (iIODevice);
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
        memset(aAclNameString, 0, ACL_NAMEMAXLENTH);
        strcpy(aAclNameString ,pcName);
        if(aAclNameString[0] == '\0')
        {
            oam_OutputToDevice(iIODevice, "invalid access-list-name!\n");

            oam_ArrangeStatusByMode (iIODevice);
            result = OAM_CMD_UPLEVEL;
            OAM_ACK;
            OAM_RETURN;
        }
        else
        {
            MakeCliToPimsmMsg(&(stCliMsgToPim), CLI_CMD_PIM_SSM_ACCESS_GROUP, iIODevice);
            pstPimMsg = &(stCliMsgToPim.u_msg.mCliToPim6);
            pstMldMsg = &(stCliMsgToMld.u_msg.mCliToMld);
            strcpy(pstPimMsg->ucmd.stAccessGroup.acAclNameString, aAclNameString);
            strcpy(pstMldMsg->ucmd.stAccessGroup.aAclNameString, aAclNameString);
            //发送消息
#if 0//FIXME: will use socket
            vos_MsgPost(TASK_ID_PIMSM, (char *)&(stCliMsgToPim), WAIT_FOREVER);
#endif
        }
    }
#endif

    oam_ArrangeStatusByMode (iIODevice);
    result = OAM_CMD_UPLEVEL;
    OAM_ACK;
    OAM_RETURN;
}

#endif
