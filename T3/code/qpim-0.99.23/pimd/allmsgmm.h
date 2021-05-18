#ifndef __ALLMSGMM_H
#define __ALLMSGMM_H


/********************************************************************
*																	*
*							vos										*
*																	*
********************************************************************/
#define mm_Timeout_VOStoALL						0x0001
#define mmAliveCheck_MONtoALL						0x0002
#define mmSelfCheckError_ALLtoMON					0x0003
#define mmVOSIPCBulkMessage							0x0004	 //对消息类型，增加这个宏定义
#define mmVOSIPChelloMessage						0x0005	 //对消息类型，增加这个宏定义
#define mmVosBusAddrTell							0x0006
#define mmVosBusNodeTell							0x0007
#define mmVOSIPCFragMessage							0x0008	 //对消息类型，增加这个宏定义
#define mmVOSIPCClockSet							0x0009
#define mmVOSIPCResetSlave							0x000a //复位从板
#define mmGetSg										0x000b
#define mmUpdateMrt									0x000c
#define mmGetRpf									0x000d

/********************************************************************
*																	*
*		configuration msg between PROTOCOL and CFM					*
*		reserved from 0x00c0 to 0x00df								*
*																	*
********************************************************************/
#define	mmCfmMsgBegin					    	0x00c0

//所有从CFM传递到NICTL的消息（从CLI到CFM主板到CFM从板到NICTL方向）
#define mm_NICommand_CFMtoNICTL                                 (mmCfmMsgBegin + 1)
//所有从NICTL传递到CFM的消息（从NICTL到从板CFM到主板CFM到CLI方向）
#define mm_NICommandResponse_NICTLtoCFM                         (mmCfmMsgBegin + 2)
//从板到主板间的大块数据
#define mm_BigMsg_NICTLtoCFM                                    (mmCfmMsgBegin + 3)
//CFM发送到CLI的是否进入SETUP模式消息
#define mm_CfgDataResponse_CFMtoCLI                             (mmCfmMsgBegin + 4)
//show running-config消息类型
#define mm_ShowRunConfig_CLItoCFM			        (mmCfmMsgBegin + 5)
//show startup-config消息类型
#define	mm_ShowStartConfig_CLItoCFM				(mmCfmMsgBegin + 6)
//CFM发送给高层协议的端口配置改变消息
#define mm_CfgLogicIntf_CFMtoALL                                (mmCfmMsgBegin + 7)
#define mmCfgLogicIntf						(mm_CfgLogicIntf_CFMtoALL)
//CFM向高层协议要配置数据
#define mm_RequestRunningData_CFMtoALL                          (mmCfmMsgBegin + 8)
//高层协议给CFM回应的配置数据
#define mm_RunningDataResponse_ALLtoCFM                         (mmCfmMsgBegin + 9)
//WRITE MEMORY OR WRITE EREASE CMD
#define mm_WriteCmd_CLItoCFM                                    (mmCfmMsgBegin + 10)
#define mm_ConfigCmd_CLItoCFM                                    (mmCfmMsgBegin + 14)
#define mm_RebootCmd_CLItoCFM                                    (mmCfmMsgBegin + 15)
//从VOS申请一个延时时钟
#define mm_SetDelayTime_CFMtoVOS                                (mmCfmMsgBegin + 11)
#define mm_SetDelayTime_CFMtoVOS_NoAck                                (mmCfmMsgBegin + 11 + 0x8000)

//OAM通知CFM从板插拔
#define mm_NotifySlotStatus_OAMtoCFM                            (mmCfmMsgBegin + 12)
//CFM通知IPF插拔
#define mm_NotifySlotStatus_CFMtoIPF                            (mmCfmMsgBegin + 13)
#define mm_NotifySlotStatus_CFMtoALL                            (mmCfmMsgBegin + 13)
//收到NICLL的对get table消息的返回
#define mmGetTableResponse                                      (mmCfmMsgBegin + 16)

//收到表变量的回应
#define mm_GetTableResponse_NICTLtoCFM   			(mmCfmMsgBegin + 17)

//NI在全局配置模式下的配置命令消息, 消息结构用mNICommand_CFMtoNICTL
#define mm_NIGlobalConfig_CFMtoNICTL  		  	        (mmCfmMsgBegin + 18)

//NI在全局配置模式下的配置给CFM的回应, 消息结构用mNIGlobalConfig_NICTLtoCFM
#define mm_NIGlobalConfigResponse_NICTLtoCFM			(mmCfmMsgBegin + 19)

//NI在全局配置模式下的配置，NICTL让CFM分发, 消息结构用mNICommand_CFMtoNICTL
#define mm_NIGlobalConfigDistribute_NICTLtoCFM			mm_NICommand_CFMtoNICTL
#define mm_NIGlobalConfigDistribute_NICTLtoNICTL		(mmCfmMsgBegin + 20)

//NI在普通模式下全局相关的显示命令消息，消息结构用mNICommand_CFMtoNICTL
#define mm_NIGlobalShow_CFMtoNICTL							(mmCfmMsgBegin + 40)

//NI在普通模式下全局相关的显示给CFM的回应，消息结构用mNICommandResponse_NICTLtoCFM
#define mm_NIGlobalShowResponse_NICTLtoCFM					(mmCfmMsgBegin + 21)

//NI在普通模式下的显示结果给CFM的回应并且分发, 消息结构用mNICommandResponse_NICTLtoCFM
#define mm_NIGlobalShowDistribute_NICTLtoCFM				mm_NICommandShow_CFMtoNICTL

//NI在全局配置模式下的配置，NICTL让CFM分发, 消息结构用mNICommand_CFMtoNICTL
#define mm_NIGlobalConfigDistribute_NICTLtoCFM			mm_NICommand_CFMtoNICTL

#define mm_TerminalCommonCommand				            (mmCfmMsgBegin + 22)

// 链路帧接收消息
#define mm_LinkFrameReceive_NItoNICTL                       (mmCfmMsgBegin + 24)
#define mm_IsrMessage_NItoNICTL                             (mmCfmMsgBegin + 25)
#define mm_FailedCommand_CLItoCFM                           (mmCfmMsgBegin + 26)
#define mm_ShowRunIndication_ALLtoCFM					(mmCfmMsgBegin + 27)
#define mm_TerminalCommonCommandComplete		            (mmCfmMsgBegin + 28)

/*CLI to CFM for configuring ACL add by caizhihong 04-11-4*/
#define mm_ACLCommand_CLItoCFM							(mmCfmMsgBegin + 29)
#define mm_ACLUpdate_CFMtoCFMC							(mmCfmMsgBegin + 30)

//NI在普通模式下的接口相关显示命令消息，消息结构用mNICommand_CFMtoNICTL
#define mm_NICommandShow_CFMtoNICTL                                 (mmCfmMsgBegin + 31)

//NI在普通模式下的接口相关显示命令给CFM的回应，消息结构用mBigMsg_NICTLtoCFM
#define mm_NICommandShowResponse_NICTLtoCFM                         (mmCfmMsgBegin + 32)

#ifdef BWOS_INCLUDE_SWITCH
#define mm_SwitchEventMessage_NItoNICTL                         (mmCfmMsgBegin + 33)
#define mm_SwitchShowResponse_NICTLtoCFM						(mmCfmMsgBegin + 34)
#endif

#define mmInterfRangeCmd_CLItoCFM (mmCfmMsgBegin + 35)
//copy tftp to/from flash
#define mm_CopyCmd_CLItoCFM                                 (mmCfmMsgBegin + 36)
#define mm_AclCliMsgCliToCFM								(mmCfmMsgBegin + 37)
#define mm_AclCliMsgCliToCFM_cxe 							(mmCfmMsgBegin + 38)
#define mmFilterObjectUpdate_CFMtoALL          mmFilterObjectUpdate_CFMtoBGP
#define mmFilterObjectDelete_CFMtoALL     	mmFilterObjectDelete_CFMtoBGP
#define mmFilterObjectDeleteALL_CFMtoALL     	(mmCfmMsgBegin + 39)
#define mmRegisterFilterObject_ALLtoCFM				mmRegisterFilterObject_BGPtoCFM
#define mm_aclMsg_Reg_ACLtoQOS		(mmCfmMsgBegin + 41)
#define mm_qosMsg_Conf_QOStoACL		(mmCfmMsgBegin + 42)

//get link-local address output interface(outif)
#define mm_LinkLocalOutif_CLItoCFM		(mmCfmMsgBegin + 50)

/********************************************************************
*																	*
*			command message between PROCOTOL and CLI				*
*			reserved from 0x0100 to 0x017f																	*
********************************************************************/
/*rtmgt*/
#define mmCliCmdHeader							0x0100
#define mm_Cmd_CLItoRTMGT						mmCliCmdHeader + 1
#define mm_CmdResponse_RTMGTtoCLI				mmCliCmdHeader + 2


/* ospf */
#define mmReceiveMessage_CLItoOSPF				mmCliCmdHeader + 3
#define mm_SendMessage_CLItoOSPF				mmCliCmdHeader + 3
#define mmSendMessage_OSPFtoCLI					mmCliCmdHeader + 4
#define mm_ReceiveMessage_OSPFtoCLI				mmCliCmdHeader + 4
/*rip*/
#define mm_RIPtoCLI						mmCliCmdHeader + 5
#define mm_CLItoRIP						mmCliCmdHeader + 5
/*bgp*/
#define mmCliCommand_CLItoBGP					mmCliCmdHeader + 7
#define mmCliCommandRsp_BGPtoCLI				mmCliCmdHeader + 8

/*fr reserved*/
#define mmCMD_CLItoFR							mmCliCmdHeader + 9

/*tcp udp*/
#define mm_Cmd_CLItoTCP							mmCliCmdHeader + 11
#define mm_Cmd_CLItoUDP							mmCliCmdHeader + 12
#define mm_Cmd_TCPtoCLI							mmCliCmdHeader + 13
#define mm_Cmd_UDPtoCLI							mmCliCmdHeader + 14

/* ipf */
#define mm_Cmd_CLItoIP							mmCliCmdHeader + 15
#define mm_Cmd_IPtoCLI							mmCliCmdHeader + 16

/*snmp*/
#define mm_Cmd_CLItoSNMP						mmCliCmdHeader + 17

/*cfm*/
#define mmCfgNI_CLItoNI							mmCliCmdHeader + 19
#define mmCfgGlobal_CLItoCFM					mmCliCmdHeader + 21
#define mmWriteFlash_CLItoCFM					mmCliCmdHeader + 23

/*ipsec*/
#define mm_SendMsg_CLItoIPSEC					mmCliCmdHeader + 24
#define mm_SendMsg_IPSECtoCLI					mmCliCmdHeader + 25

/*dhcp*/
#define mm_ReceiveMessage_DHCPtoCLI				mmCliCmdHeader + 26
#define mm_Cmd_CLItoDHCP						mmCliCmdHeader + 27
#define mmReQuestIpAddrPPPtoDHCP             mmCliCmdHeader + 28

/*mon*/
#define mm_Cmd_CLItoMON						mmCliCmdHeader + 29
#define mm_CmdResponse_MONtoCLI					mmCliCmdHeader + 30

/*ike*/
#define	mm_SendMsg_CLItoIKE					mmCliCmdHeader + 31
#define	mm_SendMsg_IKEtoCLI					mmCliCmdHeader + 32

/*telnet*/
#define mm_Cmd_TELNETtoCLI					mmCliCmdHeader + 33

/*pim	*/
#define mm_Cmd_CLItoPIM						mmCliCmdHeader + 34
#define mm_Cmd_PIMtoCLI						mmCliCmdHeader + 35

/*mrtmgt*/
#define mm_Cmd_CLItoMRTMGT					mmCliCmdHeader + 36



/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ce1 yxq 9.21 */
#define mmLoopBack_CLItoCE1					mmCliCmdHeader + 34
#define mmDescription_CLItoCE1				mmCliCmdHeader + 35
#define mmFraming_CLItoCE1					mmCliCmdHeader + 36
#define mmLineCode_CLItoCE1					mmCliCmdHeader + 37
#define mmClockSource_CLItoCE1				mmCliCmdHeader + 38
#define mmCfgNI_CLItoCFM					mmCliCmdHeader + 39
#define mmCreateBindingChannel_CLItoCE1		mmCliCmdHeader + 40
#define mmCreateTimer_E1toVos				mmCliCmdHeader + 41
#define mmResetTimer_E1toVos				mmCliCmdHeader + 42
#define mmCardActiveLedOffTimer_E1toVos		mmCliCmdHeader + 43

#define mmLoopBack_CLItoPOS					mmCliCmdHeader + 44
#define mmCRCMode_CLItoPOS				    mmCliCmdHeader + 45
#define mmFraming_CLItoPOS					mmCliCmdHeader + 46
#define mmClockSource_CLItoPOS				mmCliCmdHeader + 47
#define mmScramble_CLItoPOS				    mmCliCmdHeader + 48
#define mmAisShut_CLItoPOS					mmCliCmdHeader + 49
#define mmPosFlag_CLItoPOS					mmCliCmdHeader + 50
#define mmPosReport_CLItoPOS				mmCliCmdHeader + 51
/*ospf6*/
#define mm_RoutingInfo_Ospf6ToRtm			mmCliCmdHeader + 52
#define mmCommandClitoVty					mmCliCmdHeader + 53

/*added by dingqiang*/
#define mm_Cmd_RAWtoCLI				mmCliCmdHeader + 54
#define mm_Cmd_CLItoRAW				mmCliCmdHeader + 55

#define mm_Cmd_UDPV6toCLI				mmCliCmdHeader + 56
#define mm_Cmd_CLItoUDPV6				mmCliCmdHeader + 57

/*telnetd, add by caizhihong 04-12-13*/
#define mm_Cmd_TELNETDtoCLI			mmCliCmdHeader + 58

#define mm_Cmd_IGMPtoCLI				        mmCliCmdHeader + 59
#define mm_Cmd_CLItoIGMP                     mmCliCmdHeader + 60
#define mm_Cmd_CLItoMLD                     mmCliCmdHeader + 61
//#define mm_Cmd_PIMtoCLI				    mmCliCmdHeader + 61
//#define mm_Cmd_CLItoPIM                    mmCliCmdHeader + 62

typedef enum CLI_MSG_TYPE
{
    mmOpen_TerminaltoShell = mmCliCmdHeader + 63,
    mmClose_TerminaltoShell,
    mmMultiScreenPrint_OthertoShell,
    mmMultiScreenPrintEnd_OutputtoShell,
    mmMultiScreenPrintAbort_OutputtoShell,
    mmACK_OthertoShell,
    mmCharFlow_TerminaltoShell,
    mmAbort_ShelltoOther,
    mmReturnMsg_ShelltoOther,
    mmCmdFinished_ShelltoTerminal,
    mmCmdFinished_ShelltoOutput,
    mmCmdFinished_TerminaltoOther,
    mmOpen_OthertoTerminal,
    mmClose_OthertoTerminal,
    mmInputRedirect_OthertoTerminal,
    mmDataIN_TerminalServicetoTerminal,
    mmOpen_TerminaltoOutput,
    mmClose_TerminaltoOutput,
    mmNextLine_ShelltoOutput,
    mmNextPage_ShelltoOutput,
    mmAbortMore_ShelltoOutput,
    mmMultiScreenPrint_ShelltoOutput,
    mmTerminalLen_ShelltoTerminal,
    mmTerminalWidth_ShelltoTerminal,
    mmTerminalScreenAttrChanged_TerminaltoOther,
    mmGetString_OthertoShell,
    mmGetString_ShelltoOther,
    mmRedirectData_TerminaltoOther,
    mmOutputData_TerminaltoOther,
    mmCommonData_TerminaltoOther,
    mmInputRedirect_TerminaltoShell,
    mmNotify_cli_telnet_jam  //add by wanghao
} CLI_MSG_TYPE;

/********************************************************************
*																	*
*							rtmgt									*
*			reserved from 0x0180 to 0x01af							*
*																	*
********************************************************************/
#define mmRtmgtMsgHeader							0x0180
#define mmRequestCfgData_RTMGTtoCFM					mmRequestCfgData
#define mmRequestCfgDataResponse_CFMtoRTMGT			mmRequestCfgDataResponse
#define mmRequestRunningData_CFMtoRTMGT				mm_RequestRunningData_CFMtoALL
#define mmRequestRunningDataResponse_RTMGTtoCFM		mm_RunningDataResponse_ALLtoCFM
#define mmCfgLogicIntf_CFMtoRTMGT					mmCfgLogicIntf
#define mmCfgLogicIntfResponse_RTMGTtoCFM			mmCfgLogicIntf

#define mmUpdateRoute_RIPtoRTMGT					mmRtmgtMsgHeader + 1
#define mmUpdateRoute_OSPFtoRTMGT					mmRtmgtMsgHeader + 2
#define mmUpdateRoute_BGPtoRTMGT					mmRtmgtMsgHeader + 3

#define mmRedistributeRoute_RTMGTtoRIP				mmRtmgtMsgHeader + 4
#define mmRedistributeRoute_RTMGTtoOSPF				mmRtmgtMsgHeader + 5
#define mmRedistributeRoute_RTMGTtoBGP				mmRtmgtMsgHeader + 6


#define mmRegisterFilterObject_RTMGTtoCFM			mmRtmgtMsgHeader + 7

/*
#define mmFilterObjectDelete_CFMtoRTMGT				mmRtmgtMsgHeader + 8
#define mmFilterObjectUpdate_CFMtoRTMGT				mmRtmgtMsgHeader + 9
*/

#define mmFilterObjectUpdate_CFMtoRTMGT     mmFilterObjectUpdate_CFMtoBGP
#define mmFilterObjectDelete_CFMtoRTMGT     mmFilterObjectDelete_CFMtoBGP

#define mm_GetLogicIfNo_TcpToRtmgt					mmRtmgtMsgHeader + 10
#define mm_GetLogicIfNo_RtmgtToTcp					mmRtmgtMsgHeader + 11

#define mmOSPFRedistributionInd_RTMGTtoOSPF			mmRtmgtMsgHeader + 12
#define mmRedistributionInd_RTMGTtoALL				mmOSPFRedistributionInd_RTMGTtoOSPF
#define mmStaticRouteCheckSchedule_RTMGTtoRTMGT		mmRtmgtMsgHeader + 13

#define mmNoRouter_CLItoRTMGT						mmRtmgtMsgHeader + 14
// multi update route msg
#define mmUpdateMultiRoute_RIPtoRTMGT					mmRtmgtMsgHeader + 15
#define mmUpdateMultiRoute_OSPFtoRTMGT					mmRtmgtMsgHeader + 16
#define mmUpdateMultiRoute_BGPtoRTMGT					mmRtmgtMsgHeader + 17

#define mmUpdateRoute_AlltoRTMGT  						mmRtmgtMsgHeader + 18
#define mmRpfRegister_PimToMrtmgt						mmRtmgtMsgHeader + 19

/********************************************************************
*																	*
*							ospf									*
*			reserved from 0x01b0 to 0x01df							*
*																	*
********************************************************************/
/*Defined for CFM*/
#define mmOspfMsgHeader								0x01b0
#define mmRequestCfgData_OSPFtoCFM					mmRequestCfgData
#define mmCfgDataResponse_CFMtoOSPF					mmRequestCfgDataResponse
#define mmRequestRunningData_CFMtoOSPF				mm_RequestRunningData_CFMtoALL
#define mmRunningDataResponse_OSPFtoCFM				mm_RunningDataResponse_ALLtoCFM

#define mmCfgLogicIntf_CFMtoOSPF					mmCfgLogicIntf
#define mmCfgLogicIntfReponse_OSPFtoCFM				mmCfgLogicIntf

/*		Defined for	IPF*/
#define	mmReceivePkt_IPtoOSPF						mm_Pkt_IPtoOSPF
#define	mmSendPkt_OSPFtoIP							mm_Pkt_TRANStoIP
/*		Defined for Inside Event*/
#define mmIntraMsg_ALLtoOSPF						mmOspfMsgHeader+2

/********************************************************************
*																	*
*							rip										*
*				reserved from 0x01e0 to 0x01ff						*
*																	*
********************************************************************/


/********************************************************************
*																	*
*							bgp										*
*				reserved from 0x0200 to 0x024f						*
*																	*
********************************************************************/
#define mmBgpMsgHeader								0x0200
#define mmTimerOut_TMRtoBGP 						mm_Timeout_VOStoALL
#define mmActiveCheck_MONtoBGP						mmBgpMsgHeader + 2

#define mmRouteMonitorResponse_RTMGTtoBGP			mmBgpMsgHeader + 50
#define mmIpMonitorResponse_RTMGTtoBGP				mmBgpMsgHeader + 51
#define mmUpdateRoute_RTMGTtoBGP					mmBgpMsgHeader + 52
#define mmIpReachableInfo_RTMGTtoBGP				mmBgpMsgHeader + 53

#define mmFilterObjectDelete_CFMtoBGP				mmBgpMsgHeader + 60
#define mmFilterObjectUpdate_CFMtoBGP				mmBgpMsgHeader + 61
#define mmRequestRunningData_CFMtoBGP				mm_RequestRunningData_CFMtoALL
#define mmCfgDataResponse_CFMtoBGP					mmRequestCfgDataResponse
#define mmInterfaceIpResponse_CFMtoBGP				mmBgpMsgHeader + 64
#define mmRouterIDResponse_CFMtoBGP					mmBgpMsgHeader + 65


/*  BGP ==> Route management   */
#define mmRegistRouteMonitor_BGPtoRTMGT				mmBgpMsgHeader + 10
#define mmRegistIpMonitor_BGPtoRTMGT				mmBgpMsgHeader + 11
#define mmCheckRoutingInfo_BGPtoRTM					mmBgpMsgHeader + 12
#define mmRegisterIpReachable_BGPtoRTMGT			mmBgpMsgHeader + 13

/*  BGP ==> Config management   */
#define mmRegisterFilterObject_BGPtoCFM				mmBgpMsgHeader + 60
#define mmRequestCfgData_BGPtoCFM					mmRequestCfgData
#define mmRunningDataResponse_BGPtoCFM				mm_RunningDataResponse_ALLtoCFM
#define mmInquireInterfaceIp_BGPtoCFM				mmBgpMsgHeader + 63
#define mmInquireRouterID_BGPtoCFM					mmBgpMsgHeader + 64
#define mmCommandResponse_BGPtoCLI				mmBgpMsgHeader + 65

#define mmGetSimpleVarible_BGPtoSNMP  				mmGetSimpleVarible
#define mmSetSimpleVarible_BGPtoSNMP  				mmSetSimpleVarible
#define mmGetTableField_BGPtoSNMP     				mmGetTableField
#define mmSetTableField_BGPtoSNMP     				mmSetTableField
#define mmGetTable_BGPtoSNMP      					mmGetTable
/********************************************************************
*																	*
*							fr										*
*				reserved from 0x0250 to 0x026f						*
*																	*
********************************************************************/
#define		mmRequestConfigData_FRtoCFM				mmRequestCfgData
#define		mmConfigDataResponse_CFMtoFR			mmRequestCfgDataResponse
#define		mmRequestRunningData_CFMtoFR			mm_RequestRunningData_CFMtoALL
#define		mmRunningDataResponse_FRtoCFM			mm_RunningDataResponse_ALLtoCFM

/********************************************************************
*																	*
*						telnetd telnet								*
*				reserved from 0x0270 to 0x027f						*
*																	*
********************************************************************/
#define mm_Telnetd_Msg_Header						0x0270

#define mmRequestCfgData_TelnetDtoCFM				mmRequestCfgData
#define mmRequestCfgDataResponse_CFMtoTelnetD		mmRequestCfgDataResponse
#define mmRequestRunningData_CFMtoTelnetD			mmRequestRunningData
#define mmRequestRunningDataResponse_TelnetDtoCFM 	mmRequestRunningDataResponse
#define mmCfgLogicIntf_CFMtoTelnetD					mmCfgLogicIntf
#define mmCfgLogicIntfResponse_TelnetDtoCFM			mmCfgLogicIntfResponse


#define mm_MsgFromOamToTelnetd						mm_Telnetd_Msg_Header + 1
#define mm_MsgFromTelnetdToOam						mm_MsgFromOamToTelnetd
#define mm_ConnCtrl_CLItoTELNET						mm_Telnetd_Msg_Header + 2
#define mm_ConnCtrl_CLItoTELNETD						mm_ConnCtrl_CLItoTELNET
#define mm_ConnState_TELNETtoCLI					mm_Telnetd_Msg_Header + 3
#define mm_ConnCtrl_TELNETDtoCLI						mm_ConnState_TELNETtoCLI
#define	mm_UserData_CLItoTELNET						mm_Telnetd_Msg_Header + 4
#define mm_ConnCtrl_TELNETtoADC						mm_Telnetd_Msg_Header + 5
#define mm_ConnState_ADCtoTELNET					mm_Telnetd_Msg_Header + 6
#define mm_ReverseData_ADCtoTELNET					mm_Telnetd_Msg_Header + 7
#define mm_ReverseData_TELNETtoADC					mm_ReverseData_ADCtoTELNET
#define mm_ConnCtrl_TELNETDtoTELNET					mm_Telnetd_Msg_Header + 8
#define mm_Connect_TELNETDtoAAA					mm_Telnetd_Msg_Header + 9
#define mm_ServerConfig_CLItoTELNETD					mm_Telnetd_Msg_Header + 10
#define mm_MaxUsrNumCfg_CLItoTELNETD					mm_Telnetd_Msg_Header + 11

/********************************************************************
*																	*
*							tcp udp									*
*				reserved from 0x0280 to 0x029f						*
*																	*
********************************************************************/
#define mm_TcpUdpMsgHeader								0x0280

#define mmRequestCfgData_TCPtoCFM				mmRequestCfgData
#define mmCfgDataResponse_CFMtoTCP				mmRequestCfgDataResponse
#define mmRequestRunningData_CFMtoTCP			mmRequestRunningData
#define mmRunningResponse_TCPtoCFM				mmRequestRunningDataResponse

#define mm_PortInAccessible_TCPtoIPF			mm_TcpUdpMsgHeader + 1
#define mm_PortInAccessible_UDPtoIPF			mm_TcpUdpMsgHeader + 2
#define mm_Pkt_TCPtoIP							mm_TcpUdpMsgHeader + 3
#define mm_TcpMessageApiReq_APPtoTCP			mm_TcpUdpMsgHeader + 4
#define mm_TcpFunctionApiReq_APPtoTCP			mm_TcpUdpMsgHeader + 5
#define mm_TcpApiRes_TCPtoAPP					mm_TcpUdpMsgHeader + 6
#define mm_ReadWriteReady_TCPtoAPP				mm_TcpUdpMsgHeader + 7
#define mm_PortInAccessible_UDPV6toIPF			mm_TcpUdpMsgHeader + 8


//add by caizhihong 04-7-14
#define mm_V6PortInAccessible_TCPtoIPF			mm_TcpUdpMsgHeader + 8
#define mm_GetSrcV6Addr_TCPtoIPF				mm_TcpUdpMsgHeader + 9
#define mm_Pkt_IPV6toTCP						mm_TcpUdpMsgHeader + 10

/********************************************************************
*																	*
*							ipf										*
*				reserved from 0x02a0 to 0x02ff						*
*																	*
********************************************************************/
#define mm_MsgType_Ipf_Header						0x02a0

#define mm_Pkt_IPtoUDP								mm_MsgType_Ipf_Header + 1
#define mm_Pkt_TRANStoIP							mm_MsgType_Ipf_Header + 2
#define mm_Pkt_IPtoTCP								mm_MsgType_Ipf_Header + 3
#define mm_Pkt_IPtoOSPF								mm_MsgType_Ipf_Header + 4

#define mm_GetSrcAdd_TRANStoIP						mm_MsgType_Ipf_Header + 5
#define mm_GetMtu_TRANStoIP							mm_MsgType_Ipf_Header + 6


#define mm_Pkt_IPtoNI								mm_MsgType_Ipf_Header + 7
#define mm_Pkt_NItoIP								mm_MsgType_Ipf_Header + 8

/* msg type added for zhu jiang */
#define mmFwTabEntryAdd_RTMGTtoIPF					mm_MsgType_Ipf_Header + 9
#define mmFwTabEntryDel_RTMGTtoIPF					mm_MsgType_Ipf_Header + 10
#define mmFwTabEntryNewDel_RTMGTtoIPF				mm_MsgType_Ipf_Header + 11
#define mmFwTabEntryNewAdd_RTMGTtoIPF				mm_MsgType_Ipf_Header + 12
#define mmFwTabEntryUpdate_IPFtoIPF					mm_MsgType_Ipf_Header + 13

#define mmAddNode_CFMtoIPF							mm_MsgType_Ipf_Header + 14

#define mmAclUpdate_IPFtoIPF						mm_MsgType_Ipf_Header + 16
#define mmNatUpdate_IPFtoIPF                        mm_MsgType_Ipf_Header + 17

#define	mm_PrintPing_IPFtoCLI						mm_MsgType_Ipf_Header + 20
#define	mm_PrintTraceRoute_IPFtoCLI					mm_MsgType_Ipf_Header + 21

#define mm_GetLogicIftabEntry_TRANStoIP				mm_MsgType_Ipf_Header + 22

#define	mmRequestCfgData_IPFtoCFM					mmRequestCfgData
#define	mmCfgDataResponse_CFMtoIPF					mmRequestCfgDataResponse
#define	mmRequestRunningData_CFMtoIPF				mmRequestRunningData
#define	mmRunningDataResponse_IPFtoCFM				mmRequestRunningDataResponse
#define	mmCfgLogicIntf_CFMtoIPF						mmCfgLogicIntf
#define	mmCfgLogicIntfResponse_IPFtoCFM				mmCfgLogicIntfResponse

#define mmAddLogicInterf_CFMtoIPF					mm_MsgType_Ipf_Header + 23
#define mmDelLogicInterf_CFMtoIPF					mm_MsgType_Ipf_Header + 24
#define mmChangeLogicInterfStatus_CFMtoIPF			mm_MsgType_Ipf_Header + 25
#define mmChangeLogicInterfMtu_IPFtoCFM				mm_MsgType_Ipf_Header + 26
#define mmChangeLogicInterfIpAdd_IPFtoCFM			mm_MsgType_Ipf_Header + 27

#define mmChangeLogicInterfMru_IPFtoCFM				mm_MsgType_Ipf_Header + 28
#define mmChangeLogicInterfPassive_IPFtoCFM			mm_MsgType_Ipf_Header + 29
#define mmChangeLogicInterfRedirect_IPFtoCFM		mm_MsgType_Ipf_Header + 30
#define mmChangeLogicInterfSourceRoute_IPFtoCFM		mm_MsgType_Ipf_Header + 31
#define mmChangeLogicInterfUnreachable_IPFtoCFM		mm_MsgType_Ipf_Header + 32
#define mmChangeLogicInterfAcl_IPFtoCFM				mm_MsgType_Ipf_Header + 33
#define mmChangeLogicInterfNat_IPFtoCFM				mm_MsgType_Ipf_Header + 34
#define mm_PingResponse_IPFtoDHCP 					mm_MsgType_Ipf_Header + 35
#define mm_RequestPing_DHCPtoIPF					mm_MsgType_Ipf_Header + 36
#define mmChangeLogicInterfWFQ_IPFtoCFM				mm_MsgType_Ipf_Header + 37
#define mmChangeLogicInterfRouteMap_IPFtoCFM		mm_MsgType_Ipf_Header + 38
#define mmChangeLogicInterfPolicyMap_IPFtoCFM		mm_MsgType_Ipf_Header + 39
#define mm_MsgType_Ipf_Test							mm_MsgType_Ipf_Header + 50
#define mmRegisterFilterObject_IPFtoCFM				mm_MsgType_Ipf_Header + 51
#define mmRegisterPkt_IPFtoPIMSM					mm_MsgType_Ipf_Header + 52
#define mmMrtEntrySetFlag_IPFtoPIMSM  				mm_MsgType_Ipf_Header + 53
#define mmMrtEntryDel_IPFtoPIMSM					mm_MsgType_Ipf_Header + 54
#define mmAssertInfom_IPFtoPIMSM					mm_MsgType_Ipf_Header + 55
#define mmMrtEntryUpdate_IPFtoMRTMGT					mm_MsgType_Ipf_Header + 56

#define mmProtocolPkt_IpfToPimsm					mm_MsgType_Ipf_Header + 57
//add by wuyan 2018.08.02
#define mmProtocolPkt_IpfToIgmp						mmProtocolPkt_IpfToPimsm
//added end by wuyan
#define mm_Pkt_IPtoPIMDM							mmProtocolPkt_IpfToPimsm
#define mm_WholePktTransToIp						mm_MsgType_Ipf_Header + 58
/*added by cwl for ipv6 20040404*/

//add by wuyan for pim-sm in 2017-12-04
#define mmMulticastData_IpfToPimsm						mm_MsgType_Ipf_Header + 59
//add end

#define mmFwTab_Ipv6Add_RTMGTtoIPF                mm_MsgType_Ipf_Header + 60
#define mmFwTab_Ipv6Del_RTMGTtoIPF                mm_MsgType_Ipf_Header + 61
#define mmFwTabEntryUpdate_IPV6_IPFtoIPF					mm_MsgType_Ipf_Header + 62
#define	mm_PrintPingIpv6_IPFtoCLI						mm_MsgType_Ipf_Header + 63
#define mm_PrintTraceRouteIpv6_IPFtoCLI                mm_MsgType_Ipf_Header + 64

#define mm_RawSocketIpv6_RAWtoIPF                mm_MsgType_Ipf_Header + 65
#define mm_Pkt_IPtoRAWSOCKET                     mm_MsgType_Ipf_Header + 66
//add by caizhihong 04-7-20
#define mm_SendSrcV6Addr_IPFtoTCP				mm_MsgType_Ipf_Header + 67
/*cwl_notice : care of the value of macro for v6*/
/*end added by cwl for ipv6 20040404*/

#define mm_UdpSocketIpv6_UDPtoIPF            mm_MsgType_Ipf_Header + 67
#define mm_Pkt_IPtoUDPv6                     mm_MsgType_Ipf_Header + 68
#define mm_SendSkb_NATPTtoIPF                mm_MsgType_Ipf_Header + 69
#define mm_Tcam_IPFtoIPF                    mm_MsgType_Ipf_Header + 70
/*Add by cwl, 2004.12.2*/

#define mmMultiFwTabEntryUpdate_RTMGTtoIPF   mm_MsgType_Ipf_Header + 71

/********************************************************************
*																	*
*							SNMP									*
*				reserved from 0x0300 to 0x031f						*
*																	*
********************************************************************/
#define mmRequestCfgData_SNMPtoCFM				mmRequestCfgData
#define mmCfgDataResponse_CFMtoSNMP				mmRequestCfgDataResponse
#define mmRequestRunningData_CFMtoSNMP			mmRequestRunningData
#define mmRunningResponse_SNMPtoCFM				mmRequestRunningDataResponse

/********************************************************************
*																	*
*							cli										*
*				reserved from 0x0320 to 0x033f						*
*																	*
********************************************************************/
#define mmCliMsgHeader						0x0320
#define mmCfgDataResponse_CFMtoCLI			mmRequestCfgDataResponse
#define mmCfgLogicIntf_CFMtoCLI				mmCfgLogicIntfResponse
#define mmCfgVirtualLogicIntf_CFMtoCLI			mmCfgVirtualLogicIntfResponse
#define mmRequestRunningData_CFMtoCLI		mmRequestRunningData
#define mmRunningDataResponse_CLItoCFM		mmRequestRunningDataResponse
#define mm_CliInnerMsg						mmCliMsgHeader + 1
#define mm_CliInntrMsg						mm_CliInnerMsg
#define mmActivePhyPort_CFMtoCLI			mmCliMsgHeader + 2
#define	mm_CliTelnetD						mm_MsgFromOamToTelnetd
#define mm_Test								0x0320 + 30
#ifdef BWOS_BESIM
#define mm_Bw2osAuxOutput					0x0320 + 31
#endif
#define mm_CmdResponse_ALLtoCLI				0x0320 + 32
#define mm_CmdResponseData_ALLtoCLI         0x0320 + 33

/* added by zhangkj at 2004.8.2 */
#define mmAux2Console_tShelltoTerminal			mmCliMsgHeader + 3
#define mmReportTemperature					mmCliMsgHeader + 4
/********************************************************************
*																	*
*							arp ethernet							*
*				reserved from 0x0340 to 0x035f						*
*																	*
********************************************************************/
#define mm_UpdateArpTable_ARPtoIPF   0x0350  //added by wangst on 2003/3/25
#define mm_UpdateArpTable_ARPtoRTMGT  mm_UpdateArpTable_ARPtoIPF
#define mm_UpdateNdTable_NDtoIPF 	 0x0351  //added by zhangkj on 2018.11.14
#define mm_UpdateNdTable_NDtoRTMGT   mm_UpdateNdTable_NDtoIPF

/********************************************************************
*																	*
*							ppp										*
*				reserved from 0x0360 to 0x037f						*
*																	*
********************************************************************/
/* PPP NI Msg Type */
#define mmPppMsgHeader						0x0360
#define mmCmd_NItoPPP						mmPppMsgHeader + 1
#define mmOpen_NItoPPP						mmPppMsgHeader + 2
#define mmClose_NItoPPP						mmPppMsgHeader + 3
#define mmLinkUp_NItoPPP					mmPppMsgHeader + 4
#define mmLinkDown_NItoPPP					mmPppMsgHeader + 5
#define mmSend_NItoPPP						mmPppMsgHeader + 6
#define mmUnload_NItoPPP					mmPppMsgHeader + 7
#define mmKeepalive_NItoPPP					mmPppMsgHeader + 8
#define mmResetPhyInt_PPPtoNI				mmPppMsgHeader + 9
#define mmMultilink_PPPtoDDR				mmPppMsgHeader + 10
#define mmShowPppMultilink_CLItoPPP			mmPppMsgHeader + 11
#define mmMultilink_CLItoPPP		 		mmPppMsgHeader + 12

/********************************************************************
*																	*
*							ipsec									*
*				reserved from 0x0380 to 0x039f						*
*																	*
********************************************************************/
#define mmIPsecMsgHeader						0x0380
#define mm_OutboundPkt_IPFtoIPSEC				mmIPsecMsgHeader + 1
#define mm_OutboundPkt_IPSECtoIPF				mmIPsecMsgHeader + 2
#define mm_InboundPkt_IPFtoIPSEC				mmIPsecMsgHeader + 3
#define mm_InboundPkt_IPSECtoIPF				mmIPsecMsgHeader + 4
#define mm_SendMsg_IPSECtoIPF					mmIPsecMsgHeader + 5
#define mm_SendMsg_IPFtoIPSEC					mmIPsecMsgHeader + 6
#define mm_IpsecPolicyResponse_IPSECtoIKE			mmIPsecMsgHeader + 7
#define mm_IpsecPolicyRequest_IKEtoIPSEC			mmIPsecMsgHeader + 8
#define mm_IpsecSARequest_IPSECtoIKE				mmIPsecMsgHeader + 9
#define mm_IpsecSAResponse_IKEtoIPSEC				mmIPsecMsgHeader + 10

#define mm_RequestCfgData_IPSECtoCFM            		mmRequestCfgData
#define mm_RequestCfgDataResponse_CFMtoIPSEC			mmRequestCfgDataResponse

#define mm_CfgLogicIntf_CFMtoIPSEC				mmCfgLogicIntf
#define mm_CfgLogicIntfResponse_IPSECtoCFM			mmCfgLogicIntfResponse

#define mm_RequestRunningData_CFMtoIPSEC			mm_RequestRunningData_CFMtoALL
#define mm_RequestRunningDataResponse_IPSECtoCFM		mm_RunningDataResponse_ALLtoCFM

/********************************************************************
*																	*
*							AAA									*
*				reserved from 0x0380 to 0x039f						*
*																	*
********************************************************************/
#define mmAAAMsgHeader						0x03a0
#define mm_Config_CLItoAAA					mmAAAMsgHeader + 1
#define mm_Msg_PPPtoAAA						mmAAAMsgHeader + 2
#define mm_Msg_CLItoAAA						mmAAAMsgHeader + 3
#define mm_Msg_TelnetDtoAAA					mmAAAMsgHeader + 4
#define mm_Msg_AAAtoSSHD					mmAAAMsgHeader + 5

#define mm_RequestCfgData_AAAtoCFM	            		mmRequestCfgData
#define mm_RequestCfgDataResponse_CFMtoAAA			mmRequestCfgDataResponse

#define mm_CfgLogicIntf_CFMtoAAA				mmCfgLogicIntf
#define mm_CfgLogicIntfResponse_AAAtoCFM			mmCfgLogicIntfResponse

#define mm_RequestRunningData_CFMtoAAA				mmRequestRunningData
#define mm_RequestRunningDataResponse_AAAtoCFM			mmRequestRunningDataResponse


/********************************************************************
*																	*
*							ni										*
*				reserved from 0x03a0 to 0x03bf						*
*																	*
********************************************************************/
#define mmNIMsgHeader							0x03b0
#define mmTraceSkBuf_NItoTrace					mmNIMsgHeader + 1
#define mmCancelSkQueueCongestion_NItoOther     mmNIMsgHeader + 2


/********************************************************************
*																	*
*							tftp										*
*				reserved from 0x03c0 to 0x03cf						*
*																	*
********************************************************************/
#define mmTFTPMsgHeader							0x03c0
#define mm_Cmd_CLItoTFTP						mmTFTPMsgHeader + 1
#define mm_CmdResponse_TFTPtoCLI				mmTFTPMsgHeader + 2
#define mm_BRDRequest_BRDtoTFTP					mmTFTPMsgHeader + 3
/*Add by lizhao, for ftp*/
#define mm_Cmd_CLItoFTP						mmTFTPMsgHeader + 4
#define mm_CmdResponse_FTPtoCLI				mmTFTPMsgHeader + 5
/********************************************************************
*						ddr 										*
*				reserved from 0x03d0 to 0x03ef						*
********************************************************************/
#define mmDDRMsgHeader							0x03d0
#define mmLoadNewCell_CFMtoDDR 					mmDDRMsgHeader+1
#define mmUnloadCell_CFMtoDDR					mmDDRMsgHeader+2
#define mmOpenCell_CFMtoDDR						mmDDRMsgHeader+3
#define mmCloseCell_CFMtoDDR					mmDDRMsgHeader+4
#define mmCliCommand_CLItoDDR					mmDDRMsgHeader+5
#define mmDialerRotaryGroup_CFMtoDDR			mmDDRMsgHeader+6
#define mmDialerInBand_CFMtoDDR					mmDDRMsgHeader+7
#define mmDDRSend_NItoDDR						mmDDRMsgHeader+8
#define mmLowLayerUp_NItoDDR					mmDDRMsgHeader+9
#define mmLowLayerDown_NItoDDR					mmDDRMsgHeader+10
#define mmLowLayerRing_NItoDDR					mmDDRMsgHeader+11
#define mmAddAccessControl_DDRtoIPF				mmDDRMsgHeader+12
#define mmDeleteAllAccessControl_DDRtoIPF		mmDDRMsgHeader+13
#define mmSetCfgData_CFMtoDDR					mmDDRMsgHeader+14

#define mmTimeOut_VOStoDDR						mm_Timeout_VOStoALL

#define mmDialerRotaryGroup_DDRtoCFM		mmDialerRotaryGroup_CFMtoDDR
#define mmDialerInBand_DDRtoCFM				mmDialerInBand_CFMtoDDR
#define mmDDRResponse_DDRtoCLI 				mmCliCommand_CLItoDDR
#define mmEvent_ADCtoADC						0x03ef

/********************************************************************
*					mon 			    *
*				reserved from 0x03f0 to 0x040f 	    *
********************************************************************/
#define mmMONMsgHeader							0x03f0
#define mmExcTaskRestart_MONtoVOS 					mmMONMsgHeader+1
#define mmExcTaskRestartResponse_VOStoMON				mmMONMsgHeader+2
#define mmExcInfo_MONtoLOG						mmMONMsgHeader+3
#define mmExcInfoReponse_LOGtoMON					mmMONMsgHeader+4
/********************************************************************
*					httpd 			    *
*				reserved from 0x0410 to 0x041a 	    *
********************************************************************/
#define mmHTTPDMsgHeader							0x0410
#define mmRunCmdReq_HTTPtoCLI	 					mmHTTPDMsgHeader+1
#define mmRunCmdRep_CLItoHTTP						mmHTTPDMsgHeader+2
#define mmCommonDataOutput_CLItoHTTP				mmHTTPDMsgHeader+3
#define mmStopCmdReq_HTTPtoCLI					mmHTTPDMsgHeader+4
#define mmClidevFree_HTTPtoHTTP					mmHTTPDMsgHeader+5
#define mmCliCmdMsg_CLItoHTTP					mmHTTPDMsgHeader+6

/********************************************************************
*																	*
*							IKE		*
*				reserved from 0x0420 to 0x042f		*
*									*
********************************************************************/
#define mmIKEMsgHeader				0x0420

#define mm_RequestCfgData_IKEtoCFM            		mmRequestCfgData
#define mm_RequestCfgDataResponse_CFMtoIKE		mmRequestCfgDataResponse

#define mm_RequestRunningData_CFMtoIKE			mm_RequestRunningData_CFMtoALL
#define mm_RequestRunningDataResponse_IKEtoCFM		mm_RunningDataResponse_ALLtoCFM


/********************************************************************
*							LOG 									*
*				reserved from 0x0430 to 0x043f						*
*				added in 2001-08-28									*
********************************************************************/
#define mmLOGMsgHeader		0x0430
//#define mmExcInfo_MONtoLOG	mmLOGMsgHeader+1		//收MON消息
#define mmExcInfoResponse_LOGtoMON 	mmLOGMsgHeader+2	//向MON回消息
#define mmExcReboot_MONtoLOG		mmLOGMsgHeader+3	//监控任务发送给日志任务系统异常重启的消息
#define mm_Cmd_CLItoLOG 			mmLOGMsgHeader+4	//CLI发送用户操作日志的命令的消息
#define mmRemoteUserInfo_CLItoLOG	mmLOGMsgHeader+5	//CLI给日志任务发送以TELNET和HTTP方式远程登陆和退出时的消息
#define mmCmdRecord_CLItoLOG 		mmLOGMsgHeader+6	//CLI给日志任务发送的纪录用户对路由器的配置命令的消息
#define mmUserReboot_CLItoLOG 		mmLOGMsgHeader+7	//CLI给日志任务发送用户重启路由器的消息
#define mmPortState_CFMtoLOG 		mmLOGMsgHeader+8	//与CFM任务之间的消息号
#define mmRouteTabWarning_RTMGTtoLOG mmLOGMsgHeader+9	//与路由管理任务之间的消息号
#define mmMemWarning_VOStoLOG 		mmLOGMsgHeader+10	//与VOS子系统之间的消息号
#define mmSkBufWarning_ALLtoLOG 	mmLOGMsgHeader+11	//SK_BUF报警信息
#define mmFileTransfer_TFTPtoLOG 	mmLOGMsgHeader+12	//与TFTP任务之间的消息号

/********************************************************************
*							DEBUG 									*
*				reserved from 0x0440 to 0x044f						*
*				added in 2001-10-30									*
********************************************************************/
#define mmDEBUGMsgHeader		0x0440
#define mmCmd_CLItoDEBUG			mmDEBUGMsgHeader+1	/*接受CLI　消息*/
#define mmTelnetClose_CLItoDEBUG		mmDEBUGMsgHeader+2	/*TELNET　断开*/
#define mmTimerOut_VOStoDEBUG			mmDEBUGMsgHeader+3	/*发送超时消息*/
#define mmRegisterFilterObject_DEBUGtoCFM	mmDEBUGMsgHeader+4	/*注册过滤对象*/
#define mmReceiveFilterObject_CFMtoDEBUG	mmDEBUGMsgHeader+5	/*接受过滤对象*/
#define mmSendDebugMsg_PROTOCOLtoDEBUG		mmDEBUGMsgHeader+6	/*发送调试信息*/
#define mm_DebugConfigData_MastertoSlave	mmDEBUGMsgHeader+7	/*发送配置信息到从板*/
#define mm_DirectMsg_MastertoSlave			mmDEBUGMsgHeader+8	/*发送调试信息到主板*/

/*end define debug message type*/

#ifdef _OLD_VERSION_ALLMSGMM_H

#define mmTraceSkBuf_NItoTrace                     200
#define mmCancelSkQueueCongestion_NItoOther      300


//  与BGP相关的
#define mmTimerOut_TMRtoBGP 					1
#define mmActiveCheck_MONtoBGP					2

#define mmRouteMonitorResponse_RTMGTtoBGP		50
#define mmIpMonitorResponse_RTMGTtoBGP			51
#define mmIpReachableInfo_RTMGTtoBGP			53

#define mmFilterObjectDelete_CFMtoBGP			60
#define mmFilterObjectUpdate_CFMtoBGP			61
#define mmRequestRunningData_CFMtoBGP			62
#define mmCfgDataResponse_CFMtoBGP				63
#define mmInterfaceIpResponse_CFMtoBGP			64
#define mmRouterIDResponse_CFMtoBGP				65

#define mmCliCommand_CLItoBGP                   70

/*  BGP ==> Route management   */
#define mmRegistRouteMonitor_BGPtoRTMGT			10
#define mmRegistIpMonitor_BGPtoRTMGT			11
#define mmRegisterIpReachable_BGPtoRTMGT		13

/*  BGP ==> Config management   */
#define mmRegisterFilterObject_BGPtoCFM			60
#define mmRequestCfgData_BGPtoCFM				61
#define mmRunningDataResponse_BGPtoCFM			62
#define mmInquireInterfaceIp_BGPtoCFM			63
#define mmInquireRouterID_BGPtoCFM				64

#define mmCliCommandRsp_BGPtoCLI                80

/* 与RTMGT相关的	*/
#define mmUpdateRoute_RIPtoRTMGT		0x2a10
#define mmUpdateRoute_OSPFtoRTMGT		0x2a11
#define mmUpdateRoute_BGPtoRTMGT		0x2a12

#define mmRedistributeRoute_RTMGTtoRIP	0x2a20
#define mmRedistributeRoute_RTMGTtoOSPF	0x2a21
#define mmRedistributeRoute_RTMGTtoBGP	0x2a22

#define mm_Cmd_CLItoRTMGT				0x2a30
#define mm_CmdResponse_RTMGTtoCLI		0x2a31

#define mmRequestCfgData_RTMGTtoCFM					0x0100
#define	mmRequestCfgDataResponse_CFMtoRTMGT			0x0101
#define mmRequestRunningData_CFMtoRTMGT				0x0102
#define	mmRequestRunningDataResponse_RTMGTtoCFM		0x0103
#define	mmCfgLogicIntf_RTMGTtoCFM					0x0104
#define	mmCfgLogicIntfResponse_CFMtoRTMGT			0x0105

#define mmRegisterFilterObject_RTMGTtoCFM	0x2a40
/*
#define mmFilterObjectDelete_CFMtoRTMGT		0x2a41
#define mmFilterObjectUpdate_CFMtoRTMGT		0x2a42
*/
#define mmFilterObjectUpdate_CFMtoRTMGT     mmFilterObjectUpdate_CFMtoBGP
#define mmFilterObjectDelete_CFMtoRTMGT     mmFilterObjectDelete_CFMtoBGP



#endif // _OLD_VERSION_ALLMSGMM_H

/********************************************************************
*							SYSMGT 									*
*				reserved from 0x0450 to 0x045f						*
*				added in 2002-4-25									*
********************************************************************/
#define mm_SysMgt_Msg 0x0450
#define mm_Removal_HSDRVtoSYSMGT 	mm_SysMgt_Msg+1
#define mm_SlaveDownAck_SLAVEtoMASTER	mm_SysMgt_Msg+2
#define mm_SlaveUp_SLAVEtoMASTER	mm_SysMgt_Msg+3
#define mm_Insertion_HSDRVtoSYSMGT		mm_SysMgt_Msg+4
#define mm_StartConfig_MASTERtoSLAVE	mm_SysMgt_Msg+5
#define mm_RemovalPended_HSDRVtoSYSMGT  mm_SysMgt_Msg+6

#define mm_SlaveDown_SYSMGTtoCFM	mm_SysMgt_Msg+10
#define mm_SlaveDown_MASTERtoSLAVE	mm_SysMgt_Msg+11
#define mm_SlaveStop_MASTERtoSLAVE	mm_SysMgt_Msg+12
#define mm_SlaveStopAck_SLAVEtoMASTER	mm_SysMgt_Msg+13
#define mm_SlaveUp_SYSMGTtoCFM		mm_SysMgt_Msg+14
#define mm_Echo_SYSMGT			mm_SysMgt_Msg+15
#define mm_StartConfig_SYSMGTtoCFM	mm_SysMgt_Msg+16

/********************************************************************
*							USERMGT									*
*				reserved from 0x0470 to 0x0490						*
*				added in 2002-5-25									*
********************************************************************/
#define mmUserMsgHeader 0x0470
#define mmTelnetPassword_CLItoUSERMGT  		mmUserMsgHeader + 1
#define mmEnablePassword_CLItoUSERMGT  		mmUserMsgHeader + 2
#define mmUserPassword_CLItoUSERMGT		  		mmUserMsgHeader + 3
#define mmTelnetLogin_CLItoUSERMGT 	 		mmUserMsgHeader + 4
#define mmTelnetLogin_USERMGTtoCLI	 	 		mmUserMsgHeader + 5
#define mmCheckTelnetPassword_CLItoUSERMGT 		mmUserMsgHeader + 6
#define mmCheckTelnetPassword_USERMGTtoCLI 		mmUserMsgHeader + 7
#define mmCheckEnablePassword_CLItoUSERMGT 		mmUserMsgHeader + 8
#define mmCheckEnablePassword_USERMGTtoCLI 		mmUserMsgHeader + 9

#define mmGetUserPassword_ALLtoUSERMGT  		mmUserMsgHeader + 10
#define mmGetUserPassword_USERMGTtoALL  		mmUserMsgHeader + 11
#define mmCheckUserPassword_ALLtoUSERMGT 		mmUserMsgHeader + 12
#define mmCheckUserPassword_USERMGTtoALL	 	mmUserMsgHeader + 13
#define mmGetUserSecret_ALLtoUSERMGT 			mmUserMsgHeader + 14
#define mmGetUserSecret_USERMGTtoALL 			mmUserMsgHeader + 15
#define mmGetPasswdSecret_ALLtoUSERMGT 			mmUserMsgHeader + 16
#define mmGetPasswdSecret_USERMGTtoALL 			mmUserMsgHeader + 17
#define mmCheckUserSecret_ALLtoUSERMGT 			mmUserMsgHeader + 18
#define mmCheckUserSecret_USERMGTtoALL 			mmUserMsgHeader + 19

#define mmCheckEnablePassword_HTTPtoUSERMGT		mmUserMsgHeader + 20
#define mmCheckEnablePassword_USERMGTtoHTTP		mmUserMsgHeader + 21

/********************************************************************
*							DOT1X									*
*				reserved from 0x0490 to 0x0500						*
*				added in 2003-5-8									*
********************************************************************/
#define mmDot1xMsgHeader 0x0490
#define mmEvent_DOT1XtoDOT1X		mmDot1xMsgHeader + 1
#define mmEapolPacket_DOT1XtoDOT1X	mmDot1xMsgHeader + 2
#define mmComm_AAAtoDOT1X			mmDot1xMsgHeader + 3
#define mmComm_DOT1XtoAAA			mmDot1xMsgHeader + 4

/********************************************************************
*							VRRP									*
*																	*
*																	*
********************************************************************/
#define mmVrrpMsgHeader 0x0500
#define mmRequestCfgData_VRRPtoCFM					mmVrrpMsgHeader + 1
#define mmRequestRunningData_CFMtoVRRP				mm_RequestRunningData_CFMtoALL
#define mm_Pkt_VRRPtoIP								mmVrrpMsgHeader + 2
#define mm_Pkt_VRRPtoARP							mmVrrpMsgHeader + 3
#define mm_Cmd_CLItoVRRP							mmVrrpMsgHeader + 4
#define mm_Pkt_IPtoVRRP								mmVrrpMsgHeader + 5
#define mmRunningResponse_VRRPtoCFM					mm_RunningDataResponse_ALLtoCFM

/********************************************************************
*							PKI									*
*																	*
*																	*
********************************************************************/
#define mmPkiMsgHeader 0x0520
#define	mmHostname_CLItoPKI							mmPkiMsgHeader + 1
#define	mmDomainname_CLItoPKI						mmPkiMsgHeader + 2
#define	mmRSAKeyGen_CLItoPKI						mmPkiMsgHeader + 3
#define	mmRSAKeyZeroize_CLItoPKI					mmPkiMsgHeader + 4
#define	mmShowMyPubRSAKey_CLItoPKI					mmPkiMsgHeader + 5
#define	mmShowPubChainRSAKey_CLItoPKI				mmPkiMsgHeader + 6
#define	mmCAname_CLItoPKI							mmPkiMsgHeader + 7
#define	mmCAURL_CLItoPKI							mmPkiMsgHeader + 8
#define	mmCRLOptional_CLItoPKI						mmPkiMsgHeader + 9
#define	mmCAEnroolRetryCount_CLItoPKI				mmPkiMsgHeader + 10
#define	mmCAEnrollRetryPeriod_CLItoPKI				mmPkiMsgHeader + 11
#define	mmRootCAname_CLItoPKI						mmPkiMsgHeader + 12
#define	mmRootCAURL_CLItoPKI						mmPkiMsgHeader + 13
#define	mmRootCACRLOptional_CLItoPKI				mmPkiMsgHeader + 14
#define	mmShowRootCA_CLItoPKI						mmPkiMsgHeader + 15
#define	mmCAAuthenticate_CLItoPKI					mmPkiMsgHeader + 16
#define	mmShowCACert_CLItoPKI						mmPkiMsgHeader + 17
#define	mmCertEnrollment_CLItoPKI					mmPkiMsgHeader + 18
#define	mmCRLRequest_CLItoPKI						mmPkiMsgHeader + 19
#define	mmShowCRL_CLItoPKI							mmPkiMsgHeader + 20
#define	mmDebug_CLItoPKI							mmPkiMsgHeader + 21
#define	mmWriteMemory_CLItoPKI						mmPkiMsgHeader + 22
#define	mmWriteErase_CLItoPKI						mmPkiMsgHeader + 23

#define mm_Cmd_CLItoPKI								mmPkiMsgHeader + 30

/********************************************************************
*							NTP									*
*				reserved from 0x0560 to 0x0570						*
*				added in 2003-8-8									*
********************************************************************/
#define mmNtpMsgHeader 0x0550

#define mmCliMsg_CLItoNTP							mmNtpMsgHeader + 1

/********************************************************************
*							SSHD									*
*				reserved from 0x0590 to 0x0600						*
*				added in 2004-2-16									*
********************************************************************/
#define mmSshdMsgHeader 0x0560
#define mmCmdMsg_CLItoSSHD							mmSshdMsgHeader + 1
#define mmPwdAuthentication_SSHDtoAAA				mmSshdMsgHeader + 2

/********************************************************************
*							POE									*
*				reserved from 0x0580 to 0x0590						*
*				added in 2003-8-8									*
********************************************************************/
#define mmPOEMsgHeader 0x0580

#define mmEnable_CLItoPOE							mmPOEMsgHeader + 1
#define mmPriority_CLItoPOE							mmPOEMsgHeader + 2
#define mmPwrLimit_CLItoPOE							mmPOEMsgHeader + 3
#define mmShowPortInfo_CLItoPOE						mmPOEMsgHeader + 4
#define mmSysEnable_CLItoPOE						mmPOEMsgHeader + 5
/********************************************************************
*							L2TCP									*
*				reserved from 0x0580 to 0x0590						*
*				added in 2003-8-8									*
********************************************************************/
#define mmL2TcpMsgHeader 0x0590

//L2Tcp发送消息
#define		mmReceiveConnectSuccess_L2TcptoUser		mmL2TcpMsgHeader + 1
#define		mmReceiveConnectFail_L2TcptoUser 		mmL2TcpMsgHeader+ 2
#define		mmConnectSuccess_L2TcptoUser			mmL2TcpMsgHeader+ 3
#define		mmConnectFail_L2TcptoUser				mmL2TcpMsgHeader+ 4
#define		mmSendSuccess_L2TcptoUser				mmL2TcpMsgHeader+ 5
#define		mmSendFail_L2TcptoUser					mmL2TcpMsgHeader+ 6
#define		mmCloseSuccess_L2TcptoUser  			mmL2TcpMsgHeader+ 7
#define		mmCloseFail_L2TcptoUser					mmL2TcpMsgHeader+ 8
#define		mmOverflow_L2TcptoUser  				mmL2TcpMsgHeader+ 9
#define		mmDisConnect_L2TcptoUser  				mmL2TcpMsgHeader+ 10
#define		mmReceiveData_L2TcptoUser  				mmL2TcpMsgHeader+ 11
//L2Tcp接收消息
#define		mmCreatSocket_UsertoL2Tcp  				mmL2TcpMsgHeader+ 12
#define		mmListenSocket_UsertoL2Tcp  			mmL2TcpMsgHeader+ 13
#define		mmConnectSocket_UsertoL2Tcp  			mmL2TcpMsgHeader+ 14
#define		mmCloseSocket_UsertoL2Tcp  				mmL2TcpMsgHeader+ 15
#define		mmSocketSend_UsertoL2Tcp				mmL2TcpMsgHeader+ 16
//L2Tcp接收的CLI消息
#define		mmShowSocket_ClitoL2Tcp					mmL2TcpMsgHeader+ 17

/********************************************************************
*							BDP										*
*				reserved from 0x0600 to 0x0610						*
*				added in 2004-5-8									*
********************************************************************/
#define mmBdpMsgHeader 0x0600

//BDP发送消息
#define		mmAddNeighbor_BdptoUser			mmBdpMsgHeader + 1
#define		mmDeleteNeighbor_BdptoUser		mmBdpMsgHeader + 2


/********************************************************************
*							SYSNODEMGT									*
*				reserved from 0x610 to 0x620						*
*				added in 2002-5-25									*
********************************************************************/
#define mm_SysNodeMgt_Msg	0x0610

/********************************************************************
*							RTMGTv6									*
*				reserved from 0x620 to 0x650							*
*				added in 2004-6-9									*
********************************************************************/
#define mmRTMGTv6MsgHeader					0x0620
#define mmUpdateRoute_ALLToRTMGTv6 			(mmRTMGTv6MsgHeader+1)
#define mmRedRoute_RTMGTv6ToALL				(mmRTMGTv6MsgHeader+2)
#define mmRTQuery_ALLtoRTMGTv6				(mmRTMGTv6MsgHeader+3)
#define mmStaticRoute_CLItoRTMGTv6			(mmRTMGTv6MsgHeader+4)
#define mmRouteRed_CLItoRTMGTv6				(mmRTMGTv6MsgHeader+5)
#define mmShowIPRoute_CLItoRTMGTv6			(mmRTMGTv6MsgHeader+6)
#define mmConfResponse_RTMGTv6toCLI			(mmRTMGTv6MsgHeader+7)
#define mmRequestRunningData_CFMtoRTMGTv6	mm_RequestRunningData_CFMtoALL
#define mmRunningDataResponse_RTMGTv6toCFM	mm_RunningDataResponse_ALLtoCFM
#define mmCfgLogicIntf_CFMtoRTMGTv6			mm_CfgLogicIntf_CFMtoALL
#define mmIPV6FTEntryAdd_RTMGTtoIPF			mmFwTab_Ipv6Add_RTMGTtoIPF
#define mmIPV6FTEntryDel_RTMGTtoIPF			mmFwTab_Ipv6Del_RTMGTtoIPF
#define mmRedInd_RTMGTv6toRoutingProtocol	(mmRTMGTv6MsgHeader+8)
#define mmRTQuery_RTMGTv6toAll				(mmRTMGTv6MsgHeader+9)
#define mmRTQueryNoRegister_ALLtoRTMGTv6		(mmRTMGTv6MsgHeader+10)
#define mmUpdateNdTable_NDtoRTMGTv6			(mmRTMGTv6MsgHeader+11)

/********************************************************************
*							log										*
*				reserved from 0x0540 to 0x054f						*
*				added in 2004-6-9									*
********************************************************************/
#define mmLOGMessageHeader					0x0640
#define mmLogSendMsg_ALLtoLOG 				(mmLOGMessageHeader+1)
#define mmDisconnect_TELNETtoLOG			(mmLOGMessageHeader+2)
#define mmCliCmdMsg_CLItoLOG				(mmLOGMessageHeader+3)
#define mmCliCmdMsgResp_LOGtoCLI			(mmLOGMessageHeader+4)
#define mmReadEnd_LOGtoLOG					(mmLOGMessageHeader+5)
#define mmTermStateNotify_LOGtoLOG			(mmLOGMessageHeader+6)
#define mmRebootNotify_ALLtoLOG				(mmLOGMessageHeader+7)

/********************************************************************
*							natpt									*
*				reserved from 0x0550 to 0x055f						*
*				added in 2004-6-9									*
********************************************************************/
#define mmNATPTMsgHeader					0x0660
#define mm_CliToNatpt           (mmNATPTMsgHeader+1)
#define mm_pkt_IpfToNatpt           (mmNATPTMsgHeader+2)
#define mm_Addr_NatptToRtmgt           (mmNATPTMsgHeader+3)
#define mm_CfmToNatpt           (mmNATPTMsgHeader+4)
#define mm_CMD_NATPTtoCLI        (mmNATPTMsgHeader+5)
#define mmRequestRunningDataResponse_NATPTtoCFM  (mmNATPTMsgHeader+6)

/********************************************************************
*																	*
*							mib										*
*					reserved from 0x0900 to 0x09ff					*
*																	*
********************************************************************/
#define mmMibOperHeader							0x0680
#define mm_GetSimpleVariable						mmMibOperHeader + 1
#define mm_SetSimpleVariable						mmMibOperHeader + 2
#define mm_GetTableField							mmMibOperHeader + 3
#define mm_SetTableField							mmMibOperHeader + 4
#define mm_GetTable								mmMibOperHeader + 5
#define mm_SetTable								mmMibOperHeader + 6
#define mm_GetTableEntry 						mmMibOperHeader + 7
#define mm_AddTableEntry						mmMibOperHeader + 8
#define mm_FixTableEntry						mmMibOperHeader + 9
#define mm_RemoveTableEntry						mmMibOperHeader + 10
#define mm_TrapEvent								mmMibOperHeader + 11
#define mm_CFM_NOTIFY_SNMP_IFTABLE_CHANGE		mmMibOperHeader + 12

#define mmGetSimpleVariable	mm_GetSimpleVariable
#define mmSetSimpleVariable	mm_SetSimpleVariable

#define mmGetTableField	mm_GetTableField
#define mmSetTableField	mm_SetTableField

#define mmGetTable	mm_GetTable
#define mmSetTable	mm_SetTable

#define mmGetTableEntry 	mm_GetTableEntry
#define mmAddTableEntry	mm_AddTableEntry
#define mmFixTableEntry	mm_FixTableEntry
#define mmRemoveTableEntry	mm_RemoveTableEntry
#define mmSendTrap	mmMibOperHeader + 13
/********************************************************************
*																	*
*							dhcp										*
*					reserved from 0x0700 to 0x07ff					*
*																	*
********************************************************************/
#define mmDhcpMsgHeader							0x06a0
#define mmIpAddress_DHCPtoNI   					mmDhcpMsgHeader + 1
#define mmDoubleAddressDetect_NItoDHCP   		mmDhcpMsgHeader + 2

/**********************************************************************
*                          POE                                                                                             *
*		reserved from 0x1000 to 0x10ff                                                                        *
*                                                                                                                             *
***********************************************************************/
#define mmPoeMsgHeader							0x06b0
#define mm_POEConfig_CFMtoPOE    				mmPoeMsgHeader + 1

/**********************************************************************
*                          SNTP                                                                                         *
*		reserved from 0x1000 to 0x10ff                                                                 *
*                                                                                                                           *
***********************************************************************/
#define mmSntpMsgHeader							0x06c0
#define mmCmdMsg_CLItoSNTP	    				mmSntpMsgHeader + 1

/********************************************************************
*							MLDV1 MLDV2								*
*				reserved from 0x06f0 to 0x06ff						*
*				added in 2004-11-4									*
********************************************************************/
#define mmIgmpMsgHeader                     	0x06f0
#define mmIgmpv1ToPim                           (mmIgmpMsgHeader + 1)  //added by hgx
#define mmIgmpv2ToPim                           (mmIgmpMsgHeader + 2)
#define mmIgmpv3ToPim                           (mmIgmpMsgHeader + 3)

/********************************************************************
*							PIMDM								*
*				reserved from 0x0710 to 0x071f						*
*				added in 2018-03-06									*
********************************************************************/
#define mmPimDmMsgHeader                      0x0710
#define mm_Cmd_CLItoPIMDM                     (mmPimDmMsgHeader + 1)
#define mm_CmdResponse_PIMDMtoCLI             (mmPimDmMsgHeader + 2)
#define mm_Pkt_mRoute                         (mmPimDmMsgHeader + 3)

/********************************************************************
*							MLDV1 MLDV2								*
*				reserved from 0x0720 to 0x072f						*
*				added in 2004-11-4									*
********************************************************************/
#define mmMldMsgHeader                     	0x0720
#define mmMldv1ToPim                           (mmMldMsgHeader + 1)
#define mmMldv2ToPim                           (mmMldMsgHeader + 2)

#endif //__ALLMSGMM_H

