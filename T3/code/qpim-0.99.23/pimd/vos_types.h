/*************************************************
Copyright (C), 1000-2000, BitWay.
File:			c_vos_types.h
Author:			ZhuJiang
Version:		1.0
Date: 			Feb 20, 2011
Description:
Others:
Function List:
History:
*************************************************/
#ifndef _VOS_TYPES_H
#define _VOS_TYPES_H

#include <zebra.h>

/* 版本说明	*/
#if 1 /*sangmeng add*/
/*
 * 常用宏定义
 */
#define FALSE               0
#define TRUE                1

#define	VOS_OK				0
#define VOS_ERROR			-1
#define VOS_FAILURE			-1

#define VOS_TRUE	1
#define VOS_FALSE	0
/* CFM发送的 IP 地址和掩码类型定义，"202.112.238.222"　为 "b1.b2.b3.b4"　*/
typedef struct
{
    uint8_t 		b1;
    uint8_t			b2;
    uint8_t			b3;
    uint8_t			b4;
} CFM_IPADDRESS;

typedef union
{
    //BYTE  bAddr[16];
    //WORD  wAddr[8];
    //DWORD dwAddr[4];
    uint8_t 	u8_addr[16];
    uint16_t	u16_addr[8];
    uint32_t	u32_addr[4];
} VOS_IPV6_ADDR;

#define VOS_PACK_STRUCT __attribute__((packed))
typedef struct VOS_IPV6_PREFIX
{
    VOS_IPV6_ADDR addr;
    uint16_t	  wLength;

} VOS_IPV6_PREFIX,INTERFACE_ADDRESS,INTERFACE_IPV6;
/*zhoulei : CFM定义的IPV6地址*/
typedef struct CFM_IPV6_ADDRESS
{
    struct CFM_IPV6_ADDRESS *pNext;
    VOS_IPV6_PREFIX 	stIpAddr;
    int			ipAddrType;
} CFM_IPV6_ADDRESS;
typedef struct
{
    uint32_t dwCmdType;			/* 命令类型 */
    uint32_t dwIODevNo;			/* 终端设备号,CLI use only */
    uint32_t dwCreateTime;			/* 控制块创建时间, CLI use only */
} VOS_PACK_STRUCT CliHead;
/* 通知端口发生变化的内容 */
typedef struct
{
    uint32_t		    dwModifyFlag;
    uint32_t 		    dwLogicID;
    CFM_IPADDRESS	stIpAddr;
    CFM_IPADDRESS   stIpMask;
    CFM_IPV6_ADDRESS		stIpv6Address;
    uint32_t		    dwMTU;
    uint32_t		    dwBandWidth;
    uint32_t		    dwIntfType;
    uint32_t   			bIpFlag;   // 1 is used , 0 is no ip addr
    uint32_t           dwLinklayerType;
} CFM_MODIFIED_IF_DATA;

typedef CliHead cliCmdHead;

#endif

/*
 * VOS基本数据类型定义
 */
typedef	uint32_t	TASK_ID;
typedef	uint32_t	VOSFd;

/* 消息队列相关宏定义	*/
#define	VOS_MAX_TASK_NUM	100		/* VOS的最大任务数									*/
#define VOS_MAX_MSG_NUM		1000	/* VOS的消息队列中最多能容纳的消息个数				*/
/* 实际消息队列能容纳的消息个数为VOS_MAX_MSG_NUM-1	*/
#define VOS_MAX_QUE_SIZE	12000	/* VOS的消息队列中最多能容纳的字节数				*/
/* 实际消息队列能容纳的字节数为VOS_MAX_QUE_SIZE-4	*/
/* (因为运行时指针会进行地址对齐）					*/
#define VOS_MAX_MSG_SIZE	400		/* VOS的单个消息的最大长度							*/

/* VOSFdSet相关宏定义	*/
#define VOS_MAX_FD_NUM		100		/* VOSFdSet中最多包含的VOSFd个数					*/
#define VOS_MAX_FD_SET_NUM	50		/* VOS中最多允许的VOSFdSet个数						*/

/* 时钟系统相关宏定义	*/
#define VOS_TICKS_PER_SEC	100		/* 每秒钟的时钟Tick数								*/
#define VOS_TM_FREQUENCY	1		/* 每个时钟Tick内，时钟任务检查次数					*/
#define VOS_TM_INT_INTERVAL	(838.2229/2)			/* 硬件中断的频率(ns)				*/
#define VOS_TM_FREQUENCY_PER_TICK	0x2e9a			/* 每个时钟Tick的硬件中断次数，		*/
/* 由VOS_TICKS_PER_SEC、VOS_TM_FREQUENCY和VOS_TM_FREQUENCY_PER_TICK决定					*/
/* VOS_TM_FREQUENCY_PER_TICK = 1000(ms)/VOS_TICKS_PER_SEC/VOS_TM_FREQUENCY * 1000000 / VOS_TM_INT_INTERVAL	*/

#define VOS_MAX_TM_PARA_SIZE VOS_MAX_MSG_SIZE		/* 时钟参数表大小限制				*/


/* 公共消息类型定义			*/
#define mmTimeOut_VOStoALL	1
/* 调试用消息类型			*/
#define mmTestMsg_VOStoVOS	16

#define	VOS_TASK_ID_START			1
#define  VOS_TASK_ID_END				(VOS_MAX_TASK_NUM - 1)
enum TASK_ID_ENUM
{
    TASK_ID_VOS_TM_SERV = 1,
    TASK_ID_VOS_TM_FUNC,
    TASK_ID_VOS_ISR_SERV,
    TASK_ID_VOS,
    TASK_ID_VOS_MEM_MON,
    TASK_ID_VOS_IPC,
    TASK_ID_ISRCTRL,
    /* 接口子系统	*/
#if 1
    TASK_ID_PPP,
    TASK_ID_FRAME_RELAY,
    TASK_ID_DDR,
    TASK_ID_ETH_ARP,
    TASK_ID_NI,
    TASK_ID_SD,									/*ADD BY GUOMAO FOR THE SD TASK 0506/01*/
    TASK_ID_ADC,
    TASK_ID_ISDN,
    TASK_ID_HDLC,
    TASK_ID_LOOPBACK,/* only a task id ,have not task */
#endif
    TASK_ID_CE1,
    /* 转发子系统 */
    TASK_ID_IPF = 20,
    /*	 TASK_ID_NAT					21
    	 TASK_ID_ACL					22
    	 TASK_ID_ISRCTRL				23*/
    TASK_ID_NATPT,
    /* 支撑子系统 */
    TASK_ID_TCP = 25,
    TASK_ID_UDP_INPUT,
    TASK_ID_RAW_SOCKET,
    TASK_ID_TELNETD,
    TASK_ID_TELNET,
    TASK_ID_SSHD,
    TASK_ID_SSH,
    TASK_ID_DHCP,
    TASK_ID_TFTP,
    TASK_ID_FTP,
    TASK_ID_EVENT_PRO,
    TASK_ID_BUF_FREE,
    TASK_ID_HTTPD,
    TASK_ID_NTP,
    TASK_ID_BRD,
    TASK_ID_L2TCP,
    TASK_ID_SNTP,
    TASK_ID_INTERRUPT,
    /* 路由子系统 */
    TASK_ID_RIP = 45,
    TASK_ID_OSPF_IP_IF,
    TASK_ID_OSPF_CMI	,
    TASK_ID_OSPF_RT_IF,
    TASK_ID_OSPF_MAIN,
    TASK_ID_BGP,
    TASK_ID_RT_MGT,
    TASK_ID_OSPF6,
    TASK_ID_RIPNG,
#define		TASK_ID_MRTMGT			   TASK_ID_RT_MGT
    TASK_ID_RTMGTV6,
    TASK_ID_PIMSM,
    TASK_ID_IGMP,
    TASK_ID_MLD,

    /* 操作管理子系统 */
    TASK_ID_SNMP = 60,
    TASK_ID_CLI_SHELL,
    TASK_ID_CLI_TERMINAL,
    TASK_ID_CLI_OUTPUT,
    TASK_ID_CLI_SERIAL_INPUT,
    TASK_ID_CLI_SERIAL_OUTPUT,
    TASK_ID_MON,
    /* TASK_ID_OAM以后将不再使用	*/
    TASK_ID_CFM,
    TASK_ID_CFMC,
    TASK_ID_NICTL,
    TASK_ID_DEBUG,
    TASK_ID_LOG2 = TASK_ID_DEBUG,
    TASK_ID_LOG,
    TASK_ID_OAM_IDLE,
    TASK_ID_OAM_LED,
    /* 安全和VPN子系统 */
    TASK_ID_IPSEC,
    TASK_ID_IKE,
    TASK_ID_AAA,
    TASK_ID_USERMGT,
    TASK_ID_PKI,
    /* 语音子系统 */
    TASK_ID_VOIPC,
    TASK_ID_VOIPV,
    TASK_ID_VOIPN	,
    /* BE7K新加任务 */
    TASK_ID_SYSMGT,
    /*igmp snooping*/
    TASK_ID_IGSN,

    TASK_ID_SFLOW,

    /*vrrp*/
    TASK_ID_VRRP,

    TASK_ID_SWITCH_DRIVER,

    TASK_ID_DHCPSN,
    TASK_ID_HW_RT_SYNC,
    TASK_ID_TX,
    TASK_ID_PIMDM,

    TASK_ID_LAST

};
/* Address family numbers from RFC1700. */
#define VOS_AFI_IP                    1
#define VOS_AFI_IPV6                   2
#define VOS_AFI_MAX                   3

/* 消息公共头结构定义		*/
typedef struct
{
    uint16_t	wDestTaskID;    /*  目的任务号					*/
    uint16_t	wSourTaskID;    /*  源任务号					*/
    uint16_t	wMsgType;       /*  消息类型					*/
    uint16_t	wMsgLength ;    /*  消息长度					*/
} CommonHead;				/*  此结构为所有消息的共同消息头*/

/* VOS任务信息记录块定义	*/
#define VOS_TASK_STATUS_PEND 1
#define VOS_TASK_STATUS_READY 2
#define VOS_TASK_STATUS_SUSPEND 3
#define VOS_TASK_STATUS_DELAY 4


/* real clock data structure */
typedef struct
{
    char second;
    char minute;
    char hour;
    char week;
    char date;
    char month;
    char year;
    char century;
} REAL_CLOCK;

#endif	/* _VOS_TYPES_H	*/
