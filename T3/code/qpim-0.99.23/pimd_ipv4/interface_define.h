/************************************************************************************
Copyright (C) Tsinghua Bitway Networking Technology Co.,LTD.
ALL RIGHTS RESERVED
Description:            NICTL与CFM之间的公共定义
**************************************************************************************/
#ifndef _INTERFACE_DEFINE_H
#define _INTERFACE_DEFINE_H

#include "vos_types.h"
#define INTERFACE_DEFAULT_LOGICID               -1
#define INTERFACE_DEFAULT_ADAPTOR               -1
#define INTERFACE_DEFAULT_SLOT                  -1
#define INTERFACE_DEFAULT_PORT                  -1
#define INTERFACE_DEFAULT_CHANNEL               -1
#define INTERFACE_DEFAULT_CHILD                 -1
#define INTERFACE_DEFAULT_ENCAPSULATION         -1
#define INTERFACE_DEFAULT_DRIVER_TYPE			-1

/*******************************************************************************
       CFM头定义
*******************************************************************************/
//接口公共头,相当于CFM头
typedef struct
{
    int	iLogicID;
    int	iDriverType;
    int	iLinklayerType;
    int	iSlotNo;
    int	iAdaptorNo;
    int	iPortNo;
    int	iChannelNo;
    int	iChildNo;
    int   iSubType;
} INTERFACE_INDEX;
typedef	INTERFACE_INDEX				CFM_HEAD;

//接口类型和CELL类型
enum
{
    INTERFACE_NULL,
    INTERFACE_FE,
    INTERFACE_GE,
    INTERFACE_POS,
    INTERFACE_ATM,
    INTERFACE_SERIAL,	// serial 1/1/1
    INTERFACE_AS,		// async 1/1/1
    INTERFACE_SW_FE,
    INTERFACE_SW_GE,
    INTERFACE_SW_10GE,
    INTERFACE_CE1,
    INTERFACE_SERIAL_CHILD,
    INTERFACE_POS_CHILD,
    INTERFACE_CHILD,
    INTERFACE_CHANNAL,
    INTERFACE_ACT_PHY_ALL
};

enum
{
    INTERFACE_LOOPBACK = INTERFACE_ACT_PHY_ALL,
    INTERFACE_MPPP, // interface mutilink
    INTERFACE_VTP, // interface virtual-template
    INTERFACE_MVA, //interface virtual-access
    INTERFACE_DIALER,
    INTERFACE_SW_VRP,
    INTERFACE_SW_AGG,
    INTERFACE_FE_CHILD,  /*wangst2003/8*/
    INTERFACE_TUNNEL,//added by zhoulei
    // ADD BY USER,请不要将非接口类型的宏定义加入到INTERFACE_PHY_ALL之前，可能导致命令行匹配错误
    INTERFACE_PHY_ALL,
    INTERFACE_PPP,
    INTERFACE_HDLC,
    INTERFACE_FR,
    INTERFACE_ARP,
    INTERFACE_ADC,
    INTERFACE_LOGIC
};

#endif
