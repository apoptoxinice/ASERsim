#ifndef __PIMSM_IGMP_TASKMAIN_H__
#define __PIMSM_IGMP_TASKMAIN_H__

#include "pimsm_define.h"

#include <stdio.h>
#include <stdlib.h>

#include <zebra.h>
#include "memory.h"
#include "hash.h"
#include "log.h"
#include "vty.h"


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
#include "pimsm_bootstrap.h"
#include "interface_define.h"


#define IGMP_VERSION_1               1
#define IGMP_VERSION_2               2
#define IGMP_VERSION_3               3

#define  MLD_OK                     0
#define  MLD_ERROR                  1
#define  MLD_FAIL                   2
#define  MLD_CANCEL_ADDR            1
#define  MLD_ADD_ADDR               2


//过滤器模式
#define MLDv2_FILTER_MODE_INCLUDE   1           //过滤器包含模式
#define MLDv2_FILTER_MODE_EXCLUDE 2           //过滤器排除模式


#define mmIgmpMsgHeader                         0x06f0
#define mmIgmpv1ToPim                           (mmIgmpMsgHeader + 1)  //added by hgx
#define mmIgmpv2ToPim                           (mmIgmpMsgHeader + 2)
#define mmIgmpv3ToPim                           (mmIgmpMsgHeader + 3)


/*
 *  * VOS基本数据类型定义
 *   */
typedef uint32_t  TimerID;
typedef uint32_t  TimerType;
typedef uint32_t  TimeInterval;
typedef uint32_t  DelayInterval;

//结构类型定义
////MLD跟其他模块交互的消息类型结构
typedef struct
{
    uint16_t    wDestTaskID;
    uint16_t    wSourTaskID;
    uint16_t    wMsgType;
    uint16_t    wMsgLength;
} CommonHead_t;

typedef struct
{
    uint32_t dwCmdType;
    uint32_t dwIODevNo;
    uint32_t dwCreateTime;
} CliHead_t;


//mldv1给pim发的消息结构
typedef struct group_list_t
{
    struct group_list_t    *pstNext;
    VOS_IP_ADDR           stGrAddr;
} GROUPLIST;

//IGMPv1发给PIM的消息结构
typedef struct
{
    uint32_t dwType;//标识是删除组播组还是添加组播组还是接口的组播功能被DISABLE了
    uint32_t   dwIfIndex;          /*接口索引*/
    uint16_t    wMcAddrNum;     //组播组地址的个数
    GROUPLIST *pstGrHead;   //组播组的ip地址
} m_IGMPv1ToPim_t;


typedef struct
{
    uint32_t           dwType;          //标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了
    uint32_t           dwIfIndex;      /*接口索引*/
    uint16_t            wMcAddrNum;     //组播组地址的个数
    GROUPLIST       *pstGrHead;//组播组的ip地址
} m_Mldv1ToPim6_t;

//给pim的消息中带的记录
typedef struct source_list_t
{
    struct source_list_t    *pstNext;
    VOS_IP_ADDR           stSourceAddr;
} SOURLIST;
typedef struct record_list_t
{
    struct record_list_t *pstNext;
    VOS_IP_ADDR  stMulticastAddr;
    uint16_t             wSourAddrNum;
    uint16_t             wFilterMode;   //过滤器模式，有包含和排除两种宏定义确定
    SOURLIST         *pstSourAddrHead;
} MLDv2_RECORDLIST;

//mldv2给pim发的消息结构
typedef struct
{
    uint32_t            dwType;          //标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了
    uint32_t            dwIfIndex;     /*接口索引*/
    uint16_t             wMcAddrNum;     //组播组地址的个数
    MLDv2_RECORDLIST *pstRecordToPimHead;
} m_Mldv2ToPim6_t;


typedef struct
{
    CommonHead_t CommonHead;
#if 1
    union
    {
        m_IGMPv1ToPim_t			mIGMPv1ToPim;
        m_Mldv1ToPim6_t       	mMldv1ToPim;
        m_Mldv2ToPim6_t       	mMldv2ToPim;
    } u_msg;
#endif
} MLD_MSG;



//MLDv2源地址列表结构类型
typedef struct mldv2_sourcelist_t
{
    struct mldv2_sourcelist_t   *pstNext;           /*链表指针*/
    VOS_IP_ADDR               stSourceAddr;       /*源的ipv6地址*/
    uint16_t                        wRemainNum;         /*重传剩余次数*/
    TimerID                     stSourceAddrTimerID;/*源定时器ID*/
    char                        bSflag;             /*标识s标志是否应被设置了发送*/
} MLDv2_SOURCELIST;

//MLDv2组播组信息链表结构
typedef struct mldv2_mcaddrlist_t
{
    struct mldv2_mcaddrlist_t *pstNext; 		    /*链表指针*/
    VOS_IP_ADDR           stMulticastAddr; 	    /*本组播地址*/
    //几种定时器的ID
    TimerID 	stSpecMulticastAddrQueryIntervalTimerID;/*询问者指定组播地址询问间隔定时器ID*/
    //changed by madongchao for COMPATIBLE MODE ERROR
    TimerID 	dwIgmpv1HostKeepAliveTimerID;			/*IGMPv1版本主机保活定时器ID*///added by hgx
    TimerID 	dwMLDv1HostKeepAliveTimerID;    		/*MLD老版本主机保活定时器ID*/
    uint16_t		wCurrentMode;							/*标识当前是v2模式还是v1兼容模式*/
    //changed end
    TimerID 	stMultiAddrFilterTimerID;               /*组播组过滤器定时器ID*/
    TimerID 	stSpecMulticastAddrAndSourceQureyIntervalTimerID;/*询问者指定组播地址和源地址的询问间隔定时器ID*/
    //两种源地址列表
    MLDv2_SOURCELIST *pstExcludeListHead;           /*组播组过滤器为排除模式时的排除表*/
    MLDv2_SOURCELIST *pstSourceListHead;            /*包含模式时的源地址列表暨排除模式时的需求源列表*/
    uint32_t             dwRemainMAQueryNum;        	/*预定的指定组播地址的询问报文的剩余的次数*/

    uint16_t              wFilterMode;             		/*过滤器模式，有包含和排除两种宏定义确定*/
    REAL_CLOCK        stCreatTime; 					/*本组播组的创建时间*/
    unsigned char 		  blBlongToSsm; 				/*本组播组地址是否属于SSM范围*/
} MLDv2_MULTICASTADDRLIST;


extern void MLD_WriteMsgHeadToPim(MLD_MSG *pstMsgToPim, uint32_t dwMsgType, uint16_t wAddrNum, uint32_t dwIfIndex, uint16_t wVersion);

#endif
