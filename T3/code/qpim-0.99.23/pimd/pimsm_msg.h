#ifndef _PIMMSG_H_
#define _PIMMSG_H_

#include "pimsm_bootstrap.h"
#include "interface_define.h"
#include "vty.h"
#include "allmsgmm.h"

#if 1
//sangmeng add
typedef enum
{
    //全局模式的命令
    CLI_CMD_PIMSM_GLOBAL_ENABLE = 0x002e301,
    CLI_CMD_PIMSM_NO_GLOBAL_ENABLE,
    CLI_CMD_PIMSM_RP_ADDRESS,
    CLI_CMD_PIMSM_NO_RP_ADDRESS,
    CLI_CMD_PIMSM_ACCEPT_REGISTER,
    CLI_CMD_PIMSM_NO_ACCEPT_REGISTER,
    CLI_CMD_PIMSM_SPT_THRESHOLD_INFINITY,
    CLI_CMD_PIMSM_NO_SPT_THRESHOLD_INFINITY,
    CLI_CMD_PIMSM_SSM_ACCESS_GROUP,
    CLI_CMD_PIMSM_NO_SSM_ACCESS_GROUP,
    CLI_CMD_PIMSM_BOOTSTRAP_ENABLE,
    CLI_CMD_PIMSM_NO_BOOTSTRAP_ENABLE,
    CLI_CMD_PIMSM_BOOTSTRAP_CRP_ENABLE,
    CLI_CMD_PIMSM_NO_BOOTSTRAP_CRP_ENABLE,
    CLI_CMD_PIMSM_CRP_GROUP_POLICY,
    CLI_CMD_PIMSM_NO_CRP_GROUP_POLICY,
    //接口模式的命令
    CLI_CMD_PIMSM_INTERFACE_ENABLE,
    CLI_CMD_PIMSM_NO_INTERFACE_ENABLE,
    CLI_CMD_PIMSM_HELLO_INTERVAL,
    CLI_CMD_PIMSM_NO_HELLO_INTERVAL,
    CLI_CMD_PIMSM_JOIN_PRUNE_INTERVAL,
    CLI_CMD_PIMSM_NO_JOIN_PRUNE_INTERVAL,
    CLI_CMD_PIMSM_DR_PRIORITY,
    CLI_CMD_PIMSM_NO_DR_PRIORITY,
    //show命令
    CLI_CMD_PIMSM_SHOW_INTERFACE,
    CLI_CMD_PIMSM_SHOW_NEIGHBOR,
    CLI_CMD_PIMSM_SHOW_TOPOLOGY,
    CLI_CMD_PIMSM_SHOW_TRAFFIC,
    CLI_CMD_PIMSM_SHOW_RPF_PREFIX,
    CLI_CMD_PIMSM_SHOW_BOOTSTRAP,
    CLI_CMD_PIMSM_SHOW_BOOTSTRAP_RP,
    CLI_CMD_PIMSM_CLEAR_COUNTERS,
} PIM_CMD_TYPE;
enum DEBUG_LEVEL
{
    LEVEL_EMERGENCIES = 0,	/**/
    LEVEL_ALERTS,			/**/
    LEVEL_CRITICAL,			/**/
    LEVEL_ERRORS,			/*错误信息*/
    LEVEL_WARNING,			/*一般警告信息*/
    LEVEL_NOTIFICATIONS,	/**/
    LEVEL_INFORMATIONAL,	/*一般信息*/
    LEVEL_DEBUG,			/*调试信息*/
};
#endif

#define IGMP_TO_PIMSM_CANCEL_ADDR 1
#define IGMP_TO_PIMSM_ADD_ADDR 2
#define MLD_TO_PIMSM_CANCEL_ADDR 1
#define MLD_TO_PIMSM_ADD_ADDR 2

//Filter Mode
#define IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE 1   //过滤器包含模式
#define IGMPv3_TO_PIMSM_FILTER_MODE_EXCLUDE 2	 //过滤器排除模式
#define MLDv2_TO_PIMSM_FILTER_MODE_INCLUDE 1
#define MLDv2_TO_PIMSM_FILTER_MODE_EXCLUDE 2
#if 0
typedef enum pimsm_igmp_msg_type_t
{
    PIMSM_IN_SSM_RANGE_INCLUDE_ADD = 0,
    PIMSM_IN_SSM_RANGE_INCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_INCLUDE_ADD,
    PIMSM_OUT_SSM_RANGE_INCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD,
    PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_IGMPv1_ADD,
    PIMSM_OUT_SSM_RANGE_IGMPv2_ADD,
    PIMSM_OUT_SSM_RANGE_IGMPv1_DEL,
    PIMSM_OUT_SSM_RANGE_IGMPv2_DEL
} PIMSM_MEMBER_UPDATE_TYPE_T;
#endif
typedef enum pimsm_member_updte_type_t
{
    PIMSM_IN_SSM_RANGE_INCLUDE_ADD = 0,
    PIMSM_IN_SSM_RANGE_INCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_INCLUDE_ADD,
    PIMSM_OUT_SSM_RANGE_INCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD,
    PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL,
    PIMSM_OUT_SSM_RANGE_IGMPv1_ADD,
    PIMSM_OUT_SSM_RANGE_IGMPv2_ADD,
    PIMSM_OUT_SSM_RANGE_IGMPv1_DEL,
    PIMSM_OUT_SSM_RANGE_IGMPv2_DEL,
    PIMSM_OUT_SSM_RANGE_MLDv1_ADD,
    PIMSM_OUT_SSM_RANGE_MLDv1_DEL
} PIMSM_MEMBER_UPDATE_TYPE_T;

/* Igmp Message to Pimsm */
typedef struct pimsm_addr_list_node_t
{
    struct pimsm_addr_list_node_t *pstNext;
    VOS_IPV6_ADDR addr;
} PIMSM_ADDR_LIST_NODE_T;
typedef PIMSM_ADDR_LIST_NODE_T PIMSM_ADDR_LIST_T;
typedef struct pimsm_record_list_node_t
{
    struct pimsm_record_list_node_t *pstNext;
    VOS_IPV6_ADDR grp_addr;
    uint16_t wSourNum;
    uint16_t wFilterMode; /* 过滤器模式，有包含和排除两种宏定义确定 */
    PIMSM_ADDR_LIST_T *pstSourListHead;
} PIMSM_RECORD_LIST_NODE_T;
typedef PIMSM_RECORD_LIST_NODE_T PIMSM_RECORD_LIST_T;



typedef struct pimsm_addr_list_node_ipv6_t
{
    struct pimsm_addr_list_node_ipv6_t *pstNext;
    VOS_IPV6_ADDR stAddr;
} PIMSM_ADDR_LIST_NODE_IPV6_T;
typedef PIMSM_ADDR_LIST_NODE_IPV6_T PIMSM_ADDR_LIST_IPV6_T;

typedef struct pimsm_record_list_node_ipv6_t
{
    struct pimsm_record_list_node_ipv6_t *pstNext;
    VOS_IPV6_ADDR stGrpAddr;
    uint16_t wSourNum;
    uint16_t wFilterMode; /* 过滤器模式，有包含和排除两种宏定义确定 */
    PIMSM_ADDR_LIST_IPV6_T *pstSourListHead;
} PIMSM_RECORD_LIST_NODE_IPV6_T;
typedef PIMSM_RECORD_LIST_NODE_IPV6_T PIMSM_RECORD_LIST_IPV6_T;



typedef struct
{
    uint32_t dwType; /* 标识是删除组播组还是添加组播组还是接口的组播功能被DISABLE了 */
    uint32_t ifindex; /* 接口索引*/
    uint16_t wGrpNum; /* 组播组地址的个数 */
    PIMSM_ADDR_LIST_T *pstGrpListHead; /* 组播组的ip地址 */
} m_Igmpv1ToPimsm_t;
typedef struct
{
    uint32_t dwType; /*  标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了 */
    uint32_t ifindex;/*  接口索引 */
    uint16_t wGrpNum; /*  组播组地址的个数 */
    PIMSM_ADDR_LIST_T *pstGrpListHead; /*  组播组的ip地址 */
} m_Igmpv2ToPimsm_t;
typedef struct
{
    uint32_t dwType; /* 标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了 */
    uint32_t ifindex; /* 接口索引 */
    uint16_t wGrpNum; /* 组播组地址的个数 */
    PIMSM_RECORD_LIST_T *pstRecordListHead;
} m_Igmpv3ToPimsm_t;
typedef struct IgmpToPimsm_t
{
    union
    {
        m_Igmpv1ToPimsm_t	stIgmpv1ToPimsm;
        m_Igmpv2ToPimsm_t	stIgmpv2ToPimsm;
        m_Igmpv3ToPimsm_t	mIgmpv3ToPimsm;
    } u_version;
} m_IgmpToPimsm_t;


typedef struct
{
    uint32_t dwType; /*  标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了 */
    uint32_t dwIfIndex;/*  接口索引 */
    uint16_t wGrpNum; /*  组播组地址的个数 */
    PIMSM_ADDR_LIST_IPV6_T *pstGrpListHead; /*  组播组的ip地址 */
} m_Mldv1ToPimsm_t;
typedef struct
{
    uint32_t dwType; /* 标识是删除组播组还是添加组播组还是接口的mld功能被DISABLE了 */
    uint32_t dwIfIndex; /* 接口索引 */
    uint16_t wGrpNum; /* 组播组地址的个数 */
    PIMSM_RECORD_LIST_IPV6_T *pstRecordListHead;
} m_Mldv2ToPimsm_t;
typedef struct MldToPimsm_t
{
    union
    {
        m_Mldv1ToPimsm_t    stMldv1ToPimsm;
        m_Mldv2ToPimsm_t    stMldv2ToPimsm;
    };
} m_MldToPimsm_t;

#if 1 //sangmeng add
struct ipf_pkt_to_pim_t
{
    uint32_t	dwPktInputIf;

#define ID_PROTOCOL_IGMP 	2
#define ID_PROTOCOL_PIM 	103
    uint32_t	dwProtocolID;
    uint8_t 	*byPkt;
    uint32_t	dwPktLen;
};
#endif
/* Ipf message to Pimsm */
typedef struct IpfToPimsm_t
{
    struct ipf_pkt_to_pim_t mIpfPktToPimsm;
} m_IpfToPimsm_t;

/* Rtmgt message to Pimsm */
struct rtmgt_to_pimsm
{
    VOS_IPV6_ADDR   source; 		// the source for which we want iif and rpfnbr
    uint32_t   prefixlen; //sangmeng add

#define	MRTMGT_RPF_CTL_INVALID_NEIGHBOR	0
    VOS_IPV6_ADDR   rpf_nbr_addr;	// next hop towards the source

#define MRTMGT_RPF_CTL_INVALID_INTF	0xffffffff
    uint32_t   iif;			// the incoming interface ifindex to reach the next hop
    uint32_t   metric;
    uint32_t   preference;
};

typedef struct RtMrtToPimsm_t
{
#define MRTMGT_MSG_GET_RPF_QUERY		1
#define MRTMGT_MSG_GET_RPF_REPLY		2
    int type;
    int iId;
    struct rtmgt_to_pimsm *pstRpf;
} m_RtMrtToPimsm_t;


/* Cfm message to Pimsm */
typedef struct CfmToPimsm_t
{
    CliHead stCliHead;
    CFM_MODIFIED_IF_DATA stModify;
} m_CfmToPimsm_t;


/* VosTimer message to Pimsm */
typedef struct VosTmServToPimsm_t
{
    uint32_t tmTimerId;
    uint32_t tmTimerType;
    char acPara[0];
} m_VosTmServToPimsm_t;


/* Cli message to Pimsm */
typedef struct CliRpAddrToPimsm_t
{
    VOS_IPV6_ADDR   stRpAddress;
    VOS_IPV6_ADDR   group_addr;
    VOS_IPV6_ADDR   stGroupMask;
} m_CliRpToPimsm_t; // Cli message for RP address
typedef struct CliAcceptSrcToPimsm_t
{
    VOS_IPV6_ADDR   stSourceAddr;
    VOS_IPV6_ADDR   stSourceMask;
} m_CliAcceptSrcToPimsm_t; // Cli message for Accept Source address
typedef struct CliCrpGroupPolicyToPimsm_t
{
    VOS_IPV6_ADDR   group_addr;
    VOS_IPV6_ADDR   stGroupMask;
} m_CliCrpGroupPolicyToPimsm_t; // Cli message for C-RP group policy
typedef struct CliEnableCbsrToPimsm_t
{
    int iIfIndex;
    uint32_t dr_priority;
} m_CliEnableCbsrToPimsm_t; // Cli message for enable C-BSR
typedef struct CliEnableCrpToPimsm_t
{
    int iIfIndex;
    uint32_t dr_priority;
} m_CliEnableCrpToPimsm_t; // Cli message for enable C-RP
#if 1
typedef struct CliToPimsm_t
{
    CFM_HEAD stCfmHead;
    cliCmdHead subclihead;
    union
    {
        m_CliEnableCbsrToPimsm_t stEnableCbsr;//C-BSR
        m_CliEnableCrpToPimsm_t stEnableCrp;//C-RP
        m_CliCrpGroupPolicyToPimsm_t stCrpGroupPolicy;//C-RP group policy
        uint32_t dwSeconds;
        uint32_t dwPrValue;
        VOS_IPV6_ADDR stRpfDestAddr;

        m_CliAcceptSrcToPimsm_t stAcceptSource;
        m_CliRpToPimsm_t stRp;
    } u_cmd;
} m_CliToPimsm_t;
#endif


/* Pimsm message to Rtmgt */
typedef struct RegRpfToRtmgt_t
{
    uint32_t dwIpAddr;
    uint8_t bIsAdd; // 1: add register entry  0: delete register entry
    struct rtmgt_to_pimsm *pstRpf;
#if 0 //FIXME: for Unicast routing synchronization
    SEM_ID pstSemId;
#endif
} m_RegRpfToRtmgt_t;
#if 1//sangmeng add
#define MRTMGT_MRT_MAX_UPDATE_NUM  1

struct mrtmgt_mrt_output_Interf
{
    int	iOutLifNo;    			//输出逻辑接口号，0表示出接口为CPU

#define FLAG_MRTMGT_MRT_OUTPUT_LIF_STATE_FORWARD	0
#define FLAG_MRTMGT_MRT_OUTPUT_LIF_STATE_PRUNE		1
};
struct  mrtmgt_mrt_update_entry
{
#define MRTMGT_MRT_UPDT_TYPE_ADD			0
#define MRTMGT_MRT_UPDT_TYPE_DELETE			1
#define MRTMGT_MRT_UPDT_TYPE_ADD_OIF		2
#define MRTMGT_MRT_UPDT_TYPE_DELETE_OIF		3
#define MRTMGT_MRT_UPDT_TYPE_UPDT_FLAG		4
    uint16_t	wUpdtType;	//更新类型

#define MRTMGT_MRT_ROUTE_TYPE_PIM			1	//来自PIM的路由
#define MRTMGT_MRT_ROUTE_TYPE_SELF			2	//匹配该路由的报文本机接收
#define MRTMGT_MRT_ROUTE_TYPE_DEFAULT		3	//缺省路由
    uint16_t	wRouteType;			//路由类型

    uint32_t	dwGrp;				//多播组地址
    uint32_t	source;			//有源树的源IP地址，共享树为0
    uint32_t	dwGrpMask;			//组播地址掩码

    uint8_t	bMode;				//PIM协议模式
    uint8_t	type;				//共享树还是有源树
    uint32_t	dwFlag;				//标志

    uint32_t	dwRpfNei;			//RPF NEIGHBOR地址,(*, G)和(s, g)表项都用
    uint32_t	dwRpAddr;			//RP 地址, (*, G)表项使用.

#define	MRTMGT_MRT_RPF_NO_CHECK 0 //不作rpf检查
#define	MRTMGT_MRT_RPF_CHECK_IN_IF 1 //rpf检查入接口
    uint8_t	byRpfCheck;
    int	iInLifNo;				//输入接口号
    uint32_t	dwOutLifNum;			//输出接口数

#define MRTMGT_MRT_UPDATE_ENTRY_MAX_OUTIF_NUM		32
    struct mrtmgt_mrt_output_Interf	stOutputLif[MRTMGT_MRT_UPDATE_ENTRY_MAX_OUTIF_NUM];
};
#endif
typedef struct MrtUpdateToRtmgt_t
{
    uint32_t dwMrtNum; //修改表项的数目
    struct mrtmgt_mrt_update_entry stMrtUpdt[MRTMGT_MRT_MAX_UPDATE_NUM]; //多播路由表项的更新
} m_MrtUpdateToRtmgt_t;
typedef struct PimsmToRtMgt_t
{
    union
    {
        m_RegRpfToRtmgt_t mRegRpf;
        m_MrtUpdateToRtmgt_t mMrtUpdate;
    };
} m_PimsmToRtMgt_t;


/* Pimsm message to Ipf */
typedef struct IpfPktHead
{
    int logicinterfno;
    char *ip_packet;
    int ip_len;
} m_IpfPktHead;
typedef struct PimsmToIpf_t
{
    m_IpfPktHead stIpfPktHead;
} m_PimsmToIpf_t;


/* Pimsm message to Cfm */
typedef struct
{
    uint16_t wIfNum;
    uint8_t blGlobalEnable;
    uint8_t blRpEmbeded;
    VOS_IPV6_ADDR dwBsrRootID;
    VOS_IPV6_ADDR dwRpRootID;
    uint32_t dwBsrSendInterval;
    uint8_t bCbsrEnable;
    uint8_t bCrpEnable;
    uint16_t wCbsrPriority;
    uint16_t wCrpPriority;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpList;
    PIMSM_ACCEPT_REGISTER_ENTRY_T *pstAcceptRegList;
    struct pimsm_crp_group_policy_list *pstCrpGroupPolicyList;
    uint8_t bSptThresholdInfinity;
} PIMSM_GLOBAL_RUNNING_DATA_T;
typedef struct
{
    uint32_t ifindex;                  /*接口索引*/
    uint16_t wPimsmEnableFlag;            /*本接口上是否启动了pimsm*/
    uint32_t pimsm_hello_period;        /*hello报文的发送间隔*/
    uint32_t dwJoinPruneInterval;    /*加枝剪枝消息发送间隔*/
    uint32_t dwDrPriority;           /*DR选举用的优先级*/
} PIMSM_IF_RUNNING_DATA_T;
typedef struct RunningDataResponseToCfm_t
{
    CliHead stCliHead;
    uint32_t bDataFlag;
    char *pData;
    uint32_t dwDataSize;
} m_RunningDataResponseToCfm_t;
typedef struct PimsmToCfm_t
{
    union
    {
        m_RunningDataResponseToCfm_t stRunningDataResponse;
    };
} m_PimsmToCfm_t;


/* message about pimsm */
typedef struct
{
    CommonHead stCommonHead;
    union
    {
        /* message from other task*/
        m_IgmpToPimsm_t		mIgmpToPimsm;
        m_MldToPimsm_t      mMldToPimsm;
        m_IpfToPimsm_t		mIpfToPimsm;
        m_RtMrtToPimsm_t		mRtMrtToPimsm;
        m_CfmToPimsm_t		mCfmToPimsm;
        m_VosTmServToPimsm_t	mVosTmServToPimsm;
        m_CliToPimsm_t		mCliToPimsm;

        /* message to other task */
        m_PimsmToRtMgt_t		mPimsmToRtMgt;
        m_PimsmToIpf_t		mPimsmToIpf;
        m_PimsmToCfm_t		mPimsmToCfm;
    } u_msg;
} PIMSM_MSG_T;

int pimsm_ShowTraffic(struct vty *vty);

extern int pimsm_ClearCounters(void);

uint8_t Debug_Common_Func(void);
int pimsm_ToCliPrint(char *pcBuf);

int pimsm_MsgProcIgmp(PIMSM_MSG_T *pstPimsmMsg);
int pimsm_MsgProcMld(PIMSM_MSG_T *pstPimsmMsg);
#endif
