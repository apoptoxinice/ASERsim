/*****************************************************
*
*
*
*****************************************************/
#ifndef _PIM_H_
#define _PIM_H_

#include <hash.h>
#include "vos_types.h"

////////////////////////////////////////////////////////////////

#define PIMSM_RECV_MSG_BUF_LEN (2*1024)
#define PIMSM_MAX_DISPLAY_LEN (1024*1024)

////////////////////////////////////////////////////////////////


#define ALL_PIM_ROUTERS     "224.0.0.13"

/*mode*/
//为了跟IPF同步做如下修改
#define PIM_MODE_SM          0x00
#define PIM__MODE_DM          0x01
#define PIM__MODE_NULL          0x02

#define PIM_SEND_PACK_BUFFER_SIZE     5*1024
#define PIM_RECIEVE_PACK_BUFFER_SIZE  5*1024
#define PIM_MAX_CMSG_SIZE             64
#define SS_DEB_lENTH                   6*1024
#define SS_ADDR_LENTH                  200
#define PIM_MAX_BUF                   1024
#define PIM_MAX_SHOWSIZE              1024*1024


/*versioni*/
#define PIM_V1          0x01
#define PIM_V2          0x02

#define ADDRF_IPv4      1   /* family  1: ipv4  2: ipv6 */
#define ADDRT_IPv4      0   /* type */

#define PIM_IP_VERSION 4

#define SINGLE_SRC_MSK6LEN            32 /* the single source mask length */
#define SINGLE_GRP_MSK6LEN            32 /* the single group mask length  */
#define STAR_STAR_RP_MSK6LEN          4   /* Masklen for e0.0.0.0 to encode (*,*,RP) */

#define MAX_UPSTREAM    255 /* 上游邻居的最多个数 */

#define PIM_CONFIG                 0x0001  /* 标识是否在全局模式下配置了PIM */
#define PIM_CREATE                 0x0002  /* 标识和PIM相关的全局变量是否已初始化 */

#define PIM_ACLNAMEMAXLENTH 80      /*ACL表名字最大长度*/


#ifndef MIN
#define MIN(a,b)((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b)((a)>(b)?(a):(b))
#endif


#define MASK_TO_MASKLEN(mask , masklen) \
do { \
	uint8_t maskarray[8] = \
	 {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};\
	uint8_t i,j; \
	masklen = 0; \
	for(i=0;i<sizeof(mask);i++) \
	{ \
		for(j=0;j<8;j++) \
		{ \
			if ((mask.u8_addr[i] & maskarray[j]) == maskarray[j]) \
			{ \
				masklen = i*8+j+1; \
			} \
		} \
		if (mask.u8_addr[i] != maskarray[7]) break; \
	} \
} while (0);



#define MASKLEN_TO_MASK6(masklen, mask6) \
     do {\
         uint8_t maskarray[8] = \
         {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff}; \
         int bytelen, bitlen, i; \
         memset(&(mask6), 0, sizeof(mask6));\
         bytelen = (masklen) / 8;\
         bitlen = (masklen) % 8;\
         for (i = 0; i < bytelen; i++) \
             (mask6).u8_addr[i] = 0xff;\
         if (bitlen) \
             (mask6).u8_addr[bytelen] = maskarray[bitlen - 1]; \
     }while(0);


#define GET_BYTE(val, cp)       ((val) = *(cp)++)
#define PUT_BYTE(val, cp)       (*(cp)++ = (u_int8)(val))

#define GET_HOSTSHORT(val, cp)                  \
        do {                                    \
                register uint16_t Xv;            \
                Xv = (*(cp)++) << 8;            \
                Xv |= *(cp)++;                  \
                (val) = Xv;                     \
        } while (0)

#define PUT_HOSTSHORT(val, cp)                  \
         do {                                   \
                 register uint16_t Xv;           \
                 Xv = (uint16_t)(val);           \
                 *(cp)++ = (uint8_t)(Xv >> 8);   \
                 *(cp)++ = (uint8_t)Xv;          \
         } while (0)

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#define GET_NETSHORT(val, cp)                   \
        do {                                    \
                register uint16_t Xv;            \
                Xv = *(cp)++;                   \
                Xv |= (*(cp)++) << 8;           \
                (val) = Xv;                     \
        } while (0)
#define PUT_NETSHORT(val, cp)                   \
        do {                                    \
                register uint16_t Xv;            \
                Xv = (uint16_t)(val);            \
                *(cp)++ = (uint8_t)Xv;           \
                *(cp)++ = (uint8_t)(Xv >> 8);    \
        } while (0)
#else
#define GET_NETSHORT(val, cp) GET_HOSTSHORT(val, cp)
#define PUT_NETSHORT(val, cp) PUT_HOSTSHORT(val, cp)
#endif /* {GET,PUT}_NETSHORT */

#define GET_HOSTLONG(val, cp)                   \
        do {                                    \
                register uint32_t Xv;             \
                Xv  = (*(cp)++) << 24;          \
                Xv |= (*(cp)++) << 16;          \
                Xv |= (*(cp)++) <<  8;          \
                Xv |= *(cp)++;                  \
                (val) = Xv;                     \
        } while (0)

#define PUT_HOSTLONG(val, cp)                   \
        do {                                    \
                register uint32_t Xv;            \
                Xv = (uint32_t)(val);            \
                *(cp)++ = (uint8_t)(Xv >> 24);   \
                *(cp)++ = (uint8_t)(Xv >> 16);   \
                *(cp)++ = (uint8_t)(Xv >>  8);   \
                *(cp)++ = (uint8_t)Xv;           \
        } while (0)

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#define GET_NETLONG(val, cp)                    \
        do {                                    \
                register uint32_t Xv;             \
                Xv  = *(cp)++;                  \
                Xv |= (*(cp)++) <<  8;          \
                Xv |= (*(cp)++) << 16;          \
                Xv |= (*(cp)++) << 24;          \
                (val) = Xv;                     \
        } while (0)

#define PUT_NETLONG(val, cp)                    \
        do {                                    \
                register uint32_t Xv;            \
                Xv = (uint32_t)(val);            \
                *(cp)++ = (uint8_t)Xv;           \
                *(cp)++ = (uint8_t)(Xv >>  8);   \
                *(cp)++ = (uint8_t)(Xv >> 16);   \
                *(cp)++ = (uint8_t)(Xv >> 24);   \
        } while (0)
#else
#define GET_NETLONG(val, cp) GET_HOSTLONG(val, cp)
#define PUT_NETLONG(val, cp) PUT_HOSTLONG(val, cp)
#endif /* {GET,PUT}_HOSTLONG */

#define GET_ESADDR(esa, cp)  /* XXX: hard coding */  \
        do {                                    \
            (esa)->addr_family = *(cp)++;       \
            (esa)->encod_type  = *(cp)++;       \
            (esa)->flags       = *(cp)++;       \
            (esa)->masklen     = *(cp)++;       \
             memcpy(&(esa)->src_addr, (cp), sizeof(struct in_addr)); \
         (cp) += sizeof(struct in_addr);   \
        } while(0)

#define PUT_ESADDR(addr, masklen, flags, cp)    \
        do {                                    \
            uint32_t i; \
            VOS_IP_ADDR maskaddr; \
        MASKLEN_TO_MASK6(masklen, maskaddr); \
            *(cp)++ = ADDRF_IPv4; /* family */  \
            *(cp)++ = ADDRT_IPv4; /* type   */  \
            *(cp)++ = (flags);    /* flags  */  \
            *(cp)++ = (masklen);                \
            for (i = 0; i < sizeof(struct in_addr); i++, (cp)++) \
                *(cp) = maskaddr.u8_addr[i] & (addr).u8_addr[i]; \
        } while(0)

#define GET_EGADDR(ega, cp) /* XXX: hard coding */ \
        do {                                    \
            (ega)->family  = *(cp)++;       \
            (ega)->encoding_type    = *(cp)++;       \
            (ega)->flags   = *(cp)++;       \
            (ega)->mask_len = *(cp)++;       \
             memcpy(&(ega)->grp_addr, (cp), sizeof(VOS_IP_ADDR)); \
            (cp) += sizeof(VOS_IP_ADDR);    \
        } while(0)


#define PUT_EGADDR(addr, masklen, reserved, cp) \
         do {                                    \
             uint32_t i; \
             VOS_IP_ADDR maskaddr; \
         MASKLEN_TO_MASK6(masklen, maskaddr); \
             *(cp)++ = ADDRF_IPv4; /* family */  \
             *(cp)++ = ADDRT_IPv4; /* type   */  \
             *(cp)++ = (reserved); /* reserved; should be 0 */  \
             *(cp)++ = (masklen);                \
             for (i = 0; i < sizeof(VOS_IP_ADDR); i++, (cp)++) \
                 *(cp) = maskaddr.u8_addr[i] & (addr).u8_addr[i]; \
         } while(0)

#define GET_EUADDR(eua, cp)  /* XXX hard conding */    \
        do {                                    \
         (eua)->family = *(cp)++;  \
         (eua)->encoding_type   = *(cp)++;  \
         memcpy(&(eua)->unicast_addr, (cp), sizeof(VOS_IP_ADDR)); \
         (cp) += sizeof(VOS_IP_ADDR);   \
        } while(0)

#define PUT_EUADDR(addr, cp) \
         do {                                    \
             *(cp)++ = ADDRF_IPv4; /* family */  \
             *(cp)++ = ADDRT_IPv4; /* type   */  \
             memcpy((cp), &(addr), sizeof(VOS_IP_ADDR)); \
             (cp) += sizeof(VOS_IP_ADDR); \
         } while(0)



#define PIM_NULL_ENTRY_OIL(e) \
        ((NULL == (((struct stu_pimsm_mrtentry *) (e))->pstLeaveOil)) \
         && (NULL == (((struct stu_pimsm_mrtentry *) (e))->pstPimOil)))

typedef union
{
    uint8_t 	u8_addr[4];
    uint16_t	u16_addr[2];
    uint32_t	u32_addr[1];
} VOS_IP_ADDR;

typedef struct stu_Addr_list
{
    struct stu_Addr_list    *pstNext;
    VOS_IP_ADDR           addr;
} PIM_ADDRLIST;

//////////////////////////////////////////////////////////////////////////////////
struct pimsm_rpf_entry
{
    struct pimsm_rpf_entry *next;
    struct pimsm_rpf_entry *prev;
    VOS_IP_ADDR stDest;
    VOS_IP_ADDR stRpfNbr;
    uint32_t rpf_if;
    uint32_t preference;
    uint32_t metric;
};

typedef struct pimsm_static_rp_entry_t
{
    struct pimsm_static_rp_entry_t	*pstNext;
    VOS_IP_ADDR group_addr;
    uint16_t group_masklen;
    VOS_IP_ADDR stRPAddress;
} PIMSM_STATIC_RP_ENTRY_T;

typedef struct pim_accept_register_entry_t
{
    struct pim_accept_register_entry_t * pstNext;
    VOS_IP_ADDR stSourceAddr;
    uint16_t wSourceMaskLen;
} PIMSM_ACCEPT_REGISTER_ENTRY_T;

#define PIMSM_FLAG_CONFIG 0x0001  /* 标识是否在全局模式下配置了PIM */
#define PIMSM_FLAG_CREATE 0x0002  /* 标识和PIM相关的全局变量是否已初始化 */
typedef struct pimsm_global_t
{
    uint8_t version;              /* version */
    uint8_t mode;             /* mode */

    VOS_IP_ADDR stAllPimRouters;   /* All_PIM_ROUTERS */
    VOS_IP_ADDR stSockAddr6d;       /* for (*,*,RP) */

    uint8_t *pucSendBuf;         /* send message buffer size 5*1024 */

    struct hash *pstGrpHash;        /* pimsm Group entry hash */
    struct hash *pstSrcHash;        /* pimsm Source entry hash */

    struct pimsm_rpf_entry *pstRpfList;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpList;
    PIMSM_ACCEPT_REGISTER_ENTRY_T *pstAcceptRegisterList;

    uint8_t bSptThresholdInfinity; /* 0:切换 1:不切换 */

    uint16_t wFlags; /* PIMSM_FLAG_CONFIG  PIMSM_FLAG_CREATE */

    /* receive packet count */
    uint32_t dwInPimsmRegister;
    uint32_t dwInPimsmRegisterStop;
    uint32_t dwInPimsmGraftAck;
    uint32_t dwInPimsmCandRpAdv;

    /* send packet count */
    uint32_t dwOutPimsmRegister;
    uint32_t dwOutPimsmRegisterStop;
    uint32_t dwOutPimsmGraftAck;
    uint32_t dwOutPimsmCandRpAdv;
} PIMSM_GLOBAL_T;
//////////////////////////////////////////////////////////////////////////////////////////

/* pimsm message statistics */
typedef struct stu_pimsm_stat
{
    uint32_t   dwInPim6Hello;
    uint32_t   dwInPim6JP;
    uint32_t   dwInPim6Bootstrap;
    uint32_t   dwInPim6Assert;
    uint32_t   dwInPim6Graft;

    uint32_t   dwOutPim6Hello;
    uint32_t   dwOutPim6JP;
    uint32_t   dwOutPim6Bootstrap;
    uint32_t   dwOutPim6Assert;
    uint32_t   dwOutPim6Graft;
} PIM_STAT;

typedef struct stu_pimsm_assert_metric
{
    uint8_t            ucRptBit;       /*从断言报文中获取rpt位*/
    uint32_t           dwMetricPref;   /*花费参考值*/
    uint32_t           dwRouteMetric;  /*花费值*/
    VOS_IP_ADDR   stIpv6Addr;     /*/ipv6地址*/
} PIM_ASSERT_METRIC;

typedef enum em_pimsm_assert_state
{
    PIM_ASSERT_NOINFO = 0,
    PIM_ASSERT_WINNER,
    PIM_ASSERT_LOSER,
    PIM_ASSERT_END
} PIM_ASSERT_STATE;

typedef enum em_pimsm_mld_messege_type
{
    PIM_IN_SSM_RANGE_INCLUDE_ADD = 0,
    PIM_IN_SSM_RANGE_INCLUDE_DEL,
    PIM_OUT_SSM_RANGE_INCLUDE_ADD,
    PIM_OUT_SSM_RANGE_INCLUDE_DEL,
    PIM_OUT_SSM_RANGE_EXCLUDE_ADD,
    PIM_OUT_SSM_RANGE_EXCLUDE_DEL,
    PIM_OUT_SSM_RANGE_IGMPv1_ADD,
    PIM_OUT_SSM_RANGE_IGMPv2_ADD,
    PIM_OUT_SSM_RANGE_IGMPv1_DEL,
    PIM_OUT_SSM_RANGE_IGMPv2_DEL
} PIM_MLD_MSG_TYPE;

/* incoming interface */
typedef struct stu_pimsm_iif
{
    uint32_t               ifindex;     /* incoming interface number to RP or S */
    VOS_IP_ADDR       stUpstreamNbr; /* upstream neighbor address */
    PIM_ASSERT_METRIC  stAssertWinner;/*保存断言胜利者及其花费*/
    PIM_ASSERT_STATE   emState;
    uint32_t             tmAssertTimerID;/* 断言定时器ID */
} PIM_IIF;

/*outgoing interfaces*/
typedef struct stu_pimsm_oif
{
    struct stu_pimsm_oif *next;
    struct stu_pimsm_oif *prev;
    uint32_t               ifindex;      /* output interface number */
    uint8_t                ucIfType;       /* immediate--收到加枝或MLD上报,
                                           inherited--拷贝自(*,*,RP)或(*,G)*/
#if 1
    struct thread * t_pimsm_hold_timer;
#endif
    uint32_t             tmDelTimer;     /* 继承出接口没有holdtimer定时器,
    　　　　　　　　　　　　　　　　　　　 在非P2P链路删除继承出接口需要用此定时器删除 */
    uint32_t             tmAssertTimerID;/* 断言定时器ID */
    PIM_ASSERT_METRIC  stAssertWinner; /*保存断言胜利者及其花费*/
    PIM_ASSERT_STATE   emState;
} PIM_OIF;

#define OIF_IMMEDIATE 0x01
#define OIF_INHERITED 0x02

typedef struct stu_pimsm_jp_para
{
    struct stu_pimsm_jp_para *pstNext;
    uint8_t ucActType;
    VOS_IP_ADDR stSrc;
    VOS_IP_ADDR stGrp;
} PIM_JP_PARA;

/*soruce entry*/
typedef struct stu_pimsm_srcentry
{
    VOS_IP_ADDR               address;  /* source address */
    struct stu_pimsm_mrtentry    *pstSrcMrtLink; /* link to the (S,G) routing entries */
} PIM_SRCENTRY;

/* group entry */
typedef struct stu_pimsm_grpentry
{
    struct stu_pimsm_grpentry    *rpnext;    /* next grp for the same RP */
    struct stu_pimsm_grpentry    *rpprev;    /* prev grp for the same RP */
    uint8_t                flags;    /* SSM range or SM range */
    VOS_IP_ADDR                  address;  /* subnet group of multicasts */
    VOS_IP_ADDR                  stRp;       /* The IPv6 address of the RP */
    struct stu_pimsm_mrtentry    *pstMrt;    /* Pointer to the (*,G) routing entry */
    struct stu_pimsm_mrtentry    *pstSrcMrtLink; /* link to sub (S,G) routing entries */
} PIM_GRPENTRY;

/*(*,G) and (S,G) entry */
typedef struct stu_pimsm_mrtentry
{
    struct stu_pimsm_mrtentry    *samegrpnext;   /* link to next entry of same group  */
    struct stu_pimsm_mrtentry    *samegrpprev;   /* link to prev entry of same group  */
    struct stu_pimsm_mrtentry    *samesrcnext;   /* link to next entry of same source */
    struct stu_pimsm_mrtentry    *samesrcprev;   /* link to prev entry of same source */
    struct stu_pimsm_grpentry    *group;  /* pointer to group entry */
    struct stu_pimsm_srcentry    *source; /* pointer to source entry */

    VOS_IP_ADDR   stPmbrAddr;  /* The PMBR address (for interop) */

    PIM_IIF        stIif;       /* incoming interface *//* incoming interface (point to RP or S) */
    PIM_OIF        *oif;     /* output interface link ((pstPimOil + pstLeaveOil) - pstAssertedOil - Iif)*/
    PIM_OIF        *pstPimOil;       /* pim protocol process output interface link (can include Iif) */
    PIM_OIF        *pstLeaveOil;     /* directness connect member output interface link (can include Iif) */
    PIM_OIF        *pstAssertedOil;  /* assert loser output interface */

    uint32_t           flags;          /* the  flags information */

    uint32_t           metric;         /* entry metric */
    uint32_t           preference;     /* metric preference */

    uint32_t         tmRegSuppTimer;   /* Register-Suppression Timer */
    uint32_t         tmRegSuppAuxTimer;/* Register-Suppression Timer */

    uint32_t         tmJPDelayTimer;   /* delay send join_prune timer */
    uint32_t         tmJPPeriodTimer;  /* Proid send join_prune timer */

    REAL_CLOCK      stInitTime;       /* entry create time */
    PIM_JP_PARA    *pstJpPara;

    signed long lPacketMatchCount;
    uint32_t tmKeepAliveTimer;

    uint8_t bIsCopyToCpu;//add by wuyan at 2018-05-02
} PIM_MRTENTRY;

/* 组项的flags取值定义 */
#define MRTF_RPT       0x00000001 /* 从共享树剪除多播数据流 */
#define MRTF_SPT       0x00000002 /* 数据流从最短路径树转发了 */
#define MRTF_REG       0x00000004 /* 路由器与源直连，并触发注册过程 */
/* !! 注意: 以上的定义与组播路由管理统一，不能重新定义。
   以上标志位在组项标志改变后要通知路由管理 */

#define MRTF_TIMEROFF  0x00000010 /* 表项定时器关闭 */
#define MRTF_CONNECT   0x00000020 /* 该组存在直连的组成员 */
#define MRTF_PRUNE     0x00000040 /* 出接口列表为空，并且入接口不在出接口表中,设置此标志 */
#define MRTF_RP        0x00000080 /* 入接口朝RP方向 */
#define MRTF_WC        0x00000100 /* (*,G)项 */
#define MRTF_SG        0x00000200 /* (S,G)项 */
#define MRTF_PMBR      0x00000400 /* (*,*,RP)项 */
#define MRTF_ADD2MRTYET	0x00001000 /* 此表项已经下发给mrtmgt */

//#define PIMSM_SSM_RANGE  0x01 /* 组地址在SSM范围 */

typedef enum mrt_action
{
    PIM_ACTION_NOTHING,
    PIM_ACTION_JOIN,
    PIM_ACTION_PRUNE,
    PIM_ACTION_JOIN_RPT,
    PIM_ACTION_PRUNE_RPT,
    PIM_ACTION_END
} MRT_ACTION;

/* 出接口列表类型 */
typedef enum oil_type
{
    EM_OIL_RESULT,
    EM_OIL_PIM,
    EM_OIL_LEAVE,
    EM_OIL_ASSERTED,
    EM_OIL_END

} OIL_TYPE;

typedef int (* ACL_NOTIFY_API)(uint32_t);


///////////////////////////////////////////////////////////////////////////
extern PIMSM_GLOBAL_T g_stPimsm;          /* pim全局变量 */
extern int g_debug_pim;

#define PIM_DEBUG(format,...) if(g_debug_pim) { printf("%s %s @%d: "format, __FILE__, __func__, __LINE__, ##__VA_ARGS__); /*printf("\n");*/ }
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
extern int pimsm_Create(void);
extern int pimsm_Destroy(void);
extern int pimsm_GlobalEnable(void);
extern int pimsm_GlobalDisable(void);
//////////////////////////////////////////////////////////////////////////


#endif
