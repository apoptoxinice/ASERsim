#ifndef _PIMMRTMGT_H_
#define _PIMMRTMGT_H_

#include <hash.h>
#include "pimsm_register.h"
#include "pimsm_jp.h"
#include "pimsm_assert.h"
#include "pimsm_msg.h"

#include "pimsm.h"
#include "vty.h"

typedef __u32       if_mask;
#define NIFBITS (sizeof(if_mask) * 8)        /* bits per mask */

#define IF_SET(n, p)    ((p)->ifs_bits[(n)/NIFBITS] |= (1 << ((n) % NIFBITS)))
#define IF_CLR(n, p)    ((p)->ifs_bits[(n)/NIFBITS] &= ~(1 << ((n) % NIFBITS)))
#define IF_ISSET(n, p)  ((p)->ifs_bits[(n)/NIFBITS] & (1 << ((n) % NIFBITS)))
#define IF_COPY(f, t)   bcopy(f, t, sizeof(*(f)))
#define IF_ZERO(p)      bzero(p, sizeof(*(p)))

void init_sin6(struct sockaddr_in6 *sin6);

/* Period after last (S,G) data packet during which (S,G) Join state will be maintained even in the absence of (S,G) Join messages.*/
#define PIMSM_TIMER_KEEPALIVE_PERIOD (210) /* default: 210s */

/* for hash tables */
#define HASHTABSIZE     2048

#define hash_traversal_start(hash, contents) \
	{\
		struct hash_backet * pHashBacket;\
		int i = 0;\
		for(i = 0; i < HASHTABSIZE; ++i) {\
			pHashBacket = hash->index[i];\
			for(; NULL != pHashBacket; pHashBacket = pHashBacket->next) {\
				contents = pHashBacket->data;

#define hash_traversal_end() \
			}\
		}\
	}

/* 删除出接口的返回值 */
typedef enum del_oif_result
{
    EM_SUCCESS_DEL,
    EM_CANCEL_TYPE,
    EM_NO_FIND,
    EM_DEL_ERROR
} DEL_OIF_RESULT;

struct pimsm_rpf
{
    struct pimsm_rpf *next;
    struct pimsm_rpf *prev;
    VOS_IPV6_ADDR dest_addr;
    uint32_t rpf_if;
    VOS_IPV6_ADDR rpf_nbr_addr;
    uint32_t preference;
    uint32_t metric;
};

#define PIMSM_INHERITED_OIF 0x00
#define PIMSM_IMMEDIATE_OIF 0x01
struct pimsm_oif
{
    struct pimsm_oif *next;
    struct pimsm_oif *prev;
    uint32_t ifindex;      /* output interface number */
};

/* upstream and downstream general interface */
struct pimsm_updownstream_if_entry
{
    struct pimsm_updownstream_if_entry *next;
    struct pimsm_updownstream_if_entry *prev;
    uint32_t ifindex; /* downstream: output interface number. upstream: incoming interface number to RP or S. */

    /* upstream */
    VOS_IPV6_ADDR up_stream_nbr; /* upstream neighbor address, just for upstream interface */
    struct pimsm_upstream_state_machine stUpstreamStateMachine; /* just upstream */

    /* downstream */
    uint8_t byLocalReceiverInclude; /* TRUE: exist IGMP report local receiver.  FALSE: no IGMP report local receiver. */
    struct pimsm_downstream_state_machine down_stream_state_mchine; /* just downstream */
};


/* assert interface */
struct pimsm_assert_if
{
    struct pimsm_assert_if *next;
    struct pimsm_assert_if *prev;
    uint32_t ifindex;     /* assert interface number */
    struct pimsm_assert_state_machine stAssertStateMachine;
};

/*soruce entry*/
struct pimsm_src_entry
{
    VOS_IPV6_ADDR address;  /* source address */
    struct pimsm_mrt_entry *pstSrcMrtLink; /* link to the (S,G) routing entries */
};

/* group entry */
#define PIMSM_SM_RANGE 0
#define PIMSM_SSM_RANGE 1
struct pimsm_grp_entry
{
    uint8_t		type;    /* SSM range or SM range */
    VOS_IPV6_ADDR		address;  /* subnet group of multicasts */
    VOS_IPV6_ADDR		rp_addr;       /* The IP address of the RP */
    struct pimsm_mrt_entry *pstStarMrtLink;    /* Pointer to the (*,G) routing entry */
    struct pimsm_mrt_entry *pstSrcMrtLink; /* link to sub (S,G) routing entries */
};

/*(*,G) and (S,G) entry */
/* Upstream Interface */
#define PIMSM_UPSTREAM_IF 0
#define PIMSM_DOWNSTREAM_IF 1
/* Mrt Entry Type */
#define PIMSM_MRT_TYPE_WC 0 /* (*,G) entry */
#define PIMSM_MRT_TYPE_SG 1 /* (S,G) entry */
#define PIMSM_MRT_TYPE_SGRPT 2 /* (S,G,rpt) entry */
#define PIMSM_MRT_TYPE_PMBR 3 /* (*,*,RP) entry */
/* Mrt Entry Flag */
#define PIMSM_MRT_FLAG_STR "SPT","REG"
#define PIMSM_MRT_FLAG_NUL 0x00000000
#define PIMSM_MRT_FLAG_SPT 0x00000001 /* 当完成RPT到SPT的切换后, (S,G)设置此标志位, 在切换过程中, 数据流按照(*,G)转发*/
#define PIMSM_MRT_FLAG_REG 0x00000002 /* 在RP上的(S,G) 表项设置此标志表示收到与源直连的DR 的对于源S 的注册消息*/
/* RPF check */
#define PIMSM_MRT_RPF_NO_CHECK 0
#define PIMSM_MRT_RPF_CHECK_IN_IF 1

struct pimsm_mrt_entry
{
    struct pimsm_mrt_entry *samegrpnext; /* link to next entry of same group  */
    struct pimsm_mrt_entry *samegrpprev; /* link to prev entry of same group  */
    struct pimsm_mrt_entry *samesrcnext; /* link to next entry of same source */
    struct pimsm_mrt_entry *samesrcprev; /* link to prev entry of same source */

    struct pimsm_grp_entry    *group; /* pointer to group entry */
    struct pimsm_src_entry     *source; /* pointer to source entry */

    struct pimsm_updownstream_if_entry upstream_if;
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_assert_if *pimsmassert_if;
    struct pimsm_oif *oil;

    uint8_t		type; /* (*,G) (S,G) (S,G,rpt) (*,*,RP) */
    uint32_t		flags; /* the  flags information */

    struct thread *t_pimsm_keep_alive_timer;

    uint32_t packet_match_count; /* For tmKeepAliveTimer */

    PIMSM_REG_STATE_MACHINE_T stRegStateMachine;/* Register State Machine at a DR, just (S,G) */

    uint32_t           metric;         /* entry metric */
    uint32_t           preference;     /* metric preference */

    int64_t            creation; /* timestamp of creation */

    uint8_t byRpfCheck; //0: no check , 1: check in interface

    uint8_t bIsCopyToCpu; /*TRUE: 表项存在copy to cpu的出接口, FALSE: 表项不存在copy to cpu的出接口 */

    uint8_t valid; //TRUE: 表项已经下发给RTMGT, FALSE: 表项没有下发给RTMGT 只存在于pimsm的软件表里
    struct thread *t_pimsm_delay_timer;
};

struct pimsm_mrt_hardware_entry
{
    struct pimsm_mrt_hardware_entry *prev;
    struct pimsm_mrt_hardware_entry *next;

    uint8_t type; /* (*,G) (S,G) (S,G,rpt) (*,*,RP) */

    VOS_IPV6_ADDR src_addr;
    VOS_IPV6_ADDR grp_addr;

    uint32_t iif;
    struct pimsm_oif *oil;

    //sangmeng add
    int    oil_size;
    uint8_t bIsCopyToCpu;

    uint8_t byRpfCheck; /* 0: not check , 1: check in interface */
};


extern void pimsm_InitHash(void);
extern struct pimsm_grp_entry *pimsm_SearchGrpEntry(VOS_IPV6_ADDR *pstGrpAddr);
extern struct pimsm_src_entry *pimsm_SearchSrcEntry(VOS_IPV6_ADDR *src_addr);
extern struct pimsm_mrt_entry *pimsm_SearchMrtEntry(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint8_t type);
extern struct pimsm_mrt_entry *pimsm_CreateMrtEntry(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint8_t type, uint32_t flags);
extern int pimsm_MrtSetValid(struct pimsm_mrt_entry *mrt_entry, uint8_t valid);
extern int pimsm_CheckMrtEntryValid(struct pimsm_mrt_entry *mrt_entry);
extern uint8_t pimsm_SwitchToSptDesired(VOS_IPV6_ADDR *pstGrp);
extern uint8_t pimsm_AssertState(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex);
extern struct pimsm_oif *pimsm_Prunes(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
extern struct pimsm_oif *pimsm_InheritedOlist(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
extern struct pimsm_oif *pimsm_ImmediateOlist(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
extern struct pimsm_rpf *pimsm_SearchRpf(VOS_IPV6_ADDR *pstDstAddr);
extern int pimsm_AddLocalReceiver(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint8_t type, uint32_t ifindex);
extern int pimsm_DelLocalReceiver(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint8_t type, uint32_t ifindex);
extern int pimsm_DelAllLocalReceiver(void);

uint32_t pimsm_RpfInterface(VOS_IPV6_ADDR *pstDstAddr);
uint8_t pimsm_SptBit(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr);
int pimsm_KeepAliveTimerStart(struct pimsm_mrt_entry *src_grp_entry, uint32_t dwTimerValue);
int pimsm_SetCopyToCpu(struct pimsm_mrt_entry *mrt_entry, uint8_t bIsCopy2Cpu);


int pimsm_RegisterStateMachineEventProc(struct pimsm_mrt_entry *src_grp_entry, PIMSM_REG_STATE_MACHINE_EVENT_T emRegisterEventType);
uint8_t pimsm_JoinDesired(struct pimsm_mrt_entry *mrt_entry);
int pimsm_UpdownstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry, uint8_t byUpOrDown, uint32_t ifindex, uint8_t byEventType, struct pimsm_updown_state_machine_event_para *event_para);
struct pimsm_updownstream_if_entry * pimsm_CreateDownstreamIf(VOS_IPV6_ADDR *src_addr,VOS_IPV6_ADDR *pstGrpAddr,uint8_t type,uint32_t flags,uint32_t ifindex);
int pimsm_AssertStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex,uint8_t byEventType,struct pimsm_assert_state_machine_event_para *event_para);
struct pimsm_updownstream_if_entry *pimsm_SearchDownstreamIfByIndex(struct pimsm_updownstream_if_entry *pstDownstreamifHead,uint32_t ifindex);
struct pimsm_assert_if *pimsm_SearchAssertIfByIndex(struct pimsm_assert_if *pstAssertIfHead,uint32_t ifindex);
uint8_t pimsm_AssertMetricInferior(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
uint8_t pimsm_CouldAssert(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
uint8_t pimsm_AssertMetricAcceptable(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
uint8_t pimsm_AssertTrackingDesired(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
uint8_t pimsm_AssertMetricPreferred(struct pimsm_assert_metric *pstTargetMetric,struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);

int pimsm_SetSptBit(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint8_t byIsTrue);
int pimsm_RpfNeighborAddr(struct pimsm_mrt_entry *mrt_entry, VOS_IPV6_ADDR *pstNeighborAddr);
int pimsm_SendJoin(struct pimsm_mrt_entry *mrt_entry,VOS_IPV6_ADDR *pstUpstreamNbrAddr);
int pimsm_FreeOil(struct pimsm_oif *oif);
uint8_t pimsm_LocalReceiverExist (struct pimsm_mrt_entry *mrt_entry);

struct pimsm_oif *pimsm_SearchOifByIndex(struct pimsm_oif *pstOilHead, uint32_t dwOifIndex);
struct pimsm_oif *pimsm_OilSubOil(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2);
struct hash_backet *hash_head (struct hash *hash, int index);
int pimsm_SendPrune(struct pimsm_mrt_entry *mrt_entry,VOS_IPV6_ADDR *pstUpstreamNbrAddr);
void pimsm_DisplayAllGrpEntry(void);
void pimsm_DisplayAllSrcEntry(void);
void pimsm_DisplayAllStarGrpEntry(struct vty *vty);
void pimsm_DisplayAllSrcGrpEntry(void);
uint8_t pimsm_PruneDesired(struct pimsm_mrt_entry *mrt_entry);
int pimsm_SetSptThresholdInfinity(uint8_t byValue);
int pimsm_DestroyDownstreamIf(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
struct pimsm_assert_if *pimsm_CreateAssertIf(VOS_IPV6_ADDR *src_addr,VOS_IPV6_ADDR *pstGrpAddr,uint8_t type,uint32_t flags,uint32_t ifindex);
int pimsm_DestroyAssertIf(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
int pimsm_DestroyAssertIf(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex);
struct pimsm_oif *pimsm_OilAddOil(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2);
struct pimsm_oif *pimsm_OilAddOilFree(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2);
struct pimsm_oif *pimsm_OilSubOilFree(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2);
uint8_t pimsm_LocalReceiverInclude(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex);
struct pimsm_oif *pimsm_Joins(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
struct pimsm_oif *pimsm_PimInclude(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
struct pimsm_oif *pimsm_PimExclude(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
struct pimsm_oif *pimsm_LostAssert(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents);
int pimsm_MrtUpdateMsgRepostProcess(void);
int pimsm_MrtManagePeriod(void);
int pimsm_UpdateRpf(struct rtmgt_to_pimsm *pstNewRpfMsg);
#if 0
int pimsm_ShowRpf(m_CliToPimsm_t *pstCliMsgToPimsm);
#endif
int pimsm_ShowRpf(struct vty *vty,VOS_IPV6_ADDR *pstRpfDestAddr);

int pimsm_DestroyMrtEntry(struct pimsm_mrt_entry *mrt_entry);
uint8_t pimsm_InterfaceWinAssert(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex);

void pimsm_mroute_add_all(void);
void pimsm_mroute_del_all(void);

int pimsm_ShowTopology(struct vty *vty);
int pimsm_UpstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para);
struct pimsm_assert_metric pimsm_MyAssertMetric(struct pimsm_mrt_entry * mrt_entry, uint32_t ifindex);
int pimsm_DownstreamStateMachineEventProc(struct pimsm_mrt_entry *mrt_entry,struct pimsm_updownstream_if_entry *downstream_if,uint8_t byEventType,struct pimsm_updown_state_machine_event_para *event_para);
#endif
