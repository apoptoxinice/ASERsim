#ifndef _PIMTIMER_H_
#define _PIMTIMER_H_

#include <zebra.h>
#include "thread.h"

#include "pimsm_mrtmgt.h"


struct thread *g_pimsm_mrt_manage_timer;
struct thread *g_pimsm_msg_pim2rtmgt_timer;
/* define pim timer type */

#define PIMSM_TIMER_TYPE_HELLO 0x00000001 /* 0-5s, 30s */
#define PIMSM_TIMER_NEIGHBOR_EXPIRY 0x00000002 /* 3.5*HelloPeriod(30s) */
#define PIMSM_TIMER_TYPE_BSR_EXPIRE 0x00000012
#define PIMSM_TIMER_TYPE_CRP_ADV 0x00000013
#define PIMSM_TIMER_TYPE_RP_KEEP 0x00000014
#define PIMSM_TIMER_TYPE_REGISTER_STOP 0x00000015 /* (S,G) Register Stop Timer */
#define PIMSM_TIMER_TYPE_KEEPALIVE 0x00000016 /* (S,G) OR (S,G,rpt) Keepalive Timer */
#define PIMSM_TIMER_TYPE_JOIN 0x00000017 /* (S,G) OR (*,G) Upstream Join Timer */
#define PIMSM_TIMER_TYPE_OVERRIDE 0x00000018 /* (S,G) OR (*,G) Upstream Join Timer */
#define PIMSM_TIMER_TYPE_PRUNE_PENDING 0x00000019 /* (S,G) OR (*,G) OR (S,G,rpt) Downstream Prune-Pending Timer */
#define PIMSM_TIMER_TYPE_DOWNIF_EXPIRY 0x00000020 /* (S,G) OR (*,G) OR (S,G,rpt) Downstream Expiry Timer */
#define PIMSM_TIMER_TYPE_ASSERT 0x00000021 /* (S,G) OR (*,G) Assert Timer */
#define PIMSM_TIMER_TYPE_MRT_EXPIRY 0x00000022 /* (*,G) OR (S,G) OR (S,G,rpt) Entry Delete Timer */

#define PIMSM_TIMER_TYPE_MSG_REPOST 0x00010004 /* 1s cycle */ /* failed message repost timer */
#define PIMSM_TIMER_TYPE_MRT_MANAGE 0x00010005 /* 1s cycle */ /* multicast router table manage Timer */


#define PIMSM_TIMER_VALUE_TRIGGER_HELLO_DELAY 5 /* 5s */

//===================================================================





/* 模拟MLD周期上报定时器 */
#define PIM_TIMER_MLD_REPORT               0x0000000f


/* PIM protocol timers (in seconds) */
#define PIM_HELLO_PERIOD               30
#define PIM_TRIGGER_HELLO_DELAY        5
#define PIM_HELLO_HOLDTIME             (3.5 * PIM_HELLO_PERIOD)
#define PIM_REGISTER_SUPPRESSION       60
#define PIM_REGISTER_SUPPRESSION_AUX   5
#define PIM_JOIN_PRUNE_PERIOD          60
#define PIM_JOIN_PRUNE_HOLDTIME        (3.5 * PIM_JOIN_PRUNE_PERIOD)
#define PIM_ASSERT_TIMEOUT             180
#define PIM_ENTRY_HOLDTIME             210
#define PIM_PROPAGATION_DELAY          (0.5 * 1000) /*0.5m*/
#define PIM_OVERRIDE_INTERVAL          (2.5 * 1000) /*2.5m*/
//#define PIM_ASSERT_OVERRIDE_INTERVAL   3

#define PIM_MLD_REPORT_PERIOD          PIM_JOIN_PRUNE_PERIOD




//===================================================================

struct pimsm_timer_para_neighbor
{
    uint32_t ifindex;
    VOS_IP_ADDR   source_addr;
};

struct pimsm_timer_para_hello
{
    uint32_t ifindex;
    VOS_IP_ADDR neighbor_addr;
};

typedef struct pimsm_timer_para_register_stop_t
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
} PIMSM_TIMER_PARA_REGISTER_STOP_T;

typedef struct pimsm_timer_para_keepalive_t
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) OR (S,G,rpt) */
} PIMSM_TIMER_PARA_KEEPALIVE_T;

typedef struct pimsm_timer_para_mrt_expiry_t
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) OR (S,G,rpt) */
} PIMSM_TIMER_PARA_MRT_EXPIRY_T;

typedef struct pimsm_timer_para_join_t
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) */
    uint32_t ifindex;
} PIMSM_TIMER_PARA_JOIN_T;

typedef struct pimsm_timer_para_override_t
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (S,G,rpt) */
    uint32_t ifindex;
} PIMSM_TIMER_PARA_OVERRIDE_T;

struct pimsm_timer_para_prune_pending
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) OR (S,G,rpt) */
    uint32_t ifindex;
};

struct pimsm_timer_para_downif_expiry
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) OR (S,G,rpt) */
    uint32_t ifindex;
};

struct pimsm_timer_para_assert
{
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G)  OR (S,G,rpt) */
    uint32_t ifindex; /* interface id */
};

int Pimsm_TimerCancel(uint32_t *p_timer_id, uint32_t timer_type);
uint32_t Pimsm_TimerCreate(uint32_t timer_type, uint32_t seconds, void *p_para, uint32_t para_len);
int pimsm_TimerOutProc(m_VosTmServToPimsm_t *pstTimeOutMsg);

int Pimsm_TimerReset(uint32_t timer_id, uint32_t timer_type);
int Pimsm_TimerGetRemain(uint32_t timer_id);

int on_pimsm_hello_send(struct thread *t);
int pimsm_on_neighbor_timer(struct thread *t);
int pimsm_TimeroutAssert(struct thread *t);
int pimsm_TimeroutDownIfExpiry(struct thread *t);
int pimsm_TimeroutPrunePending(struct thread *t);
int pimsm_TimeroutJoin(struct thread *t);
int pimsm_TimeroutOverride(struct thread *t);
int pimsm_TimeroutKeepAlive(struct thread *t);
int pimsm_TimeroutMrtExpiry(struct thread *t);
int pimsm_TimeroutRegisterStop(struct thread *t);
int pimsm_TimeroutMsgRepost(struct thread *t);
int pimsm_TimeroutMrtManage(struct thread *t);
#endif
