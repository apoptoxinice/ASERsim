#ifndef _PIM_REGISTER_H
#define _PIM_REGISTER_H
#include <zebra.h>
#include "thread.h"

#include "pimsm.h"
#include "pimsm_mrtmgt.h"

#define PIMSM_TIMER_VALUE_REGISTER_SUPPRESSION (60) /* 60s */
#define PIMSM_TIMER_VALUE_REGISTER_PROBE (5) /* 5s */
#define PIMSM_TIMER_VALUE_RP_KEEPALIVE_PERIOD (3*PIMSM_TIMER_VALUE_REGISTER_SUPPRESSION+PIMSM_TIMER_VALUE_REGISTER_PROBE)

struct ipv4
{
    char	ip_verlen;	/* IP version & header length (in longs)*/
    char	ip_tos;		/* type of service			*/
    short	ip_len;		/* total packet length (in octets)	*/
    short	ip_id;		/* datagram id				*/
    short 	ip_fragoff;	/* fragment offset (in 8-octet's)	*/
    char	ip_ttl;		/* time to live, in gateway hops	*/
    char	ip_proto;	/* IP protocol (see IPT_* above)	*/
    short	ip_cksum;	/* header checksum 			*/
    /* modified by wming for compiling convenience */
    int 	ip_src;		/* IP address of source			*/
    int	ip_dst;		/* IP address of destination		*/
    char	ip_data[1];	/* variable length data			*/
};

typedef enum pimsm_could_register_t
{
    PimsmRegCheckCouldRegister = 0,
    PimsmRegCheckCouldNotRegister,
    PimsmRegCheckIamDrAndRp
} PIMSM_COULD_REGISTER_T;

typedef enum pimsm_reg_event_t
{
    PimsmRegEventRegStopTimerExpires = 0,
    PimsmRegEventCouldRegToTrue,
    PimsmRegEventCouldRegToFalse,
    PimsmRegEventRegStopRecv,
    PimsmRegEventRpChanged
} PIMSM_REG_STATE_MACHINE_EVENT_T;

#define PIMSM_REG_STATE_STR "NoInfo","Join","JoinPending","Prune"
typedef enum pimsm_reg_state_t
{
    PimsmRegStateNoInfo = 0,
    PimsmRegStateJoin,
    PimsmRegStateJoinPending,
    PimsmRegStatePrune,
    PimsmRegStateEnd
} PIMSM_REG_STATE_T;

typedef struct pimsm_reg_tunnel_t
{
    VOS_IP_ADDR rp_addr;
} PIMSM_REG_TUNNEL_T;

typedef struct pimsm_reg_state_machine_t
{
    PIMSM_REG_STATE_T emRegisterState;
    PIMSM_REG_TUNNEL_T *pstRegisterTunnel;
    uint32_t tmRegisterTimer;
#if 1
    struct thread *t_pimsm_register_timer;
#endif
} PIMSM_REG_STATE_MACHINE_T;

PIMSM_COULD_REGISTER_T pimsm_CouldRegister(VOS_IP_ADDR *src_addr, VOS_IP_ADDR *pstGrpAddr, uint32_t ifindex);

uint8_t pimsm_AcceptRegist(VOS_IP_ADDR *pstSrc);

int pimsm_SendRegisterStop(VOS_IP_ADDR *src_addr, VOS_IP_ADDR *pstDstAddr, VOS_IP_ADDR *pstInnerSrc, VOS_IP_ADDR *pstInnerGrp);

//int pimsm_RegisterStateMachineEventProc(struct pimsm_mrt_entry *src_grp_entry, PIMSM_REG_STATE_MACHINE_EVENT_T emRegisterEventType);

int pimsm_DataForwardingOnRegTunnel(const char *pkt, uint32_t len, PIMSM_REG_TUNNEL_T *pstRegTunnel);
const char *pimsm_GetRegStateString(PIMSM_REG_STATE_T emState);
#endif
