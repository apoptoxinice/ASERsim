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
/*ipv6 header*/
#if  0
struct ipv6hdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8            priority:4,
                    version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8            version:4,
                    priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8            flow_lbl[3];

    __be16          payload_len;
    __u8            nexthdr;
    __u8            hop_limit;

    struct  in6_addr    saddr;
    struct  in6_addr    daddr;
};
#endif
struct ipv6
{
    int     ipv6_ver; // version(4bits) & traffic class(8bits) & flow label(20bits)
    short   ipv6_len; //payload length
    char    ipv6_nexthead; //next header
    char    ipv6_hoplimit; //hop limit
    VOS_IPV6_ADDR   ipv6_src; //source
    VOS_IPV6_ADDR   ipv6_dst; //destination
    char    ipv6_data[0];
} __attribute__((packed));
#define PIMSM_IPV6_HEADER_LEN (40)

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
    VOS_IPV6_ADDR rp_addr;
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

PIMSM_COULD_REGISTER_T pimsm_CouldRegister(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr, uint32_t ifindex);

uint8_t pimsm_AcceptRegist(VOS_IPV6_ADDR *pstSrc);

int pimsm_SendRegisterStop(VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstDstAddr, VOS_IPV6_ADDR *pstInnerSrc, VOS_IPV6_ADDR *pstInnerGrp);

//int pimsm_RegisterStateMachineEventProc(struct pimsm_mrt_entry *src_grp_entry, PIMSM_REG_STATE_MACHINE_EVENT_T emRegisterEventType);

int pimsm_DataForwardingOnRegTunnel(const char *pkt, uint32_t len, PIMSM_REG_TUNNEL_T *pstRegTunnel);
const char *pimsm_GetRegStateString(PIMSM_REG_STATE_T emState);
#endif
