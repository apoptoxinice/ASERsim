#ifndef _PIMBOOTSTRAP_H
#define _PIMBOOTSTRAP_H

#include <zebra.h>
#include "thread.h"
#include "vty.h"

#include "pimsm.h"
#include "pimsm_datagramproc.h"

#define MAX_RP_NUM 10
#define PIM_TIMER_SEND_INTERVAL 60

#define PIM_BSR_MSG_HEADLEN		14
#define PIM_CRP_ADV_HEADLEN		8
#define PIM_GROUP_HEADlEN			12
#define PIM_HASH_MSAK_LEN_V6		120
#define PIM_CRP_HOLDTIME			125

//C-BSR enable and state is Candidate BSR
#define PIM_CBSR_STATE_CANDIDATE_BSR 0
//C-BSR enable and state is Pending BSR
#define PIM_CBSR_STATE_PENDING_BSR 1
//C-BSR enable and state is Elected BSR
#define PIM_CBSR_STATE_ELECTED_BSR 2
//C-BSR disable and state is No Info
#define PIM_CBSR_STATE_NO_INFO 3
//C-BSR disable and state is Accept Prefered
#define PIM_CBSR_STATE_ACCEPT_PREFERED 4
//C-BSR disable and state is Accept Any
#define PIM_CBSR_STATE_ACCEPT_ANY 5

#define PIM_TIMER_SZ_TIMEOUT 1300
#define PIM_TIMER_BS_TIMEOUT 130
#define PIM_TIMER_BS_PERIOD 60
#define PIM_TIMER_BS_RAND_OVERRIDE 10

#if 0
struct pimsm_encoded_unicast_addr
{
    uint8_t		family;
    uint8_t		encoding_type;
    VOS_IPV6_ADDR	        unicast_addr;
} __attribute__((packed));
#endif

struct pimsm_encoded_group_addr
{
    uint8_t		family;
    uint8_t		encoding_type;
    uint8_t 		b:1;
    uint8_t		reserved:6;
    uint8_t 		z:1;
    uint8_t		prefixlen;
    VOS_IPV6_ADDR	        group_addr;
} __attribute__((packed));

struct pimsm_rp
{
    struct pimsm_encoded_unicast_addr	rp_addr;
    uint16_t	hold_time;
    uint8_t	rp_priority;
    uint8_t	reserved;
} __attribute__((packed));

struct pimsm_rpgroup
{
    struct pimsm_encoded_group_addr	group_addr;
    uint8_t			rp_count;
    uint8_t			rp_frag_count;
    uint16_t			reserved;
    struct pimsm_rp		rp_addr[0];
} __attribute__((packed));


struct pimsm_bootstrap
{
    uint8_t		pimsm_ver:4;
    uint8_t		type:4;
    uint8_t		reserved;
    uint16_t		checksum;
    uint16_t		fragment_tag;
    uint8_t		hash_masklen;
    uint8_t		bsr_priority;
    struct pimsm_encoded_unicast_addr stBsrAddr;
    struct pimsm_rpgroup 	astRpAddrList[0];
} __attribute__((packed));

struct pimsm_cpradv
{
    uint8_t		pimsm_ver:4;
    uint8_t		type:4;
    uint8_t		reserved;
    uint16_t		checksum;
    uint8_t		prefix_count;
    uint8_t		priority;
    uint16_t		hold_time;
    struct pimsm_encoded_unicast_addr	rp_addr;
    struct pimsm_encoded_group_addr	group_addr[0];
} __attribute__((packed));

#if 1
struct pimsm_timer_rp_para
{
    long                timer_id;
    VOS_IPV6_ADDR	        unicast_addr;
};
#endif

struct pimsm_group_rp
{
    struct pimsm_encoded_group_addr   	group_addr;
    uint8_t 				rp_count;
    uint8_t 				rp_frag_count;
    uint16_t				reserved;
    struct pimsm_rp			rp_list[MAX_RP_NUM];
    struct thread   			*t_rp_keep_timer[MAX_RP_NUM];
    long				timer_id[MAX_RP_NUM];
};

struct pimsm_bsr_msg
{
    struct pimsm_bootstrap *p_msg;
    uint32_t len;
};

struct pimsm_crpadv_msg
{
    struct pimsm_cpradv *p_msg;
    uint32_t len;
};

struct pimsm_rp_election_result_list
{
    struct pimsm_encoded_group_addr group;
    struct pimsm_encoded_unicast_addr stRp;
    struct pim_rp_election_result_list *pstPrev;
    struct pim_rp_election_result_list *pstNext;
};

struct pimsm_rp_list
{
    struct pimsm_group_rp rp_group;
    struct pimsm_rp_list *pstPrev;
    struct pimsm_rp_list *pstNext;
};

struct pimsm_crp_group_policy_list
{
    struct pimsm_crp_group_policy_list *pstNext;
    VOS_IPV6_ADDR group_addr;
    uint16_t group_masklen;
    uint16_t hold_time;
};

int pim_BootstrapInit(void);
int pim_BsrRpSearch(VOS_IPV6_ADDR *pstGroupAddr, VOS_IPV6_ADDR *pstRpAddr);
int pim_SendBootstrapMsg(VOS_IPV6_ADDR *pstDstAddr);
int pim_ReceiveCandRpAdv(uint32_t ifindex, VOS_IPV6_ADDR *pstSrc, uint8_t *pim_msg, uint32_t pim_msg_size );
int pim_ReceiveBootstrap(uint32_t ifindex, VOS_IPV6_ADDR *pstSrc, uint8_t *pim_msg, uint32_t pim_msg_size );
int pim_TimeoutCrpAdv(struct thread *t);
int pim_TimeoutRpKeep(struct thread *t);
int pim_BootstrapCbsrEnable(uint32_t ifindex, uint8_t priority);
int pim_BootstrapCbsrDisable(void);
int pim_BootstrapCrpEnable(uint32_t ifindex, uint8_t priority);
int pim_BootstrapCrpDisable(void);
int pim_CrpGroupPolicyAdd(VOS_IPV6_ADDR *pstGrpAddr, uint32_t dwMaskLen);
int pim_CrpGroupPolicyDel(VOS_IPV6_ADDR *pstGrpAddr, VOS_IPV6_ADDR *pstGrpMask);
int pim_BootstrapBsrShow(struct vty *vty);
int pim_BootstrapRpShow(struct vty *vty);
int pimsm_bootstrapconfig(struct vty *vty);

#endif
