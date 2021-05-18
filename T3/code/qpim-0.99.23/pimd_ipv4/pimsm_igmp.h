#ifndef _PIMMLD_H_
#define _PIMMLD_H_

#include "pimsm_mrtmgt.h"
#define PIMSM_IF_IGMP_MRT_RESOURCE_MAX 10

typedef enum pimsm_record_type_t
{
    PIMSM_IF_IGMPv1 = 0,
    PIMSM_IF_IGMPv2,
    PIMSM_IF_INCLUDE,
    PIMSM_IF_EXCLUDE
} PIMSM_RECORD_TYPE_T;

typedef struct pimsm_igmp_mrt_resource_t
{
    struct pimsm_igmp_mrt_resource_t *prev;
    struct pimsm_igmp_mrt_resource_t *next;
    VOS_IP_ADDR src_addr; /* if (*,G) , address is 0.0.0.0 */
    VOS_IP_ADDR grp_addr;
    uint8_t type; /* (*,G) OR (S,G) OR (S,G,rpt) see: PIMSM_MRT_TYPE_WC , PIMSM_MRT_TYPE_SG , PIMSM_MRT_TYPE_SGRPT*/
    struct pimsm_oif *pstOilist;
} PIMSM_IGMP_MRT_RESOURCE_T;

/* 记录由于IGMP 本地成员加入而要占用的组播路由表项 */
typedef struct pimsm_igmp_mrt_resource_count_t
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResourceList;
    uint32_t dwIfMrtResourceMax;
} PIMSM_IGMP_MRT_RESOURCE_COUNT_T;

extern int pimsm_IgmpGrpMemberProc(uint32_t ifindex, void *p, PIMSM_IGMP_MSG_TYPE_T emType);
int pimsm_IgmpInit(void);
int pimsm_DestroyAllIgmpMrtResEntry(void);

#endif
