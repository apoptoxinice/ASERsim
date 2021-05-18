#include "pimsm_define.h"
#if INCLUDE_PIMSM

#include <zebra.h>
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "vty.h"

#include "pimd.h"

#include "vos_types.h"
#include "pimsm_bootstrap.h"
#include "pimsm_msg.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"
#include "pimsm_rp.h"

int pimsm_bsr_timer(struct thread *t);
int pim_HashFunction(VOS_IP_ADDR *group, VOS_IP_ADDR *rp, int masklen);
int pim_CrpGroupPolicyListShow(void);

//C-RP and C-BSR information
struct pimsm_encoded_unicast_addr g_root_cbsr_id;
struct pimsm_encoded_unicast_addr g_root_crp_id;
uint8_t g_root_cbsr_priority;
uint32_t g_root_cbsr_ifindex;
uint8_t g_root_crp_priority;
uint32_t g_root_crp_ifindex;
uint8_t g_cbsr_enable = FALSE;
uint8_t g_crp_enable = FALSE;


#if 1//sangmeng add for bsr timer
struct thread *g_t_bsr_timer = NULL;
#endif


#if 1//sangmeng add for rp timer
struct thread *g_t_rp_timer = NULL;
#endif
//Candidate-BSR State Machine
uint8_t g_root_bsr_state = PIM_CBSR_STATE_NO_INFO;

//elected BSR information
struct pimsm_encoded_unicast_addr g_bsr_addr;
uint8_t g_bsr_hash_masklen;
uint8_t g_bsr_priority;

//Bootstrap and C-RP-ADV message
struct pimsm_crpadv_msg g_crp_msg;
struct pimsm_bsr_msg g_bsr_msg;

//C-RP policy
struct pimsm_crp_group_policy_list *g_crp_group_policy_list = NULL;
//RP set
struct pimsm_rp_list *g_rp_set_list = NULL;
//RP election result list
struct pimsm_rp_election_result_list *g_rp_election_result_list_old = NULL;
struct pimsm_rp_election_result_list *g_rp_election_result_list_new = NULL;

//extern
extern struct pimsm_interface_entry *g_pimsm_interface_list;
extern PIMSM_GLOBAL_T g_stPimsm;

static int pim_OriginateBootstrapMsg(void);

int pim_BootstrapInit(void)
{
    memset(&g_root_cbsr_id, 0, sizeof(g_root_cbsr_id));
    memset(&g_root_crp_id, 0, sizeof(g_root_cbsr_id));

    return VOS_OK;
}

static uint8_t pim_iAmBsr()
{
    return ((g_bsr_addr.unicast_addr.u32_addr[0] == g_root_cbsr_id.unicast_addr.u32_addr[0]) && (g_cbsr_enable));
}

static uint8_t pim_iBecomeBsr(void)
{
    g_bsr_addr = g_root_cbsr_id;
    g_bsr_priority = g_root_cbsr_priority;
    g_bsr_hash_masklen = PIM_HASH_MSAK_LEN_V4;
    //pim_GrpRpTableClean();
    pim_OriginateBootstrapMsg();
    pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);
    g_root_bsr_state = PIM_CBSR_STATE_ELECTED_BSR;

    if (g_t_bsr_timer)
        THREAD_OFF(g_t_bsr_timer);

    THREAD_TIMER_ON(master, g_t_bsr_timer,
                    pimsm_bsr_timer,
                    NULL, PIM_TIMER_BS_PERIOD);

    return VOS_OK;
}

int pim_HashFunction(VOS_IP_ADDR *group, VOS_IP_ADDR *rp, int masklen)
{
    VOS_IP_ADDR mask;
    unsigned long tmp1;
    unsigned long tmp2;
    unsigned long tmp3;
    int value = -1;

    if((NULL == group) || (NULL == rp))
    {
        return value;
    }

    MASKLEN_TO_MASK6(masklen, mask);

    tmp1 = ntohl(group->u32_addr[0] & mask.u32_addr[0]);
    tmp2 = ntohl(rp->u32_addr[0]);
    tmp3 = (unsigned long)1 << 31;

    //Value(G,M,C(i))=   (1103515245 * ((1103515245 * (G&M)+12345) XOR C(i)) + 12345) mod 2^31
    //where C(i) is the RP address and M is a hash-mask.
    value = (1103515245UL * ( (1103515245UL * (tmp1) + 12345UL) ^ tmp2 ) + 12345UL) % tmp3;

    return value;
}

int pim_BsrRpSearch(VOS_IP_ADDR *pstGroupAddr, VOS_IP_ADDR *pstRpAddr)
{
    struct pimsm_rp_list *pstRpGrpListNode = NULL;
    struct pimsm_encoded_unicast_addr rp_addr;
    struct pimsm_rp_list *pstSearchEntry = NULL;
    uint16_t wMaskLen = 0;
    int res = VOS_OK;
    int find = FALSE;
    int hash_value1;
    int hash_value2;
    int priority = 0;
    int i;

    if((NULL == pstRpAddr) || (NULL == pstGroupAddr))
    {
        return VOS_ERROR;
    }

    memset(pstRpAddr, 0, sizeof(VOS_IP_ADDR));

    pstRpGrpListNode = g_rp_set_list;
    while(pstRpGrpListNode)
    {
        if (pim_MatchPrefix(pstGroupAddr, &pstRpGrpListNode->rp_group.group_addr.group_addr, pstRpGrpListNode->rp_group.group_addr.prefixlen)
                && (wMaskLen <= pstRpGrpListNode->rp_group.group_addr.prefixlen) )
        {
            pstSearchEntry = pstRpGrpListNode;
            wMaskLen = pstRpGrpListNode->rp_group.group_addr.prefixlen;
            find = TRUE;
        }

        pstRpGrpListNode = pstRpGrpListNode->pstNext;
    }

    if(find)
    {
        for(i = 0; i < pstSearchEntry->rp_group.rp_count; ++i)
        {
            if((0 == i) || (priority > pstSearchEntry->rp_group.rp_list[i].rp_priority))
            {
                memcpy(&rp_addr, &pstSearchEntry->rp_group.rp_list[i].rp_addr, sizeof(rp_addr));
                priority = pstSearchEntry->rp_group.rp_list[i].rp_priority;
            }
            else if(priority == pstSearchEntry->rp_group.rp_list[i].rp_priority)
            {
                hash_value1 = pim_HashFunction(pstGroupAddr, &rp_addr.unicast_addr, g_bsr_hash_masklen);
                hash_value2 = pim_HashFunction(pstGroupAddr,
                                               &pstSearchEntry->rp_group.rp_list[i].rp_addr.unicast_addr,
                                               g_bsr_hash_masklen);
                if((hash_value1 < 0) || (hash_value2 < 0))
                {
                    memset(&rp_addr, 0, sizeof(rp_addr));
                    res = VOS_ERROR;
                }
                else if(hash_value1 < hash_value2)
                {
                    memcpy(&rp_addr, &pstSearchEntry->rp_group.rp_list[i].rp_addr, sizeof(rp_addr));
                }
                else if(hash_value1 == hash_value2)
                {
                    if(rp_addr.unicast_addr.u32_addr[0] < pstSearchEntry->rp_group.rp_list[i].rp_addr.unicast_addr.u32_addr[0])
                    {
                        memcpy(&rp_addr, &pstSearchEntry->rp_group.rp_list[i].rp_addr, sizeof(rp_addr));
                    }
                }
            }
        }
    }
    else
    {
        res = VOS_ERROR;
    }

    memcpy(pstRpAddr, &rp_addr.unicast_addr, sizeof(*pstRpAddr));
    return res;
}

static int pim_GrpRpTableAddEntry(struct pimsm_group_rp * pstGroupRps)
{
    struct pimsm_rp_list *node;
    struct pimsm_rp_list *tmp = NULL;
    struct pimsm_timer_rp_para *rp_para;
    struct timeval now;
    uint8_t priority;
    uint8_t findrp;
    int iRpCount;
    int i;
    int j;

    if (NULL == pstGroupRps)
    {
        return VOS_ERROR;
    }

    rp_para = XMALLOC(MTYPE_PIM_RP_PARA, sizeof(struct pimsm_timer_rp_para));
    memset(rp_para, 0, sizeof(struct pimsm_timer_rp_para));

    quagga_gettime (QUAGGA_CLK_MONOTONIC, &now);

    //search the same group scope
    tmp = g_rp_set_list;
    while (NULL != tmp)
    {
        if (0 == memcmp(&tmp->rp_group.group_addr,
                        &pstGroupRps->group_addr,
                        sizeof(tmp->rp_group.group_addr)))
        {
            break;
        }
        tmp = tmp->pstNext;
    }

    if (NULL != tmp)
    {
        //printf("pim_GrpRpTableAddEntry: GRP table find group entry.\n");
        struct pimsm_timer_rp_para *rp_para = NULL;
        iRpCount = tmp->rp_group.rp_count;
        for(i = 0; i < pstGroupRps->rp_count; ++i)
        {
            findrp = FALSE;
            for(j = 0; j < tmp->rp_group.rp_count; ++j)
            {
                if(tmp->rp_group.rp_list[j].rp_addr.unicast_addr.u32_addr[0] == pstGroupRps->rp_list[i].rp_addr.unicast_addr.u32_addr[0])
                {
                    findrp = TRUE;
                    break;
                }
            }

            rp_para = XMALLOC(MTYPE_PIM_RP_PARA, sizeof(struct pimsm_timer_rp_para));
            memset(rp_para, 0, sizeof(struct pimsm_timer_rp_para));
            if(findrp)
            {
                priority = tmp->rp_group.rp_list[j].rp_priority;
                //printf("pim_GrpRpTableAddEntry: find the same rp entry.\n");
                memcpy(&tmp->rp_group.rp_list[j], &pstGroupRps->rp_list[i], sizeof(struct pimsm_rp));

                if (tmp->rp_group.t_rp_keep_timer[j])
                    THREAD_OFF(tmp->rp_group.t_rp_keep_timer[j]);


                tmp->rp_group.timer_id[j] = rp_para->timer_id = now.tv_sec;
                rp_para->unicast_addr.u32_addr[0] = tmp->rp_group.rp_list[j].rp_addr.unicast_addr.u32_addr[0];
                THREAD_TIMER_ON(master, tmp->rp_group.t_rp_keep_timer[j],
                                pim_TimeoutRpKeep,
                                rp_para, ntohs(tmp->rp_group.rp_list[j].hold_time));

                if(priority != pstGroupRps->rp_list[i].rp_priority)
                {
                    pimsm_RpChangeCheck(&tmp->rp_group.group_addr.group_addr, tmp->rp_group.group_addr.prefixlen);
                }
            }
            else
            {
                //printf("pim_GrpRpTableAddEntry: not find the same rp entry.\n");
                if(tmp->rp_group.rp_count >= MAX_RP_NUM)
                {
                    //printf("pim_GrpRpTableAddEntry: rp table for this group is full.\n");
                    return VOS_ERROR;
                }
                memcpy(&tmp->rp_group.rp_list[iRpCount], &pstGroupRps->rp_list[i], sizeof(struct pimsm_rp));

                tmp->rp_group.timer_id[iRpCount] = rp_para->timer_id = now.tv_sec;
                rp_para->unicast_addr.u32_addr[0] = tmp->rp_group.rp_list[iRpCount].rp_addr.unicast_addr.u32_addr[0];
                THREAD_TIMER_ON(master, tmp->rp_group.t_rp_keep_timer[iRpCount],
                                pim_TimeoutRpKeep,
                                rp_para, ntohs(tmp->rp_group.rp_list[iRpCount].hold_time));

                iRpCount++;

                pimsm_RpChangeCheck(&tmp->rp_group.group_addr.group_addr, tmp->rp_group.group_addr.prefixlen);
            }
        }
        tmp->rp_group.rp_count = iRpCount;
        tmp->rp_group.rp_frag_count = iRpCount;
    }
    else
    {
        //printf("pim_GrpRpTableAddEntry: GRP table not find group entry.\n");
        //create a new entry
        if(pstGroupRps->rp_count != 0)
        {
            node = XMALLOC(MTYPE_PIM_RP_SET_LIST_NODE, sizeof(*node));
            if (NULL == node)
            {
                return VOS_ERROR;
            }
            memcpy(&node->rp_group, pstGroupRps, sizeof(node->rp_group));
            if (g_rp_set_list != NULL)
            {
                g_rp_set_list->pstPrev = node;
            }
            node->pstNext = g_rp_set_list;
            node->pstPrev = NULL;
            g_rp_set_list = node;

            struct pimsm_timer_rp_para *rp_para2 = NULL;
            for(i = 0; i < node->rp_group.rp_count; ++i)
            {
                rp_para2 = XMALLOC(MTYPE_PIM_RP_PARA, sizeof(struct pimsm_timer_rp_para));
                memset(rp_para2, 0, sizeof(struct pimsm_timer_rp_para));

                node->rp_group.timer_id[i] = rp_para2->timer_id = now.tv_sec;
                rp_para2->unicast_addr.u32_addr[0] = node->rp_group.rp_list[i].rp_addr.unicast_addr.u32_addr[0];
                THREAD_TIMER_ON(master, node->rp_group.t_rp_keep_timer[i],
                                pim_TimeoutRpKeep,
                                rp_para2, ntohs(node->rp_group.rp_list[i].hold_time));
            }

            pimsm_RpChangeCheck(&node->rp_group.group_addr.group_addr, node->rp_group.group_addr.prefixlen);
        }
    }

    return VOS_OK;
}

static int pim_GrpRpTableDelEntry(struct pimsm_group_rp *pstGroupRps)
{
    struct pimsm_rp_list * tmp;
    int n;
    int i;
    int j;

    if (NULL == pstGroupRps)
    {
        return VOS_ERROR;
    }

    //search the same entry
    tmp = g_rp_set_list;
    while (NULL != tmp)
    {
        if (0 == memcmp(&tmp->rp_group.group_addr,
                        &pstGroupRps->group_addr,
                        sizeof(tmp->rp_group.group_addr)))
        {
            break;
        }
        tmp = tmp->pstNext;
    }

    if (NULL != tmp)
    {
        //printf("pim_GrpRpTableDelEntry: find the group entry.\n");
        for(i = 0; i < pstGroupRps->rp_count; ++i)
        {
            for(j = 0; j < tmp->rp_group.rp_count; ++j)
            {
                if(tmp->rp_group.rp_list[j].rp_addr.unicast_addr.u32_addr[0] == pstGroupRps->rp_list[i].rp_addr.unicast_addr.u32_addr[0])
                {
                    //printf("pim_GrpRpTableDelEntry: find the rp entry.\n");

                    if (tmp->rp_group.t_rp_keep_timer[j])
                        THREAD_OFF(tmp->rp_group.t_rp_keep_timer[j]);

                    for(n = j; n < (tmp->rp_group.rp_count - 1); ++n)
                    {
                        memcpy(&tmp->rp_group.rp_list[n], &tmp->rp_group.rp_list[n+1], sizeof(struct pimsm_rp));
                        tmp->rp_group.timer_id[n] = tmp->rp_group.timer_id[n+1];
                    }
                    tmp->rp_group.rp_count--;
                    tmp->rp_group.rp_frag_count--;
                    break;
                }
            }
        }

        pimsm_RpChangeCheck(&tmp->rp_group.group_addr.group_addr, tmp->rp_group.group_addr.prefixlen);

        if(0 == tmp->rp_group.rp_count)
        {
            if (tmp == g_rp_set_list)
            {
                g_rp_set_list = tmp->pstNext;
                if (NULL != g_rp_set_list)
                {
                    g_rp_set_list->pstPrev = NULL;
                }
            }
            else
            {
                tmp->pstPrev->pstNext = tmp->pstNext;
                if (NULL != tmp->pstNext)
                {
                    tmp->pstNext->pstPrev = tmp->pstPrev;
                }
            }
        }

        return VOS_OK;
    }
    else
    {
        printf("pim_GrpRpTableDelEntry: not find the group entry.\n");
    }

    return VOS_ERROR;
}

static int pim_GrpRpTableClean(void)
{
    struct pimsm_rp_list *tmp;
    struct pimsm_rp_list *pNext;
    int i;

    tmp = g_rp_set_list;
    g_rp_set_list=NULL;
    //clean RpGrp table
    while(NULL != tmp)
    {
        pNext = tmp->pstNext;
        for (i = 0; i < tmp->rp_group.rp_count; ++i)
        {
            if (tmp->rp_group.t_rp_keep_timer[i])
                THREAD_OFF(tmp->rp_group.t_rp_keep_timer[i]);
        }

        pimsm_RpChangeCheck(&tmp->rp_group.group_addr.group_addr, tmp->rp_group.group_addr.prefixlen);

        XFREE(MTYPE_PIM_RP_SET_LIST_NODE, tmp);
        tmp = pNext;
    }

    return VOS_OK;
}

static int pim_StoryLastBootstrapMsg(char *pcData, uint32_t dwLen)
{
    struct pimsm_bootstrap *pstBootstrapMsg;

    pstBootstrapMsg = XMALLOC(MTYPE_PIM_BOOTSTRAP, dwLen);
    memcpy(pstBootstrapMsg, pcData, dwLen);
    if(g_bsr_msg.p_msg != NULL)
        XFREE(MTYPE_PIM_BOOTSTRAP, g_bsr_msg.p_msg);

    g_bsr_msg.p_msg = pstBootstrapMsg;
    g_bsr_msg.len = dwLen;

    return VOS_OK;
}

static int pim_OriginateBootstrapMsg(void)
{
    struct pimsm_rp_list *pRpGList;
    struct pimsm_bootstrap *p_send_bsr_buf;
    struct pimsm_rpgroup *pstRpGroupTmp;
    uint32_t bootstrap_len;
    int group_count = 0;
    struct pimsm_rp *pstRpTmp;
    int i;
    int j;

    pRpGList = g_rp_set_list;
    bootstrap_len = sizeof(struct pimsm_bootstrap);
    while (pRpGList != NULL)
    {
        if (pRpGList->rp_group.rp_count != 0)
        {
            bootstrap_len += sizeof(struct pimsm_rpgroup) + pRpGList->rp_group.rp_count * sizeof(struct pimsm_rp);
        }
        pRpGList = pRpGList->pstNext;
        group_count++;
    }
    p_send_bsr_buf = XMALLOC(MTYPE_PIM_BOOTSTRAP, bootstrap_len);
    memset(p_send_bsr_buf, 0, bootstrap_len);

    p_send_bsr_buf->bsr_priority = g_root_cbsr_priority;
    p_send_bsr_buf->stBsrAddr = g_root_cbsr_id;
    p_send_bsr_buf->hash_masklen = PIM_HASH_MSAK_LEN_V4;

    pRpGList = g_rp_set_list;
    pstRpGroupTmp = p_send_bsr_buf->astRpAddrList;
    for (i = 0; i < group_count; ++i)
    {
        pstRpGroupTmp->group_addr = pRpGList->rp_group.group_addr;
        pstRpGroupTmp->rp_frag_count = pRpGList->rp_group.rp_frag_count;
        pstRpGroupTmp->rp_count = pRpGList->rp_group.rp_count;
        pstRpGroupTmp->reserved = pRpGList->rp_group.reserved;
        pstRpTmp = pstRpGroupTmp->rp_addr;
        for (j = 0; j < pRpGList->rp_group.rp_count; ++j)
        {
            *pstRpTmp = pRpGList->rp_group.rp_list[j];
            pstRpTmp++;
        }

        pstRpGroupTmp = (struct pimsm_rpgroup *)pstRpTmp;
        pRpGList = pRpGList->pstNext;
    }

    pim_StoryLastBootstrapMsg((char *)p_send_bsr_buf, bootstrap_len);
    XFREE(MTYPE_PIM_BOOTSTRAP, p_send_bsr_buf);

    return VOS_OK;
}

int pim_SendBootstrapMsg(VOS_IP_ADDR *pstDstAddr)
{
    struct pimsm_interface_entry *pimsm_ifp;

    if(pstDstAddr)
    {
        if(pstDstAddr->u32_addr[0] == g_stPimsm.stAllPimRouters.u32_addr[0]) //multicast address
        {
            pimsm_ifp = g_pimsm_interface_list;
            while(pimsm_ifp)
            {
                pimsm_SendPimPacket((uint8_t *)g_bsr_msg.p_msg,pimsm_ifp->ifindex,&(g_root_cbsr_id.unicast_addr),&(g_stPimsm.stAllPimRouters),PIM_TYPE_BOOTSTRAP,g_bsr_msg.len - PIM_MSG_HEADER_LEN);
                pimsm_ifp = pimsm_ifp->next;
            }
        }
        else //unicast address
        {
            pimsm_SendPimPacket((uint8_t *)g_bsr_msg.p_msg, 0, &(g_root_cbsr_id.unicast_addr), pstDstAddr, PIM_TYPE_BOOTSTRAP,g_bsr_msg.len - PIM_MSG_HEADER_LEN);
        }
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

static int pim_GenerateCrpAdvMsg(uint16_t hold_time)
{
    struct pimsm_crp_group_policy_list *pstCurr = NULL;
    struct pimsm_encoded_group_addr group_addr;
    uint16_t wGroupCount = 0;
    char *p;

    if(g_crp_msg.p_msg)
    {
        XFREE(MTYPE_PIM_CRPADV, g_crp_msg.p_msg);
        memset(&g_crp_msg, 0, sizeof(g_crp_msg));
    }

    pstCurr = g_crp_group_policy_list;
    while (pstCurr != NULL)
    {
        wGroupCount++;
        pstCurr = pstCurr->pstNext;
    }

    if(0 != wGroupCount)
    {
        g_crp_msg.len = sizeof(struct pimsm_cpradv) + sizeof(struct pimsm_encoded_group_addr) * wGroupCount;
        g_crp_msg.p_msg = XMALLOC(MTYPE_PIM_CRPADV, g_crp_msg.len);
        memset(g_crp_msg.p_msg, 0, g_crp_msg.len);

        g_crp_msg.p_msg->prefix_count = wGroupCount;
        g_crp_msg.p_msg->hold_time = htons(hold_time);//PIM_CRP_HOLDTIME
        g_crp_msg.p_msg->priority = g_root_crp_priority;
        g_crp_msg.p_msg->rp_addr = g_root_crp_id;

        pstCurr = g_crp_group_policy_list;
        p = (char *)g_crp_msg.p_msg->group_addr;
        while (pstCurr != NULL)
        {
            memset(&group_addr,0,sizeof(struct pimsm_encoded_group_addr));
            group_addr.family = 1;
            group_addr.encoding_type = 0;
            group_addr.prefixlen = pstCurr->group_masklen;
            group_addr.reserved = 0;
            group_addr.b = 0;
            group_addr.z = 0;
            group_addr.group_addr.u32_addr[0] = pstCurr->group_addr.u32_addr[0];

            memcpy(p, &group_addr, sizeof(group_addr));
            p += sizeof(group_addr);

            pstCurr = pstCurr->pstNext;
        }
    }

    return VOS_OK;
}

static int pim_SendCrpAdvMsg(void)
{
    if(g_crp_enable)
    {
        if(pim_iAmBsr())
        {
            pim_ReceiveCandRpAdv(0, &g_root_crp_id.unicast_addr, (uint8_t *)g_crp_msg.p_msg, g_crp_msg.len);
            return VOS_OK;
        }
        else
        {
            pimsm_SendPimPacket((uint8_t *)g_crp_msg.p_msg,0, &(g_root_crp_id.unicast_addr), &(g_bsr_addr.unicast_addr), PIM_TYPE_CAND_RP_ADV, g_crp_msg.len - PIM_MSG_HEADER_LEN);
        }
    }

    return VOS_OK;
}

static int pim_SendSpecificCrpAdvMsg(struct pimsm_crp_group_policy_list *pstCrpGroupPolicyEntry)
{
    struct pimsm_encoded_group_addr group_addr;
    struct pimsm_cpradv *pstMsg;
    uint32_t pim_msg_size;

    memset(&group_addr,0,sizeof(struct pimsm_encoded_group_addr));
    group_addr.family = 1;
    group_addr.encoding_type = 0;
    group_addr.prefixlen = pstCrpGroupPolicyEntry->group_masklen;
    group_addr.reserved = 0;
    group_addr.b = 0;
    group_addr.z = 0;
    group_addr.group_addr.u32_addr[0] = pstCrpGroupPolicyEntry->group_addr.u32_addr[0];

    pim_msg_size = sizeof(struct pimsm_cpradv) + sizeof(struct pimsm_encoded_group_addr);
    pstMsg = XMALLOC(MTYPE_PIM_CRPADV, pim_msg_size);
    memset(pstMsg, 0, pim_msg_size);

    pstMsg->prefix_count = 1;
    pstMsg->hold_time = htons(pstCrpGroupPolicyEntry->hold_time);//PIM_CRP_HOLDTIME
    pstMsg->priority = g_root_crp_priority;
    pstMsg->rp_addr = g_root_crp_id;
    memcpy(pstMsg->group_addr, &group_addr, sizeof(group_addr));

    if(g_crp_enable)
    {
        if(pim_iAmBsr())
        {
            pim_ReceiveCandRpAdv(0, &g_root_crp_id.unicast_addr,(uint8_t *)pstMsg, pim_msg_size);
        }
        else
        {
            pimsm_SendPimPacket((uint8_t *)pstMsg,0,&(g_root_crp_id.unicast_addr),&(g_bsr_addr.unicast_addr),PIM_TYPE_CAND_RP_ADV ,pim_msg_size - PIM_MSG_HEADER_LEN);
        }
    }

    XFREE(MTYPE_PIM_CRPADV, pstMsg);

    return VOS_OK;
}

int pim_ReceiveBootstrap(uint32_t ifindex,VOS_IP_ADDR *pstSrc,uint8_t *pim_msg,uint32_t pim_msg_size)
{
    //printf("this is bootstrap receive!%d\n",ifindex);
    uint8_t byRecvPreferedBsm = FALSE;
    struct pimsm_bootstrap *pstBootstrap;
    struct pimsm_encoded_unicast_addr stBsrAddr;
    struct pimsm_rpgroup *pstRpGroup;
    struct pimsm_group_rp stGroupRps;
    uint32_t offset = 0;
    uint16_t i;

    if((pim_msg == NULL)||(pim_msg_size == 0)||(ifindex == 0))
    {
        return VOS_ERROR;
    }

    pstBootstrap = (struct pimsm_bootstrap *)pim_msg;

    stBsrAddr = pstBootstrap->stBsrAddr;
    if(stBsrAddr.family != ADDRF_IPv4)
    {
        return VOS_ERROR;
    }
    if(stBsrAddr.unicast_addr.u32_addr[0] == g_root_cbsr_id.unicast_addr.u32_addr[0])
    {
        return VOS_ERROR;
    }

    if (stBsrAddr.unicast_addr.u32_addr[0] != g_bsr_addr.unicast_addr.u32_addr[0])
    {
        if(g_bsr_priority > pstBootstrap->bsr_priority) //current priority > new priority
        {
            pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);
        }
        else if(g_bsr_priority < pstBootstrap->bsr_priority) //current priority < new priority
        {
            pim_GrpRpTableClean();

            g_bsr_addr = stBsrAddr; //story new BSR address
            g_bsr_priority = pstBootstrap->bsr_priority;
            g_bsr_hash_masklen = pstBootstrap->hash_masklen;

            pim_StoryLastBootstrapMsg((char *)pstBootstrap, pim_msg_size);

            //transmit this bootstrap message to all interface
            //pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);

            //create new RP table
            offset = 0;
            while(offset < pim_msg_size - PIM_BSR_MSG_HEADLEN)
            {
                pstRpGroup = (struct pimsm_rpgroup *)(((char*)pstBootstrap->astRpAddrList) + offset);

                memset(&stGroupRps, 0, sizeof(stGroupRps));
                stGroupRps.group_addr = pstRpGroup->group_addr;
                stGroupRps.rp_frag_count = pstRpGroup->rp_frag_count;
                stGroupRps.reserved = pstRpGroup->reserved;
                stGroupRps.rp_count = (pstRpGroup->rp_count > MAX_RP_NUM) ? MAX_RP_NUM : pstRpGroup->rp_count;
                for(i = 0; i < stGroupRps.rp_count; i++)
                {
                    stGroupRps.rp_list[i] = * (pstRpGroup->rp_addr + i);
                    stGroupRps.rp_list[i].hold_time = stGroupRps.rp_list[i].hold_time;
                }
                pim_GrpRpTableAddEntry(&stGroupRps);

                offset = offset + PIM_GROUP_HEADlEN + pstRpGroup->rp_count * (sizeof(struct pimsm_rp));
            }

            if(g_crp_enable)
            {
                pim_SendCrpAdvMsg();

                /*sangmeng add for timer reset*/
                if (g_t_bsr_timer)
                    THREAD_OFF(g_t_bsr_timer);
                THREAD_TIMER_ON(master, g_t_rp_timer,
                                pim_TimeoutCrpAdv,
                                &(g_root_crp_id.unicast_addr), PIM_TIMER_SEND_INTERVAL);
            }

            byRecvPreferedBsm = TRUE;
        }
        else //current priority == new priority
        {
            if (stBsrAddr.unicast_addr.u32_addr[0] < g_bsr_addr.unicast_addr.u32_addr[0])
            {
                pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);
            }
            else
            {
                pim_GrpRpTableClean();

                g_bsr_addr = stBsrAddr; //story new BSR address
                g_bsr_hash_masklen = pstBootstrap->hash_masklen;

                pim_StoryLastBootstrapMsg((char *)pstBootstrap, pim_msg_size);

                //transmit this bootstrap message to all interface
                //pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);

                //create new RP table
                offset = 0;
                while(offset < pim_msg_size-PIM_BSR_MSG_HEADLEN)
                {
                    pstRpGroup = (struct pimsm_rpgroup *)(((char*)pstBootstrap->astRpAddrList) + offset);

                    memset(&stGroupRps, 0, sizeof(stGroupRps));
                    stGroupRps.group_addr = pstRpGroup->group_addr;
                    stGroupRps.rp_frag_count = pstRpGroup->rp_frag_count;
                    stGroupRps.reserved = pstRpGroup->reserved;
                    stGroupRps.rp_count = (pstRpGroup->rp_count > MAX_RP_NUM) ? MAX_RP_NUM : pstRpGroup->rp_count;
                    for(i = 0; i < stGroupRps.rp_count; i++)
                    {
                        stGroupRps.rp_list[i] = * (pstRpGroup->rp_addr + i);
                        stGroupRps.rp_list[i].hold_time = stGroupRps.rp_list[i].hold_time;
                    }
                    pim_GrpRpTableAddEntry(&stGroupRps);

                    offset = offset + PIM_GROUP_HEADlEN + pstRpGroup->rp_count * (sizeof(struct pimsm_rp));
                }

                if(g_crp_enable)
                {
                    pim_SendCrpAdvMsg();
                    if (g_t_bsr_timer)
                        THREAD_OFF(g_t_bsr_timer);
                    THREAD_TIMER_ON(master, g_t_rp_timer,
                                    pim_TimeoutCrpAdv,
                                    &(g_root_crp_id.unicast_addr), PIM_TIMER_SEND_INTERVAL);

                }

                byRecvPreferedBsm = TRUE;
            }
        }
    }
    else
    {
        if((g_root_cbsr_priority > pstBootstrap->bsr_priority) || ((g_root_cbsr_priority == pstBootstrap->bsr_priority) && (stBsrAddr.unicast_addr.u32_addr[0] < g_root_cbsr_id.unicast_addr.u32_addr[0])))
        {
            //I become BSR
            pim_iBecomeBsr();
        }
        else
        {
            //story Bootstrap message
            pim_StoryLastBootstrapMsg((char *)pstBootstrap, pim_msg_size);
            pim_GrpRpTableClean();

            //create new RP table
            offset = 0;
            while(offset < pim_msg_size-PIM_BSR_MSG_HEADLEN)
            {
                pstRpGroup = (struct pimsm_rpgroup *)(((char*)pstBootstrap->astRpAddrList) + offset);

                memset(&stGroupRps, 0, sizeof(stGroupRps));
                stGroupRps.group_addr = pstRpGroup->group_addr;
                stGroupRps.rp_frag_count = pstRpGroup->rp_frag_count;
                stGroupRps.reserved = pstRpGroup->reserved;
                stGroupRps.rp_count = (pstRpGroup->rp_count > MAX_RP_NUM) ? MAX_RP_NUM : pstRpGroup->rp_count;
                for(i = 0; i < stGroupRps.rp_count; i++)
                {
                    stGroupRps.rp_list[i] = * (pstRpGroup->rp_addr + i);
                    stGroupRps.rp_list[i].hold_time = stGroupRps.rp_list[i].hold_time;
                }
                pim_GrpRpTableAddEntry(&stGroupRps);

                offset = offset + PIM_GROUP_HEADlEN + pstRpGroup->rp_count * (sizeof(struct pimsm_rp));
            }

            //transmit this bootstrap message to all interface
            //pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);

            byRecvPreferedBsm = TRUE;
        }

    }

    switch(g_root_bsr_state)
    {
    case PIM_CBSR_STATE_CANDIDATE_BSR:
        if((g_root_cbsr_priority < pstBootstrap->bsr_priority) || ((g_root_cbsr_priority == pstBootstrap->bsr_priority) && (stBsrAddr.unicast_addr.u32_addr[0] > g_root_cbsr_id.unicast_addr.u32_addr[0])))
        {
            if (g_t_bsr_timer)
                THREAD_OFF(g_t_bsr_timer);

            THREAD_TIMER_ON(master, g_t_bsr_timer,
                            pimsm_bsr_timer,
                            NULL, PIM_TIMER_BS_TIMEOUT);
        }
        else
        {
            if (stBsrAddr.unicast_addr.u32_addr[0] == g_bsr_addr.unicast_addr.u32_addr[0])
            {
                g_root_bsr_state = PIM_CBSR_STATE_PENDING_BSR;

                if (g_t_bsr_timer)
                    THREAD_OFF(g_t_bsr_timer);

                THREAD_TIMER_ON(master, g_t_bsr_timer,
                                pimsm_bsr_timer,
                                NULL, PIM_TIMER_BS_RAND_OVERRIDE);
            }
        }
        break;
    case PIM_CBSR_STATE_PENDING_BSR:
        if((g_root_cbsr_priority < pstBootstrap->bsr_priority) || ((g_root_cbsr_priority == pstBootstrap->bsr_priority) && (stBsrAddr.unicast_addr.u32_addr[0] > g_root_cbsr_id.unicast_addr.u32_addr[0])))
        {
            g_root_bsr_state = PIM_CBSR_STATE_CANDIDATE_BSR;
            if (g_t_bsr_timer)
                THREAD_OFF(g_t_bsr_timer);

            THREAD_TIMER_ON(master, g_t_bsr_timer,
                            pimsm_bsr_timer,
                            NULL, PIM_TIMER_BS_TIMEOUT);

        }
        break;
    case PIM_CBSR_STATE_ELECTED_BSR:
        if((g_root_cbsr_priority < pstBootstrap->bsr_priority) || ((g_root_cbsr_priority == pstBootstrap->bsr_priority) && (stBsrAddr.unicast_addr.u32_addr[0] > g_root_cbsr_id.unicast_addr.u32_addr[0])))
        {
            g_root_bsr_state = PIM_CBSR_STATE_CANDIDATE_BSR;
            if (g_t_bsr_timer)
                THREAD_OFF(g_t_bsr_timer);

            THREAD_TIMER_ON(master, g_t_bsr_timer,
                            pimsm_bsr_timer,
                            NULL, PIM_TIMER_BS_TIMEOUT);
        }
        else
        {
            if (g_t_bsr_timer)
                THREAD_OFF(g_t_bsr_timer);

            THREAD_TIMER_ON(master, g_t_bsr_timer,
                            pimsm_bsr_timer,
                            NULL, PIM_TIMER_BS_PERIOD);

        }
        break;
    case PIM_CBSR_STATE_NO_INFO:
        g_root_bsr_state = PIM_CBSR_STATE_ACCEPT_PREFERED;

        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_BS_TIMEOUT);

        break;
    case PIM_CBSR_STATE_ACCEPT_PREFERED:
        if(byRecvPreferedBsm)
        {
            if (g_t_bsr_timer)
                THREAD_OFF(g_t_bsr_timer);

            THREAD_TIMER_ON(master, g_t_bsr_timer,
                            pimsm_bsr_timer,
                            NULL, PIM_TIMER_BS_TIMEOUT);
        }
        break;
    case PIM_CBSR_STATE_ACCEPT_ANY:
        if (g_t_bsr_timer)
            THREAD_OFF(g_t_bsr_timer);

        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_BS_TIMEOUT);
        break;
    default:
        break;
    }


    return VOS_OK;
}

int pim_ReceiveCandRpAdv(uint32_t ifindex,VOS_IP_ADDR *pstSrc,uint8_t *pim_msg,uint32_t pim_msg_size)
{
    struct pimsm_group_rp stGroupRps;
    struct pimsm_cpradv *pstCrpAdv;
    int i;

    if ((pim_msg == NULL) || (0 == pim_msg_size))
    {
        return VOS_ERROR;
    }

    pstCrpAdv = (struct pimsm_cpradv *)pim_msg;
    if (pim_iAmBsr()) //I'm BSR.
    {
        for(i = 0; i < pstCrpAdv->prefix_count; ++i) //Number of prefix for group address.
        {
            memset(&stGroupRps, 0, sizeof(stGroupRps));
            stGroupRps.group_addr = pstCrpAdv->group_addr[i];
            stGroupRps.rp_count = 1;
            stGroupRps.rp_frag_count = 1;
            stGroupRps.rp_list[0].rp_addr = pstCrpAdv->rp_addr;
            stGroupRps.rp_list[0].rp_priority = pstCrpAdv->priority;
            stGroupRps.rp_list[0].hold_time = pstCrpAdv->hold_time;
            pim_GrpRpTableAddEntry(&stGroupRps);
        }

        pim_OriginateBootstrapMsg();
        pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);
    }

    return VOS_OK;
}

int pimsm_bsr_timer(struct thread *t)
{
    PIM_DEBUG("pimsm bsr timer state is %d\n",g_root_bsr_state);
    switch(g_root_bsr_state)
    {
    case PIM_CBSR_STATE_CANDIDATE_BSR:
        g_root_bsr_state = PIM_CBSR_STATE_PENDING_BSR;
        if (g_t_bsr_timer)
            THREAD_OFF(g_t_bsr_timer);
        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_BS_RAND_OVERRIDE);
        break;
    case PIM_CBSR_STATE_PENDING_BSR:
        pim_OriginateBootstrapMsg();
        pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);
        g_root_bsr_state = PIM_CBSR_STATE_ELECTED_BSR;
        if (g_t_bsr_timer)
            THREAD_OFF(g_t_bsr_timer);

        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_BS_PERIOD);
        break;
    case PIM_CBSR_STATE_ELECTED_BSR:
        pim_OriginateBootstrapMsg();
        pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);

        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_BS_PERIOD);
        break;
    case PIM_CBSR_STATE_NO_INFO:
        break;
    case PIM_CBSR_STATE_ACCEPT_PREFERED:
        g_bsr_addr.unicast_addr.u32_addr[0] = 0;
        g_bsr_hash_masklen = PIM_HASH_MSAK_LEN_V4;

        g_root_bsr_state = PIM_CBSR_STATE_ACCEPT_ANY;
        THREAD_TIMER_ON(master, g_t_bsr_timer,
                        pimsm_bsr_timer,
                        NULL, PIM_TIMER_SZ_TIMEOUT);

        break;
    case PIM_CBSR_STATE_ACCEPT_ANY:
        //Remove scope zone state
        g_root_bsr_state = PIM_CBSR_STATE_NO_INFO;
        break;
    default:
        break;
    }

    return VOS_OK;
}



int pim_TimeoutCrpAdv(struct thread *t)
{

    zassert(t);

    //Timer expires, sending Candidate-RP-Advertisement message.
    pim_SendCrpAdvMsg();


    if (g_t_bsr_timer)
        THREAD_OFF(g_t_bsr_timer);

    THREAD_TIMER_ON(master, g_t_rp_timer,
                    pim_TimeoutCrpAdv,
                    &(g_root_crp_id.unicast_addr), PIM_TIMER_SEND_INTERVAL);

    return VOS_OK;
}



int pim_TimeoutRpKeep(struct thread *t)
{
    struct pimsm_rp_list *tmp;
    struct pimsm_group_rp stGroupRps;
    VOS_IP_ADDR *address;
    int find;
    int i;

    zassert(t);

    struct pimsm_timer_rp_para *rp_para;
    rp_para = THREAD_ARG(t);

    address = &rp_para->unicast_addr;
    printf("Timeout rp address: %s, time_id: %ld.\n", pim_InetFmt(address), rp_para->timer_id);

    tmp = g_rp_set_list;
    find = FALSE;
    while(tmp)
    {
        for (i = 0; i < tmp->rp_group.rp_count; ++i)
        {
            if(tmp->rp_group.timer_id[i] == rp_para->timer_id)
            {
                find = TRUE;
                break;
            }
        }

        if(find)
            break;

        tmp = tmp->pstNext;
    }

    if(find)
    {
        printf("TimeoutRpKeep: find rp entry and delete rp.\n");
        memcpy(&stGroupRps, &tmp->rp_group, sizeof(stGroupRps));
        stGroupRps = tmp->rp_group;
        stGroupRps.rp_count = 1;
        stGroupRps.rp_frag_count = 1;
        stGroupRps.rp_list[0] = tmp->rp_group.rp_list[i];
        pim_GrpRpTableDelEntry(&stGroupRps);
    }
    else
    {
        printf("TimeoutRpKeep: not find rp entry, time_id = %ld.\n", rp_para->timer_id);
    }

    XFREE(MTYPE_PIM_RP_PARA, rp_para);
    return VOS_OK;
}

int pim_BootstrapCbsrEnable(uint32_t ifindex, uint8_t priority)
{
    struct pimsm_interface_entry  *pimsm_ifp = NULL;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp)
    {
        if(ifindex == pimsm_ifp->ifindex)
        {
            break;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    if(NULL == pimsm_ifp)
    {
        //oam_OutputToDevice(0, "Error: The interface is not exist!\n");
        return VOS_ERROR;
    }

    g_cbsr_enable = TRUE;

    PIM_DEBUG("enable root_cbsr addr %s\n",pim_InetFmt(&g_root_cbsr_id.unicast_addr));
    PIM_DEBUG("pimsm_ifp->ifindex = %d\n",pimsm_ifp->ifindex);
    if(ip_isAnyAddress(&pimsm_ifp->primary_address))
    {
        PIM_DEBUG("%s ifindex %d primary_address id any addr\n",ifindex2ifname(pimsm_ifp->ifindex),pimsm_ifp->ifindex);
        g_root_cbsr_priority = priority;
        g_root_cbsr_ifindex = pimsm_ifp->ifindex;
        return VOS_OK;
    }
    if (g_root_cbsr_id.unicast_addr.u32_addr[0] == pimsm_ifp->primary_address.u32_addr[0])
    {
        PIM_DEBUG("root_cbsr addr %s\n",pim_InetFmt(&pimsm_ifp->primary_address));
        if(g_root_cbsr_priority != priority)
        {
            g_root_cbsr_priority = priority;
            //priority is changed
            if(!pim_iAmBsr())
            {
                if((g_bsr_priority < priority) ||((g_bsr_priority == priority) && (g_root_cbsr_id.unicast_addr.u32_addr[0] > g_bsr_addr.unicast_addr.u32_addr[0])))
                {
                    //I become BSR
                    pim_iBecomeBsr();
                }
            }
            else
            {
                pim_iBecomeBsr();
            }
        }
    }
    else if(g_root_cbsr_id.unicast_addr.u32_addr[0] != pimsm_ifp->primary_address.u32_addr[0])
    {
        //root id init
        g_root_cbsr_id.family = 1;
        PIM_DEBUG("cp root_cbsr addr %s\n",pim_InetFmt(&pimsm_ifp->primary_address));
        g_root_cbsr_id.unicast_addr.u32_addr[0] = pimsm_ifp->primary_address.u32_addr[0];
        g_root_cbsr_id.encoding_type = 0;

        g_root_cbsr_priority = priority;
        g_root_cbsr_ifindex = pimsm_ifp->ifindex;

        pim_iBecomeBsr();
    }

    printf("C-BSR rootid: %s, priority: %d.\n", pim_InetFmt(&g_root_cbsr_id.unicast_addr), priority);

    return VOS_OK;
}


int pim_BootstrapCbsrDisable(void)
{
    printf("pim bootstrap disable.\n");

    if(g_bsr_addr.unicast_addr.u32_addr[0] == g_root_cbsr_id.unicast_addr.u32_addr[0])
    {
        g_root_cbsr_priority = 0;
        pim_OriginateBootstrapMsg();
        pim_SendBootstrapMsg(&g_stPimsm.stAllPimRouters);

        g_bsr_addr.unicast_addr.u32_addr[0] = 0;
        XFREE(MTYPE_PIM_BOOTSTRAP, g_bsr_msg.p_msg);
        g_bsr_msg.p_msg = NULL;
    }

    if (g_t_bsr_timer)
        THREAD_OFF(g_t_bsr_timer);

    g_t_bsr_timer = 0;
    g_root_bsr_state = PIM_CBSR_STATE_NO_INFO;

    g_root_cbsr_id.family = 1;
    g_root_cbsr_id.unicast_addr.u32_addr[0] = 0;
    g_root_cbsr_id.encoding_type = 0;
    g_root_cbsr_priority = 0;
    g_bsr_hash_masklen = PIM_HASH_MSAK_LEN_V4;

    g_cbsr_enable = FALSE;

    return VOS_OK;
}

int pim_BootstrapCrpEnable(uint32_t ifindex, uint8_t priority)
{
    struct pimsm_interface_entry *pimsm_ifp = NULL;

    pimsm_ifp = g_pimsm_interface_list;
    while(pimsm_ifp)
    {
        if(ifindex == pimsm_ifp->ifindex)
        {
            break;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    if(NULL == pimsm_ifp)
    {
        printf("Error: The interface is not exist!\n");
        return VOS_ERROR;
    }

    if(g_crp_enable && (g_root_crp_id.unicast_addr.u32_addr[0] != pimsm_ifp->primary_address.u32_addr[0]))
    {
        //C-RP root id changed
        pim_GenerateCrpAdvMsg(0);
        pim_SendCrpAdvMsg();
    }

    g_crp_enable = TRUE;

    g_root_crp_id.family = 1;
    g_root_crp_id.encoding_type = 0;
    g_root_crp_id.unicast_addr = pimsm_ifp->primary_address;
    g_root_crp_priority = priority;
    g_root_crp_ifindex = pimsm_ifp->ifindex;

    pim_GenerateCrpAdvMsg(PIM_CRP_HOLDTIME);
    pim_SendCrpAdvMsg();

    if(!g_t_rp_timer)
    {

        THREAD_TIMER_ON(master, g_t_rp_timer,
                        pim_TimeoutCrpAdv,
                        &(g_root_crp_id.unicast_addr), PIM_TIMER_SEND_INTERVAL);
    }
    else
    {
        if (g_t_bsr_timer)
            THREAD_OFF(g_t_bsr_timer);

        THREAD_TIMER_ON(master, g_t_rp_timer,
                        pim_TimeoutCrpAdv,
                        &(g_root_crp_id.unicast_addr), PIM_TIMER_SEND_INTERVAL);
    }

    printf("C-RP %s priority is %d.\n", pim_InetFmt(&g_root_crp_id.unicast_addr), g_root_crp_priority);

    return VOS_OK;
}


int pim_BootstrapCrpDisable(void)
{
    //struct pimsm_crp_group_policy_list *pstCurr = NULL;

    if(!g_crp_enable)
    {
        return VOS_ERROR;
    }

    pim_GenerateCrpAdvMsg(0);
    pim_SendCrpAdvMsg();

    if(!g_crp_msg.p_msg)
    {
        XFREE(MTYPE_PIM_CRPADV, g_crp_msg.p_msg);
    }
    memset(&g_crp_msg, 0, sizeof(g_crp_msg));


    if (g_t_bsr_timer)
        THREAD_OFF(g_t_bsr_timer);

    g_crp_enable = FALSE;

    printf("Pim bootstrap crp disable.\n");

    return VOS_OK;
}

int pim_CrpGroupPolicyAdd(VOS_IP_ADDR *pstGrpAddr, VOS_IP_ADDR *pstGrpMask)
{
    struct pimsm_crp_group_policy_list * pstCurr = NULL;
    struct pimsm_crp_group_policy_list * pstEntry = NULL;
    VOS_IP_ADDR stGroupMask;
    uint32_t dwMaskLen;

    zassert(NULL != pstGrpAddr);
    zassert(NULL != pstGrpMask);

    stGroupMask = *pstGrpMask;
    MASK_TO_MASKLEN(stGroupMask, dwMaskLen);

    printf("[C-RP group policy add] G:%s/%d\n", pim_InetFmt(pstGrpAddr), dwMaskLen);

    pstCurr = g_crp_group_policy_list;
    while (NULL != pstCurr)
    {
        if ( pim_MatchPrefix(pstGrpAddr, &pstCurr->group_addr, dwMaskLen)
                && (pstCurr->group_masklen == dwMaskLen) )
        {
            break;
        }

        pstCurr = pstCurr->pstNext;
    }

    /* 如果存在return */
    if (NULL != pstCurr)
    {
        PIM_DEBUG("exist!\n");
        return VOS_OK;
    }
    else /* 不存在,新建 */
    {
        pstEntry = XMALLOC(MTYPE_PIM_CRP_GROUP_POLICY_LIST, sizeof(struct pimsm_crp_group_policy_list));
        if (pstEntry == NULL)
        {
            PIM_DEBUG("Memory not enough!\n");
            return VOS_ERROR;
        }
        else
        {
            memset(pstEntry, 0x00, sizeof(struct pimsm_crp_group_policy_list));
            memcpy(&(pstEntry->group_addr), pstGrpAddr, sizeof(VOS_IP_ADDR));
            ip_GetPrefixFromAddr(&(pstEntry->group_addr), dwMaskLen);
            pstEntry->group_masklen = dwMaskLen;
            pstEntry->hold_time = PIM_CRP_HOLDTIME;

            pstEntry->pstNext = g_crp_group_policy_list;
            g_crp_group_policy_list = pstEntry;
        }
    }

    pim_GenerateCrpAdvMsg(PIM_CRP_HOLDTIME);
    pim_SendSpecificCrpAdvMsg(pstEntry);

    return VOS_OK;
}

int pim_CrpGroupPolicyDel(VOS_IP_ADDR *pstGrpAddr, VOS_IP_ADDR *pstGrpMask)
{
    struct pimsm_crp_group_policy_list *pstPrev = NULL;
    struct pimsm_crp_group_policy_list *pstCurr = NULL;
    VOS_IP_ADDR stGroupMask;
    uint32_t dwMaskLen;

    zassert(NULL != pstGrpAddr);
    zassert(NULL != pstGrpMask);

    stGroupMask = *pstGrpMask;
    MASK_TO_MASKLEN(stGroupMask, dwMaskLen);

    printf("[C-RP group policy delete] G:%s/%d\n", pim_InetFmt(pstGrpAddr), dwMaskLen);

    pstCurr = g_crp_group_policy_list;
    while (pstCurr != NULL)
    {
        if ( (dwMaskLen == pstCurr->group_masklen)
                && pim_MatchPrefix(pstGrpAddr, &pstCurr->group_addr, dwMaskLen) )
        {
            break;
        }
        pstPrev = pstCurr;
        pstCurr = pstCurr->pstNext;
    }

    if (pstCurr == NULL)
    {
        PIM_DEBUG("No corresponding accept register entry to delete!\n");
        return VOS_ERROR;
    }
    else
    {
        pstCurr->hold_time = 0;
        pim_SendSpecificCrpAdvMsg(pstCurr);

        if (pstCurr == g_crp_group_policy_list)
        {
            g_crp_group_policy_list = pstCurr->pstNext;
        }
        else
        {
            pstPrev->pstNext = pstCurr->pstNext;
        }

        XFREE(MTYPE_PIM_CRP_GROUP_POLICY_LIST, pstCurr);
    }

    pim_GenerateCrpAdvMsg(PIM_CRP_HOLDTIME);

    return VOS_OK;
}

int pim_BootstrapBsrShow(struct vty *vty)
{
    char acPrintBuf[200];
    const char *acStateString[] = {"Candidate-BSR", "Pending-BSR", "Elected-BSR", "No-Info", "Accept-Prefered", "Accept-Any"};

    memset(acPrintBuf, 0, sizeof(acPrintBuf));
    sprintf(acPrintBuf, "BSR address: %s, HashMaskLen: %d, MyState: %s\n", pim_InetFmt(&g_bsr_addr.unicast_addr), g_bsr_hash_masklen, acStateString[g_root_bsr_state]);
    //oam_OutputToDevice(0, acPrintBuf);

    vty_out(vty,"%s\n",acPrintBuf);

    return VOS_OK;
}

int pim_BootstrapRpShow(struct vty *vty)
{
    struct pimsm_rp_list *pstRpGrpListNode;
    uint32_t dwRpNum;
    uint32_t i;

    pstRpGrpListNode = g_rp_set_list;
    while(pstRpGrpListNode)
    {
        vty_out(vty,"Group address: %s/%d\n",
                pim_InetFmt(&pstRpGrpListNode->rp_group.group_addr.group_addr),
                pstRpGrpListNode->rp_group.group_addr.prefixlen);

        dwRpNum = pstRpGrpListNode->rp_group.rp_count;
        for(i = 0; i < dwRpNum; ++i)
        {
            vty_out(vty,"\t Rp address: %s , Priority: %d , HoldTime: %d , time_id: %ld\n",
                    pim_InetFmt(&pstRpGrpListNode->rp_group.rp_list[i].rp_addr.unicast_addr),
                    pstRpGrpListNode->rp_group.rp_list[i].rp_priority,
                    ntohs(pstRpGrpListNode->rp_group.rp_list[i].hold_time),
                    pstRpGrpListNode->rp_group.timer_id[i]);
        }
        pstRpGrpListNode = pstRpGrpListNode->pstNext;
        vty_out(vty,"%s","\n");
    }

    return VOS_OK;
}

int pim_CrpGroupPolicyListShow(void)
{
    struct pimsm_crp_group_policy_list *pstCurr = NULL;

    pstCurr = g_crp_group_policy_list;
    while (pstCurr != NULL)
    {
        printf("Group: %s/%d\n", pim_InetFmt(&pstCurr->group_addr), pstCurr->group_masklen);

        pstCurr = pstCurr->pstNext;
    }

    return VOS_OK;
}


int pimsm_bootstrapconfig(struct vty *vty)
{
    struct pimsm_crp_group_policy_list * pstCurr = NULL;
    VOS_IP_ADDR stGroupMask;

    pstCurr = g_crp_group_policy_list;
    while (NULL != pstCurr)
    {
        memset(&stGroupMask,0,sizeof(VOS_IP_ADDR));
        MASKLEN_TO_MASK6(pstCurr->group_masklen,stGroupMask);

        vty_out(vty,"ip pim-sm c-rp group-policy %s %s %s", pim_InetFmt(&pstCurr->group_addr), pim_InetFmt(&stGroupMask),VTY_NEWLINE);
        pstCurr = pstCurr->pstNext;
    }

    /*配置备选RP*/
    if(g_crp_enable == TRUE)
    {
        /*根据ip地址找到接口名称*/
        //g_root_crp_id.unicast_addr
        //    printf("---test--\n");
        //printf("ip pim-sm c-rp interface %s priority %d %s","GE3",g_root_crp_priority,VTY_NEWLINE);
        vty_out(vty,"ip pim-sm c-rp interface %s priority %d %s",ifindex2ifname(g_root_crp_ifindex),g_root_crp_priority,VTY_NEWLINE);
    }

    /*配置备选BSR*/
    if(g_cbsr_enable == TRUE)
    {
        //g_root_cbsr_id.unicast_addr
        PIM_DEBUG("g_root_cbsr_ifindex = %d\n",g_root_cbsr_ifindex);
        vty_out(vty,"ip pim-sm c-bsr interface %s priority %d %s",ifindex2ifname(g_root_cbsr_ifindex),g_root_cbsr_priority,VTY_NEWLINE);
    }

    return VOS_OK;
}

#endif
