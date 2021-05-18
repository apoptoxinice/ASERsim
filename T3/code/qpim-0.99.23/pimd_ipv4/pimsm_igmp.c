#include "pimsm_define.h"
#if INCLUDE_PIMSM

#include <zebra.h>
#include "memory.h"
#include "hash.h"

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
#include "pimsm_igmp.h"

extern struct pimsm_interface_entry *g_pimsm_interface_list;

PIMSM_IGMP_MRT_RESOURCE_COUNT_T g_IgmpMrtResourceCount;

int pimsm_DisplayAllIgmpMrtResEntry(void);

static int pimsm_IgmpMrtResProcMemberDel(uint32_t ifindex,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType);

static int pimsm_IgmpMrtResProcMemberAdd
(
    uint32_t ifindex,
    VOS_IP_ADDR *src_addr,
    VOS_IP_ADDR *pstGrpAddr,
    PIMSM_RECORD_TYPE_T emType
);


int pimsm_IgmpInit(void)
{
    memset(&g_IgmpMrtResourceCount, 0, sizeof(g_IgmpMrtResourceCount));
    g_IgmpMrtResourceCount.dwIfMrtResourceMax = PIMSM_IF_IGMP_MRT_RESOURCE_MAX;
    g_IgmpMrtResourceCount.pstIgmpMrtResourceList = NULL;
    return VOS_OK;
}

#define igmp_res

static PIMSM_IGMP_MRT_RESOURCE_T *pimsm_IgmpMrtResEntryFind
(
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResList,
    VOS_IP_ADDR *pstSrcAddr,
    VOS_IP_ADDR *pstGrpAddr,
    uint8_t type
)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtRes;
    VOS_IP_ADDR src_addr;

    if (NULL == pstGrpAddr)
    {
        return NULL;
    }

    if (NULL == pstSrcAddr)
    {
        memset(&src_addr, 0, sizeof(VOS_IP_ADDR));
    }
    else
    {
        memcpy(&src_addr, pstSrcAddr, sizeof(VOS_IP_ADDR));
    }

    pstIgmpMrtRes = pstIgmpMrtResList;
    while(NULL != pstIgmpMrtRes)
    {
        if ((0 == ip_AddressCompare(pstGrpAddr, &pstIgmpMrtRes->grp_addr)) &&
                (0 == ip_AddressCompare(&src_addr, &pstIgmpMrtRes->src_addr)) &&
                (type == pstIgmpMrtRes->type))
        {
            return pstIgmpMrtRes;
        }
        pstIgmpMrtRes = pstIgmpMrtRes->next;
    }

    return NULL;
}

static PIMSM_IGMP_MRT_RESOURCE_T *pimsm_IgmpMrtResEntryAdd(VOS_IP_ADDR *pstSrcAddr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t ifindex)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResEntry;
    uint8_t isMrtResNewCreate = FALSE;
    uint8_t isOifNewCreate = FALSE;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;
    struct pimsm_oif *pstOif;

    if (NULL == pstGrpAddr)
    {
        return NULL;
    }
    memcpy(&grp_addr, pstGrpAddr, sizeof(grp_addr));

    if (NULL == pstSrcAddr)
    {
        memset(&src_addr, 0, sizeof(src_addr));
    }
    else
    {
        memcpy(&src_addr, pstSrcAddr, sizeof(src_addr));
    }

    if (NULL == pimsm_SearchInterface(ifindex))
    {
        return NULL;
    }

    if ((PIMSM_MRT_TYPE_WC != type) && (PIMSM_MRT_TYPE_SG != type) && (PIMSM_MRT_TYPE_SGRPT != type))
    {
        return NULL;
    }

    pstIgmpMrtResEntry = pimsm_IgmpMrtResEntryFind(g_IgmpMrtResourceCount.pstIgmpMrtResourceList, &src_addr, &grp_addr, type);
    if (NULL == pstIgmpMrtResEntry)
    {
        pstIgmpMrtResEntry = XMALLOC(MTYPE_PIM_IGMP_GROUP_SOURCE, sizeof(PIMSM_IGMP_MRT_RESOURCE_T));
        if (NULL == pstIgmpMrtResEntry)
        {
            return NULL;
        }
        memset(pstIgmpMrtResEntry, 0, sizeof(PIMSM_IGMP_MRT_RESOURCE_T));

        memcpy(&pstIgmpMrtResEntry->src_addr, &src_addr, sizeof(VOS_IP_ADDR));
        memcpy(&pstIgmpMrtResEntry->grp_addr, &grp_addr, sizeof(VOS_IP_ADDR));
        pstIgmpMrtResEntry->type = type;
        pstIgmpMrtResEntry->pstOilist = NULL;
        pstIgmpMrtResEntry->prev = NULL;
        pstIgmpMrtResEntry->next = NULL;

        isMrtResNewCreate = TRUE;
    }

    //add oil
    pstOif = pimsm_SearchOifByIndex(pstIgmpMrtResEntry->pstOilist, ifindex);
    if (NULL == pstOif)
    {
        pstOif = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
        if (NULL == pstOif)
        {
            if (isMrtResNewCreate)
            {
                XFREE(MTYPE_PIM_IGMP_GROUP_SOURCE, pstIgmpMrtResEntry);
            }
            return NULL;
        }
        memset(pstOif, 0, sizeof(struct pimsm_oif));

        pstOif->ifindex = ifindex;
        pstOif->prev = NULL;
        pstOif->next = pstIgmpMrtResEntry->pstOilist;
        if (NULL != pstIgmpMrtResEntry->pstOilist)
        {
            pstIgmpMrtResEntry->pstOilist->prev = pstOif;
        }
        pstIgmpMrtResEntry->pstOilist = pstOif;

        isOifNewCreate = TRUE;
    }

    if (isMrtResNewCreate)
    {
        pstIgmpMrtResEntry->next = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
        pstIgmpMrtResEntry->prev = NULL;
        if (NULL != g_IgmpMrtResourceCount.pstIgmpMrtResourceList)
        {
            g_IgmpMrtResourceCount.pstIgmpMrtResourceList->prev = pstIgmpMrtResEntry;
        }
        g_IgmpMrtResourceCount.pstIgmpMrtResourceList = pstIgmpMrtResEntry;
    }

    return pstIgmpMrtResEntry;
}

static int pimsm_IgmpMrtResEntryDel(VOS_IP_ADDR *pstSrcAddr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t ifindex)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResEntry;
    //struct pimsm_oif *pstOifPrev;
    struct pimsm_oif *pstOifNext;
    struct pimsm_oif *pstOifCurr;
    VOS_IP_ADDR grp_addr;
    VOS_IP_ADDR src_addr;

    if (NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }
    memcpy(&grp_addr, pstGrpAddr, sizeof(grp_addr));

    if (NULL == pstSrcAddr)
    {
        memset(&src_addr, 0, sizeof(src_addr));
    }
    else
    {
        memcpy(&src_addr, pstSrcAddr, sizeof(src_addr));
    }

    pstIgmpMrtResEntry = pimsm_IgmpMrtResEntryFind(g_IgmpMrtResourceCount.pstIgmpMrtResourceList, &src_addr, &grp_addr, type);
    if (NULL == pstIgmpMrtResEntry)
    {
        return VOS_OK;
    }

    if (0 == ifindex)
    {
        //delete this entry and all Oif
        pstOifCurr = pstIgmpMrtResEntry->pstOilist;
        while(NULL != pstOifCurr)
        {
            pstOifNext = pstOifCurr->next;
            XFREE(MTYPE_PIM_OIF, pstOifCurr);
            pstOifCurr = pstOifNext;
        }

        if (NULL != pstIgmpMrtResEntry->next)
        {
            pstIgmpMrtResEntry->next->prev = pstIgmpMrtResEntry->prev;
        }
        if (NULL != pstIgmpMrtResEntry->prev)
        {
            pstIgmpMrtResEntry->prev->next = pstIgmpMrtResEntry->next;
        }
        if (g_IgmpMrtResourceCount.pstIgmpMrtResourceList == pstIgmpMrtResEntry)
        {
            g_IgmpMrtResourceCount.pstIgmpMrtResourceList = pstIgmpMrtResEntry->next;
        }
    }
    else
    {
        //just delete Oif
        pstOifCurr = pstIgmpMrtResEntry->pstOilist;
        while(NULL != pstOifCurr)
        {
            if (ifindex == pstOifCurr->ifindex)
            {
                if (NULL != pstOifCurr->prev)
                {
                    pstOifCurr->prev->next = pstOifCurr->next;
                }
                if (NULL != pstOifCurr->next)
                {
                    pstOifCurr->next->prev = pstOifCurr->prev;
                }
                if (pstOifCurr == pstIgmpMrtResEntry->pstOilist) //head node
                {
                    pstIgmpMrtResEntry->pstOilist = pstOifCurr->next;
                }
                XFREE(MTYPE_PIM_OIF, pstOifCurr);
                break;
            }
            pstOifCurr = pstOifCurr->next;
        }
    }

    return VOS_OK;
}


int pimsm_DestroyAllIgmpMrtResEntry(void)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResCurr;
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResNext;

    pstIgmpMrtResCurr = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;

    while(NULL != pstIgmpMrtResCurr)
    {
        pstIgmpMrtResNext = pstIgmpMrtResCurr->next;
        pimsm_IgmpMrtResEntryDel(&pstIgmpMrtResCurr->src_addr, &pstIgmpMrtResCurr->grp_addr, pstIgmpMrtResCurr->type, 0);
        pstIgmpMrtResCurr = pstIgmpMrtResNext;
    }

    g_IgmpMrtResourceCount.pstIgmpMrtResourceList = NULL;

    return VOS_OK;
}

static int pimsm_DestroyMrtResourceList(PIMSM_IGMP_MRT_RESOURCE_T *pstMrtResList)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResCurr;
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResNext;
    struct pimsm_oif *pstOilCurr;
    struct pimsm_oif *pstOilNext;

    pstIgmpMrtResCurr = pstMrtResList;

    while(NULL != pstIgmpMrtResCurr)
    {
        pstOilCurr = pstIgmpMrtResCurr->pstOilist;
        while(NULL != pstOilCurr)
        {
            pstOilNext = pstOilCurr->next;
            XFREE(MTYPE_PIM_OIF, pstOilCurr);
            pstOilCurr = pstOilNext;
        }

        pstIgmpMrtResNext = pstIgmpMrtResCurr->next;
        XFREE(MTYPE_PIM_IGMP_GROUP_SOURCE, pstIgmpMrtResCurr);
        pstIgmpMrtResCurr = pstIgmpMrtResNext;
    }

    return VOS_OK;
}


int pimsm_DisplayAllIgmpMrtResEntry(void)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtRes;
    struct pimsm_oif *oif;

    printf("\n==============================================\n");
    printf("igmp mrt resource amount:\n");
    pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
    while(NULL != pstIgmpMrtRes)
    {
        if (PIMSM_MRT_TYPE_WC == pstIgmpMrtRes->type)
        {
            printf("(*, %s)\n\t", pim_InetFmt(&pstIgmpMrtRes->grp_addr));
        }
        else if (PIMSM_MRT_TYPE_SG == pstIgmpMrtRes->type)
        {
            printf("(%s, %s)\n\t", pim_InetFmt(&pstIgmpMrtRes->src_addr), pim_InetFmt(&pstIgmpMrtRes->grp_addr));
        }
        else if (PIMSM_MRT_TYPE_SGRPT == pstIgmpMrtRes->type)
        {
            printf("(%s, %s, rpt)\n\t", pim_InetFmt(&pstIgmpMrtRes->src_addr), pim_InetFmt(&pstIgmpMrtRes->grp_addr));
        }
        oif = pstIgmpMrtRes->pstOilist;
        while(NULL != oif)
        {
            printf("%s", pimsm_GetIfName(oif->ifindex));

            oif = oif->next;
            (NULL != oif) ? printf(", ") : printf(". ");
        }
        printf("\n");

        pstIgmpMrtRes = pstIgmpMrtRes->next;
    }
    printf("----------------------------------------------\n");

    return VOS_OK;
}

#define member

static int pimsm_IgmpMrtResProcMemberAdd(uint32_t ifindex,VOS_IP_ADDR *pstSrcAddr, VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType)
{
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResNext;
    //PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtRes2;
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtRes;
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    //struct pimsm_oif *oif;
    //struct pimsm_oif *pstOil2;

    if ((PIMSM_IF_INCLUDE == emType) && (NULL == pstSrcAddr))
    {
        return VOS_ERROR;
    }

    if (NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }
    memcpy(&grp_addr, pstGrpAddr, sizeof(VOS_IP_ADDR));

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType)|| (NULL == pstSrcAddr))
    {
        memset(&src_addr, 0, sizeof(src_addr));
    }
    else
    {
        memcpy(&src_addr, pstSrcAddr, sizeof(VOS_IP_ADDR));
    }

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType) ||
            ((PIMSM_IF_EXCLUDE == emType) && (NULL == pstSrcAddr)))
    {
        //直接创建, 函数会自己查重
        if (NULL == pimsm_IgmpMrtResEntryAdd(NULL, &grp_addr, PIMSM_MRT_TYPE_WC, ifindex))
        {
            return VOS_ERROR;
        }

        /* 如果是IGMPv1和IGMPv2, 或者排除模式下源为空的情况,
        	不仅要添加到(*,G) 还要添加到所有的(S,G) , 并从(S,G,rpt) 中删除 */
        pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
        while(NULL != pstIgmpMrtRes)
        {
            pstIgmpMrtResNext = pstIgmpMrtRes->next;
            if ((0 != pstIgmpMrtRes->src_addr.u32_addr[0]) &&
                    (0 == ip_AddressCompare(&pstIgmpMrtRes->grp_addr, pstGrpAddr)) &&
                    (PIMSM_MRT_TYPE_SG == pstIgmpMrtRes->type))
            {
                pimsm_IgmpMrtResEntryAdd(&pstIgmpMrtRes->src_addr, &pstIgmpMrtRes->grp_addr, PIMSM_MRT_TYPE_SG, ifindex);
                //pimsm_IgmpMrtResProcMemberAdd(ifindex, &pstIgmpMrtRes->src_addr, pstGrpAddr, PIMSM_IF_INCLUDE);
            }
            pstIgmpMrtRes = pstIgmpMrtResNext;
        }
        pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
        while(NULL != pstIgmpMrtRes)
        {
            pstIgmpMrtResNext = pstIgmpMrtRes->next;
            if ((0 != pstIgmpMrtRes->src_addr.u32_addr[0]) &&
                    (0 == ip_AddressCompare(&pstIgmpMrtRes->grp_addr, pstGrpAddr)) &&
                    (PIMSM_MRT_TYPE_SGRPT == pstIgmpMrtRes->type))
            {
                pimsm_IgmpMrtResEntryDel(&pstIgmpMrtRes->src_addr, &pstIgmpMrtRes->grp_addr, PIMSM_MRT_TYPE_SGRPT, ifindex);
                //pimsm_IgmpMrtResProcMemberAdd(ifindex, &pstIgmpMrtRes->src_addr, pstGrpAddr, PIMSM_IF_INCLUDE);
            }
            pstIgmpMrtRes = pstIgmpMrtResNext;
        }

        return VOS_OK;
    }
    else if ((PIMSM_IF_INCLUDE == emType) && (NULL != pstSrcAddr))
    {
        //直接创建, 函数会自己查重
        if (NULL == pimsm_IgmpMrtResEntryAdd(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG, ifindex))
        {
            return VOS_ERROR;
        }

        return VOS_OK;
    }
    else if ((PIMSM_IF_EXCLUDE == emType) && (NULL != pstSrcAddr))
    {
        /* 排除模式, 并且源不为NULL */
        /* 如果不存在(*,G) 则新建一个 并添加此接口, 如果存在直接添加此接口 */
        /* 如果存在(S,G,rpt) , 则添加到此表项 , 表示不接收从此源发来的数据流 , 如果不存在则新建并添加出接口*/
        /* 从(S,G) 表项中删除此接口 */
        pimsm_IgmpMrtResEntryAdd(NULL, &grp_addr, PIMSM_MRT_TYPE_WC, ifindex);
        pimsm_IgmpMrtResEntryAdd(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SGRPT, ifindex);
        pimsm_IgmpMrtResEntryDel(&src_addr, &grp_addr, PIMSM_MRT_TYPE_SG, ifindex);
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

static int pimsm_IgmpMrtResProcMemberDel(uint32_t ifindex,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType)
{
#if 0
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtRes;
    PIMSM_IGMP_MRT_RESOURCE_T *pstIgmpMrtResNext;
    VOS_IP_ADDR src_addr;
    VOS_IP_ADDR grp_addr;
    struct pimsm_oif *oif;
    struct pimsm_oif *pstOilNext;

    if (NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }
    memcpy(&grp_addr, pstGrpAddr, sizeof(grp_addr));

    if ((PIMSM_IF_INCLUDE == emType) && (NULL == pstSrcAddr))
    {
        //no return
        //delete all
    }

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType) || (NULL == pstSrcAddr))
    {
        memset(&src_addr, 0, sizeof(src_addr));
    }
    else
    {
        memcpy(&src_addr, pstSrcAddr, sizeof(VOS_IP_ADDR));
    }

    if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType) ||
            ((PIMSM_IF_INCLUDE == emType) && (NULL != pstSrcAddr)) ||
            ((PIMSM_IF_EXCLUDE == emType) && (NULL == pstSrcAddr)))
    {
        /* IGMPv1 --> (*,G) */
        /* IGMPv2 --> (*,G) */
        /* INCLUDE --> (S,G) */
        /* EXCLUDE_NULL --> (*,G) */
        pimsm_IgmpMrtResEntryDel(&src_addr, &grp_addr, ifindex);
        pstIgmpMrtRes = pimsm_IgmpMrtResEntryFind(g_IgmpMrtResourceCount.pstIgmpMrtResourceList, &src_addr, pstGrpAddr);
        if (NULL == pstIgmpMrtRes)
        {
            return VOS_OK;
        }

        if (NULL == pstIgmpMrtRes->pstOilist)
        {
            pimsm_IgmpMrtResEntryDel(&src_addr, &grp_addr, 0);//出接口为空则删除此条目
        }

        /* 如果IGMPv1和IGMPv2, 或者是排除模式下源为空的情况下, 不仅要删除(*,G)的出接口 也要将所有(S,G)下面的出接口删除*/
        if ((PIMSM_IF_IGMPv1 == emType) || (PIMSM_IF_IGMPv2 == emType) || ((PIMSM_IF_EXCLUDE == emType) && (NULL == pstSrcAddr)))
        {
            pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
            while(NULL != pstIgmpMrtRes)
            {
                pstIgmpMrtResNext = pstIgmpMrtRes->next;
                if ((0 != pstIgmpMrtRes->src_addr.u32_addr[0]) && (0 == ip_AddressCompare(&pstIgmpMrtRes->grp_addr, pstGrpAddr)))
                {
                    pimsm_IgmpMrtResProcMemberDel(ifindex, &pstIgmpMrtRes->src_addr, pstGrpAddr, PIMSM_IF_INCLUDE);
                }
                pstIgmpMrtRes = pstIgmpMrtResNext;
            }
        }

        return VOS_OK;

    }
    else if ((PIMSM_IF_INCLUDE == emType) && (NULL == pstSrcAddr))
    {
        /* 包含模式下源为NULL, 此时删除所有的(S,G)的出接口*/
        pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
        while(NULL != pstIgmpMrtRes)
        {
            pstIgmpMrtResNext = pstIgmpMrtRes->next;
            if ((0 != pstIgmpMrtRes->src_addr.u32_addr[0]) && (0 == ip_AddressCompare(&pstIgmpMrtRes->grp_addr, pstGrpAddr)))
            {
                pimsm_IgmpMrtResProcMemberDel(ifindex, &pstIgmpMrtRes->src_addr, pstGrpAddr, PIMSM_IF_INCLUDE);
            }
            pstIgmpMrtRes = pstIgmpMrtResNext;
        }
    }
    else if (PIMSM_IF_EXCLUDE == emType)
    {
        /* 排除模式下源不为NULL, 添加到(S,G) 和(*,G) , 如果(*,G) 不存在, 则新建*/
        pstIgmpMrtRes = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
        while(NULL != pstIgmpMrtRes)
        {
            pstIgmpMrtResNext = pstIgmpMrtRes->next;
            if ((0 == ip_AddressCompare(&pstIgmpMrtRes->src_addr, pstSrcAddr)) && (0 == ip_AddressCompare(&pstIgmpMrtRes->grp_addr, pstGrpAddr)))
            {
                pimsm_IgmpMrtResProcMemberAdd(ifindex, &pstIgmpMrtRes->src_addr, pstGrpAddr, PIMSM_IF_INCLUDE);
            }
            pstIgmpMrtRes = pstIgmpMrtResNext;
        }

        pimsm_IgmpMrtResProcMemberAdd(ifindex, NULL, pstGrpAddr, PIMSM_IF_EXCLUDE);
    }
    else
    {
        return VOS_ERROR;
    }
#endif

    return VOS_OK;
}

static int pimsm_IfMemberChangedCheck()
{
    PIMSM_IGMP_MRT_RESOURCE_T * const pstIgmpMrtResOld = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
    struct pimsm_interface_member *pstIfMember;
    PIMSM_IGMP_MRT_RESOURCE_T *pstResourceNew;
    PIMSM_IGMP_MRT_RESOURCE_T *pstResourceOld;
    struct pimsm_interface_entry *pimsm_ifp;
    PIMSM_ADDR_LIST_T *pstSrcNode;
    struct pimsm_oif *pstOif;
    struct pimsm_oif *oil_1;
    struct pimsm_oif *oil_2;

    g_IgmpMrtResourceCount.pstIgmpMrtResourceList = NULL;

    PIM_DEBUG("Enter pimsm_IfMemberChangedCheck.\n");
    pimsm_ifp = g_pimsm_interface_list;
    while(NULL != pimsm_ifp)
    {
        pstIfMember = pimsm_ifp->pstMemberList;
        while(NULL != pstIfMember)
        {
            pstSrcNode = pstIfMember->pSrcAddrList;
            if (NULL == pstSrcNode) //Exclude 存在源为NULL 的情况
            {
                pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, NULL, &pstIfMember->grp_addr, pstIfMember->type);
            }
            else
            {
                while(NULL != pstSrcNode)
                {
                    pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, &pstSrcNode->addr, &pstIfMember->grp_addr, pstIfMember->type);
                    pstSrcNode = pstSrcNode->pstNext;
                }
            }

            pstIfMember = pstIfMember->next;
        }

        pimsm_ifp = pimsm_ifp->next;
    }

    pstResourceNew = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
    pstResourceOld = pstIgmpMrtResOld;
    if (NULL == pstResourceNew)
    {
        while(pstResourceOld)
        {
            /* delete all old */
            pstOif = pstResourceOld->pstOilist;
            while(pstOif)
            {
                pimsm_DelLocalReceiver(&pstResourceOld->src_addr, &pstResourceOld->grp_addr, pstResourceOld->type, pstOif->ifindex);
                pstOif = pstOif->next;
            }
            pstResourceOld = pstResourceOld->next;
        }
    }
    else if (NULL == pstResourceOld)
    {
        while(pstResourceNew)
        {
            /* add all new */
            pstOif = pstResourceNew->pstOilist;
            while(pstOif)
            {
                PIM_DEBUG("Will call pimsm_AddLocalReceiver.\n");
                pimsm_AddLocalReceiver(&pstResourceNew->src_addr, &pstResourceNew->grp_addr, pstResourceNew->type, pstOif->ifindex);
                pstOif = pstOif->next;
            }
            pstResourceNew = pstResourceNew->next;
        }
    }
    else
    {
        while(pstResourceNew)
        {
            pstResourceOld = pstIgmpMrtResOld;
            while(pstResourceOld)
            {
                if ((0 == ip_AddressCompare(&pstResourceOld->src_addr, &pstResourceNew->src_addr)) &&
                        (0 == ip_AddressCompare(&pstResourceOld->grp_addr, &pstResourceNew->grp_addr)) &&
                        (pstResourceOld->type == pstResourceNew->type))
                {
                    break;
                }
                pstResourceOld = pstResourceOld->next;
            }
            if (NULL == pstResourceOld)
            {
                /* add all oil local member */
                pstOif = pstResourceNew->pstOilist;
                while(pstOif)
                {
                    PIM_DEBUG("Will call pimsm_AddLocalReceiver.\n");
                    pimsm_AddLocalReceiver(&pstResourceNew->src_addr, &pstResourceNew->grp_addr, pstResourceNew->type, pstOif->ifindex);
                    pstOif = pstOif->next;
                }
            }
            else
            {
                oil_1 = pimsm_OilSubOil(pstResourceNew->pstOilist, pstResourceOld->pstOilist);
                oil_2 = pimsm_OilSubOil(pstResourceOld->pstOilist, pstResourceNew->pstOilist);
                pstOif = oil_1;
                while(pstOif)
                {
                    PIM_DEBUG("Will call pimsm_AddLocalReceiver.\n");
                    pimsm_AddLocalReceiver(&pstResourceNew->src_addr, &pstResourceNew->grp_addr, pstResourceNew->type, pstOif->ifindex);
                    pstOif = pstOif->next;
                }
                pstOif = oil_2;
                while(pstOif)
                {
                    pimsm_DelLocalReceiver(&pstResourceOld->src_addr, &pstResourceOld->grp_addr, pstResourceOld->type, pstOif->ifindex);
                    pstOif = pstOif->next;
                }
                pimsm_FreeOil(oil_1);
                pimsm_FreeOil(oil_2);
            }
            pstResourceNew = pstResourceNew->next;
        }

        pstResourceOld = pstIgmpMrtResOld;
        while(pstResourceOld)
        {
            pstResourceNew = g_IgmpMrtResourceCount.pstIgmpMrtResourceList;
            while(pstResourceNew)
            {
                if ((0 == ip_AddressCompare(&pstResourceOld->src_addr, &pstResourceNew->src_addr)) &&
                        (0 == ip_AddressCompare(&pstResourceOld->grp_addr, &pstResourceNew->grp_addr)) &&
                        (pstResourceOld->type == pstResourceNew->type))
                {
                    break;
                }
                pstResourceNew = pstResourceNew->next;
            }
            if (NULL == pstResourceNew)
            {
                pstOif = pstResourceOld->pstOilist;
                while(pstOif)
                {
                    pimsm_DelLocalReceiver(&pstResourceOld->src_addr, &pstResourceOld->grp_addr, pstResourceOld->type, pstOif->ifindex);
                    pstOif = pstOif->next;
                }
            }
            pstResourceOld = pstResourceOld->next;
        }
    }
    pimsm_DestroyMrtResourceList(pstIgmpMrtResOld);

    return VOS_OK;
}

#define igmp_v

static int pimsm_IGMPv1GrpMemberAdd(struct pimsm_interface_entry *pimsm_ifp,PIMSM_ADDR_LIST_T *pstGrpListHead)
{
    PIMSM_ADDR_LIST_T *pstGrpNode = NULL;
    //struct pimsm_updownstream_if_entry *pstDownIf;

    if((NULL == pstGrpListHead) || (NULL == pimsm_ifp))
    {
        return VOS_ERROR;
    }

    for (pstGrpNode = pstGrpListHead; NULL != pstGrpNode; pstGrpNode = pstGrpNode->pstNext)
    {
        /*
        if (VOS_OK != pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv1))
        {
        	break;
        }
        */
        pimsm_CreateIfMember(pimsm_ifp, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv1);
    }

    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

static int pimsm_IGMPv1GrpMemberDel(struct pimsm_interface_entry *pimsm_ifp,PIMSM_ADDR_LIST_T  *pstGrpListHead)
{
    PIMSM_ADDR_LIST_T *pstGrpNode = NULL;
    //struct pimsm_updownstream_if_entry *pstDownIf;
    //struct pimsm_mrt_entry *mrt_entry;

    if((NULL == pstGrpListHead) || (NULL == pimsm_ifp))
    {
        return VOS_ERROR;
    }

    for (pstGrpNode = pstGrpListHead; NULL != pstGrpNode; pstGrpNode = pstGrpNode->pstNext)
    {
        //pimsm_IgmpMrtResProcMemberDel(pimsm_ifp->ifindex, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv1);
        pimsm_DestroyIfMember(pimsm_ifp, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv1);
    }

    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

static int pimsm_IGMPv2GrpMemberAdd(struct pimsm_interface_entry *pimsm_ifp,PIMSM_ADDR_LIST_T *pstGrpListHead)
{
    PIMSM_ADDR_LIST_T *pstGrpNode = NULL;
    //struct pimsm_updownstream_if_entry *pstDownIf;

    if((NULL == pstGrpListHead) || (NULL == pimsm_ifp))
    {
        return VOS_ERROR;
    }

    for (pstGrpNode = pstGrpListHead; NULL != pstGrpNode; pstGrpNode = pstGrpNode->pstNext)
    {
        /*
        if (VOS_OK != pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv2))
        {
        	break;
        }
        */
        pimsm_CreateIfMember(pimsm_ifp, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv2);
    }

    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

static int pimsm_IGMPv2GrpMemberDel(struct pimsm_interface_entry *pimsm_ifp,PIMSM_ADDR_LIST_T  *pstGrpListHead)
{
    PIMSM_ADDR_LIST_T *pstGrpNode = NULL;
    //struct pimsm_updownstream_if_entry *pstDownIf;
    //struct pimsm_mrt_entry *mrt_entry;

    if((NULL == pstGrpListHead) || (NULL == pimsm_ifp))
    {
        return VOS_ERROR;
    }

    for (pstGrpNode = pstGrpListHead; NULL != pstGrpNode; pstGrpNode = pstGrpNode->pstNext)
    {
        //pimsm_IgmpMrtResProcMemberDel(pimsm_ifp->ifindex, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv2);
        pimsm_DestroyIfMember(pimsm_ifp, NULL, &pstGrpNode->addr, PIMSM_IF_IGMPv2);
    }

    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

static int pimsm_IGMPv3GrpMemberAdd(struct pimsm_interface_entry *pimsm_ifp,PIMSM_RECORD_LIST_T *pstRecordListEntry,PIMSM_RECORD_TYPE_T emType)
{
    PIMSM_ADDR_LIST_T *pstSrcNode = NULL;

    PIM_DEBUG("Enter pimsm_IGMPv3GrpMemberAdd.\n");

    if((NULL == pstRecordListEntry) || (NULL == pimsm_ifp))
    {
        PIM_DEBUG("return pimsm_IGMPv3GrpMemberAdd here.\n");
        return VOS_ERROR;
    }

    if (NULL == pstRecordListEntry->pstSourListHead)
    {
        /*
        if (VOS_OK != pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, NULL, &pstRecordListEntry->grp_addr, emType))
        {
        	return VOS_ERROR;
        }
        */
        pimsm_CreateIfMember(pimsm_ifp, NULL, &pstRecordListEntry->grp_addr, emType);

        PIM_DEBUG("will call pimsm_IfMemberChangedCheck.\n");
        pimsm_IfMemberChangedCheck();

        return VOS_OK;
    }

    pstSrcNode = pstRecordListEntry->pstSourListHead;
    while (NULL != pstSrcNode)
    {
        /*
        if (VOS_OK != pimsm_IgmpMrtResProcMemberAdd(pimsm_ifp->ifindex, &pstSrcNode->addr, &pstRecordListEntry->grp_addr, emType))
        {
        	return VOS_ERROR;
        }
        */
        pimsm_CreateIfMember(pimsm_ifp, &pstSrcNode->addr, &pstRecordListEntry->grp_addr, emType);
        pstSrcNode = pstSrcNode->pstNext;
    }

    PIM_DEBUG("will call pimsm_IfMemberChangedCheck.\n");
    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

static int pimsm_IGMPv3GrpMemberDel(struct pimsm_interface_entry  *pimsm_ifp,PIMSM_RECORD_LIST_T *pstRecordListEntry)
{
    PIMSM_ADDR_LIST_T *pstSrcNode = NULL;
    PIMSM_RECORD_TYPE_T emType;
    //VOS_IP_ADDR src_addr;

    if((NULL == pstRecordListEntry) || (NULL == pimsm_ifp))
    {
        return VOS_ERROR;
    }

    if (IGMPv3_TO_PIMSM_FILTER_MODE_INCLUDE == pstRecordListEntry->wFilterMode)
    {
        emType = PIMSM_IF_INCLUDE;
    }
    else if (IGMPv3_TO_PIMSM_FILTER_MODE_EXCLUDE == pstRecordListEntry->wFilterMode)
    {
        emType = PIMSM_IF_EXCLUDE;
    }
    else
    {
        return VOS_ERROR;
    }

    if (NULL == pstRecordListEntry->pstSourListHead)
    {
        //pimsm_IgmpMrtResProcMemberDel(pimsm_ifp->ifindex, NULL, &pstRecordListEntry->grp_addr, emType);
        pimsm_DestroyIfMember(pimsm_ifp, NULL, &pstRecordListEntry->grp_addr, emType);
    }
    else
    {
        pstSrcNode = pstRecordListEntry->pstSourListHead;
        while(NULL != pstSrcNode)
        {
            //pimsm_IgmpMrtResProcMemberDel(pimsm_ifp->ifindex, &pstSrcNode->addr, &pstRecordListEntry->grp_addr, emType);
            pimsm_DestroyIfMember(pimsm_ifp, &pstSrcNode->addr, &pstRecordListEntry->grp_addr, emType);
            pstSrcNode = pstSrcNode->pstNext;
        }
    }

    pimsm_IfMemberChangedCheck();

    return VOS_OK;
}

#define igmp_proc

int pimsm_IgmpGrpMemberProc(uint32_t   ifindex,void *p,PIMSM_IGMP_MSG_TYPE_T emType)
{
    PIMSM_RECORD_LIST_T *pstRecordListHead = NULL;
    PIMSM_ADDR_LIST_T *pstGroupListHead = NULL;
    struct pimsm_interface_entry *pimsm_ifp = NULL;
    int ret = VOS_OK;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(pimsm_ifp == NULL)
    {
        PIM_DEBUG("The interface(%d) cann't be found!\n", ifindex);
        return VOS_ERROR;
    }

    pstRecordListHead = (PIMSM_RECORD_LIST_T *)p;
    pstGroupListHead = (PIMSM_ADDR_LIST_T *)p;

    PIM_DEBUG("in pimsm_IgmpGrpMemberProc, emType:%d.\n", emType);
    switch(emType)
    {
    case PIMSM_IN_SSM_RANGE_INCLUDE_ADD:
        ret = pimsm_IGMPv3GrpMemberAdd(pimsm_ifp, pstRecordListHead, PIMSM_IF_INCLUDE);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberAdd return error!\n");
        }
        break;
    case PIMSM_IN_SSM_RANGE_INCLUDE_DEL:
        ret = pimsm_IGMPv3GrpMemberDel(pimsm_ifp, pstRecordListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberDel return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_INCLUDE_ADD:
        ret = pimsm_IGMPv3GrpMemberAdd(pimsm_ifp, pstRecordListHead, PIMSM_IF_INCLUDE);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberAdd return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_INCLUDE_DEL:
        ret = pimsm_IGMPv3GrpMemberDel(pimsm_ifp, pstRecordListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberDel return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD:
        PIM_DEBUG("Recv PIMSM_OUT_SSM_RANGE_EXCLUDE_ADD msg.\n");
        ret = pimsm_IGMPv3GrpMemberAdd(pimsm_ifp, pstRecordListHead, PIMSM_IF_EXCLUDE);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberAdd return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_EXCLUDE_DEL:
        ret = pimsm_IGMPv3GrpMemberDel(pimsm_ifp, pstRecordListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv3GrpMemberDel return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_IGMPv1_ADD:
        ret = pimsm_IGMPv1GrpMemberAdd(pimsm_ifp, pstGroupListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv1GrpMemberAdd return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_IGMPv1_DEL:
        ret = pimsm_IGMPv1GrpMemberDel(pimsm_ifp, pstGroupListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv1GrpMemberDel return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_IGMPv2_ADD:
        ret = pimsm_IGMPv2GrpMemberAdd(pimsm_ifp, pstGroupListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv2GrpMemberAdd return error!\n");
        }
        break;
    case PIMSM_OUT_SSM_RANGE_IGMPv2_DEL:
        ret = pimsm_IGMPv2GrpMemberDel(pimsm_ifp, pstGroupListHead);
        if(ret != VOS_OK)
        {
            PIM_DEBUG("call pim_IGMPv2GrpMemberDel return error!\n");
        }
        break;
    default:
        break;
    }

    return ret;
}

#endif

