#include "pimsm_define.h"
#if INCLUDE_PIMSM
#include <zebra.h>
#include "memory.h"
#include "hash.h"

#include "pimsm_rp.h"
#include "pimsm.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_msg.h"
#include "pimsm_inet.h"
#include "pimsm_interface.h"
#include "vos_types.h"

extern struct hash *g_group_hash;

#define rp

int pimsm_staticrpconfig (struct vty *vty)
{
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntry = NULL;
    VOS_IP_ADDR stGroupMask;

    pstStaticRpEntry = g_stPimsm.pstStaticRpList;

    while (NULL != pstStaticRpEntry)
    {

        memset(&stGroupMask,0,sizeof(VOS_IP_ADDR));
        MASKLEN_TO_MASK6(pstStaticRpEntry->group_masklen,stGroupMask);
        if(ip_isAnyAddress(&(pstStaticRpEntry->group_addr)))
        {

            vty_out(vty,"ip pim-sm rp-address %s \n", pim_InetFmt(&(pstStaticRpEntry->stRPAddress)));
        }
        else
        {

            vty_out(vty,"ip pim-sm rp-address %s %s %s\n", pim_InetFmt(&(pstStaticRpEntry->stRPAddress)), pim_InetFmt(&(pstStaticRpEntry->group_addr)), pim_InetFmt(&stGroupMask));
        }
        pstStaticRpEntry = pstStaticRpEntry->pstNext;
    }


    return VOS_OK;
}

int pimsm_StaticRpAdd (VOS_IP_ADDR *pstGroupAddr, VOS_IP_ADDR *pstGroupMask, VOS_IP_ADDR *pstRpAddr)
{
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntry = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntryNew = NULL;
    VOS_IP_ADDR stGroupMask;
    uint32_t dwMaskLen;

    zassert(NULL != pstGroupAddr);
    zassert(NULL != pstGroupMask);
    zassert(NULL != pstRpAddr);

    stGroupMask = *pstGroupMask;
    MASK_TO_MASKLEN(stGroupMask, dwMaskLen);

    printf("[static rp add] RP:%s, G:%s/%d\n", pim_InetFmt(pstRpAddr), pim_InetFmt(pstGroupAddr), dwMaskLen);

    pstStaticRpEntry = g_stPimsm.pstStaticRpList;
    while (NULL != pstStaticRpEntry)
    {
        if ( pim_MatchPrefix(pstGroupAddr, &pstStaticRpEntry->group_addr, dwMaskLen)
                && (pstStaticRpEntry->group_masklen == dwMaskLen) )
        {
            break;
        }

        pstStaticRpEntry = pstStaticRpEntry->pstNext;
    }

    /* ????????????update and return */
    if (NULL != pstStaticRpEntry)
    {
        memcpy(&(pstStaticRpEntry->stRPAddress), pstRpAddr, sizeof(VOS_IP_ADDR));
    }
    else /* ?????????,?????? */
    {
        pstStaticRpEntryNew = XMALLOC(MTYPE_PIM_STATIC_RP, sizeof(PIMSM_STATIC_RP_ENTRY_T));
        if (pstStaticRpEntryNew == NULL)
        {
            PIM_DEBUG("memory not enough!\n");
            return VOS_ERROR;
        }
        else
        {
            memset(pstStaticRpEntryNew, 0x00, sizeof(PIMSM_STATIC_RP_ENTRY_T));
            memcpy(&(pstStaticRpEntryNew->stRPAddress), pstRpAddr, sizeof(VOS_IP_ADDR));
            memcpy(&(pstStaticRpEntryNew->group_addr), pstGroupAddr, sizeof(VOS_IP_ADDR));
            ip_GetPrefixFromAddr(&(pstStaticRpEntryNew->group_addr), dwMaskLen);
            pstStaticRpEntryNew->group_masklen = dwMaskLen;

            pstStaticRpEntryNew->pstNext = g_stPimsm.pstStaticRpList;
            g_stPimsm.pstStaticRpList = pstStaticRpEntryNew;
        }
    }

    pimsm_RpChangeCheck(pstGroupAddr, dwMaskLen);

    return VOS_OK;
}

int pimsm_StaticRpDel (VOS_IP_ADDR *pstGroupAddr, VOS_IP_ADDR *pstGroupMask, VOS_IP_ADDR *pstRpAddr)
{
    PIMSM_STATIC_RP_ENTRY_T *pstPrev = NULL;
    PIMSM_STATIC_RP_ENTRY_T *pstCurr = NULL;
    VOS_IP_ADDR stGroupMask;
    uint32_t dwMaskLen;

    zassert(NULL != pstGroupAddr);
    zassert(NULL != pstGroupMask);
    zassert(NULL != pstRpAddr);

    stGroupMask = *pstGroupMask;
    MASK_TO_MASKLEN(stGroupMask, dwMaskLen);

    printf("[static rp delete] RP:%s, G:%s/%d\n", pim_InetFmt(pstRpAddr), pim_InetFmt(pstGroupAddr), dwMaskLen);

    pstCurr = g_stPimsm.pstStaticRpList;
    while (pstCurr != NULL)
    {
        if ( (ip_AddressCompare(&(pstCurr->stRPAddress), pstRpAddr) == 0)
                && (dwMaskLen == pstCurr->group_masklen)
                && pim_MatchPrefix(pstGroupAddr, &pstCurr->group_addr, dwMaskLen) )
        {
            break;
        }
        pstPrev = pstCurr;
        pstCurr = pstCurr->pstNext;
    }

    if (pstCurr == NULL)
    {
        PIM_DEBUG("no corresponding RP entry to delete!\n");
        return VOS_ERROR;
    }
    else
    {
        if (pstCurr == g_stPimsm.pstStaticRpList)
        {
            g_stPimsm.pstStaticRpList = pstCurr->pstNext;
        }
        else
        {
            pstPrev->pstNext = pstCurr->pstNext;
        }

        XFREE(MTYPE_PIM_STATIC_RP, pstCurr);
    }

    pimsm_RpChangeCheck(pstGroupAddr, dwMaskLen);

    return VOS_OK;
}

static int pimsm_StaticRpSearch (VOS_IP_ADDR *pstGrpAddr, VOS_IP_ADDR *pstRpAddr)
{
    PIMSM_STATIC_RP_ENTRY_T *pstStaticRpEntry = NULL;
    uint16_t wMaskLen = 0;
    uint8_t find = 0;

    zassert(pstGrpAddr != NULL);
    zassert(pstRpAddr != NULL);

    pstStaticRpEntry = g_stPimsm.pstStaticRpList;
    while (pstStaticRpEntry != NULL )
    {
        if(pim_MatchPrefix(pstGrpAddr, &pstStaticRpEntry->group_addr, pstStaticRpEntry->group_masklen)
                && (wMaskLen <= pstStaticRpEntry->group_masklen) )
        {
            *pstRpAddr = pstStaticRpEntry->stRPAddress;
            wMaskLen = pstStaticRpEntry->group_masklen;
            find = 1;
        }

        pstStaticRpEntry = pstStaticRpEntry->pstNext;
    }

    if (find)
    {
        return VOS_OK;
    }
    else
    {
        return VOS_ERROR;
    }
}

int pimsm_RpSearch (VOS_IP_ADDR *pstGrpAddr, VOS_IP_ADDR *pstRpAddr)
{
    zassert(pstGrpAddr != NULL);
    zassert(pstRpAddr != NULL);

    if (VOS_OK == pimsm_StaticRpSearch(pstGrpAddr, pstRpAddr))
    {
        return VOS_OK;
    }

    if (VOS_OK == pim_BsrRpSearch(pstGrpAddr, pstRpAddr))
    {
        return VOS_OK;
    }

    return VOS_ERROR;
}

/* Whether I am the RP of the specified group address. */
uint8_t pimsm_IamRP(VOS_IP_ADDR *pstGrpAddr)
{
    VOS_IP_ADDR rp_addr;
    int ret;

    ret = pimsm_RpSearch(pstGrpAddr, &rp_addr);
    if (VOS_OK != ret)
    {
        return FALSE;
    }

    if (pimsm_IsLocalAddress(&rp_addr))
    {
        return TRUE;
    }

    return FALSE;
}

int pimsm_RpChangeCheck(VOS_IP_ADDR *pstGrpAddr, uint16_t wMaskLen)
{
    struct pimsm_updown_state_machine_event_para stUpdownPara;
    struct pimsm_mrt_entry *pstSrcGrpEntryNext;
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_mrt_entry *src_grp_entry;
    //struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_grp_entry *pstGrpEntry;
    VOS_IP_ADDR stNewRpAddr;
    uint8_t bIbecomeRP;
    struct pimsm_rpf *pstRpf;

    if(NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }

    printf("RP address for group(%s/%d) change check: Add your code to here.\n", pim_InetFmt(pstGrpAddr), wMaskLen);


    if(g_group_hash != NULL)
    {
        hash_traversal_start(g_group_hash, pstGrpEntry);
        if(NULL != pstGrpEntry)
        {
            if (pim_MatchPrefix(&pstGrpEntry->address, pstGrpAddr, wMaskLen))
            {
                pimsm_RpSearch(&pstGrpEntry->address, &stNewRpAddr);
                bIbecomeRP = pimsm_IamRP(&pstGrpEntry->address);

                //Register State Machine About
                src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                while(NULL != src_grp_entry)
                {
                    pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                    if (bIbecomeRP)
                    {
                        pimsm_RegisterStateMachineEventProc(src_grp_entry, PimsmRegEventCouldRegToFalse);
                    }
                    else
                    {
                        pimsm_RegisterStateMachineEventProc(src_grp_entry, PimsmRegEventRpChanged);
                    }

                    src_grp_entry = pstSrcGrpEntryNext;
                }

                //(*,G) State Machine About
                start_grp_entry = pstGrpEntry->pstStarMrtLink;
                if (NULL != start_grp_entry)
                {
                    stUpdownPara.old_upstream_nbr_addr = start_grp_entry->upstream_if.up_stream_nbr;
                    pstRpf = pimsm_SearchRpf(&stNewRpAddr);
                    if(pstRpf != NULL)
                    {
                        stUpdownPara.new_upstream_nbr_addr = pstRpf->rpf_nbr_addr;
                        pimsm_UpdownstreamStateMachineEventProc(pstGrpEntry->pstStarMrtLink,
                                                                PIMSM_UPSTREAM_IF,
                                                                0,
                                                                PimsmRpfaStarGrpChangesNotAssertEvent,
                                                                &stUpdownPara);

                        start_grp_entry->upstream_if.ifindex = pstRpf->rpf_if;
                        start_grp_entry->upstream_if.up_stream_nbr = start_grp_entry->upstream_if.up_stream_nbr;
                    }
                }

                pstGrpEntry->rp_addr = stNewRpAddr;
            }

            goto return_back;
        }
        hash_traversal_end();
    }

return_back:

    return VOS_OK;
}

#define source

int pimsm_IsAcceptSource (VOS_IP_ADDR * src_addr)
{
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstPimAcptRegEntry = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstTmp = NULL;
    uint16_t   wMaskLen = 0;
    uint8_t result_find = FALSE;

    if (src_addr == NULL)
    {
        return result_find;
    }

    pstTmp = g_stPimsm.pstAcceptRegisterList;
    while (NULL != pstTmp)
    {
        if (pim_MatchPrefix(src_addr, &pstTmp->stSourceAddr, pstTmp->wSourceMaskLen)
                && (pstTmp->wSourceMaskLen >= wMaskLen))
        {
            wMaskLen = pstTmp->wSourceMaskLen;
            pstPimAcptRegEntry = pstTmp;
            result_find = TRUE;
        }

        pstTmp = pstTmp->pstNext;
    }

    return result_find;
}

int pimsm_acceptsourceconfig(struct vty *vty)
{
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstPimAcptRegEntry = NULL;
    VOS_IP_ADDR stSourceMask;

    pstPimAcptRegEntry = g_stPimsm.pstAcceptRegisterList;
    while (NULL != pstPimAcptRegEntry)
    {
        memset(&stSourceMask,0,sizeof(VOS_IP_ADDR));
        MASKLEN_TO_MASK6(pstPimAcptRegEntry->wSourceMaskLen,stSourceMask);

        vty_out(vty,"ip pim-sm accept-register %s %s %s", pim_InetFmt(&pstPimAcptRegEntry->stSourceAddr),pim_InetFmt(&stSourceMask),VTY_NEWLINE);
        pstPimAcptRegEntry = pstPimAcptRegEntry->pstNext;
    }


    return VOS_OK;
}




int pimsm_AcceptSourceAdd(VOS_IP_ADDR *src_addr, VOS_IP_ADDR * pstSrcMask)
{
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstPimAcptRegEntry = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T * pstPimAcptRegAdd = NULL;
    VOS_IP_ADDR stSourceMask;
    uint32_t dwMaskLen;

    zassert(NULL != src_addr);
    zassert(NULL != pstSrcMask);

    stSourceMask = *pstSrcMask;
    MASK_TO_MASKLEN(stSourceMask, dwMaskLen);

    printf("[Accept register add] S:%s/%d\n", pim_InetFmt(src_addr), dwMaskLen);

    pstPimAcptRegEntry = g_stPimsm.pstAcceptRegisterList;
    while (NULL != pstPimAcptRegEntry)
    {
        if ( pim_MatchPrefix(src_addr, &pstPimAcptRegEntry->stSourceAddr, dwMaskLen)
                && (pstPimAcptRegEntry->wSourceMaskLen == dwMaskLen) )
        {
            break;
        }

        pstPimAcptRegEntry = pstPimAcptRegEntry->pstNext;
    }

    /* ????????????return */
    if (NULL != pstPimAcptRegEntry)
    {
        return VOS_OK;
    }
    else /* ?????????,?????? */
    {
        pstPimAcptRegAdd = XMALLOC(MTYPE_PIM_ACCEPT_REGISTER, sizeof(PIMSM_ACCEPT_REGISTER_ENTRY_T));
        if (pstPimAcptRegAdd == NULL)
        {
            return VOS_ERROR;
        }
        else
        {
            memset(pstPimAcptRegAdd, 0x00, sizeof(PIMSM_ACCEPT_REGISTER_ENTRY_T));
            memcpy(&(pstPimAcptRegAdd->stSourceAddr), src_addr, sizeof(VOS_IP_ADDR));
            ip_GetPrefixFromAddr(&(pstPimAcptRegAdd->stSourceAddr), dwMaskLen);
            pstPimAcptRegAdd->wSourceMaskLen = dwMaskLen;

            pstPimAcptRegAdd->pstNext = g_stPimsm.pstAcceptRegisterList;
            g_stPimsm.pstAcceptRegisterList = pstPimAcptRegAdd;
        }
    }

    return VOS_OK;
}

int pimsm_AcceptSourceDel(VOS_IP_ADDR * src_addr, VOS_IP_ADDR * pstSrcMask)
{
    PIMSM_ACCEPT_REGISTER_ENTRY_T *pstPrev = NULL;
    PIMSM_ACCEPT_REGISTER_ENTRY_T *pstCurr = NULL;
    VOS_IP_ADDR stSourceMask;
    uint32_t dwMaskLen;

    zassert(NULL != src_addr);
    zassert(NULL != pstSrcMask);

    stSourceMask = *pstSrcMask;
    MASK_TO_MASKLEN(stSourceMask, dwMaskLen);

    printf("[Accept register delete] S:%s/%d\n", pim_InetFmt(src_addr), dwMaskLen);

    pstCurr = g_stPimsm.pstAcceptRegisterList;
    while (pstCurr != NULL)
    {
        if ( (dwMaskLen == pstCurr->wSourceMaskLen)
                && pim_MatchPrefix(src_addr, &pstCurr->stSourceAddr, dwMaskLen) )
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
        if (pstCurr == g_stPimsm.pstAcceptRegisterList)
        {
            g_stPimsm.pstAcceptRegisterList = pstCurr->pstNext;
        }
        else
        {
            pstPrev->pstNext = pstCurr->pstNext;
        }

        XFREE(MTYPE_PIM_ACCEPT_REGISTER, pstCurr);
        return VOS_OK;
    }
}

#endif
