#include "pimsm_define.h"

#if INCLUDE_PIMSM
#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "hash.h"
#include "memory.h"

#include "pimd.h"
#include "pim_str.h"
#include "pim_zebra.h"
#include "pim_rpf.h"
#include "pim_time.h"

#include "vos_types.h"
#include "interface_define.h"
#include "pimsm_rp.h"
#include "pimsm.h"
#include "pimsm_mrtmgt.h"
#include "pimsm_msg.h"
#include "pimsm_igmp.h"
#include "pimsm_interface.h"
#include "pimsm_datagramproc.h"
#include "pimsm_timer.h"
#include "pimsm_inet.h"
#include "vty.h"

#include "hash.h"

struct hash *g_group_hash = NULL;
struct hash *g_source_hash = NULL;
struct pimsm_rpf *g_rpf_list;
struct pimsm_mrt_hardware_entry *g_multicast_router_hardware_list = NULL;
int pimsm_DestroyAllDownstreamIf(struct pimsm_mrt_entry *mrt_entry);
void pimsm_FreeGrpEntry(struct pimsm_grp_entry *pstGrpEntry);
void pimsm_FreeSrcEntry(struct pimsm_src_entry *pstSrcEntry);
void pimsm_DestroyAllSrcEntry(void);
char* pimsm_DisplayOneMrtEntry(struct pimsm_mrt_entry *mrt_entry);
int pimsm_MrtDelTimerStop(struct pimsm_mrt_entry *mrt_entry);
int pimsm_MrtDelTimerStart(struct pimsm_mrt_entry *mrt_entry, uint32_t dwTimerValue);
int pimsm_MrtUpdateToRtmgt(struct mrtmgt_mrt_update_entry *pEntryData);

int pimsm_SrcHashCmp(struct pimsm_src_entry *pstSrcEntry1,struct pimsm_src_entry *pstSrcEntry2);
int pimsm_DestroyAllAssertIf(struct pimsm_mrt_entry *mrt_entry);
int pimsm_DestroyAllHardwareEntry(void);

#if 0 //FIXME: for Unicast routing synchronization
SEM_ID g_pstPimsmRegSem = NULL; //add by wuyan 2018.08.02
#endif

struct list *g_msg_pim2rtmgt_list = NULL;

extern struct pimsm_interface_entry *g_pimsm_interface_list;

static struct pimsm_rpf *pimsm_CreateRpfEntry(VOS_IP_ADDR *pstDstAddr);
static int pimsm_TryDestroyGrpEntry(struct pimsm_grp_entry *pstGrpEntry);
static int pimsm_TryDestroySrcEntry(struct pimsm_src_entry *pstSrcEntry);
static uint8_t pimsm_IsCopyToCpu(struct pimsm_mrt_entry *mrt_entry);
uint8_t pimsm_LocalReceiverExist (struct pimsm_mrt_entry *mrt_entry);


#define _hash
#if 1
uint32_t pimsm_GrpHashMake(struct pimsm_grp_entry *pstGrpEntry);
uint32_t pimsm_SrcHashMake(struct pimsm_src_entry *pstSrcEntry);
struct hash_backet *hash_push (struct hash *hash, void *data);
void *hash_pull (struct hash *hash, void *data);
/* allocate new hash backet */
static struct hash_backet *hash_backet_new (void *data)
{
    struct hash_backet *new;

    new = XMALLOC (MTYPE_HASH_BACKET, sizeof (struct hash_backet));
    new->data = data;
    new->next = NULL;

    return new;
}
/* Push data into hash. */
struct hash_backet *hash_push (struct hash *hash, void *data)
{
    uint32_t key;
    struct hash_backet *backet, *mp;

    key = (*hash->hash_key) (data);
    backet = hash_backet_new (data);

    hash->count++;

    if (hash->index[key] == NULL)
        hash->index[key] = backet;
    else
    {
        for (mp = hash->index[key]; mp->next != NULL; mp = mp->next)
            if ((*hash->hash_cmp) (data, mp->data) == 1)
            {
                printf("hash data [%p] was duplicated!\n", data);
                XFREE (MTYPE_HASH_BACKET, backet);
                return NULL;
            }

        if ((*hash->hash_cmp) (data, mp->data) == 1)
        {
            printf("hash account name [%p] was duplicated!\n", data);
            XFREE (MTYPE_HASH_BACKET, backet);
            return NULL;
        }
        mp->next = backet;
    }
    return backet;
}
/* When deletion is finished successfully return data of delete
 *    backet. */
void *hash_pull (struct hash *hash, void *data)
{
    void *ret;
    uint32_t key;
    struct hash_backet *mp;
    struct hash_backet *mpp;

    key = (*hash->hash_key) (data);

    if(hash->index[key] == NULL)
        return NULL;

    mp = mpp = hash->index[key];
    while (mp)
    {
        if((*hash->hash_cmp) (mp->data, data) == 1)
        {
            if (mp == mpp)
                hash->index[key] = mp->next;
            else
                mpp->next = mp->next;

            ret = mp->data;
            XFREE (MTYPE_HASH_BACKET, mp);
            hash->count--;
            return ret;
        }
        mpp = mp;
        mp = mp->next;
    }
    return NULL;
}
#endif



uint32_t pimsm_GrpHashMake(struct pimsm_grp_entry *pstGrpEntry)
{
    VOS_IP_ADDR *pstIpv4Addr = NULL;
    uint32_t key;
    uint32_t c;

    pstIpv4Addr = &pstGrpEntry->address;
    key = 0;

    for(c = 0; c < sizeof(VOS_IP_ADDR); c++)
    {
        key += pstIpv4Addr->u8_addr[c];
    }

    return (key %= HASHTABSIZE);
}

uint32_t pimsm_SrcHashMake(struct pimsm_src_entry *pstSrcEntry)
{
    VOS_IP_ADDR *pstIpv4Addr = NULL;
    uint32_t key;
    uint32_t c;

    pstIpv4Addr = &pstSrcEntry->address;
    key = 0;

    for(c = 0; c < sizeof(VOS_IP_ADDR); c++)
    {
        key += pstIpv4Addr->u8_addr[c];
    }

    return (key %= HASHTABSIZE);
}

int pimsm_GrpHashCmp(struct pimsm_grp_entry *pstGrpEntry1,struct pimsm_grp_entry *pstGrpEntry2);
int pimsm_SrcHashCmp(struct pimsm_src_entry *pstSrcEntry1,struct pimsm_src_entry *pstSrcEntry2);
int pimsm_GrpHashCmp(struct pimsm_grp_entry *pstGrpEntry1,struct pimsm_grp_entry *pstGrpEntry2)
{
    if (0 == ip_AddressCompare(&pstGrpEntry1->address, &pstGrpEntry2->address))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int pimsm_SrcHashCmp(struct pimsm_src_entry *pstSrcEntry1,struct pimsm_src_entry *pstSrcEntry2)
{
    if (0 == ip_AddressCompare(&pstSrcEntry1->address, &pstSrcEntry2->address))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void pimsm_InitHash(void)
{
    g_group_hash = hash_create_size (HASHTABSIZE, (void *)pimsm_GrpHashMake, (void *)pimsm_GrpHashCmp);
    g_source_hash = hash_create_size (HASHTABSIZE, (void *)pimsm_SrcHashMake, (void *)pimsm_SrcHashCmp);
#if 0
    g_group_hash = hash_new(HASHTABSIZE);
    g_group_hash->hash_key = pimsm_GrpHashMake;
    g_group_hash->hash_cmp = pimsm_GrpHashCmp;

    g_source_hash = hash_new(HASHTABSIZE);
    g_source_hash->hash_key = pimsm_SrcHashMake;
    g_source_hash->hash_cmp = pimsm_SrcHashCmp;
#endif
}

#define create

static struct pimsm_grp_entry *pimsm_CreateGrpEntry(VOS_IP_ADDR *pstGrpAddr)
{
    struct pimsm_grp_entry *pstGrpEntry = NULL;
    VOS_IP_ADDR rp_addr;

    if(NULL == pstGrpAddr)
    {
        return NULL;
    }

    pstGrpEntry = XMALLOC( MTYPE_PIM_GROUP, sizeof(struct pimsm_grp_entry));
    if (NULL == pstGrpEntry)
    {
        return NULL;
    }
    memset(pstGrpEntry, 0x00, sizeof(struct pimsm_grp_entry));

    memcpy(&pstGrpEntry->address, pstGrpAddr, sizeof(VOS_IP_ADDR));

    if (pimsm_IsSsmRangeAddr(pstGrpAddr))
    {
        pstGrpEntry->type = PIMSM_SSM_RANGE;
    }
    else
    {
        memset(&rp_addr, 0, sizeof(rp_addr));
        pimsm_RpSearch(pstGrpAddr, &rp_addr);
        memcpy(&pstGrpEntry->rp_addr, &rp_addr, sizeof(VOS_IP_ADDR));
    }

    hash_push(g_group_hash, pstGrpEntry);

    return pstGrpEntry;
}

static struct pimsm_src_entry *pimsm_CreateSrcEntry(VOS_IP_ADDR *src_addr)
{
    struct pimsm_src_entry *pstSrcEntry = NULL;

    if(NULL == src_addr)
    {
        return NULL;
    }

    pstSrcEntry = XMALLOC(MTYPE_PIM_SOURCE, sizeof(struct pimsm_src_entry));
    if (NULL == pstSrcEntry)
    {
        return NULL;
    }
    memset(pstSrcEntry, 0x00, sizeof(struct pimsm_src_entry));

    memcpy(&pstSrcEntry->address, src_addr, sizeof(VOS_IP_ADDR));

    hash_push(g_source_hash, pstSrcEntry);

    return pstSrcEntry;
}

static struct pimsm_mrt_entry *pimsm_CreateStarGrpEntry(struct pimsm_grp_entry *pstGrpEntry,uint32_t flags)
{
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_rpf *pstRpf;

    if(NULL == pstGrpEntry)
    {
        return NULL;
    }

    mrt_entry = XMALLOC(MTYPE_PIM_MRT, sizeof(struct pimsm_mrt_entry));
    if (NULL == mrt_entry)
    {
        return NULL;
    }
    memset(mrt_entry, 0x00, sizeof(struct pimsm_mrt_entry));

    pstGrpEntry->pstStarMrtLink = mrt_entry;

    mrt_entry->group = pstGrpEntry;
    mrt_entry->upstream_if.ifindex = MRTMGT_RPF_CTL_INVALID_INTF;
    mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotJoined;
    mrt_entry->flags = flags;

    if ((PIMSM_SSM_RANGE != pstGrpEntry->type ) &&
            (0 != pstGrpEntry->rp_addr.u32_addr[0]))
    {

        PIM_DEBUG("grp entry, rp_addr:%s.\n", pim_InetFmt(&pstGrpEntry->rp_addr));

        pstRpf = pimsm_SearchRpf(&pstGrpEntry->rp_addr);
        if(NULL != pstRpf)
        {
            mrt_entry->upstream_if.ifindex = pstRpf->rpf_if;
            PIM_DEBUG("pstRpf->rpf_if:%d.\n", pstRpf->rpf_if);

            memcpy(&mrt_entry->upstream_if.up_stream_nbr, &pstRpf->rpf_nbr_addr, sizeof(VOS_IP_ADDR));
            mrt_entry->metric = pstRpf->metric;
            mrt_entry->preference = pstRpf->preference;
        }
    }

    if (pimsm_IamRP(&pstGrpEntry->address))
    {
        mrt_entry->byRpfCheck = PIMSM_MRT_RPF_NO_CHECK;
    }
    else
    {
        mrt_entry->byRpfCheck = PIMSM_MRT_RPF_CHECK_IN_IF;
    }

    mrt_entry->creation = pim_time_monotonic_sec();

    if (MRTMGT_RPF_CTL_INVALID_INTF == mrt_entry->upstream_if.ifindex)
    {
        PIM_DEBUG("pimsm mroute set valid.\n");
        pimsm_MrtSetValid(mrt_entry, FALSE);
    }
    else
    {
        pimsm_MrtSetValid(mrt_entry, TRUE);
    }

    return mrt_entry;
}

static struct pimsm_mrt_entry *pimsm_CreateSrcGrpEntry(struct pimsm_src_entry *pstSrcEntry,struct pimsm_grp_entry *pstGrpEntry,uint8_t type,uint32_t flags)
{
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_rpf *pstRpf = NULL;

    if((NULL == pstGrpEntry) || (NULL == pstSrcEntry))
    {
        return NULL;
    }

    mrt_entry = XMALLOC(MTYPE_PIM_MRT, sizeof(struct pimsm_mrt_entry));
    if (NULL == mrt_entry)
    {
        return NULL;
    }
    memset(mrt_entry, 0x00, sizeof(struct pimsm_mrt_entry));

    mrt_entry->group = pstGrpEntry;
    mrt_entry->source = pstSrcEntry;
    mrt_entry->upstream_if.ifindex = MRTMGT_RPF_CTL_INVALID_INTF;
    //mrt_entry->upstream_if.stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;
    mrt_entry->type = type;
    mrt_entry->flags = flags;
    mrt_entry->stRegStateMachine.emRegisterState = PimsmRegStateNoInfo;
    mrt_entry->stRegStateMachine.t_pimsm_register_timer = 0;

    if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState = PimsmUpstreamStateNotJoined;
        pstRpf = pimsm_SearchRpf(&pstSrcEntry->address);
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState= PimsmUpstreamStateNotPruned;
        pstRpf = pimsm_SearchRpf(&pstGrpEntry->rp_addr);
    }
    if(NULL != pstRpf)
    {
        mrt_entry->upstream_if.ifindex = pstRpf->rpf_if;
        memcpy(&mrt_entry->upstream_if.up_stream_nbr, &pstRpf->rpf_nbr_addr, sizeof(VOS_IP_ADDR));
        mrt_entry->metric = pstRpf->metric;
        mrt_entry->preference = pstRpf->preference;
    }

    if (MRTMGT_RPF_CTL_INVALID_INTF == mrt_entry->upstream_if.ifindex)
    {
        pimsm_MrtSetValid(mrt_entry, FALSE);
    }
    else
    {
        pimsm_MrtSetValid(mrt_entry, TRUE);
    }

    if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        pimsm_KeepAliveTimerStart(mrt_entry, PIMSM_TIMER_KEEPALIVE_PERIOD);
        pimsm_SetCopyToCpu(mrt_entry, TRUE);
    }
    mrt_entry->creation = pim_time_monotonic_sec();

    if (NULL != pstGrpEntry->pstSrcMrtLink)
    {
        pstGrpEntry->pstSrcMrtLink->samegrpprev = mrt_entry;
    }
    mrt_entry->samegrpprev = NULL;
    mrt_entry->samegrpnext = pstGrpEntry->pstSrcMrtLink;
    pstGrpEntry->pstSrcMrtLink = mrt_entry;

    if (NULL != pstSrcEntry->pstSrcMrtLink)
    {
        pstSrcEntry->pstSrcMrtLink->samesrcprev = mrt_entry;
    }
    mrt_entry->samesrcprev = NULL;
    mrt_entry->samesrcnext = pstSrcEntry->pstSrcMrtLink;
    pstSrcEntry->pstSrcMrtLink = mrt_entry;

    return mrt_entry;
}

struct pimsm_mrt_entry *pimsm_CreateMrtEntry(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t flags)
{
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_grp_entry *pstGrpEntry = NULL;
    struct pimsm_src_entry *pstSrcEntry = NULL;
    //struct pimsm_grp_entry stGrpEntry;
    //struct pimsm_src_entry stSrcEntry;

    if ((PIMSM_MRT_TYPE_WC == type) ||
            (PIMSM_MRT_TYPE_SG == type) ||
            (PIMSM_MRT_TYPE_SGRPT == type))
    {
        /* source address check */
        if ((PIMSM_MRT_TYPE_SG == type) ||
                (PIMSM_MRT_TYPE_SGRPT == type))
        {
            if (NULL == src_addr)
            {
                PIM_DEBUG("Create (S, %s) multicast entry failed, group address is NULL!\n", pim_InetFmt(pstGrpAddr));
                return NULL;
            }
            if (ip_isMulticastAddress(src_addr))
            {
                PIM_DEBUG("Create (%s, %s) multicast entry failed, group address invalid!\n", pim_InetFmt(src_addr), pim_InetFmt(pstGrpAddr));
                return NULL;
            }
        }

        /* group address check */
        if (NULL == pstGrpAddr)
        {
            PIM_DEBUG("Create multicast entry failed, group address is NULL!\n");
            return NULL;
        }
        if (!ip_isMulticastAddress(pstGrpAddr) || ip_isMulticastLocalAddr(pstGrpAddr) )
        {
            PIM_DEBUG("Create multicast entry failed, group address(%s) invalid!\n", pim_InetFmt(pstGrpAddr));
            return NULL;
        }

        /* create group entry while it not exist */
        pstGrpEntry = pimsm_SearchGrpEntry(pstGrpAddr);
        if (NULL == pstGrpEntry)
        {
            pstGrpEntry = pimsm_CreateGrpEntry(pstGrpAddr);
            if (NULL == pstGrpEntry)
            {
                return NULL;
            }
        }

        /* create (*,G) entry */
        if (PIMSM_MRT_TYPE_WC == type)
        {
            mrt_entry = pstGrpEntry->pstStarMrtLink;
            if (NULL == mrt_entry)
            {
                mrt_entry = pimsm_CreateStarGrpEntry(pstGrpEntry, flags);
                if (NULL == mrt_entry)
                {
                    pimsm_TryDestroyGrpEntry(pstGrpEntry);
                    return NULL;
                }
            }
        }

        /* prepare create (S,G) entry */
        if ((PIMSM_MRT_TYPE_SG == type) ||
                (PIMSM_MRT_TYPE_SGRPT == type))
        {
            /* create source entry while it not exist */
            pstSrcEntry = pimsm_SearchSrcEntry(src_addr);
            if (NULL == pstSrcEntry)
            {
                pstSrcEntry = pimsm_CreateSrcEntry(src_addr);
                if (NULL == pstSrcEntry)
                {
                    pimsm_TryDestroyGrpEntry(pstGrpEntry);
                    return NULL;
                }
            }

            mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
            if (NULL == mrt_entry)
            {
                /* create (S,G) entry */
                mrt_entry = pimsm_CreateSrcGrpEntry(pstSrcEntry, pstGrpEntry, type, flags);
                if (NULL == mrt_entry)
                {
                    pimsm_TryDestroySrcEntry(pstSrcEntry);
                    pimsm_TryDestroyGrpEntry(pstGrpEntry);
                    return NULL;
                }
            }
        }

        return mrt_entry;
    }
    else if (type == PIMSM_MRT_TYPE_PMBR)
    {
        /* create (*,*,RP) entry not support */
        return NULL;
    }

    return NULL;
}

#define destroy

void pimsm_FreeGrpEntry(struct pimsm_grp_entry *pstGrpEntry)
{
    if(NULL != pstGrpEntry)
    {
        XFREE(MTYPE_PIM_GROUP, pstGrpEntry);
    }

    return;
}

void pimsm_FreeSrcEntry(struct pimsm_src_entry *pstSrcEntry)
{
    if(NULL != pstSrcEntry)
    {
        XFREE(MTYPE_PIM_SOURCE, pstSrcEntry);
    }

    return;
}

static int pimsm_TryDestroyGrpEntry(struct pimsm_grp_entry *pstGrpEntry)
{
    if(NULL == pstGrpEntry)
    {
        return VOS_ERROR;
    }

    if ((NULL == pstGrpEntry->pstSrcMrtLink) && (NULL == pstGrpEntry->pstStarMrtLink))
    {
        hash_pull(g_group_hash, pstGrpEntry);
        memset(pstGrpEntry, 0, sizeof(struct pimsm_grp_entry));
        pimsm_FreeGrpEntry(pstGrpEntry);
        return VOS_OK;
    }

    return VOS_ERROR;
}

static int pimsm_TryDestroySrcEntry(struct pimsm_src_entry *pstSrcEntry)
{
    if(NULL == pstSrcEntry)
    {
        return VOS_ERROR;
    }

    if (NULL == pstSrcEntry->pstSrcMrtLink)
    {
        hash_pull(g_source_hash, pstSrcEntry);
        memset(pstSrcEntry, 0, sizeof(struct pimsm_src_entry));
        pimsm_FreeSrcEntry(pstSrcEntry);
        return VOS_OK;
    }

    return VOS_ERROR;
}

static int pimsm_DestroyStarGrpEntry(struct pimsm_mrt_entry *mrt_entry)
{
    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    mrt_entry->group->pstStarMrtLink = NULL;

    if (PimsmUpstreamStateJoined == mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState)
    {
        pimsm_SendPrune(mrt_entry, &mrt_entry->upstream_if.up_stream_nbr);
    }

    /* Upstream Interface About */
    if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
        THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);

    if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
        THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);

    if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
        THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);

    /* Assert Interface About */
    pimsm_DestroyAllAssertIf(mrt_entry);

    /* Downstream Interface About */
    pimsm_DestroyAllDownstreamIf(mrt_entry);

    /* Oil About */
    pimsm_FreeOil(mrt_entry->out_if);

    XFREE(MTYPE_PIM_MRT, mrt_entry);

    return VOS_OK;
}

static int pimsm_DestroySrcGrpEntry(struct pimsm_mrt_entry *mrt_entry)
{
    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        printf("Pimsm destroy (%s, %s, rpt).\n", pim_InetFmt(&mrt_entry->source->address), pim_InetFmt(&mrt_entry->source->address));
    }

    if (PimsmUpstreamStateJoined == mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState)
    {
        pimsm_SendPrune(mrt_entry, &mrt_entry->upstream_if.up_stream_nbr);
    }

    /* 同组不同源链表 */
    if (NULL != mrt_entry->samegrpnext)
    {
        mrt_entry->samegrpnext->samegrpprev = mrt_entry->samegrpprev;
    }
    if (NULL != mrt_entry->samegrpprev)
    {
        mrt_entry->samegrpprev->samegrpnext = mrt_entry->samegrpnext;
    }
    else
    {
        if (NULL != mrt_entry->group)
        {
            mrt_entry->group->pstSrcMrtLink = mrt_entry->samegrpnext;
        }
    }

    /* 同源不同组链表*/
    if (NULL != mrt_entry->samesrcnext)
    {
        mrt_entry->samesrcnext->samesrcprev = mrt_entry->samesrcprev;
    }
    if (NULL != mrt_entry->samesrcprev)
    {
        mrt_entry->samesrcprev->samesrcnext = mrt_entry->samesrcnext;
    }
    else
    {
        if (NULL != mrt_entry->source)
        {
            mrt_entry->source->pstSrcMrtLink = mrt_entry->samesrcnext;
        }
    }

    /* Upstream Interface About */
    if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer)
        THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_join_timer);

    if (mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer)
        THREAD_OFF(mrt_entry->upstream_if.stUpstreamStateMachine.t_pimsm_override_timer);

    /* Assert Interface About */
    pimsm_DestroyAllAssertIf(mrt_entry);

    /* Downstream Interface About */
    pimsm_DestroyAllDownstreamIf(mrt_entry);

    /* Oil About */
    pimsm_FreeOil(mrt_entry->out_if);

    /* Keep Alive Timer About */
    if (mrt_entry->t_pimsm_keep_alive_timer)
        THREAD_OFF(mrt_entry->t_pimsm_keep_alive_timer);

    /* Register Tunnel About */
    if (mrt_entry->stRegStateMachine.t_pimsm_register_timer)
        THREAD_OFF(mrt_entry->stRegStateMachine.t_pimsm_register_timer);

    if (NULL != mrt_entry->stRegStateMachine.pstRegisterTunnel)
    {
        XFREE(MTYPE_PIM_OTHER, mrt_entry->stRegStateMachine.pstRegisterTunnel);
    }

    XFREE(MTYPE_PIM_MRT, mrt_entry);
    return VOS_OK;
}

int pimsm_DestroyMrtEntry(struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_grp_entry *pstGrpEntry = NULL;
    struct pimsm_src_entry *pstSrcEntry = NULL;
    uint32_t dwMrtFlags;
    uint8_t type;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    dwMrtFlags = mrt_entry->flags;
    type = mrt_entry->type;

    if ((PIMSM_MRT_TYPE_WC == type) ||
            (PIMSM_MRT_TYPE_SG == type) ||
            (PIMSM_MRT_TYPE_SGRPT == type))
    {
        pstSrcEntry = mrt_entry->source;
        pstGrpEntry = mrt_entry->group;

        /* (*,G) entry */
        if (PIMSM_MRT_TYPE_WC == type)
        {
            pimsm_DestroyStarGrpEntry(mrt_entry);
        }
        /* (S,G)项 */
        else if ((PIMSM_MRT_TYPE_SG == type) || (PIMSM_MRT_TYPE_SGRPT == type))
        {
            pimsm_DestroySrcGrpEntry(mrt_entry);
            pimsm_TryDestroySrcEntry(pstSrcEntry);
        }
        pimsm_TryDestroyGrpEntry(pstGrpEntry);
    }
    else if (PIMSM_MRT_TYPE_PMBR == type)
    {
        /* (*,*,RP) entry not support */
        return VOS_ERROR;
    }

    return VOS_OK;
}

static void pimsm_DestroyAllStarGrpEntry(void)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;

    if(g_group_hash != NULL)
    {
        hash_traversal_start(g_group_hash, pGroupEntry);
        if(NULL != pGroupEntry)
        {
            pimsm_DestroyStarGrpEntry(pGroupEntry->pstStarMrtLink);
        }
        hash_traversal_end();
    }
}

static void pimsm_DestroyAllSrcGrpEntry(void)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_mrt_entry *pstMrtNext = NULL;

    if(g_group_hash != NULL)
    {
        hash_traversal_start(g_group_hash, pGroupEntry);
        if(NULL != pGroupEntry)
        {
            mrt_entry = pGroupEntry->pstSrcMrtLink;
            while (NULL != mrt_entry)
            {
                pstMrtNext = mrt_entry->samegrpnext;
                pimsm_DestroySrcGrpEntry(mrt_entry);
                mrt_entry = pstMrtNext;
            }
            pGroupEntry->pstSrcMrtLink = NULL;
        }
        hash_traversal_end();
    }
}

static void pimsm_DestroyAllMrtEntry(void)
{
    pimsm_DestroyAllStarGrpEntry();
    pimsm_DestroyAllSrcGrpEntry();
}

static void pimsm_DestroyAllGrpEntry(void)
{
    pimsm_DestroyAllMrtEntry();
    hash_clean(g_group_hash, (void (*) (void *))pimsm_FreeGrpEntry);
}

void pimsm_DestroyAllSrcEntry(void)
{
    pimsm_DestroyAllSrcGrpEntry();
    hash_clean(g_source_hash, (void (*) (void *))pimsm_FreeSrcEntry);
}

#define search

static void *hash_search (struct hash *hash, void *data)
{
    unsigned int key;
    struct hash_backet *backet;

    key = (*hash->hash_key) (data);

    if (hash->index[key] == NULL)
        return NULL;

    for (backet = hash->index[key]; backet != NULL; backet = backet->next)
        if ((*hash->hash_cmp) (backet->data, data) == 1)
            return backet->data;

    return NULL;
}
struct pimsm_grp_entry *pimsm_SearchGrpEntry(VOS_IP_ADDR *pstGrpAddr)
{
    struct pimsm_grp_entry stGrpEntry;

    if(NULL == pstGrpAddr)
    {
        return NULL;
    }

    if(NULL != g_group_hash)
    {
        memcpy(&(stGrpEntry.address), pstGrpAddr, sizeof(VOS_IP_ADDR));
        return (struct pimsm_grp_entry *)hash_search(g_group_hash, &stGrpEntry);
    }
    return NULL;
}

struct pimsm_src_entry *pimsm_SearchSrcEntry(VOS_IP_ADDR *src_addr)
{
    struct pimsm_src_entry stSrcEntry;

    if(NULL == src_addr)
    {
        return NULL;
    }

    if(NULL != g_source_hash)
    {
        memcpy(&(stSrcEntry.address), src_addr, sizeof(VOS_IP_ADDR));
        return (struct pimsm_src_entry *)hash_search(g_source_hash, &stSrcEntry);
    }

    return NULL;
}

static struct pimsm_mrt_entry *pimsm_SearchStarGrpEntry(VOS_IP_ADDR *pstGrpAddr)
{
    //struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_grp_entry *pstGrpEntry = NULL;

    if(NULL == pstGrpAddr)
    {
        return NULL;
    }

    pstGrpEntry = pimsm_SearchGrpEntry(pstGrpAddr);

    if(NULL == pstGrpEntry)
    {
        return NULL;
    }

    return pstGrpEntry->pstStarMrtLink;
}

static struct pimsm_mrt_entry *pimsm_SearchSrcGrpEntry(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type)
{
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_grp_entry *pstGrpEntry = NULL;

    if((NULL == pstGrpAddr) || (NULL == src_addr))
    {
        return NULL;
    }

    pstGrpEntry = pimsm_SearchGrpEntry(pstGrpAddr);
    if(NULL == pstGrpEntry)
    {
        return NULL;
    }

    mrt_entry = pstGrpEntry->pstSrcMrtLink;
    while (NULL != mrt_entry)
    {
        if ((0 == ip_AddressCompare(src_addr, &(mrt_entry->source->address))) &&
                (type == mrt_entry->type))
        {
            return mrt_entry;
        }
        mrt_entry = mrt_entry->samegrpnext;
    }

    return NULL;
}

struct pimsm_mrt_entry *pimsm_SearchMrtEntry(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type)
{
    if ((PIMSM_MRT_TYPE_WC == type) ||
            (PIMSM_MRT_TYPE_SG == type) ||
            (PIMSM_MRT_TYPE_SGRPT == type))
    {
        /* source address check */
        if ((PIMSM_MRT_TYPE_SG == type) || (PIMSM_MRT_TYPE_SGRPT == type))
        {
            if (ip_isMulticastAddress(src_addr))
            {
                return NULL;
            }
        }

        /* group address check */
        if (!ip_isMulticastAddress(pstGrpAddr))
        {
            return NULL;
        }

        if (PIMSM_MRT_TYPE_WC == type)
        {
            return pimsm_SearchStarGrpEntry(pstGrpAddr);
        }
        else
        {
            return pimsm_SearchSrcGrpEntry(src_addr, pstGrpAddr, type);
        }
    }
    else
    {
        /* (*,*,RP) entry not support */
        return NULL;
    }

    return NULL;
}

#define display
void pimsm_DisplayAllGrpEntry(void)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;
    const char *acFlag[2] = {"SM", "SSM"};
    int count = 0;

    if(g_group_hash != NULL)
    {
        printf("\n=================================================\n");
        printf("%-15s%-10s%-15s\n", "GroupAddr", "Flag", "RP");
        printf("-------------------------------------------------\n");
        hash_traversal_start(g_group_hash, pGroupEntry);
        if(NULL != pGroupEntry)
        {
            printf("%-15s%-10s%-15s\n", pim_InetFmt(&pGroupEntry->address), acFlag[pGroupEntry->type], pim_InetFmt(&pGroupEntry->rp_addr));
            count++;
        }
        hash_traversal_end();
        printf("\ncount: %d\n", count);
        printf("-------------------------------------------------\n");
    }
}

void pimsm_DisplayAllSrcEntry(void)
{
    struct pimsm_src_entry * pSrouceEntry = NULL;
    int count = 0;

    if(g_source_hash != NULL)
    {
        printf("\n=================================================\n");
        printf("%-15s\n", "SourceAddr");
        printf("-------------------------------------------------\n");
        hash_traversal_start(g_source_hash, pSrouceEntry);
        if(NULL != pSrouceEntry)
        {
            printf("%-15s\n", pim_InetFmt(&pSrouceEntry->address));
            count++;
        }
        hash_traversal_end();
        printf("\ncount: %d\n", count);
        printf("-------------------------------------------------\n");
    }
}

char* pimsm_DisplayOneMrtEntry(struct pimsm_mrt_entry *mrt_entry)
{
    const char *flags_str[] = {PIMSM_MRT_FLAG_STR};
    char display_buf[PIMSM_MAX_DISPLAY_LEN];
    struct pimsm_updownstream_if_entry *pstDownIf;
    struct pimsm_assert_if *pimsmassert_if;
    char *p = display_buf;
    char *return_buf;
    int bit_index[32];
    int bit_count;
    int len = 0;
    int i = 0;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    memset(display_buf, 0, PIMSM_MAX_DISPLAY_LEN);

    pimsm_BitMapIndex(mrt_entry->flags, bit_index, &bit_count);

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        len += sprintf(p + len, "(*, %s) G_RP: %s\n\t",
                       pim_InetFmt(&mrt_entry->group->address),
                       pim_InetFmt(&mrt_entry->group->rp_addr));
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        len += sprintf(p + len, "(%s, %s) G_RP: %s\n\t",
                       pim_InetFmt(&mrt_entry->source->address),
                       pim_InetFmt(&mrt_entry->group->address),
                       pim_InetFmt(&mrt_entry->group->rp_addr));

        len += sprintf(p + len, "RegStateDR: %s , ", pimsm_GetRegStateString(mrt_entry->stRegStateMachine.emRegisterState));
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        len += sprintf(p + len, "(%s, %s, rpt) G_RP: %s\n\t",
                       pim_InetFmt(&mrt_entry->source->address),
                       pim_InetFmt(&mrt_entry->group->address),
                       pim_InetFmt(&mrt_entry->group->rp_addr));
    }

    len += sprintf(p + len, "IsCopyToCpu: %s , ", pimsm_IsCopyToCpu(mrt_entry) ? "True" : "False");
    len += sprintf(p + len, "Valid: %d , ", mrt_entry->valid);

    len += sprintf(p + len, "Flags: ");
    for(i = 0; i < bit_count; ++i)
    {
        len += sprintf(p + len, "%s  ", flags_str[bit_index[i]]);
    }
    len += sprintf(p + len, "\n");

    len += sprintf(p + len, "\tUpIf: %s , Nbr: %s , JPState: %s\n",
                   pimsm_GetIfName(mrt_entry->upstream_if.ifindex),
                   pim_InetFmt(&mrt_entry->upstream_if.up_stream_nbr),
                   pimsm_GetUpstreamStateString(mrt_entry->upstream_if.stUpstreamStateMachine.emUpstreamState));

    pstDownIf = mrt_entry->downstream_if;
    while(NULL != pstDownIf)
    {
        len += sprintf(p + len, "\tDownIf: %s, AssertState: %s, JPState: %s, Local%s: %s\n",
                       pimsm_GetIfName(pstDownIf->ifindex),
                       pimsm_GetAssertStateString(pimsm_AssertState(mrt_entry, pstDownIf->ifindex)),
                       pimsm_GetDownstreamStateString(pstDownIf->down_stream_state_mchine.emDownstreamState),
                       (mrt_entry->type == PIMSM_MRT_TYPE_SGRPT) ? "Deny" : "Recv",
                       pstDownIf->byLocalReceiverInclude ? "True" : "False");

        pstDownIf = pstDownIf->next;
    }

    pimsmassert_if = mrt_entry->pimsmassert_if;
    while(NULL != pimsmassert_if)
    {
        len += sprintf(p + len, "\tAssertIf: %s, AssertState: %s, AssertWinner: %s, WinnerPref: %d, WinnerMetric: %d\n",
                       pimsm_GetIfName(pimsmassert_if->ifindex),
                       pimsm_GetAssertStateString(pimsmassert_if->stAssertStateMachine.emAssertState),
                       pim_InetFmt(&pimsmassert_if->stAssertStateMachine.stAssertWinner.address),
                       pimsmassert_if->stAssertStateMachine.stAssertWinner.dwMetricPref,
                       pimsmassert_if->stAssertStateMachine.stAssertWinner.dwRouteMetric);

        pimsmassert_if = pimsmassert_if->next;
    }

    p[len++] = 0;

    if(0 != len)
    {
        return_buf = XMALLOC(MTYPE_BUFFER, len);
        if(NULL == return_buf)
        {
            return NULL;
        }
        else
        {
            memcpy(return_buf, display_buf, len);
            return return_buf;
        }
    }

    return NULL;
}

void pimsm_DisplayAllStarGrpEntry(struct vty *vty)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;
    char *pBuf;

    vty_out(vty, "\n================================================================\n");
    if(g_group_hash != NULL)
    {
        hash_traversal_start(g_group_hash, pGroupEntry);
        if(NULL != pGroupEntry)
        {
            pBuf = pimsm_DisplayOneMrtEntry(pGroupEntry->pstStarMrtLink);
            if(NULL != pBuf)
            {
                vty_out(vty, "%s.\n", pBuf);
                XFREE(MTYPE_BUFFER, pBuf);
            }
        }
        hash_traversal_end();
    }
    vty_out(vty, "----------------------------------------------------------------\n");
}

void pimsm_DisplayAllSrcGrpEntry(void)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;
    struct pimsm_mrt_entry *mrt_entry = NULL;
    char *pBuf;

    printf("\n================================================================\n");
    if(g_group_hash != NULL)
    {
        hash_traversal_start(g_group_hash, pGroupEntry);
        if(NULL != pGroupEntry)
        {
            mrt_entry = pGroupEntry->pstSrcMrtLink;
            while (NULL != mrt_entry)
            {
                pBuf = pimsm_DisplayOneMrtEntry(mrt_entry);
                if(NULL != pBuf)
                {
                    printf(pBuf);
                    printf("\n");
                    XFREE(MTYPE_BUFFER, pBuf);
                }
                mrt_entry = mrt_entry->samegrpnext;
            }
        }
        hash_traversal_end();
    }
    printf("----------------------------------------------------------------\n");
}

#define _2cpu

int pimsm_SetCopyToCpu(struct pimsm_mrt_entry *mrt_entry, uint8_t bIsCopy2Cpu)
{
    zassert(NULL != mrt_entry);

    if (bIsCopy2Cpu)
    {
        mrt_entry->bIsCopyToCpu = TRUE;
    }
    else
    {
        mrt_entry->bIsCopyToCpu = FALSE;
    }

    return VOS_OK;
}

static uint8_t pimsm_IsCopyToCpu(struct pimsm_mrt_entry *mrt_entry)
{
    zassert(NULL != mrt_entry);

    return (mrt_entry->bIsCopyToCpu);
}

#define pimsmvalid

int pimsm_MrtSetValid(struct pimsm_mrt_entry *mrt_entry, uint8_t valid)
{
    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    if (valid)
    {
        mrt_entry->valid = TRUE;
        pimsm_MrtDelTimerStop(mrt_entry);
    }
    else
    {
        mrt_entry->valid = FALSE;

        PIM_DEBUG("pimsm mroute set valid:%d.\n", valid);
        pimsm_MrtDelTimerStart(mrt_entry, 5);
    }

    return VOS_OK;
}

int pimsm_CheckMrtEntryValid(struct pimsm_mrt_entry *mrt_entry)
{
    //struct pimsm_grp_entry *pstGrpEntry;
    //struct pimsm_updownstream_if_entry *pstDownIf;

    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    if (MRTMGT_RPF_CTL_INVALID_INTF == mrt_entry->upstream_if.ifindex)
    {
        pimsm_MrtSetValid(mrt_entry, FALSE);
        return VOS_OK;
    }

    if (PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        if (NULL == pimsm_ImmediateOlist(mrt_entry, FALSE))
        {
            pimsm_MrtSetValid(mrt_entry, FALSE);
            return VOS_OK;
        }
    }
    else if (PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        if ((NULL == pimsm_InheritedOlist(mrt_entry, FALSE)) &&
                (NULL == mrt_entry->t_pimsm_keep_alive_timer))
        {
            pimsm_MrtSetValid(mrt_entry, FALSE);
            return VOS_OK;
        }
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        /*
        if (NULL == pimsm_InheritedOlist(mrt_entry, FALSE))
        {
        	pimsm_MrtSetValid(mrt_entry, FALSE);
        	return VOS_OK;
        }
        */
        if (!pimsm_PruneDesired(mrt_entry))
        {
            pimsm_MrtSetValid(mrt_entry, FALSE);
            return VOS_OK;
        }
    }

    pimsm_MrtSetValid(mrt_entry, TRUE);

    /*
    if ((PIMSM_MRT_TYPE_WC == mrt_entry->type) ||
    	(PIMSM_MRT_TYPE_SG == mrt_entry->type))
    {
    	pstDownIf = mrt_entry->downstream_if;
    	while(NULL != pstDownIf)
    	{
    		if (pstDownIf->byLocalReceiverInclude)
    		{
    			break;
    		}
    		if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
    		{
    			break;
    		}
    		pstDownIf = pstDownIf->next;
    	}

    	if (NULL == pstDownIf)
    	{
    		pimsm_MrtSetValid(mrt_entry, FALSE);
    	}
    	else
    	{
    		pimsm_MrtSetValid(mrt_entry, TRUE);
    	}
    }
    else if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
    	pstDownIf = mrt_entry->downstream_if;
    	while(NULL != pstDownIf)
    	{
    		if (!pstDownIf->byLocalReceiverInclude)
    		{
    			break;
    		}
    		if (PimsmDownstreamStateNoInfo != pstDownIf->down_stream_state_mchine.emDownstreamState)
    		{
    			break;
    		}
    		pstDownIf = pstDownIf->next;
    	}

    	if (NULL == pstDownIf)
    	{
    		pimsm_MrtSetValid(mrt_entry, FALSE);
    	}
    	else
    	{
    		pimsm_MrtSetValid(mrt_entry, TRUE);
    	}
    }
    */

    return VOS_OK;
}

#define spt

uint8_t pimsm_SptBit(VOS_IP_ADDR *src_addr, VOS_IP_ADDR *pstGrpAddr)
{
    struct pimsm_mrt_entry *src_grp_entry;

    src_grp_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, PIMSM_MRT_TYPE_SG);
    if(NULL == src_grp_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_FLAG_SPT == (src_grp_entry->flags & PIMSM_MRT_FLAG_SPT))
    {
        return TRUE;
    }

    return FALSE;
}

int pimsm_SetSptBit(VOS_IP_ADDR *src_addr, VOS_IP_ADDR *pstGrpAddr, uint8_t byIsTrue)
{
    struct pimsm_mrt_entry *src_grp_entry;

    zassert(NULL != src_addr);
    zassert(NULL != pstGrpAddr);

    src_grp_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, PIMSM_MRT_TYPE_SG);
    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if(byIsTrue)
    {
        /* Set SPTbit(S,G) to TRUE */
        src_grp_entry->flags |= PIMSM_MRT_FLAG_SPT;
        if (PimsmRegStateJoin != src_grp_entry->stRegStateMachine.emRegisterState)
        {
            pimsm_SetCopyToCpu(src_grp_entry, FALSE);
        }
    }
    else
    {
        /* Set SPTbit(S,G) to FALSE */
        src_grp_entry->flags &= ~PIMSM_MRT_FLAG_SPT;
        pimsm_SetCopyToCpu(src_grp_entry, TRUE);
    }

    return VOS_OK;
}

int pimsm_SetSptThresholdInfinity(uint8_t byValue)
{
    struct pimsm_grp_entry * pGroupEntry = NULL;
    struct pimsm_mrt_entry *start_grp_entry;

    if (byValue)
    {
        g_stPimsm.bSptThresholdInfinity = TRUE;

        /* All (*,G) */
        if(g_group_hash != NULL)
        {
            hash_traversal_start(g_group_hash, pGroupEntry);
            if(NULL != pGroupEntry)
            {
                start_grp_entry = pGroupEntry->pstStarMrtLink;
                if (NULL != start_grp_entry)
                {
                    if (pimsm_LocalReceiverExist(start_grp_entry))
                    {
                        pimsm_SetCopyToCpu(start_grp_entry, TRUE);
                    }
                }
            }
            hash_traversal_end();
        }
    }
    else
    {
        g_stPimsm.bSptThresholdInfinity = FALSE;

        /* All (*,G) */
        if(g_group_hash != NULL)
        {
            hash_traversal_start(g_group_hash, pGroupEntry);
            if(NULL != pGroupEntry)
            {
                start_grp_entry = pGroupEntry->pstStarMrtLink;
                if (NULL != start_grp_entry)
                {
                    pimsm_SetCopyToCpu(start_grp_entry, FALSE);
                }
            }
            hash_traversal_end();
        }
    }

    return VOS_OK;
}

uint8_t pimsm_SwitchToSptDesired
(
    VOS_IP_ADDR *pstGrp   /* 组地址 */
)
{
    /* 切换阀值由命令 ip pim spt-threshold infinity 设置，
    设置了该命令阀值为无穷大，否则为0 */
    /* 该命令没有配置(默认值) */

    if(g_stPimsm.bSptThresholdInfinity)
    {
        return FALSE; /* 切换阀值为无穷大 */
    }
    else
    {
        return TRUE;
    }
}

#define downstream

struct pimsm_updownstream_if_entry *pimsm_SearchDownstreamIfByIndex(struct pimsm_updownstream_if_entry *pstDownstreamifHead,uint32_t ifindex)
{
    struct pimsm_updownstream_if_entry *downstream_if;

    downstream_if = pstDownstreamifHead;
    while (NULL != downstream_if)
    {
        if (downstream_if->ifindex == ifindex)
        {
            return downstream_if;
        }
        downstream_if = downstream_if->next;
    }

    return NULL;
}

struct pimsm_updownstream_if_entry * pimsm_CreateDownstreamIf(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t flags,uint32_t ifindex)
{
    struct pimsm_updownstream_if_entry *pstDownstreamIfNew;
    uint8_t byMrtEntryIsNewCreate = FALSE;
    struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(NULL == pimsm_ifp)
    {
        return NULL;
    }

    mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
    if(NULL == mrt_entry)
    {
        PIM_DEBUG("create mrt entry, src:%s grp:%s, type:%d.\n", pim_InetFmt(src_addr), pim_InetFmt(pstGrpAddr), type);
        mrt_entry = pimsm_CreateMrtEntry(src_addr, pstGrpAddr, type, flags);
        if(NULL == mrt_entry)
        {
            return NULL;
        }
        byMrtEntryIsNewCreate = TRUE;
    }

    pstDownstreamIfNew = pimsm_SearchDownstreamIfByIndex(mrt_entry->downstream_if, ifindex);
    if(NULL != pstDownstreamIfNew)
    {
        return pstDownstreamIfNew;
    }

    pstDownstreamIfNew = XMALLOC(MTYPE_PIM_UPDOWNSTREAM_IF, sizeof(struct pimsm_updownstream_if_entry));
    if(NULL == pstDownstreamIfNew)
    {
        if(byMrtEntryIsNewCreate)
        {
            pimsm_DestroyMrtEntry(mrt_entry);
        }
        return NULL;
    }

    memset(pstDownstreamIfNew, 0, sizeof(struct pimsm_updownstream_if_entry));
    pstDownstreamIfNew->ifindex = ifindex;
    pstDownstreamIfNew->down_stream_state_mchine.emDownstreamState = PimsmDownstreamStateNoInfo;

    if(NULL != mrt_entry->downstream_if)
    {
        mrt_entry->downstream_if->prev = pstDownstreamIfNew;
    }
    pstDownstreamIfNew->next = mrt_entry->downstream_if;
    mrt_entry->downstream_if = pstDownstreamIfNew;

    return pstDownstreamIfNew;
}

int pimsm_DestroyDownstreamIf(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_updownstream_if_entry *pstDownstreamIfCurr;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    PIM_DEBUG("Pimsm destroy (%s, %s) %s.\n", pim_InetFmt(&mrt_entry->source->address), pim_InetFmt(&mrt_entry->group->address), pimsm_GetIfName(ifindex));

    pstDownstreamIfCurr = pimsm_SearchDownstreamIfByIndex(mrt_entry->downstream_if, ifindex);
    if(NULL == pstDownstreamIfCurr)
    {
        return VOS_ERROR;
    }

    if (PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
        PIM_DEBUG("Pimsm destroy (%s, %s, rpt) %s .\n", pim_InetFmt(&mrt_entry->source->address), pim_InetFmt(&mrt_entry->group->address), pimsm_GetIfName(ifindex));

    if(NULL != pstDownstreamIfCurr->prev)
    {
        pstDownstreamIfCurr->prev->next = pstDownstreamIfCurr->next;
    }
    if(NULL != pstDownstreamIfCurr->next)
    {
        pstDownstreamIfCurr->next->prev = pstDownstreamIfCurr->prev;
    }
    if(mrt_entry->downstream_if == pstDownstreamIfCurr)
    {
        mrt_entry->downstream_if = pstDownstreamIfCurr->next;
    }

    if (pstDownstreamIfCurr->down_stream_state_mchine.t_pimsm_expiry_timer)
        THREAD_OFF(pstDownstreamIfCurr->down_stream_state_mchine.t_pimsm_expiry_timer);

    if (pstDownstreamIfCurr->down_stream_state_mchine.t_pimsm_prunpend_timer)
        THREAD_OFF(pstDownstreamIfCurr->down_stream_state_mchine.t_pimsm_prunpend_timer);


    PIM_DEBUG("return here, pstDownstreamIfCurr->ifindex:%d.\n", pstDownstreamIfCurr->ifindex);

    XFREE(MTYPE_PIM_UPDOWNSTREAM_IF, pstDownstreamIfCurr);

    return VOS_OK;
}

int pimsm_DestroyAllDownstreamIf(struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_updownstream_if_entry *pstDownIfNext;
    struct pimsm_updownstream_if_entry *pstDownIf;

    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    pstDownIf = mrt_entry->downstream_if;
    while(NULL != pstDownIf)
    {
        pstDownIfNext = pstDownIf->next;

        pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);

        pstDownIf = pstDownIfNext;
    }

    return VOS_OK;
}

#define assert_if

struct pimsm_assert_if *pimsm_SearchAssertIfByIndex(struct pimsm_assert_if *pstAssertIfHead,uint32_t ifindex)
{
    struct pimsm_assert_if *pimsmassert_if;

    pimsmassert_if = pstAssertIfHead;
    while (NULL != pimsmassert_if)
    {
        if (pimsmassert_if->ifindex == ifindex)
        {
            return pimsmassert_if;
        }
        pimsmassert_if = pimsmassert_if->next;
    }

    return NULL;
}

struct pimsm_assert_if *pimsm_CreateAssertIf(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t flags,uint32_t ifindex)
{
    struct pimsm_assert_if *pstAssertIfNew;
    uint8_t byMrtEntryIsNewCreate = FALSE;
    struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_interface_entry *pimsm_ifp;

    pimsm_ifp = pimsm_SearchInterface(ifindex);
    if(NULL == pimsm_ifp)
    {
        return NULL;
    }

    mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
    if(NULL == mrt_entry)
    {
        PIM_DEBUG("create mrt entry, src:%s grp:%s, type:%d.\n", pim_InetFmt(src_addr), pim_InetFmt(pstGrpAddr), type);
        mrt_entry = pimsm_CreateMrtEntry(src_addr, pstGrpAddr, type, flags);
        if(NULL == mrt_entry)
        {
            return NULL;
        }
        byMrtEntryIsNewCreate = TRUE;
    }

    pstAssertIfNew = pimsm_SearchAssertIfByIndex(mrt_entry->pimsmassert_if, ifindex);
    if(NULL != pstAssertIfNew)
    {
        return pstAssertIfNew;
    }

    pstAssertIfNew = XMALLOC(MTYPE_PIM_ASSERT_IF, sizeof(struct pimsm_assert_if));
    if(NULL == pstAssertIfNew)
    {
        if(byMrtEntryIsNewCreate)
        {
            pimsm_DestroyMrtEntry(mrt_entry);
        }
        return NULL;
    }

    memset(pstAssertIfNew, 0, sizeof(struct pimsm_assert_if));
    pstAssertIfNew->prev = NULL;
    pstAssertIfNew->next = NULL;
    pstAssertIfNew->ifindex = ifindex;
    pstAssertIfNew->stAssertStateMachine.emAssertState = PimsmAssertStateNoInfo;

    if(NULL != mrt_entry->pimsmassert_if)
    {
        mrt_entry->pimsmassert_if->prev = pstAssertIfNew;
    }
    pstAssertIfNew->next = mrt_entry->pimsmassert_if;
    mrt_entry->pimsmassert_if = pstAssertIfNew;

    return pstAssertIfNew;
}

int pimsm_DestroyAssertIf(struct pimsm_mrt_entry *mrt_entry,uint32_t ifindex)
{
    struct pimsm_assert_if *pstAssertIfCurr;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    pstAssertIfCurr = pimsm_SearchAssertIfByIndex(mrt_entry->pimsmassert_if, ifindex);
    if(NULL == pstAssertIfCurr)
    {
        return VOS_ERROR;
    }

    if(NULL != pstAssertIfCurr->prev)
    {
        pstAssertIfCurr->prev->next = pstAssertIfCurr->next;
    }
    if(NULL != pstAssertIfCurr->next)
    {
        pstAssertIfCurr->next->prev = pstAssertIfCurr->prev;
    }
    if(mrt_entry->pimsmassert_if == pstAssertIfCurr)
    {
        mrt_entry->pimsmassert_if = pstAssertIfCurr->next;
    }

    if (pstAssertIfCurr->stAssertStateMachine.t_pimsm_assert_timer)
        THREAD_OFF(pstAssertIfCurr->stAssertStateMachine.t_pimsm_assert_timer);

    XFREE(MTYPE_PIM_ASSERT_IF, pstAssertIfCurr);

    return VOS_OK;
}

int pimsm_DestroyAllAssertIf(struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_assert_if *pstAssertIfNext;
    struct pimsm_assert_if *pimsmassert_if;

    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    pimsmassert_if = mrt_entry->pimsmassert_if;
    while(NULL != pimsmassert_if)
    {
        pstAssertIfNext = pimsmassert_if->next;

        pimsm_DestroyAssertIf(mrt_entry, pimsmassert_if->ifindex);

        pimsmassert_if = pstAssertIfNext;
    }

    return VOS_OK;
}

uint8_t pimsm_AssertState(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex)
{
    struct pimsm_assert_if *pstAssertInterface;

    zassert(NULL != mrt_entry);

    pstAssertInterface = mrt_entry->pimsmassert_if;
    while(NULL != pstAssertInterface)
    {
        if (ifindex == pstAssertInterface->ifindex)
        {
            return pstAssertInterface->stAssertStateMachine.emAssertState;
        }

        pstAssertInterface = pstAssertInterface->next;
    }

    return PimsmAssertStateNoInfo;
}

#define olist

int pimsm_FreeOil(struct pimsm_oif *oif)
{
    struct pimsm_oif *pstOifCurr;
    struct pimsm_oif *pstOifNext;

    pstOifCurr = oif;
    while(NULL != pstOifCurr)
    {
        pstOifNext = pstOifCurr->next;

        XFREE(MTYPE_PIM_OIF, pstOifCurr);

        pstOifCurr = pstOifNext;
    }

    return VOS_OK;
}

struct pimsm_oif *pimsm_SearchOifByIndex(struct pimsm_oif *pstOilHead, uint32_t dwOifIndex)
{
    struct pimsm_oif *oif;

    oif = pstOilHead;
    while (NULL != oif)
    {
        if (oif->ifindex == dwOifIndex)
        {
            return oif;
        }
        oif = oif->next;
    }

    return NULL;
}

/* pstOil1 (+) pstOil2 */
/* return new Oil */
/* pstOil1 and pstOil2 not free */
struct pimsm_oif *pimsm_OilAddOil(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2)
{
    struct pimsm_oif *pstNewOil = NULL;
    struct pimsm_oif *pstOifEntry;
    struct pimsm_oif *pstOifTmp;

    pstOifTmp = pstOil1;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
        if(NULL != pstOifEntry)
        {
            memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
            if(NULL != pstNewOil)
            {
                pstNewOil->prev = pstOifEntry;
            }
            pstOifEntry->next = pstNewOil;
            pstOifEntry->prev = NULL;
            pstNewOil = pstOifEntry;
        }

        pstOifTmp = pstOifTmp->next;
    }

    pstOifTmp = pstOil2;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = pimsm_SearchOifByIndex(pstNewOil, pstOifTmp->ifindex);
        if(NULL == pstOifEntry)
        {
            pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
            if(NULL != pstOifEntry)
            {
                memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
                pstOifEntry->next = pstNewOil;
                pstOifEntry->prev = NULL;
                if(NULL != pstNewOil)
                {
                    pstNewOil->prev = pstOifEntry;
                }
                pstNewOil = pstOifEntry;
            }
        }

        pstOifTmp = pstOifTmp->next;
    }

    return pstNewOil;
}

/* pstOil1 (-) pstOil2 */
/* return new Oil */
/* pstOil1 and pstOil2 not free */
struct pimsm_oif *pimsm_OilSubOil(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2)
{
    struct pimsm_oif *pstNewOil = NULL;
    struct pimsm_oif *pstOifEntry;
    struct pimsm_oif *pstOifTmp;

    pstOifTmp = pstOil1;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
        if(NULL != pstOifEntry)
        {
            memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
            if(NULL != pstNewOil)
            {
                pstNewOil->prev = pstOifEntry;
            }
            pstOifEntry->next = pstNewOil;
            pstOifEntry->prev = NULL;
            pstNewOil = pstOifEntry;
        }

        pstOifTmp = pstOifTmp->next;
    }

    pstOifTmp = pstOil2;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = pimsm_SearchOifByIndex(pstNewOil, pstOifTmp->ifindex);
        if(NULL != pstOifEntry)
        {
            if(NULL != pstOifEntry->next)
            {
                pstOifEntry->next->prev = pstOifEntry->prev;
            }
            if(NULL != pstOifEntry->prev)
            {
                pstOifEntry->prev->next = pstOifEntry->next;
            }
            if(pstOifEntry == pstNewOil)
            {
                pstNewOil = pstOifEntry->next;
            }

            XFREE(MTYPE_PIM_OIF, pstOifEntry);
        }

        pstOifTmp = pstOifTmp->next;
    }

    return pstNewOil;
}

/* pstOil1 (+) pstOil2 */
/* return new Oil */
/* pstOil1 and pstOil2 will free */
struct pimsm_oif *pimsm_OilAddOilFree(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2)
{
    struct pimsm_oif *pstNewOil = NULL;
    struct pimsm_oif *pstOifEntry;
    struct pimsm_oif *pstOifTmp;

    pstOifTmp = pstOil1;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
        if(NULL != pstOifEntry)
        {
            memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
            if(NULL != pstNewOil)
            {
                pstNewOil->prev = pstOifEntry;
            }
            pstOifEntry->next = pstNewOil;
            pstOifEntry->prev = NULL;
            pstNewOil = pstOifEntry;
        }

        pstOifTmp = pstOifTmp->next;
    }

    pstOifTmp = pstOil2;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = pimsm_SearchOifByIndex(pstNewOil, pstOifTmp->ifindex);
        if(NULL == pstOifEntry)
        {
            pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
            if(NULL != pstOifEntry)
            {
                memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
                pstOifEntry->next = pstNewOil;
                pstOifEntry->prev = NULL;
                if(NULL != pstNewOil)
                {
                    pstNewOil->prev = pstOifEntry;
                }
                pstNewOil = pstOifEntry;
            }
        }

        pstOifTmp = pstOifTmp->next;
    }

    pimsm_FreeOil(pstOil1);
    pimsm_FreeOil(pstOil2);

    return pstNewOil;
}

/* pstOil1 (-) pstOil2 */
/* return new Oil */
/* pstOil1 and pstOil2 will free */
struct pimsm_oif *pimsm_OilSubOilFree(struct pimsm_oif *pstOil1, struct pimsm_oif *pstOil2)
{
    struct pimsm_oif *pstNewOil = NULL;
    struct pimsm_oif *pstOifEntry;
    struct pimsm_oif *pstOifTmp;

    pstOifTmp = pstOil1;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
        if(NULL != pstOifEntry)
        {
            memcpy(pstOifEntry, pstOifTmp, sizeof(struct pimsm_oif));
            pstOifEntry->next = pstNewOil;
            pstOifEntry->prev = NULL;
            if(NULL != pstNewOil)
            {
                pstNewOil->prev = pstOifEntry;
            }
            pstNewOil = pstOifEntry;
        }

        pstOifTmp = pstOifTmp->next;
    }

    pstOifTmp = pstOil2;
    while(NULL != pstOifTmp)
    {
        pstOifEntry = pimsm_SearchOifByIndex(pstNewOil, pstOifTmp->ifindex);
        if(NULL != pstOifEntry)
        {
            if (NULL != pstOifEntry->next)
            {
                pstOifEntry->next->prev = pstOifEntry->prev;
            }
            if (NULL != pstOifEntry->prev)
            {
                pstOifEntry->prev->next = pstOifEntry->next;
            }
            if(pstNewOil == pstOifEntry)
            {
                pstNewOil = pstOifEntry->next;
            }
            XFREE(MTYPE_PIM_OIF, pstOifEntry);
        }

        pstOifTmp = pstOifTmp->next;
    }

    pimsm_FreeOil(pstOil1);
    pimsm_FreeOil(pstOil2);

    return pstNewOil;
}

static uint8_t pimsm_InterfaceLostAssert(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex)
{
    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return FALSE;/* There is no lost_assert(*,*,RP) */
    }

    if (PimsmAssertStateLoser == pimsm_AssertState(mrt_entry, ifindex))
    {
        return TRUE;
    }

    return FALSE;
}

uint8_t pimsm_InterfaceWinAssert(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex)
{
    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return FALSE;/* There is no assert_winner(*,*,RP) */
    }

    if (PimsmAssertStateWinner == pimsm_AssertState(mrt_entry, ifindex))
    {
        return TRUE;
    }

    return FALSE;
}

static int pimsm_InterfaceAssertWinner(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex, VOS_IP_ADDR *pstWinnerAddr)
{
    struct pimsm_assert_if *pstAssertInterface;
    //uint8_t isFound = FALSE;

    zassert(NULL != mrt_entry);
    zassert(NULL != pstWinnerAddr);

    memset(pstWinnerAddr, 0, sizeof(VOS_IP_ADDR));

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return VOS_ERROR;/* There is no assert_winner(*,*,RP) */
    }

    pstAssertInterface = mrt_entry->pimsmassert_if;
    while(NULL != pstAssertInterface)
    {
        if (ifindex == pstAssertInterface->ifindex)
        {
            memcpy(pstWinnerAddr, &(pstAssertInterface->stAssertStateMachine.stAssertWinner.address), sizeof(VOS_IP_ADDR));
        }

        pstAssertInterface = pstAssertInterface->next;
    }

    return VOS_OK;
}

uint8_t pimsm_LocalReceiverInclude(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    uint8_t isFound = FALSE;

    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return FALSE;/* There is no receiver_include(*,*,RP,I) */
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return FALSE;/* There is no receiver_include(S,G,rpt,I) */
    }

    downstream_if = mrt_entry->downstream_if;
    while(downstream_if)
    {
        if(downstream_if->ifindex == ifindex)
        {
            isFound = TRUE;
            if(downstream_if->byLocalReceiverInclude)
            {
                return TRUE;
            }
            break;
        }

        downstream_if = downstream_if->next;
    }

    if(!isFound)
    {
        return FALSE;
    }

    return FALSE;
}

static uint8_t pimsm_LocalReceiverExclude(struct pimsm_mrt_entry *mrt_entry, uint32_t ifindex)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_interface_member *pstMember;
    struct pimsm_mrt_entry *pstSrcGrpRptEntry;
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_interface_entry *pimsm_ifp;
    struct pimsm_oif *pstOiList;

    if(NULL == mrt_entry)
    {
        return FALSE;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return FALSE;/* There is no local_receiver_exclude(*,*,RP,I) */
    }

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        return FALSE;/* There is no local_receiver_exclude(*,G,I) */
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return FALSE;/* There is no local_receiver_exclude(S,G,rpt,I) */
    }

    if(PIMSM_MRT_TYPE_SG != mrt_entry->type)
    {
        return FALSE;
    }

    /* local_recever_exclude(S,G,I) is true if local_recever_include_(*,G,I) is true
    	but none of the local members desire to receive traffic from S. */

    start_grp_entry = mrt_entry->group->pstStarMrtLink;
    if(NULL == start_grp_entry)
    {
        return FALSE;
    }

    downstream_if = start_grp_entry->downstream_if;
    while(downstream_if)
    {
        if(pimsm_LocalReceiverInclude(start_grp_entry, ifindex))
        {
            pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SGRPT);
            if (NULL != pstSrcGrpRptEntry)
            {
                pstOiList = pimsm_Prunes(pstSrcGrpRptEntry, TRUE);
                pimsm_SearchOifByIndex(pstOiList, ifindex);
                if (NULL != pimsm_SearchOifByIndex(pstOiList, ifindex))
                {
                    pimsm_FreeOil(pstOiList);
                    return TRUE;
                }
                pimsm_FreeOil(pstOiList);
            }

            pimsm_ifp = g_pimsm_interface_list;
            while(pimsm_ifp)
            {
                if (ifindex == pimsm_ifp->ifindex)
                {
                    pstMember = pimsm_ifp->pstMemberList;
                    while(pstMember)
                    {
                        if ((PIMSM_IF_EXCLUDE == pstMember->type) &&
                                (NULL != pstMember->pSrcAddrList))
                        {
                            return TRUE;
                        }
                        pstMember = pstMember->next;
                    }
                }
                pimsm_ifp = pimsm_ifp->next;
            }
        }

        downstream_if = downstream_if->next;
    }

    return FALSE;
}

struct pimsm_oif *pimsm_Joins(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_oif *oil = NULL; //return oil
    struct pimsm_oif *pstOif = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return NULL; /* There is no joins(S,G,rpt) */
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no joins(*,*,RP) */
    }

    if((PIMSM_MRT_TYPE_SG == mrt_entry->type) ||(PIMSM_MRT_TYPE_WC == mrt_entry->type) )
    {
        /* all interfaces I such that DownstreamJPState(S,G,I) is either Join or Prune-Pending */
        /* all interfaces I such that DownstreamJPState(*,G,I) is either Join or Prune-Pending */
        downstream_if = mrt_entry->downstream_if;
        while(NULL != downstream_if)
        {
            if((PimsmDownstreamStateJoin == downstream_if->down_stream_state_mchine.emDownstreamState) ||
                    (PimsmDownstreamStatePrunePending == downstream_if->down_stream_state_mchine.emDownstreamState))
            {
                if(byIsCareListContents)
                {
                    pstOif = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
                    if(NULL == pstOif)
                    {
                        return oil;
                    }
                    pstOif->ifindex = downstream_if->ifindex;
                    pstOif->prev = NULL;
                    pstOif->next = oil;
                    if(NULL != oil)
                    {
                        oil->prev = pstOif;
                    }
                    oil = pstOif;
                }
                else
                {
                    return (struct pimsm_oif *)mrt_entry->downstream_if; //return !NULL;
                }
            }

            downstream_if = downstream_if->next;
        }
    }

    return oil;
}

/* Just for prunes(S,G,rpt) */
struct pimsm_oif *pimsm_Prunes(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_oif *oil = NULL; //return oil
    struct pimsm_oif *pstOif = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    /*
    all interfaces I such that
    DownstreamJPState(S,G,rpt,I) is Prune or PruneTmp
    */
    downstream_if = mrt_entry->downstream_if;
    while(NULL != downstream_if)
    {
        if((PimsmDownstreamStatePrune == downstream_if->down_stream_state_mchine.emDownstreamState) ||
                (PimsmDownstreamStatePruneTmp== downstream_if->down_stream_state_mchine.emDownstreamState))
        {
            if(byIsCareListContents)
            {
                pstOif = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
                if(NULL == pstOif)
                {
                    return oil;
                }
                pstOif->ifindex = downstream_if->ifindex;
                pstOif->prev = NULL;
                pstOif->next = oil;
                if(NULL != oil)
                {
                    oil->prev = pstOif;
                }
                oil = pstOif;
            }
            else
            {
                return (struct pimsm_oif *)mrt_entry->downstream_if; //return !NULL;
            }
        }

        downstream_if = downstream_if->next;
    }

    return oil;
}

struct pimsm_oif *pimsm_PimInclude(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_oif *oil = NULL; //return oil
    struct pimsm_oif *pstOif = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return NULL; //There is no pim_include(S,G,rpt).
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no pim_include(*,*,RP) */
    }

    if((PIMSM_MRT_TYPE_SG == mrt_entry->type) ||(PIMSM_MRT_TYPE_WC == mrt_entry->type))
    {
        /*
        { all interfaces I such that:
        (  (I_am_DR(I) AND lost_assert(*,G,I) == FALSE) OR AssertWinner(*,G,I) == me  )
        AND local_receiver_include(*,G,I) }
        */
        /*
        { all interfaces I such that:
        (  (I_am_DR(I) AND lost_assert(S,G,I) == FALSE) OR AssertWinner(S,G,I) == me  )
        AND local_receiver_include(S,G,I) }
        */
        downstream_if = mrt_entry->downstream_if;
        while(NULL != downstream_if)
        {
            if (((pimsm_IamDR(downstream_if->ifindex) &&
                    !pimsm_InterfaceLostAssert(mrt_entry, downstream_if->ifindex))
                    ||pimsm_InterfaceWinAssert(mrt_entry, downstream_if->ifindex))
                    && pimsm_LocalReceiverInclude(mrt_entry, downstream_if->ifindex))
            {
                if(byIsCareListContents)
                {
                    pstOif = XMALLOC(MTYPE_PIM_OIF ,sizeof(struct pimsm_oif));
                    if(NULL == pstOif)
                    {
                        return oil;
                    }
                    pstOif->ifindex = downstream_if->ifindex;
                    pstOif->prev = NULL;
                    pstOif->next = oil;
                    if(NULL != oil)
                    {
                        oil->prev = pstOif;
                    }
                    oil = pstOif;
                }
                else
                {
                    return (struct pimsm_oif *)mrt_entry->downstream_if; //return !NULL;
                }
            }

            downstream_if = downstream_if->next;
        }
    }

    return oil;
}

struct pimsm_oif *pimsm_PimExclude(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_oif *oil = NULL; //return oil
    struct pimsm_oif *pstOif = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return NULL; /* There is no pim_exclude(S,G,rpt) */
    }

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        return NULL; /* There is no pim_exclude(*,G)  */
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no pim_exclude(*,*,RP) */
    }

    /* pim_exclude(S,G) */
    if((PIMSM_MRT_TYPE_SG == mrt_entry->type) ||(PIMSM_MRT_TYPE_WC == mrt_entry->type))
    {
        start_grp_entry = pimsm_SearchMrtEntry(NULL, &(mrt_entry->group->address), PIMSM_MRT_TYPE_WC);
        if(NULL == start_grp_entry)
        {
            return NULL;
        }
        /*
        { all interfaces I such that:
        (  (I_am_DR(I) AND lost_assert(*,G,I) == FALSE) OR AssertWinner(*,G,I) == me  )
        AND local_receiver_exclude(S,G,I) }
        */
        downstream_if = start_grp_entry->downstream_if;
        while(NULL != downstream_if)
        {
            if (((pimsm_IamDR(downstream_if->ifindex) &&
                    !pimsm_InterfaceLostAssert(start_grp_entry, downstream_if->ifindex))
                    ||pimsm_InterfaceWinAssert(start_grp_entry, downstream_if->ifindex))
                    && pimsm_LocalReceiverExclude(mrt_entry, downstream_if->ifindex))
            {
                if(byIsCareListContents)
                {
                    pstOif = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
                    if(NULL == pstOif)
                    {
                        return oil;
                    }
                    pstOif->ifindex = downstream_if->ifindex;
                    pstOif->prev = NULL;
                    pstOif->next = oil;
                    if(NULL != oil)
                    {
                        oil->prev = pstOif;
                    }
                    oil = pstOif;
                }
                else
                {
                    return (struct pimsm_oif *)mrt_entry->downstream_if; //return !NULL;
                }
            }

            downstream_if = downstream_if->next;
        }
    }

    return oil;
}


struct pimsm_oif *pimsm_LostAssert(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_updownstream_if_entry *downstream_if;
    struct pimsm_oif *oil = NULL; //return oil
    struct pimsm_oif *pstOif = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no lost_assert(*,*,RP) */
    }

    /*
    lost_assert(S,G,rpt)
    all interfaces I such that:
    lost_assert(S,G,rpt,I) == TRUE
    */
    /*
    lost_assert(S,G)
    all interfaces I such that:
    lost_assert(S,G,I) == TRUE
    */
    /*
    lost_assert(*,G)
    all interfaces I such that:
    lost_assert(*,G,I) == TRUE
    */
    downstream_if = mrt_entry->downstream_if;
    while(NULL != downstream_if)
    {
        if (pimsm_InterfaceLostAssert(mrt_entry, downstream_if->ifindex))
        {
            if(byIsCareListContents)
            {
                pstOif = XMALLOC(MTYPE_PIM_OIF, sizeof(struct pimsm_oif));
                if(NULL == pstOif)
                {
                    return oil;
                }
                pstOif->ifindex = downstream_if->ifindex;
                pstOif->prev = NULL;
                pstOif->next = oil;
                if(NULL != oil)
                {
                    oil->prev = pstOif;
                }
                oil = pstOif;
            }
            else
            {
                return (struct pimsm_oif *)mrt_entry->downstream_if; //return !NULL;
            }
        }

        downstream_if = downstream_if->next;
    }

    return oil;
}

struct pimsm_oif *pimsm_InheritedOlist(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_mrt_entry *pstSrcGrpRptEntry = NULL;
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_mrt_entry *start_grp_entry = NULL;
    struct pimsm_oif *pstOilInheritedOlistSrcGrpRpt = NULL;
    struct pimsm_oif *pstOilJoinsStarGrp = NULL;
    struct pimsm_oif *pstOilPrunesSrcGrpRpt = NULL;
    struct pimsm_oif *pstOilPimIncludeStarGrp = NULL;
    struct pimsm_oif *pstOilPimExcludeSrcGrp = NULL;
    struct pimsm_oif *pstOilLostAssertStarGrp = NULL;
    struct pimsm_oif *pstOilLostAssertSrcGrpRpt = NULL;
    struct pimsm_oif *pstOilInheritedOlistSrcGrp = NULL;
    struct pimsm_oif *pstOilJoinsSrcGrp = NULL;
    struct pimsm_oif *pstOilPimIncludeSrcGrp = NULL;
    struct pimsm_oif *pstOilLostAssertSrcGrp = NULL;
    struct pimsm_oif *pstOilTmp1 = NULL;
    struct pimsm_oif *pstOilTmp2 = NULL;
    struct pimsm_oif *pstOilTmp3 = NULL;
    struct pimsm_oif *pstOilTmp4 = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no inherited_olist(*,*,RP) */
    }

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        return NULL; /* There is no inherited_olist(*,G) */
    }

    if((PIMSM_MRT_TYPE_SG == mrt_entry->type) ||(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type))
    {
        /*
        inherited_olist(S,G,rpt) =
        	       ( joins(*,G) (-) prunes(S,G,rpt) )
        	(+) ( pim_include(*,G) (-) pim_exclude(S,G) )
        	(-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
        */
        start_grp_entry = mrt_entry->group->pstStarMrtLink;
        pstSrcGrpRptEntry = pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SGRPT);
        src_grp_entry = pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SG);

        pstOilJoinsStarGrp = pimsm_Joins(start_grp_entry, TRUE);
        pstOilPrunesSrcGrpRpt = pimsm_Prunes(pstSrcGrpRptEntry, TRUE);
        pstOilPimIncludeStarGrp = pimsm_PimInclude(start_grp_entry, TRUE);
        pstOilPimExcludeSrcGrp = pimsm_PimExclude(src_grp_entry, TRUE);
        pstOilLostAssertStarGrp = pimsm_LostAssert(start_grp_entry, TRUE);
        pstOilLostAssertSrcGrpRpt = pimsm_LostAssert(pstSrcGrpRptEntry, TRUE);

        pstOilTmp1 = pimsm_OilSubOilFree(pstOilJoinsStarGrp, pstOilPrunesSrcGrpRpt);
        pstOilTmp2 = pimsm_OilSubOilFree(pstOilPimIncludeStarGrp, pstOilPimExcludeSrcGrp);
        pstOilTmp3 = pimsm_OilAddOilFree(pstOilLostAssertStarGrp, pstOilLostAssertSrcGrpRpt);

        pstOilTmp4 = pimsm_OilAddOilFree(pstOilTmp1, pstOilTmp2);
        pstOilInheritedOlistSrcGrpRpt = pimsm_OilSubOilFree(pstOilTmp4, pstOilTmp3);

        if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
        {
            if(!byIsCareListContents)
            {
                if(NULL != pstOilInheritedOlistSrcGrpRpt)
                {
                    pimsm_FreeOil(pstOilInheritedOlistSrcGrpRpt);
                    return (void *)1;
                    //return (!NULL);
                }
                else
                {
                    return NULL;
                }
            }
            else
            {
                return pstOilInheritedOlistSrcGrpRpt;
            }
        }
    }

    if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        /*
        inherited_olist(S,G) =
        	inherited_olist(S,G,rpt) (+)
        	joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G)
        */
        pstOilJoinsSrcGrp = pimsm_Joins(src_grp_entry, TRUE);
        pstOilPimIncludeSrcGrp = pimsm_PimInclude(src_grp_entry, TRUE);
        pstOilLostAssertSrcGrp = pimsm_LostAssert(src_grp_entry, TRUE);

        pstOilTmp1 = pimsm_OilAddOilFree(pstOilInheritedOlistSrcGrpRpt, pstOilJoinsSrcGrp);
        pstOilTmp2 = pimsm_OilAddOilFree(pstOilTmp1, pstOilPimIncludeSrcGrp);
        pstOilInheritedOlistSrcGrp = pimsm_OilSubOilFree(pstOilTmp2, pstOilLostAssertSrcGrp);

        if(!byIsCareListContents)
        {
            if(NULL != pstOilInheritedOlistSrcGrp)
            {
                pimsm_FreeOil(pstOilInheritedOlistSrcGrp);
                return (void *)1;
            }
            else
            {
                return NULL;
            }
        }
        else
        {
            return pstOilInheritedOlistSrcGrp;
        }
    }
    else
    {
        pimsm_FreeOil(pstOilInheritedOlistSrcGrpRpt);
    }

    return NULL;
}

struct pimsm_oif *pimsm_ImmediateOlist(struct pimsm_mrt_entry *mrt_entry, uint8_t byIsCareListContents)
{
    struct pimsm_oif *pstOilImmediate = NULL;
    struct pimsm_oif *pstOilLostAssert = NULL;
    struct pimsm_oif *pstOilInclude = NULL;
    struct pimsm_oif *pstOilJoins = NULL;
    struct pimsm_oif *pstOilTmp1 = NULL;

    if(NULL == mrt_entry)
    {
        return NULL;
    }

    if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        return NULL; /* There is no immediate_olist(S,G,rpt) */
    }

    if(PIMSM_MRT_TYPE_PMBR == mrt_entry->type)
    {
        return NULL; /* There is no immediate_olist(*,*,RP) */
    }

    /* joins(*,G) + pim_include(*,G) - lost_assert(*,G)  */
    /* joins(S,G) + pim_include(S,G) - lost_assert(S,G)  */

    pstOilLostAssert = pimsm_LostAssert(mrt_entry, TRUE);
    pstOilInclude = pimsm_PimInclude(mrt_entry, TRUE);
    pstOilJoins = pimsm_Joins(mrt_entry, TRUE);

    pstOilTmp1 = pimsm_OilAddOilFree(pstOilJoins, pstOilInclude); //This will create new Oil
    pstOilImmediate = pimsm_OilSubOilFree(pstOilTmp1, pstOilLostAssert); //This will create new Oil

    if(!byIsCareListContents)
    {
        if(NULL != pstOilImmediate)
        {
            pimsm_FreeOil(pstOilImmediate);
            return (void *)1;
        }
    }

    return pstOilImmediate;
}

#define local_receiver

int pimsm_AddLocalReceiver(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t ifindex)
{
    struct pimsm_mrt_entry *pstSrcGrpEntryNext = NULL;
    struct pimsm_updownstream_if_entry *pstDownIf = NULL;
    struct pimsm_mrt_entry *src_grp_entry = NULL;
    struct pimsm_mrt_entry *mrt_entry = NULL;
    struct pimsm_grp_entry *pstGrpEntry = NULL;

    if (NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }

    if (NULL == pimsm_SearchInterface(ifindex))
    {
        return VOS_ERROR;
    }

    if (PIMSM_MRT_TYPE_WC == type)
    {
        pstDownIf = pimsm_CreateDownstreamIf(NULL, pstGrpAddr, type, 0, ifindex);
        if (NULL != pstDownIf)
        {
            pstDownIf->byLocalReceiverInclude = TRUE;
            mrt_entry = pimsm_SearchMrtEntry(NULL, pstGrpAddr, type);

            if (pimsm_CheckMrtEntryValid(mrt_entry) == VOS_ERROR)
            {
                return VOS_ERROR;
            }

            if (pimsm_SwitchToSptDesired(&pstGrpEntry->address) &&
                    pimsm_LocalReceiverExist(mrt_entry))
            {
                pimsm_SetCopyToCpu(mrt_entry, TRUE);
            }

            if (pimsm_JoinDesired(mrt_entry))
            {
                pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToTrueEvent, NULL);
            }

            pstGrpEntry = pimsm_SearchGrpEntry(pstGrpAddr);
            if(NULL != pstGrpEntry)
            {
                /* All (S,G) */
                src_grp_entry = pstGrpEntry->pstSrcMrtLink;
                while (NULL != src_grp_entry)
                {
                    pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                    if (PIMSM_MRT_TYPE_SG == src_grp_entry->type)
                    {
                        if (pimsm_JoinDesired(src_grp_entry))
                        {
                            pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
                        }
                    }
                    else if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                    {
                        if (NULL != pimsm_InheritedOlist(src_grp_entry, FALSE))
                        {
                            pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmInheritedOlistSrcGrpRptToNonNullEvent, NULL);
                        }
                    }

                    src_grp_entry = pstSrcGrpEntryNext;
                }
            }
        }
    }
    else if (PIMSM_MRT_TYPE_SG == type)
    {
        pstDownIf = pimsm_CreateDownstreamIf(src_addr, pstGrpAddr, type, PIMSM_MRT_FLAG_NUL, ifindex);
        if (NULL != pstDownIf)
        {
            pstDownIf->byLocalReceiverInclude = TRUE;
            mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
            pimsm_CheckMrtEntryValid(mrt_entry);
            if (pimsm_JoinDesired(mrt_entry))
            {
                pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToTrueEvent, NULL);
            }
        }
    }
    else if (PIMSM_MRT_TYPE_SGRPT == type)
    {
        pstDownIf = pimsm_CreateDownstreamIf(src_addr, pstGrpAddr, type, 0, ifindex);
        if (NULL != pstDownIf)
        {
            pstDownIf->byLocalReceiverInclude = TRUE; /* 如果是(S,G,rpt) 表项, 此字段表示存在本地接收者不接收S 到 G  的组播流 */
            mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
            pimsm_CheckMrtEntryValid(mrt_entry);
            if (pimsm_PruneDesired(mrt_entry))
            {
                pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmPruneDesiredSrcGrpRptToTrueEvent, NULL);
            }
        }
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

int pimsm_DelLocalReceiver(VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstGrpAddr,uint8_t type,uint32_t ifindex)
{
    struct pimsm_mrt_entry *pstSrcGrpEntryNext = NULL;
    struct pimsm_updownstream_if_entry *pstDownIf;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_grp_entry *pstGrpEntry;

    if (NULL == pstGrpAddr)
    {
        return VOS_ERROR;
    }

    if ((PIMSM_MRT_TYPE_SG == type) || (PIMSM_MRT_TYPE_SGRPT == type))
    {
        if (NULL == src_addr)
        {
            return VOS_ERROR;
        }
    }

    if (PIMSM_MRT_TYPE_WC == type)
    {
        mrt_entry = pimsm_SearchMrtEntry(NULL, pstGrpAddr, type);
    }
    else if (PIMSM_MRT_TYPE_SG == type)
    {
        mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
    }
    else if (PIMSM_MRT_TYPE_SGRPT == type)
    {
        mrt_entry = pimsm_SearchMrtEntry(src_addr, pstGrpAddr, type);
    }
    else
    {
        return VOS_ERROR;
    }

    if (NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    pstDownIf = mrt_entry->downstream_if;
    pstDownIf = pimsm_SearchDownstreamIfByIndex(mrt_entry->downstream_if, ifindex);
    if (NULL == pstDownIf)
    {
        return VOS_ERROR;
    }

    pstDownIf->byLocalReceiverInclude = FALSE;

    pimsm_CheckMrtEntryValid(mrt_entry);

    if (PIMSM_MRT_TYPE_WC == type)
    {
        if (!pimsm_SwitchToSptDesired(&pstGrpEntry->address) ||
                !pimsm_LocalReceiverExist(mrt_entry))
        {
            pimsm_SetCopyToCpu(mrt_entry, FALSE);
        }

        if (!pimsm_JoinDesired(mrt_entry))
        {
            pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredStarGrpToFalseEvent, NULL);
        }

        pstGrpEntry = pimsm_SearchGrpEntry(pstGrpAddr);
        if (NULL != pstGrpEntry)
        {
            /* All (S,G) */
            src_grp_entry = pstGrpEntry->pstSrcMrtLink;
            while (NULL != src_grp_entry)
            {
                pstSrcGrpEntryNext = src_grp_entry->samegrpnext;

                if (PIMSM_MRT_TYPE_SG == src_grp_entry->type)
                {
                    if (!pimsm_JoinDesired(src_grp_entry))
                    {
                        pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
                    }
                }
                else if (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type)
                {
                    if (!pimsm_RPTJoinDesired(pstGrpAddr))
                    {
                        pimsm_UpdownstreamStateMachineEventProc(src_grp_entry, PIMSM_UPSTREAM_IF, 0, PimsmRptJoinDesiredGrpToFalse, NULL);
                    }
                }

                src_grp_entry = pstSrcGrpEntryNext;
            }
        }

        if ((PimsmAssertStateNoInfo == pimsm_AssertState(mrt_entry, pstDownIf->ifindex)) &&
                (PimsmDownstreamStateNoInfo == pstDownIf->down_stream_state_mchine.emDownstreamState) &&
                (!pstDownIf->byLocalReceiverInclude))
        {
            pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);
        }
    }
    else if (PIMSM_MRT_TYPE_SG == type)
    {
        if (!pimsm_JoinDesired(mrt_entry))
        {
            pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmJoinDesiredSrcGrpToFalseEvent, NULL);
        }

        if ((PimsmAssertStateNoInfo == pimsm_AssertState(mrt_entry, pstDownIf->ifindex)) &&
                (PimsmDownstreamStateNoInfo == pstDownIf->down_stream_state_mchine.emDownstreamState) &&
                (!pstDownIf->byLocalReceiverInclude))
        {
            pimsm_DestroyDownstreamIf(mrt_entry, pstDownIf->ifindex);
        }
    }
    else if (PIMSM_MRT_TYPE_SGRPT == type)
    {
        if (!pimsm_PruneDesired(mrt_entry))
        {
            pimsm_UpdownstreamStateMachineEventProc(mrt_entry, PIMSM_UPSTREAM_IF, 0, PimsmPruneDesiredSrcGrpRptToFalseEvent, NULL);
        }
    }

    return VOS_OK;
}

int pimsm_DelAllLocalReceiver(void)
{
    struct pimsm_updownstream_if_entry *pstDownIf;
    struct pimsm_grp_entry *pstGroupEntry;
    struct pimsm_mrt_entry *mrt_entry;

    if (NULL != g_group_hash)
    {
        hash_traversal_start(g_group_hash, pstGroupEntry);
        if(NULL != pstGroupEntry)
        {
            /* (*,G) */
            mrt_entry = pstGroupEntry->pstStarMrtLink;
            if (NULL != mrt_entry)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(pstDownIf)
                {
                    pstDownIf->byLocalReceiverInclude = FALSE;
                    pstDownIf = pstDownIf->next;
                }
            }

            /* All (S,G) (S,G,rpt) */
            mrt_entry = pstGroupEntry->pstSrcMrtLink;
            for (; NULL != mrt_entry; mrt_entry = mrt_entry->samegrpnext)
            {
                pstDownIf = mrt_entry->downstream_if;
                while(pstDownIf)
                {
                    pstDownIf->byLocalReceiverInclude = FALSE;
                    pstDownIf = pstDownIf->next;
                }
            }
        }
        hash_traversal_end();
    }

    return VOS_ERROR;
}

uint8_t pimsm_LocalReceiverExist (struct pimsm_mrt_entry *mrt_entry)
{
    struct pimsm_updownstream_if_entry *pstDownIf;

    zassert(NULL != mrt_entry);

    pstDownIf = mrt_entry->downstream_if;

    while(NULL != pstDownIf)
    {
        if (pstDownIf->byLocalReceiverInclude)
        {
            return TRUE;
        }
        pstDownIf = pstDownIf->next;
    }

    return FALSE;
}

#define alive

int pimsm_KeepAliveTimerStart(struct pimsm_mrt_entry *src_grp_entry, uint32_t dwTimerValue)
{
    PIMSM_TIMER_PARA_KEEPALIVE_T *keepAlivePara;

    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if (src_grp_entry->t_pimsm_keep_alive_timer)
        THREAD_OFF(src_grp_entry->t_pimsm_keep_alive_timer);

    keepAlivePara = XMALLOC(MTYPE_PIM_KEEPALIVE_PARA, sizeof(PIMSM_TIMER_PARA_KEEPALIVE_T));

    memset(keepAlivePara, 0, sizeof(PIMSM_TIMER_PARA_KEEPALIVE_T));
    if(NULL != src_grp_entry->source)
    {
        memcpy(&keepAlivePara->src_addr, &src_grp_entry->source->address, sizeof(VOS_IP_ADDR));
    }
    if(NULL != src_grp_entry->group)
    {
        memcpy(&keepAlivePara->grp_addr, &src_grp_entry->group->address, sizeof(VOS_IP_ADDR));
    }
    keepAlivePara->type = src_grp_entry->type;

    THREAD_TIMER_ON(master, src_grp_entry->t_pimsm_keep_alive_timer,
                    pimsm_TimeroutKeepAlive,
                    keepAlivePara, dwTimerValue);


    return VOS_OK;
}

static int pimsm_KeepAliveTimerStop(struct pimsm_mrt_entry *src_grp_entry)
{
    if(NULL == src_grp_entry)
    {
        return VOS_ERROR;
    }

    if (src_grp_entry->t_pimsm_keep_alive_timer)
        THREAD_OFF(src_grp_entry->t_pimsm_keep_alive_timer);

    src_grp_entry->t_pimsm_keep_alive_timer = 0;

    return VOS_OK;
}

static uint8_t pimsm_KeepAliveTimerIsRunning(struct pimsm_mrt_entry *src_grp_entry)
{
    if(NULL == src_grp_entry)
    {
        return FALSE;
    }

    return (src_grp_entry->t_pimsm_keep_alive_timer ? TRUE : FALSE);
}

int pimsm_MrtDelTimerStart(struct pimsm_mrt_entry *mrt_entry, uint32_t dwTimerValue)
{
    PIMSM_TIMER_PARA_MRT_EXPIRY_T *mrtDelPara;

    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    if (mrt_entry->t_pimsm_delay_timer)
        THREAD_OFF(mrt_entry->t_pimsm_delay_timer);

    mrtDelPara = XMALLOC(MTYPE_PIM_MRTEXPIRY_PARA, sizeof(PIMSM_TIMER_PARA_MRT_EXPIRY_T));
    memset(mrtDelPara, 0, sizeof(PIMSM_TIMER_PARA_MRT_EXPIRY_T));
    if(NULL != mrt_entry->source)
    {
        memcpy(&mrtDelPara->src_addr, &mrt_entry->source->address, sizeof(VOS_IP_ADDR));
    }
    if(NULL != mrt_entry->group)
    {
        memcpy(&mrtDelPara->grp_addr, &mrt_entry->group->address, sizeof(VOS_IP_ADDR));
    }
    mrtDelPara->type = mrt_entry->type;

    THREAD_TIMER_ON(master, mrt_entry->t_pimsm_delay_timer,
                    pimsm_TimeroutMrtExpiry,
                    mrtDelPara, dwTimerValue);

    return VOS_OK;
}

int pimsm_MrtDelTimerStop(struct pimsm_mrt_entry *mrt_entry)
{
    if(NULL == mrt_entry)
    {
        return VOS_ERROR;
    }

    if (mrt_entry->t_pimsm_delay_timer)
        THREAD_OFF(mrt_entry->t_pimsm_delay_timer);

    mrt_entry->t_pimsm_delay_timer = 0;

    return VOS_OK;
}

#define rtmgt

int pimsm_MrtUpdateMsgRepostProcess(void)
{
    PIMSM_MSG_T *msg_tmp;
    struct listnode *pHead;

    pHead = listhead(g_msg_pim2rtmgt_list);
    while(pHead != NULL)
    {
        msg_tmp = pHead->data;
#if 0//FIXME: will use socket
        if(vos_MsgPost(msg_tmp->stCommonHead.wDestTaskID, (char*)(pHead->data), NO_WAIT) != VOS_OK)
        {
            return -1;
        }
        else
#endif
        {
            listnode_delete(g_msg_pim2rtmgt_list, msg_tmp);
            XFREE(MTYPE_PIM_MSG, msg_tmp);
        }
        pHead = listhead(g_msg_pim2rtmgt_list);
    }

    return 0;
}
#define mmUpdateMrt 0x000c
int pimsm_MrtUpdateToRtmgt(struct mrtmgt_mrt_update_entry *pEntryData)
{
    PIMSM_MSG_T *pstMsg;

    if( pEntryData == NULL )
    {
        return VOS_ERROR;
    }

    pstMsg = XMALLOC(MTYPE_PIM_MSG, sizeof(PIMSM_MSG_T));
    if (NULL == pstMsg)
    {
        return VOS_ERROR;
    }
    memset(pstMsg, 0x00, sizeof(PIMSM_MSG_T));

    pstMsg->stCommonHead.wSourTaskID = TASK_ID_PIMSM;
    pstMsg->stCommonHead.wDestTaskID = TASK_ID_RT_MGT;
    pstMsg->stCommonHead.wMsgLength = sizeof(PIMSM_MSG_T);
    pstMsg->stCommonHead.wMsgType = mmUpdateMrt;
    pstMsg->u_msg.mPimsmToRtMgt.mMrtUpdate.dwMrtNum= 1;
    memcpy(pstMsg->u_msg.mPimsmToRtMgt.mMrtUpdate.stMrtUpdt, pEntryData, sizeof(struct mrtmgt_mrt_update_entry) );

    if (0 == pimsm_MrtUpdateMsgRepostProcess())
    {
#if 0//FIXME: will use socket
        if (VOS_OK != vos_MsgPost(pstMsg->stCommonHead.wDestTaskID, (char *)pstMsg, NO_WAIT))
        {
            listnode_add(g_msg_pim2rtmgt_list, pstMsg);
        }
        else
#endif
        {
            XFREE(MTYPE_PIM_MSG, pstMsg);
        }
    }
    else
    {
        listnode_add(g_msg_pim2rtmgt_list, pstMsg);
    }

    return VOS_OK;
}

#define MRTMGT_PIM_MODE_SPARSE	0	//稀疏模式
static int pimsm_AddHardwareEntry(struct pimsm_mrt_hardware_entry *pstHardEntry)
{
    struct mfcctl mc;
    struct pimsm_oif *oil;

    zassert(NULL != pstHardEntry);

    PIM_DEBUG("(********important********)Enter pimsm_AddHardwareEntry, iif:%s.\n", ifindex2ifname(pstHardEntry->in_ifindex))

    memset(&mc, 0, sizeof(struct mfcctl));
    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        mc.mfcc_origin.s_addr = pstHardEntry->src_addr.u32_addr[0];
    }
    else
        PIM_DEBUG("pstHardEntry->src_addr is 0.\n");

    mc.mfcc_mcastgrp.s_addr = pstHardEntry->grp_addr.u32_addr[0];

    char group_str[100];
    char source_str[100];
    pim_inet4_dump("<group?>",  mc.mfcc_mcastgrp, group_str, sizeof(group_str));
    pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));

    if (pstHardEntry->in_ifindex < 1)
    {
        zlog_warn("%s %s: could not find input interface for source %s group %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str, group_str);
        return -1;
    }
    mc.mfcc_parent =  pstHardEntry->in_ifindex;
    oil = pstHardEntry->out_if;
    while(NULL != oil)
    {
        if (oil->ifindex)
        {
            PIM_DEBUG("oil->ifindex:%d.\n", oil->ifindex);
            mc.mfcc_ttls[oil->ifindex] = PIM_MROUTE_MIN_TTL;
        }

        oil = oil->next;
    }
    if (pim_mroute_add(&mc))
    {
        zlog_warn("%s %s: could not add  from channel (S,G)=(%s,%s)",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str, group_str);

        return -1;
    }

    PIM_DEBUG("add  from channel (S,G)=(%s,%s) success.\n", source_str, group_str);
    return VOS_OK;
#if 0
    struct mrtmgt_mrt_update_entry stPim2MrtUpdateEntry;
    struct pimsm_oif *pstOif;
    uint32_t dwNumIf = 0;

    zassert(NULL != pstHardEntry);

    memset(&stPim2MrtUpdateEntry, 0, sizeof(struct	mrtmgt_mrt_update_entry));

    if(pstHardEntry->bIsCopyToCpu)
    {
        if(dwNumIf < MRTMGT_MRT_UPDATE_ENTRY_MAX_OUTIF_NUM)
        {
            stPim2MrtUpdateEntry.stOutputLif[dwNumIf].iOutLifNo= 0;
            dwNumIf++;
        }
    }

    for(pstOif = pstHardEntry->out_if; NULL != pstOif; pstOif = pstOif->next)
    {
        if(dwNumIf >= MRTMGT_MRT_UPDATE_ENTRY_MAX_OUTIF_NUM)
        {
            break;
        }
        stPim2MrtUpdateEntry.stOutputLif[dwNumIf].iOutLifNo= pstOif->ifindex;
        dwNumIf++;
    }

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        stPim2MrtUpdateEntry.source = ntohl(pstHardEntry->src_addr.u32_addr[0]);
    }
    stPim2MrtUpdateEntry.wUpdtType = MRTMGT_MRT_UPDT_TYPE_ADD;
    stPim2MrtUpdateEntry.dwGrp = ntohl(pstHardEntry->grp_addr.u32_addr[0]);
    stPim2MrtUpdateEntry.dwOutLifNum = dwNumIf;
    stPim2MrtUpdateEntry.byRpfCheck = pstHardEntry->byRpfCheck;
    stPim2MrtUpdateEntry.iInLifNo = pstHardEntry->in_ifindex;
    stPim2MrtUpdateEntry.bMode = MRTMGT_PIM_MODE_SPARSE;

    return pimsm_MrtUpdateToRtmgt(&stPim2MrtUpdateEntry);
#endif
}

static int pimsm_DelHardwareEntry(struct pimsm_mrt_hardware_entry *pstHardEntry)
{
    struct mfcctl mc;
    struct pimsm_oif *oil;

    zassert(NULL != pstHardEntry);

    PIM_DEBUG("(********important********)Enter pimsm_DelHardwareEntry, iif:%s.\n", ifindex2ifname(pstHardEntry->in_ifindex))

    memset(&mc, 0, sizeof(struct mfcctl));

    PIM_DEBUG("Enter pimsm_DelHardwareEntry.\n");

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        mc.mfcc_origin.s_addr = pstHardEntry->src_addr.u32_addr[0];
    }
    mc.mfcc_mcastgrp.s_addr = pstHardEntry->grp_addr.u32_addr[0];

    if (pstHardEntry->in_ifindex < 1)
    {
        char source_str[100];
        pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));
        zlog_warn("%s %s: could not find input interface for source %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str);
        return -1;
    }
    mc.mfcc_parent =  pstHardEntry->in_ifindex;
    oil = pstHardEntry->out_if;
    while(NULL != oil)
    {
        if (oil->ifindex)
        {
            PIM_DEBUG("oil->ifindex:%d.\n", oil->ifindex);
            mc.mfcc_ttls[oil->ifindex] = 0;
        }
        oil = oil->next;
    }

    char group_str[100];
    char source_str[100];
    pim_inet4_dump("<group?>", mc.mfcc_mcastgrp, group_str, sizeof(group_str));
    pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));

    if (pim_mroute_del(&mc))
    {
        zlog_warn("%s %s: could not remove  from channel (S,G)=(%s,%s)",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str, group_str);

        return -1;
    }
    PIM_DEBUG("remove  from channel (S,G)=(%s,%s) success.\n",
              source_str, group_str);

    return VOS_OK;

#if 0
    struct mrtmgt_mrt_update_entry stPim2MrtUpdateEntry;

    if (NULL == pstHardEntry)
    {
        return VOS_OK;
    }

    memset(&stPim2MrtUpdateEntry, 0, sizeof(struct	mrtmgt_mrt_update_entry));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        stPim2MrtUpdateEntry.source = ntohl(pstHardEntry->src_addr.u32_addr[0]);
    }
    stPim2MrtUpdateEntry.dwGrp = ntohl(pstHardEntry->grp_addr.u32_addr[0]);
    stPim2MrtUpdateEntry.wUpdtType = MRTMGT_MRT_UPDT_TYPE_DELETE;
    stPim2MrtUpdateEntry.iInLifNo = pstHardEntry->in_ifindex;

    /*
    PIM_DEBUG("----------------------------------------\n");
    PIM_DEBUG("pimsm_DelHardwareEntry\n");
    if(0 != pstHardEntry->src_addr.u32_addr[0])
    {
    	PIM_DEBUG("(%s, %s)\n", pim_InetFmt(&pstHardEntry->src_addr),
    		pim_InetFmt(&pstHardEntry->grp_addr));
    }
    else
    {
    	PIM_DEBUG("(*, %s)\n", pim_InetFmt(&pstHardEntry->grp_addr));
    }
    PIM_DEBUG("InLifNo = %d\n", pstHardEntry->in_ifindex);
    PIM_DEBUG("----------------------------------------\n");
    */

    return pimsm_MrtUpdateToRtmgt(&stPim2MrtUpdateEntry);
#endif
}
void pimsm_mroute_add_all(void)
{
    struct pimsm_mrt_hardware_entry *hard_list;
    hard_list = g_multicast_router_hardware_list;
    while(NULL != hard_list)
    {
        pimsm_AddHardwareEntry(hard_list);
        hard_list = hard_list->next;
    }
}
void pimsm_mroute_del_all(void)
{
    struct pimsm_mrt_hardware_entry *hard_list;
    hard_list = g_multicast_router_hardware_list;
    while(NULL != hard_list)
    {
        pimsm_DelHardwareEntry(hard_list);
        hard_list = hard_list->next;
    }
}

static int pimsm_AddHardwareEntryOif(struct pimsm_mrt_hardware_entry *pstHardEntry, uint32_t dwOifIndex)
{
    struct mfcctl mc;
    struct pimsm_oif *oil;
    struct pimsm_interface_entry *pimsm_ifp;

    zassert(NULL != pstHardEntry);

    memset(&mc, 0, sizeof(struct mfcctl));

    PIM_DEBUG("(*******important*******)Enter pimsm_AddHardwareEntryOif, dwOifIndex:%d, iif:%s.\n", dwOifIndex, ifindex2ifname(pstHardEntry->in_ifindex));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        mc.mfcc_origin.s_addr = pstHardEntry->src_addr.u32_addr[0];
    }
    mc.mfcc_mcastgrp.s_addr = pstHardEntry->grp_addr.u32_addr[0];

    if (pstHardEntry->in_ifindex < 1)
    {
        char source_str[100];
        pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));
        zlog_warn("%s %s: could not find input interface for source %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str);
        return -1;
    }

    mc.mfcc_parent = pstHardEntry->in_ifindex;

    oil = pstHardEntry->out_if;
    while(NULL != oil)
    {
        if (oil->ifindex)
        {
            PIM_DEBUG("oil->ifindex:%d.\n", oil->ifindex);
            mc.mfcc_ttls[oil->ifindex] = PIM_MROUTE_MIN_TTL;
        }

        oil = oil->next;
    }

    pimsm_ifp = pimsm_SearchInterface(dwOifIndex);
    if (pimsm_ifp == NULL)
    {
        PIM_DEBUG("can't find pimsm_ifp, use:%d.\n", dwOifIndex);
        return -1;
    }


    mc.mfcc_ttls[pimsm_ifp->mroute_vif_index] = PIM_MROUTE_MIN_TTL;

    char group_str[100];
    char source_str[100];
    pim_inet4_dump("<group?>", mc.mfcc_mcastgrp, group_str, sizeof(group_str));
    pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));


    if (pim_mroute_add(&mc))
    {
        zlog_warn("%s %s: could not add output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
                  __FILE__, __PRETTY_FUNCTION__,
                  ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->mroute_vif_index,
                  source_str, group_str);

        return -1;
    }
#if 0
    ++pstHardEntry->oil_size;
#endif

    PIM_DEBUG("add output interface %s (vif_index=%d) for channel (S,G)=(%s,%s), success.\n",
              ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->mroute_vif_index,
              source_str, group_str);
    return VOS_OK;
}

static int pimsm_DelHardwareEntryOif(struct pimsm_mrt_hardware_entry *pstHardEntry,uint32_t dwOifIndex)
{
    struct mfcctl mc;
    struct pimsm_oif *oil;
    struct pimsm_interface_entry *pimsm_ifp;

    zassert(NULL != pstHardEntry);

    PIM_DEBUG("(********important************)Enter pimsm_DelHardwareEntryOif, dwOifIndex:%d, iif:%s.\n", dwOifIndex, ifindex2ifname(pstHardEntry->in_ifindex));

    memset(&mc, 0, sizeof(struct mfcctl));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        mc.mfcc_origin.s_addr = pstHardEntry->src_addr.u32_addr[0];
    }
    mc.mfcc_mcastgrp.s_addr = pstHardEntry->grp_addr.u32_addr[0];

    if (pstHardEntry->in_ifindex < 1)
    {
        char source_str[100];
        pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));
        zlog_warn("%s %s: could not find input interface for source %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  source_str);
        return -1;
    }

    mc.mfcc_parent =  pstHardEntry->in_ifindex;

    oil = pstHardEntry->out_if;
    while(NULL != oil)
    {
        if (oil->ifindex)
        {
            PIM_DEBUG("oil->ifindex:%d.\n", oil->ifindex);
            mc.mfcc_ttls[oil->ifindex] = PIM_MROUTE_MIN_TTL;
        }
        oil = oil->next;
    }

    pimsm_ifp = pimsm_SearchInterface(dwOifIndex);
    if (pimsm_ifp == NULL)
    {
        PIM_DEBUG("can't find pimsm_ifp, use:%d.\n", dwOifIndex);
        return -1;
    }

    PIM_DEBUG("mroute_vif_index:%d.\n", pimsm_ifp->mroute_vif_index);

    mc.mfcc_ttls[pimsm_ifp->mroute_vif_index] = 0;

    char group_str[100];
    char source_str[100];
    pim_inet4_dump("<group?>", mc.mfcc_mcastgrp, group_str, sizeof(group_str));
    pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));

    if (pim_mroute_add(&mc))
    {
        zlog_warn("%s %s: could not  remove output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
                  __FILE__, __PRETTY_FUNCTION__,
                  ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->mroute_vif_index,
                  source_str, group_str);

        return -1;
    }

#if 0
    --pstHardEntry->oil_size;
    if (pstHardEntry->oil_size < 1)
    {
        if (pim_mroute_del(&mc))
        {
            /* just log a warning in case of failure */
            char group_str[100];
            char source_str[100];
            pim_inet4_dump("<group?>", mc.mfcc_mcastgrp, group_str, sizeof(group_str));
            pim_inet4_dump("<source?>", mc.mfcc_origin, source_str, sizeof(source_str));
            zlog_warn("%s %s: failure removing OIL for channel (S,G)=(%s,%s)",
                      __FILE__, __PRETTY_FUNCTION__,
                      source_str, group_str);
        }
    }
#endif
    PIM_DEBUG("remove output interface %s (vif_index=%d) for channel (S,G)=(%s,%s) success.\n",
              ifindex2ifname(pimsm_ifp->ifindex), pimsm_ifp->mroute_vif_index,
              source_str, group_str);

    return VOS_OK;

#if 0
    struct  mrtmgt_mrt_update_entry stPim2MrtUpdateEntry;
    int ret;

    zassert(NULL != pstHardEntry);

    memset(&stPim2MrtUpdateEntry, 0, sizeof(struct  mrtmgt_mrt_update_entry));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        stPim2MrtUpdateEntry.source = ntohl(pstHardEntry->src_addr.u32_addr[0]);
    }
    stPim2MrtUpdateEntry.dwGrp = ntohl(pstHardEntry->grp_addr.u32_addr[0]);
    stPim2MrtUpdateEntry.wUpdtType = MRTMGT_MRT_UPDT_TYPE_DELETE_OIF;
    stPim2MrtUpdateEntry.dwOutLifNum = 1;
    stPim2MrtUpdateEntry.iInLifNo = pstHardEntry->in_ifindex;
    stPim2MrtUpdateEntry.stOutputLif[0].iOutLifNo= dwOifIndex;

    ret = pimsm_MrtUpdateToRtmgt(&stPim2MrtUpdateEntry);

    return ret;
#endif
}

#if 0
static int pimsm_AddHardwareEntryToCpu(struct pimsm_mrt_hardware_entry *pstHardEntry)
{
    struct  mrtmgt_mrt_update_entry stPim2MrtUpdateEntry;
    int ret = VOS_ERROR;

    zassert(NULL != pstHardEntry);

    memset(&stPim2MrtUpdateEntry, 0, sizeof(struct  mrtmgt_mrt_update_entry));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        stPim2MrtUpdateEntry.source = ntohl(pstHardEntry->src_addr.u32_addr[0]);
    }
    stPim2MrtUpdateEntry.dwGrp = ntohl(pstHardEntry->grp_addr.u32_addr[0]);
    stPim2MrtUpdateEntry.wUpdtType = MRTMGT_MRT_UPDT_TYPE_ADD_OIF;
    stPim2MrtUpdateEntry.dwOutLifNum = 1;
    stPim2MrtUpdateEntry.iInLifNo = pstHardEntry->in_ifindex;
    stPim2MrtUpdateEntry.stOutputLif[0].iOutLifNo = 0;//0: to cpu

    ret = pimsm_MrtUpdateToRtmgt(&stPim2MrtUpdateEntry);
    return ret;
}

static int pimsm_DelHardwareEntryToCpu(struct pimsm_mrt_hardware_entry *pstHardEntry)
{
    struct  mrtmgt_mrt_update_entry stPim2MrtUpdateEntry;
    int ret = 0;

    zassert(NULL != pstHardEntry);

    memset(&stPim2MrtUpdateEntry, 0, sizeof(struct  mrtmgt_mrt_update_entry));

    if (0 != pstHardEntry->src_addr.u32_addr[0])
    {
        stPim2MrtUpdateEntry.source = ntohl(pstHardEntry->src_addr.u32_addr[0]);
    }
    stPim2MrtUpdateEntry.dwGrp = ntohl(pstHardEntry->grp_addr.u32_addr[0]);
    stPim2MrtUpdateEntry.wUpdtType = MRTMGT_MRT_UPDT_TYPE_DELETE_OIF;
    stPim2MrtUpdateEntry.dwOutLifNum = 1;
    stPim2MrtUpdateEntry.iInLifNo = pstHardEntry->in_ifindex;
    stPim2MrtUpdateEntry.stOutputLif[0].iOutLifNo= 0;

    ret = pimsm_MrtUpdateToRtmgt(&stPim2MrtUpdateEntry);

    return ret;
}
#endif
#define mmRtmgtMsgHeader							0x0180
#define mmRpfRegister_PimToMrtmgt						mmRtmgtMsgHeader + 19

static struct pimsm_rpf *pimsm_CreatRpfChangeRegister(VOS_IP_ADDR *pstDstAddr)
{
    struct pimsm_rpf *pstRpf = NULL;
    struct in_addr addr;

    if(NULL == pstDstAddr)
    {
        return NULL;
    }

    pstRpf =pimsm_CreateRpfEntry(pstDstAddr);
    if(NULL == pstRpf)
    {
        return NULL;
    }

    memset(&addr, 0, sizeof(struct in_addr));
    addr.s_addr = pstDstAddr->u32_addr[0];
    if (pimsm_nexthop_lookup(pstRpf, addr))
        return NULL;
    return pstRpf;
}

#define manage

static int pimsm_HardwareTableCheck(struct pimsm_mrt_hardware_entry *pstHardwareListNew)
{
    struct pimsm_mrt_hardware_entry *hard_list_new;
    struct pimsm_mrt_hardware_entry *hard_list_old;
    struct pimsm_oif *oil_1;
    struct pimsm_oif *oil_2;
    struct pimsm_oif *pstOif;

    hard_list_old = g_multicast_router_hardware_list;
    hard_list_new = pstHardwareListNew;

    if (NULL == hard_list_new)
    {
        /* delete all old hardware entry */
        while(NULL != hard_list_old)
        {
            /* need delete this entry */
            PIM_DEBUG("will call pimsm_DelHardwareEntry.\n");
            pimsm_DelHardwareEntry(hard_list_old);
            hard_list_old = hard_list_old->next;
        }
    }
    else if (NULL == hard_list_old)
    {
        /* add all new hardware entry */
        while(NULL != hard_list_new)
        {
            /* need add this entry */
            pimsm_AddHardwareEntry(hard_list_new);
            hard_list_new = hard_list_new->next;
        }
    }
    else
    {
        hard_list_new = pstHardwareListNew;
        while(NULL != hard_list_new)
        {
            hard_list_old = g_multicast_router_hardware_list;
            while(NULL != hard_list_old)
            {
                if ((hard_list_new->type == hard_list_old->type) &&
                        (0 == ip_AddressCompare(&hard_list_new->grp_addr, &hard_list_old->grp_addr)) &&
                        (0 == ip_AddressCompare(&hard_list_new->src_addr, &hard_list_old->src_addr)))
                {
                    break;
                }
                hard_list_old = hard_list_old->next;
            }

            if (NULL != hard_list_old)
            {
                /* need update this hardware entry */
                oil_1 = pimsm_OilSubOil(hard_list_new->out_if, hard_list_old->out_if);
                oil_2 = pimsm_OilSubOil(hard_list_old->out_if, hard_list_new->out_if);

                if ((hard_list_new->in_ifindex != hard_list_old->in_ifindex) ||
                        (hard_list_new->byRpfCheck != hard_list_old->byRpfCheck))
                {
                    PIM_DEBUG("will call pimsm_DelHardwareEntry.\n");
                    pimsm_DelHardwareEntry(hard_list_old);
                    pimsm_AddHardwareEntry(hard_list_new);
                }
                else
                {
#if 0
                    if (hard_list_new->bIsCopyToCpu && !hard_list_old->bIsCopyToCpu)
                    {
                        pimsm_AddHardwareEntryToCpu(hard_list_new);
                    }
                    else if (!hard_list_new->bIsCopyToCpu && hard_list_old->bIsCopyToCpu)
                    {
                        pimsm_DelHardwareEntryToCpu(hard_list_old);
                    }
#endif
                    if (NULL != oil_1)
                    {
                        pstOif = oil_1;
                        while(pstOif)
                        {
                            pimsm_AddHardwareEntryOif(hard_list_new, pstOif->ifindex);
                            pstOif = pstOif->next;
                        }
                    }
                    if (NULL != oil_2)
                    {
                        pstOif = oil_2;
                        while(pstOif)
                        {
                            pimsm_DelHardwareEntryOif(hard_list_old, pstOif->ifindex);
                            pstOif = pstOif->next;
                        }
                    }
                }

                pimsm_FreeOil(oil_1);
                pimsm_FreeOil(oil_2);
            }
            else
            {
                /* need add this hardware entry */
                pimsm_AddHardwareEntry(hard_list_new);
            }

            hard_list_new = hard_list_new->next;
        }

        hard_list_old = g_multicast_router_hardware_list;
        while(NULL != hard_list_old)
        {
            hard_list_new = pstHardwareListNew;
            while(NULL != hard_list_new)
            {
                if ((hard_list_new->type == hard_list_old->type) &&
                        (0 == ip_AddressCompare(&hard_list_new->grp_addr, &hard_list_old->grp_addr)) &&
                        (0 == ip_AddressCompare(&hard_list_new->src_addr, &hard_list_old->src_addr)))
                {
                    break;
                }
                hard_list_new = hard_list_new->next;
            }

            if (NULL == hard_list_new)
            {
                /* need delete this hardware entry */
                PIM_DEBUG("will call pimsm_DelHardwareEntry.\n");
                pimsm_DelHardwareEntry(hard_list_old);
            }

            hard_list_old = hard_list_old->next;
        }
    }

    /* free old hardware list */
    pimsm_DestroyAllHardwareEntry();
    g_multicast_router_hardware_list = pstHardwareListNew;

    return VOS_OK;
}

int pimsm_DestroyAllHardwareEntry(void)
{
    struct pimsm_mrt_hardware_entry *pstHardwareEntryNext;
    struct pimsm_mrt_hardware_entry *pstHardwareEntry;

    pstHardwareEntry = g_multicast_router_hardware_list;
    while(NULL != pstHardwareEntry)
    {
        pstHardwareEntryNext = pstHardwareEntry->next;

        pimsm_FreeOil(pstHardwareEntry->out_if);
        XFREE(MTYPE_PIM_OTHER, pstHardwareEntry);

        pstHardwareEntry = pstHardwareEntryNext;
    }
    g_multicast_router_hardware_list = NULL;

    return VOS_OK;
}

static int pimsm_DisplayAllHardwareEntry(struct vty *vty)
{
    struct pimsm_mrt_hardware_entry *pstHardwareEntry;
    struct pimsm_oif *pstOif;

    pstHardwareEntry = g_multicast_router_hardware_list;

    vty_out(vty, "Heardware Multicast Router Information:\n");
    vty_out(vty, "=================================================\n");
    while(NULL != pstHardwareEntry)
    {
        if (PIMSM_MRT_TYPE_WC == pstHardwareEntry->type)
        {
            vty_out(vty, "(*, %s) iif: %s",
                    pim_InetFmt(&pstHardwareEntry->grp_addr),
                    pimsm_GetIfName(pstHardwareEntry->in_ifindex));
        }
        else if (PIMSM_MRT_TYPE_SG == pstHardwareEntry->type)
        {
            vty_out(vty, "(%s, %s) iif: %s",
                    pim_InetFmt(&pstHardwareEntry->src_addr),
                    pim_InetFmt(&pstHardwareEntry->grp_addr),
                    pimsm_GetIfName(pstHardwareEntry->in_ifindex));
        }
        else if (PIMSM_MRT_TYPE_SGRPT == pstHardwareEntry->type)
        {
            vty_out(vty, "(%s, %s, rpt) iif: %s",
                    pim_InetFmt(&pstHardwareEntry->src_addr),
                    pim_InetFmt(&pstHardwareEntry->grp_addr),
                    pimsm_GetIfName(pstHardwareEntry->in_ifindex));
        }
        vty_out(vty,"\t%s", "oif:");
        pstOif = pstHardwareEntry->out_if;
        while(NULL != pstOif)
        {
            vty_out(vty, "%s ", pimsm_GetIfName(pstOif->ifindex));

            pstOif = pstOif->next;
        }
        vty_out(vty, "%s", "\n");

        pstHardwareEntry = pstHardwareEntry->next;
    }
    vty_out(vty, "%s", "-------------------------------------------------\n");

    return VOS_OK;
}

int pimsm_MrtManagePeriod(void)
{
    struct pimsm_mrt_hardware_entry *pstHardwareNewList = NULL;
    struct pimsm_mrt_hardware_entry *pstHardwareEntry;
    struct pimsm_grp_entry *pstGroupEntry;
    struct pimsm_mrt_entry *mrt_entry;
    struct pimsm_oif *pstImmediateOutIfList;
    struct pimsm_oif *pstInheritedOutIfList;

#if 0//test
    struct pimsm_oif *oif;
#endif

    if (NULL != g_group_hash)
    {
        //PIM_DEBUG("g_group_hash is not null.\n");
        hash_traversal_start(g_group_hash, pstGroupEntry);
        if(NULL != pstGroupEntry)
        {
            /* (*,G) */
            mrt_entry = pstGroupEntry->pstStarMrtLink;
            if (NULL != mrt_entry)
            {
                if (mrt_entry->valid)
                {
                    pstHardwareEntry = XMALLOC(MTYPE_PIM_OTHER, sizeof(struct pimsm_mrt_hardware_entry));
                    if (NULL == pstHardwareEntry)
                    {
                        continue;
                    }
                    memset(pstHardwareEntry, 0, sizeof(struct pimsm_mrt_hardware_entry));

                    pstImmediateOutIfList = pimsm_ImmediateOlist(mrt_entry, TRUE);
                    pstHardwareEntry->out_if = pstImmediateOutIfList;
                    pstHardwareEntry->grp_addr = mrt_entry->group->address;
                    pstHardwareEntry->in_ifindex = mrt_entry->upstream_if.ifindex;
                    pstHardwareEntry->type = PIMSM_MRT_TYPE_WC;
                    pstHardwareEntry->bIsCopyToCpu = pimsm_IsCopyToCpu(mrt_entry);//mrt_entry->bIsCopyToCpu;
                    pstHardwareEntry->byRpfCheck = mrt_entry->byRpfCheck;

                    pstHardwareEntry->next = pstHardwareNewList;
                    if (NULL != pstHardwareNewList)
                    {
                        pstHardwareNewList->prev = pstHardwareEntry;
                    }
                    pstHardwareEntry->prev = NULL;
                    pstHardwareNewList = pstHardwareEntry;
                }
            }

            /* All (S,G) (S,G,rpt) */
            mrt_entry = pstGroupEntry->pstSrcMrtLink;
            for (; NULL != mrt_entry; mrt_entry = mrt_entry->samegrpnext)
            {
                if (!mrt_entry->valid)
                    continue;

                if ((PIMSM_MRT_TYPE_SGRPT == mrt_entry->type) &&
                        (NULL != pimsm_SearchMrtEntry(&mrt_entry->source->address, &mrt_entry->group->address, PIMSM_MRT_TYPE_SG)))
                    continue;

                pstHardwareEntry = XMALLOC(MTYPE_PIM_OTHER, sizeof(struct pimsm_mrt_hardware_entry));
                if (NULL == pstHardwareEntry)
                    continue;

                memset(pstHardwareEntry, 0, sizeof(struct pimsm_mrt_hardware_entry));
                pstInheritedOutIfList = pimsm_InheritedOlist(mrt_entry, TRUE);

#if 0
                PIM_DEBUG("calc olist, (s,g)%s:%s.\n", pim_InetFmt(&mrt_entry->source->address), pim_InetFmt(&mrt_entry->group->address));
                oif = pstInheritedOutIfList;
                while(oif)
                {
                    PIM_DEBUG("oif->ifindex:%d.\n", oif->ifindex);
                    oif = oif->next;
                }
#endif

                pstHardwareEntry->out_if = pstInheritedOutIfList;
                pstHardwareEntry->src_addr = mrt_entry->source->address;
                pstHardwareEntry->grp_addr = mrt_entry->group->address;
                pstHardwareEntry->in_ifindex = mrt_entry->upstream_if.ifindex;
                pstHardwareEntry->type = PIMSM_MRT_TYPE_SG;//mrt_entry->type;
                pstHardwareEntry->bIsCopyToCpu = pimsm_IsCopyToCpu(mrt_entry);//mrt_entry->bIsCopyToCpu;
                pstHardwareEntry->byRpfCheck = mrt_entry->byRpfCheck;

                pstHardwareEntry->next = pstHardwareNewList;
                if (NULL != pstHardwareNewList)
                {
                    pstHardwareNewList->prev = pstHardwareEntry;
                }
                pstHardwareEntry->prev = NULL;
                pstHardwareNewList = pstHardwareEntry;
            }
        }
        hash_traversal_end();

        pimsm_HardwareTableCheck(pstHardwareNewList);
    }
    return VOS_OK;
}

#define rpf

#if 0
static int pimsm_RpfChanged(struct pimsm_rpf *pstOldRpf, struct pimsm_rpf *pstNewRpf)
{
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_grp_entry *pstGroupEntry;
    //struct pimsm_mrt_entry *mrt_entry;
    char acTempBuf1[200];
    char acTempBuf2[200];
    uint32_t bRes1;
    uint32_t bRes2;

    if ((NULL == pstOldRpf) || (NULL == pstNewRpf))
    {
        return VOS_ERROR;
    }

    memset(acTempBuf1, 0, sizeof(acTempBuf1));
    memset(acTempBuf2, 0, sizeof(acTempBuf2));

    bRes1 = pim_GetIntfNameFromLogicID(pstOldRpf->rpf_if, acTempBuf1);
    bRes2 = pim_GetIntfNameFromLogicID(pstNewRpf->rpf_if, acTempBuf2);

    if (bRes1 && bRes2)
    {
        printf("RpfChanged: ( Dst: %s, If: %s, Nbr: %s )  -->  ( Dst: %s, If: %s, Nbr: %s )\n",
               pim_InetFmt(&pstOldRpf->dest_addr), acTempBuf1, pim_InetFmt(&pstOldRpf->rpf_nbr_addr),
               pim_InetFmt(&pstNewRpf->dest_addr), acTempBuf2, pim_InetFmt(&pstNewRpf->rpf_nbr_addr));
    }
    else if(bRes1 && !bRes2)
    {
        printf("RpfChanged: ( Dst: %s, If: %s, Nbr: %s )  -->  ( Dst: %s, If: %d, Nbr: %s )\n",
               pim_InetFmt(&pstOldRpf->dest_addr), acTempBuf1, pim_InetFmt(&pstOldRpf->rpf_nbr_addr),
               pim_InetFmt(&pstNewRpf->dest_addr), pstNewRpf->rpf_if, pim_InetFmt(&pstNewRpf->rpf_nbr_addr));
    }
    else if(!bRes1 && bRes2)
    {
        printf("RpfChanged: ( Dst: %s, If: %d, Nbr: %s )  -->  ( Dst: %s, If: %s, Nbr: %s )\n",
               pim_InetFmt(&pstOldRpf->dest_addr), pstOldRpf->rpf_if, pim_InetFmt(&pstOldRpf->rpf_nbr_addr),
               pim_InetFmt(&pstNewRpf->dest_addr), acTempBuf2, pim_InetFmt(&pstNewRpf->rpf_nbr_addr));
    }
    else
    {
        printf("RpfChanged: ( Dst: %s, If: %d, Nbr: %s )  -->  ( Dst: %s, If: %d, Nbr: %s )\n",
               pim_InetFmt(&pstOldRpf->dest_addr), pstOldRpf->rpf_if, pim_InetFmt(&pstOldRpf->rpf_nbr_addr),
               pim_InetFmt(&pstNewRpf->dest_addr), pstNewRpf->rpf_if, pim_InetFmt(&pstNewRpf->rpf_nbr_addr));
    }

    if (g_group_hash)
    {
        hash_traversal_start(g_group_hash, pstGroupEntry);
        if(NULL != pstGroupEntry)
        {
            /* update (*,G) */
            if (0 == ip_AddressCompare(&pstGroupEntry->rp_addr, &pstOldRpf->dest_addr))
            {
                start_grp_entry = pstGroupEntry->pstStarMrtLink;
                if (start_grp_entry)
                {
                    /* rpf to rp changed */
                    start_grp_entry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    start_grp_entry->upstream_if.up_stream_nbr = pstNewRpf->rpf_nbr_addr;
                    pimsm_CheckMrtEntryValid(start_grp_entry);
                }
            }

            src_grp_entry = pstGroupEntry->pstSrcMrtLink;
            while(src_grp_entry)
            {
                /* update (S,G) */
                if ((0 == ip_AddressCompare(&src_grp_entry->source->address, &pstOldRpf->dest_addr)) &&
                        (PIMSM_MRT_TYPE_SG == src_grp_entry->type))
                {
                    /* rpf to source changed */
                    src_grp_entry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    src_grp_entry->upstream_if.up_stream_nbr = pstNewRpf->rpf_nbr_addr;
                }
                /* update (S,G,rpt) */
                else if ((0 == ip_AddressCompare(&src_grp_entry->group->rp_addr, &pstOldRpf->dest_addr)) &&
                         (PIMSM_MRT_TYPE_SGRPT == src_grp_entry->type))
                {
                    /* rpf to rp changed */
                    src_grp_entry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    src_grp_entry->upstream_if.up_stream_nbr = pstNewRpf->rpf_nbr_addr;
                }
                pimsm_CheckMrtEntryValid(src_grp_entry);
                src_grp_entry = src_grp_entry->samegrpnext;
            }
        }
        hash_traversal_end();
    }

    return VOS_OK;
}
#endif
#if 1
static int pimsm_RpfChanged(struct pimsm_rpf *pstOldRpf, struct pimsm_rpf *pstNewRpf)
{
    struct pimsm_updown_state_machine_event_para stUpEventPara;

    struct pimsm_mrt_entry *pstStarGrpEntry = NULL;
    struct pimsm_mrt_entry *pstSrcGrpEntry = NULL;
    struct pimsm_mrt_entry *pstSrcGrpNextEntry = NULL;
    struct pimsm_grp_entry *pstGroupEntry = NULL;
    struct pimsm_assert_metric stMyMetric;
    struct pimsm_assert_if *pstAssertIfNext;
    struct pimsm_assert_if *pstAssertIfTmp1;
    struct pimsm_assert_if *pstAssertIfTmp2;
    struct pimsm_assert_if *pimsmassert_if;
    VOS_IP_ADDR stNewUpNbrAddr;
    VOS_IP_ADDR stOldUpNbrAddr;
    VOS_IP_ADDR stUpNbrAddr;
    int dwNewUpIf;
    int dwOldUpIf;

    if ((NULL == pstOldRpf) || (NULL == pstNewRpf))
    {
        return VOS_ERROR;
    }

    memset(&stNewUpNbrAddr, 0, sizeof(VOS_IP_ADDR));
    memset(&stOldUpNbrAddr, 0, sizeof(VOS_IP_ADDR));

    PIM_DEBUG("RpfChanged: ( DestAddr: %s, Interface: %s, NextHop: %s )  -->  ( DestAddr: %s, Interface: %s, NextHop: %s )\n",
              pim_InetFmt(&pstOldRpf->dest_addr), pimsm_GetIfName(pstOldRpf->rpf_if), pim_InetFmt(&pstOldRpf->rpf_nbr_addr),
              pim_InetFmt(&pstNewRpf->dest_addr), pimsm_GetIfName(pstNewRpf->rpf_if), pim_InetFmt(&pstNewRpf->rpf_nbr_addr));

    if (g_group_hash)
    {
        hash_traversal_start(g_group_hash, pstGroupEntry);
        if(NULL != pstGroupEntry)
        {
            /* update (*,G) */
            if (0 == ip_AddressCompare(&pstGroupEntry->rp_addr, &pstOldRpf->dest_addr))
            {
                PIM_DEBUG("update (*,G).\n");

                pstStarGrpEntry = pstGroupEntry->pstStarMrtLink;
                if (NULL != pstStarGrpEntry)
                {
                    dwOldUpIf = pstStarGrpEntry->upstream_if.ifindex;
                    dwNewUpIf = pstNewRpf->rpf_if;

                    memcpy(&stOldUpNbrAddr, &pstStarGrpEntry->upstream_if.up_stream_nbr, sizeof(VOS_IP_ADDR));
                    pimsm_RpfNeighborAddr(pstStarGrpEntry, &stNewUpNbrAddr);

                    pstStarGrpEntry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    memcpy(&pstStarGrpEntry->upstream_if.up_stream_nbr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                    pstStarGrpEntry->preference = pstNewRpf->preference;
                    pstStarGrpEntry->metric = pstNewRpf->metric;

                    if (0 != ip_AddressCompare(&stOldUpNbrAddr, &stNewUpNbrAddr))
                    {
                        memcpy(&stUpEventPara.old_upstream_nbr_addr, &stOldUpNbrAddr, sizeof(VOS_IP_ADDR));
                        memcpy(&stUpEventPara.new_upstream_nbr_addr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                        pimsm_UpstreamStateMachineEventProc(pstStarGrpEntry, PimsmRpfaStarGrpChangesNotAssertEvent, &stUpEventPara);
                    }

                    if ((NULL != pimsm_SearchAssertIfByIndex(pstStarGrpEntry->pimsmassert_if, pstNewRpf->rpf_if)) &&
                            !pimsm_CouldAssert(pstStarGrpEntry, pstNewRpf->rpf_if))
                    {
                        pimsm_AssertStateMachineEventProc(pstStarGrpEntry, pstNewRpf->rpf_if, PimsmAssertEvent_16, NULL);
                    }

                    pimsmassert_if = pstStarGrpEntry->pimsmassert_if;
                    while(NULL != pimsmassert_if)
                    {
                        pstAssertIfNext = pimsmassert_if->next;

                        stMyMetric = pimsm_MyAssertMetric(pstStarGrpEntry, pimsmassert_if->ifindex);
                        if (0 < pimsm_MetricCompare(&stMyMetric, &pimsmassert_if->stAssertStateMachine.stAssertWinner))
                        {
                            pimsm_AssertStateMachineEventProc(pstStarGrpEntry, pimsmassert_if->ifindex, PimsmAssertEvent_24, NULL);
                        }

                        pimsmassert_if = pstAssertIfNext;
                    }

                    pstAssertIfTmp1 = pimsm_SearchAssertIfByIndex(pstStarGrpEntry->pimsmassert_if, dwOldUpIf);
                    pstAssertIfTmp2 = pimsm_SearchAssertIfByIndex(pstStarGrpEntry->pimsmassert_if, dwNewUpIf);
                    if (NULL != pstAssertIfTmp1)
                    {
                        if ((NULL == pstAssertIfTmp2) || (dwOldUpIf != dwNewUpIf))
                        {
                            pimsm_AssertStateMachineEventProc(pstStarGrpEntry, pstAssertIfTmp1->ifindex, PimsmAssertEvent_26, NULL);
                        }
                    }

                    pimsm_CheckMrtEntryValid(pstStarGrpEntry);
                }

            }

            pstSrcGrpEntry = pstGroupEntry->pstSrcMrtLink;
            while(pstSrcGrpEntry)
            {
                pstSrcGrpNextEntry = pstSrcGrpEntry->samegrpnext;

                /* update (S,G) */
                if ((0 == ip_AddressCompare(&pstSrcGrpEntry->source->address, &pstOldRpf->dest_addr)) &&
                        (PIMSM_MRT_TYPE_SG == pstSrcGrpEntry->type))
                {

                    PIM_DEBUG("update (S,G), oldupif:%d, newupif:%d.\n", pstSrcGrpEntry->upstream_if.ifindex, pstNewRpf->rpf_if);
                    dwOldUpIf = pstSrcGrpEntry->upstream_if.ifindex;
                    dwNewUpIf = pstNewRpf->rpf_if;

                    memcpy(&stOldUpNbrAddr, &pstSrcGrpEntry->upstream_if.up_stream_nbr, sizeof(VOS_IP_ADDR));
                    pimsm_RpfNeighborAddr(pstSrcGrpEntry, &stNewUpNbrAddr);

                    pstSrcGrpEntry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    memcpy(&pstSrcGrpEntry->upstream_if.up_stream_nbr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                    pstSrcGrpEntry->preference = pstNewRpf->preference;
                    pstSrcGrpEntry->metric = pstNewRpf->metric;

                    if (0 != ip_AddressCompare(&stOldUpNbrAddr, &stNewUpNbrAddr))
                    {
                        memcpy(&stUpEventPara.old_upstream_nbr_addr, &stOldUpNbrAddr, sizeof(VOS_IP_ADDR));
                        memcpy(&stUpEventPara.new_upstream_nbr_addr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                        pimsm_UpstreamStateMachineEventProc(pstSrcGrpEntry, PimsmRpfaSrcGrpChangesNotAssertEvent, &stUpEventPara);
                    }

                    if ((NULL != pimsm_SearchAssertIfByIndex(pstSrcGrpEntry->pimsmassert_if, pstNewRpf->rpf_if)) &&
                            !pimsm_CouldAssert(pstSrcGrpEntry, pstNewRpf->rpf_if))
                    {
                        pimsm_AssertStateMachineEventProc(pstSrcGrpEntry, pstNewRpf->rpf_if, PimsmAssertEvent_15, NULL);
                    }

                    pimsmassert_if = pstSrcGrpEntry->pimsmassert_if;
                    while(NULL != pimsmassert_if)
                    {
                        pstAssertIfNext = pimsmassert_if->next;

                        stMyMetric = pimsm_MyAssertMetric(pstSrcGrpEntry, pimsmassert_if->ifindex);
                        if (0 < pimsm_MetricCompare(&stMyMetric, &pimsmassert_if->stAssertStateMachine.stAssertWinner))
                        {
                            pimsm_AssertStateMachineEventProc(pstSrcGrpEntry, pimsmassert_if->ifindex, PimsmAssertEvent_24, NULL);
                        }

                        pimsmassert_if = pstAssertIfNext;
                    }

                    pstAssertIfTmp1 = pimsm_SearchAssertIfByIndex(pstSrcGrpEntry->pimsmassert_if, dwOldUpIf);
                    pstAssertIfTmp2 = pimsm_SearchAssertIfByIndex(pstSrcGrpEntry->pimsmassert_if, dwNewUpIf);
                    if (NULL != pstAssertIfTmp1)
                    {
                        if ((NULL == pstAssertIfTmp2) || (dwOldUpIf != dwNewUpIf))
                        {
                            pimsm_AssertStateMachineEventProc(pstSrcGrpEntry, pstAssertIfTmp1->ifindex, PimsmAssertEvent_25, NULL);
                        }
                    }

                }
                /* update (S,G,rpt) */
                else if ((0 == ip_AddressCompare(&pstSrcGrpEntry->group->rp_addr, &pstOldRpf->dest_addr)) &&
                         (PIMSM_MRT_TYPE_SGRPT == pstSrcGrpEntry->type))
                {
                    memcpy(&stOldUpNbrAddr, &pstSrcGrpEntry->upstream_if.up_stream_nbr, sizeof(VOS_IP_ADDR));
                    pimsm_RpfNeighborAddr(pstSrcGrpEntry, &stNewUpNbrAddr);

                    pstSrcGrpEntry->upstream_if.ifindex = pstNewRpf->rpf_if;
                    memcpy(&pstSrcGrpEntry->upstream_if.up_stream_nbr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                    pstSrcGrpEntry->preference = pstNewRpf->preference;
                    pstSrcGrpEntry->metric = pstNewRpf->metric;

                    if ((0 != ip_AddressCompare(&stOldUpNbrAddr, &stUpNbrAddr)) &&
                            (0 == ip_AddressCompare(&stNewUpNbrAddr, &stUpNbrAddr)))/* RPF'(S,G,rpt) -> RPF'(*,G) */
                    {
                        memcpy(&stUpEventPara.old_upstream_nbr_addr, &stOldUpNbrAddr, sizeof(VOS_IP_ADDR));
                        memcpy(&stUpEventPara.new_upstream_nbr_addr, &stNewUpNbrAddr, sizeof(VOS_IP_ADDR));
                        pimsm_UpstreamStateMachineEventProc(pstSrcGrpEntry, PimsmRpfaSrcGrpRptToRpfaStarGrpEvent, &stUpEventPara);
                    }

                }
                pimsm_CheckMrtEntryValid(pstSrcGrpEntry);

                pstSrcGrpEntry = pstSrcGrpNextEntry;
            }
        }
        hash_traversal_end();
    }

    return VOS_OK;
}
#endif

int pimsm_UpdateRpf(struct rtmgt_to_pimsm *pstNewRpfMsg)
{
    struct pimsm_rpf *pstRpfCurr;
    struct pimsm_rpf stNewRpf;
    struct pimsm_rpf stOldRpf;

    zassert(NULL != pstNewRpfMsg);

    memcpy(&stNewRpf.dest_addr, &(pstNewRpfMsg->source), sizeof(VOS_IP_ADDR));
    memcpy(&stNewRpf.rpf_nbr_addr, &(pstNewRpfMsg->rpf_nbr_addr), sizeof(VOS_IP_ADDR));
    stNewRpf.rpf_if = pstNewRpfMsg->iif;
    stNewRpf.preference = pstNewRpfMsg->preference;
    stNewRpf.metric = pstNewRpfMsg->metric;

#if 1
    PIM_DEBUG("source:%s, rpf_nbr_addr:%s, iif:%d.\n", pim_InetFmt(&stNewRpf.dest_addr), pim_InetFmt(&stNewRpf.rpf_nbr_addr), stNewRpf.rpf_if);
#endif

    pstRpfCurr = g_rpf_list;
    while (NULL != pstRpfCurr)
    {
        //if (0 == ip_AddressCompare(&(pstRpfCurr->dest_addr), &stNewRpf.dest_addr))
        PIM_DEBUG("in list dst_addr:%s, new dst_addr:%s, prefixlen:%d.\n", pim_InetFmt(&pstRpfCurr->dest_addr), pim_InetFmt(&stNewRpf.dest_addr), pstNewRpfMsg->prefixlen);
        if (pim_MatchPrefix(&pstRpfCurr->dest_addr, &stNewRpf.dest_addr, pstNewRpfMsg->prefixlen))
        {
            PIM_DEBUG("enter here, rpf_if:%d.\n", stNewRpf.rpf_if);
            //sangmeng change
            stNewRpf.dest_addr.u32_addr[0] = pstRpfCurr->dest_addr.u32_addr[0]; //192.168.1.0----->192.168.1.2

            if((NULL == pimsm_SearchInterface(stNewRpf.rpf_if)) &&
                    (MRTMGT_RPF_CTL_INVALID_INTF != stNewRpf.rpf_if))
            {
                PIM_DEBUG("return error.\n");
                return VOS_ERROR;
            }

            memcpy(&stOldRpf, pstRpfCurr, sizeof(struct pimsm_rpf));
            memcpy(&pstRpfCurr->rpf_nbr_addr, &stNewRpf.rpf_nbr_addr, sizeof(VOS_IP_ADDR));
            pstRpfCurr->rpf_if = stNewRpf.rpf_if;
            pstRpfCurr->preference = stNewRpf.preference;
            pstRpfCurr->metric = stNewRpf.metric;

            PIM_DEBUG("old rpf_if:%d, rpf_if:%d.\n", stOldRpf.rpf_if, stNewRpf.rpf_if);
            PIM_DEBUG("old nbr:%s, new nbr:%s.\n", pim_InetFmt(&stOldRpf.rpf_nbr_addr), pim_InetFmt(&stNewRpf.rpf_nbr_addr));

            if((stOldRpf.rpf_if != stNewRpf.rpf_if) ||
                    (stOldRpf.rpf_nbr_addr.u32_addr[0] != stNewRpf.rpf_nbr_addr.u32_addr[0]))
            {
                PIM_DEBUG("will call pimsm_RpfChanged.\n");
                pimsm_RpfChanged(&stOldRpf, &stNewRpf);
            }
        }

        pstRpfCurr = pstRpfCurr->next;
    }

    return VOS_OK;
}
static struct pimsm_rpf *pimsm_CreateRpfEntry(VOS_IP_ADDR *pstDstAddr)
{
    struct pimsm_rpf *pstRpf = NULL;

    if(NULL == pstDstAddr)
    {
        return NULL;
    }

    pstRpf = XMALLOC(MTYPE_PIM_RPF, sizeof(struct pimsm_rpf));
    if (NULL == pstRpf)
    {
        return NULL;
    }
    memset(pstRpf, 0x00, sizeof(struct pimsm_rpf));

    pstRpf->prev = NULL;
    pstRpf->next = g_rpf_list;
    if(NULL != g_rpf_list)
    {
        g_rpf_list->prev = pstRpf;
    }
    g_rpf_list = pstRpf;
    memcpy(&(pstRpf->dest_addr), pstDstAddr, sizeof(VOS_IP_ADDR));

    PIM_DEBUG(" create rpf rpf_addr:%s\n", pim_InetFmt(&pstRpf->dest_addr));
    return pstRpf;
}

struct pimsm_rpf *pimsm_SearchRpf(VOS_IP_ADDR *pstDstAddr)
{
    struct pimsm_rpf *pstRpf = NULL;
    if (NULL == pstDstAddr)
    {
        return NULL;
    }

    pstRpf = g_rpf_list;
    while (NULL != pstRpf)
    {
        if (0 == ip_AddressCompare(&(pstRpf->dest_addr), pstDstAddr))
        {
            return pstRpf;
        }

        pstRpf = pstRpf->next;
    }

    PIM_DEBUG(" pstDstAddr:%s.\n", pim_InetFmt(pstDstAddr));
    return pimsm_CreatRpfChangeRegister(pstDstAddr);
}

uint32_t pimsm_RpfInterface(VOS_IP_ADDR *pstDstAddr)
{
    struct pimsm_rpf *pstRpf = NULL;

    zassert(NULL != pstDstAddr);

    pstRpf = pimsm_SearchRpf(pstDstAddr);
    if(NULL != pstRpf)
    {
        return pstRpf->rpf_if;
    }

    return VOS_ERROR;
}

int pimsm_RpfNeighborAddr(struct pimsm_mrt_entry *mrt_entry, VOS_IP_ADDR *pstNeighborAddr)
{
    struct pimsm_interface_entry *pstInterface;
    struct pimsm_neighbor_entry *pstRpfNbr;
    VOS_IP_ADDR neighbor_addr;
    VOS_IP_ADDR stAssertWinner;
    struct pimsm_rpf *pstRpfToSrc;
    struct pimsm_rpf *pstRpfToRp = NULL;

    zassert(NULL != mrt_entry);
    zassert(NULL != pstNeighborAddr);

    memset(pstNeighborAddr, 0, sizeof(VOS_IP_ADDR));

    if(PIMSM_MRT_TYPE_WC == mrt_entry->type)
    {
        /*
        neighbor RPF'(*,G){
        	if(I_Am_Assert_Loser(*,G,RPF_interface(RP(G)))){
        		return AssertWinner(*,G,RPF_interface(RP(G)));
        	} else {
        		return NBR(RPF_interface(RP(G)), MRIB.next_hop(RP(G)));
        	}
        }
        */
        pstRpfToRp = pimsm_SearchRpf(&mrt_entry->group->rp_addr);
        if (pstRpfToRp == NULL)
        {
            PIM_DEBUG("search rpf return null.\n");
            return VOS_ERROR;
        }
        if(pimsm_InterfaceLostAssert(mrt_entry, pstRpfToRp->rpf_if))
        {
            pimsm_InterfaceAssertWinner(mrt_entry, pstRpfToRp->rpf_if, &stAssertWinner);
            memcpy(pstNeighborAddr, &stAssertWinner, sizeof(VOS_IP_ADDR));
        }
        else
        {
            if (NULL != (pstInterface = pimsm_SearchInterface(pstRpfToRp->rpf_if)))
            {
                if ((NULL != pstInterface->pimsm_neigh) && (!pimsm_IamRP(&mrt_entry->group->address)))
                {
                    memcpy(pstNeighborAddr, &pstInterface->pimsm_neigh->source_addr, sizeof(VOS_IP_ADDR));
                }
            }
        }
    }
    else if(PIMSM_MRT_TYPE_SG == mrt_entry->type)
    {
        /*
        neighbor RPF'(S,G){
        	if(I_Am_Assert_Loser(S,G,RPF_interface(S))){
        		return AssertWinner(S,G,RPF_interface(S));
        	} else {
        		return NBR(RPF_interface(S), MRIB.next_hop(S));
        	}
        }
        */
        pstRpfToSrc = pimsm_SearchRpf(&mrt_entry->source->address);
        if (pstRpfToSrc == NULL)
        {
            PIM_DEBUG("search rpf return null.\n");
            return VOS_ERROR;
        }
        if(pimsm_InterfaceLostAssert(mrt_entry, pstRpfToSrc->rpf_if))
        {
            pimsm_InterfaceAssertWinner(mrt_entry, pstRpfToSrc->rpf_if, &stAssertWinner);
            memcpy(pstNeighborAddr, &stAssertWinner, sizeof(VOS_IP_ADDR));
        }
        else
        {
            if (NULL != (pstInterface = pimsm_SearchInterface(pstRpfToSrc->rpf_if)))
            {
                pstRpfNbr = pstInterface->pimsm_neigh;
                while(pstRpfNbr)
                {
                    if (0 == ip_AddressCompare(&pstRpfNbr->source_addr, &pstRpfToSrc->rpf_nbr_addr))
                    {
                        memcpy(pstNeighborAddr, &pstRpfNbr->source_addr, sizeof(VOS_IP_ADDR));
                        break;
                    }
                    pstRpfNbr = pstRpfNbr->next;
                }
            }
        }
    }
    else if(PIMSM_MRT_TYPE_SGRPT == mrt_entry->type)
    {
        /*
        neighbor RPF'(S,G,rpt){
        	if(I_Am_Assert_Loser(S,G,RPF_interface(RP(G)))){
        		return AssertWinner(*,G,RPF_interface(RP(G)));
        	} else {
        		return RPF'(*,G);
        	}
        }
        */
        pstRpfToRp = pimsm_SearchRpf(&mrt_entry->group->rp_addr);
        if (pstRpfToRp == NULL)
        {
            PIM_DEBUG("search rpf return null.\n");
            return VOS_ERROR;
        }
        if(pimsm_InterfaceLostAssert(mrt_entry, pstRpfToRp->rpf_if))
        {
            pimsm_InterfaceAssertWinner(mrt_entry, pstRpfToRp->rpf_if, &stAssertWinner);
            memcpy(pstNeighborAddr, &stAssertWinner, sizeof(VOS_IP_ADDR));
        }
        else
        {
            if (NULL != mrt_entry->group->pstStarMrtLink)
            {
                pimsm_RpfNeighborAddr(mrt_entry->group->pstStarMrtLink, &neighbor_addr);
                memcpy(pstNeighborAddr, &neighbor_addr, sizeof(VOS_IP_ADDR));
            }
        }
    }
    else
    {
        return VOS_ERROR;
    }

    return VOS_OK;
}

#define show
#if 0
int pimsm_ShowRpf(struct vty *vty,VOS_IP_ADDR *pstRpfDestAddr)
{
    char sIf[PIMSM_IF_NAME_MAX_LEN];
    char sNexthop[SS_ADDR_LENTH];
    char print_buf[SS_DEB_lENTH];
    char sDest[SS_ADDR_LENTH];
    struct pimsm_rpf_entry *pstRpf = NULL;

    if (NULL == pstRpfDestAddr)
        return VOS_ERROR;

    memset(sDest, 0x00, SS_ADDR_LENTH);
    memset(print_buf, 0x00, SS_DEB_lENTH);
    memset(sNexthop,0x00, SS_ADDR_LENTH);
    memset(sIf, 0x00, PIMSM_IF_NAME_MAX_LEN);

    ip_printAddress(pstRpfDestAddr, sDest, sizeof(sDest));
    vty_out(vty, "IP PIM-SM RPF:\n");

    //pstRpf = g_stPimsm.pstRpfList;
    pstRpf = g_rpf_list;

    if (NULL == pstRpf)
    {
        vty_out(vty, "        Destination(%s) RPF no find!\n", sDest);
        return VOS_OK;
    }

    while (NULL != pstRpf)
    {
        if (0 == ip_AddressCompare(pstRpfDestAddr, &pstRpf->stDest))
        {
            //len += sprintf(print_buf + len, "        Destination: %s\n", sDest);
            vty_out(vty, "        Destination: %s\n", sDest);
            ip_printAddress(&pstRpf->stRpfNbr, sNexthop, sizeof(sNexthop));
            pim_GetIntfNameFromLogicID(pstRpf->rpf_if, sIf);
            //len += sprintf(print_buf + len, "        RpfNeighbor: %s, %s\n", sNexthop, sIf);
            vty_out(vty, "        RpfNeighbor: %s, %s(%d)\n", sNexthop, sIf,pstRpf->rpf_if);
            //len += sprintf(print_buf + len, "        Preference: %u, Metric: %u\n", pstRpf->preference, pstRpf->metric);
            vty_out(vty, "        Preference: %u, Metric: %u\n", pstRpf->preference, pstRpf->metric);
            //pimsm_ToCliPrint(print_buf);
            return VOS_OK;
        }
        pstRpf = pstRpf->next;
    }

    //len += sprintf(print_buf + len, "        Destination(%s) RPF no find!\n", sDest);
    vty_out(vty, "        Destination(%s) RPF no find!\n", sDest);
    //pimsm_ToCliPrint(print_buf);

    return VOS_OK;
}
#endif
int pimsm_ShowRpf(struct vty *vty,VOS_IP_ADDR *pstRpfDestAddr)
{

    char sIf[PIMSM_IF_NAME_MAX_LEN];
    char sNexthop[SS_ADDR_LENTH];
    char print_buf[SS_DEB_lENTH];
    char sDest[SS_ADDR_LENTH];
    struct pimsm_rpf *pstRpf = NULL;

    if (NULL == pstRpfDestAddr)
        return VOS_ERROR;

    memset(sDest, 0x00, SS_ADDR_LENTH);
    memset(print_buf, 0x00, SS_DEB_lENTH);
    memset(sNexthop,0x00, SS_ADDR_LENTH);
    memset(sIf, 0x00, PIMSM_IF_NAME_MAX_LEN);

    ip_printAddress(pstRpfDestAddr, sDest, sizeof(sDest));
    vty_out(vty, "IP PIM-SM RPF:\n");

    //pstRpf = g_stPimsm.pstRpfList;
    pstRpf = g_rpf_list;
    if (NULL == pstRpf)
    {
        vty_out(vty, "        Destination(%s) RPF no find!\n", sDest);
        return VOS_OK;
    }

    while (NULL != pstRpf)
    {
        if (0 == ip_AddressCompare(pstRpfDestAddr, &pstRpf->dest_addr))
        {
            //len += sprintf(print_buf + len, "        Destination: %s\n", sDest);
            vty_out(vty, "        Destination: %s\n", sDest);
            ip_printAddress(&pstRpf->rpf_nbr_addr, sNexthop, sizeof(sNexthop));
            pim_GetIntfNameFromLogicID(pstRpf->rpf_if, sIf);
            //len += sprintf(print_buf + len, "        RpfNeighbor: %s, %s\n", sNexthop, sIf);
            vty_out(vty, "        RpfNeighbor: %s, %s(%d)\n", sNexthop, sIf,pstRpf->rpf_if);
            //len += sprintf(print_buf + len, "        Preference: %u, Metric: %u\n", pstRpf->preference, pstRpf->metric);
            vty_out(vty, "        Preference: %u, Metric: %u\n", pstRpf->preference, pstRpf->metric);
            //pimsm_ToCliPrint(print_buf);
            return VOS_OK;
        }
        pstRpf = pstRpf->next;
    }

    //len += sprintf(print_buf + len, "        Destination(%s) RPF no find!\n", sDest);
    vty_out(vty, "        Destination(%s) RPF no find!\n", sDest);
    //pimsm_ToCliPrint(print_buf);

    return VOS_OK;


}

/* show pim topology table */
int pimsm_ShowTopology(struct vty *vty)
{
    struct pimsm_grp_entry *pstGroupEntry;
    struct pimsm_mrt_entry *start_grp_entry;
    struct pimsm_mrt_entry *src_grp_entry;
    struct pimsm_updownstream_if_entry *pstDownIf;
    struct pimsm_interface_entry *pstIf;
    struct pimsm_assert_if *pimsmassert_if;
    struct pimsm_oif *pstImmediateOil;
    struct pimsm_oif *pstInheritedOil;
    struct pimsm_oif *pstJoinsOil;
    struct pimsm_oif *pstOif_1;
    struct pimsm_oif *pstOif_2;
    char grp_addr_str[200];
    char src_addr_str[200];
    char addr_str[200];
    char *print_buf;
    int len = 0;
    time_t            now;
    char uptime[10];

    print_buf = (char *)XMALLOC(MTYPE_BUFFER, PIM_MAX_SHOWSIZE);
    if(NULL == print_buf)
    {
        return VOS_ERROR;
    }

    now = pim_time_monotonic_sec();
    memset(print_buf, 0, PIM_MAX_SHOWSIZE);
    memset(uptime, 0, sizeof(uptime));

    len += sprintf(print_buf + len, "IP PIM Multicast Topology Table\n");
    len += sprintf(print_buf + len, "Entry state:(*/S,G)[RPT/SPT] Protocol Uptime Info\n");
    len += sprintf(print_buf + len, "Interface state:Name, Uptime, Fwd, Info\n");
    len += sprintf(print_buf + len, "Interface flags:LI - Local Interest, LD - Local Disinterest,\n");
    len += sprintf(print_buf + len, "ASW - Assert Winner, ASL - Assert Loser\n");

    if(NULL == g_group_hash)
    {
        //pimsm_ToCliPrint(&pstCliMsgToPimsm->subclihead, print_buf, len);
        vty_out(vty,"%s\n",print_buf);
        return VOS_OK;
    }

    hash_traversal_start(g_group_hash, pstGroupEntry);
    if(NULL != pstGroupEntry)
    {
        //(*,G)
        start_grp_entry = pstGroupEntry->pstStarMrtLink;
        if (NULL != start_grp_entry)
        {
            memset(addr_str, 0, sizeof(addr_str));
            ip_printAddress(&(start_grp_entry->group->address), addr_str, sizeof(addr_str));
            len += sprintf(print_buf + len, "\n(*,%s)\n", addr_str);
            pim_time_uptime(uptime, sizeof(uptime), now - start_grp_entry->creation);
            len += sprintf(print_buf + len, "UP TIME : %s ", uptime);
            if(pimsm_LocalReceiverExist(start_grp_entry))
            {
                len += sprintf(print_buf + len, "flags : LI\n");
            }
            else
            {
                len += sprintf(print_buf + len, "flags : LD\n");
            }
            memset(addr_str, 0, sizeof(addr_str));
            ip_printAddress(&(pstGroupEntry->rp_addr), addr_str, sizeof(addr_str));
            len += sprintf(print_buf + len, "RP ADDRESS : %s\n", addr_str);
            len += sprintf(print_buf + len, "METRIC PREF  : %u\n", start_grp_entry->preference);
            len += sprintf(print_buf + len, "METRIC       : %u\n", start_grp_entry->metric);
            memset(addr_str, 0, sizeof(addr_str));
            ip_printAddress(&(start_grp_entry->upstream_if.up_stream_nbr), addr_str, sizeof(addr_str));
            len += sprintf(print_buf + len, "UPSTREAM NBR : %s\n", addr_str);
            //先处理入接口,此处要考虑到自己为rp时没有入接口的特殊情况
            if(0 != start_grp_entry->upstream_if.ifindex)
            {
                pstIf = pimsm_SearchInterface(start_grp_entry->upstream_if.ifindex);
                if(pstIf == NULL)
                {
                    len += sprintf(print_buf + len, "RPF interface no find\n");
                }
                else
                {
                    memset(addr_str, 0, sizeof(addr_str));
                    ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                    len += sprintf(print_buf + len, "RPF Interface : %s Linklocal address : %s ", pimsm_GetIfName(pstIf->ifindex), addr_str);

                    pimsmassert_if = pimsm_SearchAssertIfByIndex(start_grp_entry->pimsmassert_if, pstIf->ifindex);
                    if (NULL != pimsmassert_if)
                    {
                        if (PimsmAssertStateWinner == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASW\n");
                        }
                        else if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASL\n");
                            memset(addr_str, 0, sizeof(addr_str));
                            ip_printAddress(&(pimsmassert_if->stAssertStateMachine.stAssertWinner.address), addr_str, sizeof(addr_str));
                            len += sprintf(print_buf + len, "  Current Assert Winner is %s\n", addr_str);
                            len += sprintf(print_buf + len, "  The Winner's RPT-bit is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.byRptBit);
                            len += sprintf(print_buf + len, "  The Winner's metric pref is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwMetricPref);
                            len += sprintf(print_buf + len, "  The Winner's metric is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwRouteMetric);
                        }
                        else
                        {
                            len += sprintf(print_buf + len, "\n");
                        }
                    }
                    else
                    {
                        len += sprintf(print_buf + len, "\n");
                    }
                }
            }
            else
            {
                len += sprintf(print_buf + len, "RPF Interface : NULL\n");
            }

            //再循环处理出接口
            pstImmediateOil = pimsm_ImmediateOlist(start_grp_entry, TRUE);
            pstJoinsOil = pimsm_Joins(start_grp_entry, TRUE);
            pstOif_1 = pstImmediateOil;
            while(pstOif_1 != NULL)
            {
                pstIf = pimsm_SearchInterface(pstOif_1->ifindex);
                if(pstIf == NULL)
                {
                    len += sprintf(print_buf + len, "Output interface no find\n");
                }
                else
                {
                    memset(addr_str, 0, sizeof(addr_str));
                    ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                    len += sprintf(print_buf + len, "Output Interface : %s Linklocal address : %s", pimsm_GetIfName(pstOif_1->ifindex), addr_str);
                    pimsmassert_if = pimsm_SearchAssertIfByIndex(start_grp_entry->pimsmassert_if, pstOif_1->ifindex);
                    if (NULL != pimsmassert_if)
                    {
                        if (PimsmAssertStateWinner == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASW");
                        }
                        else if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASL");
                            len += sprintf(print_buf + len, " ERROR : a assert loser present in the OIL\n");
                        }
                    }

                    pstOif_2 = pimsm_SearchOifByIndex(pstJoinsOil, pstOif_1->ifindex);
                    if(pstOif_2 != NULL)
                    {
                        pstDownIf = pimsm_SearchDownstreamIfByIndex(start_grp_entry->downstream_if, pstOif_2->ifindex);
                        if (NULL != pstDownIf)
                        {
                            if(pstDownIf->down_stream_state_mchine.t_pimsm_expiry_timer)
                            {

                                len += sprintf(print_buf + len, "  LIVE TIME : %ld s", thread_timer_remain_second(pstDownIf->down_stream_state_mchine.t_pimsm_expiry_timer));
                            }
                        }
                    }
                    len += sprintf(print_buf + len, "\n");
                }

                pstOif_1 = pstOif_1->next;
            }

            pimsmassert_if = start_grp_entry->pimsmassert_if;
            while((pimsmassert_if != NULL) && (NULL != pimsm_SearchOifByIndex(pstImmediateOil, pimsmassert_if->ifindex)))
            {
                if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                {
                    pstIf = pimsm_SearchInterface(pimsmassert_if->ifindex);
                    if(pstIf == NULL)
                    {
                        len += sprintf(print_buf + len, "Output interface no find\n");
                    }
                    else
                    {
                        memset(addr_str, 0, sizeof(addr_str));
                        ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                        len += sprintf(print_buf + len, "Output Interface : %s Linklocal address : %s", pimsm_GetIfName(pstIf->ifindex), addr_str);
                        len += sprintf(print_buf + len, " ASL\n");
                        memset(addr_str, 0, sizeof(addr_str));
                        ip_printAddress(&(pimsmassert_if->stAssertStateMachine.stAssertWinner.address), addr_str, sizeof(addr_str));
                        len += sprintf(print_buf + len, "  Current Assert Winner is %s\n", addr_str);
                        len += sprintf(print_buf + len, "  The Winner's RPT-bit is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.byRptBit);
                        len += sprintf(print_buf + len, "  The Winner's metric pref is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwMetricPref);
                        len += sprintf(print_buf + len, "  The Winner's metric is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwRouteMetric);
                    }
                }

                pimsmassert_if = pimsmassert_if->next;
            }

            pimsm_FreeOil(pstImmediateOil);
            pimsm_FreeOil(pstJoinsOil);
        }

        //(S,G)
        src_grp_entry = pstGroupEntry->pstSrcMrtLink;
        while (NULL != src_grp_entry)
        {
            memset(src_addr_str, 0, sizeof(src_addr_str));
            memset(grp_addr_str, 0, sizeof(grp_addr_str));
            ip_printAddress(&(src_grp_entry->source->address), src_addr_str, sizeof(src_addr_str));
            ip_printAddress(&(src_grp_entry->group->address), grp_addr_str, sizeof(grp_addr_str));
            len += sprintf(print_buf + len, "\n(%s,%s)\n", src_addr_str, grp_addr_str);

            pim_time_uptime(uptime, sizeof(uptime), now - src_grp_entry->creation);
            len += sprintf(print_buf + len, "UP TIME : %s ", uptime);
            /*
            if((src_grp_entry->flags & MRTF_RPT) != 0)
            {
                len += sprintf(print_buf + len, "RP-BIT = 1  ");
            }
            else
            {
                len += sprintf(print_buf + len, "RP-BIT = 0  ");
            }
            */
            if((src_grp_entry->flags & PIMSM_MRT_FLAG_SPT) != 0)
            {
                len += sprintf(print_buf + len, "SPT-BIT = 1 ");
            }
            else
            {
                len += sprintf(print_buf + len, "SPT-BIT = 0  ");
            }
            if(pimsm_LocalReceiverExist(src_grp_entry))
            {
                len += sprintf(print_buf + len, "flags : LI\n");
            }
            else
            {
                len += sprintf(print_buf + len, "flags : LD\n");
            }

            len += sprintf(print_buf + len, "METRIC PREF  : %u\n", src_grp_entry->preference);
            len += sprintf(print_buf + len, "METRIC       : %u\n", src_grp_entry->metric);
            memset(addr_str, 0, sizeof(addr_str));
            ip_printAddress(&(src_grp_entry->upstream_if.up_stream_nbr), addr_str, sizeof(addr_str));
            len += sprintf(print_buf + len, "UPSTREAM NBR : %s\n", addr_str);
            //处理入接口
            if (0 != src_grp_entry->upstream_if.ifindex)
            {
                pstIf = pimsm_SearchInterface(src_grp_entry->upstream_if.ifindex);
                if(pstIf == NULL)
                {
                    len += sprintf(print_buf + len, "RPF interface no find\n");
                }
                else
                {
                    memset(addr_str, 0, sizeof(addr_str));
                    ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                    len += sprintf(print_buf + len, "RPF Interface : %s Linklocal address : %s ", pimsm_GetIfName(pstIf->ifindex), addr_str);


                    pimsmassert_if = pimsm_SearchAssertIfByIndex(src_grp_entry->pimsmassert_if, pstIf->ifindex);
                    if (NULL != pimsmassert_if)
                    {
                        if (PimsmAssertStateWinner == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASW\n");
                        }
                        else if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASL\n");
                            memset(addr_str, 0, sizeof(addr_str));
                            ip_printAddress(&(pimsmassert_if->stAssertStateMachine.stAssertWinner.address), addr_str, sizeof(addr_str));
                            len += sprintf(print_buf + len, "  Current Assert Winner is %s\n", addr_str);
                            len += sprintf(print_buf + len, "  The Winner's RPT-bit is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.byRptBit);
                            len += sprintf(print_buf + len, "  The Winner's metric pref is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwMetricPref);
                            len += sprintf(print_buf + len, "  The Winner's metric is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwRouteMetric);
                        }
                        else
                        {
                            len += sprintf(print_buf + len, "\n");
                        }
                    }
                    else
                    {
                        len += sprintf(print_buf + len, "\n");
                    }
                }
            }
            else
            {
                len += sprintf(print_buf + len, "RPF Interface : NULL\n");
            }

            //针对出接口列表
            pstInheritedOil = pimsm_InheritedOlist(src_grp_entry, TRUE);
            pstJoinsOil = pimsm_Joins(src_grp_entry, TRUE);
            pstOif_1 = pstInheritedOil;
            while(pstOif_1 != NULL)
            {
                pstIf = pimsm_SearchInterface(pstOif_1->ifindex);
                if(pstIf == NULL)
                {
                    len += sprintf(print_buf + len, "Out interface no find\n");
                }
                else
                {
                    memset(addr_str, 0, sizeof(addr_str));
                    ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                    len += sprintf(print_buf + len, "Output Interface : %s Linklocal address : %s", pimsm_GetIfName(pstIf->ifindex), addr_str);
                    pimsmassert_if = pimsm_SearchAssertIfByIndex(src_grp_entry->pimsmassert_if, pstOif_1->ifindex);
                    if (NULL != pimsmassert_if)
                    {
                        if (PimsmAssertStateWinner == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASW");
                        }
                        else if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                        {
                            len += sprintf(print_buf + len, " ASL");
                            len += sprintf(print_buf + len, " ERROR : a assert loser present in the OIL\n");
                        }
                    }

                    pstOif_2 = pimsm_SearchOifByIndex(pstJoinsOil, pstOif_1->ifindex);
                    if(pstOif_2 != NULL)
                    {
                        pstDownIf = pimsm_SearchDownstreamIfByIndex(src_grp_entry->downstream_if, pstOif_2->ifindex);
                        if (NULL != pstDownIf)
                        {
                            if(pstDownIf->down_stream_state_mchine.t_pimsm_expiry_timer)
                            {
                                len += sprintf(print_buf + len, "  LIVE TIME : %ld s", thread_timer_remain_second(pstDownIf->down_stream_state_mchine.t_pimsm_expiry_timer));
                            }
                        }
                    }

                    len += sprintf(print_buf + len, "\n");
                }
                pstOif_1 = pstOif_1->next;
            }

            pimsmassert_if = src_grp_entry->pimsmassert_if;
            while((pimsmassert_if != NULL) && (NULL != pimsm_SearchOifByIndex(pstInheritedOil, pimsmassert_if->ifindex)))
            {
                if (PimsmAssertStateLoser == pimsmassert_if->stAssertStateMachine.emAssertState)
                {
                    pstIf = pimsm_SearchInterface(pimsmassert_if->ifindex);
                    if(pstIf == NULL)
                    {
                        len += sprintf(print_buf + len, "Output interface no find\n");
                    }
                    else
                    {
                        memset(addr_str, 0, sizeof(addr_str));
                        ip_printAddress(&(pstIf->primary_address), addr_str, sizeof(addr_str));
                        len += sprintf(print_buf + len, "Output Interface : %s Linklocal address : %s", pimsm_GetIfName(pstIf->ifindex), addr_str);
                        len += sprintf(print_buf + len, " ASL\n");
                        memset(addr_str, 0, sizeof(addr_str));
                        ip_printAddress(&(pimsmassert_if->stAssertStateMachine.stAssertWinner.address), addr_str, sizeof(addr_str));
                        len += sprintf(print_buf + len, "  Current Assert Winner is %s\n", addr_str);
                        len += sprintf(print_buf + len, "  The Winner's RPT-bit is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.byRptBit);
                        len += sprintf(print_buf + len, "  The Winner's metric pref is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwMetricPref);
                        len += sprintf(print_buf + len, "  The Winner's metric is %u\n", pimsmassert_if->stAssertStateMachine.stAssertWinner.dwRouteMetric);
                    }
                }

                pimsmassert_if = pimsmassert_if->next;
            }

            pimsm_FreeOil(pstInheritedOil);
            pimsm_FreeOil(pstJoinsOil);

            src_grp_entry = src_grp_entry->samegrpnext;
        }
    }
    hash_traversal_end();

    //pimsm_ToCliPrint(&pstCliMsgToPimsm->subclihead, print_buf, len);

    vty_out(vty,"%s\n",print_buf);

    vty_out(vty, "%s\n", "will DisplayAllStarGrpEntry.");
    //sangmeng test
    pimsm_DisplayAllStarGrpEntry(vty);

    vty_out(vty, "%s\n", "will DisplayAllHardwareEntry.");

    pimsm_DisplayAllHardwareEntry(vty);

    return VOS_OK;
}

#define end

#if 0
int pim_PrintRpf(void)
{
    struct pimsm_rpf_entry              *pstRpf = NULL;
    uint8_t acIpAddrDst[30];
    uint8_t acIpAddrNbr[30];
    char acTempBuf[200];
    int count = 0;

    pstRpf = g_stPimsm.pstRpfList;

    /* 在已注册过的表中查找 */
    printf("\n==============================================\n");
    printf("RPF information:\n");
    while (NULL != pstRpf)
    {
        memset(acIpAddrDst, 0, sizeof(acIpAddrDst));
        memset(acIpAddrNbr, 0, sizeof(acIpAddrNbr));
        sprintf(acIpAddrDst, "%s", pim_InetFmt(&pstRpf->stDest));
        sprintf(acIpAddrNbr, "%s", pim_InetFmt(&pstRpf->stRpfNbr));
        memset(acTempBuf, 0, sizeof(acTempBuf));
        if ( pim_GetIntfNameFromLogicID(pstRpf->rpf_if, acTempBuf) == FALSE )
        {
            printf("[%d]  DestAddress = %s, OutInterface = %d, NbrAddress = %s .\n", count, acIpAddrDst, pstRpf->rpf_if, acIpAddrNbr);
        }
        else
        {
            printf("[%d]  DestAddress = %s, OutInterface = %s, NbrAddress = %s .\n", count, acIpAddrDst, acTempBuf, acIpAddrNbr);
        }
        pstRpf = pstRpf->next;
        count++;
    }
    printf("----------------------------------------------\n");

    return VOS_OK;
}

int pim_PrintMrtTable(void)
{
    PIM_GRPENTRY * pGroupEntry = NULL;
    PIM_MRTENTRY *mrt_entry = NULL;
    struct hash_backet *pHashBacket;
    char acTempBuf[200];
    PIM_OIF * oif;
    int loop = 0;
    int i = 0;

    if(g_stPimsm.pstGrpHash != NULL)
    {
        printf("\n==============================================\n");
        printf("Share Tree:\n");
        for(loop = 0; loop < HASHTABSIZE; ++loop)
        {
            pHashBacket = g_stPimsm.pstGrpHash->index[loop];
            while(NULL != pHashBacket)
            {
                if (pHashBacket->data != NULL)
                {
                    pGroupEntry = pHashBacket->data;
                    mrt_entry = pGroupEntry->pstMrt;
                    if(NULL != mrt_entry)
                    {
                        printf("\t(*, %s) G_RP: %s\n", pim_InetFmt(&pGroupEntry->address), pim_InetFmt(&pGroupEntry->stRp));
#if 0
                        printf("\t\tRSTimerID: %d, RSATimerID: %d, JPDTimerID: %d, JPPTimerID: %d, KATimerID: %d.\n",
                               mrt_entry->tmRegSuppTimer, mrt_entry->tmRegSuppAuxTimer,
                               mrt_entry->tmJPDelayTimer, mrt_entry->tmJPPeriodTimer,
                               mrt_entry->tmKeepAliveTimer);
#endif
                        memset(acTempBuf, 0, sizeof(acTempBuf));
                        if ( pim_GetIntfNameFromLogicID(mrt_entry->stIif.ifindex, acTempBuf) == FALSE )
                        {
                            printf("\t\tIif: %d, UpNbr: %s, Flag: 0x%x, CopyToCpu: %d\n", mrt_entry->stIif.ifindex,
                                   pim_InetFmt(&mrt_entry->stIif.stUpstreamNbr),
                                   mrt_entry->flags, mrt_entry->bIsCopyToCpu);
                        }
                        else
                        {
                            printf("\t\tIif: %s, UpNbr: %s, Flag: 0x%x, CopyToCpu: %d\n", acTempBuf,
                                   pim_InetFmt(&mrt_entry->stIif.stUpstreamNbr),
                                   mrt_entry->flags, mrt_entry->bIsCopyToCpu);
                        }
                        printf("\t\tOil: ");
                        oif = mrt_entry->oif;
                        if(oif == NULL) printf("NULL\n");
                        while(NULL != oif)
                        {
                            memset(acTempBuf, 0, sizeof(acTempBuf));
                            if ( pim_GetIntfNameFromLogicID(oif->ifindex, acTempBuf) == FALSE )
                            {
                                printf("%d", oif->ifindex);
                            }
                            else
                            {
                                printf("%s", acTempBuf);
                            }
                            oif = oif->next;
                            if(oif != NULL) printf(", ");
                            else printf(".\n");
                        }
                    }
                }
                pHashBacket = pHashBacket->next;
            }
        }
        printf("\n----------------------------------------------\n");

        printf("\n==============================================\n");
        printf("Source Tree:\n");
        for(loop = 0; loop < HASHTABSIZE; ++loop)
        {
            pHashBacket = g_stPimsm.pstGrpHash->index[loop];
            while(NULL != pHashBacket)
            {
                if (NULL != pHashBacket->data)
                {
                    pGroupEntry = pHashBacket->data;
                    mrt_entry = pGroupEntry->pstSrcMrtLink;
                    while (NULL != mrt_entry)
                    {
                        //modfied by wangfj, rp->g, 2018-7-10
                        printf("\t(%s, %s) G_RP: %s\n", pim_InetFmt(&mrt_entry->source->address), pim_InetFmt(&pGroupEntry->address), pim_InetFmt(&pGroupEntry->stRp));
#if 0
                        printf("\t\tRSTimer: 0x%x, RSATimer: 0x%x, JPDTimer: 0x%x, JPPTimer: 0x%x, KATimer: 0x%x.\n",
                               mrt_entry->tmRegSuppTimer, mrt_entry->tmRegSuppAuxTimer,
                               mrt_entry->tmJPDelayTimer, mrt_entry->tmJPPeriodTimer,
                               mrt_entry->tmKeepAliveTimer);
#endif
                        memset(acTempBuf, 0, sizeof(acTempBuf));
                        if ( pim_GetIntfNameFromLogicID(mrt_entry->stIif.ifindex, acTempBuf) == FALSE )
                        {
                            printf("\t\tIif: %d, UpNbr: %s, Flag: 0x%x, CopyToCpu: %d\n", mrt_entry->stIif.ifindex,
                                   pim_InetFmt(&mrt_entry->stIif.stUpstreamNbr),
                                   mrt_entry->flags, mrt_entry->bIsCopyToCpu);
                        }
                        else
                        {
                            printf("\t\tIif: %s, UpNbr: %s, Flag: 0x%x, CopyToCpu: %d\n", acTempBuf,
                                   pim_InetFmt(&mrt_entry->stIif.stUpstreamNbr),
                                   mrt_entry->flags, mrt_entry->bIsCopyToCpu);
                        }
                        printf("\t\tOil: ");
                        oif = mrt_entry->oif;
                        if(oif == NULL) printf("NULL\n");
                        while(NULL != oif)
                        {
                            memset(acTempBuf, 0, sizeof(acTempBuf));
                            if ( pim_GetIntfNameFromLogicID(oif->ifindex, acTempBuf) == FALSE )
                            {
                                printf("%d", oif->ifindex);
                            }
                            else
                            {
                                printf("%s", acTempBuf);
                            }
                            oif = oif->next;
                            if(oif != NULL) printf(", ");
                            else printf(".\n");
                        }

                        mrt_entry = mrt_entry->samegrpnext;
                    }
                }
                pHashBacket = pHashBacket->next;
            }
        }
        printf("\n----------------------------------------------\n");
    }

    return VOS_OK;
}

int pim_ClearStarGrpTable(void)
{
    PIM_GRPENTRY * pGroupEntry = NULL;
    PIM_MRTENTRY *mrt_entry = NULL;
    struct hash_backet *pHashBacket;
    PIM_OIF * oif;
    int loop = 0;
    int i = 0;

    if(g_stPimsm.pstGrpHash != NULL)
    {
        for(loop = 0; loop < HASHTABSIZE; ++loop)
        {
            pHashBacket = g_stPimsm.pstGrpHash->index[loop];
            while(NULL != pHashBacket)
            {
                if (pHashBacket->data != NULL)
                {
                    pGroupEntry = pHashBacket->data;
                    mrt_entry = pGroupEntry->pstMrt;
                    if(NULL != mrt_entry)
                    {
                        pimsm_DelEntry2Mrtmgt(mrt_entry);
                        pimsm_DelMrtEntry(mrt_entry);
                    }
                    pGroupEntry->pstMrt = NULL;
                }
                pHashBacket = pHashBacket->next;
            }
        }
        printf("Clear star group table ok.\n");
    }

    return VOS_OK;
}

int pim_ClearSrcGrpTable(void)
{
    PIM_GRPENTRY * pGroupEntry = NULL;
    PIM_MRTENTRY *mrt_entry = NULL;
    PIM_MRTENTRY *pstNextEntry = NULL;
    struct hash_backet * pHashBacket;
    PIM_OIF * oif;
    int loop = 0;
    int i = 0;

    if(g_stPimsm.pstGrpHash != NULL)
    {
        for(loop = 0; loop < HASHTABSIZE; ++loop)
        {
            pHashBacket = g_stPimsm.pstGrpHash->index[loop];
            while(NULL != pHashBacket)
            {
                if (NULL != pHashBacket->data)
                {
                    pGroupEntry = pHashBacket->data;
                    mrt_entry = pGroupEntry->pstSrcMrtLink;
                    while (NULL != mrt_entry)
                    {
                        pstNextEntry = mrt_entry->samegrpnext;
                        pimsm_DelEntry2Mrtmgt(mrt_entry);
                        pimsm_DelMrtEntry(mrt_entry);
                        mrt_entry = pstNextEntry;
                    }
                    pGroupEntry->pstSrcMrtLink = NULL;
                }
                pHashBacket = pHashBacket->next;
            }
        }
        printf("Clear source group table ok.\n");
    }

    return VOS_OK;
}
#endif

#endif
