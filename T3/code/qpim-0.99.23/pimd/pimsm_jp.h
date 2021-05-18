#ifndef _PIM_JP_H
#define _PIM_JP_H

#include <zebra.h>
#include "thread.h"

#include "pimsm.h"
#include "pimsm_mrtmgt.h"

#define PIMSM_TIMER_VALUE_JOIN_PERIODIC (60) /* t_periodic Default: 60s */
#define PIMSM_TIMER_VALUE_JOIN_PRUNE_OVERRIDE (10) /* 10s */ /* Protocol says: It is set to the J/P_Override_Interval(I) if the router has more than one neighbor on that interface; otherwise, it is set to zero, causing it to expire immediately.*/
#define PIMSM_TIMER_VALUE_SUPPRESSED (1.2 * PIMSM_TIMER_VALUE_JOIN_PERIODIC) /* rand(1.1 * t_periodic, 1.4 * t_periodic) when Suppression_Enable(I) is true, 0 otherwise. */
#define PIMSM_TIMER_VALUE_OVERRIDE (10) /* rand(0, Effective_Override_Interval(I) */

/* Join/Prune state meachine event type define */
/* (*,G) (S,G) (S,G,rpt) downstream and upstream */
typedef enum pimsm_updown_state_machine_event_t
{
    PimsmReceiveJoinStarGrpEvent = 0, /* Receive Join(*,G) */
    PimsmReceiveJoinSrcGrpEvent, /* Receive Join(S,G) */
    PimsmReceiveJoinSrcGrpRptEvent, /* Receive Join(S,G,rpt) */
    PimsmReceivePruneStarGrpEvent, /* Receive Prune(*,G) */
    PimsmReceivePruneSrcGrpEvent, /* Receive Prune(S,G) */
    PimsmReceivePruneSrcGrpRptEvent, /* Receive Prune(S,G,rpt) */
    PimsmPrunePendingTimerExpiresEvent, /* Prune-Pending Timer Expires */
    PimsmDownIfTimerExpiresEvent, /* Expiry Timer Expires */
    PimsmEndOfMessageEvent, /* End of Message */

    PimsmJoinDesiredStarGrpToTrueEvent, /* JoinDesired(*,G) -> True */
    PimsmJoinDesiredStarGrpToFalseEvent, /* JoinDesired(*,G) -> False */
    PimsmJoinTimerExpiresEvent, /* Timer Expires */
    PimsmSeeJoinStarGrpToRpfaStarGrpEvent, /* See Join(*,G) to RPF'(*,G) */
    PimsmSeePruneStarGrpToRpfaStarGrpEvent, /* See Prune(*,G) to RPF'(*,G) */
    PimsmRpfaStarGrpChangesDueAssertEvent, /* RPF'(*,G) changes due to an Assert */
    PimsmRpfaStarGrpChangesNotAssertEvent, /* RPF'(*,G) changes not due to an Assert */
    PimsmRpfaStarGrpGenidChangesEvent, /* RPF'(*,G) GenID changes */
    PimsmJoinDesiredSrcGrpToTrueEvent, /* JoinDesired(S,G) -> True */
    PimsmJoinDesiredSrcGrpToFalseEvent, /* JoinDesired(S,G) -> False */
    PimsmSeeJoinSrcGrpToRpfaSrcGrpEvent, /* See Join(S,G) to RPF'(S,G) */
    PimsmSeePruneSrcGrpToRpfaSrcGrpEvent, /* See Prune(S,G) to RPF'S,G) */
    PimsmSeePruneSrcGrpRptToRpfaSrcGrpEvent, /* See Prune(S,G,rpt) to RPF'(S,G) */
    PimsmSeePruneStarGrpToRpfaSrcGrpEvent, /* See Prune(*,G) to RPF'(S,G) */
    PimsmRpfaSrcGrpChangesNotAssertEvent, /* RPF'(S,G) changes not due to an Assert */
    PimsmRpfaSrcGrpGenidChangesEvent, /* RPF'(S,G) GenID changes */
    PimsmRpfaSrcGrpChangesDueAssertEvent, /* RPF'(S,G) changes due to an Assert */
    PimsmPruneDesiredSrcGrpRptToTrueEvent, /* PruneDesired(S,G,rpt) -> True */
    PimsmPruneDesiredSrcGrpRptToFalseEvent, /* PruneDesired(S,G,rpt) -> False */
    PimsmRptJoinDesiredGrpToFalse, /* RPTJoinDesired(G) -> False */
    PimsmInheritedOlistSrcGrpRptToNonNullEvent, /* inherited_olist(S,G,rpt) -> non-NULL */
    PimsmOverrideTimerExpires, /* Override Timer Expires */
    PimsmSeePruneSrcGrpRptToRpfaSrcGrpRptEvent, /* See Prune(S,G,rpt) to RPF'(S,G,rpt) */
    PimsmSeeJoinSrcGrpRptToRpfaSrcGrpRptEvent, /* See Join(S,G,rpt) to RPF'(S,G,rpt) */
    PimsmSeePruneSrcGrpToRpfaSrcGrpRptEvent, /* See Prune(S,G) to RPF'(S,G,rpt) */
    PimsmRpfaSrcGrpRptToRpfaStarGrpEvent /* RPF'(S,G,rpt) -> RPF'(*,G) */
} PIMSM_UPDOWN_STATE_MACHINE_EVENT_T;

struct pimsm_updown_state_machine_event_para
{
    VOS_IPV6_ADDR old_upstream_nbr_addr;
    VOS_IPV6_ADDR new_upstream_nbr_addr;
    uint16_t hold_time;
};

#define PIMSM_UPSTREAM_STATE_STR "NotJoined","Joined","Pruned","NotPruned","RptNotJoined"
typedef enum pimsm_upstream_state_t
{
    PimsmUpstreamStateNotJoined = 0,
    PimsmUpstreamStateJoined,
    PimsmUpstreamStatePruned,
    PimsmUpstreamStateNotPruned,
    PimsmUpstreamStateRptNotJoined,
    PimsmUpstreamStateEnd
} PIMSM_UPSTREAM_STATE_T;

#define PIMSM_DOWNSTREAM_STATE_STR "NoInfo","Join","PrunePending","Prune","PruneTmp","PrunePendingTmp"
typedef enum pimsm_downstream_state_t
{
    PimsmDownstreamStateNoInfo = 0,
    PimsmDownstreamStateJoin,
    PimsmDownstreamStatePrunePending,
    PimsmDownstreamStatePrune,
    PimsmDownstreamStatePruneTmp,
    PimsmDownstreamStatePrunePendingTmp,
    PimsmDownstreamStateEnd
} PIMSM_DOWNSTREAM_STATE_T;

struct pimsm_upstream_state_machine
{
    PIMSM_UPSTREAM_STATE_T emUpstreamState;
    uint32_t tmOverrideTimer; /* (S,G,RPT) */
#if 1
    struct thread *t_pimsm_join_timer;
    struct thread *t_pimsm_override_timer;
#endif
};

struct pimsm_downstream_state_machine
{
    PIMSM_DOWNSTREAM_STATE_T emDownstreamState;
    struct thread *t_pimsm_expiry_timer;
    struct thread *t_pimsm_prunpend_timer;
};

extern uint8_t pimsm_RPTJoinDesired(VOS_IPV6_ADDR *pstGrpAddr);
const char *pimsm_GetUpstreamStateString(PIMSM_UPSTREAM_STATE_T emState);
const char *pimsm_GetDownstreamStateString(PIMSM_DOWNSTREAM_STATE_T emState);
#endif
