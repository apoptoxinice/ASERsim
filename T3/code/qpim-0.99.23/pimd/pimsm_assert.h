#ifndef _PIM_ASSERT_H
#define _PIM_ASSERT_H

#include <zebra.h>
#include "thread.h"

#include "pimsm.h"

#define PIMSM_TIMER_VALUE_ASSERT_TIMER (180) /* Default: 180s */
#define PIMSM_TIMER_VALUE_ASSERT_OVERRIDE (3) /* Default: 3s */

#define PIMSM_ASSERT_PREFERENCE_INFINITY   0xffffffff
#define PIMSM_ASSERT_METRIC_INFINITY   0xffffffff
#define PIMSM_ASSERT_RPTBIT 0x80000000

/* [RFC7761: Page 85] When an Assert message is received whith a source address other than zero, a PIM
implementation must first match it against the possible events in the (S,G) assert state machine and process any
transitions and actions, before considering wether the Assert message matches against the (*,G) assert state machine. */
/* [RFC7761: Page 86] It is important to note that NO TRANSITION CAN OCCUR in the (*,G) state machine as
a result of receiving an Assert message unless the (S,G) assert state machine for relevant S and G is in the "NoInfo"
state after the (S,G) state machine has processed the message. Also, NO TRANSITION CAN OCCUR in the (*,G) state
machine as a result of receiving an assert message if the message triggers any change of state in the (S,G) state machine.
Obviously, when the source address in the received message is set to zero, an (S,G) state machine for the S and G does
not exist and can be assumed to be in the "NoInfo" state. */
typedef enum pimsm_assert_event_process_result_t
{
    PimsmAssertResultError = -1,
    PimsmAssertResultOk = 0,
    PimsmAssertResultWinnerToNoInfo,
    PimsmAssertResultWinnerToLoser,
    PimsmAssertResultNoInfoToWinner,
    PimsmAssertResultNoInfoToLoser,
    PimsmAssertResultLoserToNoInfo,
    PimsmAssertResultLoserToWinner
} PIMSM_ASSERT_EVENT_PROCESS_RESULT_T;

typedef enum pimsm_assert_state_machine_event_t
{
    PimsmAssertEvent_01 = 0, /* Assert Timer Expires */
    PimsmAssertEvent_02, /* Neighbor Liveness Timer(NLT) Expires */
    PimsmAssertEvent_03, /* Receive Inferior Assert */
    PimsmAssertEvent_04, /* Receive Inferior Assert with RPTbit clear */
    PimsmAssertEvent_05, /* Receive Inferior Assert with RPTbit set and CouldAssert(*,G,I) */
    PimsmAssertEvent_06, /* Receive Inferior Assert from Current Winner */
    PimsmAssertEvent_07, /* Receive Inferior Assert Cancel from Current Winner */
    PimsmAssertEvent_08, /* Receive Preferred Assert */
    PimsmAssertEvent_09, /* Receive Preferred Assert with RPTbit set */
    PimsmAssertEvent_10, /* Receive Acceptable Assert with RPTbit clear and AssTrDes(S,G,I) */
    PimsmAssertEvent_11, /* Receive Acceptable Assert with RPTbit clear from Current Winner */
    PimsmAssertEvent_12, /* Receive Acceptable Assert with RPTbit set and AsstrDes(*,G,I) */
    PimsmAssertEvent_13, /* Receive Acceptable Assert with RPTbit set from Current Winner */
    PimsmAssertEvent_14, /* Receive Assert with RPTbit set and CouldAssert(S,G,I) */
    PimsmAssertEvent_15, /* CouldAssert(S,G,I) --> FALSE */
    PimsmAssertEvent_16, /* CouldAssert(*,G,I) --> FALSE */
    PimsmAssertEvent_17, /* AssTrDes(S,G,I) -> FALSE */
    PimsmAssertEvent_18, /* AssTrDes(*,G,I) -> FALSE */
    PimsmAssertEvent_19, /* Receive Join(S,G) on Interface I */
    PimsmAssertEvent_20, /* Receive Join(*,G) on Interface I */
    PimsmAssertEvent_21, /* Data arrives from S to G on I and CouldAssert(S,G,I) */
    PimsmAssertEvent_22, /* Data arrives for G on I and CouldAssert(*,G,I) */
    PimsmAssertEvent_23, /* Current Winner's GenID Changes */
    PimsmAssertEvent_24, /* my_metric --> better than Winner's metric */
    PimsmAssertEvent_25, /* RPF_interface(S) stops being I */
    PimsmAssertEvent_26 /* RPF_interface(RP(G)) stops being I */
} PIMSM_ASSERT_STATE_MACHINE_EVENT_T;

struct pimsm_assert_metric
{
    uint8_t byRptBit;       /*从断言报文中获取rpt位*/
    uint32_t dwMetricPref;   /*花费参考值*/
    uint32_t dwRouteMetric;  /*花费值*/
    VOS_IPV6_ADDR address;     /*/ip地址*/
};

struct pimsm_assert_state_machine_event_para
{
    struct pimsm_assert_metric stAssertMetric;
};

#define PIMSM_ASSERT_STATE_STR "NoInfo","Winner","Loser"
typedef enum pimsm_assert_state_t
{
    PimsmAssertStateNoInfo = 0,
    PimsmAssertStateWinner,
    PimsmAssertStateLoser,
    PimsmAssertStateEnd
} PIMSM_ASSERT_STATE_T;

struct pimsm_assert_state_machine
{
    PIMSM_ASSERT_STATE_T emAssertState;
    //sangmeng add for assert timer
    struct thread *t_pimsm_assert_timer;
    struct pimsm_assert_metric stAssertWinner;
};

const char *pimsm_GetAssertStateString(PIMSM_ASSERT_STATE_T emState);
int pimsm_MetricCompare(struct pimsm_assert_metric *pstMetric1, struct pimsm_assert_metric *pstMetric2);
#endif
