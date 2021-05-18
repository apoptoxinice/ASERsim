#ifndef _PIM_INTERFACE_H
#define _PIM_INTERFACE_H

#include <zebra.h>
#include "zclient.h"
#include "if.h"

#include "pim_iface.h"
#include "pimsm_msg.h"
#include "pimsm_igmp.h"

#include "vty.h"

#define PIMSM_INTERFACE_COPY_TO_CPU 0

//Interface Flags
#define PIMSM_IF_FLAG_UP 0x0001      //interface is up
#define PIMSM_IF_FLAG_ENABLE 0x0002      //interface not enabling PIM
#define PIMSM_IF_FLAG_NONBRS 0x0004      //interface has no neighbors
#define PIMSM_IF_FLAG_DR 0x0008      //interface is DR
#define PIMSM_IF_FLAG_P2P 0x0010      //interface type is P2P

#define PIMSM_NO_IF 0xffffffff
#define PIMSM_DR_PRIORITY_DEFAULT 1
#define PIMSM_IF_NAME_MAX_LEN 80

#define PIMSM_NEIGHBOR_MAX_NUM_PER_INTERFACE 48


struct pimsm_prefix_ipv6_list
{
    struct pimsm_prefix_ipv6_list *next;
    struct pimsm_prefix_ipv6_list *prev;
    VOS_IPV6_ADDR   addr;
    uint16_t prefixlen;
};

struct pimsm_neighbor_entry
{
    struct pimsm_neighbor_entry *next;
    struct pimsm_neighbor_entry *prev;

    uint8_t mode; /* current PIM mode of neighbor (SM, DM) */
    uint8_t version; /* current PIM version of neighbor */

    uint8_t send_hello_already; /* A flag indicating whether a hello message has been sent to the neighbor */
    int pimsm_generation_id; /* Generation ID of neighbor */
    VOS_IPV6_ADDR source_addr; /* The neighbor Primary address */
    struct pimsm_prefix_ipv6_list *pstSecondaryAddrList; /* The neighbor secondary address list  */
    uint8_t bPriorityPresent; /* A flag indicating if the DR Priority field was present in the Hello message. */
    uint32_t dr_priority; /* The DR Priority field of the PIM neighbor, if it is present in the Hello message. */

    uint8_t bLanPruneDelayPresent; /*A flag indicating if the LAN Prune Delay option was present in the Hello message. */
    uint8_t bTrackingSupport; /*A flag storing the value of the T bit in the LAN Prune Delay option if it is present in the Hello message.
							This indicates the neighbor's capability to disable Join message suppression.*/
    uint16_t pimsm_propagation_delay_msec; /* The Propagation Delay field of the LAN Prune Delay option (if present) in the Hello message. */
    uint16_t pimsm_override_interval_msec; /* The Override_Interval field of the LAN Prune Delay option (if present) in the Hello message. */

#if 1//sangmeng add for neighbor timer
    struct thread   *t_expire_timer;
#endif
    int64_t            creation; /* timestamp of creation */
};

struct pimsm_interface_member
{
    struct pimsm_interface_member *next;
    struct pimsm_interface_member *prev;

    VOS_IPV6_ADDR grp_addr;  //group address
    PIMSM_ADDR_LIST_T *pSrcAddrList; //source address list
    uint8_t type; //record mode type , see PIMSM_RECORD_TYPE_T
};

struct pimsm_interface_stat
{
    int64_t  start; /* start timestamp for stats */
    uint32_t hello_recv;
    uint32_t hello_recvfail;
    uint32_t join_prune_recv;
    uint32_t join_prune_recvfail;
    uint32_t bootstrap_recv;
    uint32_t bootstrap_recvfail;
    uint32_t assert_recv;
    uint32_t assert_recvfail;
    uint32_t graft_recv;
    uint32_t graft_recvfail;


    uint32_t hello_send;
    uint32_t hello_sendfail;
    uint32_t join_prune_send;
    uint32_t join_prune_sendfail;
    uint32_t bootstrap_send;
    uint32_t bootstrap_sendfail;
    uint32_t assert_send;
    uint32_t assert_sendfail;
    uint32_t graft_send;
    uint32_t graft_sendfail;

};

struct pimsm_interface_entry
{
    struct pimsm_interface_entry *prev;
    struct pimsm_interface_entry *next;

    int options;
    uint32_t dwIfType;

    uint8_t mode;     //cuurent PIM mode (SM, DM)
    uint8_t version;      //current PIM version

    int  mroute_vif_index;
    VOS_IPV6_ADDR primary_address;//the linklocal address fe80
    uint16_t prefixlen; //the linklocal address prefix len
    struct pimsm_prefix_ipv6_list *pstSecondaryAddr; //global address list

    uint32_t ifindex;  //interface number
    char name[INTERFACE_NAMSIZ + 1];  //interface name
    int pimsm_generation_id;

    VOS_IPV6_ADDR pimsm_dr_addr;       //the current DR (is :: in P2P network)
    uint32_t pimsm_dr_priority;   //priority of the current DR

    uint16_t pimsm_propagation_delay_msec;  //Expected propagation delay over the local link,ini 0.5
    uint16_t pimsm_override_interval_msec;  //delay interval over which to randomize when scheduling a delayed Join message, init 2.5

    //sangmeng add for hello timer
    struct thread *t_pimsm_hello_timer;

    uint32_t pimsm_hello_period;    //the time interval for sending hello message (30s default)
    uint32_t dwJoinPruneInterval;       //the time interval for sending Join/Prune message (60s default)

    //sangmeng add for igmp timer
    struct thread *t_pimsm_igmp_timer;

    struct pimsm_neighbor_entry *pimsm_neigh;    //the neighbor list
    struct pimsm_interface_member *pstMemberList; //the group member list
    struct pimsm_interface_stat pimsm_ifstat;

    //sangmeng add for socket
    int            pimsm_sock_fd;       /* PIM socket file descriptor */
    struct thread *t_pimsm_sock_read;   /* thread for reading PIM socket */
    int64_t        pimsm_sock_creation; /* timestamp of PIM socket creation */
};


#if 0
extern int pimsm_ShowInterface(m_CliToPimsm_t *pstCliMsgToPimsm);
#endif
int pimsm_ShowInterface(struct vty *vty, uint32_t ifindex);
int pimsm_ShowNeighbor(struct vty *vty,struct interface *ifp);

int pimsm_ShowInterface(struct vty *vty,uint32_t ifindex);
extern uint8_t pimsm_IsLocalAddress(VOS_IPV6_ADDR *pstAddr);
extern uint32_t pimsm_DirectIfSearch(VOS_IPV6_ADDR *pstAddr);
extern struct pimsm_interface_entry *pimsm_SearchInterface(uint32_t ifindex);
extern int pimsm_DRElection(struct pimsm_interface_entry *pimsm_ifp);

struct pimsm_neighbor_entry *pimsm_SearchNeighbor(struct pimsm_interface_entry *pimsm_ifp, VOS_IPV6_ADDR *pstNbrAddr);
int pimsm_DelNbr(struct pimsm_interface_entry *pimsm_ifp, struct pimsm_neighbor_entry *pimsm_neigh);
uint32_t pimsm_GetNeighborCount(struct pimsm_interface_entry *pimsm_ifp);
uint8_t pimsm_IsLocalIfAddress(uint32_t ifindex, VOS_IPV6_ADDR *pstAddr);
uint8_t pimsm_IsMyNeighbor(uint32_t ifindex, VOS_IPV6_ADDR *pstNbrAddr);
uint32_t pim_GetIntfNameFromLogicID(int LogicID,char *name);


int pimsm_zebra_if_state_up(int command, struct zclient *zclient,zebra_size_t length);
int pimsm_zebra_if_state_down(int command, struct zclient *zclient,zebra_size_t length);
int pimsm_zebra_if_address_add(int command, struct zclient *zclient,zebra_size_t length);
int pimsm_zebra_if_address_del(int command, struct zclient *client,zebra_size_t length);
int pimsm_zebra_if_add(int command, struct zclient *zclient,zebra_size_t length);
int pimsm_zebra_if_del(int command, struct zclient *zclient,zebra_size_t length);

int pimsm_IfStart(uint32_t ifindex);
int pimsm_IfMtuUpdate(m_CfmToPimsm_t *pstCfmMsg);
int pimsm_IfStop(uint32_t ifindex);

int pimsm_IfEnable(struct interface *ifp);
int pimsm_IfDisable(struct interface *ifp);

int pimsm_IfEnableAll (void);
int pimsm_IfDisableAll (void);

int pimsm_SetHelloInterval(struct vty *vty, struct interface *ifp, uint32_t dwSeconds);
int pimsm_SetJoinPruneInterval(struct vty *vty, struct interface *ifp, uint32_t dwSeconds);
int pimsm_SetDRPriority(struct vty *vty, struct interface *ifp, uint32_t dwSeconds);

uint8_t pimsm_IamDR(uint32_t ifindex);

int oam_OutputToDevice(uint32_t dwIODeviceNO, const char *szInChar);
struct pimsm_interface_member *pimsm_CreateIfMember(struct pimsm_interface_entry *pimsm_ifp, VOS_IPV6_ADDR *src_addr, VOS_IPV6_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType);
int pimsm_DestroyIfMember(struct pimsm_interface_entry *pimsm_ifp,VOS_IPV6_ADDR *src_addr,VOS_IPV6_ADDR *pstGrpAddr,PIMSM_RECORD_TYPE_T emType);
int pimsm_if_config_write(struct vty *vty);
int pimsm_DestroyIfAllMember(struct pimsm_interface_entry *pimsm_ifp);
uint8_t pimsm_ExistIfEnable(void);
#endif
