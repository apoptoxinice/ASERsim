#ifndef _PIMDATAGRAMPROC_H_
#define _PIMDATAGRAMPROC_H_

#include "pimd.h"
#include "pimsm_msg.h"
//sangmeng add
#define	IP_VERSION	4	/* current version value		*/

#if 0
/*mac header*/
typedef struct stu_pim_mac_header
{
    uint8_t 	ucDMacAddr[6];
    uint8_t 	ucSMacAddr[6];
    uint16_t          		wLength;
} __attribute__((packed)) PIM_MAC_HEADER;

/*vlan tag*/
typedef struct stu_pim_l2_pkt_tag
{
    PIM_MAC_HEADER		stMacHeader;
    uint16_t 				wVlanId;
    uint16_t				wProtocolId;
    uint8_t				ucIpPkt[0];
} __attribute__((packed)) PIM_L2_PKT_TAG;

/*ip header*/
typedef struct stu_pim_ip_header
{
    uint8_t	ip_verlen;	/* IP version & header length (in longs)*/
    uint8_t	ip_tos;		/* type of service			*/
    uint16_t	ip_len;		/* total packet length (in octets)	*/
    uint16_t	ip_id;		/* datagram id				*/
    uint16_t 	ip_fragoff;	/* fragment offset (in 8-octet's)	*/
    uint8_t	ip_ttl;		/* time to live, in gateway hops	*/
    uint8_t	ip_proto;	/* IP protocol (see IPT_* above)	*/
    uint16_t	ip_cksum;	/* header checksum 			*/
    VOS_IP_ADDR 	ip_src;		/* IP address of source			*/
    VOS_IP_ADDR	ip_dst;		/* IP address of destination		*/
    uint8_t	ip_data[0];	/* variable length data			*/
} __attribute__((packed)) PIM_IP_HEADER;
#endif

#define PIM_IP_HEADER_LEN 20

/* Encoded-Unicast address */
struct pimsm_encoded_unicast_addr
{
    uint8_t family; /* Addr Family */
    uint8_t encoding_type;   /* Encoding type */
    VOS_IP_ADDR unicast_addr; /* Unicast Address */
} __attribute__((packed));

/* Encoded-Group address */
struct pimsm_encoded_grp_addr
{
    uint8_t family;  /* Addr Family */
    uint8_t encoding_type;    /* Encoding type */
    uint8_t flags;   /* B、Z */
    uint8_t mask_len; /* Mssk Len */
    VOS_IP_ADDR grp_addr; /* group multicast address */
} __attribute__((packed));

#define PIM_UGADDR_B    0x01
#define PIM_UGADDR_Z    0x80

/* Encoded-Source address */
struct pimsm_encoded_src_addr
{
    uint8_t family;  /* Addr Family */
    uint8_t encoding_type;    /* Encoding type */
    uint8_t flags;   /* S、W、R */
    uint8_t mask_len; /* Mssk Len */
    VOS_IP_ADDR src_addr; /* source address */
} __attribute__((packed));

#define PIM_USADDR_RP   0x01
#define PIM_USADDR_WC   0x02
#define PIM_USADDR_S    0x04

#if 0
/* PIM Common Header */
struct pimsm_common_header
{
    uint8_t btType : 4;    /* Type */
    uint8_t btVer  : 4;    /* pim ver */
    uint8_t reserved;        /* Reserved */
    uint16_t wCksum;        /* Checksum */
} __attribute__((packed));

#define PIM_HEADER_LEN  (sizeof(struct pimsm_common_header))
#endif

/* PIM Hello Message */
struct pimsm_hello
{
    uint16_t    type;      /* option type */
    uint16_t    value_len;  /* value len */
    char    data[0];   /* value */
} __attribute__((packed));
#define PIM_OPTION_HEADER_LEN  4

/* Vartious options from PIM messages definitions */

/* struct pimsm_hello holdtime */
#define PIM_HELLO_HOLDTIME_OPTION      1
#define PIM_HELLO_HOLDTIME_LEN         2
#define PIM_HELLO_HOLDTIME_FOREVER     0xffff

/* struct pimsm_hello LAN Prune Delay */
#define PIM_HELLO_PRUNE_DELAY          2
#define PIM_HELLO_PRUNE_DELAY_LEN      4
/* This indicates the neighbor's capability
   to disable Join message suppression */
#define PIM_TRACKING_SUPPORT_BIT       0x8000

/* struct pimsm_hello DR Priority */
#define PIM_HELLO_DR_PRIORITY          19
#define PIM_HELLO_DR_PRIORITY_LEN      4

/* struct pimsm_hello Generation ID */
#define PIM_HELLO_GENERATION_ID        20
#define PIM_HELLO_GENERATION_ID_LEN    4

/* PIM HELLO additional addresses option (experimental) */
#define PIM_HELLO_ADDR_LIST            24

#define PIM_ASSERT_MSG_LENTH           48/*不含pim头的长度*/


/* PIM Register Message */
struct pimsm_register
{
    uint32_t   flags;    /* highest two bit effective, other bit must is 0 */
    char    data[0];   /* Multicast data packet */
} __attribute__((packed));

/* pim Register Message header len */
#define PIM_REGISTER_HEADER_LEN (sizeof(uint32_t))

/* struct pimsm_register definitions */
#define PIM_REG_BORDER_BIT             0x80000000 /* The Border bit, is PMBR set 1 */
#define PIM_REG_NULL_REGISTER_BIT      0x40000000 /* The Null-Register bit */

/* PIM Register-Stop Message */
struct pimsm_register_stop
{
    struct pimsm_encoded_grp_addr       stEncodGrpAddr; /* encoded group address */
    struct pimsm_encoded_unicast_addr   stEncodSrcAddr; /* encoded source address */
} __attribute__((packed));


enum em_jp_type
{
    PIM_JOIN,
    PIM_PRUNE,
    PIM_JP_END
};
/* PIM Join/Prune Message */
struct pimsm_jp_header
{
    struct pimsm_encoded_unicast_addr   encod_upstream_nbr;   /* Upstream Neighbor Address */
    uint8_t    reserved;    /* Reserved */
    uint8_t    num_groups;  /* Num groups */
    uint16_t    hold_time;  /* Holdtime */
} __attribute__((packed));

#define PIM_JP_MINLEN  (PIM_MSG_HEADER_LEN + sizeof(struct pimsm_jp_header))

/* PIM Join/Prune message */
struct pimsm_jp_grp
{
    struct pimsm_encoded_grp_addr   stEncodGrpAddr; /* Multicast Group Address 1-N */
    uint16_t    wNumJoin;  /* Number of Joined Sources */
    uint16_t    wNumPrune; /* Number of Pruned Sources */
} __attribute__((packed));

/* Pim Assert message */
struct pimsm_assert
{
    struct pimsm_encoded_grp_addr       stEncodGrpAddr; /* encoded group address */
    struct pimsm_encoded_unicast_addr   stEncodSrcAddr; /* encoded source address */
    uint32_t   preference;
    uint32_t   metric;
} __attribute__((packed));

#define PIM_INFINITE   0xffffffff
#define PIM_ASSERT_RPT 0x80000000

/* PIM messages type */
#define PIM_TYPE_HELLO                 0
#define PIM_TYPE_REGISTER              1
#define PIM_TYPE_REGISTER_STOP         2
#define PIM_TYPE_JOIN_PRUNE            3
#define PIM_TYPE_BOOTSTRAP             4
#define PIM_TYPE_ASSERT                5
#define PIM_TYPE_GRAFT                 6
#define PIM_TYPE_GRAFT_ACK             7
#define PIM_TYPE_CAND_RP_ADV           8

//函数声明
int pimsm_ReceiveProtocolDatagram(int ifindex, uint8_t *buf, size_t len);
int pimsm_ReceiveMulticastDatagram(int fd, const char *buf, int buf_size);
int pimsm_SendHello(uint32_t ifindex, uint16_t  hold_time, VOS_IP_ADDR *nbr_primary_addr);
#if 0
uint16_t pimsm_CheckSum (uint16_t *buf, int nwords);
#endif
int pimsm_SendPimPacket(uint8_t *pim_msg, uint32_t ifindex, VOS_IP_ADDR *pstSrc, VOS_IP_ADDR *pstDst, int type, uint32_t pim_tlv_size);
int pimsm_ReceiveRegisterStop(uint32_t ifindex,VOS_IP_ADDR *src_addr,VOS_IP_ADDR *pstDstAddr,uint8_t *pim_msg,uint32_t pim_msg_size);

#endif
