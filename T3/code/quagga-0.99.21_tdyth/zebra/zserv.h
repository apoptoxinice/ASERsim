/* Zebra daemon server header.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_ZSERV_H
#define _ZEBRA_ZSERV_H

#include "rib.h"
#include "if.h"
#include "workqueue.h"

/* Default port information. */
#define ZEBRA_VTY_PORT                2601
#define JUN_ADD //zhangqingjun


#ifdef JUN_ADD
#define ADD_OSPF6_ACL 36
#define DEL_OSPF6_ACL 37
#endif

/* Default configuration filename. */
#define DEFAULT_CONFIG_FILE "zebra.conf"

/* Client structure. */
#define LOCAL_ADDRESS "127.0.0.1"
#define LOCAL_PORT 2016

#define ARMY_TYPE 0x00
#define PEOPLE_TYPE 0x01
#define IN_AREA  1 << 1
#define OUT_AREA  0 << 1

struct comm_head
{
    unsigned short len;
    char data[0];
};
struct msg_head
{
    char chrType;
    unsigned short len;
    char data[0];
} __attribute__((packed));

struct prefix_msg
{
    struct in6_addr prefix;
    unsigned char prefixlen;
};
struct zserv
{
    /* Client file descriptor. */
    int sock;

    /* Input/output buffer to the client. */
    struct stream *ibuf;
    struct stream *obuf;

    /* Buffer of data waiting to be written to client. */
    struct buffer *wb;

    /* Threads for read/write. */
    struct thread *t_read;
    struct thread *t_write;

    /* Thread for delayed close. */
    struct thread *t_suicide;

    /* default routing table this client munges */
    int rtm_table;

    /* This client's redistribute flag. */
    u_char redist[ZEBRA_ROUTE_MAX];

    /* Redistribute default route flag. */
    u_char redist_default;

    /* Interface information. */
    u_char ifinfo;

    /* Router-id information. */
    u_char ridinfo;
};
#define IVI_INET_ADDRESS	"127.0.0.1"
#define IVI_INET_PORT		10032
struct ivi_message
{

    unsigned int type;
    unsigned int len;
    void *data;
};
//#ifdef JUN_ADD
#if 1
#define  ospf_acl_message ivi_message
typedef union _ospf6_acl_addr
{
    unsigned char b_addr[16];
    unsigned short w_addr[8];
    unsigned int d_addr[4];
} ospf6_acl_addr;
struct ospf6_acl_message
{
    ospf6_acl_addr src_addr;
    ospf6_acl_addr dst_addr;
    unsigned int src_len;
    unsigned int dst_len;
    unsigned int fwd;
};
#endif
/* Zebra instance */
struct zebra_t
{
    /* Thread master */
    struct thread_master *master;
    struct list *client_list;

    /* default table */
    int rtm_table_default;

    /* rib work queue */
    struct work_queue *ribq;
    struct meta_queue *mq;
};

//added for 4over6 20130305
#define TUNNELNUMBER 4096
#define ZEBRA_4OVER6_ENABLE		1
#define ZEBRA_4OVER6_DISABLE	0

//#define	IFNAMSIZ	16
struct zebra_4over6_tunnel_entry
{
    char name[IFNAMSIZ];	/* name of tunnel device */
    struct in6_addr nexthop;	/* the nexthop	*/
    int num;
    int state;
    char tunnel_number;

    struct zebra_4over6_tunnel_entry *next;
};

//added for nat 20130507
#define	NATSIZE	20
#define	CMDSTR	200
#define	POOLSTR	200
#define NAT_ENABLE 1
#define NAT_DISABLE 0


struct nat_pool_entry
{
    char name[NATSIZE];
    char startaddr[NATSIZE];
    struct in_addr start_addr;
    char endaddr[NATSIZE];
    struct in_addr end_addr;
    char poolcmdstr[POOLSTR];

    struct nat_pool_entry *next;
};

struct nat_source_list
{
    char name[NATSIZE];
    char snet[NATSIZE];
    struct in_addr source_addr;
    int masklen;

    struct nat_source_list *next;
};

struct nat_source_list_pool_entry
{
    int pool_state;
    int list_state;

    struct nat_pool_entry pool;
    struct nat_source_list source;

    struct nat_source_list_pool_entry *next;
};

//add by limingyuan 2013.8.16 for snmp
struct config_cmd_string
{
    char *config_string;
    struct config_cmd_string *next;
    struct config_cmd_string *tail;
};
extern void free_snmp_config_string();

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Prototypes. */
extern void zebra_init (void);
extern void zebra_if_init (void);
extern void zebra_zserv_socket_init (char *path);
extern void hostinfo_get (void);
extern void rib_init (void);
extern void interface_list (void);
extern void kernel_init (void);
extern void route_read (void);
extern void zebra_route_map_init (void);
extern void zebra_snmp_init (void);
extern void zebra_vty_init (void);

extern int zsend_interface_add (struct zserv *, struct interface *);
extern int zsend_interface_delete (struct zserv *, struct interface *);
extern int zsend_interface_address (int, struct zserv *, struct interface *,
                                    struct connected *);
extern int zsend_interface_update (int, struct zserv *, struct interface *);
extern int zsend_route_multipath (int, struct zserv *, struct prefix *,
                                  struct rib *);
extern int zsend_router_id_update(struct zserv *, struct prefix *);

extern pid_t pid;

extern int ospf6_show_route_to_xml(void);//zlw
extern int zebra_write_interface_to_xml(char *pName,char *pIpv4,char *pIpv6);//zlw
#endif /* _ZEBRA_ZEBRA_H */


//add by myj  for two demesion route
#ifndef __TWO_RUT_CLIENT_H__
#define __TWO_RUT_CLIENT_H__

//#define DMESION2_ROUT_SEND_SIZE 1
#define ROUT_DEBUG 1
#define   ROUT_CTRL_MSG   3


struct dmesion2_ctrl_msg
{
    struct in6_addr src_prefix;
    unsigned char src_prefixlen;
    struct in6_addr dst_prefix;
    unsigned char dst_prefixlen;
    struct in6_addr next_hop;
    int ifindex;
};


#if 1
struct tlv_flow
{
    unsigned char type;
    int length;
    char data[0];
};

#endif



#define NLMSG_ALIGNTO	4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))

#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
#define NLMSG_OVERRUN		0x4	/* Data lost		*/
/* nlmsg Flags values */
#define NLM_F_REQUEST		1	/* It is request message. 	*/
#define NLM_F_MULTI		2	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		4	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		8	/* Echo this request 		*/
/* Modifiers to NEW request */
#define NLM_F_REPLACE	0x100	/* Override existing		*/
#define NLM_F_EXCL	0x200	/* Do not touch, if it exists	*/
#define NLM_F_CREATE	0x400	/* Create, if it does not exist	*/
#define NLM_F_APPEND	0x800	/* Add to end of list		*/

#define TCA_BUF_MAX	(64*1024)

#define TC_H_ROOT	(0xFFFFFFFFU)

/* Macros to handle rtattributes */
#define RTA_ALIGNTO	4
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* RED section */
enum
{
    TCA_RED_UNSPEC,
    TCA_RED_PARMS,
    TCA_RED_STAB,
    __TCA_RED_MAX,
};
/* rtnl */

struct rtnl_handle
{
    int			fd;
    struct sockaddr_nl	local;
    struct sockaddr_nl	peer;
    unsigned int			seq;
    unsigned int			dump;
};
struct rtnl_handle rth;

//dev
/* Modifiers to GET request */
#define NLM_F_ROOT	0x100	/* specify tree	root	*/
#define NLM_F_MATCH	0x200	/* return all matching	*/
#define NLM_F_ATOMIC	0x400	/* atomic GET		*/
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)
/* Flags values */

#define NLM_F_REQUEST		1	/* It is request message. 	*/
#define NLM_F_MULTI		2	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		4	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		8	/* Echo this request 		*/
//rtnl_dump_filter
typedef int (*rtnl_filter_t)(const struct sockaddr_nl *,
                             struct nlmsghdr *n, void *);
struct rtnl_dump_filter_arg
{
    rtnl_filter_t filter;
    void *arg1;
    rtnl_filter_t junk;
    void *arg2;
};
//ll_remember_index
struct idxmap
{
    struct idxmap * next;
    unsigned	index;
    int		type;
    int		alen;
    unsigned	flags;
    unsigned char	addr[20];
    char		name[16];
};
static struct idxmap *idxmap[16];

#define IFLA_MAX (__IFLA_MAX - 1)
#define RTA_ALIGNTO	4
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
#define IFLA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
int filter_ifindex;
unsigned int filter_qdisc;
unsigned int filter_classid;
#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
#define SPRINT_BSIZE 64
#define SPRINT_BUF(x)	char x[SPRINT_BSIZE]
#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))
enum
{
    TCA_STAB_UNSPEC,
    TCA_STAB_BASE,
    TCA_STAB_DATA,
    __TCA_STAB_MAX
};
#define TCA_STAB_MAX (__TCA_STAB_MAX - 1)
struct gnet_stats_basic
{
    unsigned long	bytes;
    unsigned int	packets;
};
#define MIN(a, b) ((a) < (b) ? (a) : (b))
enum
{
    TCA_STATS_UNSPEC,
    TCA_STATS_BASIC,
    TCA_STATS_RATE_EST,
    TCA_STATS_QUEUE,
    TCA_STATS_APP,
    __TCA_STATS_MAX,
};
struct gnet_stats_queue
{
    unsigned int	qlen;
    unsigned int	backlog;
    unsigned int	drops;
    unsigned int	requeues;
    unsigned int	overlimits;
};
#define TCA_STATS_MAX (__TCA_STATS_MAX - 1)
struct tc_stats
{
    unsigned int	bytes;			/* NUmber of enqueues bytes */
    unsigned int	packets;		/* Number of enqueued packets	*/
    unsigned int	drops;			/* Packets dropped because of lack of resources */
    unsigned int	overlimits;		/* Number of throttle events when this
					 * flow goes out of allocated bandwidth */
    unsigned int	bps;			/* Current flow byte rate */
    unsigned int	pps;			/* Current flow packet rate */
    unsigned int	qlen;
    unsigned int	backlog;
};
struct tc_red_xstats
{
    unsigned int           early;          /* Early drops */
    unsigned int           pdrop;          /* Drops due to queue limits */
    unsigned int           other;          /* Drops due to drop() calls */
    unsigned int           marked;         /* Marked packets */
};

//add by ccc for ecn
//check
struct tc_red_qopt
{
    unsigned int		limit;		/* HARD maximal queue length (bytes)	*/
    unsigned int		qth_min;	/* Min average length threshold (bytes) */
    unsigned int		qth_max;	/* Max average length threshold (bytes) */
    unsigned char   Wlog;		/* log(W)		*/
    unsigned char   Plog;		/* log(P_max/(qth_max-qth_min))	*/
    unsigned char   Scell_log;	/* cell size for idle damping */
    unsigned char	flags;
};
#define TC_RED_ECN	1
#define TC_RED_HARDDROP	2
struct if_politic_qdisc
{
    char ifname[16];
    char politic;
    struct if_politic_qdisc *next;
};
#endif
#if 0
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,int alen);
extern int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type);
extern int rtnl_dump_filter_l(struct rtnl_handle *rth,const struct rtnl_dump_filter_arg *arg);
extern int rtnl_dump_filter(struct rtnl_handle *rth,rtnl_filter_t filter,void *arg1,rtnl_filter_t junk,void *arg2);
extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int ll_remember_index(const struct sockaddr_nl *who,struct nlmsghdr *n, void *arg);
extern int ll_init_map(struct rtnl_handle *rth);
extern unsigned ll_name_to_index(const char *name);
extern int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,int protocol);
extern int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);
extern void rtnl_close(struct rtnl_handle *rth);
extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,unsigned groups, struct nlmsghdr *answer,rtnl_filter_t junk,void *jarg);
extern int tc_red_eval_idle_damping(unsigned char *sbuf);
#endif

//add by ccc for flow separation
#ifndef __FLOW_SEPARATION_BY_PEOPLE_AND_SOLDIER__
#define __FLOW_SEPARATION_BY_PEOPLE_AND_SOLDIER__
#define INTEGRATION 0
#define PEOPLE 1

#define FLOW_ADD 1
#define FLOW_DEL 2

struct inter_in_area
{
    char ifname[16];
    char area_value;
    struct inter_in_area *next;
};
#if 1 //add by myj in 2016.12.23
#define COMPRESS_ON 1    // the header compression will be opend
#define COMPRESS_OFF 0

#define APPOINT_STR  "[interface]"
#define APPOINT_AFTER  "[ipv4 dst]"

#define COMPBUFSIZE 1024
#define COMPBUFSIZE_TOTAL (4*1024)
#define COMPBUFSIZE_DOWN (2*1024)


//#define _PATH_HEADER_COMPRESS   "/usr/src/router_hc/src/config/conmp_config.config"
#define _PATH_HEADER_COMPRESS   "/usr/src/router_hc/src/config/comp_config"  //"/root/work/test/if_compress.conf"
#define _PATH_COMMAND_COMPRESS1 "" //"cd /root/work/"
#define _PATH_COMMAND_COMPRESS2 "cd /root/work/"
#define INSTALL_COMPRESS1 "/sbin/insmod /usr/src/router_hc/lib/rohc_src/linux/kmod/rohc.ko"
#define INSTALL_COMPRESS2 "/sbin/insmod /usr/src/router_hc/src/rhc_de_comp/router_hc_comp.ko"
#define UNINSTALL_COMPRESS1 "/sbin/rmmod -f router_hc_comp"
#define UNINSTALL_COMPRESS2 "/sbin/rmmod -f rohc"
struct if_compress_enabled
{
    char ifname[16];
    unsigned char compres_flag;
    struct if_compress_enabled *next;
};

#endif
#endif
