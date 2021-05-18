/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA

  $QuaggaId: $Format:%an, %ai, %h$ $
*/

#include <zebra.h>
#include <netinet/icmp6.h>
#include <string.h>

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/mroute6.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <linux/igmp.h>
#include <linux/socket.h>

#include "memory.h"

#include "pimd.h"
#include "pim_igmp.h"
#include "pim_igmpv3.h"
#include "pim_iface.h"
#include "pim_sock.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_util.h"
#include "pim_time.h"
#include "pim_zebra.h"


#include "pimsm_msg.h"

#include "pimsm_igmp_taskmain.h"
#include "membership.h"
#include "input.h"
#include "handler.h"

#define IGMP_GRP_REC_TYPE_MODE_IS_INCLUDE        (1)
#define IGMP_GRP_REC_TYPE_MODE_IS_EXCLUDE        (2)
#define IGMP_GRP_REC_TYPE_CHANGE_TO_INCLUDE_MODE (3)
#define IGMP_GRP_REC_TYPE_CHANGE_TO_EXCLUDE_MODE (4)
#define IGMP_GRP_REC_TYPE_ALLOW_NEW_SOURCES      (5)
#define IGMP_GRP_REC_TYPE_BLOCK_OLD_SOURCES      (6)


static int igmpv1_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type);
static int igmpv2_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type);
static int igmpv3_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type);

void mld_v1_report(struct mld_sock *mld, struct mld_hdr *p_mldhr);
void mld_v2_report(struct mld_sock *mld, struct mld_hdr *p_mldh, int buf_len);
void pim_mld_other_querier_timer_off(struct mld_sock *mld);
int icmp6_sock_init(void);

int mldv1_send_msg_to_pimsm(struct in6_addr *group_addr,uint32_t ifindex,uint32_t msg_type);
int mldv2_send_msg_to_pimsm(struct in6_addr *group_addr,uint32_t ifindex,uint32_t msg_type);


void pim_mld_general_query_on(struct mld_sock *mld);
int pim_mld_packet(struct mld_sock *mld, char *buf, size_t len);
int mld_sock_init(void);


static void group_timer_off(struct igmp_group *group);

static struct igmp_group *find_group_by_addr(struct igmp_sock *igmp,
        struct in_addr group_addr);

#if 0
static int igmp_sock_open(struct in_addr ifaddr, int ifindex, uint32_t pim_options)
{
    int fd;
    int join = 0;
    struct in_addr group;

    fd = pim_socket_mcast(IPPROTO_IGMP, ifaddr, 1 /* loop=true */);
    if (fd < 0)
        return -1;

    if (PIM_IF_TEST_IGMP_LISTEN_ALLROUTERS(pim_options))
    {
        if (inet_aton(PIM_ALL_ROUTERS, &group))
        {
            if (!pim_socket_join(fd, group, ifaddr, ifindex))
                ++join;
        }
        else
        {
            zlog_warn("%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
                      __FILE__, __PRETTY_FUNCTION__, fd, inet_ntoa(ifaddr),
                      PIM_ALL_ROUTERS, errno, safe_strerror(errno));
        }
    }

    /*
      IGMP routers periodically send IGMP general queries to AllSystems=224.0.0.1
      IGMP routers must receive general queries for querier election.
    */
    if (inet_aton(PIM_ALL_SYSTEMS, &group))
    {
        if (!pim_socket_join(fd, group, ifaddr, ifindex))
            ++join;
    }
    else
    {
        zlog_warn("%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__, fd, inet_ntoa(ifaddr),
                  PIM_ALL_SYSTEMS, errno, safe_strerror(errno));
    }

    if (inet_aton(PIM_ALL_IGMP_ROUTERS, &group))
    {
        if (!pim_socket_join(fd, group, ifaddr, ifindex))
        {
            ++join;
        }
    }
    else
    {
        zlog_warn("%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__, fd, inet_ntoa(ifaddr),
                  PIM_ALL_IGMP_ROUTERS, errno, safe_strerror(errno));
    }

    if (!join)
    {
        zlog_err("IGMP socket fd=%d could not join any group on interface address %s",
                 fd, inet_ntoa(ifaddr));
        close(fd);
        fd = -1;
    }

    return fd;
}
#endif
#if 1
#define MLD_V2_LISTENER_REPORT 143
int mld_sock_init(void)
{
    struct icmp6_filter filt;
    int             on;
#if 1
    static struct
    {
        struct ip6_hbh hdr;
        struct ip6_opt_router rt;
        unsigned char padding[2];
    } hopts =
    {
        .hdr = {0, 0},
        .rt = {IP6OPT_ROUTER_ALERT, 2, {0, IP6_ALERT_MLD}},
        .padding = {0x1, 0} /* PadN option, RFC 2460, 4.2 */
    };
#endif

    int mld_socket = -1;
    mld_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if(mld_socket == -1)
    {
        printf("can't create mld socket\n");
        return -1;
    }

    /* filter all non-MLD ICMP messages */
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(MLD_LISTENER_REPORT, &filt);
    ICMP6_FILTER_SETPASS(MLD_LISTENER_REDUCTION, &filt);
    ICMP6_FILTER_SETPASS(MLD_V2_LISTENER_REPORT, &filt);


    int   opt = 1;
    int   len  =  sizeof(opt);
    setsockopt(mld_socket,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,len);


    if (setsockopt(mld_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,sizeof(filt)) < 0)
        printf("ICMP6_FILTER: %s\n", strerror(errno));

    /* specify to tell receiving interface */
    on = 1;
    if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,sizeof(on)) < 0)
        printf("IPV6_RECVPKTINFO: %s\n", strerror(errno));

    on = 1;
    if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &on,sizeof(on)) < 0)
        printf("IPV6_MULTICAST_HOPS: %s\n", strerror(errno));

    on = 0;
    if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,sizeof(on)) < 0)
        printf("IPV6_MULTICAST_LOOP: %s\n", strerror(errno));

    on = 1;
    if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on,sizeof(on)) < 0)
        printf("IPV6_RECVHOPOPTS: %s\n", strerror(errno));
#if 1
    /* RTR-ALERT option */
    if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_HOPOPTS, &hopts, sizeof(hopts)))
    {
        printf("IPV6_HOPOPTS: %s\n", strerror(errno));
    }
#endif

    int d = 1;
    if (setsockopt(mld_socket, IPPROTO_IPV6, MRT6_INIT, &d, sizeof(int)) < 0)
    {

        perror("MRT6_INIT");
        //return -1;
        return mld_socket;
    }

    return mld_socket;
}

#endif
#if 0
int icmp6_sock_init(void)
{
    int sockfd;
    struct icmp6_filter filter;

    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sockfd == -1)
    {
        printf("Failed to create raw socket for ICMP: %s\n", strerror(errno));
        exit(1);
    }

    if (setsockopt_ipv6_pktinfo(sockfd, 1))
    {
        printf("Failed to enable ipv6 pktinfo on ICMP6 socket: %s\n", strerror(errno));
        exit(1);
    }

    if (setsockopt_ipv6_multicast_loop(sockfd, 0))
    {
        printf("Failed to disable multicast loopback on ICMP6 socket: %s\n", strerror(errno));
        exit(1);
    }

    if (setsockopt_ipv6_hoplimit(sockfd, 1))
    {
        printf("Failed to set hop limit to 1 on ICMP6 socket: %s\n", strerror(errno));
        exit(1);
    }

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(MLD_TYPE_DONE, &filter);
    ICMP6_FILTER_SETPASS(MLD_TYPE_QUERY, &filter);
    ICMP6_FILTER_SETPASS(MLD_TYPE_REPORT, &filter);

    if (setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) != 0)
    {
        printf("Failed to set ICMP filter: %s\n", strerror(errno));
        exit(1);
    }


    return sockfd;

}
#endif

#undef IGMP_SOCK_DUMP

#ifdef IGMP_SOCK_DUMP
static void igmp_sock_dump(array_t *igmp_sock_array)
{
    int size = array_size(igmp_sock_array);
    for (int i = 0; i < size; ++i)
    {

        struct igmp_sock *igmp = array_get(igmp_sock_array, i);

        zlog_debug("%s %s: [%d/%d] igmp_addr=%s fd=%d",
                   __FILE__, __PRETTY_FUNCTION__,
                   i, size,
                   inet_ntoa(igmp->ifaddr),
                   igmp->fd);
    }
}
#endif

struct igmp_sock *pim_igmp_sock_lookup_ifaddr(struct list *igmp_sock_list,
        struct in_addr ifaddr)
{
    struct listnode  *sock_node;
    struct igmp_sock *igmp;

#ifdef IGMP_SOCK_DUMP
    igmp_sock_dump(igmp_sock_list);
#endif

    for (ALL_LIST_ELEMENTS_RO(igmp_sock_list, sock_node, igmp))
        if (ifaddr.s_addr == igmp->ifaddr.s_addr)
            return igmp;

    return 0;
}

struct mld_sock *pim_mld_sock_lookup_ifaddr(struct list *mld_sock_list,
        struct in6_addr ifaddr)
{
    struct listnode  *sock_node = NULL;
    struct mld_sock *mld = NULL;



    for (ALL_LIST_ELEMENTS_RO(mld_sock_list, sock_node, mld))
        //if (ifaddr.s_addr == igmp->ifaddr.s_addr)
        if (memcmp(&(ifaddr.s6_addr),&(mld->ifaddr.s6_addr),sizeof(struct in6_addr)));
    return mld;

    return 0;
}


struct igmp_sock *igmp_sock_lookup_by_fd(struct list *igmp_sock_list,
        int fd)
{
    struct listnode  *sock_node;
    struct igmp_sock *igmp;

    for (ALL_LIST_ELEMENTS_RO(igmp_sock_list, sock_node, igmp))
        if (fd == igmp->fd)
            return igmp;

    return 0;
}

static int pim_igmp_other_querier_expire(struct thread *t)
{
    struct igmp_sock *igmp;

    zassert(t);
    igmp = THREAD_ARG(t);
    zassert(igmp);

    zassert(igmp->t_other_querier_timer);
    zassert(!igmp->t_igmp_query_timer);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char ifaddr_str[100];
        pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
        zlog_debug("%s: Querier %s resuming",
                   __PRETTY_FUNCTION__,
                   ifaddr_str);
    }

    igmp->t_other_querier_timer = 0;

    /*
      We are the current querier, then
      re-start sending general queries.
    */
    pim_igmp_general_query_on(igmp);

    return 0;
}

void pim_igmp_other_querier_timer_on(struct igmp_sock *igmp)
{
    long other_querier_present_interval_msec;
    struct pim_interface *pim_ifp;

    zassert(igmp);
    zassert(igmp->interface);
    zassert(igmp->interface->info);

    pim_ifp = igmp->interface->info;

    if (igmp->t_other_querier_timer)
    {
        /*
          There is other querier present already,
          then reset the other-querier-present timer.
        */

        if (PIM_DEBUG_IGMP_TRACE)
        {
            char ifaddr_str[100];
            pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("Querier %s resetting TIMER event for Other-Querier-Present",
                       ifaddr_str);
        }

        THREAD_OFF(igmp->t_other_querier_timer);
        zassert(!igmp->t_other_querier_timer);
    }
    else
    {
        /*
          We are the current querier, then stop sending general queries:
          igmp->t_igmp_query_timer = 0;
        */
        pim_igmp_general_query_off(igmp);
    }

    /*
      Since this socket is starting the other-querier-present timer,
      there should not be periodic query timer for this socket.
     */
    zassert(!igmp->t_igmp_query_timer);

    /*
      RFC 3376: 8.5. Other Querier Present Interval

      The Other Querier Present Interval is the length of time that must
      pass before a multicast router decides that there is no longer
      another multicast router which should be the querier.  This value
      MUST be ((the Robustness Variable) times (the Query Interval)) plus
      (one half of one Query Response Interval).

      other_querier_present_interval_msec = \
        igmp->querier_robustness_variable * \
        1000 * igmp->querier_query_interval + \
        100 * (pim_ifp->query_max_response_time_dsec >> 1);
    */
    other_querier_present_interval_msec =
        PIM_IGMP_OQPI_MSEC(igmp->querier_robustness_variable,
                           igmp->querier_query_interval,
                           pim_ifp->igmp_query_max_response_time_dsec);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char ifaddr_str[100];
        pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
        zlog_debug("Querier %s scheduling %ld.%03ld sec TIMER event for Other-Querier-Present",
                   ifaddr_str,
                   other_querier_present_interval_msec / 1000,
                   other_querier_present_interval_msec % 1000);
    }

    THREAD_TIMER_MSEC_ON(master, igmp->t_other_querier_timer,
                         pim_igmp_other_querier_expire,
                         igmp, other_querier_present_interval_msec);
}

void pim_igmp_other_querier_timer_off(struct igmp_sock *igmp)
{
    zassert(igmp);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        if (igmp->t_other_querier_timer)
        {
            char ifaddr_str[100];
            pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("IGMP querier %s fd=%d cancelling other-querier-present TIMER event on %s",
                       ifaddr_str, igmp->fd, igmp->interface->name);
        }
    }
    THREAD_OFF(igmp->t_other_querier_timer);
    zassert(!igmp->t_other_querier_timer);
}
void pim_mld_other_querier_timer_off(struct mld_sock *mld)
{
    zassert(mld);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        if (mld->t_other_querier_timer)
        {
            char ifaddr_str[100];
            pim_inet6_dump("<ifaddr?>", mld->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("IGMP querier %s fd=%d cancelling other-querier-present TIMER event on %s",
                       ifaddr_str, mld->fd, mld->interface->name);
        }
    }
    THREAD_OFF(mld->t_other_querier_timer);
    zassert(!mld->t_other_querier_timer);
}
static int recv_igmp_query(struct igmp_sock *igmp, int query_version,
                           int max_resp_code,
                           struct in_addr from, const char *from_str,
                           char *igmp_msg, int igmp_msg_len)
{
    struct interface     *ifp;
    struct pim_interface *pim_ifp;
    uint8_t               resv_s_qrv = 0;
    uint8_t               s_flag = 0;
    uint8_t               qrv = 0;
    struct in_addr        group_addr;
    uint16_t              recv_checksum;
    uint16_t              checksum;
    int                   i;

    //group_addr = *(struct in_addr *)(igmp_msg + 4);
    memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

    ifp = igmp->interface;
    pim_ifp = ifp->info;

    recv_checksum = *(uint16_t *) (igmp_msg + IGMP_V3_CHECKSUM_OFFSET);

    /* for computing checksum */
    *(uint16_t *) (igmp_msg + IGMP_V3_CHECKSUM_OFFSET) = 0;

    checksum = in_cksum(igmp_msg, igmp_msg_len);
    if (checksum != recv_checksum)
    {
        zlog_warn("Recv IGMP query v%d from %s on %s: checksum mismatch: received=%x computed=%x",
                  query_version, from_str, ifp->name, recv_checksum, checksum);
        return -1;
    }

    if (PIM_DEBUG_IGMP_PACKETS)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group_addr, group_str, sizeof(group_str));
        zlog_debug("Recv IGMP query v%d from %s on %s: size=%d checksum=%x group=%s",
                   query_version, from_str, ifp->name,
                   igmp_msg_len, checksum, group_str);
    }

    /*
      RFC 3376: 6.6.2. Querier Election

      When a router receives a query with a lower IP address, it sets
      the Other-Querier-Present timer to Other Querier Present Interval
      and ceases to send queries on the network if it was the previously
      elected querier.
     */
    if (ntohl(from.s_addr) < ntohl(igmp->ifaddr.s_addr))
    {

        if (PIM_DEBUG_IGMP_TRACE)
        {
            char ifaddr_str[100];
            pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("%s: local address %s (%u) lost querier election to %s (%u)",
                       ifp->name,
                       ifaddr_str, ntohl(igmp->ifaddr.s_addr),
                       from_str, ntohl(from.s_addr));
        }

        pim_igmp_other_querier_timer_on(igmp);
    }

    if (query_version == 3)
    {
        /*
          RFC 3376: 4.1.6. QRV (Querier's Robustness Variable)

          Routers adopt the QRV value from the most recently received Query
          as their own [Robustness Variable] value, unless that most
          recently received QRV was zero, in which case the receivers use
          the default [Robustness Variable] value specified in section 8.1
          or a statically configured value.
        */
        resv_s_qrv = igmp_msg[8];
        qrv = 7 & resv_s_qrv;
        igmp->querier_robustness_variable = qrv ? qrv : pim_ifp->igmp_default_robustness_variable;
    }

    /*
      RFC 3376: 4.1.7. QQIC (Querier's Query Interval Code)

      Multicast routers that are not the current querier adopt the QQI
      value from the most recently received Query as their own [Query
      Interval] value, unless that most recently received QQI was zero,
      in which case the receiving routers use the default.
    */
    if (igmp->t_other_querier_timer && query_version == 3)
    {
        /* other querier present */
        uint8_t  qqic;
        uint16_t qqi;
        qqic = igmp_msg[9];
        qqi = igmp_msg_decode8to16(qqic);
        igmp->querier_query_interval = qqi ? qqi : pim_ifp->igmp_default_query_interval;

        if (PIM_DEBUG_IGMP_TRACE)
        {
            char ifaddr_str[100];
            pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("Querier %s new query interval is %s QQI=%u sec (recv QQIC=%02x from %s)",
                       ifaddr_str,
                       qqi ? "recv-non-default" : "default",
                       igmp->querier_query_interval,
                       qqic,
                       from_str);
        }
    }

    /*
      RFC 3376: 6.6.1. Timer Updates

      When a router sends or receives a query with a clear Suppress
      Router-Side Processing flag, it must update its timers to reflect
      the correct timeout values for the group or sources being queried.

      General queries don't trigger timer update.
    */
    if (query_version == 3)
    {
        s_flag = (1 << 3) & resv_s_qrv;
    }
    else
    {
        /* Neither V1 nor V2 have this field. Pimd should really go into
         * a compatibility mode here and run as V2 (or V1) but it doesn't
         * so for now, lets just set the flag to suppress these timer updates.
         */
        s_flag = 1;
    }

    if (!s_flag)
    {
        /* s_flag is clear */

        if (PIM_INADDR_IS_ANY(group_addr))
        {
            /* this is a general query */

            /* log that general query should have the s_flag set */
            zlog_warn("General IGMP query v%d from %s on %s: Suppress Router-Side Processing flag is clear",
                      query_version, from_str, ifp->name);
        }
        else
        {
            struct igmp_group *group;

            /* this is a non-general query: perform timer updates */

            group = find_group_by_addr(igmp, group_addr);
            if (group)
            {
                int recv_num_sources = ntohs(*(uint16_t *)(igmp_msg + IGMP_V3_NUMSOURCES_OFFSET));

                /*
                  RFC 3376: 6.6.1. Timer Updates
                  Query Q(G,A): Source Timer for sources in A are lowered to LMQT
                  Query Q(G): Group Timer is lowered to LMQT
                */
                if (recv_num_sources < 1)
                {
                    /* Query Q(G): Group Timer is lowered to LMQT */

                    igmp_group_timer_lower_to_lmqt(group);
                }
                else
                {
                    /* Query Q(G,A): Source Timer for sources in A are lowered to LMQT */

                    /* Scan sources in query and lower their timers to LMQT */
                    struct in_addr *sources = (struct in_addr *)(igmp_msg + IGMP_V3_SOURCES_OFFSET);
                    for (i = 0; i < recv_num_sources; ++i)
                    {
                        //struct in_addr src_addr = sources[i];
                        //struct igmp_source *src = igmp_find_source_by_addr(group, src_addr);
                        struct in_addr src_addr;
                        struct igmp_source *src;
                        memcpy(&src_addr, sources + i, sizeof(struct in_addr));
                        src = igmp_find_source_by_addr(group, src_addr);
                        if (src)
                        {
                            igmp_source_timer_lower_to_lmqt(src);
                        }
                    }
                }

            }
            else
            {
                char group_str[100];
                pim_inet_dump("<group?>", group_addr, group_str, sizeof(group_str));
                zlog_warn("IGMP query v%d from %s on %s: could not find group %s for timer update",
                          query_version, from_str, ifp->name, group_str);
            }
        }
    } /* s_flag is clear: timer updates */

    return 0;
}

static int igmp_v3_report(struct igmp_sock *igmp,
                          struct in_addr from, const char *from_str,
                          char *igmp_msg, int igmp_msg_len)
{
    uint16_t          recv_checksum;
    uint16_t          checksum;
    int               num_groups;
    uint8_t          *group_record;
    uint8_t          *report_pastend = (uint8_t *) igmp_msg + igmp_msg_len;
    struct interface *ifp = igmp->interface;
    int               i;

    if (igmp_msg_len < IGMP_V3_MSG_MIN_SIZE)
    {
        zlog_warn("Recv IGMP report v3 from %s on %s: size=%d shorter than minimum=%d",
                  from_str, ifp->name, igmp_msg_len, IGMP_V3_MSG_MIN_SIZE);
        return -1;
    }

    recv_checksum = *(uint16_t *) (igmp_msg + IGMP_V3_CHECKSUM_OFFSET);

    /* for computing checksum */
    *(uint16_t *) (igmp_msg + IGMP_V3_CHECKSUM_OFFSET) = 0;

    checksum = in_cksum(igmp_msg, igmp_msg_len);
    if (checksum != recv_checksum)
    {
        zlog_warn("Recv IGMP report v3 from %s on %s: checksum mismatch: received=%x computed=%x",
                  from_str, ifp->name, recv_checksum, checksum);
        return -1;
    }

    num_groups = ntohs(*(uint16_t *) (igmp_msg + IGMP_V3_REPORT_NUMGROUPS_OFFSET));
    if (num_groups < 1)
    {
        zlog_warn("Recv IGMP report v3 from %s on %s: missing group records",
                  from_str, ifp->name);
        return -1;
    }

    if (PIM_DEBUG_IGMP_PACKETS)
    {
        zlog_debug("Recv IGMP report v3 from %s on %s: size=%d checksum=%x groups=%d",
                   from_str, ifp->name, igmp_msg_len, checksum, num_groups);
    }

    group_record = (uint8_t *) igmp_msg + IGMP_V3_REPORT_GROUPPRECORD_OFFSET;

    /* Scan groups */
    for (i = 0; i < num_groups; ++i)
    {
        struct in_addr  rec_group;
        uint8_t        *sources;
        uint8_t        *src;
        int             rec_type;
        int             rec_auxdatalen;
        int             rec_num_sources;
        int             j;

        if ((group_record + IGMP_V3_GROUP_RECORD_MIN_SIZE) > report_pastend)
        {
            zlog_warn("Recv IGMP report v3 from %s on %s: group record beyond report end",
                      from_str, ifp->name);
            return -1;
        }

        rec_type        = group_record[IGMP_V3_GROUP_RECORD_TYPE_OFFSET];
        rec_auxdatalen  = group_record[IGMP_V3_GROUP_RECORD_AUXDATALEN_OFFSET];
        rec_num_sources = ntohs(* (uint16_t *) (group_record + IGMP_V3_GROUP_RECORD_NUMSOURCES_OFFSET));

        //rec_group = *(struct in_addr *)(group_record + IGMP_V3_GROUP_RECORD_GROUP_OFFSET);
        memcpy(&rec_group, group_record + IGMP_V3_GROUP_RECORD_GROUP_OFFSET, sizeof(struct in_addr));

        if (PIM_DEBUG_IGMP_PACKETS)
        {
            zlog_debug("Recv IGMP report v3 from %s on %s: record=%d type=%d auxdatalen=%d sources=%d group=%s",
                       from_str, ifp->name, i, rec_type, rec_auxdatalen, rec_num_sources, inet_ntoa(rec_group));
        }

        /* Scan sources */

        sources = group_record + IGMP_V3_GROUP_RECORD_SOURCE_OFFSET;

        for (j = 0, src = sources; j < rec_num_sources; ++j, src += 4)
        {

            if ((src + 4) > report_pastend)
            {
                zlog_warn("Recv IGMP report v3 from %s on %s: group source beyond report end",
                          from_str, ifp->name);
                return -1;
            }

            if (PIM_DEBUG_IGMP_PACKETS)
            {
                char src_str[200];

                if (!inet_ntop(AF_INET, src, src_str , sizeof(src_str)))
                    sprintf(src_str, "<source?>");

                zlog_debug("Recv IGMP report v3 from %s on %s: record=%d group=%s source=%s",
                           from_str, ifp->name, i, inet_ntoa(rec_group), src_str);
            }
        } /* for (sources) */

        switch (rec_type)
        {
        case IGMP_GRP_REC_TYPE_MODE_IS_INCLUDE:
            igmpv3_report_isin(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        case IGMP_GRP_REC_TYPE_MODE_IS_EXCLUDE:
            igmpv3_report_isex(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        case IGMP_GRP_REC_TYPE_CHANGE_TO_INCLUDE_MODE:
            igmpv3_report_toin(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        case IGMP_GRP_REC_TYPE_CHANGE_TO_EXCLUDE_MODE:
            igmpv3_report_toex(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        case IGMP_GRP_REC_TYPE_ALLOW_NEW_SOURCES:
            igmpv3_report_allow(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        case IGMP_GRP_REC_TYPE_BLOCK_OLD_SOURCES:
            igmpv3_report_block(igmp, from, rec_group, rec_num_sources, (struct in_addr *) sources);
            break;
        default:
            zlog_warn("Recv IGMP report v3 from %s on %s: unknown record type: type=%d",
                      from_str, ifp->name, rec_type);
        }

        group_record += 8 + (rec_num_sources << 2) + (rec_auxdatalen << 2);

    } /* for (group records) */

    return 0;
}

static void on_trace(const char *label,
                     struct interface *ifp, struct in_addr from)
{
    if (PIM_DEBUG_IGMP_TRACE)
    {
        char from_str[100];
        pim_inet_dump("<from?>", from, from_str, sizeof(from_str));
        zlog_debug("%s: from %s on %s",
                   label, from_str, ifp->name);
    }
}

static int igmp_v2_report(struct igmp_sock *igmp,
                          struct in_addr from, const char *from_str,
                          char *igmp_msg, int igmp_msg_len)
{
    struct interface *ifp = igmp->interface;
    struct igmp_group *group;
    struct in_addr group_addr;

    on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

    if (igmp_msg_len != IGMP_V12_MSG_SIZE)
    {
        zlog_warn("Recv IGMP report v2 from %s on %s: size=%d other than correct=%d",
                  from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
        return -1;
    }

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_warn("%s %s: FIXME WRITEME",
                  __FILE__, __PRETTY_FUNCTION__);
    }

    //group_addr = *(struct in_addr *)(igmp_msg + 4);
    memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

    /* non-existant group is created as INCLUDE {empty} */
    group = igmp_add_group_by_addr(igmp, group_addr, ifp->name);
    if (!group)
    {
        return -1;
    }

    group->last_igmp_v2_report_dsec = pim_time_monotonic_dsec();

    return 0;
}

static int igmp_v2_leave(struct igmp_sock *igmp,
                         struct in_addr from, const char *from_str,
                         char *igmp_msg, int igmp_msg_len)
{
    struct interface *ifp = igmp->interface;

    on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

    if (igmp_msg_len != IGMP_V12_MSG_SIZE)
    {
        zlog_warn("Recv IGMP leave v2 from %s on %s: size=%d other than correct=%d",
                  from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
        return -1;
    }

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_warn("%s %s: FIXME WRITEME",
                  __FILE__, __PRETTY_FUNCTION__);
    }

    return 0;
}

static int igmp_v1_report(struct igmp_sock *igmp,
                          struct in_addr from, const char *from_str,
                          char *igmp_msg, int igmp_msg_len)
{
    struct interface *ifp = igmp->interface;
    struct igmp_group *group;
    struct in_addr group_addr;

    on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

    if (igmp_msg_len != IGMP_V12_MSG_SIZE)
    {
        zlog_warn("Recv IGMP report v1 from %s on %s: size=%d other than correct=%d",
                  from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
        return -1;
    }

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_warn("%s %s: FIXME WRITEME",
                  __FILE__, __PRETTY_FUNCTION__);
    }

    //group_addr = *(struct in_addr *)(igmp_msg + 4);
    memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

    /* non-existant group is created as INCLUDE {empty} */
    group = igmp_add_group_by_addr(igmp, group_addr, ifp->name);
    if (!group)
    {
        return -1;
    }

    group->last_igmp_v1_report_dsec = pim_time_monotonic_dsec();

    return 0;
}

int pim_igmp_packet(struct igmp_sock *igmp, char *buf, size_t len)
{
    struct ip *ip_hdr;
    size_t ip_hlen; /* ip header length in bytes */
    char *igmp_msg;
    int igmp_msg_len;
    int msg_type;
    char from_str[100];
    char to_str[100];

    if (len < sizeof(*ip_hdr))
    {
        zlog_warn("IGMP packet size=%zu shorter than minimum=%zu",
                  len, sizeof(*ip_hdr));
        return -1;
    }

    ip_hdr = (struct ip *) buf;

    pim_inet_dump("<src?>", ip_hdr->ip_src, from_str , sizeof(from_str));
    pim_inet_dump("<dst?>", ip_hdr->ip_dst, to_str , sizeof(to_str));

    ip_hlen = ip_hdr->ip_hl << 2; /* ip_hl gives length in 4-byte words */

    if (PIM_DEBUG_IGMP_PACKETS)
    {
        zlog_debug("Recv IP packet from %s to %s on %s: size=%zu ip_header_size=%zu ip_proto=%d",
                   from_str, to_str, igmp->interface->name, len, ip_hlen, ip_hdr->ip_p);
    }

    if (ip_hdr->ip_p != PIM_IP_PROTO_IGMP)
    {
        zlog_warn("IP packet protocol=%d is not IGMP=%d",
                  ip_hdr->ip_p, PIM_IP_PROTO_IGMP);
        return -1;
    }

    if (ip_hlen < PIM_IP_HEADER_MIN_LEN)
    {
        zlog_warn("IP packet header size=%zu shorter than minimum=%d",
                  ip_hlen, PIM_IP_HEADER_MIN_LEN);
        return -1;
    }
    if (ip_hlen > PIM_IP_HEADER_MAX_LEN)
    {
        zlog_warn("IP packet header size=%zu greater than maximum=%d",
                  ip_hlen, PIM_IP_HEADER_MAX_LEN);
        return -1;
    }

    igmp_msg = buf + ip_hlen;
    msg_type = *igmp_msg;
    igmp_msg_len = len - ip_hlen;

    if (PIM_DEBUG_IGMP_PACKETS)
    {
        zlog_debug("Recv IGMP packet from %s to %s on %s: ttl=%d msg_type=%d msg_size=%d",
                   from_str, to_str, igmp->interface->name, ip_hdr->ip_ttl, msg_type,
                   igmp_msg_len);
    }

    if (igmp_msg_len < PIM_IGMP_MIN_LEN)
    {
        zlog_warn("IGMP message size=%d shorter than minimum=%d",
                  igmp_msg_len, PIM_IGMP_MIN_LEN);
        return -1;
    }

    switch (msg_type)
    {
    case PIM_IGMP_MEMBERSHIP_QUERY:
    {
        int max_resp_code = igmp_msg[1];
        int query_version;

        /*
        RFC 3376: 7.1. Query Version Distinctions
        IGMPv1 Query: length = 8 octets AND Max Resp Code field is zero
        IGMPv2 Query: length = 8 octets AND Max Resp Code field is non-zero
        IGMPv3 Query: length >= 12 octets
             */

        if (igmp_msg_len == 8)
        {
            query_version = max_resp_code ? 2 : 1;
        }
        else if (igmp_msg_len >= 12)
        {
            query_version = 3;
        }
        else
        {
            zlog_warn("Unknown IGMP query version");
            return -1;
        }

        return recv_igmp_query(igmp, query_version, max_resp_code,
                               ip_hdr->ip_src, from_str,
                               igmp_msg, igmp_msg_len);
    }

    case PIM_IGMP_V3_MEMBERSHIP_REPORT:
        return igmp_v3_report(igmp, ip_hdr->ip_src, from_str,
                              igmp_msg, igmp_msg_len);

    case PIM_IGMP_V2_MEMBERSHIP_REPORT:
        return igmp_v2_report(igmp, ip_hdr->ip_src, from_str,
                              igmp_msg, igmp_msg_len);

    case PIM_IGMP_V1_MEMBERSHIP_REPORT:
        return igmp_v1_report(igmp, ip_hdr->ip_src, from_str,
                              igmp_msg, igmp_msg_len);

    case PIM_IGMP_V2_LEAVE_GROUP:
        return igmp_v2_leave(igmp, ip_hdr->ip_src, from_str,
                             igmp_msg, igmp_msg_len);
    }

    zlog_warn("Ignoring unsupported IGMP message type: %d", msg_type);

    return -1;
}
#if 1
#define mld_num_multi    mld_icmp6_hdr.icmp6_data16[1]
#define    IN_LOCAL_CONTROL_BLOCK(a)        ((((unsigned long)(a)) & 0xffffff00) == 0xe0000000)

#define    IN_LOCAL_SCOPE_BLOCK(a)        ((((unsigned long)(a)) & 0xEFFF0000) == 0xEFFF0000)
#if 0
typedef union _pi_addr
{
    struct sockaddr_in      v4;
    struct sockaddr_in6     v6;
    struct sockaddr         sa;
    struct sockaddr_storage ss;
} pi_addr;

typedef struct pa_list
{
    struct pa_list     *next;
    pi_addr            addr;
} pa_list;
#endif
struct imp_multi_rec
{
    unsigned char   rec_type;
    unsigned char   aux_len;
    unsigned short  src_num;
    struct in6_addr multi_addr;
    struct in6_addr src_list[0];
};

char* imp_inet_ntoa(unsigned long ip)
{
    static char buf[INET_ADDRSTRLEN * 10] = {0};
    static char *p = buf;
    char *res = NULL;
    struct in_addr sin;

    sin.s_addr = ip;

    memset(p, 0, INET_ADDRSTRLEN);
    strcpy(p, inet_ntoa(sin));
    res = p;

    p += INET_ADDRSTRLEN;
    if ((p - buf ) >= (INET_ADDRSTRLEN * 10))
        p = buf;

    return res;

}
char* imp_inet6_ntoa(unsigned char *in6)
{
    static char ipbuf[INET6_ADDRSTRLEN * 10];
    static char *ipStr = ipbuf;
    char *res;

    memset(ipStr, 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, in6, ipStr, INET6_ADDRSTRLEN);
    res = ipStr;

    ipStr += INET6_ADDRSTRLEN;
    if ((ipStr - ipbuf) >= INET6_ADDRSTRLEN * 10)
        ipStr = ipbuf;

    return res;

}

char *imp_pi_ntoa(pi_addr *p_pia)
{
    if (p_pia->ss.ss_family == AF_INET)
        return imp_inet_ntoa(p_pia->v4.sin_addr.s_addr);
    else if (p_pia->ss.ss_family == AF_INET6)
        return imp_inet6_ntoa(p_pia->v6.sin6_addr.s6_addr);
    else
        return "server error";
}
pa_list *pa_list_add(pa_list* p_head, pi_addr* p_addr)
{
    pa_list *p_new = NULL;
    if((p_new = malloc(sizeof(pa_list))) == NULL)
    {

        printf("malloc failed");
        return NULL;
    }

    memcpy(&p_new->addr, p_addr, sizeof(pi_addr));
    p_new->next = p_head;
    return p_new;
}

void pa_list_cleanup(pa_list **pp_head)
{
    pa_list *p_next = NULL;
    pa_list *p_head = *pp_head;
    for (; p_head; p_head = p_next)
    {
        p_next = p_head->next;
        free(p_head);
    }
    *pp_head = NULL;
    return;
}


static int imp_verify_multicast_addr(pi_addr *p_pia)
{

    if(p_pia->ss.ss_family == AF_INET6)
    {

        if (!IN6_IS_ADDR_MULTICAST(p_pia->v6.sin6_addr.s6_addr))
        {

            printf("Address %s isn't multicast address\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }
        /* Interface-Local scope spans only a single interface on a node
         * and is useful only for loopback transmission of multicast.
         *
         * Link-Local multicast scope spans the same topological region as
         * the corresponding unicast scope.
         * [RFC 4291 section 2.7]
         */

        if (IN6_IS_ADDR_MC_LINKLOCAL(p_pia->v6.sin6_addr.s6_addr) ||
                IN6_IS_ADDR_MC_NODELOCAL(p_pia->v6.sin6_addr.s6_addr))
        {

            printf("Group address %s is link-local multicast address\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }
        /*
         * Nodes must not originate a packet to a multicast address whose scop
         * field contains the reserved value 0; if such a packet is received, it
         * must be silently dropped.  Nodes should not originate a packet to a
         * multicast address whose scop field contains the reserved value F; if
         * such a packet is sent or received, it must be treated the same as
         * packets destined to a global (scop E) multicast address.
         * [RFC 4291 section 2.7]
         */
        if ((p_pia->v6.sin6_addr.s6_addr[1] & 0x0f) == 0)
        {

            printf("group address %s's scope is 0, Ignore it.\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }
    }
    else if(p_pia->ss.ss_family == AF_INET)
    {

        if (!IN_MULTICAST(ntohl(p_pia->v4.sin_addr.s_addr)))
        {

            printf("group address %s isn't multicast adddress\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }

        /*
         * Address Range                 Size       Designation
         * -------------                 ----       -----------
         * 224.0.0.0 - 224.0.0.255       (/24)      Local Network Control Block
         *
         * Addresses in the Local Network Control Block are used for protocol
         * control traffic that is not forwarded off link.
         * [RFC 5771 section 4]
         */
        if (IN_LOCAL_CONTROL_BLOCK(ntohl(p_pia->v4.sin_addr.s_addr)))
        {

            printf("Group address %s is Local Network Control Block\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }

        /* 239.255.0.0/16 is defined to be the IPv4 Local Scope.
         *   * [RFC 2365 section 6.1]
         *       */

        if (IN_LOCAL_SCOPE_BLOCK(ntohl(p_pia->v4.sin_addr.s_addr)))
        {

            printf("Group address %s belongs to IPv4 Local Scope.\n",
                   imp_pi_ntoa(p_pia));
            return -1;
        }


    }
    else
        return -1;

    return 0;
}

#if 1
void mld_v1_report(struct mld_sock *mld, struct mld_hdr *p_mldhr)
{

    pi_addr pig;

    imp_interface *p_if  ;
    p_if =imp_interface_find_by_name(mld->interface->name);
    if(p_if == NULL)
    {
        printf("imp interface %s not exist\n",mld->interface->name);
        return ;
    }
    imp_build_piaddr(AF_INET6, &p_mldhr->mld_addr, &pig);

    if (imp_verify_multicast_addr(&pig) < 0)
        return;

    printf("test %s\n", imp_pi_ntoa(&pig));

    switch (p_mldhr->mld_type)
    {
    case MLD_LISTENER_REPORT:
        mcast_is_ex_hander(p_if, &pig, NULL, IM_IGMPv2_MLDv1);
        break;
    case MLD_LISTENER_REDUCTION:
        mcast_to_in_handler(p_if, &pig, NULL, IM_IGMPv2_MLDv1);
        break;
    }
    imp_membership_db_update(&pig);
    return;
}

void mld_v2_report(struct mld_sock *mld, struct mld_hdr *p_mldh, int buf_len)
{
    int i = 0, num = 0, cur_len = 0;
    int ret = 0;
    pi_addr pig;
    //printf("in %s %d mld->interface->name = %s\n",__func__,__LINE__,mld->interface->name);
    imp_interface *p_if  ;
    p_if =imp_interface_find_by_name(mld->interface->name);
    if(p_if == NULL)
    {
        printf("imp interface %s not exist\n",mld->interface->name);
        return ;
    }
    //printf("in %s %d p_if->if_name = %s\n",__func__,__LINE__,p_if->if_name);

    num =  ntohs(p_mldh->mld_num_multi);
    cur_len += sizeof(struct icmp6_hdr);
    //printf("num = %d ,cur_len = %d\n",num,cur_len);

    for (; i < num; i++)
    {
        struct imp_multi_rec* p_rec = (struct imp_multi_rec*)((char*)p_mldh + cur_len);

        //struct in6_addr *p_src_list = NULL;
        struct pa_list *p_src_list = NULL;
        int k;

        imp_build_piaddr(AF_INET6, &p_rec->multi_addr, &pig);
        printf("group is = %s\n", imp_pi_ntoa(&pig));

        if (imp_verify_multicast_addr(&pig) < 0)
        {
            cur_len += sizeof(struct imp_multi_rec);
            continue;
        }

        cur_len += (ntohs(p_rec->src_num)*sizeof(struct in6_addr) +
                    sizeof(struct imp_multi_rec));

        if (cur_len > buf_len)
        {

            printf("exceed buffer\n");
            return;
        }

        for (k = 0; k < ntohs(p_rec->src_num); k++)
        {

            pi_addr pa;
            imp_build_piaddr(AF_INET6, &p_rec->src_list[k], &pa);
            p_src_list = pa_list_add(p_src_list, &pa);
        }

        switch (p_rec->rec_type)
        {
#if 1
        case MLD_MODE_IS_INCLUDE:
            printf(". MLD_MODE_IS_INCLUDE\n");
            mcast_is_in_handler(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
            break;
        case MLD_MODE_IS_EXCLUDE:
            printf(". MLD_MODE_IS_EXCLUDE\n");
            mcast_is_ex_hander(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
            break;
        case MLD_CHANGE_TO_INCLUDE:
            /*leave */
            printf(". MLD_CHANGE_TO_INCLUDE\n");
            mcast_to_in_handler(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
            //MLD_CANCEL_ADDR
            //mldv2_send_msg_to_pimsm(&(pig.v6.sin6_addr),mld->interface->ifindex,MLD_CANCEL_ADDR);
            break;
        case MLD_CHANGE_TO_EXCLUDE:
            /*join*/
            printf(". MLD_CHANGE_TO_EXCLUDE\n");
            ret = mcast_to_ex_hander(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
#if 0
            if(ret == 0)
            {
                mldv2_send_msg_to_pimsm(&(pig.v6.sin6_addr),mld->interface->ifindex,MLD_ADD_ADDR);
            }
#endif
            break;
        case MLD_ALLOW_NEW_SOURCES:
            printf(". MLD_ALLOW_NEW_SOURCES\n");
            mcast_allow_handler(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
            break;
        case MLD_BLOCK_OLD_SOURCES:
            printf(". MLD_BLOCK_OLD_SOURCES\n");
            mcast_block_handler(p_if, &pig, p_src_list, IM_IGMPv3_MLDv2);
            break;
        default:
            printf("error group type\n");
            pa_list_cleanup(&p_src_list);
            return;
#endif
        }
        imp_membership_db_update(&pig);
        pa_list_cleanup(&p_src_list);

    }
}
#endif
#endif
int pim_mld_packet(struct mld_sock *mld, char *buf, size_t len)
{

    struct mld_hdr  *p_mldh;
    p_mldh = (struct mld_hdr*)buf;

    switch (p_mldh->mld_type)
    {
    case MLD_LISTENER_REPORT:
    case MLD_LISTENER_REDUCTION:
        printf("MLDv1 report\n");
        mld_v1_report(mld, p_mldh);
        break;
    case MLD_V2_LISTENER_REPORT:
        mld_v2_report(mld, p_mldh, len);
        printf("MLDv2 report\n");
        break;
    default:
        printf("unknown type %d\n", p_mldh->mld_type);
        break;

    }
    return 0;
}
static int pim_igmp_general_query(struct thread *t);
static int pim_mld_general_query(struct thread *t);

void pim_igmp_general_query_on(struct igmp_sock *igmp)
{
    struct pim_interface *pim_ifp;
    int startup_mode;
    int query_interval;

    zassert(igmp);
    zassert(igmp->interface);

    /*
      Since this socket is starting as querier,
      there should not exist a timer for other-querier-present.
     */
    zassert(!igmp->t_other_querier_timer);
    pim_ifp = igmp->interface->info;
    zassert(pim_ifp);

    /*
      RFC 3376: 8.6. Startup Query Interval

      The Startup Query Interval is the interval between General Queries
      sent by a Querier on startup.  Default: 1/4 the Query Interval.
    */
    startup_mode = igmp->startup_query_count > 0;
    if (startup_mode)
    {
        --igmp->startup_query_count;

        /* query_interval = pim_ifp->igmp_default_query_interval >> 2; */
        query_interval = PIM_IGMP_SQI(pim_ifp->igmp_default_query_interval);
    }
    else
    {
        query_interval = igmp->querier_query_interval;
    }

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char ifaddr_str[100];
        pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
        zlog_debug("Querier %s scheduling %d-second (%s) TIMER event for IGMP query on fd=%d",
                   ifaddr_str,
                   query_interval,
                   startup_mode ? "startup" : "non-startup",
                   igmp->fd);
    }
    igmp->t_igmp_query_timer = 0;
    zassert(!igmp->t_igmp_query_timer);
    THREAD_TIMER_ON(master, igmp->t_igmp_query_timer,
                    pim_igmp_general_query,
                    igmp, query_interval);
}

void pim_mld_general_query_on(struct mld_sock *mld)
{
    struct mld_interface *pim_ifp;
    int startup_mode;
    int query_interval;

    zassert(mld);
    zassert(mld->interface);

    /*
      Since this socket is starting as querier,
      there should not exist a timer for other-querier-present.
     */
    zassert(!mld->t_other_querier_timer);
    pim_ifp = mld->interface->info;
    zassert(pim_ifp);

    /*
      RFC 3376: 8.6. Startup Query Interval

      The Startup Query Interval is the interval between General Queries
      sent by a Querier on startup.  Default: 1/4 the Query Interval.
    */
    startup_mode = mld->startup_query_count > 0;
    if (startup_mode)
    {
        --mld->startup_query_count;

        /* query_interval = pim_ifp->igmp_default_query_interval >> 2; */
        query_interval = PIM_IGMP_SQI(pim_ifp->mld_default_query_interval);
    }
    else
    {
        query_interval = mld->querier_query_interval;
    }

    /*if (PIM_DEBUG_IGMP_TRACE)*/
    {
        char ifaddr_str[100];
        pim_inet6_dump("<ifaddr?>", mld->ifaddr, ifaddr_str, sizeof(ifaddr_str));
        zlog_debug("Querier %s scheduling %d-second (%s) TIMER event for IGMP query on fd=%d",
                   ifaddr_str,
                   query_interval,
                   startup_mode ? "startup" : "non-startup",
                   mld->fd);
    }
    mld->t_mld_query_timer = 0;
    zassert(!mld->t_mld_query_timer);
    THREAD_TIMER_ON(master, mld->t_mld_query_timer,
                    pim_mld_general_query,
                    mld, query_interval);
}


void pim_mld_general_query_off(struct mld_sock *mld)
{
    THREAD_TIMER_OFF (mld->t_mld_query_timer);
}
void pim_igmp_general_query_off(struct igmp_sock *igmp)
{
    zassert(igmp);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        if (igmp->t_igmp_query_timer)
        {
            char ifaddr_str[100];
            pim_inet_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str, sizeof(ifaddr_str));
            zlog_debug("IGMP querier %s fd=%d cancelling query TIMER event on %s",
                       ifaddr_str, igmp->fd, igmp->interface->name);
        }
    }
    THREAD_OFF(igmp->t_igmp_query_timer);
    zassert(!igmp->t_igmp_query_timer);
}

/* Issue IGMP general query */
static int pim_igmp_general_query(struct thread *t)
{
    char   query_buf[PIM_IGMP_BUFSIZE_WRITE];
    struct igmp_sock *igmp;
    struct in_addr dst_addr;
    struct in_addr group_addr;
    struct pim_interface *pim_ifp;

    zassert(t);

    igmp = THREAD_ARG(t);

    zassert(igmp);
    zassert(igmp->interface);
    zassert(igmp->interface->info);

    pim_ifp = igmp->interface->info;

    /*
      RFC3376: 4.1.12. IP Destination Addresses for Queries

      In IGMPv3, General Queries are sent with an IP destination address
      of 224.0.0.1, the all-systems multicast address.  Group-Specific
      and Group-and-Source-Specific Queries are sent with an IP
      destination address equal to the multicast address of interest.
    */

    dst_addr.s_addr   = htonl(INADDR_ALLHOSTS_GROUP);
    group_addr.s_addr = PIM_NET_INADDR_ANY;

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char querier_str[100];
        char dst_str[100];
        pim_inet_dump("<querier?>", igmp->ifaddr, querier_str,
                      sizeof(querier_str));
        pim_inet_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
        zlog_debug("Querier %s issuing IGMP general query to %s on %s",
                   querier_str, dst_str, igmp->interface->name);
    }

    pim_igmp_send_membership_query(0 /* igmp_group */,
                                   igmp->fd,
                                   igmp->interface->name,
                                   query_buf,
                                   sizeof(query_buf),
                                   0 /* num_sources */,
                                   dst_addr,
                                   group_addr,
                                   pim_ifp->igmp_query_max_response_time_dsec,
                                   1 /* s_flag: always set for general queries */,
                                   igmp->querier_robustness_variable,
                                   igmp->querier_query_interval);

    pim_igmp_general_query_on(igmp);

    return 0;
}

/* Issue MLD general query */
static int pim_mld_general_query(struct thread *t)
{
    printf("%s %d\n",__func__,__LINE__);
    char   query_buf[PIM_IGMP_BUFSIZE_WRITE];
    struct mld_sock *mld;
    struct in6_addr dst_addr;
    struct in6_addr group_addr;
    struct mld_interface *pim_ifp;

    zassert(t);

    mld = THREAD_ARG(t);

    zassert(mld);
    zassert(mld->interface);
    zassert(mld->interface->info);

    pim_ifp = mld->interface->info;

    /*
      RFC3376: 4.1.12. IP Destination Addresses for Queries

      In IGMPv3, General Queries are sent with an IP destination address
      of 224.0.0.1, the all-systems multicast address.  Group-Specific
      and Group-and-Source-Specific Queries are sent with an IP
      destination address equal to the multicast address of interest.
    */

    //dst_addr.s_addr   = htonl(INADDR_ALLHOSTS_GROUP);
    inet_pton(AF_INET6, "ff02::1", &dst_addr);
    //group_addr.s_addr = PIM_NET_INADDR_ANY;
    inet_pton(AF_INET6, ":::", &dst_addr);

    /*if (PIM_DEBUG_IGMP_TRACE)*/
    {
        char querier_str[100];
        char dst_str[100];
        pim_inet6_dump("<querier?>", mld->ifaddr, querier_str,
                       sizeof(querier_str));
        pim_inet6_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
        zlog_debug("Querier %s issuing IGMP general query to %s on %s",
                   querier_str, dst_str, mld->interface->name);
    }

    pim_mld_send_membership_query(0 /* igmp_group */,
                                  mld->fd,
                                  mld->interface->name,
                                  query_buf,
                                  sizeof(query_buf),
                                  0 /* num_sources */,
                                  dst_addr,
                                  group_addr,
                                  pim_ifp->mld_query_max_response_time_dsec,
                                  1 /* s_flag: always set for general queries */,
                                  mld->querier_robustness_variable,
                                  mld->querier_query_interval);

    pim_mld_general_query_on(mld);

    return 0;
}
//static int pim_igmp_read(struct thread *t);
static int pim_mld_read(struct thread *t);
#if 0
static void igmp_read_on(struct igmp_sock *igmp)
{
    zassert(igmp);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_debug("Scheduling READ event on IGMP socket fd=%d",
                   igmp->fd);
    }
    igmp->t_igmp_read = 0;
    zassert(!igmp->t_igmp_read);
    THREAD_READ_ON(master, igmp->t_igmp_read, pim_igmp_read, igmp, igmp->fd);
}
#endif
static void mld_read_on(struct mld_sock *mld)
{
    zassert(mld);

    /*if (PIM_DEBUG_IGMP_TRACE)*/
    {
        zlog_debug("Scheduling READ event on mld socket fd=%d",
                   mld->fd);
    }
    mld->t_mld_read = 0;
    zassert(!mld->t_mld_read);
    THREAD_READ_ON(master, mld->t_mld_read, pim_mld_read, mld, mld->fd);
    //printf("THREAD_READ_ON pim_mld_read OK\n");
}


#if 0
static int pim_igmp_read(struct thread *t)
{
    struct igmp_sock *igmp;
    int fd;
    struct sockaddr_in from;
    struct sockaddr_in to;
    socklen_t fromlen = sizeof(from);
    socklen_t tolen = sizeof(to);
    uint8_t buf[PIM_IGMP_BUFSIZE_READ];
    int len;
    int ifindex = -1;
    int result = -1; /* defaults to bad */

    zassert(t);

    igmp = THREAD_ARG(t);

    zassert(igmp);

    fd = THREAD_FD(t);

    zassert(fd == igmp->fd);

    //len = pim_socket_recvfromto(fd, buf, sizeof(buf),
    len = pimsm_socket_recvfromto(fd, buf, sizeof(buf),
                                  &from, &fromlen,
                                  &to, &tolen,
                                  &ifindex);
    if (len < 0)
    {
        zlog_warn("Failure receiving IP IGMP packet on fd=%d: errno=%d: %s",
                  fd, errno, safe_strerror(errno));
        goto done;
    }
    if (PIM_DEBUG_IGMP_PACKETS)
    {
        char from_str[100];
        char to_str[100];

        if (!inet_ntop(AF_INET, &from.sin_addr, from_str, sizeof(from_str)))
            sprintf(from_str, "<from?>");
        if (!inet_ntop(AF_INET, &to.sin_addr, to_str, sizeof(to_str)))
            sprintf(to_str, "<to?>");

        zlog_debug("Recv IP IGMP pkt size=%d from %s to %s on fd=%d on ifindex=%d (sock_ifindex=%d)",
                   len, from_str, to_str, fd, ifindex, igmp->interface->ifindex);
    }

#ifdef PIM_CHECK_RECV_IFINDEX_SANITY
    /* ifindex sanity check */
    if (ifindex != (int) igmp->interface->ifindex)
    {
        char from_str[100];
        char to_str[100];
        struct interface *ifp;

        if (!inet_ntop(AF_INET, &from.sin_addr, from_str , sizeof(from_str)))
            sprintf(from_str, "<from?>");
        if (!inet_ntop(AF_INET, &to.sin_addr, to_str , sizeof(to_str)))
            sprintf(to_str, "<to?>");

        ifp = if_lookup_by_index(ifindex);
        if (ifp)
        {
            zassert(ifindex == (int) ifp->ifindex);
        }

#ifdef PIM_REPORT_RECV_IFINDEX_MISMATCH
        zlog_warn("Interface mismatch: recv IGMP pkt from %s to %s on fd=%d: recv_ifindex=%d (%s) sock_ifindex=%d (%s)",
                  from_str, to_str, fd,
                  ifindex, ifp ? ifp->name : "<if-notfound>",
                  igmp->interface->ifindex, igmp->interface->name);
#endif
        goto done;
    }
#endif

    if (pim_igmp_packet(igmp, (char *)buf, len))
    {
        goto done;
    }

    result = 0; /* good */

done:
    igmp_read_on(igmp);

    return result;
}
#endif
static int pim_mld_read(struct thread *t)
{
    printf("%s %d ----- in pim mld read\n",__func__,__LINE__);
    fflush(stdout);
    struct mld_sock *mld;
    int fd;
    struct sockaddr_in6 from;
    struct sockaddr_in6 to;
    socklen_t fromlen = sizeof(from);
    socklen_t tolen = sizeof(to);
    uint8_t buf[PIM_IGMP_BUFSIZE_READ];
    int len;
    int ifindex = -1;
    int result = -1; /* defaults to bad */

    zassert(t);

    mld = THREAD_ARG(t);

    zassert(mld);

    fd = THREAD_FD(t);

    zassert(fd == mld->fd);

    //len = pim_socket_recvfromto(fd, buf, sizeof(buf),
    len = pimsm_socket_recvfromto(fd, buf, sizeof(buf),
                                  &from, &fromlen,
                                  &to, &tolen,
                                  &ifindex);
    if (len < 0)
    {
        zlog_warn("Failure receiving IP IGMP packet on fd=%d: errno=%d: %s",
                  fd, errno, safe_strerror(errno));
        goto done;
    }
    //if (PIM_DEBUG_IGMP_PACKETS)
    {
        char from_str[100];
        char to_str[100];

        if (!inet_ntop(AF_INET6, &from.sin6_addr, from_str, sizeof(from_str)))
            sprintf(from_str, "<from?>");
        if (!inet_ntop(AF_INET6, &to.sin6_addr, to_str, sizeof(to_str)))
            sprintf(to_str, "<to?>");

        zlog_debug("Recv IP IGMP pkt size=%d from %s to %s on fd=%d on ifindex=%d (sock_ifindex=%d)",
                   len, from_str, to_str, fd, ifindex, mld->interface->ifindex);
    }

#ifdef PIM_CHECK_RECV_IFINDEX_SANITY
#if 1
    /* ifindex sanity check */
    printf("ifindex = %d,(int) mld->interface->ifindex = %d\n",ifindex,(int) mld->interface->ifindex);
    if (ifindex != (int) mld->interface->ifindex)
    {
#if 1
        char from_str[100];
        char to_str[100];
        struct interface *ifp;

        if (!inet_ntop(AF_INET6, &from.sin6_addr, from_str , sizeof(from_str)))
            sprintf(from_str, "<from?>");
        if (!inet_ntop(AF_INET6, &to.sin6_addr, to_str , sizeof(to_str)))
            sprintf(to_str, "<to?>");

        ifp = if_lookup_by_index(ifindex);
        if (ifp)
        {
            zassert(ifindex == (int) ifp->ifindex);
        }

//#ifdef PIM_REPORT_RECV_IFINDEX_MISMATCH
        zlog_warn("Interface mismatch: recv IGMP pkt from %s to %s on fd=%d: recv_ifindex=%d (%s) sock_ifindex=%d (%s)",
                  from_str, to_str, fd,
                  ifindex, ifp ? ifp->name : "<if-notfound>",
                  mld->interface->ifindex, mld->interface->name);
//#endif

#endif
        goto done;
    }
#endif

#endif

    if (pim_mld_packet(mld, (char *)buf, len))
    {
        goto done;
    }

    result = 0; /* good */

done:
    mld_read_on(mld);

    return result;
}
#if 0
static void sock_close(struct igmp_sock *igmp)
{
    pim_igmp_other_querier_timer_off(igmp);
    pim_igmp_general_query_off(igmp);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        if (igmp->t_igmp_read)
        {
            zlog_debug("Cancelling READ event on IGMP socket %s fd=%d on interface %s",
                       inet_ntoa(igmp->ifaddr), igmp->fd,
                       igmp->interface->name);
        }
    }
    THREAD_OFF(igmp->t_igmp_read);
    zassert(!igmp->t_igmp_read);

    if (close(igmp->fd))
    {
        zlog_err("Failure closing IGMP socket %s fd=%d on interface %s: errno=%d: %s",
                 inet_ntoa(igmp->ifaddr), igmp->fd, igmp->interface->name,
                 errno, safe_strerror(errno));
    }

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_debug("Deleted IGMP socket %s fd=%d on interface %s",
                   inet_ntoa(igmp->ifaddr), igmp->fd, igmp->interface->name);
    }
}
#endif
static void sock_close(struct mld_sock *mld)
{
    pim_mld_other_querier_timer_off(mld);
    pim_mld_general_query_off(mld);

    //if (PIM_DEBUG_MLD_TRACE)
    {
        if (mld->t_mld_read)
        {
            zlog_debug("Cancelling READ event on MLD socket %s fd=%d on interface %s",
                       inet6_ntoa(mld->ifaddr), mld->fd,
                       mld->interface->name);
        }
    }
    THREAD_OFF(mld->t_mld_read);
    zassert(!mld->t_mld_read);

    if (close(mld->fd))
    {
        zlog_err("Failure closing MLD socket %s fd=%d on interface %s: errno=%d: %s",
                 inet6_ntoa(mld->ifaddr), mld->fd, mld->interface->name,
                 errno, safe_strerror(errno));
    }

    //if (PIM_DEBUG_MLD_TRACE)
    {
        zlog_debug("Deleted MLD socket %s fd=%d on interface %s",
                   inet6_ntoa(mld->ifaddr), mld->fd, mld->interface->name);
    }
}
void igmp_startup_mode_on(struct igmp_sock *igmp)
{
    struct pim_interface *pim_ifp;

    pim_ifp = igmp->interface->info;

    /*
      RFC 3376: 8.7. Startup Query Count

      The Startup Query Count is the number of Queries sent out on
      startup, separated by the Startup Query Interval.  Default: the
      Robustness Variable.
    */
    igmp->startup_query_count = igmp->querier_robustness_variable;

    /*
      Since we're (re)starting, reset QQI to default Query Interval
    */
    igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
}
static void mld_startup_mode_on(struct mld_sock *mld)
{
    struct mld_interface *pim_ifp;

    pim_ifp = mld->interface->info;

    /*
      RFC 3376: 8.7. Startup Query Count

      The Startup Query Count is the number of Queries sent out on
      startup, separated by the Startup Query Interval.  Default: the
      Robustness Variable.
    */
    mld->startup_query_count = mld->querier_robustness_variable;

    /*
      Since we're (re)starting, reset QQI to default Query Interval
    */
    mld->querier_query_interval = pim_ifp->mld_default_query_interval;
}

static void igmp_group_free(struct igmp_group *group)
{
    zassert(!group->t_group_query_retransmit_timer);
    zassert(!group->t_group_timer);
    zassert(group->group_source_list);
    zassert(!listcount(group->group_source_list));

    list_free(group->group_source_list);

    XFREE(MTYPE_PIM_IGMP_GROUP, group);
}

static void mld_group_free(struct mld_group *group)
{
    zassert(!group->t_group_query_retransmit_timer);
    zassert(!group->t_group_timer);
    zassert(group->group_source_list);
    zassert(!listcount(group->group_source_list));

    list_free(group->group_source_list);

    XFREE(MTYPE_PIM_IGMP_GROUP, group);
}

static void igmp_group_delete(struct igmp_group *group)
{
    struct listnode *src_node;
    struct listnode *src_nextnode;
    struct igmp_source *src;

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group->group_addr, group_str, sizeof(group_str));
        zlog_debug("Deleting IGMP group %s from socket %d interface %s",
                   group_str,
                   group->group_igmp_sock->fd,
                   group->group_igmp_sock->interface->name);
    }

    for (ALL_LIST_ELEMENTS(group->group_source_list, src_node, src_nextnode, src))
    {
        igmp_source_delete(src);
    }

    if (group->t_group_query_retransmit_timer)
    {
        THREAD_OFF(group->t_group_query_retransmit_timer);
        zassert(!group->t_group_query_retransmit_timer);
    }

    group_timer_off(group);
    struct in_addr *group_addr = &(group->group_addr);
    //uint32_t igmp_version = 3;
    uint32_t igmp_version = igmp_group_compat_mode(group->group_igmp_sock, group);
    printf("igmp_version = %d\n",igmp_version);
    switch(igmp_version)
    {
    case IGMP_VERSION_1:
        igmpv1_send_msg_to_pimsm(group_addr,ifname2ifindex(group->group_igmp_sock->interface->name),MLD_CANCEL_ADDR);
        break;
    case IGMP_VERSION_2:
        igmpv2_send_msg_to_pimsm(group_addr,ifname2ifindex(group->group_igmp_sock->interface->name),MLD_CANCEL_ADDR);
        break;
    case IGMP_VERSION_3:
        igmpv3_send_msg_to_pimsm(group_addr,ifname2ifindex(group->group_igmp_sock->interface->name),MLD_CANCEL_ADDR);
        break;
    default :
        printf("unknow igmp version\n");
        break;
    }
    listnode_delete(group->group_igmp_sock->igmp_group_list, group);
    igmp_group_free(group);
}

void igmp_group_delete_empty_include(struct igmp_group *group)
{
    zassert(!group->group_filtermode_isexcl);
    zassert(!listcount(group->group_source_list));

    igmp_group_delete(group);
}

void mld_sock_free(struct mld_sock *mld)
{
    zassert(!mld->t_mld_read);
    zassert(!mld->t_mld_query_timer);
    zassert(!mld->t_other_querier_timer);
    zassert(mld->mld_group_list);
    zassert(!listcount(mld->mld_group_list));

    list_free(mld->mld_group_list);

    XFREE(MTYPE_PIM_IGMP_SOCKET, mld);

}
void igmp_sock_free(struct igmp_sock *igmp)
{
    zassert(!igmp->t_igmp_read);
    zassert(!igmp->t_igmp_query_timer);
    zassert(!igmp->t_other_querier_timer);
    zassert(igmp->igmp_group_list);
    zassert(!listcount(igmp->igmp_group_list));

    list_free(igmp->igmp_group_list);

    XFREE(MTYPE_PIM_IGMP_SOCKET, igmp);
}
#if 0
void igmp_sock_delete(struct igmp_sock *igmp)
{
    struct pim_interface *pim_ifp;
    struct listnode      *grp_node;
    struct listnode      *grp_nextnode;
    struct igmp_group    *grp;
    uint32_t igmp_version ;

    for (ALL_LIST_ELEMENTS(igmp->igmp_group_list, grp_node, grp_nextnode, grp))
    {
        igmp_version = igmp_group_compat_mode(igmp, grp);
        printf("in igmp_sock_delete igmp_version = %d\n",igmp_version);

        igmp_group_delete(grp);
    }

    sock_close(igmp);

    pim_ifp = igmp->interface->info;

    listnode_delete(pim_ifp->igmp_socket_list, igmp);

    igmp_sock_free(igmp);
}
#endif
void mld_sock_delete(struct mld_sock *mld)
{
    struct mld_interface *pim_ifp;
#if 0
    struct listnode      *grp_node;
    struct listnode      *grp_nextnode;
    struct mld_group    *grp;
    uint32_t mld_version ;
#endif
#if 0
    for (ALL_LIST_ELEMENTS(mld->igmp_group_list, grp_node, grp_nextnode, grp))
    {
        igmp_version = igmp_group_compat_mode(igmp, grp);
        printf("in igmp_sock_delete igmp_version = %d\n",igmp_version);

        igmp_group_delete(grp);
    }
#endif

    sock_close(mld);

    pim_ifp = mld->interface->info;

    listnode_delete(pim_ifp->mld_socket_list, mld);
    mld_sock_free(mld);
}


#if 0
static struct igmp_sock *igmp_sock_new(int fd,
                                       struct in_addr ifaddr,
                                       struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct igmp_sock *igmp;

    pim_ifp = ifp->info;

    if (PIM_DEBUG_IGMP_TRACE)
    {
        zlog_debug("Creating IGMP socket fd=%d for address %s on interface %s",
                   fd, inet_ntoa(ifaddr), ifp->name);
    }

    igmp = XMALLOC(MTYPE_PIM_IGMP_SOCKET, sizeof(*igmp));
    if (!igmp)
    {
        zlog_warn("%s %s: XMALLOC() failure",
                  __FILE__, __PRETTY_FUNCTION__);
        return 0;
    }

    igmp->igmp_group_list = list_new();
    if (!igmp->igmp_group_list)
    {
        zlog_err("%s %s: failure: igmp_group_list = list_new()",
                 __FILE__, __PRETTY_FUNCTION__);
        return 0;
    }
    igmp->igmp_group_list->del = (void (*)(void *)) igmp_group_free;

    igmp->fd                          = fd;
    igmp->interface                   = ifp;
    igmp->ifaddr                      = ifaddr;
    igmp->t_igmp_read                 = 0;
    igmp->t_igmp_query_timer          = 0;
    igmp->t_other_querier_timer       = 0; /* no other querier present */
    igmp->querier_robustness_variable = pim_ifp->igmp_default_robustness_variable;
    igmp->sock_creation               = pim_time_monotonic_sec();

    /*
      igmp_startup_mode_on() will reset QQI:

      igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
    */
    igmp_startup_mode_on(igmp);

    igmp_read_on(igmp);
    pim_igmp_general_query_on(igmp);

    return igmp;
}
#endif

static struct mld_sock *mld_sock_new(int fd,
                                     struct in6_addr ifaddr,
                                     struct interface *ifp)
{
    printf("%s %d \n",__func__,__LINE__);
    struct mld_interface *pim_ifp;
    struct mld_sock *mld;

    pim_ifp = ifp->info;

    /*if (PIM_DEBUG_IGMP_TRACE)*/
    {
        zlog_debug("Creating mld socket fd=%d for address %s on interface %s",
                   fd, inet6_ntoa(ifaddr), ifp->name);
    }

    mld = XMALLOC(MTYPE_PIM_IGMP_SOCKET, sizeof(*mld));
    if (!mld)
    {
        zlog_warn("%s %s: XMALLOC() failure",
                  __FILE__, __PRETTY_FUNCTION__);
        return 0;
    }
    printf("%s %d \n",__func__,__LINE__);

    mld->mld_group_list = list_new();
    if (!mld->mld_group_list)
    {
        zlog_err("%s %s: failure: mld_group_list = list_new()",
                 __FILE__, __PRETTY_FUNCTION__);
        return 0;
    }
    printf("%s %d \n",__func__,__LINE__);
    mld->mld_group_list->del = (void (*)(void *)) mld_group_free;

    mld->fd                          = fd;
    mld->interface                   = ifp;
    mld->ifaddr                      = ifaddr;
    mld->t_mld_read                 = 0;
    mld->t_mld_query_timer          = 0;
    mld->t_other_querier_timer       = 0; /* no other querier present */
    mld->querier_robustness_variable = pim_ifp->mld_default_robustness_variable;
    mld->sock_creation               = pim_time_monotonic_sec();

    /*
      igmp_startup_mode_on() will reset QQI:

      igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
    */
    mld_startup_mode_on(mld);

    mld_read_on(mld);
    pim_mld_general_query_on(mld);
    printf("%s %d \n",__func__,__LINE__);

    return mld;
}


#if 0
struct igmp_sock *pim_igmp_sock_add(struct list *igmp_sock_list,
                                    struct in_addr ifaddr,
                                    struct interface *ifp)
{
    struct pim_interface *pim_ifp;
    struct igmp_sock *igmp;
    int fd;

    pim_ifp = ifp->info;

    fd = igmp_sock_open(ifaddr, ifp->ifindex, pim_ifp->options);
    if (fd < 0)
    {
        zlog_warn("Could not open IGMP socket for %s on %s",
                  inet_ntoa(ifaddr), ifp->name);
        return 0;
    }

    igmp = igmp_sock_new(fd, ifaddr, ifp);
    if (!igmp)
    {
        zlog_err("%s %s: igmp_sock_new() failure",
                 __FILE__, __PRETTY_FUNCTION__);
        close(fd);
        return 0;
    }

    listnode_add(igmp_sock_list, igmp);

#ifdef IGMP_SOCK_DUMP
    igmp_sock_dump(igmp_sock_array);
#endif

    return igmp;
}
#endif
#if 1
struct mld_sock *pim_mld_sock_add(struct list *mld_sock_list,
                                  struct in6_addr ifaddr,
                                  struct interface *ifp)
{
    struct mld_interface *pim_ifp;
    struct mld_sock *mld;
    int fd;

    pim_ifp = ifp->info;

#if 1
    //fd = mld_sock_open(ifaddr, ifp->ifindex, pim_ifp->options);
    //fd = icmp6_sock_init();
    //fd = mld_sock_init();
    fd = pimsm_socket_mcast(IPPROTO_ICMPV6,ifp->ifindex,0);
    if(fd< 0 )
        return NULL;

    struct in6_addr all_ipv6_router;
    if(inet_pton(AF_INET6, "FF02::16", &all_ipv6_router) == 1)
    {

        pi_addr pir;
        imp_build_piaddr(AF_INET6, &all_ipv6_router, &pir);
        if (pimsm_socket_join(fd, all_ipv6_router, ifaddr, ifp->ifindex))
        {
            return NULL;
        }

    }
    if (fd < 0)
    {
        zlog_warn("Could not open mld socket for %s on %s",
                  inet6_ntoa(ifaddr), ifp->name);
        return 0;
    }
    printf("%s %d fd = %d\n",__func__,__LINE__,fd);
#endif

#if 1
    mld = mld_sock_new(fd, ifaddr, ifp);
    if (!mld)
    {
        zlog_err("%s %s: mld_sock_new() failure",
                 __FILE__, __PRETTY_FUNCTION__);
        close(fd);
        return 0;
    }
#endif

    listnode_add(mld_sock_list, mld);

#ifdef MLD_SOCK_DUMP
    mld_sock_dump(mld_sock_array);
#endif

    return mld;
}
#endif



/*
  RFC 3376: 6.5. Switching Router Filter-Modes

  When a router's filter-mode for a group is EXCLUDE and the group
  timer expires, the router filter-mode for the group transitions to
  INCLUDE.

  A router uses source records with running source timers as its state
  for the switch to a filter-mode of INCLUDE.  If there are any source
  records with source timers greater than zero (i.e., requested to be
  forwarded), a router switches to filter-mode of INCLUDE using those
  source records.  Source records whose timers are zero (from the
  previous EXCLUDE mode) are deleted.
 */
static int igmp_group_timer(struct thread *t)
{
    struct igmp_group *group;

    zassert(t);
    group = THREAD_ARG(t);
    zassert(group);

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group->group_addr, group_str, sizeof(group_str));
        zlog_debug("%s: Timer for group %s on interface %s",
                   __PRETTY_FUNCTION__,
                   group_str, group->group_igmp_sock->interface->name);
    }

    zassert(group->group_filtermode_isexcl);

    group->t_group_timer = 0;
    group->group_filtermode_isexcl = 0;

    /* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
    igmp_anysource_forward_stop(group);

    igmp_source_delete_expired(group->group_source_list);

    zassert(!group->t_group_timer);
    zassert(!group->group_filtermode_isexcl);

    /*
      RFC 3376: 6.2.2. Definition of Group Timers

      If there are no more source records for the group, delete group
      record.
    */
    if (listcount(group->group_source_list) < 1)
    {
        igmp_group_delete_empty_include(group);
    }

    return 0;
}

static void group_timer_off(struct igmp_group *group)
{
    if (!group->t_group_timer)
        return;

    if (PIM_DEBUG_IGMP_TRACE)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group->group_addr, group_str, sizeof(group_str));
        zlog_debug("Cancelling TIMER event for group %s on %s",
                   group_str, group->group_igmp_sock->interface->name);
    }

    THREAD_OFF(group->t_group_timer);
    zassert(!group->t_group_timer);
}

void igmp_group_timer_on(struct igmp_group *group,
                         long interval_msec, const char *ifname)
{
    group_timer_off(group);

    if (PIM_DEBUG_IGMP_EVENTS)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group->group_addr, group_str, sizeof(group_str));
        zlog_debug("Scheduling %ld.%03ld sec TIMER event for group %s on %s",
                   interval_msec / 1000,
                   interval_msec % 1000,
                   group_str, ifname);
    }

    /*
      RFC 3376: 6.2.2. Definition of Group Timers

      The group timer is only used when a group is in EXCLUDE mode and
      it represents the time for the *filter-mode* of the group to
      expire and switch to INCLUDE mode.
    */
    zassert(group->group_filtermode_isexcl);

    THREAD_TIMER_MSEC_ON(master, group->t_group_timer,
                         igmp_group_timer,
                         group, interval_msec);
}

static struct igmp_group *find_group_by_addr(struct igmp_sock *igmp,
        struct in_addr group_addr)
{
    struct igmp_group *group;
    struct listnode   *node;

    for (ALL_LIST_ELEMENTS_RO(igmp->igmp_group_list, node, group))
        if (group_addr.s_addr == group->group_addr.s_addr)
            return group;

    return 0;
}


static int igmpv1_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{

    MLD_MSG *pstMsgToPim = NULL;
    GROUPLIST *pstGroupList = NULL;

    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    MLD_WriteMsgHeadToPim(pstMsgToPim, msg_type, 1,ifindex, IGMP_VERSION_1);/*IGMP version Ðè´«²Î*/
    pstGroupList = (GROUPLIST *)malloc(sizeof(GROUPLIST));
    memset(pstGroupList, 0, sizeof(GROUPLIST));
    pstGroupList->stGrAddr = *((VOS_IPV6_ADDR *)(group_addr));
    pstGroupList->pstNext = pstMsgToPim->u_msg.mIGMPv1ToPim.pstGrHead;
    pstMsgToPim->u_msg.mIGMPv1ToPim.pstGrHead = pstGroupList;

    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);

    return 0;
}

static int igmpv2_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{
    MLD_MSG *pstMsgToPim = NULL;
    GROUPLIST *pstGroupList = NULL;

    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    MLD_WriteMsgHeadToPim(pstMsgToPim, msg_type, 1,ifindex, IGMP_VERSION_2);/*IGMP version Ðè´«²Î*/
    pstGroupList = (GROUPLIST *)malloc(sizeof(GROUPLIST));
    memset(pstGroupList, 0, sizeof(GROUPLIST));
    //pstGroupList->stGrAddr = *group;
    pstGroupList->stGrAddr = *((VOS_IPV6_ADDR *)(group_addr));

    pstGroupList->pstNext = pstMsgToPim->u_msg.mMldv1ToPim.pstGrHead;
    pstMsgToPim->u_msg.mMldv1ToPim.pstGrHead = pstGroupList;

    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);

    return 0;
}

static int igmpv3_send_msg_to_pimsm(struct in_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{
#if 0
    m_Mldv2ToPim6_t *pstMldv2ToPim = NULL;
    MLDv2_RECORDLIST *pstRecordToPim = NULL;
    MLDv2_MULTICASTADDRLIST *pstMldv2GroupInfo  = NULL;
    unsigned short wSourceNum;
    SOURLIST  *pstSourceListHead  = NULL;
    MLD_MSG *pstMsgToPim = NULL;
    GROUPLIST *pstGroupList = NULL;

    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    MLD_WriteMsgHeadToPim(pstMsgToPim, msg_type, 1,ifindex, IGMP_VERSION_3);/*IGMP version Ðè´«²Î*/

    pstMldv2ToPim = &(pstMsgToPim->u_msg.mMldv2ToPim);
    pstRecordToPim = (MLDv2_RECORDLIST *)malloc(sizeof(MLDv2_RECORDLIST));
    memset(pstRecordToPim, 0, sizeof(MLDv2_RECORDLIST));
    //pstRecordToPim->stMulticastAddr = pstMldv2GroupInfo->stMulticastAddr;
    pstRecordToPim->stMulticastAddr =  *((VOS_IPV6_ADDR *)(group_addr));

    //pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_INCLUDE;
    pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_EXCLUDE;


    //pstRecordToPim->wSourAddrNum = wSourceNum;
    pstRecordToPim->pstNext = NULL;
    //pstRecordToPim->pstSourAddrHead = pstSourceListHead;
    pstMldv2ToPim->pstRecordToPimHead = pstRecordToPim;

    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);

#endif
    return 0;
}

#define MLD_VERSION_1               1
#define MLD_VERSION_2               2
int mldv1_send_msg_to_pimsm(struct in6_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{
    return 0;
}
#if 0
int mldv2_send_msg_to_pimsm(struct in6_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{
#if 1
    m_Mldv2ToPim6_t *pstMldv2ToPim = NULL;
    MLDv2_RECORDLIST *pstRecordToPim = NULL;
#if 0
    MLDv2_MULTICASTADDRLIST *pstMldv2GroupInfo  = NULL;
    unsigned short wSourceNum;
    SOURLIST  *pstSourceListHead  = NULL;
#endif
    MLD_MSG *pstMsgToPim = NULL;
#if 0
    GROUPLIST *pstGroupList = NULL;
#endif

    printf("malloc : sizeof(MLD_MSG) = %ld\n",sizeof(MLD_MSG));
#if 1
    MLD_MSG mld_msg;
    pstMsgToPim = &mld_msg;
    //char *p = malloc(10);
#else
    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    if(pstMsgToPim == NULL)
    {
        printf("%s %d malloc fail\n",__func__,__LINE__);
        return -1;
    }
    else
    {

        printf("%s %d malloc OK\n",__func__,__LINE__);
    }
#endif

    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    MLD_WriteMsgHeadToPim(pstMsgToPim, msg_type, 1,ifindex, MLD_VERSION_2);

    pstMldv2ToPim = &(pstMsgToPim->u_msg.mMldv2ToPim);
    printf("----sizeof(MLDv2_RECORDLIST) = %ld----\n",sizeof(MLDv2_RECORDLIST));
#if 1
    MLDv2_RECORDLIST mld_recordlist;
    pstRecordToPim = &mld_recordlist;
#else

    pstRecordToPim = (MLDv2_RECORDLIST *)malloc(sizeof(MLDv2_RECORDLIST));
#endif
    memset(pstRecordToPim, 0, sizeof(MLDv2_RECORDLIST));
    //pstRecordToPim->stMulticastAddr = pstMldv2GroupInfo->stMulticastAddr;

    memcpy(&(pstRecordToPim->stMulticastAddr),(group_addr),sizeof(struct in6_addr));


    //pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_INCLUDE;
    pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_EXCLUDE;


    pstRecordToPim->pstNext = NULL;

#if 0
    pstRecordToPim->wSourAddrNum = 1;
    PIMSM_ADDR_LIST_NODE_IPV6_T any_src_addr_list;
    memset(&any_src_addr_list,0,sizeof(PIMSM_ADDR_LIST_NODE_IPV6_T));
    any_src_addr_list.pstNext = NULL;
    pstRecordToPim->pstSourAddrHead = &any_src_addr_list;
#endif

    pstMldv2ToPim->pstRecordToPimHead = pstRecordToPim;

    //pimsm_MsgProcMld((PIMSM_MSG_T *)pstMsgToPim);
    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);
#if 0
    if(pstMsgToPim != NULL)
        free(pstMsgToPim);
#endif
#endif
    return 0;
}

#endif

int mldv2_send_msg_to_pimsm(struct in6_addr *group_addr,uint32_t ifindex,uint32_t msg_type)
{
#if 1
    m_Mldv2ToPim6_t *pstMldv2ToPim = NULL;
    MLDv2_RECORDLIST *pstRecordToPim = NULL;
#if 1
    MLDv2_MULTICASTADDRLIST *pstMldv2GroupInfo  = NULL;
    unsigned short wSourceNum;
    SOURLIST  *pstSourceListHead  = NULL;
#endif
    MLD_MSG *pstMsgToPim = NULL;
#if 1
    GROUPLIST *pstGroupList = NULL;
#endif

    printf("malloc : sizeof(MLD_MSG) = %ld\n",sizeof(MLD_MSG));
#if 0
    MLD_MSG mld_msg;
    pstMsgToPim = &mld_msg;
#else
    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    if(pstMsgToPim == NULL)
    {
        printf("%s %d malloc fail\n",__func__,__LINE__);
        return -1;
    }
    else
    {

        printf("%s %d malloc OK\n",__func__,__LINE__);
    }
#endif

    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    MLD_WriteMsgHeadToPim(pstMsgToPim, msg_type, 1,ifindex, MLD_VERSION_2);
    pstMldv2ToPim = &(pstMsgToPim->u_msg.mMldv2ToPim);
    printf("----sizeof(MLDv2_RECORDLIST) = %ld----\n",sizeof(MLDv2_RECORDLIST));
#if 0
    MLDv2_RECORDLIST mld_recordlist;
    pstRecordToPim = &mld_recordlist;
#else

    pstRecordToPim = (MLDv2_RECORDLIST *)malloc(sizeof(MLDv2_RECORDLIST));
#endif
    memset(pstRecordToPim, 0, sizeof(MLDv2_RECORDLIST));
    //pstRecordToPim->stMulticastAddr = pstMldv2GroupInfo->stMulticastAddr;

    memcpy(&(pstRecordToPim->stMulticastAddr),(group_addr),sizeof(struct in6_addr));


    //pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_INCLUDE;
    pstRecordToPim->wFilterMode = MLDv2_FILTER_MODE_EXCLUDE;


    pstRecordToPim->pstNext = NULL;

#if 0
    pstRecordToPim->wSourAddrNum = 1;
    PIMSM_ADDR_LIST_NODE_IPV6_T any_src_addr_list;
    memset(&any_src_addr_list,0,sizeof(PIMSM_ADDR_LIST_NODE_IPV6_T));
    any_src_addr_list.pstNext = NULL;
    pstRecordToPim->pstSourAddrHead = &any_src_addr_list;
#endif

    pstMldv2ToPim->pstRecordToPimHead = pstRecordToPim;

    //pimsm_MsgProcMld((PIMSM_MSG_T *)pstMsgToPim);
    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);
#if 0
    if(pstMsgToPim != NULL)
        free(pstMsgToPim);
#endif
#endif
    return 0;
}




struct igmp_group *igmp_add_group_by_addr(struct igmp_sock *igmp,
        struct in_addr group_addr,
        const char *ifname)
{
    struct igmp_group *group;

    group = find_group_by_addr(igmp, group_addr);
    if (group)
    {
        return group;
    }

    /*
      Non-existant group is created as INCLUDE {empty}:

      RFC 3376 - 5.1. Action on Change of Interface State

      If no interface state existed for that multicast address before
      the change (i.e., the change consisted of creating a new
      per-interface record), or if no state exists after the change
      (i.e., the change consisted of deleting a per-interface record),
      then the "non-existent" state is considered to have a filter mode
      of INCLUDE and an empty source list.
    */

    group = XMALLOC(MTYPE_PIM_IGMP_GROUP, sizeof(*group));
    if (!group)
    {
        zlog_warn("%s %s: XMALLOC() failure",
                  __FILE__, __PRETTY_FUNCTION__);
        return 0; /* error, not found, could not create */
    }

    group->group_source_list = list_new();
    if (!group->group_source_list)
    {
        zlog_warn("%s %s: list_new() failure",
                  __FILE__, __PRETTY_FUNCTION__);
        XFREE(MTYPE_PIM_IGMP_GROUP, group); /* discard group */
        return 0; /* error, not found, could not initialize */
    }
    group->group_source_list->del = (void (*)(void *)) igmp_source_free;

    group->t_group_timer                         = 0;
    group->t_group_query_retransmit_timer        = 0;
    group->group_specific_query_retransmit_count = 0;
    group->group_addr                            = group_addr;
    group->group_igmp_sock                       = igmp;
    group->last_igmp_v1_report_dsec              = -1;
    group->last_igmp_v2_report_dsec              = -1;
    group->group_creation                        = pim_time_monotonic_sec();

    /* initialize new group as INCLUDE {empty} */
    group->group_filtermode_isexcl = 0; /* 0=INCLUDE, 1=EXCLUDE */

    listnode_add(igmp->igmp_group_list, group);
#if 1 // igmp->pimsm

    /*igmp send msg to pimsm */
    uint32_t igmp_version = igmp_group_compat_mode(igmp, group);
    switch(igmp_version)
    {
    case IGMP_VERSION_1:
        igmpv1_send_msg_to_pimsm(&group_addr,ifname2ifindex(ifname),MLD_ADD_ADDR);
        break;
    case IGMP_VERSION_2:
        igmpv2_send_msg_to_pimsm(&group_addr,ifname2ifindex(ifname),MLD_ADD_ADDR);
        break;
    case IGMP_VERSION_3:
        igmpv3_send_msg_to_pimsm(&group_addr,ifname2ifindex(ifname),MLD_ADD_ADDR);
        break;
    default :
        printf("unknow igmp version\n");
        break;
    }
#if 0
    MLD_MSG *pstMsgToPim = NULL;
    GROUPLIST *pstGroupList = NULL;
    pstMsgToPim = ( MLD_MSG *)malloc(sizeof(MLD_MSG));
    memset(pstMsgToPim,0,sizeof(MLD_MSG));
    int ifindex = ifname2ifindex(ifname); //需要传参过来，收包接口的索引
    MLD_WriteMsgHeadToPim(pstMsgToPim, MLD_ADD_ADDR, 1,ifindex, IGMP_VERSION_3);/*IGMP version 需传参*/
    pstGroupList = (GROUPLIST *)malloc(sizeof(GROUPLIST));
    memset(pstGroupList, 0, sizeof(GROUPLIST));
    //pstGroupList->stGrAddr = *group;
    pstGroupList->stGrAddr = *((VOS_IPV6_ADDR *)(&group_addr));
    pstGroupList->pstNext = pstMsgToPim->u_msg.mIGMPv1ToPim.pstGrHead;
    pstMsgToPim->u_msg.mIGMPv1ToPim.pstGrHead = pstGroupList;

    pimsm_MsgProcIgmp((PIMSM_MSG_T *)pstMsgToPim);
#endif
    printf("\n--------------igmp send add group to pimsm----------------\n");

    printf("group:%s\n",inet_ntoa(group_addr));
    printf("ifname:%s\n",ifname);

    printf("\n----------------------------------------------------------\n");

#endif
    if (PIM_DEBUG_IGMP_TRACE)
    {
        char group_str[100];
        pim_inet_dump("<group?>", group->group_addr, group_str, sizeof(group_str));
        zlog_debug("Creating new IGMP group %s on socket %d interface %s",
                   group_str, group->group_igmp_sock->fd, ifname);
    }

    /*
      RFC 3376: 6.2.2. Definition of Group Timers

      The group timer is only used when a group is in EXCLUDE mode and
      it represents the time for the *filter-mode* of the group to
      expire and switch to INCLUDE mode.
    */
    zassert(!group->group_filtermode_isexcl); /* INCLUDE mode */
    zassert(!group->t_group_timer); /* group timer == 0 */

    /* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
    igmp_anysource_forward_stop(group);

    return group;
}
