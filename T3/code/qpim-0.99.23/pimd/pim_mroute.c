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
#include <linux/mroute.h>
#include "log.h"
#include "privs.h"

#include "pimd.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_macro.h"


#include "pimsm_define.h"

/* GLOBAL VARS */
extern struct zebra_privs_t pimd_privs;

static void mroute_read_on(void);

/*
 * in kernel process
case MRT_PIM:
    {
        int v;

        if (get_user(v,(int __user *)optval))
            return -EFAULT;
        v = (v) ? 1 : 0;

        rtnl_lock();
        ret = 0;
        if (v != mrt->mroute_do_pim)
        {
            mrt->mroute_do_pim = v;
            mrt->mroute_do_assert = v;
        }
        rtnl_unlock();
        return ret;
    }
}
*/

static int pim_mroute_set(int fd, int enable)
{
    int err;
    int opt = enable ? MRT6_INIT : MRT6_DONE;
    socklen_t opt_len = sizeof(opt);

    err = setsockopt(fd, IPPROTO_IPV6, opt, &opt, opt_len);
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPV6,%s=%d): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  fd, enable ? "MRT_INIT" : "MRT_DONE", opt, e, safe_strerror(e));
        errno = e;
        return -1;
    }

#if 1
    opt = enable ? 1: 0;
    err = setsockopt(fd, IPPROTO_IPV6, MRT6_PIM, &opt, opt_len);
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPV6,%s=%d): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  fd, "MRT_PIM", opt, e, safe_strerror(e));
        errno = e;
        return -1;
    }

#endif
    int reuse = 1;
    err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     (void *) &reuse, sizeof(reuse));
    if (err)
    {
        int e = errno;
        zlog_warn("Could not set Reuse Address Option on socket fd=%d: errno=%d: %s",
                  fd, errno, safe_strerror(errno));

        errno = e;
        return -1;
    }
#if 1
    zlog_info("%s %s: setsockopt(fd=%d,IPPROTO_IPV6,MRT6_INIT,opt=%d): ok",
              __FILE__, __PRETTY_FUNCTION__,
              fd, opt);
#endif

    return 0;
}

#if 0
int pim_mroute_msg(int fd, const char *buf, int buf_size)
{
    struct interface     *ifp;
    const struct ip      *ip_hdr;
    const struct igmpmsg *msg;
    const char *upcall;
    char src_str[100];
    char grp_str[100];

    ip_hdr = (const struct ip *) buf;

    /* kernel upcall must have protocol=0 */
    if (ip_hdr->ip_p)
    {
        /* this is not a kernel upcall */
#ifdef PIM_UNEXPECTED_KERNEL_UPCALL
        zlog_warn("%s: not a kernel upcall proto=%d msg_size=%d",
                  __PRETTY_FUNCTION__, ip_hdr->ip_p, buf_size);
#endif
        return 0;
    }

    msg = (const struct igmpmsg *) buf;

    switch (msg->im_msgtype)
    {
    case IGMPMSG_NOCACHE:
        upcall = "NOCACHE";
        break;
    case IGMPMSG_WRONGVIF:
        upcall = "WRONGVIF";
        break;
    case IGMPMSG_WHOLEPKT:
        upcall = "WHOLEPKT";
        break;
    default:
        upcall = "<unknown_upcall?>";
    }
    ifp = pim_if_find_by_vif_index(msg->im_vif);
    pim_inet6_dump("<src?>", msg->im_src, src_str, sizeof(src_str));
    pim_inet6_dump("<grp?>", msg->im_dst, grp_str, sizeof(grp_str));

    if (msg->im_msgtype == IGMPMSG_WRONGVIF)
    {
        struct pim_ifchannel *ch;
        struct pim_interface *pim_ifp;

        /*
          Send Assert(S,G) on iif as response to WRONGVIF kernel upcall.

          RFC 4601 4.8.2.  PIM-SSM-Only Routers

          iif is the incoming interface of the packet.
          if (iif is in inherited_olist(S,G)) {
          send Assert(S,G) on iif
          }
        */

        if (PIM_DEBUG_PIM_TRACE)
        {
            zlog_debug("%s: WRONGVIF from fd=%d for (S,G)=(%s,%s) on %s vifi=%d",
                       __PRETTY_FUNCTION__,
                       fd,
                       src_str,
                       grp_str,
                       ifp ? ifp->name : "<ifname?>",
                       msg->im_vif);
        }

        if (!ifp)
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) could not find input interface for input_vif_index=%d",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, msg->im_vif);
            return -1;
        }

        pim_ifp = ifp->info;
        if (!pim_ifp)
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) multicast not enabled on interface %s",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, ifp->name);
            return -2;
        }

        ch = pim_ifchannel_find(ifp, msg->im_src, msg->im_dst);
        if (!ch)
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) could not find channel on interface %s",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, ifp->name);
            return -3;
        }

        /*
          RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

          Transitions from NoInfo State

          An (S,G) data packet arrives on interface I, AND
          CouldAssert(S,G,I)==TRUE An (S,G) data packet arrived on an
          downstream interface that is in our (S,G) outgoing interface
          list.  We optimistically assume that we will be the assert
          winner for this (S,G), and so we transition to the "I am Assert
          Winner" state and perform Actions A1 (below), which will
          initiate the assert negotiation for (S,G).
        */

        if (ch->ifassert_state != PIM_IFASSERT_NOINFO)
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) channel is not on Assert NoInfo state for interface %s",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, ifp->name);
            return -4;
        }

        if (!PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags))
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) interface %s is not downstream for channel",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, ifp->name);
            return -5;
        }

        if (assert_action_a1(ch))
        {
            zlog_warn("%s: WRONGVIF (S,G)=(%s,%s) assert_action_a1 failure on interface %s",
                      __PRETTY_FUNCTION__,
                      src_str, grp_str, ifp->name);
            return -6;
        }

        return 0;
    } /* IGMPMSG_WRONGVIF */

    zlog_warn("%s: kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%s,%s) on %s vifi=%d",
              __PRETTY_FUNCTION__,
              upcall,
              msg->im_msgtype,
              ip_hdr->ip_p,
              fd,
              src_str,
              grp_str,
              ifp ? ifp->name : "<ifname?>",
              msg->im_vif);

    return 0;
}
#endif
#if 0
int pimsm_msocket_recvfromto(int fd, uint8_t *buf, size_t len,
                             struct sockaddr_in6 *from, socklen_t *fromlen,
                             struct sockaddr_in6 *to, socklen_t *tolen,
                             int *ifindex)
{
    struct msghdr msgh;
    struct cmsghdr *cmsg;
    struct iovec iov;
    char cbuf[1000];
    int err;

    /*
     * IP_PKTINFO / IP_RECVDSTADDR don't yield sin_port.
     * Use getsockname() to get sin_port.
     */
    if (to)
    {
        struct sockaddr_in6 si;
        socklen_t si_len = sizeof(si);

        ((struct sockaddr_in6 *) to)->sin6_family = AF_INET6;

        if (pim_socket_getsockname(fd, (struct sockaddr *) &si, &si_len))
        {
            ((struct sockaddr_in6 *) to)->sin6_port        = ntohs(0);
            memset(&((struct sockaddr_in6 *) to)->sin6_addr, 0x00, sizeof(struct in6_addr));
        }
        else
        {
            ((struct sockaddr_in6 *) to)->sin6_port = si.sin6_port;
            memcpy(&((struct sockaddr_in6 *) to)->sin6_addr , &si.sin6_addr, sizeof(struct in6_addr));
        }

        if (tolen)
            *tolen = sizeof(si);
    }

    memset(&msgh, 0, sizeof(struct msghdr));
    iov.iov_base = buf;
    iov.iov_len  = len;
    msgh.msg_control = cbuf;
    msgh.msg_controllen = sizeof(cbuf);
    msgh.msg_name = from;
    msgh.msg_namelen = fromlen ? *fromlen : 0;
    msgh.msg_iov  = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_flags = 0;

    err = recvmsg(fd, &msgh, 0);
    if (err < 0)
        return err;

    if (fromlen)
        *fromlen = msgh.msg_namelen;

    for (cmsg = CMSG_FIRSTHDR(&msgh);
            cmsg != NULL;
            cmsg = CMSG_NXTHDR(&msgh,cmsg))
    {

        if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO) && (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) )
        {
            struct in6_pktinfo *i = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            if (to)
                ((struct sockaddr_in6 *) to)->sin6_addr = i->ipi6_addr;
            if (tolen)
                *tolen = sizeof(struct sockaddr_in6);
            if (ifindex)
                *ifindex = i->ipi6_ifindex;

            if (IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *) to)->sin6_addr))
                ((struct sockaddr_in6 *) to)->sin6_scope_id = *ifindex;
            else
                ((struct sockaddr_in6 *) to)->sin6_scope_id = 0;

            if (to && PIM_DEBUG_PACKETS)
            {
                char to_str[100];
                pim_inet6_dump("<to?>", to->sin6_addr, to_str, sizeof(to_str));
                zlog_debug("%s: HAVE_IP_PKTINFO to=%s,%d",
                           __PRETTY_FUNCTION__,
                           to_str, ntohs(to->sin6_port));
            }

            break;
        }

    } /* for (cmsg) */

    return err; /* len */


    struct in6_addr *group, *dst = NULL;
    struct mld_hdr *mldh;
    struct cmsghdr *cm;
    struct in6_pktinfo *pi = NULL;
    int *hlimp = NULL;
    int ifindex = 0;
    struct sockaddr_in6 *src = (struct sockaddr_in6 *) rcvmh.msg_name;

    if (recvlen < sizeof(struct mld_hdr))
    {
        log_msg(LOG_WARNING, 0,
                "received packet too short (%u bytes) for MLD header",
                recvlen);
        return;
    }
    mldh = (struct mld_hdr *) rcvmh.msg_iov[0].iov_base;

    /*
     *   * Packets sent up from kernel to daemon have ICMPv6 type = 0.
     *       * Note that we set filters on the mld6_socket, so we should never
     *           * see a "normal" ICMPv6 packet with type 0 of ICMPv6 type.
     *               */
    if (mldh->mld_type == 0)
    {
        /* XXX: msg_controllen must be reset in this case. */
        rcvmh.msg_controllen = rcvcmsglen;

        process_kernel_call();
        return;
    }

    group = &mldh->mld_addr;

    /* extract optional information via Advanced API */
    for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rcvmh);
            cm;
            cm = (struct cmsghdr *) CMSG_NXTHDR(&rcvmh, cm))
    {
        if (cm->cmsg_level == IPPROTO_IPV6 &&
                cm->cmsg_type == IPV6_PKTINFO &&
                cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
        {
            pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
            ifindex = pi->ipi6_ifindex;
            dst = &pi->ipi6_addr;
        }
        if (cm->cmsg_level == IPPROTO_IPV6 &&
                cm->cmsg_type == IPV6_HOPLIMIT &&
                cm->cmsg_len == CMSG_LEN(sizeof(int)))
            hlimp = (int *) CMSG_DATA(cm);
    }
    if (hlimp == NULL)
    {
        log_msg(LOG_WARNING, 0,
                "failed to get receiving hop limit");
        return;
    }

    /* TODO: too noisy. Remove it? */
#undef NOSUCHDEF
#ifdef NOSUCHDEF
    IF_DEBUG(DEBUG_PKT | debug_kind(IPPROTO_ICMPV6, mldh->mld_type,
                                    mldh->mld_code))
    log_msg(LOG_DEBUG, 0, "RECV %s from %s to %s",
            packet_kind(IPPROTO_ICMPV6,
                        mldh->mld_type, mldh->mld_code),
            sa6_fmt(src), inet6_fmt(dst));
#endif              /* NOSUCHDEF */

    /* for an mtrace message, we don't need strict checks */
#ifdef MLD_MTRACE
    if (mldh->mld_type == MLD_MTRACE)
    {
        accept_mtrace(src, dst, group, ifindex, (char *)(mldh + 1),
                      mldh->mld_code, recvlen - sizeof(struct mld_hdr));
        return;
    }
#endif

    /* hop limit check */
    if (*hlimp != 1)
    {
        log_msg(LOG_WARNING, 0,
                "received an MLD6 message with illegal hop limit(%d) from %s",
                *hlimp, sa6_fmt(src));
        /*
         *       * But accept the packet in case of MLDv1, since RFC2710
         *               * does not mention whether to discard such MLD packets or not.
         *                       * Whereas in case of MLDv2, it'll be discarded as is stated in
         *                               * draft-vida-mld-v2-08.txt section 6.2.
         *                                       */
    }
    if (ifindex == 0)
    {
        log_msg(LOG_WARNING, 0, "failed to get receiving interface");
        return;
    }

    /* scope check */
    if (IN6_IS_ADDR_MC_NODELOCAL(&mldh->mld_addr))
    {
        log_msg(LOG_INFO, 0,
                "RECV with an invalid scope: %s from %s",
                inet6_fmt(&mldh->mld_addr), sa6_fmt(src));
        return;         /* discard */
    }

    /* source address check */
    if (!IN6_IS_ADDR_LINKLOCAL(&src->sin6_addr))
    {
        /*
         *       * RFC3590 allows the IPv6 unspecified address as the source
         *               * address of MLD report and done messages.  However, as this
         *                       * same document says, this special rule is for snooping
         *                               * switches and the RFC requires routers to discard MLD packets
         *                                       * with the unspecified source address.
         *                                               */
        log_msg(LOG_INFO, 0,
                "RECV %s from a non link local address: %s",
                packet_kind(IPPROTO_ICMPV6, mldh->mld_type,
                            mldh->mld_code), sa6_fmt(src));
        return;
    }

    switch (mldh->mld_type)
    {
    case MLD_LISTENER_QUERY:
        if (recvlen == 24)
            accept_listener_query(src, dst, group,
                                  ntohs(mldh->mld_maxdelay));
#ifdef HAVE_MLDV2
        if (recvlen >= 28)
        {
            if (*hlimp != 1)
                return;
            accept_listenerV2_query(src, dst, (char *)(mldh), recvlen);
        }
#endif
        return;

    case MLD_LISTENER_REPORT:
        accept_listener_report(src, dst, group);
        return;

    case MLD_LISTENER_DONE:
        accept_listener_done(src, dst, group);
        return;

#ifdef HAVE_MLDV2
    case MLDV2_LISTENER_REPORT:
        if (*hlimp != 1)
            return;
        accept_listenerV2_report(src,dst,(char *)(mldh),recvlen);
        return;
#endif

    default:
        /* This must be impossible since we set a type filter */
        log_msg(LOG_INFO, 0,
                "ignoring unknown ICMPV6 message type %x from %s to %s",
                mldh->mld_type, sa6_fmt(src), inet6_fmt(dst));
        return;
    }
}
#endif

static int mroute_read_msg(int fd)
{
    const int msg_min_size = MAX(sizeof(struct ip6_hdr), sizeof(struct mrt6msg));
    char buf[1000];
    int rd;

    if (((int) sizeof(buf)) < msg_min_size)
    {
        zlog_err("%s: fd=%d: buf size=%zu lower than msg_min=%d",
                 __PRETTY_FUNCTION__, fd, sizeof(buf), msg_min_size);
        return -1;
    }

    rd = read(fd, buf, sizeof(buf));
    if (rd < 0)
    {
        zlog_warn("%s: failure reading fd=%d: errno=%d: %s",
                  __PRETTY_FUNCTION__, fd, errno, safe_strerror(errno));
        return -2;
    }

    if (rd < msg_min_size)
    {
#if 0
        pim_pkt_dump(__PRETTY_FUNCTION__, (uint8_t *)buf, rd);

        zlog_warn("%s: short message reading fd=%d: read=%d msg_min=%d",
                  __PRETTY_FUNCTION__, fd, rd, msg_min_size);
#endif
        return -3;
    }
    return pimsm_ReceiveMulticastDatagram(fd, buf, rd);
#if 0
    return pim_mroute_msg(fd, buf, rd);
#endif
}

static int mroute_read(struct thread *t)
{
    int fd;
    int result;

    zassert(t);
    zassert(!THREAD_ARG(t));

    fd = THREAD_FD(t);
    zassert(fd == qpim_mroute_socket_fd);

    result = mroute_read_msg(fd);

    /* Keep reading */
    qpim_mroute_socket_reader = 0;
    mroute_read_on();

    return result;
}

static void mroute_read_on()
{
    zassert(!qpim_mroute_socket_reader);
    zassert(PIM_MROUTE_IS_ENABLED);

    THREAD_READ_ON(master, qpim_mroute_socket_reader,
                   mroute_read, 0, qpim_mroute_socket_fd);
}

static void mroute_read_off()
{
    THREAD_OFF(qpim_mroute_socket_reader);
}

int pim_mroute_socket_enable()
{
    int fd;

    if (PIM_MROUTE_IS_ENABLED)
        return -1;

    if ( pimd_privs.change (ZPRIVS_RAISE) )
        zlog_err ("pim_mroute_socket_enable: could not raise privs, %s",
                  safe_strerror (errno) );

    fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if ( pimd_privs.change (ZPRIVS_LOWER) )
        zlog_err ("pim_mroute_socket_enable: could not lower privs, %s",
                  safe_strerror (errno) );

    if (fd < 0)
    {
        zlog_warn("Could not create mroute socket: errno=%d: %s",
                  errno, safe_strerror(errno));
        return -2;
    }

    if (pim_mroute_set(fd, 1))
    {
        zlog_warn("Could not enable mroute on socket fd=%d: errno=%d: %s",
                  fd, errno, safe_strerror(errno));
        close(fd);
        return -3;
    }

    qpim_mroute_socket_fd       = fd;
    PIM_DEBUG("create mroute sockd success:%d.\n", qpim_mroute_socket_fd);
    qpim_mroute_socket_creation = pim_time_monotonic_sec();
    mroute_read_on();

    zassert(PIM_MROUTE_IS_ENABLED);

    return 0;
}

int pim_mroute_socket_disable()
{
    if (PIM_MROUTE_IS_DISABLED)
        return -1;

    if (pim_mroute_set(qpim_mroute_socket_fd, 0))
    {
        zlog_warn("Could not disable mroute on socket fd=%d: errno=%d: %s",
                  qpim_mroute_socket_fd, errno, safe_strerror(errno));
        return -2;
    }

    if (close(qpim_mroute_socket_fd))
    {
        zlog_warn("Failure closing mroute socket: fd=%d errno=%d: %s",
                  qpim_mroute_socket_fd, errno, safe_strerror(errno));
        return -3;
    }

    mroute_read_off();
    qpim_mroute_socket_fd = -1;

    zassert(PIM_MROUTE_IS_DISABLED);

    return 0;
}

/*
  For each network interface (e.g., physical or a virtual tunnel) that
  would be used for multicast forwarding, a corresponding multicast
  interface must be added to the kernel.
 */
int pim_mroute_add_vif(int vif_index, struct in6_addr ifaddr)
{
    struct mif6ctl  mc;
    int err;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }

    memset(&mc, 0, sizeof(mc));
    mc.mif6c_mifi = vif_index;
    mc.mif6c_pifi = vif_index;
    mc.mif6c_flags = 0;
    mc.vifc_threshold = PIM_MROUTE_MIN_TTL;
    mc.vifc_rate_limit = 0;
#if 0
    memcpy(&vc.vifc_lcl_addr, &ifaddr, sizeof(vc.vifc_lcl_addr));

#ifdef PIM_DVMRP_TUNNEL
    if (vc.vifc_flags & VIFF_TUNNEL)
    {
        memcpy(&vc.vifc_rmt_addr, &vif_remote_addr, sizeof(vc.vifc_rmt_addr));
    }
#endif
#endif

    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IPV6, MRT6_ADD_MIF, (void*) &mc, sizeof(mc));
    if (err)
    {
        char ifaddr_str[100];
        int e = errno;

        pim_inet6_dump("<ifaddr?>", ifaddr, ifaddr_str, sizeof(ifaddr_str));

        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPV6,MRT_ADD_MIF,vif_index=%d,ifaddr=%s): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd, vif_index, ifaddr_str,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }
    else
    {

        char ifaddr_str[100];
        pim_inet6_dump("<ifaddr?>", ifaddr, ifaddr_str, sizeof(ifaddr_str));
        zlog_warn("%s %s: success: setsockopt(fd=%d,IPPROTO_IPV6,MRT6_ADD_MIF,vif_index=%d,ifaddr=%s):",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd, vif_index, ifaddr_str);

    }

    return 0;
}

int pim_mroute_del_vif(int vif_index)
{
    struct mif6ctl mc;
    int err;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }

    memset(&mc, 0, sizeof(mc));
    mc.mif6c_mifi = vif_index;

    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IPV6, MRT6_DEL_MIF, (void*) &mc, sizeof(mc));
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPv6, MRT6_DEL_MIF,vif_index=%d): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd, vif_index,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }
    else
    {
        zlog_warn("%s %s: success: setsockopt(fd=%d,IPPROTO_IPV6,MRT6_DEL_MIF,vif_index=%d):",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd, vif_index);
    }

    return 0;
}

int pim_mroute_add(struct mfcctl *mc)
{
    int err;

    qpim_mroute_add_last = pim_time_monotonic_sec();
    ++qpim_mroute_add_events;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }
    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IP, MRT_ADD_MFC,
                     mc, sizeof(*mc));
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_ADD_MFC): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }

    return 0;
}

int pim_mroute_del(struct mfcctl *mc)
{
    int err;

    qpim_mroute_del_last = pim_time_monotonic_sec();
    ++qpim_mroute_del_events;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }

    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IP, MRT_DEL_MFC, mc, sizeof(*mc));
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_DEL_MFC): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }

    return 0;
}
#if INCLUDE_PIMSM

int pimsm_mroute_add(struct pimsm_mf6cctl *mc)
{
    int err;

    qpim_mroute_add_last = pim_time_monotonic_sec();
    ++qpim_mroute_add_events;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }
    PIM_DEBUG("sizeof(struct pimsm_mf6cctl):%ld.\n", sizeof(struct pimsm_mf6cctl));
    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IPV6, MRT6_ADD_MFC,
                     mc, sizeof(struct pimsm_mf6cctl));
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPV6,MRT6_ADD_MFC): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }

    return 0;
}

int pimsm_mroute_del(struct pimsm_mf6cctl *mc)
{
    int err;

    qpim_mroute_del_last = pim_time_monotonic_sec();
    ++qpim_mroute_del_events;

    if (PIM_MROUTE_IS_DISABLED)
    {
        zlog_warn("%s: global multicast is disabled",
                  __PRETTY_FUNCTION__);
        return -1;
    }

    err = setsockopt(qpim_mroute_socket_fd, IPPROTO_IPV6, MRT6_DEL_MFC, mc, sizeof(struct pimsm_mf6cctl));
    if (err)
    {
        int e = errno;
        zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IPV6,MRT6_DEL_MFC): errno=%d: %s",
                  __FILE__, __PRETTY_FUNCTION__,
                  qpim_mroute_socket_fd,
                  e, safe_strerror(e));
        errno = e;
        return -2;
    }

    return 0;
}

#endif
