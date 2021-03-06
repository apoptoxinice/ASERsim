/* Zebra VTY functions
 * Copyright (C) 2002 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include <sys/socket.h>
#include <stdlib.h>
#include  <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
//#include <net/if.h>        /*struct ifreq*/
#include <linux/ip6_tunnel.h>   /* struct ip6_tnl_parm*/
#include <linux/if_tunnel.h>  /*tunnel cmd*/
#include <errno.h>
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "zebra/interface.h"

#include "zebra/zserv.h"
#include "lib/filter.h"
//add for arp_cmd
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pthread.h>//zlw
#include "ospf6d/ospf6_message.h"
#include "ospf6d/ospf6_top.h"
#define HAVE_NETWIRE
#define HAVE_DNS64
#define HAVE_DHCPV4
//#define HAVE_4OVER6_TCPMSS
#define HAVE_IPNAT
//#define HAVE_SNMP
#define BYTE unsigned char

extern struct zebra_t zebrad;//add zlw

#ifdef HAVE_DNS64
char dnsprefix[100] = {0};
char dnsv4[50] = {0};
char dns64_ubit[10] = {0};
#endif
/* add by s 130806*/
extern struct zebra_4over6_tunnel_entry zebra4over6TunnelEntry;

struct save_mss
{
    int mss_value;
    int mss_flag;
} save_mss;

struct save_mss save_tunnel4o6_tcpmss;

/* end add*/

//added by wangyl for dhcp
typedef struct DHCP_CFG_TABLE
{
    char OneCmdLine[128];
} DHCP_CFG_TABLE;

typedef struct DHCP_CFG_HEAD
{
    int count;
} DHCP_CFG_HEAD;
//added end

/*ivi46  or nat64*/
struct ion_prefix
{
    struct in6_addr prefix;
    int len;
    int ubit;
};
struct tnl_parm
{
    char name[IFNAMSIZ];    /* name of tunnel device */
    int link;               /* ifindex of underlying L2 interface */
    __u8 proto;             /* tunnel protocol */
    __u8 encap_limit;       /* encapsulation limit for tunnel */
    __u8 hop_limit;         /* hop limit for tunnel */
    __be32 flowinfo;        /* traffic class and flowlabel for tunnel */
    __u32 flags;            /* tunnel flags */
    struct in6_addr laddr;  /* local tunnel end-point address */
    struct in6_addr raddr;  /* remote tunnel end-point address */
    struct ion_prefix prefix;
};
#if 1
struct ivi64_tnl_parm
{
    char name[IFNAMSIZ];    /* name of tunnel device */
    int link;               /* ifindex of underlying L2 interface */
    __u8 proto;             /* tunnel protocol */
    __u8 encap_limit;       /* encapsulation limit for tunnel */
    __u8 hop_limit;         /* hop limit for tunnel */
    __be32 flowinfo;        /* traffic class and flowlabel for tunnel */
    __u32 flags;            /* tunnel flags */
    struct in6_addr laddr;  /* local tunnel end-point address */
    struct in6_addr raddr;  /* remote tunnel end-point address */
    struct ion_prefix prefix;
};
#endif
#if 0
struct ivi64_tnl_parm
{
    char name[IFNAMSIZ];    /* name of tunnel device */
    int link;               /* ifindex of underlying L2 interface */
    __be16 i_flags;
    __be16 o_flags;
    __be32 i_key;
    __be32 o_key;
    struct iphdr iph;
    struct ion_prefix prefix;
};
#endif
unsigned int  v4Dns;
struct prefix v6prefix;
#define KEEP_CONFIG_SIZE 50
struct arp_config
{
    int flag;
    char ip[16];
    char mac[19];
    char arp_dev[21];
} arp_keep_config[KEEP_CONFIG_SIZE];
int arp_count=0;
//added for nat 20130507
struct nat_pool_entry natPoolEntry;
struct nat_source_list natSourceList;
struct nat_source_list_pool_entry natSourceListPoolEntry;


/* General fucntion for static route. */
static int
zebra_static_ipv4 (struct vty *vty, int add_cmd, const char *dest_str,
                   const char *mask_str, const char *gate_str,
                   const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in_addr gate;
    struct in_addr mask;
    const char *ifname;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* Null0 static route.  */
    if ((gate_str != NULL) && (strncasecmp (gate_str, "Null0", strlen (gate_str)) == 0))
    {
        if (flag_str)
        {
            vty_out (vty, "%% can not have flag %s with Null0%s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
        if (add_cmd)
            static_add_ipv4 (&p, NULL, NULL, ZEBRA_FLAG_BLACKHOLE, distance, 0);
        else
            static_delete_ipv4 (&p, NULL, NULL, distance, 0);
        return CMD_SUCCESS;
    }

    /* Route flags */
    if (flag_str)
    {
        switch(flag_str[0])
        {
        case 'r':
        case 'R': /* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B': /* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    if (gate_str == NULL)
    {
        if (add_cmd)
            static_add_ipv4 (&p, NULL, NULL, flag, distance, 0);
        else
            static_delete_ipv4 (&p, NULL, NULL, distance, 0);

        return CMD_SUCCESS;
    }

    /* When gateway is A.B.C.D format, gate is treated as nexthop
       address other case gate is treated as interface name. */
    ret = inet_aton (gate_str, &gate);
    if (ret)
        ifname = NULL;
    else
        ifname = gate_str;

    if (add_cmd)
        static_add_ipv4 (&p, ifname ? NULL : &gate, ifname, flag, distance, 0);
    else
        static_delete_ipv4 (&p, ifname ? NULL : &gate, ifname, distance, 0);

    return CMD_SUCCESS;
}

//added for 4over6 20130205
static int
zebra_static_ipv4_4over6 (struct vty *vty, int add_cmd, const char *dest_str,
                          const char *mask_str, const char *gate_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr gate;
    struct in_addr mask;
    const char *ifname;
    char tunnel_name[IFNAMSIZ] = { 0 };
    u_char type = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is valid IPv6 addrees, then gate is treated as
    nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate);
    if (ret == 1)
    {
        type = STATIC_IPV6_GATEWAY;
        ifname = NULL;
    }
    else
    {
        type = STATIC_IPV6_IFNAME;
        ifname = gate_str;
    }

    if (add_cmd)
    {
        zebra_4over6_nexthop_add_check(gate);
        ret = zebra_4over6_nexthop_lookup(&gate, tunnel_name);
        if(ret == 0)
        {
            ifname = tunnel_name;
            type = STATIC_IPV6_GATEWAY_IFNAME;
        }
        static_add_ipv4_4over6(&p, type, &gate, ifname, flag, distance, 0);
    }
    else
    {
        ret = zebra_4over6_nexthop_lookup(&gate, tunnel_name);
        if(ret == 0)
        {
            ifname = tunnel_name;
            type = STATIC_IPV6_GATEWAY_IFNAME;
        }
        static_delete_ipv4_4over6(&p, type, &gate, ifname, distance, 0);
        zebra_4over6_nexthop_del_check(gate);
    }

    return CMD_SUCCESS;
}

/* Static route configuration.  */
DEFUN (ip_route,
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], NULL, NULL);
}

DEFUN (ip_route_flags,
       ip_route_flags_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], argv[2], NULL);
}

DEFUN (ip_route_flags2,
       ip_route_flags2_cmd,
       "ip route A.B.C.D/M (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, NULL, argv[1], NULL);
}

/* Mask as A.B.C.D format.  */
DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], NULL, NULL);
}

//added for 4over6 20130205
DEFUN (ip_4over6_route,
       ip_4over6_route_cmd,
       "ip 4over6 route A.B.C.D/M X:X::X:X",
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 1, argv[0], NULL, argv[1]);
}

DEFUN (no_ip_4over6_route,
       no_ip_4over6_route_cmd,
       "no ip 4over6 route A.B.C.D/M X:X::X:X",
       NO_STR
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 0, argv[0], NULL, argv[1]);
}


DEFUN (ip_4over6_route_mask,
       ip_4over6_route_mask_cmd,
       "ip 4over6 route A.B.C.D A.B.C.D X:X::X:X",
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 1, argv[0], argv[1], argv[2]);
}

DEFUN (no_ip_4over6_route_mask,
       no_ip_4over6_route_mask_cmd,
       "no ip 4over6 route A.B.C.D A.B.C.D X:X::X:X",
       NO_STR
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 0, argv[0], argv[1], argv[2]);
}

#ifdef HAVE_IPNAT
//added for nat 20130505
static int
ip_nat_state_change_by_add_pool (const char *pool_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    int ret_pool = 0;
    char poolname[NATSIZE];
    char addcmd[CMDSTR];

    memset(addcmd, 0, CMDSTR);
    memset(poolname, 0, NATSIZE);
    sprintf(poolname, pool_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext!=NULL)
    {
        ret_pool = memcmp(poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0)
        {
            pNext->pool_state = NAT_ENABLE;
            if(pNext->list_state == NAT_ENABLE)
            {
                sprintf(addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s",
                        pNext->source.snet, pNext->pool.poolcmdstr);
                system(addcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_pool_add (struct vty *vty, const char *pool_name,
                 const char *start_addr, const char *end_addr)
{
    struct nat_pool_entry  *pLast;
    struct nat_pool_entry  *pNext;
    struct nat_pool_entry  *pNew;
    int iRetVal = 0;
    int ret = 1;
    int ret_cmp = 0;
    char poolname[NATSIZE];
    char startaddr[NATSIZE];
    char endaddr[NATSIZE];
    struct in_addr start;
    struct in_addr end;

    memset(poolname, 0, NATSIZE);
    memset(startaddr, 0, NATSIZE);
    memset(startaddr, 0, NATSIZE);
    memset(&start, 0, sizeof(struct in_addr));
    memset(&end, 0, sizeof(struct in_addr));
    sprintf(poolname, pool_name);
    sprintf(startaddr, start_addr);
    sprintf(endaddr, end_addr);

    ret = inet_aton (start_addr, &start);
    if (ret == 0)
    {
        vty_out (vty, "%% Start address translation error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    ret = inet_aton (end_addr, &end);
    if (ret == 0)
    {
        vty_out (vty, "%% End address translation error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(IPV4_ADDR_CMP (&start, &end) > 0)
    {
        vty_out (vty, "%% Start address is greater than end address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext!=NULL)
    {
        iRetVal = memcmp(poolname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The pool name is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_pool_entry));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof(struct nat_pool_entry));
        strlcpy(pNew->name, poolname, NATSIZE);
        sprintf(pNew->startaddr, start_addr);
        sprintf(pNew->endaddr, end_addr);
        IPV4_ADDR_COPY (&pNew->start_addr, &start);
        IPV4_ADDR_COPY (&pNew->end_addr, &end);
        pNew->next = NULL;

        ret_cmp = memcmp(startaddr, endaddr, NATSIZE);
        if (ret_cmp == 0)
            sprintf(pNew->poolcmdstr, start_addr);
        else
            sprintf(pNew->poolcmdstr, "%s-%s", start_addr, endaddr);

        ip_nat_state_change_by_add_pool(poolname);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_state_change_by_del_pool (const char *pool_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    int ret_pool = 0;
    char poolname[NATSIZE];
    char delcmd[CMDSTR];

    memset(delcmd, 0, CMDSTR);
    memset(poolname, 0, NATSIZE);
    sprintf(poolname, pool_name);


    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext!=NULL)
    {
        ret_pool = memcmp(poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0)
        {
            pNext->pool_state = NAT_DISABLE;
            if(pNext->list_state == NAT_ENABLE)
            {
                sprintf(delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s",
                        pNext->source.snet, pNext->pool.poolcmdstr);
                system(delcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_pool_del (struct vty *vty, const char *pool_name)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int iRetVal = 0;
    char poolname[NATSIZE];

    memset(poolname, 0, NATSIZE);
    sprintf(poolname, pool_name);

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext!=NULL)
    {
        iRetVal = memcmp(poolname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        ip_nat_state_change_by_del_pool(pNext->name);
        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_pool,
       ip_nat_pool_cmd,
       "ip nat pool WORD A.B.C.D A.B.C.D",
       IP_STR
       "NAT configuration commands\n"
       "Define pool of addresses\n"
       "Pool name\n"
       "Start IP address\n"
       "End IP address\n")
{
    return ip_nat_pool_add (vty, argv[0], argv[1], argv[2]);
}

DEFUN (no_ip_nat_pool,
       no_ip_nat_pool_cmd,
       "no ip nat pool WORD",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Define pool of addresses\n"
       "Pool name\n")
{
    return ip_nat_pool_del (vty, argv[0]);
}

static int
ip_nat_state_change_by_add_source_list (const char *list_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    int ret_list = 0;
    char listname[NATSIZE];
    char addcmd[CMDSTR];

    memset(addcmd, 0, CMDSTR);
    memset(listname, 0, NATSIZE);
    sprintf(listname, list_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext!=NULL)
    {
        ret_list = memcmp(listname, pNext->source.name, NATSIZE);
        if (ret_list == 0)
        {
            pNext->list_state = NAT_ENABLE;
            if(pNext->pool_state == NAT_ENABLE)
            {
                sprintf(addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s",
                        pNext->source.snet, pNext->pool.poolcmdstr);
                system(addcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_source_list_add (struct vty *vty, const char *list_name, const char *net_str)
{
    struct nat_source_list  *pLast;
    struct nat_source_list  *pNext;
    struct nat_source_list  *pNew;
    int iRetVal = 0;
    int ret = 0;
    char listname[NATSIZE];
    struct prefix_ipv4 p;

    memset(listname, 0, NATSIZE);
    sprintf(listname, list_name);

    ret = str2prefix_ipv4 (net_str, &p);
    if (ret == 0)
    {
        vty_out (vty, "%% The Prefix is error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext!=NULL)
    {
        iRetVal = memcmp(listname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The source list name is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_source_list));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof(struct nat_source_list));
        strlcpy(pNew->name, listname, NATSIZE);
        sprintf(pNew->snet, net_str);
        IPV4_ADDR_COPY (&pNew->source_addr, &p.prefix);
        pNew->masklen = p.prefixlen;
        pNew->next = NULL;

        ip_nat_state_change_by_add_source_list(listname);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_state_change_by_del_source_list (const char *list_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    int ret_list = 0;
    char listname[NATSIZE];
    char delcmd[CMDSTR];

    memset(delcmd, 0, CMDSTR);
    memset(listname, 0, NATSIZE);
    sprintf(listname, list_name);


    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext!=NULL)
    {
        ret_list = memcmp(listname, pNext->source.name, NATSIZE);
        if (ret_list == 0)
        {
            pNext->list_state = NAT_DISABLE;
            if(pNext->pool_state = NAT_ENABLE)
            {
                sprintf(delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s",
                        pNext->source.snet, pNext->pool.poolcmdstr);
                system(delcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_source_list_del (struct vty *vty, const char *list_name)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int iRetVal = 0;
    char listname[NATSIZE];

    memset(listname, 0, NATSIZE);
    sprintf(listname, list_name);

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext!=NULL)
    {
        iRetVal = memcmp(listname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        ip_nat_state_change_by_del_source_list(pNext->name);
        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_source_list,
       ip_nat_source_list_cmd,
       "ip nat source list WORD A.B.C.D/M",
       IP_STR
       "NAT configuration commands\n"
       "Source address translation\n"
       "Specify access list describing local addresses\n"
       "IP nat source-list name\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
    return ip_nat_source_list_add (vty, argv[0], argv[1]);
}

DEFUN (no_ip_nat_source_list,
       no_ip_nat_source_list_cmd,
       "no ip nat source list WORD",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Source address translation\n"
       "Specify access list describing local addresses\n"
       "IP nat source list name\n")
{
    return ip_nat_source_list_del (vty, argv[0]);
}

int
ip_nat_pool_lookup(char *pool_name, struct nat_pool_entry *pool)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int iRetVal = 0;

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp(pNext->name, pool_name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        memcpy(pool, pNext, sizeof(struct nat_pool_entry));
        return 0;
    }
    else
        return -1;
}

int
ip_nat_source_list_lookup(char *list_name, struct nat_source_list *source)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int iRetVal = 0;

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp(pNext->name, list_name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        memcpy(source, pNext, sizeof(struct nat_source_list));
        return 0;
    }
    else
        return -1;
}

static int
ip_nat_source_list_pool_add (struct vty *vty, const char *list_name, const char *pool_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    struct nat_source_list_pool_entry  *pNew;
    struct nat_source_list sourcelist;
    struct nat_pool_entry pool;
    int ret_pool = 0;
    int ret_list = 0;
    int ret = 0;
    char listname[NATSIZE];
    char poolname[NATSIZE];
    char addcmd[CMDSTR];

    memset(addcmd, 0, CMDSTR);
    memset(poolname, 0, NATSIZE);
    memset(listname, 0, NATSIZE);
    sprintf(poolname, pool_name);
    sprintf(listname, list_name);

    ret = ip_nat_source_list_lookup(listname, &sourcelist);
    if(ret != 0)
    {
        vty_out (vty, "%% The source list does not exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    ret = ip_nat_pool_lookup(poolname, &pool);
    if(ret != 0)
    {
        vty_out (vty, "%% The pool does not exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp(listname, pNext->source.name, NATSIZE);
        ret_pool = memcmp(poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0 && ret_list == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The source list pool is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_source_list_pool_entry));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof(struct nat_source_list_pool_entry));
        pNew->pool_state = NAT_ENABLE;
        pNew->list_state = NAT_ENABLE;
        memcpy(&pNew->source, &sourcelist, sizeof(struct nat_source_list));
        memcpy(&pNew->pool, &pool, sizeof(struct nat_pool_entry));
        pNew->next = NULL;

        sprintf(addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s",
                pNew->source.snet, pNew->pool.poolcmdstr);
        system(addcmd);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int
ip_nat_source_list_pool_del (struct vty *vty, const char *list_name, const char *pool_name)
{
    struct nat_source_list_pool_entry  *pLast;
    struct nat_source_list_pool_entry  *pNext;
    struct nat_source_list_pool_entry  *pNew;
    struct nat_source_list *sourcelist;
    struct nat_pool_entry *pool;
    int ret_pool = 0;
    int ret_list = 0;
    int ret = 0;
    char listname[NATSIZE];
    char poolname[NATSIZE];
    char delcmd[CMDSTR];

    memset(delcmd, 0, CMDSTR);
    memset(poolname, 0, NATSIZE);
    memset(listname, 0, NATSIZE);
    sprintf(poolname, pool_name);
    sprintf(listname, list_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp(listname, pNext->source.name, NATSIZE);
        ret_pool = memcmp(poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0 && ret_list == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        sprintf(delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s",
                pNext->source.snet, pNext->pool.poolcmdstr);
        system(delcmd);

        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_inside_source_list_pool,
       ip_nat_inside_source_list_pool_cmd,
       "ip nat inside source list WORD pool WORD",
       IP_STR
       "NAT configuration commands\n"
       "Inside address translation\n"
       "Source address translation\n"
       "Specify access list describing local addresses\n"
       "Source list name for local addresses\n"
       "Name pool of global addresses\n"
       "Pool name for global addresses\n")
{
    return ip_nat_source_list_pool_add (vty, argv[0], argv[1]);
}


DEFUN (no_ip_nat_inside_source_list_pool,
       no_ip_nat_inside_source_list_pool_cmd,
       "no ip nat inside source list WORD pool WORD",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Inside address translation\n"
       "Source address translation\n"
       "Specify access list describing local addresses\n"
       "Source list name for local addresses\n"
       "Name pool of global addresses\n"
       "Pool name for global addresses\n")
{
    return ip_nat_source_list_pool_del (vty, argv[0], argv[1]);
}

DEFUN (ip_nat_inside,
       ip_nat_inside_cmd,
       "ip nat inside",
       IP_STR
       "NAT configuration commands\n"
       "Inside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NAT_INSIDE;

    return CMD_SUCCESS;
}

DEFUN (no_ip_nat_inside,
       no_ip_nat_inside_cmd,
       "no ip nat inside",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Inside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NO_NAT;

    return CMD_SUCCESS;
}

DEFUN (ip_nat_outside,
       ip_nat_outside_cmd,
       "ip nat outside",
       IP_STR
       "NAT configuration commands\n"
       "Outside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NAT_OUTSIDE;

    return CMD_SUCCESS;
}

DEFUN (no_ip_nat_outside,
       no_ip_nat_outside_cmd,
       "no ip nat outside",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Outside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NO_NAT;

    return CMD_SUCCESS;
}
#endif



DEFUN (ip_route_mask_flags,
       ip_route_mask_flags_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], argv[3], NULL);
}

DEFUN (ip_route_mask_flags2,
       ip_route_mask_flags2_cmd,
       "ip route A.B.C.D A.B.C.D (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], NULL, argv[2], NULL);
}

/* Distance option value.  */
DEFUN (ip_route_distance,
       ip_route_distance_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], NULL, argv[2]);
}

DEFUN (ip_route_flags_distance,
       ip_route_flags_distance_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], argv[2], argv[3]);
}

DEFUN (ip_route_flags_distance2,
       ip_route_flags_distance2_cmd,
       "ip route A.B.C.D/M (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, NULL, argv[1], argv[2]);
}

DEFUN (ip_route_mask_distance,
       ip_route_mask_distance_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (ip_route_mask_flags_distance,
       ip_route_mask_flags_distance_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (ip_route_mask_flags_distance2,
       ip_route_mask_flags_distance2_cmd,
       "ip route A.B.C.D A.B.C.D (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Distance value for this route\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (no_ip_route,
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], NULL, NULL);
}

ALIAS (no_ip_route,
       no_ip_route_flags_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")

DEFUN (no_ip_route_flags2,
       no_ip_route_flags2_cmd,
       "no ip route A.B.C.D/M (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, NULL, NULL, NULL);
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], NULL, NULL);
}

ALIAS (no_ip_route_mask,
       no_ip_route_mask_flags_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")

DEFUN (no_ip_route_mask_flags2,
       no_ip_route_mask_flags2_cmd,
       "no ip route A.B.C.D A.B.C.D (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], NULL, NULL, NULL);
}

DEFUN (no_ip_route_distance,
       no_ip_route_distance_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], NULL, argv[2]);
}

DEFUN (no_ip_route_flags_distance,
       no_ip_route_flags_distance_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], argv[2], argv[3]);
}

DEFUN (no_ip_route_flags_distance2,
       no_ip_route_flags_distance2_cmd,
       "no ip route A.B.C.D/M (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, NULL, argv[1], argv[2]);
}

DEFUN (no_ip_route_mask_distance,
       no_ip_route_mask_distance_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (no_ip_route_mask_flags_distance,
       no_ip_route_mask_flags_distance_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (no_ip_route_mask_flags_distance2,
       no_ip_route_mask_flags_distance2_cmd,
       "no ip route A.B.C.D A.B.C.D (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], NULL, argv[2], argv[3]);
}

char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];	/* "any" == ZEBRA_ROUTE_MAX */

DEFUN (ip_protocol,
       ip_protocol_cmd,
       "ip protocol PROTO route-map ROUTE-MAP",
       NO_STR
       "Apply route map to PROTO\n"
       "Protocol name\n"
       "Route map name\n")
{
    int i;

    if (strcasecmp(argv[0], "any") == 0)
        i = ZEBRA_ROUTE_MAX;
    else
        i = proto_name2num(argv[0]);
    if (i < 0)
    {
        vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
                 VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (proto_rm[AFI_IP][i])
        XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
    proto_rm[AFI_IP][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);
    return CMD_SUCCESS;
}

DEFUN (no_ip_protocol,
       no_ip_protocol_cmd,
       "no ip protocol PROTO",
       NO_STR
       "Remove route map from PROTO\n"
       "Protocol name\n")
{
    int i;

    if (strcasecmp(argv[0], "any") == 0)
        i = ZEBRA_ROUTE_MAX;
    else
        i = proto_name2num(argv[0]);
    if (i < 0)
    {
        vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
                 VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (proto_rm[AFI_IP][i])
        XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
    proto_rm[AFI_IP][i] = NULL;
    return CMD_SUCCESS;
}

/* New RIB.  Detailed information for IPv4 route. */
static void
vty_show_ip_route_detail (struct vty *vty, struct route_node *rn)
{
    struct rib *rib;
    struct nexthop *nexthop;

    for (rib = rn->info; rib; rib = rib->next)
    {
        vty_out (vty, "Routing entry for %s/%d%s",
                 inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
                 VTY_NEWLINE);
        vty_out (vty, "  Known via \"%s\"", zebra_route_string (rib->type));
        vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            vty_out (vty, ", best");
        if (rib->refcnt)
            vty_out (vty, ", refcnt %ld", rib->refcnt);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", blackhole");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", reject");
        vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
        if (rib->type == ZEBRA_ROUTE_RIP
                || rib->type == ZEBRA_ROUTE_OSPF
                || rib->type == ZEBRA_ROUTE_BABEL
                || rib->type == ZEBRA_ROUTE_ISIS
                || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

            vty_out (vty, "  Last update ");

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty,  "%02d:%02d:%02d",
                         tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, "%dd%02dh%02dm",
                         tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, "%02dw%dd%02dh",
                         tm->tm_yday/7,
                         tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
            vty_out (vty, " ago%s", VTY_NEWLINE);
        }

        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
            char addrstr[32];

            vty_out (vty, "  %c",
                     CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
                vty_out (vty, " %s", inet_ntoa (nexthop->gate.ipv4));
                if (nexthop->ifindex)
                    vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " directly connected, %s",
                         ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " directly connected, %s", nexthop->ifname);
                break;
            case NEXTHOP_TYPE_BLACKHOLE:
                vty_out (vty, " directly connected, Null0");
                break;
            default:
                break;
            }
            if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV4:
                case NEXTHOP_TYPE_IPV4_IFINDEX:
                    vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)",
                             ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
            case NEXTHOP_TYPE_IPV4_IFNAME:
                if (nexthop->src.ipv4.s_addr)
                {
                    if (inet_ntop(AF_INET, &nexthop->src.ipv4, addrstr,
                                  sizeof addrstr))
                        vty_out (vty, ", src %s", addrstr);
                }
                break;
#ifdef HAVE_IPV6
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
                {
                    if (inet_ntop(AF_INET6, &nexthop->src.ipv6, addrstr,
                                  sizeof addrstr))
                        vty_out (vty, ", src %s", addrstr);
                }
                break;
#endif /* HAVE_IPV6 */
            default:
                break;
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}

//added for 4over6 20130304
static void
vty_show_ip_4over6_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            /* Prefix information. */
            len = vty_out (vty, "%c%c%c %s/%d",
                           zebra_route_char (rib->type),
                           CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)? '>' : ' ',
                           CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)? '*' : ' ',
                           inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ), rn->p.prefixlen);

            /* Distance and metric display. */
            if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
                len += vty_out (vty, " [%d/%d]", rib->distance,rib->metric);
        }
        else
            vty_out (vty, "  %c%*c",CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)? '*' : ' ',len - 3, ' ');

        switch (nexthop->type)
        {
        case NEXTHOP_TYPE_IPV6:
        case NEXTHOP_TYPE_IPV6_IFINDEX:
        case NEXTHOP_TYPE_IPV6_IFNAME:
            vty_out (vty, " via %s", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
            if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                vty_out (vty, ", %s", nexthop->ifname);
            else if (nexthop->ifindex)
                vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
            break;
        case NEXTHOP_TYPE_IFINDEX:
            vty_out (vty, " is directly connected, %s",
                     ifindex2ifname (nexthop->ifindex));
            break;
        case NEXTHOP_TYPE_IFNAME:
            vty_out (vty, " is directly connected, %s", nexthop->ifname);
            break;
        default:
            break;
        }

        if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
            vty_out (vty, " inactive");

        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
        {
            vty_out (vty, " (recursive");

            switch (nexthop->rtype)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " via %s)", inet_ntop (AF_INET6, &nexthop->rgate.ipv6, buf, BUFSIZ));
                if (nexthop->rifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s)",
                         ifindex2ifname (nexthop->rifindex));
                break;
            default:
                break;
            }
        }

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", bh");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", rej");

        if (rib->type == ZEBRA_ROUTE_RIP
                || rib->type == ZEBRA_ROUTE_OSPF
                || rib->type == ZEBRA_ROUTE_BABEL
                || rib->type == ZEBRA_ROUTE_ISIS
                || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty,  ", %02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, ", %dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, ", %02dw%dd%02dh", tm->tm_yday/7,tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}


static void
vty_show_ip_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            if(strcmp("127.0.0.0",inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ))!=0)
            {
                /* Prefix information. */
                len = vty_out (vty, "%c%c%c %s/%d",
                               zebra_route_char (rib->type),
                               CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
                               ? '>' : ' ',
                               CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
                               ? '*' : ' ',
                               inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ),
                               rn->p.prefixlen);

                /* Distance and metric display. */
                if (rib->type != ZEBRA_ROUTE_CONNECT
                        && rib->type != ZEBRA_ROUTE_KERNEL)
                    len += vty_out (vty, " [%d/%d]", rib->distance,
                                    rib->metric);
            }
        }
        else if(strcmp("127.0.0.0",inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ))!=0)
        {
            vty_out (vty, "  %c%*c",
                     CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
                     ? '*' : ' ',
                     len - 3, ' ');
        }
        if(strcmp("127.0.0.0",inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ))!=0)
        {
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
                vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
                if (nexthop->ifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " is directly connected, %s",
                         ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s", nexthop->ifname);
                break;
            case NEXTHOP_TYPE_BLACKHOLE:
                vty_out (vty, " is directly connected, Null0");
                break;
            default:
                break;
            }
            if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV4:
                case NEXTHOP_TYPE_IPV4_IFINDEX:
                    vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)",
                             ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
            case NEXTHOP_TYPE_IPV4_IFNAME:
                if (nexthop->src.ipv4.s_addr)
                {
                    if (inet_ntop(AF_INET, &nexthop->src.ipv4, buf, sizeof buf))
                        vty_out (vty, ", src %s", buf);
                }
                break;
#ifdef HAVE_IPV6
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                if (!IPV6_ADDR_SAME(&nexthop->src.ipv6, &in6addr_any))
                {
                    if (inet_ntop(AF_INET6, &nexthop->src.ipv6, buf, sizeof buf))
                        vty_out (vty, ", src %s", buf);
                }
                break;
#endif /* HAVE_IPV6 */
            default:
                break;
            }

            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, ", bh");
            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, ", rej");

            if (rib->type == ZEBRA_ROUTE_RIP
                    || rib->type == ZEBRA_ROUTE_OSPF
                    || rib->type == ZEBRA_ROUTE_BABEL
                    || rib->type == ZEBRA_ROUTE_ISIS
                    || rib->type == ZEBRA_ROUTE_BGP)
            {
                time_t uptime;
                struct tm *tm;

                uptime = time (NULL);
                uptime -= rib->uptime;
                tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

                if (uptime < ONE_DAY_SECOND)
                    vty_out (vty,  ", %02d:%02d:%02d",
                             tm->tm_hour, tm->tm_min, tm->tm_sec);
                else if (uptime < ONE_WEEK_SECOND)
                    vty_out (vty, ", %dd%02dh%02dm",
                             tm->tm_yday, tm->tm_hour, tm->tm_min);
                else
                    vty_out (vty, ", %02dw%dd%02dh",
                             tm->tm_yday/7,
                             tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}

DEFUN (show_ip_route,
       show_ip_route_cmd,
       "show ip route",
       SHOW_STR
       IP_STR
       "IP routing table\n")
{
    struct route_table *table;
    struct route_table *table_4over6;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show all IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
            }
            vty_show_ip_route (vty, rn, rib);
        }

    //added for 4over6 20130304
    table_4over6 = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (! table_4over6)
        return CMD_SUCCESS;
    for (rn = route_top (table_4over6); rn; rn = route_next (rn))
    {
        for (rib = rn->info; rib; rib = rib->next)
        {
            vty_show_ip_4over6_route (vty, rn, rib);
        }
    }

    return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix_longer,
       show_ip_route_prefix_longer_cmd,
       "show ip route A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct prefix p;
    int ret;
    int first = 1;

    ret = str2prefix (argv[0], &p);
    if (! ret)
    {
        vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (prefix_match (&p, &rn->p))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ip_route_supernets,
       show_ip_route_supernets_cmd,
       "show ip route supernets-only",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Show supernet entries only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    u_int32_t addr;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            addr = ntohl (rn->p.u.prefix4.s_addr);

            if ((IN_CLASSC (addr) && rn->p.prefixlen < 24)
                    || (IN_CLASSB (addr) && rn->p.prefixlen < 16)
                    || (IN_CLASSA (addr) && rn->p.prefixlen < 8))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
        }
    return CMD_SUCCESS;
}

DEFUN (show_ip_route_protocol,
       show_ip_route_protocol_cmd,
       "show ip route " QUAGGA_IP_REDIST_STR_ZEBRA,
       SHOW_STR
       IP_STR
       "IP routing table\n"
       QUAGGA_IP_REDIST_HELP_STR_ZEBRA)
{
    int type;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    type = proto_redistnum (AFI_IP, argv[0]);
    if (type < 0)
    {
        vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (rib->type == type)
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ip_route_addr,
       show_ip_route_addr_cmd,
       "show ip route A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")
{
    int ret;
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv4 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (! rn)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ip_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix,
       show_ip_route_prefix_cmd,
       "show ip route A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
    int ret;
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv4 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (! rn || rn->p.prefixlen != p.prefixlen)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ip_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

static void
vty_show_ip_route_summary (struct vty *vty, struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
    u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
    u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
    u_int32_t i;

    memset (&rib_cnt, 0, sizeof(rib_cnt));
    memset (&fib_cnt, 0, sizeof(fib_cnt));
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            {
                rib_cnt[ZEBRA_ROUTE_TOTAL]++;
                rib_cnt[rib->type]++;
                if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
                {
                    fib_cnt[ZEBRA_ROUTE_TOTAL]++;
                    fib_cnt[rib->type]++;
                }
                if (rib->type == ZEBRA_ROUTE_BGP &&
                        CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
                {
                    rib_cnt[ZEBRA_ROUTE_IBGP]++;
                    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
                        fib_cnt[ZEBRA_ROUTE_IBGP]++;
                }
            }

    vty_out (vty, "%-20s %-20s %-20s %s",
             "Route Source", "Routes", "FIB", VTY_NEWLINE);

    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
        if (rib_cnt[i] > 0)
        {
            if (i == ZEBRA_ROUTE_BGP)
            {
                vty_out (vty, "%-20s %-20d %-20d %s", "ebgp",
                         rib_cnt[ZEBRA_ROUTE_BGP] - rib_cnt[ZEBRA_ROUTE_IBGP],
                         fib_cnt[ZEBRA_ROUTE_BGP] - fib_cnt[ZEBRA_ROUTE_IBGP],
                         VTY_NEWLINE);
                vty_out (vty, "%-20s %-20d %-20d %s", "ibgp",
                         rib_cnt[ZEBRA_ROUTE_IBGP], fib_cnt[ZEBRA_ROUTE_IBGP],
                         VTY_NEWLINE);
            }
            else
                vty_out (vty, "%-20s %-20d %-20d %s", zebra_route_string(i),
                         rib_cnt[i], fib_cnt[i], VTY_NEWLINE);
        }
    }

    vty_out (vty, "------%s", VTY_NEWLINE);
    vty_out (vty, "%-20s %-20d %-20d %s", "Totals", rib_cnt[ZEBRA_ROUTE_TOTAL],
             fib_cnt[ZEBRA_ROUTE_TOTAL], VTY_NEWLINE);
}

/* Show route summary.  */
DEFUN (show_ip_route_summary,
       show_ip_route_summary_cmd,
       "show ip route summary",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Summary of all routes\n")
{
    struct route_table *table;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    vty_show_ip_route_summary (vty, table);

    return CMD_SUCCESS;
}

//added for 4over6 20130306
static int
static_config_ipv4_4over6 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    int write;
    char buf[BUFSIZ];
    struct route_table *stable;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_4OVER6, 0);
    if (! stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
    {
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ip 4over6 route %s/%d", inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV6_GATEWAY:
            case STATIC_IPV6_GATEWAY_IFNAME:
                vty_out (vty, " %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ));
                break;
            case STATIC_IPV6_IFNAME:
                vty_out (vty, " %s", si->ifname);
                break;
            }

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, " %s", "reject");

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, " %s", "blackhole");

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    }
    return write;
}
/*manage ipv4 pool*/

DEFUN(nat64_v4pool,
      nat64_v4pool_cmd,
      "nat64 v4pool X.X.X.X/M ",
      "Configure nat64 protocol\n"
      "Configure IPv4 pool\n"
      "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
     )
{
#define SIOCADDPOOL (SIOCCHGTUNNEL+10)
#define NO_MATCH 37
#define V4POOL_EXIST 38
#define V4POOL_OVERFLOW 39
    struct address
    {
        struct in_addr start;
        struct in_addr end;
    };
    struct address addr;
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    int cmd=0;
    struct prefix_ipv4 ipv4p;
    unsigned int usTemp;
    char cNAT64[]="nat64";


    ret = str2prefix_ipv4 (argv[0], &ipv4p);
    ipv4p.prefix.s_addr = htonl((unsigned int)ipv4p.prefix.s_addr);
    socketfd=socket(AF_INET,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    cmd = SIOCADDPOOL;
    strcpy(ifr.ifr_name,cNAT64);
    addr.start = ipv4p.prefix;
    usTemp = ipv4p.prefixlen;
    memcpy(&addr.end,&usTemp,sizeof(unsigned int));
    //vty_out(vty,"prefix is %x len is %x\n",addr.start.s_addr,addr.end.s_addr);
    //addr.end = ipv4p.prefixlen;

    ifr.ifr_data = &addr;
    ret=ioctl(socketfd,cmd,&ifr);
    if(ret == -1)
    {
        //vty_out(vty,"ioctl error: %d\n",errno);
        if(errno == NO_MATCH)
        {
            vty_out(vty,"The start address and end address is error!\n");
        }
        else if(errno == V4POOL_EXIST)
        {
            vty_out(vty,"Nat64 v4pool existing!\n");
        }
        else if(errno == V4POOL_OVERFLOW)
        {
            vty_out(vty,"NAT64 configure fail! the  address numbers of nat64 pool  must less than 8\n");
        }
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
}
/*manage ipv4 pool*/

DEFUN(no_nat64_v4pool,
      no_nat64_v4pool_cmd,
      "no nat64 v4pool X.X.X.X/M ",
      NO_STR
      "Configure nat64 protocol\n"
      "Configure IPv4 pool\n"
      "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
     )
{
#define SIOCDELPOOL (SIOCCHGTUNNEL+11)
#define NO_MATCH 37
    struct address
    {
        struct in_addr start;
        struct in_addr end;
    };
    struct address addr;
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    int cmd=0;
    struct prefix_ipv4 ipv4p;
    unsigned int usTemp;
    char cNAT64[]="nat64";


    ret = str2prefix_ipv4 (argv[0], &ipv4p);
    ipv4p.prefix.s_addr = htonl((unsigned int)ipv4p.prefix.s_addr);
    socketfd=socket(AF_INET,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }

    cmd = SIOCDELPOOL;
    strcpy(ifr.ifr_name,cNAT64);
    addr.start = ipv4p.prefix;
    usTemp = ipv4p.prefixlen;
    memcpy(&addr.end,&usTemp,sizeof(unsigned int));
    //addr.end = ipv4p.prefixlen;

    ifr.ifr_data = &addr;
    ret=ioctl(socketfd,cmd,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error2: %d\n",errno);
        if(errno == NO_MATCH)
        {
            vty_out(vty,"The start address and end address is error!\n");
        }
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
}


/* Write IPv4 static route configuration. */
static int
static_config_ipv4 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv4 *si;
    struct route_table *stable;
    int write;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_UNICAST, 0);
    if (! stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ip route %s/%d", inet_ntoa (rn->p.u.prefix4),
                     rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV4_GATEWAY:
                vty_out (vty, " %s", inet_ntoa (si->gate.ipv4));
                break;
            case STATIC_IPV4_IFNAME:
                vty_out (vty, " %s", si->gate.ifname);
                break;
            case STATIC_IPV4_BLACKHOLE:
                vty_out (vty, " Null0");
                break;
            }

            /* flags are incompatible with STATIC_IPV4_BLACKHOLE */
            if (si->type != STATIC_IPV4_BLACKHOLE)
            {
                if (CHECK_FLAG(si->flags, ZEBRA_FLAG_REJECT))
                    vty_out (vty, " %s", "reject");

                if (CHECK_FLAG(si->flags, ZEBRA_FLAG_BLACKHOLE))
                    vty_out (vty, " %s", "blackhole");
            }

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    return write;
}

DEFUN (show_ip_protocol,
       show_ip_protocol_cmd,
       "show ip protocol",
       SHOW_STR
       IP_STR
       "IP protocol filtering status\n")
{
    int i;

    vty_out(vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out(vty, "------------------------%s", VTY_NEWLINE);
    for (i=0; i<ZEBRA_ROUTE_MAX; i++)
    {
        if (proto_rm[AFI_IP][i])
            vty_out (vty, "%-10s  : %-10s%s", zebra_route_string(i),
                     proto_rm[AFI_IP][i],
                     VTY_NEWLINE);
        else
            vty_out (vty, "%-10s  : none%s", zebra_route_string(i), VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP][i])
        vty_out (vty, "%-10s  : %-10s%s", "any", proto_rm[AFI_IP][i],
                 VTY_NEWLINE);
    else
        vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

/*
  *add by huang jing in 2013 5 14
  *function:add dhcpv4 commands
  */
#ifdef HAVE_DHCPV4
int sendtoserver(struct vty *vty,char buffer[1024])
{
    struct sockaddr_in my_addr;
    bzero(&my_addr,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(8889);
    my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");

    int fd;
    char buf[1024] = {0};

    strcpy(buf,buffer);
    //vty_out (vty,"++%s++\n",buf);

    fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(fd == -1)
    {
        vty_out (vty,"socket fault!\n");
        return -1;
    }

    if(connect(fd,(struct sockaddr *)&my_addr,sizeof(my_addr)) == -1)
    {
        //vty_out (vty,"dhcp server progress does not open!\n");
        return -1;
    }

//	vty_out (vty,"--1---%s--%d-%d--\n",buf,sizeof(buf),strlen(buf));
    usleep(1000);
    if(send(fd,"1send",sizeof("1send"),0) == -1)
    {
        vty_out (vty,"send fault!\n");
        return -1;
    }

//	vty_out (vty,"--2---%s-----\n",buf);
    usleep(1000);
    if(send(fd,buf,strlen(buf)+1,0) == -1)
    {
        vty_out (vty,"send fault!\n");
        return -1;
    }

//	vty_out (vty,"11111111\n");
    memset(buf,0,sizeof(buf));
    if(recv(fd,buf,sizeof(buf)-1,0) == -1)
    {
        vty_out (vty,"revc commands to respond fault!\n");
        return -1;
    }
//	vty_out (vty,"22222222\n");
    if( strcmp(buf,"command success")==0 )
    {
        close(fd);
        return 0;
    }
    else if( strcmp(buf,"command fault")==0 )
    {
        close(fd);
        return -2;
    }

}

void change_ipv4address(char *buf)
{
    char str[50]= {0};
    char *start=NULL,*p=buf;
    int i,address1,address2,address3,address4;

    //????????????????????????????0??eg: 010.01.001.1 -> 10.1.1.1
    i=0;
    start=p;
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address1 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address2 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address3 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='\0' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address4 = atoi(str);

    memset(str,0,sizeof(str));
    sprintf(str,"%d.%d.%d.%d",address1,address2,address3,address4);
    strcpy(buf,str);

    return;
}

int compare_twoaddress(char buf[],char buf2[])//low address should be < high address
{
    char str[50]= {0};
    char *start=NULL,*p=buf;
    int i,address1_1,address1_2,address1_3,address1_4;
    int address2_1,address2_2,address2_3,address2_4;

    i=0;
    start=p;
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address1_1 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address1_2 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address1_3 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='\0' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address1_4 = atoi(str);

    p=buf2;
    i=0;
    start=p;
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address2_1 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address2_2 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='.' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address2_3 = atoi(str);

    i=0;
    p++;
    start=p;
    memset(str,0,sizeof(str));
    while( *p!='\0' )
    {
        p++;
        i++;
    }
    strncpy(str,start,i);
    str[i]='\0';
    address2_4 = atoi(str);

    if( address1_1>address2_1 )
        return -1;
    else if( address1_1<address2_1 )
        return 0;
    else
    {
        if( address1_2>address2_2)
            return -1;
        else if( address1_2<address2_2)
            return 0;
        else
        {
            if( address1_3>address2_3)
                return -1;
            else if( address1_3<address2_3)
                return 0;
            else
            {
                if( address1_4>=address2_4)
                    return -1;
                else
                    return 0;
            }
        }
    }

    return 0;
}


DEFUN (ip_dhcp_excluded_address,
       ip_dhcp_excluded_address_cmd,
       "ip dhcp excluded-address A.B.C.D  A.B.C.D",
       IP_STR
       "Configure DHCP server and relay parameters\n"
       "Prevent DHCP from assigning certain addresses\n"
       "Low IP address\n"
       "High IP address\n")
{
    char buf[1024] = {0};
    char *p=NULL;
    int i;
    int ret;
    //dhcp_flag = 1;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);
    if( compare_twoaddress(argv[0],argv[1])==-1 )//address argv[1] should >= argv[0]
    {
        vty_out (vty,"% [%s, %s] is an illegal address range.\n",argv[0],argv[1]);
        return CMD_WARNING;
    }

    if( *(argv[0])=='0' )
        strcpy(buf,"ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy(buf,"ip dhcp excluded-address ");
        strcat(buf,argv[0]);
        strcat(buf," ");
        strcat(buf,argv[1]);
    }

//	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_excluded_address,
       no_ip_dhcp_excluded_address_cmd,
       "no ip dhcp excluded-address A.B.C.D  A.B.C.D",
       NO_STR
       IP_STR
       "Configure DHCP server and relay parameters\n"
       "Prevent DHCP from assigning certain addresses\n"
       "Low IP address\n"
       "High IP address\n")
{
    char buf[1024] = {0};
    int ret;
    char *p=NULL;
    int i;

    //dhcp_flag = 1;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }


    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);

    if( *(argv[0])=='0' )
        strcpy(buf,"no ip dhcp excluded-address 0.0.0.0");
    else
    {

        strcpy(buf,"no ip dhcp excluded-address ");
        strcat(buf,argv[0]);
        strcat(buf," ");
        strcat(buf,argv[1]);
    }

//	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;
    else if(ret == -2)
    {
        vty_out (vty,"\% Range [ %s,  %s] is not in the database.\n",argv[0],argv[1]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_excluded_address_distance1,
       ip_dhcp_excluded_address__distance1_cmd,
       "ip dhcp excluded-address A.B.C.D",
       IP_STR
       "Configure DHCP server and relay parameters\n"
       "Prevent DHCP from assigning certain addresses\n"
       "Low IP address\n")
{
    char buf[1024] = {0};
    //char str[100] = {0};
    int ret;
    char *p=NULL;
    int i;
    //dhcp_flag = 1;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);

    if( *(argv[0])=='0' )
        strcpy(buf,"ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy(buf,"ip dhcp excluded-address ");
        strcat(buf,argv[0]);
    }

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_excluded_address_distance1,
       no_ip_dhcp_excluded_address__distance1_cmd,
       "no ip dhcp excluded-address A.B.C.D",
       NO_STR
       IP_STR
       "Configure DHCP server and relay parameters\n"
       "Prevent DHCP from assigning certain addresses\n"
       "Low IP address\n")
{
    char buf[1024] = {0};
    int ret;
    char *p=NULL;
    int i;
    //dhcp_flag = 1;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }


    change_ipv4address(argv[0]);

    if( *(argv[0])=='0' )
        strcpy(buf,"no ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy(buf,"no ip dhcp excluded-address ");
        strcat(buf,argv[0]);
    }

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;
    else if(ret == -2)
    {
        vty_out (vty,"\% Range [ %s,  %s] is not in the database.\n",argv[0],argv[0]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}


DEFUN (ip_dhcp_pool ,
       ip_dhcp_pool_cmd,
       "ip dhcp pool WORD",
       IP_STR
       "Configure DHCP server and relay parameters\n"
       "Configure DHCP address pools\n"
       "  WORD  Pool name\n")
{
    char buf[1024] = {0};
    int ret;
    //dhcp_flag = 2;
    strcpy(buf,"ip dhcp pool ");
    strcat(buf,argv[0]);

    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;
    else if(ret == -2)
    {
        vty_out (vty,"name of pool %s is not in the database.\n",argv[0]);
        return CMD_WARNING;
    }

    vty->node = DHCP_NODE;
    return CMD_SUCCESS;
}


DEFUN (no_ip_dhcp_pool ,
       no_ip_dhcp_pool_cmd,
       "no ip dhcp pool WORD",
       NO_STR
       IP_STR
       "Configure DHCP server and relay parameters"
       "Configure DHCP address pools\n"
       "  WORD  Pool name\n")
{
    char buf[1024] = {0};
    int ret;
    //dhcp_flag = 2;

    strcpy(buf,"no ip dhcp pool ");
    strcat(buf,argv[0]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;
    else if(ret == -2)
    {
        vty_out (vty,"name of pool %s is not in the database.\n",argv[0]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_network ,
       ip_dhcp_pool_network_cmd,
       "network A.B.C.D A.B.C.D",
       "Network number and mask\n"
       "Network number in dotted-decimal notation\n"
       "Network mask or prefix length\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);
    if( (*(argv[0])=='0')||(*(argv[1])=='0') )
    {
        vty_out (vty,"%s / %s is an invalid network.\n",argv[0],argv[1]);
        return CMD_WARNING;
    }

    strcpy(buf,"network ");
    strcat(buf,argv[0]);
    strcat(buf," ");
    strcat(buf,argv[1]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_network ,
       no_ip_dhcp_pool_network_cmd,
       "no network A.B.C.D A.B.C.D",
       NO_STR
       "Network number and mask\n"
       "Network number in dotted-decimal notation\n"
       "Network mask or prefix length\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);

    strcpy(buf,"no network ");
    strcat(buf,argv[0]);
    strcat(buf," ");
    strcat(buf,argv[1]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret == -1)
        return CMD_WARNING;
    else if(ret == -2)
    {
        vty_out (vty,"\% Range [ %s,  %s] is not in the database.\n",argv[0],argv[1]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_dnsserver_dnstince1,
       ip_dhcp_pool_dnsserver_dnstince1_cmd,
       "dns-server A.B.C.D",
       "DNS servers\n"
       "Server's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    if( (*(argv[0])=='0') )
        strcpy(buf,"dns-server 0.0.0.0");
    else
    {
        strcpy(buf,"dns-server ");
        strcat(buf,argv[0]);
    }

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}
DEFUN (ip_dhcp_pool_dnsserver_dnstince2,
       ip_dhcp_pool_dnsserver_dnstince2_cmd,
       "dns-server A.B.C.D A.B.C.D",
       "DNS servers\n"
       "Server's IP address\n"
       "Server's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);

    strcpy(buf,"dns-server ");
    if( (*(argv[0])=='0') )
        strcat(buf,"0.0.0.0");
    else
        strcat(buf,argv[0]);

    if( (*(argv[1])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[1]);
    }

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}
DEFUN (ip_dhcp_pool_dnsserver ,
       ip_dhcp_pool_dnsserver_cmd,
       "dns-server A.B.C.D  A.B.C.D A.B.C.D",
       "DNS servers\n"
       "Server's IP address\n"
       "Server's IP address\n"
       "Server's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[2];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);
    change_ipv4address(argv[2]);

    strcpy(buf,"dns-server ");
    if( (*(argv[0])=='0') )
        strcat(buf,"0.0.0.0");
    else
        strcat(buf,argv[0]);

    if( (*(argv[1])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[1]);
    }

    if( (*(argv[2])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[2]);
    }
    /*
    		strcpy(buf,"dns-server ");
    		strcat(buf,argv[0]);
    		strcat(buf," ");
    		strcat(buf,argv[1]);
    		strcat(buf," ");
    		strcat(buf,argv[2]);
    */
    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_dnsserver ,
       no_ip_dhcp_pool_dnsserver_cmd,
       "no dns-server",
       NO_STR
       "DNS servers\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"no dns-server ");

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_defaultroute_dnstince1,
       ip_dhcp_pool_defaultroute_dnstince1_cmd,
       "default-router A.B.C.D",
       "Default routers\n"
       "Router's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    if( (*(argv[0])=='0') )
        strcpy(buf,"default-router 0.0.0.0");
    else
    {
        strcpy(buf,"default-router ");
        strcat(buf,argv[0]);
    }

    //strcpy(buf,"default-router ");
    //strcat(buf,argv[0]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}
/*
DEFUN (no_ip_dhcp_pool_defaultroute_dnstince1,
       no_ip_dhcp_pool_defaultroute_dnstince1_cmd,
       "no default-router A.B.C.D",
       NO_STR
      "Default routers\n"
       "Router's IP address\n"
      )
{
   return CMD_SUCCESS;
}
*/
DEFUN (ip_dhcp_pool_defaultroute_dnstince2,
       ip_dhcp_pool_defaultroute_dnstince2_cmd,
       "default-router A.B.C.D A.B.C.D",
       "Default routers\n"
       "Router's IP address\n"
       "Router's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);

    strcpy(buf,"default-router ");
    if( (*(argv[0])=='0') )
        strcat(buf,"0.0.0.0");
    else
        strcat(buf,argv[0]);

    if( (*(argv[1])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[1]);
    }
    /*
    		strcpy(buf,"default-router ");
    		strcat(buf,argv[0]);
    		strcat(buf," ");
    		strcat(buf,argv[1]);
    */
    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_defaultroute,
       ip_dhcp_pool_defaultroute_cmd,
       "default-router A.B.C.D  A.B.C.D A.B.C.D",
       "Default routers\n"
       "Router's IP address\n"
       "Router's IP address\n"
       "Router's IP address\n"
      )
{
    char buf[1024] = {0};
    int ret;
    int i;
    char *p=NULL;

    i=0;
    p = argv[0];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[1];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    i=0;
    p = argv[2];
    if(*p=='.')
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }
    while( *p!='\0' )
    {
        if( *p== '.' )
            i++;
        p++;
    }
    p--;
    if( (i!=3)||(*p== '.') )
    {
        vty_out (vty,"% [ZEBRA] Unknown command: %s\n",buf);
        return CMD_WARNING;
    }

    change_ipv4address(argv[0]);
    change_ipv4address(argv[1]);
    change_ipv4address(argv[2]);

    strcpy(buf,"default-router ");
    if( (*(argv[0])=='0') )
        strcat(buf,"0.0.0.0");
    else
        strcat(buf,argv[0]);

    if( (*(argv[1])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[1]);
    }

    if( (*(argv[2])=='0') )
    {
        strcat(buf," ");
        strcat(buf,"0.0.0.0");
    }
    else
    {
        strcat(buf," ");
        strcat(buf,argv[2]);
    }
    /*
    		strcpy(buf,"default-router ");
    		strcat(buf,argv[0]);
    		strcat(buf," ");
    		strcat(buf,argv[1]);
    		strcat(buf," ");
    		strcat(buf,argv[2]);
    */
    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_defaultroute,
       no_ip_dhcp_pool_defaultroute_cmd,
       "no default-router ",
       NO_STR
       "Default routers\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"no default-router ");

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease,
       ip_dhcp_pool_lease_cmd,
       "lease (<0-365>|infinite)",
       "Address lease time\n"
       "<0-365> Days\n"
       "Lease time is infinited\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"lease ");
    if( *(argv[0])=='i' )
        strcpy(argv[0],"infinite");
    strcat(buf,argv[0]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease_hours,
       ip_dhcp_pool_lease_hours_cmd,
       "lease <0-365> <0-23>",
       "Address lease time\n"
       "<0-365> Days\n"
       "<0-23> Hours\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"lease ");
    strcat(buf,argv[0]);
    strcat(buf," ");
    strcat(buf,argv[1]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease_minutes,
       ip_dhcp_pool_lease_minutes_cmd,
       "lease <0-365> <0-23> <0-59>",
       "Address lease time\n"
       "<0-365> Days\n"
       "<0-23> Hours\n"
       "<0-59>  Minutes\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"lease ");
    strcat(buf,argv[0]);
    strcat(buf," ");
    strcat(buf,argv[1]);
    strcat(buf," ");
    strcat(buf,argv[2]);

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_lease,
       no_ip_dhcp_pool_lease_cmd,
       "no lease",
       NO_STR
       "Address lease time\n"
      )
{
    char buf[1024] = {0};
    int ret;

    strcpy(buf,"no lease");

    //	vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver(vty,buf);
    if(ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}
#endif
#ifdef HAVE_DHCPV4
int zebra_dhcp_write_config(struct vty *vty)
{
    struct sockaddr_in my_addr;
    DHCP_CFG_TABLE *pTempData;
    DHCP_CFG_HEAD *pstCfgHead;
    int fd,i,j;
    char cBuf[4096];
    char *tempBuf;
    char testBuf[32];
    int len;


    bzero(&my_addr,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(8889);
    my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");




    fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(fd == -1)
    {
        vty_out (vty,"socket fault!\n");
        return CMD_SUCCESS;
    }

    if(connect(fd,(struct sockaddr *)&my_addr,sizeof(my_addr)) == -1)
    {
        //vty_out (vty,"dhcp server progress does not open!\n");
        return CMD_SUCCESS;
    }


    if(send(fd,"2recv",sizeof("2recv"),0) == -1)
    {
        vty_out (vty,"send fault!\n");
        return CMD_SUCCESS;
    }

    if((len =recv(fd,cBuf,4096,0)) == -1)
    {
        vty_out (vty,"revc show running fault!\n");
        return CMD_SUCCESS;
    }

    pstCfgHead = (DHCP_CFG_HEAD *)cBuf;
    tempBuf = cBuf+4;


    //vty_out(vty,"count is %d,len is %d",pstCfgHead->count,len);
    //vty_out (vty, "%s", VTY_NEWLINE);

    //vty_out(vty,"%s","!");
    for(i = 0; i<pstCfgHead->count; i++)
    {
        //vty_out(vty,"-----------11--------\n");
        pTempData = (DHCP_CFG_TABLE *)tempBuf;
        vty_out(vty,"%s",pTempData->OneCmdLine);
        vty_out (vty, "%s", VTY_NEWLINE);
        tempBuf+=128;
    }
    vty_out(vty,"%s","!");
    vty_out (vty, "%s", VTY_NEWLINE);
    //vty_out(vty,"%s","!");
    //vty_out (vty, "%s", VTY_NEWLINE);

    close(fd);
    return CMD_SUCCESS;
}
#endif
/*add dhcp ,add by huang jing in 2013 5 14*/
#ifdef HAVE_IPV6
/* General fucntion for IPv6 static route. */
static int
static_ipv6_func (struct vty *vty, int add_cmd, const char *dest_str,
                  const char *gate_str, const char *ifname,
                  const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr *gate = NULL;
    struct in6_addr gate_addr;
    u_char type = 0;
    int table = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Route flags */
    if (flag_str)
    {
        switch(flag_str[0])
        {
        case 'r':
        case 'R': /* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B': /* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is valid IPv6 addrees, then gate is treated as
       nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate_addr);

    if (ifname)
    {
        /* When ifname is specified.  It must be come with gateway
           address. */
        if (ret != 1)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        type = STATIC_IPV6_GATEWAY_IFNAME;
        gate = &gate_addr;
    }
    else
    {
        if (ret == 1)
        {
            type = STATIC_IPV6_GATEWAY;
            gate = &gate_addr;
        }
        else
        {
            type = STATIC_IPV6_IFNAME;
            ifname = gate_str;
        }
    }

    if (add_cmd)
        static_add_ipv6 (&p, type, gate, ifname, flag, distance, table);
    else
        static_delete_ipv6 (&p, type, gate, ifname, distance, table);

    return CMD_SUCCESS;
}

/*struct nat64_prefix{
             struct in6_addr prefix;
             int len;
             int ubit;
};
*/
static int str_to_prefix6(const char *str,struct ion_prefix *prefix)
{
    char *s=NULL;
    char *p=NULL;
    int ret;
    s=strchr(str,'/');
    p = malloc(s-str+1);
    prefix->len = atoi(++s);
    strncpy(p,str,s-str-1);
    *(p + (s - str - 1)) = '\0';
    ret=inet_pton(AF_INET6,p,&(prefix->prefix));
    free(p);
    return ret ;
}

/*NAT64 prefix*/

DEFUN(nat64_prefix,
      nat64_prefix_cmd,
      "nat64 prefix X:X::X:X/M (ubit|no-ubit)",
      "Configure nat64 protocol\n"
      "Configure IPv6 prefix\n"
      "prefix/prefix_length\n"
      "with ubit\n"
      "without ubit\n"
     )
{
#define SIOCADDNAT64PREFIX SIOCCHGTUNNEL
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    struct tnl_parm nat64;
    char cNAT64[]="nat64";
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    strcpy(ifr.ifr_name,cNAT64);
    ret = str_to_prefix6(argv[0],&(nat64.prefix));
    if(ret == 0)
    {
        vty_out(vty,"input error prefix\n");
        close(socketfd);
        return -1;
    }
    if(argc == 2)
    {
#if 0
        if(strcmp(argv[1],"ubit") != 0 && strcmp(argv[1],"no-ubit") != 0)
        {
            vty_out(vty,"input error UBIT\n");
            close(socketfd);
            return -1;
        }
        else if(strcmp(argv[1],"ubit") == 0)
            nat64.prefix.ubit = 1;
        else if(strcmp(argv[1],"no-ubit") == 0)
            nat64.prefix.ubit = 0;
#endif
        if( *(argv[1])=='n' )
        {
            strcpy(argv[1],"no-ubit");
            nat64.prefix.ubit = 0;
        }
        else if( *(argv[1])=='u' )
        {
            strcpy(argv[1],"ubit");
            nat64.prefix.ubit = 1;
        }
        else
        {
            vty_out(vty,"input error UBIT\n");
            close(socketfd);
            return -1;
        }
    }
    else
        nat64.prefix.ubit = 1;
    nat64.proto = IPPROTO_IPIP;
    ifr.ifr_data=&nat64;

    ret=ioctl(socketfd, SIOCADDNAT64PREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    //static_ipv6_func (vty, 1, argv[0],argv[1],NULL, NULL, NULL);
    close(socketfd);
    return CMD_SUCCESS;
}

/*no nat64 prefix ---delete nat64 prefix*/
DEFUN(no_nat64_prefix,
      no_nat64_prefix_cmd,
      "no nat64 prefix X:X::X:X/M",
      NO_STR
      "Configure nat64 protocol\n"
      "Configure IPv6 prefix\n"
      "prefix/prefix_length\n"
     )
{
#define SIOCDELNAT64PREFIX  (SIOCCHGTUNNEL+9)
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    struct tnl_parm nat64;
    char cNAT64[]="nat64";

    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    strcpy(ifr.ifr_name,cNAT64);
    ret = str_to_prefix6(argv[0],&(nat64.prefix));
    if(ret == 0)
    {
        vty_out(vty,"input error prefix\n");
        close(socketfd);
        return -1;
    }
    nat64.proto = IPPROTO_IPIP;
    ifr.ifr_data=&nat64;

    ret=ioctl(socketfd,SIOCDELNAT64PREFIX ,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        if(errno == 36)
        {
            vty_out(vty,"input error prefix!\n");
        }
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
}

#if 0
/* show nat64 prefix */
DEFUN(show_nat64_prefix,
      show_nat64_prefix_cmd,
      "show nat64 prefix INTERFACE",
      SHOW_NAT64_PREFIX
      "INTERFACE : interface name\n"
     )
{
#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    struct tnl_parm nat64;
    int socketfd;
    int ret=0;
    char pre[40];
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name,argv[0],strlen(argv[0])+1);
    ifr.ifr_data=&nat64;
    ret=ioctl(socketfd,SIOCGETPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    if(nat64.prefix.len == 0)
    {
        vty_out(vty,"prefix is 0\n");
    }
    else
    {
        inet_ntop(AF_INET6,&(nat64.prefix.prefix),pre,40);
        vty_out(vty,"ivi prefix is  %s/",pre);
        vty_out(vty,"%d     ",nat64.prefix.len);
        if(nat64.prefix.ubit == 1)
        {
            vty_out(vty,"ubit\n");
        }
    }
    close(socketfd);
    return CMD_SUCCESS;
}
#endif
/*configure ivi prefix*/
DEFUN(ivi_prefix,
      ivi_prefix_cmd,
      "ivi prefix X:X::X:X/M (ubit|no-ubit)",
      //   IVI_STR
      "configure ivi prefix\n"
      "ivi ipv6 prefix\n"
      "prefix/prefix_length\n"
      "with ubit\n"
      "without ubit\n"
     )
{
#define SIOCCFGPREFIX  SIOCCHGTUNNEL
    struct ifreq ifr;
    //struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret=0;
    struct prefix p;
    struct prefix_ipv6 *pIPv6;
    char cIVI64[]="ivi";
    //char cIVI46[]="ivi46";
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }

    ret = str2prefix (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }
    pIPv6 = (struct prefix_ipv6 *)&p;
    strcpy(ifr.ifr_name,cIVI64);

    ivi64.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi64.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi64.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi64.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi64.prefix.len=pIPv6->prefixlen;
#if 0
    ivi46.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi46.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi46.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi46.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi46.prefix.len=pIPv6->prefixlen;
#endif
#if 0
    if(strcmp("ubit",argv[1])==0)
    {
        ivi64.prefix.ubit = 1;
        ivi46.prefix.ubit = 1;
    }
    else if(strcmp("no-ubit",argv[1])==0)
    {
        ivi64.prefix.ubit = 0;
        ivi46.prefix.ubit = 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }
#endif
    if( *(argv[1]) == 'u' )
    {
        strcpy(argv[1],"ubit");
        ivi64.prefix.ubit = 1;
        //ivi46.prefix.ubit = 1;
    }
    else if( *(argv[1]) == 'n' )
    {
        strcpy(argv[1],"no-ubit");
        ivi64.prefix.ubit = 0;
        //ivi46.prefix.ubit = 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }

    ivi64.proto = IPPROTO_IPIP;
    ifr.ifr_data=&ivi64;
    //vty_out(vty, "name is %s", ifr.ifr_name);
    ret=ioctl(socketfd,SIOCCFGPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error6: %d\n",errno);
        close(socketfd);
        return -1;
    }
#if 0
    ivi46.proto = IPPROTO_IPIP;
    ifr.ifr_data=&ivi46;
    strcpy(ifr.ifr_name,cIVI46);
    ret=ioctl(socketfd,SIOCCFGPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error7: %d\n",errno);
        close(socketfd);
        return -1;
    }
#endif
    close(socketfd);
    return CMD_SUCCESS;

}
#if 0
/*configure ivi prefix*/
DEFUN(ivi_prefix,
      ivi_prefix_cmd,
      "ivi prefix X:X::X:X/M (ubit|no-ubit)",
      //   IVI_STR
      "configure ivi prefix\n"
      "ivi ipv6 prefix\n"
      "prefix/prefix_length\n"
      "with ubit\n"
      "without ubit\n"
     )
{
#define SIOCCFGPREFIX  SIOCCHGTUNNEL
    struct ifreq ifr;
    struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret=0;
    struct prefix p;
    struct prefix_ipv6 *pIPv6;
    char cIVI64[]="ivi64";
    char cIVI46[]="ivi46";
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }

    ret = str2prefix (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }
    pIPv6 = (struct prefix_ipv6 *)&p;
    strcpy(ifr.ifr_name,cIVI64);

    ivi64.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi64.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi64.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi64.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi64.prefix.len=pIPv6->prefixlen;

    ivi46.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi46.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi46.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi46.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi46.prefix.len=pIPv6->prefixlen;
#if 0
    if(strcmp("ubit",argv[1])==0)
    {
        ivi64.prefix.ubit = 1;
        ivi46.prefix.ubit = 1;
    }
    else if(strcmp("no-ubit",argv[1])==0)
    {
        ivi64.prefix.ubit = 0;
        ivi46.prefix.ubit = 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }
#endif
    if( *(argv[1]) == 'u' )
    {
        strcpy(argv[1],"ubit");
        ivi64.prefix.ubit = 1;
        ivi46.prefix.ubit = 1;
    }
    else if( *(argv[1]) == 'n' )
    {
        strcpy(argv[1],"no-ubit");
        ivi64.prefix.ubit = 0;
        ivi46.prefix.ubit = 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }

    ifr.ifr_data=&ivi64;
    strcpy(ifr.ifr_name,cIVI64);
    ret=ioctl(socketfd,SIOCCFGPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }

    ivi46.proto = IPPROTO_IPIP;
    ifr.ifr_data=&ivi46;
    strcpy(ifr.ifr_name,cIVI46);
    ret=ioctl(socketfd,SIOCCFGPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;

}
#endif
DEFUN(no_ivi_prefix,
      no_ivi_prefix_cmd,
      "no ivi prefix X:X::X:X/M",
      NO_STR
      //     IVI_STR
      "configure ivi prefix\n"
      "ivi ipv6 prefix\n"
      "prefix/prefix_length\n"
     )
{
#define SIOCDELPREFIX  (SIOCCHGTUNNEL+9)
    struct ifreq ifr;
    //struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret=0;
    struct prefix ivip;
    struct prefix_ipv6 *pIPv6;
    char cIVI64[]="ivi";
    //char cIVI46[] = "ivi46";

    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }

    ret = str2prefix (argv[0], &ivip);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        close(socketfd);
        return CMD_WARNING;
    }

    pIPv6 = (struct prefix_ipv6 *)&ivip;
    strcpy(ifr.ifr_name,cIVI64);

    ivi64.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi64.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi64.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi64.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi64.prefix.len=pIPv6->prefixlen;
#if 0
    ivi46.prefix.prefix.s6_addr32[0] = ntohl(pIPv6->prefix.s6_addr32[0]);
    ivi46.prefix.prefix.s6_addr32[1] = ntohl(pIPv6->prefix.s6_addr32[1]);
    ivi46.prefix.prefix.s6_addr32[2] = ntohl(pIPv6->prefix.s6_addr32[2]);
    ivi46.prefix.prefix.s6_addr32[3] = ntohl(pIPv6->prefix.s6_addr32[3]);
    ivi46.prefix.len=pIPv6->prefixlen;
#endif
    ifr.ifr_data=&ivi64;

    ivi64.proto = IPPROTO_IPIP;
    strcpy(ifr.ifr_name,cIVI64);
    ret=ioctl(socketfd,SIOCDELPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        if(errno == 36)
            vty_out(vty,"ret=%d,prefix is not existed,delete fail!\n",ret);
        close(socketfd);
        return -1;
    }

#if 0
    ifr.ifr_data=&ivi46;
    ivi46.proto = IPPROTO_IPIP;
    strcpy(ifr.ifr_name,cIVI46);
    ret=ioctl(socketfd,SIOCDELPREFIX,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error9: %d\n",errno);
        if(errno == 36)
            vty_out(vty,"ret=%d,prefix is not existed,delete fail!\n",ret);
        close(socketfd);
        return -1;
    }
#endif
    //static_ipv6_func (vty, 0 , argv[0],argv[1],NULL, NULL, NULL);
    close(socketfd);
    return CMD_SUCCESS;
}
//ecn check
struct tc_red_info
{
    char use_flag;
    int use_num;
    struct  tc_red_qopt tc_ecn_info;
};
struct tc_red_info red_ecn_opt[4];
//struct  tc_red_qopt red_ecn_opt[4];
struct if_politic_qdisc *if_ecn_head;
int zebra_ecn_write_config(struct vty *vty, char *ifname)
{
    vty_out(vty,"!%s",VTY_NEWLINE);
    int i = 0;
    for(i=0; i<4; i++)
    {
        if(red_ecn_opt[i].use_flag != 0)
            //vty_out(vty,"ecn %d red minth %d maxth %d wlog %d plog %d%s",i+1,red_ecn_opt[i].qth_min,red_ecn_opt[i].qth_max,red_ecn_opt[i].Wlog,red_ecn_opt[i].Plog,VTY_NEWLINE);
            vty_out(vty,"ecn %d red minth %d maxth %d %s",i+1,red_ecn_opt[i].tc_ecn_info.qth_min,red_ecn_opt[i].tc_ecn_info.qth_max,VTY_NEWLINE);
    }
    vty_out(vty,"!%s",VTY_NEWLINE);

    if(if_ecn_head != NULL)
    {
        vty_out(vty,"!%s",VTY_NEWLINE);
        struct if_politic_qdisc *p = if_ecn_head;
        while(p != NULL)
        {
            vty_out(vty,"ecn %s red politic %d %s",p->ifname,p->politic,VTY_NEWLINE);
            p = p->next;
        }
        vty_out(vty,"!%s",VTY_NEWLINE);
    }

    return CMD_SUCCESS;

}
//end add
int zebra_ivi_write_config(struct vty *vty, char *ifname)
{
#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    // struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret=0;
    char pre[40];
    //char argv[2][16] = {{"ivi46"},{"ivi64"}};
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        //vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name,ifname,strlen(ifname)+1);
    if(strcmp(ifname,"ivi")==0)
    {
        ifr.ifr_data=&ivi64;
        ret=ioctl(socketfd,SIOCGETPREFIX,&ifr);
        if(ret == -1)
        {
            //vty_out(vty,"ioctl error10: %d\n",errno);
            close(socketfd);
            return -1;
        }
        if(ivi64.prefix.len == 0 && ivi64.prefix.ubit == 0)
        {
            //vty_out(vty,"the prefix is 0\n");
        }
        else
        {
            ivi64.prefix.prefix.s6_addr32[0] = ntohl(ivi64.prefix.prefix.s6_addr32[0]);
            ivi64.prefix.prefix.s6_addr32[1] = ntohl(ivi64.prefix.prefix.s6_addr32[1]);
            ivi64.prefix.prefix.s6_addr32[2] = ntohl(ivi64.prefix.prefix.s6_addr32[2]);
            ivi64.prefix.prefix.s6_addr32[3] = ntohl(ivi64.prefix.prefix.s6_addr32[3]);
            inet_ntop(AF_INET6,&(ivi64.prefix.prefix),pre,40);
            vty_out(vty,"ivi prefix %s/",pre);
            vty_out(vty,"%d ",ivi64.prefix.len);
            if(ivi64.prefix.ubit == 1)
            {
                vty_out(vty,"ubit");
            }
            else
            {
                vty_out(vty,"no-ubit");
            }
            //vty_out(vty,"%s", ifname);
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
    close(socketfd);
    return CMD_SUCCESS;
}
#if 0
int zebra_ivi_write_config(struct vty *vty, char *ifname)
{
#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret=0;
    char pre[40];
    //char argv[2][16] = {{"ivi46"},{"ivi64"}};
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        //vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name,ifname,strlen(ifname)+1);
    if(strcmp(ifname,"ivi46")==0)
    {
        ifr.ifr_data=&ivi46;
        ret=ioctl(socketfd,SIOCGETPREFIX,&ifr);
        if(ret == -1)
        {
            //vty_out(vty,"ioctl error: %d\n",errno);
            close(socketfd);
            return -1;
        }
        if(ivi46.prefix.len == 0 && ivi46.prefix.ubit == 0)
        {
            //vty_out(vty,"the prefix is 0\n");
        }
        else
        {
            ivi46.prefix.prefix.s6_addr32[0] = ntohl(ivi46.prefix.prefix.s6_addr32[0]);
            ivi46.prefix.prefix.s6_addr32[1] = ntohl(ivi46.prefix.prefix.s6_addr32[1]);
            ivi46.prefix.prefix.s6_addr32[2] = ntohl(ivi46.prefix.prefix.s6_addr32[2]);
            ivi46.prefix.prefix.s6_addr32[3] = ntohl(ivi46.prefix.prefix.s6_addr32[3]);
            inet_ntop(AF_INET6,&(ivi46.prefix.prefix),pre,40);
            vty_out(vty,"ivi prefix %s/",pre);
            vty_out(vty,"%d ",ivi46.prefix.len);
            if(ivi46.prefix.ubit == 1)
            {
                vty_out(vty,"ubit");
            }
            else
            {
                vty_out(vty,"no-ubit");
            }
            //vty_out(vty,"%s", ifname);
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
    close(socketfd);
    return CMD_SUCCESS;
}

#endif


/*nat64 timeout*/
DEFUN(nat64_timeout,
      nat64_timeout_cmd,
      "nat64 timeout (tcp|udp|icmp) TIMEOUT_VALUE",
      "Configure nat64 protocol\n"
      "Configure nat64 map item's timeout parameter\n"
      "tcp Transmission Control Protocol\n"
      "udp User Datagram Protocol\n"
      "Internet Control Message Protocol\n"
      "timeout value\n")
{
#define TYPE_LEN 10
#define NAT64_CONFIG_TIMER (SIOCCHGTUNNEL + 12)
    struct ifreq ifr;
    struct nat64_timer
    {
        char date_type[TYPE_LEN];
        int value;
    };
    int socketfd;
    int ret=0;
    struct nat64_timer time;
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name,"nat64",6);
    memcpy(time.date_type,argv[0],strlen(argv[0])+1);
    time.value = atoi(argv[1]);
    ifr.ifr_data=&time;

    ret=ioctl(socketfd,NAT64_CONFIG_TIMER,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
}

/*nat64 timeout*/
DEFUN(no_nat64_timeout,
      no_nat64_timeout_cmd,
      "no nat64 timeout (tcp|udp|icmp) TIMEOUT_VALUE",
      NO_STR
      "Configure nat64 protocol\n"
      "Configure nat64 map item's timeout parameter\n"
      "tcp Transmission Control Protocol\n"
      "udp User Datagram Protocol\n"
      "Internet Control Message Protocol\n"
      "timeout value\n")
{
#define TYPE_LEN 10
#define NAT64_DEL_TIMER (SIOCCHGTUNNEL + 13)
    struct ifreq ifr;
    struct nat64_timer
    {
        char date_type[TYPE_LEN];
        int value;
    };
    int socketfd;
    int ret=0;
    struct nat64_timer time;
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name,"nat64",6);
    memcpy(time.date_type,argv[0],strlen(argv[0])+1);
    time.value = atoi(argv[1]);
    ifr.ifr_data=&time;

    ret=ioctl(socketfd,NAT64_DEL_TIMER,&ifr);
    if(ret == -1)
    {
        vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
}

#ifdef HAVE_4OVER6_TCPMSS
/*tunnel4o6 tcp mss  cmd*/
DEFUN(tunnel4o6_tcp_mss,
      tunnel4o6_tcp_mss_cmd,
      "tunnel4o6 tcp mss <1400-1500>",
      "IPv4 over IPv6 tunnle\n"
      "Transmission Control Protocol\n"
      "Maxitum Segment Size\n"
      "<1400-1500>\n")
{
#define SIOCTCPMSSSET (SIOCCHGTUNNEL + 9)
#define MSS_OVERFLOW 40

    struct tcp_mss
    {
        int mss;
        int flag;
    };
    struct tcp_mss set_mss;

    struct ifreq ifr;

    struct zebra_4over6_tunnel_entry *pNew;
    struct zebra_4over6_tunnel_entry *pNext;

    pNew = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;

    int socketfd;
    int ret = 0;
    int cmd = 0;
    int num = 0;
    char *c4OVER6;

//	vty_out(vty, "come here!: %d\n", num);
    while(pNext != NULL)
    {


        if(pNext->name != NULL)
        {
            c4OVER6 = pNext->name;

            //	vty_out(vty, "name : %s\n", c4OVER6);
            set_mss.mss = atoi(argv[0]);
            set_mss.flag = 1;


            memset(&save_tunnel4o6_tcpmss, 0, sizeof(save_tunnel4o6_tcpmss));
            save_tunnel4o6_tcpmss.mss_value = set_mss.mss;
            save_tunnel4o6_tcpmss.mss_flag = set_mss.flag;


            socketfd = socket(AF_INET6, SOCK_DGRAM, 0);

            if (socketfd < 0)
            {
                vty_out(vty, "socket_error\n");
                return -1;
            }
            cmd =  SIOCTCPMSSSET;

            strcpy(ifr.ifr_name, c4OVER6);
            //	vty_out(vty, "ifr.ifr_name: %s argv[0] %d\n",ifr.ifr_name, atoi(argv[0]));
            ifr.ifr_data = &set_mss;

            ret = ioctl (socketfd, cmd, &ifr);
            if (ret == -1)
            {
                vty_out(vty, "ioctl error13: %d\n", errno);

                if (errno ==  MSS_OVERFLOW)
                {
                    vty_out(vty, "you input mss is over range<1-1500>\n");
                }

                close(socketfd);
                return -1;
            }
        }
        num++;
        pNext = pNext->next;
    }

//	vty_out(vty, "leave here!: %d\n", num);
    close(socketfd);
    return CMD_SUCCESS;
}
#endif

#if 1
DEFUN(no_tunnel4o6_tcp_mss,
      no_tunnel4o6_tcp_mss_cmd,
      "no tunnel4o6 tcp mss <1400-1500>",
      NO_STR
      //TCP_STR
      "IPv4 over IPv6 tunnle\n"
      "Transmission Control Protocol\n"
      "Maxitum Segment Size\n"
      "the configured size for mss\n"
     )
{
#define SIOCTCPMSSDEL (SIOCCHGTUNNEL + 10)
#define DEL_ERR 41

    struct tcp_mss
    {
        int mss;
        int flag;
    };
    struct tcp_mss set_mss;

    struct ifreq ifr;

    struct zebra_4over6_tunnel_entry *pNew;
    struct zebra_4over6_tunnel_entry *pNext;

    pNew = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;

    int socketfd;
    int ret = 0;
    int cmd = 0;
    int num = 0;
    char *c4OVER6;

    //	vty_out(vty, "come here!: %d\n", num);
    while(pNext != NULL)
    {


        if(pNext->name != NULL)
        {
            c4OVER6 = pNext->name;

            //vty_out(vty, "name : %s\n", c4OVER6);
            set_mss.mss = atoi(argv[0]);
            set_mss.flag = 1;


            memset(&save_tunnel4o6_tcpmss, 0, sizeof(save_tunnel4o6_tcpmss));
            save_tunnel4o6_tcpmss.mss_value = 0;
            save_tunnel4o6_tcpmss.mss_flag  = 0;


            socketfd = socket(AF_INET6, SOCK_DGRAM, 0);

            if (socketfd < 0)
            {
                vty_out(vty, "socket_error\n");
                return -1;
            }
            cmd =  SIOCTCPMSSDEL;

            strcpy(ifr.ifr_name, c4OVER6);
            //vty_out(vty, "ifr.ifr_name: %s argv[0] %d\n",ifr.ifr_name, atoi(argv[0]));
            ifr.ifr_data = &set_mss;

            ret = ioctl (socketfd, cmd, &ifr);
            if (ret == -1)
            {
                vty_out(vty, "ioctl error*: %d\n", errno);
                if (errno ==  DEL_ERR)
                {
                    vty_out(vty, "ret=%d,4over6 tcp mss is not existed,delete fail!\n",ret);
                }
                close(socketfd);
                return -1;
            }
        }
        num++;
        pNext = pNext->next;
    }

    //	vty_out(vty, "leave here!: %d\n", num);
    close(socketfd);
    return CMD_SUCCESS;
}

#endif

#if 0

/* manage 4over6 tunnel */
DEFUN(fover6_tunnel ,
      fover6_tunnel_cmd ,
      "4over6 tunnel OPTION TUNNEL_NAME X:X::X:X  X:X::X:X [STATE]",
      TUNNEL_STR
      "--OPTION='add'/'del'/'chg'  create/delete 4over6 tunnel,or change 4over6 tunnel state\n"
      "tunnel_name\n"
      "local ipv6 addr\n"
      "remote ipv6 addr\n"
      "[up/down]  tunnel state\n")
{
    struct ifreq ifr;
    struct ip6_tnl_parm  ip6;

    int socketfd;
    int ret=0;
    int cmd=0;

    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        vty_out(vty,"socket error\n");
        return -1;
    }

    if(strcmp("del",argv[0])==0)
    {
        memcpy(ifr.ifr_name,argv[1],strlen(argv[1])+1);
        ifr.ifr_flags = 0;  //IFF_DOWN;
        ret=ioctl(socketfd,SIOCSIFFLAGS,&ifr);
        if(ret == -1)
        {
            vty_out(vty,"ioctl error: %d\n",errno);
            close(socketfd);
            return -1;
        }

        ip6.proto = IPPROTO_IPIP;
        cmd = SIOCDELTUNNEL;
        ifr.ifr_data = &ip6;
        memcpy(ifr.ifr_name,argv[1],strlen(argv[1])+1);
        ret=ioctl(socketfd,cmd,&ifr);
        if(ret == -1)
        {
            vty_out(vty,"ioctl error: %d\n",errno);
            close(socketfd);
            return -1;
        }
    }
    else
    {


        if(strcmp("chg",argv[0])==0)
        {
            if(argc == 5)
            {
                if(strcmp(argv[4],"up")==0 )
                    ifr.ifr_flags = IFF_UP;//up
                else if(strcmp(argv[4],"down")==0)
                    ifr.ifr_flags = 0; //down
                memcpy(ifr.ifr_name,argv[1],strlen(argv[1])+1);
                ret=ioctl(socketfd,SIOCSIFFLAGS,&ifr);
                if(ret == -1)
                {
                    vty_out(vty,"set flags down ioctl error : %d\n",errno);
                    close(socketfd);
                    return -1;
                }
            }
        }
        else if(strcmp("add",argv[0])==0)
        {
            cmd = SIOCADDTUNNEL;
            memcpy(ifr.ifr_name,"ip6tnl0",8);
            memcpy(ip6.name,argv[1],strlen(argv[1])+1);

            ip6.proto = IPPROTO_IPIP;
            ret=inet_pton(AF_INET6,argv[2],&(ip6.laddr));
            if(ret == 0)
            {
                vty_out(vty,"error LOACAL_ADDRESS\n");
                close(socketfd);
                return -1;
            }
            ret=inet_pton(AF_INET6,argv[3],&(ip6.raddr));
            if(ret == 0)
            {
                vty_out(vty,"error REMOTE_ADDRESS\n");
                close(socketfd);
                return -1;
            }
            ip6.hop_limit = 64;
            ifr.ifr_data = &ip6;
            ret=ioctl(socketfd,cmd,&ifr);
            if(ret == -1)
            {
                vty_out(vty,"ioctl error: %d\n",errno);
                close(socketfd);
                return -1;
            }
            memcpy(ifr.ifr_name,argv[1],strlen(argv[1])+1);
            ifr.ifr_flags = IFF_UP;
            ret=ioctl(socketfd,SIOCSIFFLAGS,&ifr);
            if(ret == -1)
            {
                vty_out(vty,"ioctl error: %d\n",errno);
                close(socketfd);
                return -1;
            }
        }
        else
        {
            vty_out(vty,"error OPTION: %s\n",argv[3]);
            close(socketfd);
            return -1;
        }
    }
    close(socketfd);
    return CMD_SUCCESS;
}

#endif

//sangmeng add for ssh
DEFUN (ssh_username_passwd,
       ssh_username_passwd_cmd,
       "ssh username WORD passwd WORD",
       "ssh\n"
       "ssh login username\n"
       "username must be less than 16 characters\n"
       "ssh login passwd\n"
       "passwd\n")
{
#if 1

    //check exists ssh username and del it
    char sshusername[16];
    char cmd[128];
    FILE *fp;
    int fd;

    //if the file is not existed , then created it
    if (access("/usr/local/etc/ssh.txt", F_OK) == -1)
    {
        fd = open("/usr/local/etc/ssh.txt", O_CREAT , S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
        if (fd < 0)
        {
            vty_out(vty, "open file failed %s", VTY_NEWLINE);
            close(fd);
            return -1;
        }
        close(fd);
    }


    if((fp=fopen("/usr/local/etc/ssh.txt","rt+"))==NULL)
    {
        vty_out (vty, "can't open the file %s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    //add new username add passwd
    memset(sshusername, 0, sizeof(sshusername));
    fread(sshusername, 1, 16, fp);
    if (strlen(sshusername) != 0)
    {
        sshusername[strlen(sshusername)-1] = '\0';
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "userdel -f %s", sshusername);
        system(cmd);
        memset(cmd, 0, sizeof(cmd));
    }
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "useradd %s -d /tmp", argv[0]);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "echo '%s' | passwd --stdin %s", argv[1], argv[0]);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "usermod -u 0 -o %s; usermod -g root %s; usermod -G root %s", argv[0], argv[0], argv[0]);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    printf(cmd, "%s", "cat /dev/null > /usr/local/etc/ssh.txt");
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "echo  %s > /usr/local/etc/ssh.txt", argv[0]);
    system(cmd);

    fclose(fp);
#endif

    return CMD_SUCCESS;
}

DEFUN (ipv6_control_server_addrss,
       ipv6_control_server_address_cmd,
       "ipv6 control-server WORD",
       IPV6_STR
       "control server\n"
       "control server address\n")
{
    FILE *fp;
    int ret;
    struct in6_addr addr6;

    ret = inet_pton(AF_INET6, argv[0], (void *)&addr6);
    if (ret <= 0)
    {
        vty_out(vty, " Please input correct ipv6 address. %s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if((fp=fopen("/usr/local/etc/address.dat","w+"))==NULL)
    {
        vty_out (vty, "Can not open the file. %s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    fwrite (argv[0], 1, strlen (argv[0]), fp);

    fclose(fp);

    return CMD_SUCCESS;

}
void show_configure_info(struct vty* vty, char *recv_buf)
{
    char prefix[128];
    int i;
    int count;
    int total_msg_len;
    int single_msg_len;
    //analyze control_msg
    struct comm_head *commhead = (struct comm_head *) recv_buf;

    total_msg_len = ntohs (commhead->len) - sizeof (struct comm_head);
    single_msg_len = sizeof (struct msg_head) + sizeof (struct prefix_msg);


    count = total_msg_len / single_msg_len;

#if 1
    for (i = 0; i < count; i++)
    {
        struct msg_head *msghead = (struct msg_head *) (commhead->data + i * (sizeof (struct msg_head) + sizeof (struct prefix_msg)));

        //analyze prefix_msg
        struct prefix_msg *prefixmsg = (struct prefix_msg *) (msghead->data);

        memset (prefix, 0, sizeof (prefix));
        inet_ntop (AF_INET6, &(prefixmsg->prefix), prefix, sizeof (prefix));
        vty_out (vty, "ipv6 address:%s prefix:%d", prefix, prefixmsg->prefixlen);

        if (msghead->chrType & PEOPLE_TYPE)
        {
            if (msghead->chrType & IN_AREA)
                vty_out (vty, " people prefix, in area %s", VTY_NEWLINE);
            else
                vty_out (vty, " people prefix, out area %s", VTY_NEWLINE);

        }
        else
        {
            if (msghead->chrType & IN_AREA)
                vty_out (vty, " army prefix, in area %s", VTY_NEWLINE);
            else
                vty_out (vty, " army prefix, out area %s", VTY_NEWLINE);
        }
    }

#endif
    return 0;

}

DEFUN (show_control_server_configure,
       show_control_server_configure_cmd,
       "show control-server configrue",
       SHOW_STR
       "control server\n"
       "configrue\n")
{
    int sockfd;
    int ret;
    size_t n;
    struct sockaddr_in socketaddress;

    sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd <= 0)
    {
        fprintf (stdout, "Create socket failed:%s\n", strerror (errno));
        return -1;
    }

    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (LOCAL_PORT);
    socketaddress.sin_addr.s_addr = inet_addr (LOCAL_ADDRESS);

    ret = connect (sockfd, (struct sockaddr *) &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        vty_out(vty, "Connect to %s:%d failed:%s %s", LOCAL_ADDRESS, LOCAL_PORT, strerror (errno), VTY_NEWLINE);
        close (sockfd);
        return CMD_WARNING;
    }

    char recv_buf[1024];
    memset (recv_buf, 0, sizeof (recv_buf));
    if ((n = recv (sockfd, recv_buf, sizeof (recv_buf), 0)) < 0)
    {
        vty_out (vty, "Read failed, errno is: %s:%d %s", strerror (errno), errno, VTY_NEWLINE);
        close(sockfd);
        return CMD_WARNING;
    }
    else if (n == 0)
    {
        vty_out (vty, "Read %ld bytes %s", n, VTY_NEWLINE);
        close(sockfd);
        return CMD_WARNING;
    }
    else
    {
        show_configure_info(vty, recv_buf);
    }

    close(sockfd);
    return CMD_SUCCESS;
}


DEFUN (ipv6_route,
       ipv6_route_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, NULL);
}

DEFUN (ipv6_route_flags,
       ipv6_route_flags_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2], NULL);
}

DEFUN (ipv6_route_ifname,
       ipv6_route_ifname_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, NULL);
}

DEFUN (ipv6_route_ifname_flags,
       ipv6_route_ifname_flags_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3], NULL);
}

DEFUN (ipv6_route_pref,
       ipv6_route_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, argv[2]);
}

DEFUN (ipv6_route_flags_pref,
       ipv6_route_flags_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (ipv6_route_ifname_pref,
       ipv6_route_ifname_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (ipv6_route_ifname_flags_pref,
       ipv6_route_ifname_flags_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, NULL);
}

ALIAS (no_ipv6_route,
       no_ipv6_route_flags_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")

DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, NULL);
}

ALIAS (no_ipv6_route_ifname,
       no_ipv6_route_ifname_flags_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")

DEFUN (no_ipv6_route_pref,
       no_ipv6_route_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, argv[2]);
}

DEFUN (no_ipv6_route_flags_pref,
       no_ipv6_route_flags_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    /* We do not care about argv[2] */
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (no_ipv6_route_ifname_pref,
       no_ipv6_route_ifname_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_route_ifname_flags_pref,
       no_ipv6_route_ifname_flags_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

/* New RIB.  Detailed information for IPv6 route. */
static void
vty_show_ipv6_route_detail (struct vty *vty, struct route_node *rn)
{
    struct rib *rib;
    struct nexthop *nexthop;
    char buf[BUFSIZ];

    for (rib = rn->info; rib; rib = rib->next)
    {
        vty_out (vty, "Routing entry for %s/%d%s",
                 inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
                 rn->p.prefixlen,
                 VTY_NEWLINE);
        vty_out (vty, "  Known via \"%s\"", zebra_route_string (rib->type));
        vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            vty_out (vty, ", best");
        if (rib->refcnt)
            vty_out (vty, ", refcnt %ld", rib->refcnt);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", blackhole");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", reject");
        vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
        if (rib->type == ZEBRA_ROUTE_RIPNG
                || rib->type == ZEBRA_ROUTE_OSPF6
                || rib->type == ZEBRA_ROUTE_BABEL
                || rib->type == ZEBRA_ROUTE_ISIS
                || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

            vty_out (vty, "  Last update ");

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty,  "%02d:%02d:%02d",
                         tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, "%dd%02dh%02dm",
                         tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, "%02dw%dd%02dh",
                         tm->tm_yday/7,
                         tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
            vty_out (vty, " ago%s", VTY_NEWLINE);
        }

        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
            vty_out (vty, "  %c",
                     CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " %s",
                         inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
                if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                    vty_out (vty, ", %s", nexthop->ifname);
                else if (nexthop->ifindex)
                    vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " directly connected, %s",
                         ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " directly connected, %s",
                         nexthop->ifname);
                break;
            default:
                break;
            }
            if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV6:
                case NEXTHOP_TYPE_IPV6_IFINDEX:
                case NEXTHOP_TYPE_IPV6_IFNAME:
                    vty_out (vty, " via %s)",
                             inet_ntop (AF_INET6, &nexthop->rgate.ipv6,
                                        buf, BUFSIZ));
                    if (nexthop->rifindex)
                        vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)",
                             ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}

static void
vty_show_ipv6_route (struct vty *vty, struct route_node *rn,
                     struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            if(strcmp("fe80::",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0 &&strcmp("::1",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0)
            {
                /* Prefix information. */
                len = vty_out (vty, "%c%c%c %s/%d",
                               zebra_route_char (rib->type),
                               CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
                               ? '>' : ' ',
                               CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
                               ? '*' : ' ',
                               inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
                               rn->p.prefixlen);

                /* Distance and metric display. */
                if (rib->type != ZEBRA_ROUTE_CONNECT
                        && rib->type != ZEBRA_ROUTE_KERNEL)
                    len += vty_out (vty, " [%d/%d]", rib->distance,
                                    rib->metric);
            }
        }
        else if(strcmp("fe80::",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0 &&strcmp("::1",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0)
        {
            vty_out (vty, "  %c%*c",
                     CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
                     ? '*' : ' ',
                     len - 3, ' ');
        }

        if(strcmp("fe80::",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0 &&strcmp("::1",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0)
        {
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " via %s",
                         inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
                if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                    vty_out (vty, ", %s", nexthop->ifname);
                else if (nexthop->ifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " is directly connected, %s",
                         ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s",
                         nexthop->ifname);
                break;
            default:
                break;
            }
            if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV6:
                case NEXTHOP_TYPE_IPV6_IFINDEX:
                case NEXTHOP_TYPE_IPV6_IFNAME:
                    vty_out (vty, " via %s)",
                             inet_ntop (AF_INET6, &nexthop->rgate.ipv6,
                                        buf, BUFSIZ));
                    if (nexthop->rifindex)
                        vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)",
                             ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }

            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, ", bh");
            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, ", rej");

            if (rib->type == ZEBRA_ROUTE_RIPNG
                    || rib->type == ZEBRA_ROUTE_OSPF6
                    || rib->type == ZEBRA_ROUTE_BABEL
                    || rib->type == ZEBRA_ROUTE_ISIS
                    || rib->type == ZEBRA_ROUTE_BGP)
            {
                time_t uptime;
                struct tm *tm;

                uptime = time (NULL);
                uptime -= rib->uptime;
                tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

                if (uptime < ONE_DAY_SECOND)
                    vty_out (vty,  ", %02d:%02d:%02d",
                             tm->tm_hour, tm->tm_min, tm->tm_sec);
                else if (uptime < ONE_WEEK_SECOND)
                    vty_out (vty, ", %dd%02dh%02dm",
                             tm->tm_yday, tm->tm_hour, tm->tm_min);
                else
                    vty_out (vty, ", %02dw%dd%02dh",
                             tm->tm_yday/7,
                             tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}

DEFUN (show_ipv6_route,
       show_ipv6_route_cmd,
       "show ipv6 route",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
            }
            vty_show_ipv6_route (vty, rn, rib);
        }
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix_longer,
       show_ipv6_route_prefix_longer_cmd,
       "show ipv6 route X:X::X:X/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct prefix p;
    int ret;
    int first = 1;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    ret = str2prefix (argv[0], &p);
    if (! ret)
    {
        vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Show matched type IPv6 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (prefix_match (&p, &rn->p))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V6_HEADER);
                    first = 0;
                }
                vty_show_ipv6_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_protocol,
       show_ipv6_route_protocol_cmd,
       "show ipv6 route " QUAGGA_IP6_REDIST_STR_ZEBRA,
       SHOW_STR
       IP_STR
       "IP routing table\n"
       QUAGGA_IP6_REDIST_HELP_STR_ZEBRA)
{
    int type;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    type = proto_redistnum (AFI_IP6, argv[0]);
    if (type < 0)
    {
        vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show matched type IPv6 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (rib->type == type)
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V6_HEADER);
                    first = 0;
                }
                vty_show_ipv6_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_addr,
       show_ipv6_route_addr_cmd,
       "show ipv6 route X:X::X:X",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 Address\n")
{
    int ret;
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv6 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (! rn)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ipv6_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix,
       show_ipv6_route_prefix_cmd,
       "show ipv6 route X:X::X:X/M",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 prefix\n")
{
    int ret;
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv6 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (! rn || rn->p.prefixlen != p.prefixlen)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ipv6_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

/* Show route summary.  */
DEFUN (show_ipv6_route_summary,
       show_ipv6_route_summary_cmd,
       "show ipv6 route summary",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "Summary of all IPv6 routes\n")
{
    struct route_table *table;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    vty_show_ip_route_summary (vty, table);

    return CMD_SUCCESS;
}

/*
 * Show IP mroute command to dump the BGP Multicast
 * routing table
 */
DEFUN (show_ip_mroute,
       show_ip_mroute_cmd,
       "show ip mroute",
       SHOW_STR
       IP_STR
       "IP Multicast routing table\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_MULTICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show all IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
            }
            vty_show_ip_route (vty, rn, rib);
        }
    return CMD_SUCCESS;
}

/*
 * Show IPv6 mroute command.Used to dump
 * the Multicast routing table.
 */

DEFUN (show_ipv6_mroute,
       show_ipv6_mroute_cmd,
       "show ipv6 mroute",
       SHOW_STR
       IP_STR
       "IPv6 Multicast routing table\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP6, SAFI_MULTICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
            }
            vty_show_ipv6_route (vty, rn, rib);
        }
    return CMD_SUCCESS;
}






/* Write IPv6 static route configuration. */
static int
static_config_ipv6 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    int write;
    char buf[BUFSIZ];
    struct route_table *stable;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ipv6 route %s/%d",
                     inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
                     rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV6_GATEWAY:
                vty_out (vty, " %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ));
                break;
            case STATIC_IPV6_IFNAME:
                vty_out (vty, " %s", si->ifname);
                break;
            case STATIC_IPV6_GATEWAY_IFNAME:
                vty_out (vty, " %s %s",
                         inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ), si->ifname);
                break;
            }

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, " %s", "reject");

            if (CHECK_FLAG(si->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, " %s", "blackhole");

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);
            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    return write;
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_DNS64
void dns64_prfix_dns_set(char *v6p,char *v4Dnstr)
{
    char v6_str[INET6_ADDRSTRLEN];
    struct prefix stv6p;

    struct prefix_ipv4 v4p;


    str2prefix (v6p, &stv6p);
    memset(&v6prefix,0x0,sizeof(struct prefix));
    memcpy(&v6prefix,&stv6p,sizeof(struct prefix));
    str2prefix_ipv4 (v4Dnstr, &v4p);
    v4Dns = v4p.prefix.s_addr;

    printf("v4dns is %d\n",v4Dns);

    //??dns64????????socket????
}

void dns64_prfix_dns_unset()
{
    memset(&v6prefix,0x0,sizeof(struct prefix));
    v4Dns =0;
    //??dns64????????socket????
}

BYTE dns64_config_check()
{

    if(v6prefix.prefixlen <0 || v6prefix.prefixlen >96)
    {
        return 1;
    }
    if((v6prefix.u.prefix6.s6_addr32[0]== 0)&&(v6prefix.u.prefix6.s6_addr32[1]== 0)&&(v6prefix.u.prefix6.s6_addr32[2]== 0)&&(v6prefix.u.prefix6.s6_addr32[3]== 0))
    {
        return 1;
    }
    return 0;
}


DEFUN (dns64_prefix,
       dns64_prefix_cmd,
       "dns64 prefix X:X::X:X/M (ubit|no-ubit) dns A.B.C.D",
       "ipv6 dns to IPv4 dns translator\n"
       "Nat64 or ivi ipv6 prefix\n"
       "Prefix/prefix_length\n"
       "with ubit\n"
       "without ubit\n"
       "Configure IPv4 dns\n"
       "IPv4 address of dns\n"
      )
{
    int ret;
    struct prefix v6p;
    struct prefix_ipv4 v4p;

    ret = str2prefix (argv[0], &v6p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    if (v6p.prefixlen < 0 || v6p.prefixlen > 96)
    {
        vty_out (vty, "%% Malformed IPv6 prefix length%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if((v6p.u.prefix6.s6_addr32[0]== 0)&&(v6p.u.prefix6.s6_addr32[1]== 0)&&(v6p.u.prefix6.s6_addr32[2]== 0)&&(v6p.u.prefix6.s6_addr32[3]== 0))
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    ret = str2prefix_ipv4 (argv[2], &v4p);

    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(v4p.prefix.s_addr == 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
    }
    dns64_prfix_dns_set (argv[0],argv[2]);
#if 0
    if(strcmp("ubit",argv[2])==0)
    {
        dns64_ubit= 1;
    }
    else if(strcmp("no-ubit",argv[2])==0)
    {
        dns64_ubit= 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        //close(socketfd);
        return CMD_WARNING;
    }
#endif
    struct sockaddr_in my_addr;
    bzero(&my_addr,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(8899);
    my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");

    int fd;
    char buf[1024] = {0};

    fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(fd == -1)
    {
        vty_out (vty,"socket fault!\n");
        return CMD_WARNING;
    }

    if(connect(fd,(struct sockaddr *)&my_addr,sizeof(my_addr)) == -1)
    {
        return CMD_SUCCESS;
    }
    strcpy(dnsprefix,argv[0]);
    strcpy(dnsv4,argv[2]);
    strcpy(dns64_ubit,argv[1]);
    if(dns64_ubit[0] == 'u')
        strcpy(dns64_ubit,"ubit");
    else if(dns64_ubit[0] == 'n')
        strcpy(dns64_ubit,"no-ubit");
    memset(buf,0,sizeof(buf));
    strncpy(buf,"dns64 prefix ",strlen("dns64 prefix "));
    strncpy(buf+strlen("dns64 prefix "),argv[0],strlen(argv[0]));
    strncpy(buf+strlen("dns64 prefix ")+strlen(argv[0])," dns ",strlen(" dns "));
    strncpy(buf+strlen("dns64 prefix ")+strlen(argv[0])+strlen(" dns "),argv[2],strlen(argv[2]));
    strcat(buf," ");
    strcat(buf,argv[1]);
    if(send(fd,buf,sizeof(buf),0) == -1)
    {
        vty_out (vty,"send fault!\n");
        return CMD_WARNING;
    }

    close(fd);
    return CMD_SUCCESS;
}


DEFUN (no_dns64_prefix,
       no_dns64_prefix_cmd,
       "no dns64 prefix",
       NO_STR
       "ipv6 dns to IPv4 dns translator\n"
       "Nat64 or ivi ipv6 prefix\n")
{
    dns64_prfix_dns_unset ();

    struct sockaddr_in my_addr;
    bzero(&my_addr,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(8899);
    my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");

    int fd;
    char buf[1024] = {0};

    if((dnsprefix[0]=='\0') && (dnsv4[0]=='\0'))
    {
        vty_out (vty,"You does not config dnsprefix,can't delete!\n");
        return CMD_SUCCESS;
    }

    fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(fd == -1)
    {
        vty_out (vty,"socket fault!\n");
        return CMD_WARNING;
    }

    if(connect(fd,(struct sockaddr *)&my_addr,sizeof(my_addr)) == -1)
    {
        return CMD_SUCCESS;
    }
    /*
    		vty_out(vty,"------%s-----\n",dnsprefix);
    		vty_out(vty,"------%s-----\n",dnsv4);
    		vty_out(vty,"------%d--%d---\n",sizeof(dnsv4),strlen(dnsv4));
    */
    memset(buf,0,sizeof(buf));
    strncpy(buf,"no dns64 prefix ",strlen("no dns64 prefix "));
    strncpy(buf+strlen("no dns64 prefix "),dnsprefix,strlen(dnsprefix));
    strncpy(buf+strlen("no dns64 prefix ")+strlen(dnsprefix)," dns ",strlen(" dns "));
    strncpy(buf+strlen("no dns64 prefix ")+strlen(dnsprefix)+strlen(" dns "),dnsv4,strlen(dnsv4));
    strcat(buf," ");
    strcat(buf,dns64_ubit);

    if(send(fd,buf,sizeof(buf),0) == -1)
    {
        vty_out (vty,"send fault!\n");
        return CMD_WARNING;
    }

    memset(dnsprefix,0,sizeof(dnsprefix));
    memset(dnsv4,0,sizeof(dnsv4));
    close(fd);

    return CMD_SUCCESS;
}
#endif
#ifdef HAVE_SNMP
//added for snmp community config  2013.7.31
#define TCP_SNMP_PORT 12345
#define MAX_STRING_LEN  1024

#pragma pack(push)
#pragma pack(1)
typedef struct msg
{
    char type;
    uint32_t  len;
    char buf[1];
} sendMsg;
#pragma pack(pop)

static struct config_cmd_string *snmp_config_string = NULL;

static struct config_cmd_string *
add_snmp_config_string(char *buf)
{
    struct config_cmd_string *pHead = snmp_config_string;
    while(pHead)
    {
        if(strcmp(pHead->config_string,buf) == 0)
        {
            return snmp_config_string;
        }
        pHead = pHead->next;
    }
    struct config_cmd_string *pNode = (struct config_cmd_string *)malloc(sizeof(struct config_cmd_string));
    if(pNode)
    {
        pNode->config_string = (char *)malloc(strlen(buf)+1);
        memset(pNode->config_string,0,strlen(buf)+1);
        memcpy(pNode->config_string,buf,strlen(buf)+1);
        pNode->next = NULL;
        pNode->tail = NULL;
        if(snmp_config_string == NULL)
        {
            snmp_config_string = pNode;
            snmp_config_string->tail = pNode;
        }
        else
        {
            snmp_config_string->tail->next = pNode;
            snmp_config_string->tail = pNode;
        }
    }
    return snmp_config_string;
}

static struct config_cmd_string *
find_snmp_config_string(char *string)
{
    struct config_cmd_string *pCurrentNode = snmp_config_string;
    while(pCurrentNode)
    {
        if(strcmp(pCurrentNode->config_string,string) == 0)
        {
            return pCurrentNode;
        }
        pCurrentNode = pCurrentNode->next;
    }
    return NULL;
}

static struct config_cmd_string *
delete_snmp_config_string(struct vty *vty,char *string)
{
    struct config_cmd_string *pFrontNode= snmp_config_string;
    struct config_cmd_string *pCurrentNode = snmp_config_string;
    while(pCurrentNode)
    {
        if(strcmp(pCurrentNode->config_string,string) == 0)
        {
            if(snmp_config_string == pCurrentNode)
            {
                if(pCurrentNode->next == NULL)
                {
                    free(pCurrentNode->config_string);
                    free(pCurrentNode);
                    snmp_config_string = NULL;
                    return NULL;
                }
                snmp_config_string = pCurrentNode->next;
                snmp_config_string->tail = pCurrentNode->tail;
            }
            else if(snmp_config_string->tail == pCurrentNode)
            {
                pFrontNode->next = pCurrentNode->next;
                snmp_config_string->tail = pFrontNode;
            }
            else
            {
                pFrontNode->next = pCurrentNode->next;
            }
            free(pCurrentNode->config_string);
            free(pCurrentNode);
            return snmp_config_string;
        }
        pFrontNode = pCurrentNode;
        pCurrentNode = pCurrentNode->next;
    }
    return NULL;
}

void free_snmp_config_string()
{
    struct config_cmd_string *temp_snmp_config_string = NULL;
    while(snmp_config_string)
    {
        temp_snmp_config_string = snmp_config_string;
        free(temp_snmp_config_string->config_string);
        free(temp_snmp_config_string);
        snmp_config_string = snmp_config_string->next;
    }
}

static int
snmp_init_socket(int fd)
{
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_SNMP_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    fd = socket(AF_INET,SOCK_STREAM,0);
    if(fd < 0)
    {
        return -1;
    }
    if(connect(fd,(struct sockaddr *)&addr,sizeof(addr)) != 0)
    {
        return -1;
    }
    return fd;
}

static int
snmp_send_config_msg(int fd,char type,char *buf)
{
    int len = strlen(buf);
    sendMsg *msg = (sendMsg *)malloc(5+len);
    msg->type = type;
    msg->len = ntohl(5+len);
    memcpy(msg->buf,buf,len);
    send(fd,(char *)msg,5+len,0);
    close(fd);
    free(msg);
    return CMD_SUCCESS;
}


DEFUN(snmp_community_config,
      snmp_community_config_cmd,
      "snmp community WORD",
      SNMP_STR
      "snmp community config\n"
      "community string for snmp\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp community %.*s",strlen(argv[0]),argv[0]);
    snmp_config_string = add_snmp_config_string(buf);
    return snmp_send_config_msg(fd,1,buf);
}

DEFUN(no_snmp_community_config,
      no_snmp_community_config_cmd,
      "no snmp community WORD",
      SNMP_STR
      "no snmp community config\n"
      "community string for snmp\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp community %.*s",strlen(argv[0]),argv[0]);
    struct config_cmd_string *pNode = find_snmp_config_string(buf);
    if(pNode)
    {
        snmp_config_string = delete_snmp_config_string(vty,buf);
        return snmp_send_config_msg(fd,5,buf);
    }
    else
    {
        vty_out(vty,"config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}


DEFUN(snmp_v3_config,
      snmp_v3_config_cmd,
      "snmpv3 user WORD (MD5|SHA) WORD (DES|AES) WORD",
      SNMP_STR
      "snmpv3 user config\n"
      "user name\n"
      "Use HMAC MD5 algorithm for authentication\n"
      "Use HMAC SHA algorithm for authentication\n"
      "authentication password for user(no less than 8 words)\n"
      "Use DES EncryptionAlgorithm\n"
      "Use AES EncryptionAlgorithm\n"
      "password for user(no less than 8 words)\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmpv3 user %.*s %.*s %.*s %.*s %.*s",strlen(argv[0]),argv[0],strlen(argv[1]),argv[1],
            strlen(argv[2]),argv[2],strlen(argv[3]),argv[3],
            strlen(argv[4]),argv[4]);
    snmp_config_string = add_snmp_config_string(buf);
    return snmp_send_config_msg(fd,2,buf);
}

DEFUN(no_snmp_v3_config,
      no_snmp_v3_config_cmd,
      "no snmpv3 user WORD (MD5|SHA) WORD (DES|AES) WORD",
      SNMP_STR
      "snmpv3 user config\n"
      "user name\n"
      "Use HMAC MD5 algorithm for authentication\n"
      "Use HMAC SHA algorithm for authentication\n"
      "authentication password for user(no less than 8 words)\n"
      "Use DES EncryptionAlgorithm\n"
      "Use AES EncryptionAlgorithm\n"
      "password for user(no less than 8 words)\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmpv3 user %.*s %.*s %.*s %.*s %.*s",strlen(argv[0]),argv[0],strlen(argv[1]),argv[1],
            strlen(argv[2]),argv[2],strlen(argv[3]),argv[3],
            strlen(argv[4]),argv[4]);
    struct config_cmd_string *pNode = find_snmp_config_string(buf);
    if(pNode)
    {
        snmp_config_string = delete_snmp_config_string(vty,buf);
        return snmp_send_config_msg(fd,5,buf);
    }
    else
    {
        vty_out(vty,"config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}


DEFUN(	snmp_trap_enable,
        snmp_trap_enable_cmd,
        "snmp enable traps",
        SNMP_STR
        "snmp trap enable\n"
        "snmp trap enable config\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "snmp enable traps";
    snmp_config_string = add_snmp_config_string(buf);
    return snmp_send_config_msg(fd,3,buf);
}

DEFUN(	snmp_trap_disable,
        snmp_trap_disable_cmd,
        "no snmp enable traps",
        SNMP_STR
        "snmp traps disable\n"
        "snmp traps disable\n"
        "snmp traps disable\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "snmp enable traps";
    struct config_cmd_string *pNode = find_snmp_config_string(buf);
    if(pNode)
    {
        snmp_config_string = delete_snmp_config_string(vty,buf);
        return snmp_send_config_msg(fd,5,buf);
    }
    else
    {
        vty_out(vty,"config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

DEFUN(	snmp_trap_host_config,
        snmp_trap_host_config_cmd,
        "snmp host (WORD | A.B.C.D:162 | A.B.C.D)",
        SNMP_STR
        "snmp host config\n"
        "hostname of SNMP notification host\n"
        "IP address of SNMP notification host with port num 162\n"
        "IP address of SNMP notification host with default port num 162\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp host %.*s",strlen(argv[0]),argv[0]);
    snmp_config_string = add_snmp_config_string(buf);
    return snmp_send_config_msg(fd,4,buf);
}

DEFUN(	no_snmp_trap_host_config,
        no_snmp_trap_host_config_cmd,
        "no snmp host (WORD | A.B.C.D:162 | A.B.C.D)",
        SNMP_STR
        "no snmp host config\n"
        "no snmp host config\n"
        "hostname of SNMP notification host\n"
        "IP address of SNMP notification host with port num 162\n"
        "IP address of SNMP notification host with default port num 162\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp host %.*s",strlen(argv[0]),argv[0]);
    struct config_cmd_string *pNode = find_snmp_config_string(buf);
    if(pNode)
    {
        snmp_config_string = delete_snmp_config_string(vty,buf);
        return snmp_send_config_msg(fd,5,buf);
    }
    else
    {
        vty_out(vty,"config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}


DEFUN(	snmp_trap_host_community_config,
        snmp_trap_host_community_config_cmd,
        "snmp host (WORD | A.B.C.D:162 | A.B.C.D) traps WORD",
        SNMP_STR
        "snmp host and community config\n"
        "hostname of SNMP notification host\n"
        "IP address of SNMP notification host with port num 162\n"
        "IP address of SNMP notification host with default port num 162\n"
        "snmp trap host config\n"
        "community string for traps\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp host %.*s traps %.*s",strlen(argv[0]),argv[0],
            strlen(argv[1]),argv[1]);
    snmp_config_string = add_snmp_config_string(buf);
    return snmp_send_config_msg(fd,4,buf);
}

DEFUN(	no_snmp_trap_host_community_config,
        no_snmp_trap_host_community_config_cmd,
        "no snmp host (WORD | A.B.C.D:162 | A.B.C.D) traps WORD",
        SNMP_STR
        "no snmp host and community config"
        "hostname of SNMP notification host\n"
        "IP address of SNMP notification host with port num 162\n"
        "IP address of SNMP notification host with default port num 162\n"
        "snmp trap host config\n"
        "community string for traps\n")
{
    int fd = 0;
    fd = snmp_init_socket(fd);
    if(fd < 0)
    {
        vty_out (vty,"socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf(buf,"snmp host %.*s traps %.*s",strlen(argv[0]),argv[0],
            strlen(argv[1]),argv[1]);
    struct config_cmd_string *pNode = find_snmp_config_string(buf);
    if(pNode)
    {
        snmp_config_string = delete_snmp_config_string(vty,buf);
        return snmp_send_config_msg(fd,5,buf);
    }
    else
    {
        vty_out(vty,"config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

//add by limingyuan 2013.8.19
int zebra_snmp_write_config(struct vty *vty)
{
    struct config_cmd_string *pHead = snmp_config_string;
    while(pHead)
    {
        if (strncmp (pHead->config_string, "snmpv3 user",strlen ("snmpv3 user")) != 0)
            vty_out(vty,"%s\r\n",pHead->config_string);
        pHead = pHead->next;
    }
    return CMD_SUCCESS;
}

#endif
#ifdef HAVE_DNS64
int zebra_dns64_write_config(struct vty *vty)
{
    int socketfd;
    int ret=0;
    char pre[40];

    if(v6prefix.prefixlen >0 && v6prefix.prefixlen <=96)
    {
        inet_ntop(AF_INET6,&(v6prefix.u.prefix6),pre,40);
        vty_out(vty,"dns64 prefix %s/",pre);
        vty_out(vty,"%d ",v6prefix.prefixlen);
        vty_out (vty, "%s ", dns64_ubit);
        {
            inet_ntop(AF_INET,&v4Dns,pre,40);
            vty_out(vty,"dns %s",pre);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

#endif
/* add by s 130806 */
#ifdef HAVE_4OVER6_TCPMSS
int zebra_4over6_write_tcp_mss_config(struct vty *vty)
{
    int socketfd;
    int ret = 0;
    if(save_tunnel4o6_tcpmss.mss_value !=0)
    {
        vty_out(vty, "tunnel4o6 tcp mss %d", save_tunnel4o6_tcpmss.mss_value);
        vty_out(vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}
#endif
/* end add*/
int zebra_nat64_write_config(struct vty *vty, char *ifname)
{
    struct nat64_ipv4AddressPool
    {
        unsigned int start;
        unsigned int end;
    } nat64_ipv4AddressPool;

    typedef struct nat64_config
    {
        struct tnl_parm nat64;
        unsigned int nat64_tcpTtimer;
        unsigned int nat64_udpTtimer;
        unsigned int nat64_icmpTtimer;
        struct nat64_ipv4AddressPool stIp4AddPool;
    } nat64_config;


#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    //struct tnl_parm nat64;
    int socketfd;
    int ret=0;
    char pre[40];
    nat64_config config;

    memset(&config, 0x0, sizeof(config));
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
        //vty_out(vty,"socket error\n");
        sprintf(stderr, "socket error\n");
        return -1;
    }
    memcpy(ifr.ifr_name, ifname,strlen(ifname)+1);
    ifr.ifr_data=&config;
    ret=ioctl(socketfd,SIOCGETPREFIX,&ifr);
    if(ret == -1)
    {
        //vty_out(vty,"ioctl error: %d\n",errno);
        close(socketfd);
        return -1;
    }
    close(socketfd);
    //write config nat64 prefix
    if(config.nat64.prefix.len == 0)
    {
        //vty_out(vty,"prefix is 0\n");
    }
    else
    {
        inet_ntop(AF_INET6,&(config.nat64.prefix.prefix),pre,40);
        vty_out(vty,"nat64 prefix %s/",pre);
        vty_out(vty,"%d ",config.nat64.prefix.len);
        //vty_out(vty,"%s ", ifname);
        if(config.nat64.prefix.ubit == 1)
        {
            vty_out(vty,"ubit");
        }
        else
        {
            vty_out(vty,"no-ubit");
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config nat64 timer icmp
    if(config.nat64_icmpTtimer != 10)
    {
        vty_out(vty,"nat64 timeout icmp %d", config.nat64_icmpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    //write config nat64 timer udp
    if(config.nat64_udpTtimer != 30)
    {
        vty_out(vty,"nat64 timeout udp %d", config.nat64_udpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config nat64 timer tcp
    if(config.nat64_tcpTtimer != 60)
    {
        vty_out(vty,"nat64 timeout tcp %d", config.nat64_tcpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config ipv4 pool create x.x.x.x x.x.x.x
    if(config.stIp4AddPool.start != 0 && config.stIp4AddPool.end != 0)
    {
        config.stIp4AddPool.start = htonl(config.stIp4AddPool.start);
        inet_ntop(AF_INET,&(config.stIp4AddPool.start),pre,40);
        vty_out(vty,"nat64 v4pool %s", pre);

        //inet_ntop(AF_INET,&config.stIp4AddPool.end,pre,40);
        vty_out(vty,"/%d", config.stIp4AddPool.end);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

static int
zebra_netwire_config (struct vty *vty)
{
    int write;
    int rc;

    write = 0;

    //show ivi46 prefix config
    rc = zebra_ivi_write_config(vty, "ivi");
    if(rc != 0)
    {
        printf("Get %s ivi prefix failed: %d", "ivi",rc);
    }
    else
        write += 1;
#if 0
    //show ivi64 prefix config
    rc = zebra_ivi_write_config(vty, "ivi64");
    if(rc != 0)
    {
        printf("Get %s ivi prefix failed: %d", "ivi46",rc);
    }
    else
        write += 1;
#endif
    //show natware prefix config
    zebra_nat64_write_config(vty, "nat64");
    //
    zebra_ecn_write_config(vty, "ecn");
    zebra_flow_sepa_write_config(vty,"flowsp");

    zebra_header_compress_write_config(vty,"header-compression"); //add by myj in 1016.12.30
    return write;
}
int get_hw_addr(u_char * buf, char *str)
{
    int i,h;
    unsigned int p[6];
    int j;
    for(j=0; j<strlen(str); j++)
    {
        if(((str[j]>='0'&&str[j]<='9')||(str[j]>='A'&&str[j]<='F')||(str[j]>='a'&&str[j]<='f')||str[j]==':')==0)
            return 0;
    }
    h = 0;
    for(j=0; j<strlen(str); j++)
    {
        if(str[j]==':')
            h++;
    }
    if(h!=5)
    {
        return 0;
    }
    i = sscanf(str, "%x:%x:%x:%x:%x:%x", &p[0], &p[1], &p[2],
               &p[3], &p[4], &p[5]);

    if (i != 6)
    {
        printf("%s\n", "error parsing MAC");
        return 0;
    }

    for (i = 0; i < 6; i++)
        buf[i] = p[i];
    return 4;
}

//added by zhangzhibo 2013.9.2 for add arp
DEFUN (arp,
       arp_cmd,
       "arp A.B.C.D HH:HH:HH:HH:HH:HH DEV",
       "Add an arp entry\n"
       "IP address (e.g. 10.0.0.1)\n"
       "MAC address (e.g.10:50:56:f4:89:8f)\n"
       "Interface name\n")
{

    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    struct arpreq arpreq,arpreq1;
    struct sockaddr_in *sin,*sin1;
    struct in_addr ina,ina1;
    int flags;
    int rc;
    char ip[16];
    strcpy(ip,argv[0]);

    char mac[19];
    strcpy(mac,argv[1]);
#if 0
    strcpy(arp_keep_config[arp_count].mac,argv[1]);
#endif
#if 1
    memset(&arpreq, 0, sizeof(struct arpreq));
    memset(&arpreq1, 0, sizeof(struct arpreq));
    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    ina.s_addr = inet_addr(ip);
    memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));

    strcpy(arpreq.arp_dev, argv[2]);


    if(get_hw_addr((unsigned char *) arpreq.arp_ha.sa_data, mac)==0)
    {
        vty_out(vty,"Invalid MAC address\n");
        return CMD_SUCCESS;
    }

    flags = ATF_PERM | ATF_COM; //note, must set flag, if not,you will get error

    arpreq.arp_flags = flags;
    int j=0;
    for(j=0; j<KEEP_CONFIG_SIZE; j++)
        if(strcmp(arp_keep_config[j].ip,argv[0])==0)
        {
            strcpy(arpreq1.arp_dev,arp_keep_config[j].arp_dev);
            sin1 = (struct sockaddr_in *) &arpreq1.arp_pa;
            memset(sin1, 0, sizeof(struct sockaddr_in));
            sin1->sin_family = AF_INET;
            ina1.s_addr = inet_addr(arp_keep_config[j].ip);
            memcpy(&sin1->sin_addr, (char *) &ina1, sizeof(struct in_addr));

            if (ioctl(sd, SIOCDARP, &arpreq1)< 0)
            {
                vty_out(vty,"%s\n", "del arp error...");
                return -1;
            }
            memset(&arp_keep_config[j],0,sizeof(struct arp_config));
            arp_keep_config[j].flag=0;
        }
    if(strcmp(arpreq.arp_dev,"lo")!=0&&strcmp(argv[0],"0.0.0.0")!=0 &&strcmp(argv[0],"255.255.255.255")!=0&&strcmp(argv[1],"0:0:0:0:0:0")!=0)
    {
        rc = ioctl(sd, SIOCSARP, &arpreq);
        if (rc < 0)
        {
            vty_out(vty,"%s\n", "set arp error...");
            return CMD_SUCCESS;
        }
        else
        {
            if(strcmp(argv[0],"0.0.0.0")!=0 &&strcmp(argv[0],"255.255.255.255")!=0&&strcmp(argv[1],"0:0:0:0:0:0")!=0)
            {
                strcpy(arp_keep_config[arp_count].ip,argv[0]);
                strcpy(arp_keep_config[arp_count].mac,argv[1]);
                strcpy(arp_keep_config[arp_count].arp_dev,argv[2]);
                arp_keep_config[arp_count].flag=1;
                arp_count=(arp_count+1)%KEEP_CONFIG_SIZE;
            }
        }
    }
#endif

    return CMD_SUCCESS;
}
//added by zhangzhibo 2013.9.2 for del arp
DEFUN (no_arp,
       no_arp_cmd,
       "no arp A.B.C.D",
       "Negate a command or set its defaults\n"
       "Delete an arp entry\n"
       "IP Address (e.g. 10.0.0.1)\n"
      )
{
    struct interface* fp1=vty->index;
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    struct arpreq arpreq;
    struct sockaddr_in *sin;
    struct in_addr ina;
    int flags;
    int rc;
    char ip[16];
    strcpy(ip,argv[0]);
    memset(&arpreq, 0, sizeof(struct arpreq));
    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    ina.s_addr = inet_addr(ip);
    memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));
    int j=0;
    for(j=0; j<KEEP_CONFIG_SIZE; j++)
        if(strcmp(arp_keep_config[j].ip,argv[0])==0)
        {
            strcpy(arpreq.arp_dev,arp_keep_config[j].arp_dev);
//strcpy(arpreq.arp_dev,argv[2]);

            rc = ioctl(sd, SIOCDARP, &arpreq);
            if (rc < 0)
            {
                vty_out(vty,"%s\n", "del arp error...");
                return -1;
            }
        }

    for(j=0; j<KEEP_CONFIG_SIZE; j++)
        if(strcmp(arp_keep_config[j].ip,argv[0])==0)
        {
            memset(&arp_keep_config[j],0,sizeof(struct arp_config));
            arp_keep_config[j].flag=0;
        }
    return CMD_SUCCESS;
}
int static_config_ipv4_arp(struct vty *vty)
{
    int k=0;
    int write=0;
    for(k=0; k<KEEP_CONFIG_SIZE; k++)
        if(arp_keep_config[k].flag==1)
        {
            vty_out(vty,"arp %s %s %s",arp_keep_config[k].ip,arp_keep_config[k].mac,arp_keep_config[k].arp_dev);
            vty_out(vty,"%s",VTY_NEWLINE);
            write=1;
        }
    return write;
}
#if 0
int static_config_ipv6_nd(struct vty*vty)
{
    int k=0;
    int write=0;
    for(k=0; k<KEEP_CONFIG_SIZE; k++)
        if(strcmp(nd_keep_config[k].ip,"\0")!=0)
        {
            vty_out(vty,"ipv6 nd neighbor %s %s",nd_keep_config[k].ip,nd_keep_config[k].mac);
            vty_out(vty,"%s",VTY_NEWLINE);
            write=1;
        }
    return write;

}
#endif
//add by ccc for flow_separation_by_people_and_soldier

struct inter_in_area *inter_area_head;
int flow_check_inter_area(char *ifname)
{
    struct inter_in_area *p= inter_area_head;
    if(inter_area_head == NULL)
        return 0;
    else
    {
        while(p!=NULL)
        {
            if(strcmp(ifname,p->ifname)==0)
                return -1;
            p=p->next;
        }
        return 0;
    }
}
int flow_add_area_list(char *ifname,char flag)
{
    struct inter_in_area *p= inter_area_head;
    if(inter_area_head == NULL)
    {
        inter_area_head=(struct inter_in_area *)malloc(sizeof(struct inter_in_area));
        memset(inter_area_head,0,sizeof(struct inter_in_area));
        memcpy(inter_area_head->ifname,ifname,16);
        inter_area_head->area_value = flag;
    }
    else
    {
        while(p->next!=NULL)
        {
            p=p->next;
        }
        p->next = (struct inter_in_area *)malloc(sizeof(struct inter_in_area));
        p=p->next;
        memset(p,0,sizeof(struct inter_in_area));
        memcpy(p->ifname,ifname,16);
        p->area_value = flag;
    }
    return 0;
}
#if 0
int write_conf(int fd_w,int fd_r)
{
    off_t length=lseek(fd_w,0,SEEK_END);
    lseek(fd_w,0,SEEK_SET);

    return 0;
}
#endif
#define  NETLINK_GENERIC 16
#define  MAX_PAYLOAD 1024
#define IF_MSG 1
#define FLAG_SWICH 10
#if 1
struct tlv_flowsp
{
    unsigned char flag_swich;
    unsigned char type;
    int length;
    char data[0];
};
#endif
struct my_test
{
    char ifname[16];
};
int send_control_msg_kernel(struct vty*vty)
{
    int sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    int ret =0;
    //vty_out(vty,"sock:%d%s",sock_fd,VTY_NEWLINE);
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    struct sockaddr_nl src_addr,dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family=AF_NETLINK;
    dest_addr.nl_pid=0;//For Linux Kernel
    dest_addr.nl_groups=0;//unicast
    //dest_addr.nl_groups=1;//muticast
    ret = bind(sock_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    //vty_out(vty,"bind:%d%s",ret,VTY_NEWLINE);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;/* not in mcast groups */

    struct nlmsghdr *nlh=NULL;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh)
    {
        //printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    nlh->nlmsg_len=NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid=0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_flags=0;

    //Fill in the netlink message payload
    struct tlv_flowsp p;
    memset(&p,0,sizeof(struct tlv_flowsp));
    p.type = IF_MSG;
    p.flag_swich = FLAG_SWICH; //add by myj
    struct inter_in_area *p_if= inter_area_head;
    char if_msg[MAX_PAYLOAD-sizeof(struct tlv_flowsp)]="";
    int count_i = 0;
    while(p_if!= NULL)
    {
        if(p_if->area_value==INTEGRATION)
        {
            memcpy((if_msg+count_i*16),&(p_if->ifname),16);
            count_i++;
        }
        p_if=p_if->next;
    }


    p.length=16*count_i;
    char msg_load[MAX_PAYLOAD]="";
    memcpy((msg_load),&p,sizeof(struct tlv_flowsp));
    memcpy((msg_load+sizeof(struct tlv_flowsp)),&if_msg,16*count_i);
    memcpy((NLMSG_DATA(nlh)),msg_load,sizeof(struct tlv_flowsp)+16*count_i);

    struct tlv_flowsp *p_test =(struct tlv_flowsp*)NLMSG_DATA(nlh);
    //vty_out(vty,"type is %d",p_test->type);
    int i =0;
    struct my_test *mm = (struct my_test *)(p_test->data);
    /*
    for(i=0;i<p_test->length/16;i++)
    {
    	struct my_test *mm = (struct my_test *)(p_test->data + 16*i);
    	vty_out(vty,"%s\n",mm->ifname);
    }
    */
    //strcpy(NLMSG_DATA(nlh),"Request IPV4 ArpTable");
    //vty_out(vty,"msg:%s%s",NLMSG_DATA(nlh),VTY_NEWLINE);

    struct iovec iov;
    memset(&iov,0,sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len =nlh->nlmsg_len;
    memset(&msg,0,sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock_fd,&msg,0);
    //vty_out(vty,"send %d%s",ret,VTY_NEWLINE);
    close(sock_fd);
    free(nlh);
    return 0;
}
int update_control_msg_to_kernel(char *ifname,struct vty*vty)
{
#if 0
    //open file and update area_flag
    int fd_read = open("/usr/local/etc/control.conf",O_RDONLY|O_CREAT,00777);
    int fd_write = open("/usr/local/etc/control_to_kernel.conf",O_WRONLY|O_CREAT|O_TRUNC,00777);
    write_conf(fd_read,fd_write);
    close(fd_read);
    close(fd_write);
#endif
    //send to kernel
    send_control_msg_kernel(vty);
    return 0;
}
#if 0
DEFUN(enable_interface_area,
      enable_interface_area_cmd,
      "flowsp IFNAME area extral",  //(integration|people)",
      "enable flow separation \n"
//"enable interface in people area\n"
     )
#endif

DEFUN(enable_interface_area,
      enable_interface_area_cmd,
      "flowsp INTERFACE area extral",
      "flowsp\n"
      "interface name\n"
      "area paramenters\n"
      "extral\n"
     )
{
    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(flow_check_inter_area(argv[0])<0)
    {
        vty_out(vty,"this interface has enable area%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    char flag = INTEGRATION;
    //if(!strcmp(argv[1],"people"))
    //flag = PEOPLE;
    flow_add_area_list(argv[0],flag);
    update_control_msg_to_kernel(argv[0],vty);

    return CMD_SUCCESS;
}
int flow_del_area_list(char *ifname)
{
    struct inter_in_area *p= inter_area_head;
    struct inter_in_area *p_front= p;
    if(inter_area_head == NULL)
        return 0;
    else if(!strcmp(inter_area_head->ifname,ifname))
    {
        inter_area_head=inter_area_head->next;
        free(p);
    }
    else
    {
        while(p!=NULL)
        {
            if(!strcmp(p->ifname,ifname))
            {
                p_front->next = p->next;
                free(p);
                break;
            }
            p_front = p;
            p=p->next;
        }
    }
    return 0;
}
DEFUN(no_enable_interface_area,
      no_enable_interface_area_cmd,
      "no flowsp IFNAME area",
      NO_STR
      "flowsp\n"
      "IFNAME"
      "area\n"
     )
{
    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    flow_del_area_list(argv[0]);
    update_control_msg_to_kernel(argv[0],vty);

    return CMD_SUCCESS;
}
int zebra_flow_sepa_write_config(struct vty *vty,char *ifname)
{
    vty_out(vty,"!%s",VTY_NEWLINE);
    struct inter_in_area *p= inter_area_head;
    while(p!=NULL)
    {
        vty_out(vty,"flowsp %s area extral%s",p->ifname,VTY_NEWLINE);//(p->ifname,p->area_value==INTEGRATION)?"integration":"people",VTY_NEWLINE);
        p=p->next;
    }
    vty_out(vty,"!%s",VTY_NEWLINE);
    return CMD_SUCCESS;
}

//add end
#define REPLACE 1
#define DEL 0
//add by ccc for ecn
//ll_name_to_index
unsigned ll_name_to_index(char *name)
{
    static char ncache[16];
    static int icache;
    struct idxmap *im;
    int i;

    if (name == NULL)
        return 0;
    if (icache && strcmp(name, ncache) == 0)
        return icache;
    for (i=0; i<16; i++)
    {
        for (im = idxmap[i]; im; im = im->next)
        {
            if (strcmp(im->name, name) == 0)
            {
                icache = im->index;
                strcpy(ncache, name);
                return im->index;
            }
        }
    }

    return if_nametoindex(name);
}
int start_rt_talk(int cmd,const char *dev_name,int p_num)
{
    if (rtnl_open(&rth, 0) < 0)
    {
        fprintf(stderr, "Cannot open rtnetlink\n");
        return -1;
        //exit(1);
    }

    //start talk
    struct
    {
        struct nlmsghdr 	n;
        struct tcmsg 		t;
        char   			buf[TCA_BUF_MAX];
    } req;
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    if (cmd == REPLACE)
    {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;//flags:replace:NLM_F_CREATE|NLM_F_REPLACE  delete:0
        req.n.nlmsg_type = RTM_NEWQDISC;//cmd:relcace:RTM_NEWQDISC  delete:RTM_DELQDISC
    }
    else
    {
        req.n.nlmsg_flags = NLM_F_REQUEST|0;
        req.n.nlmsg_type =RTM_DELQDISC;//cmd:relcace:RTM_NEWQDISC  delete:RTM_DELQDISC
    }
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_parent = TC_H_ROOT;

    //char  d[16] = dev_name;//dev name
    char  k[16] = "red";//red
    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);//enable red

    /*red_parse_opt(&req.n);//fill red parms*/
    struct rtattr *tail;//ccc
    unsigned char sbuf[256];
    red_ecn_opt[p_num-1].tc_ecn_info.Scell_log = tc_red_eval_idle_damping(sbuf);
    //fill in msg
    tail = NLMSG_TAIL(&req.n);
    addattr_l(&req.n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(&req.n, 1024, TCA_RED_PARMS, &(red_ecn_opt[p_num-1].tc_ecn_info), sizeof(struct tc_red_qopt));
    addattr_l(&req.n, 1024, TCA_RED_STAB, sbuf, 256);
    tail->rta_len = (void *) NLMSG_TAIL(&req.n) - (void *) tail;
    //return 0;
    //dev
    {
        int idx;
        ll_init_map(&rth);
        if ((idx = ll_name_to_index(dev_name)) == 0)
        {
            fprintf(stderr, "Cannot find device \"%s\"\n", dev_name);
            return 1;
        }
        req.t.tcm_ifindex = idx;
        //printf("idx = %d \n",idx);
    }

    //rtnl talk
    if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
    {
        perror("rtnl");
        printf("rtnl is wrong\n");
        return -2;
    }
    //return 0;

    rtnl_close(&rth);
    return 0;
}
int check_ecn_info(int num)
{
    struct if_politic_qdisc *p = if_ecn_head;
    while(p != NULL)
        if(p->politic == num)
            return -1;

    return 0;
}
DEFUN(ecn_politic,
      ecn_politic_cmd,
      //"ecn <1-4> minth <0-10000> maxth <0-10000> wlog <0-32> plog <0-32>",
      "ecn <1-4> red minth <0-10000> maxth <0-10000>",
      "set ecn parms\n"
      "ecn politic num\n"
      "enable red arithmetic\n"
      "set red parms :min threshold value -> bandwidth(Mbps)\n"
      "min threshold value\n"
      "set red parms :max threshold value -> bandwidth(Mbps)\n"
      "max threshold value\n"
      //"set red parms :weight value\n"
      //"weight value:if you want weight value is 0.5,you should set wlog 1 (weight value = 2^-Wlog)\n"
      //"set red parms :probability for mark packet\n"
      //"probability value:if you want probability value is 0.5,you should set plog 1 (weight value = 2^-Plog)\n"
     )
{
    //vty_out(vty,"%s",VTY_NEWLINE);
    //return CMD_WARNING;
    int num = atoi(argv[0]);
    if(num<1 || num>4)
    {
        vty_out(vty,"ecn politic should be  1-4%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(check_ecn_info(num)<0)
    {
        vty_out(vty,"this politic is already inuse%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    unsigned int minth = atoi(argv[1]);
    if(minth<0 || minth>10000)
    {
        vty_out(vty,"minth should be 0-10000%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    unsigned int maxth = atoi(argv[2]);
    if(maxth<0 || maxth>10000)
    {
        vty_out(vty,"maxth should be 0-10000%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(maxth < minth)
    {
        vty_out(vty,"maxth should be greater than minth%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    /*
    unsigned char wlog = atoi(argv[3]);
    if(wlog<0 || wlog>32){
    	vty_out(vty,"wlog should be 0-32%s",VTY_NEWLINE);
    	return CMD_WARNING;
    }
    unsigned char plog = atoi(argv[4]);
    if(plog<0 || plog>32){
    	vty_out(vty,"plog should be 0-32%s",VTY_NEWLINE);
    	return CMD_WARNING;
    }
    */
    red_ecn_opt[num-1].tc_ecn_info.limit = 125*1024*1024;
    red_ecn_opt[num-1].tc_ecn_info.qth_min = minth;//(<<17)==(1024*1024/8)
    red_ecn_opt[num-1].tc_ecn_info.qth_max = maxth;
    red_ecn_opt[num-1].tc_ecn_info.Wlog = 0;//wlog;
    red_ecn_opt[num-1].tc_ecn_info.Plog = 0;//plog;
    red_ecn_opt[num-1].tc_ecn_info.flags |= TC_RED_ECN;

    red_ecn_opt[num-1].use_flag = 1;
    //vty_out(vty,"parms is min:%d max:%d wlog:%d plog:%d %s",red_ecn_opt[num-1].qth_min,red_ecn_opt[num-1].qth_max,red_ecn_opt[num-1].Wlog,red_ecn_opt[num-1].Plog,VTY_NEWLINE);
    return CMD_SUCCESS;

}
DEFUN(no_ecn_politic,
      no_ecn_politic_cmd,
      "no ecn <1-4>",
      NO_STR
      "ecn politic\n"
      "ecn politic num\n")
{
    int num = atoi(argv[0]);
    if(num<1 || num>4)
    {
        vty_out(vty,"ecn politic should be  1-4%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(check_ecn_info(num)<0)
    {
        vty_out(vty,"this politic is already inuse%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    red_ecn_opt[num-1].use_flag = 0;
    return CMD_SUCCESS;
}
int print_qdisc(const struct sockaddr_nl *who,struct nlmsghdr *n,void *arg)
{
    //FILE *fp = (FILE*)arg;
    struct vty *vty = (struct vty*)arg;
    struct tcmsg *t = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    struct rtattr * tb[TCA_MAX+1];

    if(filter_ifindex&&filter_ifindex != t->tcm_ifindex)
        return 0;
    memset(tb,0,sizeof(tb));
    parse_rtattr(tb,TCA_MAX,TCA_RTA(t),len);
    if(!strcmp((char*)RTA_DATA(tb[TCA_KIND]),"red"))
        vty_out(vty, "system enable queue discipline :%s", (char*)RTA_DATA(tb[TCA_KIND]));
//	vty_out(vty, "system enable queue discipline :%s", (char*)RTA_DATA(tb[TCA_KIND]));
    //if (t->tcm_parent == TC_H_ROOT)
    //vty_out(vty, "root");
    //if (t->tcm_info != 1) {
    //vty_out(vty,"refcnt %d", t->tcm_info);
    //}
    vty_out(vty,"%s",VTY_NEWLINE);
    struct rtattr *xstats = NULL;
    if (tb[TCA_STATS] || tb[TCA_STATS2] || tb[TCA_XSTATS])
    {
        print_tcstats_attr(vty, tb, " ", &xstats);
        vty_out(vty,"%s",VTY_NEWLINE);
    }
    if (xstats)
    {
        red_print_xstats(vty, xstats);
        vty_out(vty,"%s",VTY_NEWLINE);
    }

    return 0;
}
int check_ecn_info_by_name(char *ifname)
{
    int num = 0;
    struct if_politic_qdisc *p = if_ecn_head;
    if(if_ecn_head == NULL)
        return -1;
    while(p!=NULL)
    {
        if(!strcmp(ifname,p->ifname))
            return p->politic;
        p=p->next;
    }
    return -1;
}
DEFUN(show_qdisc,
      show_qdisc_cmd,
      "show qdisc IFNAME",
      "show \n"
      "qdisc of interface\n"
      "interface name\n"
     )
{
    struct interface *ifp;
    ifp = if_lookup_by_name (argv[0]);
    if (ifp == NULL)
    {
        vty_out (vty, "No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(rtnl_open(&rth,0)<0)
    {
        vty_out(vty,"cannot open rt_netlink%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tcmsg t;
    memset(&t, 0, sizeof(t));
    t.tcm_family = AF_UNSPEC;
    ll_init_map(&rth);

    if ((t.tcm_ifindex = ll_name_to_index(argv[0])) == 0)
    {
        vty_out(vty, "Cannot find device %s",VTY_NEWLINE );
        return CMD_WARNING ;
    }
    filter_ifindex = t.tcm_ifindex;
    if (rtnl_dump_request(&rth, RTM_GETQDISC, &t, sizeof(t)) < 0)
    {
        vty_out(vty,"Cannot send dump request%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int num = check_ecn_info_by_name(argv[0]);
    //vty_out(vty,"num is %d%s",num,VTY_NEWLINE);
    if( num >= 0)
    {
        vty_out(vty,"enable red politic %d: minth %dMbps maxth %dMbps%s",num,red_ecn_opt[num-1].tc_ecn_info.qth_min,red_ecn_opt[num-1].tc_ecn_info.qth_max,VTY_NEWLINE);
    }
    if (rtnl_dump_filter(&rth, print_qdisc,vty, NULL, NULL) < 0)
    {
        vty_out(vty, "Dump terminated%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    rtnl_close(&rth);
    return CMD_SUCCESS;
}
int save_ecn_info(char *ifname,int num)
{
    struct if_politic_qdisc *p = if_ecn_head;
    struct if_politic_qdisc *p_front = p;
    if(if_ecn_head==NULL)
    {
        if_ecn_head = (struct if_politic_qdisc *)calloc(1,sizeof(struct if_politic_qdisc));
        strcpy(if_ecn_head->ifname,ifname);
        if_ecn_head->politic = num;
        return 1;//new add
    }
    else
    {
        while(p!=NULL)
        {
            if(!strcmp(ifname,p->ifname))
            {
                return -1;//repeat
            }
            p_front = p;
            p = p->next;
        }
        p = (struct if_politic_qdisc *)calloc(1,sizeof(struct if_politic_qdisc));
        p_front->next = p;

        strcpy(p->ifname,ifname);
        p->politic = num;
        return 1;//new
    }
}
DEFUN(ecn_enable,
      ecn_enable_cmd,
      "ecn IFNAME red politic <1-4>",
      "enable ecn\n"
      "enable interface name\n"
      "enable red arithmetic\n"
      "ecn politic\n"
      "ecn politic num\n")
{
    struct interface *ifp;
    ifp = if_lookup_by_name (argv[0]);
    if (ifp == NULL)
    {
        vty_out (vty, "%No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int num = atoi(argv[1]);
    if( num < 1 || num > 4)
    {
        vty_out(vty,"ecn politic num should be <1-4>");
        return CMD_WARNING;
    }
    //vty_out(vty,"num is %d flag is %d %s",num,red_ecn_opt[num-1].use_flag,VTY_NEWLINE);
    if(red_ecn_opt[num-1].use_flag != 1)
    {
        vty_out(vty, "this ecn politic is not enable%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(save_ecn_info(argv[0],num)<0)
    {
        vty_out (vty, "this interface has enable ecn politic%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(start_rt_talk(REPLACE,argv[0],num) < 0)
    {
        vty_out(vty,"cannot enable rtlink%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    red_ecn_opt[num-1].use_num++;
    return CMD_SUCCESS;
}
void del_ecn_info(char *ifname)
{
    if(if_ecn_head == NULL)
    {
        return;
    }
    else
    {
        struct if_politic_qdisc *p = if_ecn_head;
        struct if_politic_qdisc *p_front = p;
        if(!strcmp(if_ecn_head->ifname,ifname))
        {
            p = if_ecn_head->next;
            free(if_ecn_head);
            if_ecn_head = p;
            return;
        }
        while(p != NULL)
        {
            if(!strcmp(ifname,p->ifname))
            {
                p_front = p->next;
                free(p);
                return;
            }
            p_front = p;
            p = p->next;
        }
    }
}
DEFUN(no_ecn_enable,
      no_ecn_enable_cmd,
      "no ecn IFNAME",
      NO_STR
      "enable ecn\n"
      "enable interface name\n")
{
    int num =1;
    struct interface *ifp;
    ifp = if_lookup_by_name (argv[0]);
    if (ifp == NULL)
    {
        vty_out (vty, "No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(start_rt_talk(DEL,argv[0],num) < 0)
    {
        vty_out(vty,"this interface has no qdisc%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    del_ecn_info(argv[0]);
    /*
    if(red_ecn_opt[num-1].inuse!=0)
    	red_ecn_opt[num-1].inuse--;
    */
    return CMD_SUCCESS;
}



//add end
#if 1                           //sangmeng add for filter

/*sangmeng add for ip access list applied to the interface*/
DEFUN(ip_access_group_listnumber,
      ip_access_group_listnumber_cmd,
      "ip access-group WORD (in|out)",
      IP_STR
      "Specify access control for packets\n"
      "Access-list name\n" "inbound packets\n" "outbound packets\n")
{

    //vty_out(vty, "come here%s", VTY_NEWLINE);
    return filter_add_to_interface(vty, vty->index, argv[0], argv[1],
                                   AFI_IP);
}

/*sangmeng add for no ip access list applied to the interface*/
DEFUN(no_ip_access_group_listnumber,
      no_ip_access_group_listnumber_cmd,
      "no ip access-group WORD (in|out)",
      "Negate a command or set its defaults\n"
      IP_STR
      "Specify access control for packets\n"
      "Access-list name\n" "inbound packets\n" "outbound packets\n")
{
    return filter_delete_from_interface(vty, vty->index, argv[0], argv[1],
                                        AFI_IP);
}

DEFUN(ipv6_access_group_listnumber,
      ipv6_access_group_listnumber_cmd,
      "ipv6 access-group WORD (in|out)",
      IPV6_STR
      "Specify access control for packets\n"
      "Access-list name\n" "inbound packets\n" "outbound packets\n")
{

    //vty_out(vty, "come here%s", VTY_NEWLINE);
    return filter_add_to_interface(vty, vty->index, argv[0], argv[1],
                                   AFI_IP6);
}

/*sangmeng add for no ipv6 access list applied to the interface*/
DEFUN(no_ipv6_access_group_listnumber,
      no_ipv6_access_group_listnumber_cmd,
      "no ipv6 access-group WORD (in|out)",
      "Negate a command or set its defaults\n"
      IP_STR
      "Specify access control for packets\n"
      "Access-list name\n" "inbound packets\n" "outbound packets\n")
{
    return filter_delete_from_interface(vty, vty->index, argv[0], argv[1],
                                        AFI_IP6);
}

#endif                          // end sagnmeng add for filter
//added for nat 20130508


/*******************add for compression in 2016.12.23***************/
struct if_compress_enabled *if_compress_head = NULL;
#if 1
static int check_if_exist(char *ifname,int flag)
{
    struct if_compress_enabled *p = if_compress_head;

    while(p!=NULL)
    {
        if(!strcmp(ifname,p->ifname) && (p->compres_flag == flag))
            return -1;
        p=p->next;
    }


    return 0;
}

static int fill_ifnameflag(FILE *fp)
{
    struct if_compress_enabled *p = if_compress_head;
    char flagstr[] = "off";
    int i = 0;
    char ifnameflag[128] = "";
    //int internal = sizeof(p->ifname)+sizeof(p->compres_flag)+8 ;


    memset(ifnameflag,0,sizeof(ifnameflag));
    while(p != NULL)
    {
        //zlog_notice("fill ifname:%s flag:%d",p->ifname,p->compres_flag);


        if(p->compres_flag == 1)
        {
            memcpy(flagstr,"on",4);
        }
        else
        {
            memcpy(flagstr,"off",4);
        }
        sprintf(ifnameflag ,"    %s %s \n",p->ifname,flagstr);
        //zlog_notice("fill ifnamefalg:%s ",ifnameflag);

        fprintf(fp,"%s",ifnameflag);
        //i++;
        p=p->next;
    }

    //   zlog_notice("the function of fill_ifnameflag ifnameflag:%s",ifnameflag);
    return 0;
}

static int write_message_if_compre_file()
{
    FILE *fp;
    char *pstr = NULL;
    char *pstrI = NULL;
    char buf[COMPBUFSIZE_TOTAL] = "";
    char buf_fore[COMPBUFSIZE] = "";
    char buf_writ[COMPBUFSIZE] = "";
    int offset = 0;
    int n = 0;

    fp = fopen(_PATH_HEADER_COMPRESS,"a+");
    if(fp == NULL)
    {
        zlog_warn("Can't open compression file %s: %s", _PATH_HEADER_COMPRESS,safe_strerror(errno));
        return -1;
    }
    while(1)
    {
        n = fread(buf,sizeof(char),sizeof(buf),fp);
        // zlog_notice("******read the str from file:\n%s \n",buf);
        if(pstr = strstr(buf,APPOINT_STR))
        {
            if(pstrI = strstr(pstr,APPOINT_AFTER))
            {
                memcpy(buf_fore,buf,pstr-buf+12);
                memcpy(buf_writ,pstrI,sizeof(buf_writ));

                fclose(fp);
                fp = fopen(_PATH_HEADER_COMPRESS,"w+");

                fprintf(fp,"%s",buf_fore);
                fill_ifnameflag(fp);
                fprintf(fp,"\n%s",buf_writ);
            }
            break;
        }

        if(feof(fp))
        {
            break;
        }
    }
    fclose(fp);

    return 0;
}
static int del_if_message_at_list(char *ifname)
{
    struct if_compress_enabled *p= if_compress_head ;
    struct if_compress_enabled   *p_front= p;
#if 1
    if( if_compress_head  == NULL)
        return 0;
    else if(!strcmp(if_compress_head->ifname,ifname))
    {
        if_compress_head=if_compress_head->next;
        free(p);

    }
    else
    {
        while(p!=NULL)
        {


            //zlog_notice("del_if_message_at_list");
            if(!strcmp(p->ifname,ifname))
            {
                p_front->next = p->next;
                free(p);
                break;
            }
            p_front = p;
            p=p->next;
        }
    }

#endif
    return 0;
}

static int add_if_compress_list(char *ifname,int flag)
{
    struct  if_compress_enabled *p =if_compress_head ;
    if(if_compress_head == NULL)
    {
        if_compress_head  =(struct if_compress_enabled *)malloc(sizeof(struct if_compress_enabled ));
        memset(if_compress_head  ,0,sizeof(struct if_compress_enabled ));
        memcpy((if_compress_head->ifname),ifname,16 );
        if_compress_head->compres_flag = flag;

    }
    else
    {
        while(p->next != NULL)
        {
            p=p->next;
        }
        p->next = (struct if_compress_enabled *)malloc(sizeof(struct if_compress_enabled ));
        if(p->next == NULL)
            zlog_notice("malloc failure");
        p = p->next;
        memset(p,0,sizeof(struct if_compress_enabled));
        memcpy(p->ifname,ifname,16);
        p->compres_flag = flag;

    }
#if 0
    p =if_compress_head;
    while(p != NULL)
    {
        zlog_notice("the add if_compress_list  ifname:%s flag:%d",p->ifname,p->compres_flag);
        p=p->next;
    }
#endif
    return 0;
}
#endif
#if 1
static int operate_compress_mod()
{
    FILE *fp;
    char buf[512] = "";
    int ret1,ret2;

//_PATH_COMMAND_COMPRESS

    fp = popen("/sbin/lsmod | grep router_hc_comp","r");
    if(!fp)
    {
        zlog_notice("excute this command failure");
        return -1;
    }
    fgets(buf,sizeof(buf),fp);
    if(!strstr(buf,"route"))
    {
        zlog_notice("find this route mod");
        goto COMPRESS_INSTALL;
    }
//
    ret1 = system(UNINSTALL_COMPRESS1);
    ret2 = system(UNINSTALL_COMPRESS2);
    if((ret1 == -1 || ret1 == 127 || ret1 == 1) ||(ret2 == -1 || ret2 == 127 || ret2 == 1))
    {
        zlog_notice("uninstall header conpression failure");
        return -2;
    }


COMPRESS_INSTALL:
    ret1 = system(INSTALL_COMPRESS1);
    ret2 = system(INSTALL_COMPRESS2);
    if((ret1 == -1 || ret1 == 127 || ret1 == 1) ||(ret2 == -1 || ret2 == 127 || ret2 == 1))
    {
        zlog_notice("install header conpression failure");
        return -3;
    }


    /*
       if(flag)
       {
           ret = system(INSTALL_COMPRESS);
           zlog_notice("@excute this operate_compress_mod ");
           if(ret == -1 || ret == 127 || ret == 1)
           {
             zlog_notice(" INstall failure");
             return -2;
           }
       }else{

           ret = system(UNINSTALL_COMPRESS);
           if(ret == -1 || ret == 127 || ret == 1)
           {
             zlog_notice(" INstall failure");
             return -3;
           }
           zlog_notice("#excute this operate_compress_mod ");
       }
     */
    //system("/root/work/make install");

    pclose(fp);


    return 0;
}

static int set_if_compress_list(char *ifname,int flag)
{
    struct  if_compress_enabled *p =if_compress_head ;


    while(p != NULL)
    {
        //zlog_notice("the add if_compress_list  ifname:%s flag:%d",p->ifname,p->compres_flag);
        if(!strcmp(ifname,p->ifname))
            p->compres_flag = flag;
        p=p->next;
    }


    return 0;
}

#endif
DEFUN (header_compression_interface_enabled,
       header_compression_interface_enabled_cmd,
       "header-compression INTERFACE enabled ",
       "Compress the header of TCP/IP datagram\n"
       "Interface name\n"
       "The header compression will be opened\n")
{

#if 1

    int flag = COMPRESS_ON;
    struct  if_compress_enabled *p =if_compress_head ;

    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(p == NULL)
    {
        add_if_compress_list(argv[0],flag);

    }
    else
    {

        if(check_if_exist(argv[0],flag)< 0)
        {
            vty_out(vty," this interface has enabled header compression");
            return CMD_WARNING;
        }
        add_if_compress_list(argv[0],flag);
    }



    /*   while(p->next != NULL)
       {
         vty_out(vty,"the ifname:%s flag:%d",p->ifname,p->compres_flag);
         p=p->next;
       }
    */


    write_message_if_compre_file();
    operate_compress_mod(flag);
//
#endif

    return CMD_SUCCESS;

}
DEFUN (no_header_compression_interface_enabled,
       no_header_compression_interface_enabled_cmd,
       "no header-compression IFNAME enabled",
       NO_STR
       "header-compression\n"
       "IFNAME"
       "enabled\n")
{
    int flag = COMPRESS_OFF;
    struct  if_compress_enabled *p =if_compress_head ;

    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(check_if_exist(argv[0],flag)< 0)
    {
        vty_out(vty," this interface has disenabled header compression");
        return CMD_WARNING;
    }

    set_if_compress_list(argv[0],flag);
    write_message_if_compre_file();
    del_if_message_at_list(argv[0]);
    operate_compress_mod();

    return CMD_SUCCESS;

}

int zebra_header_compress_write_config(struct vty *vty,char *ifname)
{
    vty_out(vty,"!%s",VTY_NEWLINE);
    struct if_compress_enabled *p =if_compress_head;
    while(p != NULL)
    {
        vty_out(vty,"header-compression %s enabled%s",p->ifname,VTY_NEWLINE);

        zlog_notice("header-compression %s enabled",p->ifname);
        p=p->next;
    }

    vty_out(vty,"!%s",VTY_NEWLINE);
    zlog_notice("excute this zebra header-compress");
    return CMD_SUCCESS;

}

/**********************end add by myj in 2016.12.23****************/

static int
ip_nat_config_pool (struct vty *vty)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int write = 0;

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat pool %s %s %s",
                 pNext->name, pNext->startaddr, pNext->endaddr);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int
ip_nat_config_source_list (struct vty *vty)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int write = 0;

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat source list %s %s",
                 pNext->name, pNext->snet);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int
ip_nat_config_source_list_pool (struct vty *vty)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int write = 0;

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat inside source list %s pool %s",
                 pNext->source.name, pNext->pool.name);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int
ip_nat_config (struct vty *vty)
{
    int write = 0;
#ifdef HAVE_IPNAT
    write += ip_nat_config_pool(vty);

    write += ip_nat_config_source_list(vty);

    write += ip_nat_config_source_list_pool(vty);
#endif
    return write;
}

static int
ip_dhcp_config (struct vty *vty)
{
    int write = 0;
#ifdef HAVE_DHCPV4
    write += zebra_dhcp_write_config(vty);
#endif
    return write;
}





/* Static ip route configuration write function. */
static int
zebra_ip_config (struct vty *vty)
{
    int write = 0;

    write += static_config_ipv4 (vty);

//added for 4over6 20130306
    write += static_config_ipv4_4over6 (vty);
//added for arp 20131024
    write += static_config_ipv4_arp(vty);

#ifdef HAVE_IPV6
    write += static_config_ipv6 (vty);
#endif /* HAVE_IPV6 */

#ifdef HAVE_NETWIRE
    write += zebra_netwire_config(vty);
#endif


#ifdef HAVE_DNS64
    write += zebra_dns64_write_config(vty);
#endif

#ifdef HAVE_SNMP
    write += zebra_snmp_write_config(vty);
#endif


#ifdef HAVE_4OVER6_TCPMSS
    write += zebra_4over6_write_tcp_mss_config(vty);
#endif
    return write;
}

/* ip protocol configuration write function */
static int config_write_protocol(struct vty *vty)
{
    int i;

    for (i=0; i<ZEBRA_ROUTE_MAX; i++)
    {
        if (proto_rm[AFI_IP][i])
            vty_out (vty, "ip protocol %s route-map %s%s", zebra_route_string(i),
                     proto_rm[AFI_IP][i], VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP][ZEBRA_ROUTE_MAX])
        vty_out (vty, "ip protocol %s route-map %s%s", "any",
                 proto_rm[AFI_IP][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

    return 1;
}

/* table node for protocol filtering */
static struct cmd_node protocol_node = { PROTOCOL_NODE, "", 1 };

/* IP node for static routes. */
static struct cmd_node ip_node = { IP_NODE,  "",  1 };

//added for nat 20130508
static struct cmd_node ip_nat_node = { IP_NAT_NODE,  "",  1 };
#if 1
struct cmd_node dhcp_node =
{
    DHCP_NODE,
    "%s(config-dhcp)# ",
    1
};
#endif


/* Route VTY.  */
void
zebra_vty_init (void)
{
    memset(arp_keep_config,0,sizeof(arp_keep_config));
    //added for nat 20130508
    install_node (&ip_nat_node, ip_nat_config);


    install_node (&dhcp_node, ip_dhcp_config);//zebra_dhcpv4_write_config);
    install_default(DHCP_NODE);
    install_node (&ip_node, zebra_ip_config);
    install_node (&protocol_node, config_write_protocol);

    install_element (CONFIG_NODE, &nat64_v4pool_cmd);
    install_element (CONFIG_NODE, &no_nat64_v4pool_cmd);

    install_element (CONFIG_NODE, &nat64_prefix_cmd);
    install_element (CONFIG_NODE, &no_nat64_prefix_cmd);
//  install_element (CONFIG_NODE, &show_nat64_prefix_cmd);
    install_element (CONFIG_NODE, &nat64_timeout_cmd);
    install_element (CONFIG_NODE, &no_nat64_timeout_cmd);

    /* */
    install_element (CONFIG_NODE, &ivi_prefix_cmd);
    install_element (CONFIG_NODE, &no_ivi_prefix_cmd);
// install_element (CONFIG_NODE, &show_ivi_prefix_cmd);

// install_element (CONFIG_NODE, &fover6_tunnel_cmd);

#ifdef HAVE_DNS64
    /*added by wangyl fro dns64*/
    install_element (CONFIG_NODE, &dns64_prefix_cmd);
    install_element (CONFIG_NODE, &no_dns64_prefix_cmd);
    /*added end*/
#endif

#ifdef HAVE_4OVER6_TCPMSS
    install_element (CONFIG_NODE, &tunnel4o6_tcp_mss_cmd);
    install_element (CONFIG_NODE, &no_tunnel4o6_tcp_mss_cmd);
#endif
    install_element (CONFIG_NODE, &ip_protocol_cmd);
    install_element (CONFIG_NODE, &no_ip_protocol_cmd);
    install_element (VIEW_NODE, &show_ip_protocol_cmd);
    install_element (ENABLE_NODE, &show_ip_protocol_cmd);
    //add by ccc for ecn
    install_element (CONFIG_NODE, &ecn_enable_cmd);
    install_element (CONFIG_NODE, &no_ecn_enable_cmd);
    install_element (CONFIG_NODE, &ecn_politic_cmd);
    install_element (CONFIG_NODE, &no_ecn_politic_cmd);
    install_element (VIEW_NODE , &show_qdisc_cmd);
    install_element (ENABLE_NODE,&show_qdisc_cmd);
    //add end
    //add by ccc for flow separation by people and soldier
    install_element (CONFIG_NODE, &enable_interface_area_cmd);
    install_element (CONFIG_NODE, &no_enable_interface_area_cmd);

    //add by myj in 2016.12.23
    install_element (CONFIG_NODE, &header_compression_interface_enabled_cmd);
    install_element (CONFIG_NODE, &no_header_compression_interface_enabled_cmd);


    //add end
    /*add dhcp ,add by huang jing in 2013 5 14*/
#ifdef HAVE_DHCPV4
    install_element (CONFIG_NODE, &ip_dhcp_excluded_address_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_excluded_address_cmd);
    install_element (CONFIG_NODE, &ip_dhcp_excluded_address__distance1_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_excluded_address__distance1_cmd);

    install_element (CONFIG_NODE, &ip_dhcp_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_pool_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_network_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_network_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_dnstince1_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_dnstince1_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_dnstince2_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_dnstince2_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_dnstince1_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_dnstince1_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_dnstince2_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_dnstince2_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_lease_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_lease_hours_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_lease_minutes_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_lease_cmd);
#endif
#if 0
    install_element (DHCP_NODE,&ip_dhcp_pool_exit_cmd);
#endif
    /*add dhcp */

    install_element (CONFIG_NODE, &ip_route_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_cmd);
    install_element (CONFIG_NODE, &ip_route_flags2_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags2_cmd);
    install_element (CONFIG_NODE, &ip_route_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_distance2_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_distance2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_distance2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_distance2_cmd);

    install_element (VIEW_NODE, &show_ip_route_cmd);
    install_element (VIEW_NODE, &show_ip_route_addr_cmd);
    install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
    install_element (VIEW_NODE, &show_ip_route_prefix_longer_cmd);
    install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
    install_element (VIEW_NODE, &show_ip_route_supernets_cmd);
    install_element (VIEW_NODE, &show_ip_route_summary_cmd);
    install_element (ENABLE_NODE, &show_ip_route_cmd);
    install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
    install_element (ENABLE_NODE, &show_ip_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);
    install_element (ENABLE_NODE, &show_ip_route_supernets_cmd);
    install_element (ENABLE_NODE, &show_ip_route_summary_cmd);

    install_element (VIEW_NODE, &show_ip_mroute_cmd);
    install_element (ENABLE_NODE, &show_ip_mroute_cmd);

    //added for 4over6 20130205
    install_element (CONFIG_NODE, &ip_4over6_route_mask_cmd);
    install_element (CONFIG_NODE, &no_ip_4over6_route_mask_cmd);
    install_element (CONFIG_NODE, &ip_4over6_route_cmd);
    install_element (CONFIG_NODE, &no_ip_4over6_route_cmd);
#ifdef HAVE_IPNAT
    //added for nat 20130505
    install_element (CONFIG_NODE, &ip_nat_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_pool_cmd);
    install_element (CONFIG_NODE, &ip_nat_source_list_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_source_list_cmd);
    install_element (CONFIG_NODE, &ip_nat_inside_source_list_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_inside_source_list_pool_cmd);
    install_element (INTERFACE_NODE, &ip_nat_inside_cmd);
    install_element (INTERFACE_NODE, &no_ip_nat_inside_cmd);
    install_element (INTERFACE_NODE, &ip_nat_outside_cmd);
    install_element (INTERFACE_NODE, &no_ip_nat_outside_cmd);
    //install_element (ENABLE_NODE, &show_arp_cmd);
#endif
#ifdef HAVE_SNMP
    //added by limingyuan for snmp community config 2013.7.31
    install_element (CONFIG_NODE, &snmp_community_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_community_config_cmd);
    //added by limingyuan for snmp v3 config 2013.8.9
    install_element (CONFIG_NODE, &snmp_v3_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_v3_config_cmd);
    //added by limingyuan for snmp trap config 2013.8.16
    install_element (CONFIG_NODE, &snmp_trap_enable_cmd);
    install_element (CONFIG_NODE, &snmp_trap_disable_cmd);
    install_element (CONFIG_NODE, &snmp_trap_host_config_cmd);
    install_element (CONFIG_NODE, &snmp_trap_host_community_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_trap_host_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_trap_host_community_config_cmd);
#endif
    /*added by zhangzhibo 2013.9.2 for add arp*/
    install_element (CONFIG_NODE, &arp_cmd);
    /*added by zhangzhibo 2013.9.2 for del arp*/
    install_element (CONFIG_NODE, &no_arp_cmd);
    install_element (CONFIG_NODE, &ssh_username_passwd_cmd);

    install_element (CONFIG_NODE, &ipv6_control_server_address_cmd);
    install_element (VIEW_NODE, &show_control_server_configure_cmd);
    install_element (ENABLE_NODE, &show_control_server_configure_cmd);
#ifdef HAVE_IPV6
    install_element (CONFIG_NODE, &ipv6_route_cmd);
    install_element (CONFIG_NODE, &ipv6_route_flags_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_flags_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_flags_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_flags_cmd);
    install_element (CONFIG_NODE, &ipv6_route_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_flags_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_flags_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_flags_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_flags_pref_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_summary_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_protocol_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_addr_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_prefix_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_protocol_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_prefix_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_summary_cmd);
// install_element (ENABLE_NODE, &show_ipv6_neighbor_cmd);

    install_element (VIEW_NODE, &show_ipv6_mroute_cmd);
    install_element (ENABLE_NODE, &show_ipv6_mroute_cmd);
#if 1                           //sangmeng add
    install_element(INTERFACE_NODE, &ip_access_group_listnumber_cmd);
    install_element(INTERFACE_NODE, &no_ip_access_group_listnumber_cmd);
    install_element(INTERFACE_NODE, &ipv6_access_group_listnumber_cmd);
    install_element(INTERFACE_NODE, &no_ipv6_access_group_listnumber_cmd);
#endif
#endif                          /* HAVE_IPV6 */
}
//add by ccc for ecn

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
    {
        fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}
int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
    struct
    {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
    req.g.rtgen_family = family;

    return send(rth->fd, (void*)&req, sizeof(req), 0);
}
int rtnl_dump_filter_l(struct rtnl_handle *rth,
                       const struct rtnl_dump_filter_arg *arg)
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg =
    {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char buf[16384];

    iov.iov_base = buf;
    while (1)
    {
        int status;
        const struct rtnl_dump_filter_arg *a;

        iov.iov_len = sizeof(buf);
        status = recvmsg(rth->fd, &msg, 0);
        if (status < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            fprintf(stderr, "netlink receive error %s (%d)\n",
                    strerror(errno), errno);
            return -1;
        }

        if (status == 0)
        {
            fprintf(stderr, "EOF on netlink\n");
            return -1;
        }

        for (a = arg; a->filter; a++)
        {
            struct nlmsghdr *h = (struct nlmsghdr*)buf;

            while (NLMSG_OK(h, status))
            {
                int err;

                if (nladdr.nl_pid != 0 ||
                        h->nlmsg_pid != rth->local.nl_pid ||
                        h->nlmsg_seq != rth->dump)
                {
                    if (a->junk)
                    {
                        err = a->junk(&nladdr, h,
                                      a->arg2);
                        if (err < 0)
                            return err;
                    }
                    goto skip_it;
                }

                if (h->nlmsg_type == NLMSG_DONE)
                    return 0;
                if (h->nlmsg_type == NLMSG_ERROR)
                {
                    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                    if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    {
                        fprintf(stderr,
                                "ERROR truncated\n");
                    }
                    else
                    {
                        errno = -err->error;
                        perror("RTNETLINK answers");
                    }
                    return -1;
                }
                err = a->filter(&nladdr, h, a->arg1);
                if (err < 0)
                    return err;

skip_it:
                h = NLMSG_NEXT(h, status);
            }
        }
        while (0);
        if (msg.msg_flags & MSG_TRUNC)
        {
            fprintf(stderr, "Message truncated\n");
            continue;
        }
        if (status)
        {
            fprintf(stderr, "!!!Remnant of size %d\n", status);
            exit(1);
        }
    }
}
int rtnl_dump_filter(struct rtnl_handle *rth,
                     rtnl_filter_t filter,
                     void *arg1,
                     rtnl_filter_t junk,
                     void *arg2)
{
    const struct rtnl_dump_filter_arg a[2] =
    {
        { .filter = filter, .arg1 = arg1, .junk = junk, .arg2 = arg2 },
        { .filter = NULL,   .arg1 = NULL, .junk = NULL, .arg2 = NULL }
    };

    return rtnl_dump_filter_l(rth, a);
}
int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len))
    {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len)
        fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
    return 0;
}
int ll_remember_index(const struct sockaddr_nl *who,
                      struct nlmsghdr *n, void *arg)
{
    int h;
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct idxmap *im, **imp;
    struct rtattr *tb[IFLA_MAX+1];

    if (n->nlmsg_type != RTM_NEWLINK)
        return 0;

    if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
        return -1;


    memset(tb, 0, sizeof(tb));
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
    if (tb[IFLA_IFNAME] == NULL)
        return 0;

    h = ifi->ifi_index&0xF;

    for (imp=&idxmap[h]; (im=*imp)!=NULL; imp = &im->next)
        if (im->index == ifi->ifi_index)
            break;

    if (im == NULL)
    {
        im = malloc(sizeof(*im));
        if (im == NULL)
            return 0;
        im->next = *imp;
        im->index = ifi->ifi_index;
        *imp = im;
    }

    im->type = ifi->ifi_type;
    im->flags = ifi->ifi_flags;
    if (tb[IFLA_ADDRESS])
    {
        int alen;
        im->alen = alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
        if (alen > sizeof(im->addr))
            alen = sizeof(im->addr);
        memcpy(im->addr, RTA_DATA(tb[IFLA_ADDRESS]), alen);
    }
    else
    {
        im->alen = 0;
        memset(im->addr, 0, sizeof(im->addr));
    }
    strcpy(im->name, RTA_DATA(tb[IFLA_IFNAME]));
    return 0;
}

int ll_init_map(struct rtnl_handle *rth)
{
    if (rtnl_wilddump_request(rth, AF_UNSPEC, RTM_GETLINK) < 0)
    {
        perror("Cannot send dump request");
        exit(1);
    }

    if (rtnl_dump_filter(rth, ll_remember_index, &idxmap, NULL, NULL) < 0)
    {
        fprintf(stderr, "Dump terminated\n");
        exit(1);
    }
    return 0;
}
#if 0
//ll_name_to_index
unsigned ll_name_to_index(char *name)
{
    static char ncache[16];
    static int icache;
    struct idxmap *im;
    int i;

    if (name == NULL)
        return 0;
    if (icache && strcmp(name, ncache) == 0)
        return icache;
    for (i=0; i<16; i++)
    {
        for (im = idxmap[i]; im; im = im->next)
        {
            if (strcmp(im->name, name) == 0)
            {
                icache = im->index;
                strcpy(ncache, name);
                return im->index;
            }
        }
    }

    return if_nametoindex(name);
}
#endif
/* open rtnl*/
int rcvbuf = 1024 * 1024;
int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
                      int protocol)
{
    socklen_t addr_len;
    int sndbuf = 32768;
    memset(rth, 0, sizeof(*rth));
    rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (rth->fd < 0)
    {
        perror("Cannot open netlink socket");
        return -1;
    }
    if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0)
    {
        perror("SO_SNDBUF");
        return -1;
    }
    if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0)
    {
        perror("SO_RCVBUF");
        return -1;
    }
    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;
    if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0)
    {
        perror("Cannot bind netlink socket");
        return -1;
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0)
    {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local))
    {
        fprintf(stderr, "Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK)
    {
        fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }
    rth->seq = time(NULL);
    return 0;
}
#define NETLINK_ROUTE 0
int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
    return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}
/*rtnl close*/
void rtnl_close(struct rtnl_handle *rth)
{
    if (rth->fd >= 0)
    {
        close(rth->fd);
        rth->fd = -1;
    }
}
int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
              unsigned groups, struct nlmsghdr *answer,
              rtnl_filter_t junk,
              void *jarg)
{
    int status;
    unsigned seq;
    struct nlmsghdr *h;
    struct sockaddr_nl nladdr;
    struct iovec iov =
    {
        .iov_base = (void*) n,
        .iov_len = n->nlmsg_len
    };
    struct msghdr msg =
    {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char   buf[16384];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = peer;
    nladdr.nl_groups = groups;

    n->nlmsg_seq = seq = ++rtnl->seq;

    if (answer == NULL)
        n->nlmsg_flags |= NLM_F_ACK;

    status = sendmsg(rtnl->fd, &msg, 0);

    if (status < 0)
    {
        perror("Cannot talk to rtnetlink");
        return -1;
    }

    memset(buf,0,sizeof(buf));

    iov.iov_base = buf;

    while (1)
    {
        iov.iov_len = sizeof(buf);
        status = recvmsg(rtnl->fd, &msg, 0);

        if (status < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            fprintf(stderr, "netlink receive error %s (%d)\n",
                    strerror(errno), errno);
            return -1;
        }
        if (status == 0)
        {
            fprintf(stderr, "EOF on netlink\n");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr))
        {
            fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
            exit(1);
        }
        for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); )
        {
            int err;
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if (l<0 || len>status)
            {
                if (msg.msg_flags & MSG_TRUNC)
                {
                    fprintf(stderr, "Truncated message\n");
                    return -1;
                }
                fprintf(stderr, "!!!malformed message: len=%d\n", len);
                exit(1);
            }

            if (nladdr.nl_pid != peer ||
                    h->nlmsg_pid != rtnl->local.nl_pid ||
                    h->nlmsg_seq != seq)
            {
                if (junk)
                {
                    err = junk(&nladdr, h, jarg);
                    if (err < 0)
                        return err;
                }
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                if (l < sizeof(struct nlmsgerr))
                {
                    fprintf(stderr, "ERROR truncated\n");
                }
                else
                {
                    errno = -err->error;
                    if (errno == 0)
                    {
                        if (answer)
                            memcpy(answer, h, h->nlmsg_len);
                        return 0;
                    }
                    perror("RTNETLINK answers");
                }
                return -1;
            }
            if (answer)
            {
                memcpy(answer, h, h->nlmsg_len);
                return 0;
            }

            fprintf(stderr, "Unexpected reply!!!\n");

            status -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC)
        {
            fprintf(stderr, "Message truncated\n");
            continue;
        }
        if (status)
        {
            fprintf(stderr, "!!!Remnant of size %d\n", status);
            exit(1);
        }
    }
}
//int tc_red_eval_idle_damping(int Wlog, unsigned avpkt, unsigned bps, unsigned char *sbuf)
int tc_red_eval_idle_damping(unsigned char *sbuf)
{
#if 0
    double xmit_time = 1000000*((double)avpkt/bps);//tc_calc_xmittime(bps, avpkt);
    printf("xmit = %f\n",xmit_time);
    double lW = -log(1.0 - 1.0/(1<<Wlog))/xmit_time;
    printf("lw =%f\n",lW);
    double maxtime = 31/lW;
    printf("maxtime = %f\n",maxtime);
    int clog;
    int i;
    double tmp;

    tmp = maxtime;
    for (clog=0; clog<32; clog++)
    {
        if (maxtime/(1<<clog) < 512)
            break;
    }
    if (clog >= 32)
        return -1;

    sbuf[0] = 0;
    for (i=1; i<255; i++)
    {
        sbuf[i] = (i<<clog)*lW;
        if (sbuf[i] > 31)
            sbuf[i] = 31;
        printf("sbuf %d is %d\n",i,sbuf[i]);
    }
    sbuf[255] = 31;
    return clog;
#endif
    int clog = 0;
    memset(sbuf,0,255);
    return clog;
}
#if 0
static int red_parse_opt(struct nlmsghdr *n)
{
    struct rtattr *tail;//ccc
    unsigned char sbuf[256];
    struct tc_red_qopt opt;
    memset(&opt, 0, sizeof(opt));
    opt.limit = 100000000;
    opt.qth_min = 497;
    opt.qth_max = 497;
    opt.Wlog = 0;
    opt.Plog = 1;

    int avpkt = 1;
    unsigned rate = 1024*1024/8;
    opt.Scell_log =  tc_red_eval_idle_damping(opt.Wlog, avpkt, rate, sbuf);
    opt.flags |= TC_RED_ECN;//enable ECN

    printf("red parms limit:%d min:%d max:%d Wlog:%d Plog:%d\n",opt.limit,opt.
           qth_min,opt.qth_max,opt.Wlog,opt.Plog);
    printf("other parms avpkt:%d rate:%d\n",avpkt,rate);

    //fill in msg
    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(n, 1024, TCA_RED_PARMS, &opt, sizeof(opt));
    addattr_l(n, 1024, TCA_RED_STAB, sbuf, 256);
    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
    return 0;

}
int do_cmd(int cmd)
{
    //int tc_qdisc_modify(int cmd, unsigned flags, int argc, char **argv)

    struct
    {
        struct nlmsghdr 	n;
        struct tcmsg 		t;
        char   			buf[TCA_BUF_MAX];
    } req;
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    if (cmd == REPLACE)
    {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;//flags:replace:NLM_F_CREATE|NLM_F_REPLACE  delete:0
        req.n.nlmsg_type = RTM_NEWQDISC;//cmd:relcace:RTM_NEWQDISC  delete:RTM_DELQDISC
    }
    else
    {
        req.n.nlmsg_flags = NLM_F_REQUEST|0;
        req.n.nlmsg_type =RTM_DELQDISC;//cmd:relcace:RTM_NEWQDISC  delete:RTM_DELQDISC
    }
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_parent = TC_H_ROOT;

    char  d[16]="em1";//dev name
    char  k[16]="red";//red
    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);//enable red

    red_parse_opt(&req.n);//fill red parms
    //dev
    if (d[0])
    {
        int idx;
        ll_init_map(&rth);
        if ((idx = ll_name_to_index(d)) == 0)
        {
            fprintf(stderr, "Cannot find device \"%s\"\n", d);
            return 1;
        }
        req.t.tcm_ifindex = idx;
        //printf("idx = %d \n",idx);
    }

    //rtnl talk
    if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
    {
        perror("rtnl");
        printf("rtnl is wrong\n");
        return 2;
    }
    return 0;
}
#endif
int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len)
{
    struct nlmsghdr nlh;
    struct sockaddr_nl nladdr;
    struct iovec iov[2] =
    {
        { .iov_base = &nlh, .iov_len = sizeof(nlh) },
        { .iov_base = req, .iov_len = len }
    };
    struct msghdr msg =
    {
        .msg_name = &nladdr,
        .msg_namelen = 	sizeof(nladdr),
        .msg_iov = iov,
        .msg_iovlen = 2,
    };

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    nlh.nlmsg_len = NLMSG_LENGTH(len);
    nlh.nlmsg_type = type;
    nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    nlh.nlmsg_pid = 0;
    nlh.nlmsg_seq = rth->dump = ++rth->seq;

    return sendmsg(rth->fd, &msg, 0);
}
void print_size_table(FILE *fp, const char *prefix, struct rtattr *rta)
{
    struct rtattr *tb[TCA_STAB_MAX + 1];
    SPRINT_BUF(b1);
    parse_rtattr_nested(tb, TCA_STAB_MAX, rta);
}

void print_tcstats2_attr(struct vty*vty, struct rtattr *rta, char *prefix, struct rtattr **xstats)
{
    SPRINT_BUF(b1);
    struct rtattr *tbs[TCA_STATS_MAX + 1];

    parse_rtattr_nested(tbs, TCA_STATS_MAX, rta);

    if (tbs[TCA_STATS_BASIC])
    {
        struct gnet_stats_basic bs = {0};
        memcpy(&bs, RTA_DATA(tbs[TCA_STATS_BASIC]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_BASIC]), sizeof(bs)));
        vty_out(vty, " %sSent %llu bytes %u pkt%s",prefix, (unsigned long long) bs.bytes, bs.packets,VTY_NEWLINE);
    }

    if (tbs[TCA_STATS_QUEUE])
    {
        struct gnet_stats_queue q = {0};
        memcpy(&q, RTA_DATA(tbs[TCA_STATS_QUEUE]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(q)));
        vty_out(vty, "dropped %u pkt, overlimits %u pkt,requeues %u pkt",q.drops, q.overlimits, q.requeues);
    }
    if (xstats)
        *xstats = tbs[TCA_STATS_APP] ? : NULL;
}

void print_tcstats_attr(struct vty*vty, struct rtattr *tb[], char *prefix, struct rtattr **xstats)
{
    SPRINT_BUF(b1);
    if (tb[TCA_STATS2])
    {
        print_tcstats2_attr(vty, tb[TCA_STATS2], prefix, xstats);
        if (xstats && NULL == *xstats)
            goto compat_xstats;
        return;
    }
    /* backward compatibility */
    if (tb[TCA_STATS])
    {
        struct tc_stats st;
        /* handle case where kernel returns more/less than we know about */
        memset(&st, 0, sizeof(st));
        memcpy(&st, RTA_DATA(tb[TCA_STATS]), MIN(RTA_PAYLOAD(tb[TCA_STATS]), sizeof(st)));
        //vty_out(vty,"receive %lu bytes",(unsigned long long)st.bytes+st.packets);
        vty_out(vty, "%sSent %llu bytes %u pkts (dropped %u, overlimits %u) ",prefix, (unsigned long long)st.bytes, st.packets, st.drops,st.overlimits);
    }
compat_xstats:
    if (tb[TCA_XSTATS] && xstats)
        *xstats = tb[TCA_XSTATS];
}

int red_print_xstats(struct vty*vty, struct rtattr *xstats)
{
    struct tc_red_xstats *st;
    if (xstats == NULL)
        return 0;
    if (RTA_PAYLOAD(xstats) < sizeof(*st))
        return -1;
    st = RTA_DATA(xstats);
    vty_out(vty, "  marked %u pkt, early %u pkt, bandwidth %u Mbps",st->marked, st->early,st->other);
    //vty_out(vty, "  marked %u early %u pdrop %u other %u",st->marked, st->early, st->pdrop, st->other);
    return 0;
}
