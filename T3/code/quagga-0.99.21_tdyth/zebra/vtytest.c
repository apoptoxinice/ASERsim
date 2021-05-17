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

#define HAVE_NETWIRE
#define HAVE_DNS64
#define HAVE_DHCPV4
//#define HAVE_4OVER6_TCPMSS
#define HAVE_IPNAT
//#define HAVE_SNMP
#define BYTE unsigned char


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
////change by ccc
DEFUN(nat64_v4pool,
      nat64_v4pool_cmd,
      "nat64 v4pool X.X.X.X/M ",
      "Configure nat64 protocol\n"
      "Configure IPv4 pool\n"
      "IP prefix <network>/<length>, e.g., 35.0.0.0/29\n"
     )
{
    if(nat_pool_head != NULL)
    {
        vty_out(vty,"this pool is alreay exist%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_pool_message *p_nat_pool = (struct nat_pool_message *)malloc(sizeof(struct nat_pool_message));
    memset(p_nat_pool,0,sizeof(struct nat_pool_message));
    p_ivi->data = p_nat_pool;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = ADD_NAT64_POOL;//type
    //prefix
    ret = str2prefix_ipv4( argv[0],&(p_nat_pool->prefix4) );
    if (ret <= 0)
    {
        free(p_ivi);
        free(p_nat_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(!(p_nat_pool->prefix4.prefixlen > 28))
    {
        free(p_ivi);
        free(p_nat_pool);
        vty_out (vty, "%% prefixlen should be greater than 28%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_pool_message);//len
    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_pool);
        free(p_ivi);
        vty_out(vty,"connot connect server%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    nat_pool_head = p_nat_pool;
    return CMD_SUCCESS;

    /*
     #define SIOCADDPOOL (SIOCCHGTUNNEL+10)
     #define NO_MATCH 37
     #define V4POOL_EXIST 38
     #define V4POOL_OVERFLOW 39
      struct address{
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
       */
}
/*manage ipv4 pool*/

DEFUN(no_nat64_v4pool,
      no_nat64_v4pool_cmd,
      "no nat64 v4pool X.X.X.X/M ",
      NO_STR
      "Configure nat64 protocol\n"
      "Configure IPv4 pool\n"
      "IP prefix <network>/<length>, e.g., 35.0.0.0/29\n"
     )
{
    if(nat_pool_head == NULL)
        return CMD_WARNING;
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_pool_message *p_nat_pool = (struct nat_pool_message *)malloc(sizeof(struct nat_pool_message));
    memset(p_nat_pool,0,sizeof(struct nat_pool_message));
    p_ivi->data = p_nat_pool;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = DEL_NAT64_POOL;//type
    //prefix
    ret = str2prefix_ipv4( argv[0],&(p_nat_pool->prefix4) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_nat_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if( memcmp( &(nat_pool_head->prefix4),&(p_nat_pool->prefix4),sizeof(struct prefix_ipv4)) )
    {
        free(p_ivi);
        free(p_nat_pool);
        vty_out (vty, "%% not match address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_pool_message);//len
    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_pool);
        free(p_ivi);
        vty_out(vty,"ivi socket wrong%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    free(nat_pool_head);
    nat_pool_head = NULL;

    free(p_nat_pool);
    free(p_ivi);
    return CMD_SUCCESS;
    /*
     #define SIOCDELPOOL (SIOCCHGTUNNEL+11)
     #define NO_MATCH 37
      struct address{
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
       */
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

    //去除点分十进制地址中的无效的0，eg: 010.01.001.1 -> 10.1.1.1
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
//change by ccc
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

    if(nat_prefix_head != NULL)
    {
        vty_out(vty,"this prefix is already exist%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_prefix_message *p_nat_prefix = (struct nat_prefix_message *)malloc(sizeof(struct nat_prefix_message));
    memset(p_nat_prefix,0,sizeof(struct nat_prefix_message));
    p_ivi->data = p_nat_prefix;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = ADD_NAT64_PREFIX;//type
    //prefix
    ret = str2prefix_ipv6( argv[0],&(p_nat_prefix->prefix6) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_nat_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    if( !strcmp(argv[1],"ubit") )
    {
        p_nat_prefix->flag = UBIT;	//flag
    }
    else if( !strcmp(argv[1],"no-ubit") )
    {
        p_nat_prefix->flag = NO_UBIT;
    }
    else
    {
        free(p_ivi);
        free(p_nat_prefix);
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_prefix_message);//len

    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_prefix);
        free(p_ivi);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    nat_prefix_head = p_nat_prefix;
    return CMD_SUCCESS;
    /*
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
    	 */
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
    if(nat_prefix_head == NULL)
        return CMD_WARNING;
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_prefix_message *p_nat_prefix = (struct nat_prefix_message *)malloc(sizeof(struct nat_prefix_message));
    memset(p_nat_prefix,0,sizeof(struct nat_prefix_message));
    p_ivi->data = p_nat_prefix;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = DEL_NAT64_PREFIX;//type
    //prefix
    ret = str2prefix_ipv6( argv[0],&(p_nat_prefix->prefix6) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_nat_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_nat_prefix->flag = 0;
    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_prefix_message);//len
    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_prefix);
        free(p_ivi);
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if( !memcmp( &(nat_prefix_head->prefix6),&(p_nat_prefix->prefix6),sizeof(struct prefix_ipv6)) )
    {
        free(nat_prefix_head);
        nat_prefix_head = NULL;
    }

    free(p_nat_prefix);
    free(p_ivi);
    return CMD_SUCCESS;
    /*
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
    */
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
////change by ccc for ivi
int ivi_client_connect(struct ivi_message* p_ivi,int size)
{
    /*start connect server*/
    int ivi_sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    int ret = 0;
    if(ivi_sock <= 0)
        return -1;

    struct sockaddr_in socketaddress;
    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons(IVI_INET_PORT);
    socketaddress.sin_addr.s_addr = inet_addr(IVI_INET_ADDRESS);
    memset( &(socketaddress.sin_zero), 0, 8 );
    /*start connect*/
    ret = connect( ivi_sock,&socketaddress,sizeof(struct sockaddr) );
    if(ret < 0)
    {
        close(ivi_sock);
        return -1;
    }
    /*send ivi message*/
    char buf[1024] = "";
    memcpy(buf,p_ivi,sizeof(struct ivi_message));
    if( (p_ivi->type == ADD_IVI_PREFIX )||(p_ivi->type == DEL_IVI_PREFIX) )
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct ivi_prefix_message));
    if( (p_ivi->type == ADD_IVI_POOL )||(p_ivi->type == DEL_IVI_POOL) )
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct ivi_pool_message));
    if( (p_ivi->type == ADD_TUNNEL)||(p_ivi->type == DEL_TUNNEL) )
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct tunnel_info));
    if( (p_ivi->type == ADD_NAT64_PREFIX )||(p_ivi->type == DEL_NAT64_PREFIX) )
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct nat_prefix_message));
    if((p_ivi->type == ADD_NAT64_POOL )||(p_ivi->type == DEL_NAT64_POOL))
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct nat_pool_message));
    if((p_ivi->type == ADD_NAT64_TIMEOUT )||(p_ivi->type == DEL_NAT64_TIMEOUT))
        memcpy(buf+sizeof(struct ivi_message),p_ivi->data,sizeof(struct nat_timeout_message));
    ret = send( ivi_sock, buf, size, 0 );

    close(ivi_sock);
    return 0;
}
DEFUN(ivi_prefix,
      ivi_prefix_cmd,
      "ivi prefix X:X::X:X/M (ubit|no-ubit)",
      "configure ivi prefix\n"
      "ivi ipv6 prefix\n"
      "prefix/prefix_length\n"
      "with ubit\n"
      "without ubit\n"
     )
{
    if(ivi_prefix_head != NULL)
    {
        vty_out(vty,"IVI prefix is already exist%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct ivi_prefix_message *p_ivi_prefix = (struct ivi_prefix_message *)malloc(sizeof(struct ivi_prefix_message));
    memset(p_ivi_prefix,0,sizeof(struct ivi_prefix_message));
    p_ivi->data = p_ivi_prefix;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = ADD_IVI_PREFIX;//type
    //prefix
    ret = str2prefix_ipv6( argv[0],&(p_ivi_prefix->prefix6) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_ivi_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    if( !strcmp(argv[1],"ubit") )
    {
        p_ivi_prefix->flag = UBIT;	//flag
    }
    else if( !strcmp(argv[1],"no-ubit") )
    {
        p_ivi_prefix->flag = NO_UBIT;
    }
    else
    {
        free(p_ivi);
        free(p_ivi_prefix);
        vty_out (vty, "%% Malformed ubit%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct ivi_prefix_message);//len

    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_ivi_prefix);
        free(p_ivi);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    ivi_prefix_head = p_ivi_prefix;
    return CMD_SUCCESS;
}
DEFUN(no_ivi_prefix,
      no_ivi_prefix_cmd,
      "no ivi prefix X:X::X:X/M",
      NO_STR
      "configure ivi prefix\n"
      "ivi ipv6 prefix\n"
      "prefix/prefix_length\n"
     )
{
    if(ivi_prefix_head == NULL)
        return CMD_WARNING;
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct ivi_prefix_message *p_ivi_prefix = (struct ivi_prefix_message *)malloc(sizeof(struct ivi_prefix_message));
    memset(p_ivi_prefix,0,sizeof(struct ivi_prefix_message));
    p_ivi->data = p_ivi_prefix;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = DEL_IVI_PREFIX;//type
    //prefix
    ret = str2prefix_ipv6( argv[0],&(p_ivi_prefix->prefix6) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_ivi_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi_prefix->flag = 0;
    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct ivi_prefix_message);//len
    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_ivi_prefix);
        free(p_ivi);
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if( !memcmp( &(ivi_prefix_head->prefix6),&(p_ivi_prefix->prefix6),sizeof(struct prefix_ipv6)) )
    {
        free(ivi_prefix_head);
        ivi_prefix_head = NULL;
    }

    free(p_ivi_prefix);
    free(p_ivi);
    return CMD_SUCCESS;
}
////add by ccc for list
/*
void link_create_head(IVI_MESSAGE *ivi_new,int type)
{
	switch(type)
	{
		case ADD_IVI_POOL:
			ivi_pool_head = ivi_new;
			ivi_pool_head->ivi_next = NULL;
			break;
		case ADD_IVI_PREFIX:
			ivi_prefix_head = ivi_new;
			ivi_prefix_head->ivi_next = NULL;
		default:
			break;
	}

}

void link_insert(IVI_MESSAGE *ivi_new,int type)
{
	IVI_MESSAGE *p = NULL;
	if(type == ADD_IVI_POOL)
	{
		p = ivi_pool_head;
	}
	if(type == ADD_IVI_PREFIX)
	{
		p = ivi_prefix_head;
	}
	if(p != NULL)
	{
		while(p->ivi_next != NULL)
		{
			p = p->ivi_next;
		}
		p->ivi_next = ivi_new;
	}
	;
}

void link_del_prefix(IVI_MESSAGE *ivi_new)
{
	//IVI_MESSAGE *p = NULL;
	//p = ivi_prefix_head;
	if( ( (ivi_new->u_message.pre.prefixlen)==(ivi_prefix_head->u_message.pre.prefixlen) ) && ( !memcmp( (ivi_new->u_message.pre.u.prefix6.s6_addr),(ivi_prefix_head->u_message.pre.u.prefix6.s6_addr),16) ) )
	{
		//p = ivi_prefix_head->ivi_next;
		free(ivi_prefix_head);
		ivi_prefix_head = NULL;
		return;
	}

	else
	{
		IVI_MESSAGE *p_front = p;
		while(p != NULL)
		{
			if( !memcpy( &(ivi_new->u_message.pre.u.prefix6),&(p->u_message.pre.u.prefix6),sizeof(struct in6_addr)) )
			{
				p_front->ivi_next = p->ivi_next;
				free(p);
				//return;
			}
			p_front = p;
			p = p->ivi_next;
		}//end while
	}//end type


}

void link_del_pool(IVI_MESSAGE *ivi_new)
{
	//IVI_MESSAGE *p = NULL;
	//delete ivi_pool info
	//p = ivi_pool_head;
	if( ((ivi_new->u_message.pool.prefixlen)==(ivi_pool_head->u_message.pool.prefixlen)) && ((ivi_new->u_message.pool.u.prefix4.s_addr)==(ivi_pool_head->u_message.pool.u.prefix4.s_addr)) ) //piefixlen && addr
	{
		IVI_MESSAGE *p = ivi_pool_head;
		free(p);

		ivi_pool_head = NULL;
		return;
	}

	else
	{
		IVI_MESSAGE *p_front = p;
		while(p != NULL)
		{
			if( (ivi_new->u_message.pool.u.prefix4.s_addr)==(p->u_message.pool.u.prefix4.s_addr) )
			{
				p_front->ivi_next = p->ivi_next;
				free(p);
				return;
			}
			p_front = p;
			p = p->ivi_next;
		}//end while
	}//end if


}
*/
////add by ccc for ivi_pool
DEFUN(ivi_pool,
      ivi_pool_cmd,
      "ivi pool X:X:X:X/M ",
      "configure ivi pool\n"
      "ivi ipv4 prefix\n"
      "ivi ipv4 prefix length\n"
     )
{
    if(ivi_pool_head != NULL)
    {
        vty_out(vty,"IVI IPv4 pool is alreay exist%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct ivi_pool_message *p_ivi_pool = (struct ivi_pool_message *)malloc(sizeof(struct ivi_pool_message));
    memset(p_ivi_pool,0,sizeof(struct ivi_pool_message));
    p_ivi->data = p_ivi_pool;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = ADD_IVI_POOL;//type
    //prefix
    ret = str2prefix_ipv4( argv[0],&(p_ivi_pool->prefix4) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_ivi_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct ivi_pool_message);//len

    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_ivi_pool);
        free(p_ivi);
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    ivi_pool_head = p_ivi_pool;
    return CMD_SUCCESS;

}
DEFUN(no_ivi_pool,
      no_ivi_pool_cmd,
      "no ivi pool X:X:X:X/M ",
      NO_STR
      "configure ivi pool\n"
      "ivi ipv4 prefix\n"
      "ivi ipv4 prefix length\n"
     )
{
    if(ivi_pool_head == NULL)
        return CMD_WARNING;
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct ivi_pool_message *p_ivi_pool = (struct ivi_pool_message *)malloc(sizeof(struct ivi_pool_message));
    memset(p_ivi_pool,0,sizeof(struct ivi_pool_message));
    p_ivi->data = p_ivi_pool;

    int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = DEL_IVI_POOL;//type
    //prefix
    ret = str2prefix_ipv4( argv[0],&(p_ivi_pool->prefix4) );
    if(ret <= 0)
    {
        free(p_ivi);
        free(p_ivi_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct ivi_pool_message);//len
    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_ivi_pool);
        free(p_ivi);
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if( !memcmp( &(ivi_pool_head->prefix4),&(p_ivi_pool->prefix4),sizeof(struct prefix_ipv4)) )
    {
        free(ivi_pool_head);
        ivi_pool_head = NULL;
    }

    free(p_ivi_pool);
    free(p_ivi);
    return CMD_SUCCESS;
}
struct tunnel_info * link_search(unsigned int tunnel_num)
{
    struct tunnel_info *p = tunnel_head;
    while( p != NULL)
    {
        if(p->tunnel_num == tunnel_num)
        {
            return p;
        }
        p = p->tunnel_next;
    }
    return NULL;
}
int link_create(struct tunnel_info **p,unsigned int tunnel_num)
{
    *p = (struct tunnel_info*)malloc(sizeof(struct tunnel_info));
    bzero(*p,sizeof(struct tunnel_info));
    (*p)->tunnel_num = tunnel_num;
    if (*p == NULL)
        return -1;
    else
    {
        if(tunnel_head ==NULL)
            tunnel_head = *p;
        else
        {
            struct tunnel_info * p_insert = tunnel_head;
            if( (*p)->tunnel_num < tunnel_head->tunnel_num)
            {
                tunnel_head = *p;
                tunnel_head->tunnel_next = p_insert;
            }
            else
            {
                struct tunnel_info *p_front = p_insert;
                while(p_insert != NULL)
                {
                    if((*p)->tunnel_num < p_insert->tunnel_num )
                    {
                        p_front->tunnel_next = (*p);
                        (*p)->tunnel_next = p_insert;
                        break;
                    }
                    p_front = p_insert;
                    p_insert = p_insert->tunnel_next;
                }
                p_front->tunnel_next = (*p);
                (*p)->tunnel_next = NULL;
            }
        }
        return 0;
    }
}
int link_del(unsigned int tunnel_num)
{
    struct tunnel_info *p_tunnel = link_search(tunnel_num);
    if(p_tunnel == NULL)
        return -1;
    else
    {
        struct tunnel_info * p = tunnel_head;
        if( tunnel_num == tunnel_head->tunnel_num)
        {
            if( 0 == check_tunnel(p,DEL_TUNNEL))
            {
                tunnel_head = tunnel_head->tunnel_next;
                free(p);
                return 0;
            }
            return -1;
        }
        else
        {
            struct tunnel_info *p_front = p;
            while(p != NULL)
            {
                if(tunnel_num == p->tunnel_num)
                {

                    p_front->tunnel_next = p->tunnel_next;
                    if(0 == check_tunnel(p,DEL_TUNNEL))
                    {
                        free(p);
                        return 0;
                    }
                    else
                        return -1;
                }
                p_front = p;
                p = p->tunnel_next;
            }//end while
        }//end if

    }
    return 0;
}
DEFUN(interface_tunnel,
      interface_tunnel_cmd,
      "interface tunnel <0-32>",
      "select one interface tunnel to configure \n"
      "configure 4over6 tunnel\n"
      "tunnel number\n"
     )
{

    unsigned int tunnel_num = atoi(argv[0]);
    if( tunnel_num < 0 || tunnel_num > 32)
    {
        vty_out(vty,"tunnel num should be <0-32>");
        return CMD_WARNING;
    }
    struct tunnel_info *p_tunnel = link_search(tunnel_num);
    if(p_tunnel == NULL)
        if (0 < link_create(&p_tunnel,tunnel_num) )
        {
            vty_out(vty,"malloc tunnel_info fail");
            return CMD_WARNING;
        }

    vty->index = p_tunnel;
    vty->node = TUNNEL_NODE;
    //vty_out(vty,"tunnel number is %s%s",argv[0],VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(no_interface_tunnel,
      no_interface_tunnel_cmd,
      "no interface tunnel <0-32>",
      NO_STR
      "select one interface tunnel to configure \n"
      "configure 4over6 tunnel\n"
      "tunnel number\n"
     )
{
    unsigned int tunnel_num = atoi(argv[0]);
    if( tunnel_num < 0 || tunnel_num > 32)
    {
        vty_out(vty,"tunnel num should in <0-32>");
        return CMD_WARNING;
    }

    int	ret =link_del(tunnel_num);
    if(ret < 0)
    {
        vty_out(vty,"no this tunnel");
        return CMD_WARNING;
    }

    //vty_out(vty,"no tunnel number is %s%s",argv[0],VTY_NEWLINE);
    return CMD_SUCCESS;
}

int  check_tunnel(struct tunnel_info * p,int flag)
{
    struct ivi_message p_ivi;
    bzero(&p_ivi,sizeof(struct ivi_message));
    struct in6_addr zero_6;
    bzero(&zero_6,sizeof(struct in6_addr));
    struct in_addr zero_4;
    bzero(&zero_4,sizeof(struct in_addr));

    //if( flag == ADD_TUNNEL)
    {
        if( (memcmp(&(p->tunnel_source),&zero_6,sizeof(struct in6_addr)))&&( memcmp(&(p->tunnel_dest),&zero_6,sizeof(struct in6_addr))) && (memcmp(&(p->ip_prefix.prefix),&zero_4,sizeof(struct in_addr))) )
        {
            if(flag == ADD_TUNNEL)
                p_ivi.type = ADD_TUNNEL;
            else
                p_ivi.type = DEL_TUNNEL;
            p_ivi.len = sizeof(struct ivi_message) + sizeof(struct tunnel_info);
            p_ivi.data = p;
            return ivi_client_connect(&p_ivi,p_ivi.len);
        }
        else
            return 0;
    }

    /*
    else
    {
    	if( (memcmp(&(p->tunnel_source),&zero_6,sizeof(struct in6_addr)))&&( memcmp(&(p->tunnel_dest),&zero_6,sizeof(struct in6_addr))) && (memcmp(&(p->ip_prefix),&zero_4,sizeof(struct prefix_ipv4))) )
    	{
    		p_ivi.type = DEL_TUNNEL;
    		p_ivi.len = sizeof(struct ivi_message) + sizeof(struct tunnel_info);
    		p_ivi.data = p;
    		ivi_client_connect(&p_ivi,p_ivi.len);
    	}
    	if(flag == DEL_TUNNEL_SRC)
    	{
    		bzero(&(p->tunnel_source),sizeof(struct in6_addr));
    	}
    	else if(flag == DEL_TUNNEL_DEST)
    	{
    		bzero(&(p->tunnel_dest),sizeof(struct in6_addr));
    	}
    	else if(flag == DEL_TUNNEL_IP)
    	{
    		bzero(&(p->ip_prefix),sizeof(struct prefix_ipv4));
    	}
    	else
    	{
    		;
    	}
    }//end if
    */
}
DEFUN(tunnel_source,
      tunnel_source_cmd,
      "tunnel source X:X::X:X",
      "configure tunnel\n"
      "configure 4over6 tunnel source address\n"
      "ipv6 address\n"
     )
{
    struct in6_addr prefix;
    bzero(&prefix,sizeof(struct in6_addr));
    if(!strncmp(argv[0],"fe80",4))
    {
        //vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int ret = inet_pton(AF_INET6,argv[0],&prefix);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int count = 0;
    struct tunnel_info *p = vty->index;//get_point();
    //check interface ipv6 address
    struct listnode *node;
    struct interface *ifp;
    if (iflist != NULL)
    {
        for (ALL_LIST_ELEMENTS_RO(iflist,node,ifp))
        {
            struct listnode *addrnode;
            struct connected *ifc;
            struct prefix *p_if_prefix;
            for(ALL_LIST_ELEMENTS_RO(ifp->connected,addrnode,ifc))
            {
                //struct prefix save;
                //bzero(&save,sizeof(struct prefix));
                //save = *p_if_prefix;
                p_if_prefix = ifc->address;
                if(p_if_prefix->family == AF_INET6)
                {
                    //save = *p_if_prefix;
                    if(!memcmp(&(p_if_prefix->u.prefix6),&(prefix),sizeof(struct in6_addr)) )
                        //if(!memcmp(&save.u.prefix6,&(p->tunnel_source),sizeof(struct in6_addr)) )
                        count++;
                }
            }//end for
        }//end for
    }
    else
    {
        vty_out(vty,"interface list is NULL%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(count == 0)
    {
        vty_out(vty,"no interface has this ipv6 address%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    //check end
    struct in6_addr last; //save last source message
    bzero(&last,sizeof(struct in6_addr));
    memcpy(&last,&p->tunnel_source,sizeof(struct in6_addr));

    memcpy(&p->tunnel_source,&prefix,sizeof(struct in6_addr));
    if(0 != check_tunnel(p,ADD_TUNNEL))
    {
        //if connect fail,back to last setting
        memcpy(&p->tunnel_source,&last,sizeof(struct in6_addr));
        vty_out(vty,"connect server fail,tunnel_source%s",VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN(no_tunnel_source,
      no_tunnel_source_cmd,
      "no tunnel source X:X::X:X",
      NO_STR
      "configure tunnel\n"
      "configure source address\n"
      "ipv6 address\n"
     )
{
    struct in6_addr prefix;
    int ret = inet_pton(AF_INET6,argv[0],&prefix);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;//get_point();
    if(!memcmp(&p->tunnel_source,&prefix,sizeof(struct in6_addr)))
    {
        if(	0 == check_tunnel(p,DEL_TUNNEL_SRC))
        {
            bzero(&p->tunnel_source,sizeof(struct in6_addr));
        }
        else
        {
            vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        }
    }
    return CMD_SUCCESS;
}

DEFUN(tunnel_destination,
      tunnel_destination_cmd,
      "tunnel destination X:X::X:X",
      "configure tunnel\n"
      "configure destination address\n"
      "ipv6 address\n"
     )
{
    struct in6_addr prefix;
    int ret = inet_pton(AF_INET6,argv[0],&prefix);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    //check route table
    int count = 0;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (! table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            //vty_show_ipv6_route (vty, rn, rib);
            struct nexthop *nexthop;
            //int len = 0;
            char buf[BUFSIZ];
            for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            {
                if (nexthop == rib->nexthop)
                {
                    if(strcmp("fe80::",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0 &&strcmp("::1",inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ))!=0)
                    {
                        int i = rn->p.prefixlen/8;
                        int j = rn->p.prefixlen % 8;
                        uint8_t k = rn->p.u.prefix6.__in6_u.__u6_addr8[i];
                        uint8_t l = prefix.__in6_u.__u6_addr8[i];
                        //if( ((rn->p.u.prefix6)>>(int)(128-rn->p.prefixlen)) == (((rn->p.u.prefix6)>>(int)(128-rn->p.prefixlen)) & (prefix>>(int)(128->rn->p.prefixlen))) )
                        if(!memcmp(&(rn->p.u.prefix6),&prefix,(rn->p.prefixlen)/8) && ((k>>j) == ( (k>>j)&(l>>j) )) )
                        {
                            count++;
                            break;
                        }
                        //inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ);

                        //vty_out(vty,"address%s len%d%s",buf,rn->p.prefixlen,VTY_NEWLINE);

                    }

                }
            }//end for
        }//end for
    if(count == 0 )
    {
        vty_out(vty,"not match route table%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    //end check
    struct tunnel_info *p = vty->index;//get_point();

    struct in6_addr last; //save last source message
    bzero(&last,sizeof(struct in6_addr));
    memcpy(&last,&p->tunnel_dest,sizeof(struct in6_addr));

    memcpy(&p->tunnel_dest,&prefix,sizeof(struct in6_addr));
    if(0 != check_tunnel(p,ADD_TUNNEL))
    {
        memcpy(&p->tunnel_dest,&last,sizeof(struct in6_addr));
    }
    else
    {
        vty_out(vty,"connect server fail,tunnel_dest%s",VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

DEFUN(no_tunnel_destination,
      no_tunnel_destination_cmd,
      "no tunnel destination X:X::X:X",
      NO_STR
      "configure tunnel\n"
      "configure destination address\n"
      "ipv6 address\n"
     )
{
    struct in6_addr prefix;
    int ret = inet_pton(AF_INET6,argv[0],&prefix);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;//get_point();
    if(!memcmp(&p->tunnel_dest,&prefix,sizeof(struct in6_addr)))
    {
        if(0 == check_tunnel(p,DEL_TUNNEL_DEST))
            bzero(&p->tunnel_dest,sizeof(struct in6_addr));
        else
            vty_out(vty,"connect server fail%s",VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN(tunnel_ip_prefix,
      tunnel_ip_prefix_cmd,
      "ip prefix A.B.C.D/M",
      "configure tunnel ip subnet\n"
      "configure ipv4 prefix\n"
      "ip subnet/length\n"
     )
{
    struct prefix_ipv4 p_ipv4;
    bzero(&p_ipv4,sizeof(struct prefix_ipv4));
    int ret = str2prefix_ipv4(argv[0],&p_ipv4);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;//get_point();
    struct prefix_ipv4 last;
    bzero(&last,sizeof(struct prefix_ipv4));
    memcpy(&last,&(p->ip_prefix),sizeof(struct prefix_ipv4));

    memcpy(&p->ip_prefix,&p_ipv4,sizeof(struct prefix_ipv4));
    if(0 != check_tunnel(p,ADD_TUNNEL))
    {
        memcpy(&p->ip_prefix,&last,sizeof(struct prefix_ipv4));
    }
    else
    {
        vty_out(vty,"connect server fail,ip_prefix%s",VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN(no_tunnel_ip_prefix,
      no_tunnel_ip_prefix_cmd,
      "no ip prefix A.B.C.D/M",
      NO_STR
      "configure tunnel ip subnet\n"
      "configure ipv4 prefix\n"
      "ip subnet/length\n"
     )
{
    struct prefix_ipv4 p_ipv4;
    bzero(&p_ipv4,sizeof(struct prefix_ipv4));
    int ret = str2prefix_ipv4(argv[0],&p_ipv4);
    if(ret < 0)
    {
        vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;//get_point();
    if(!memcmp(&(p->ip_prefix),&p_ipv4,sizeof(struct prefix_ipv4)))
    {
        if(0 == check_tunnel(p,DEL_TUNNEL_IP))
            bzero(&p->ip_prefix,sizeof(struct prefix_ipv4));
        else
        {
            vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        }
    }
    return CMD_SUCCESS;
}
char *myitoa(int num, char *str, int radix)
{
    /* ??? */
    char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned unum;                /* ???? */
    int i = 0, j, k;
    /* ??unum?? */
    if (radix == 10 && num < 0)   /* ????? */
    {
        unum = (unsigned)-num;
        str[i++] = '-';
    }
    else
        unum = (unsigned)num;       /* ???? */
    /* ?? */
    do
    {
        str[i++] = index[unum % (unsigned)radix];
        unum /= radix;
    }
    while (unum);
    str[i] = '\0';
    /* ?? */
    if (str[0] == '-')
        k = 1;                      /* ????? */
    else
        k = 0;
    char temp;
    for (j = k; j <= (i - k - 1) / 2; j++)
    {
        temp = str[j];
        str[j] = str[i - 1 + k - j];
        str[i - j - 1] = temp;
    }
    return str;
}
DEFUN(show_ipv6_tunnel,
      show_ipv6_tunnel_cmd,
      "show ipv6 tunnel",
      SHOW_STR
      "ipv6 info\n"
      "tunnel info\n"
     )
{
    struct tunnel_info *p = tunnel_head;
    vty_out(vty,"%-10s %-20s %-20s %-15s%s","tunnel_num","source","dest","ip_prefix",VTY_NEWLINE);
    while(p != NULL)
    {
        char buf[40] = "";
        vty_out(vty,"%-10s ",myitoa(p->tunnel_num,buf,10));
        bzero(buf,40);
        inet_ntop(AF_INET6,&p->tunnel_source,buf,40);
        vty_out(vty,"%-20s ",buf);
        bzero(buf,40);
        inet_ntop(AF_INET6,&p->tunnel_dest,buf,40);
        vty_out(vty,"%-20s ",buf);
        bzero(buf,40);
        inet_ntop(AF_INET,&(p->ip_prefix.prefix),buf,40);
        vty_out(vty,"%-15s/%-d%s",buf,p->ip_prefix.prefixlen,VTY_NEWLINE);
        p = p->tunnel_next;
    }
    return CMD_SUCCESS;

}


#if 1 //sangmeng add
//sangmeng add for get mib
int connect_dpdk(struct vty *vty)
{
    int fd ;
    int ret = 0;
    struct sockaddr_in socketaddress;

    fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(fd <= 0)
    {
        vty_out(vty,"socket fail%s",VTY_NEWLINE);
        return -1;
    }

    //vty_out (vty, "mib socket create success %s",  VTY_NEWLINE);

    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons(IVI_INET_PORT);
    socketaddress.sin_addr.s_addr = inet_addr(IVI_INET_ADDRESS);
    memset( &(socketaddress.sin_zero), 0, 8 );
    /*start connect*/
    ret = connect(fd,&socketaddress,sizeof(struct sockaddr) );
    if(ret < 0)
    {
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        close(fd);
        return -1;
    }

    return fd;
}
DEFUN(shell_1_geMibFwdRead,
      shell_1_geMibFwdRead_cmd,
      "shell 1 geMibFwdRead",
      "Executive shell command\n"
      "1\n"
      "forward mib\n"
     )
{

    int ret = 0;
    int i, j;
    int mib_sock;
    char buf[4096];
    char get_mib_msg[8];

    mib_sock = connect_dpdk(vty);
    if (mib_sock == -1)
    {
        //vty_out(vty, "connect server failed %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    memset(get_mib_msg, 0, 8);
    *(int *) &get_mib_msg[0] = REQUEST_L3FWD_MIB;
    *(int *) &get_mib_msg[4] = htonl(8);
    ret = send( mib_sock, get_mib_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(mib_sock);
        vty_out(vty,"send get mib message fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(mib_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(mib_sock);
        vty_out(vty,"recv mib from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);


    for (i = 0, j = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_L3FWD_MIB)
        {

            //vty_out(vty,"type %d :%s", *(int *)&buf[i], VTY_NEWLINE);
            memcpy(&l3fwd_stats[j], (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);
            j++;
        }
        //i += ntohl(*(int *)&buf[i+4]);
    }
    /*print l3fwd mib*/
    vty_out(vty, "=*=*=*=*=*=*=*=*=*=*Statistics List=*=*=*=*=*=*=*=*=*=* %s", VTY_NEWLINE);
    for (i = 0; i < j; i++)
    {

#if 0
        vty_out (vty, "\nL3FWD Statistics for port %u ------------------------------" "\nPackets rx_packets: %17" PRIu64 "\nPackets tx_packets: %17" PRIu64 "\nPackets dropped: %20" PRIu64 "\nPackets rx_packets_ipv4: %12" PRIu64 "\nPackets tx_packets_ipv4: %12" PRIu64 "\nPackets dropped_ipv4: %15" PRIu64 "\nPackets rx_packets_ipv6: %12" PRIu64 "\nPackets tx_packets_ipv6: %12" PRIu64 "\nPackets dropped_ipv6: %15" PRIu64 "\nPackets rx_packets_other: %11" PRIu64 "\nPackets tx_packets_other: %11" PRIu64 "\nPackets dropped_other: %14" PRIu64 "\n",
                 l3fwd_stats[i].portid,
                 l3fwd_stats[i].rx_packets,
                 l3fwd_stats[i].tx_packets,
                 l3fwd_stats[i].dropped,
                 l3fwd_stats[i].rx_packets_ipv4,
                 l3fwd_stats[i].tx_packets_ipv4,
                 l3fwd_stats[i].dropped_ipv4,
                 l3fwd_stats[i].rx_packets_ipv6,
                 l3fwd_stats[i].tx_packets_ipv6,
                 l3fwd_stats[i].dropped_ipv6,
                 l3fwd_stats[i].rx_packets_other,
                 l3fwd_stats[i].tx_packets_other,
                 l3fwd_stats[i].dropped_other);
#endif

#if 1
        vty_out(vty, "Pkts Received from port%-12u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets);
        vty_out(vty, "Octets Received from port%-10u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_octets);
        vty_out(vty, "IPV4 Pkts Received from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_ipv4);
        vty_out(vty, "IPV6 Pkts Received from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_ipv6);
        vty_out(vty, "Other Pkts Received from port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_other);
        vty_out(vty, "ARP Pkts Received from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_arp);
        vty_out(vty, "%s", VTY_NEWLINE);
#endif

    }

    for (i = 0; i < j; i++)
    {
        vty_out(vty, "Pkts Dropped from port%-13u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped);
        vty_out(vty, "IPV4 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv4);
        vty_out(vty, "IPV6 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv6);
        vty_out(vty, "ARP Pkts Dropped from port%-9u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_arp);
        vty_out(vty, "NO MAC Pkts Dropped from port%-6u:" "%8" PRIu64 "\n",l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_mac_dropped);
        vty_out(vty, "NO ROUTE Pkts Dropped from port%-4u:" "%8" PRIu64 "\n",l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_route_dropped);
        vty_out(vty, "Other Pkts Dropped from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_other);
        vty_out(vty, "%s", VTY_NEWLINE);
    }

#if 0
    for (i = 0; i < j; i++)
    {

        vty_out(vty, "IPV4 Pkts Dropped from port%u:" "%18" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv4);
        vty_out(vty, "IPV6 Pkts Dropped from port%u:" "%18" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv6);
        vty_out(vty, "%s", VTY_NEWLINE);
    }
#endif

    for (i = 0; i < j; i++)
    {
        vty_out(vty, "Pkts Transmitted to port%-11u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets);
        vty_out(vty, "Octest Transmitted to port%-9u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_octets);
        vty_out(vty, "IPV4 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_ipv4);
        vty_out(vty, "IPV6 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_ipv6);
        vty_out(vty, "ARP Pkts Transmitted to port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_arp);
        vty_out(vty, "NO MAC Pkts Transmitted to port%-4u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_mac_up);
        vty_out(vty, "Other Pkts Transmitted to port%-5u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_other);
        vty_out(vty, "%s", VTY_NEWLINE);
    }



    vty_out(vty, "=*=*=*=*=*=*=*=*=*=*=*=*=*THE END=*=*=*=*=*=*=*=*=*=*=*=*=*");
    close(mib_sock);
    return CMD_SUCCESS;

}

DEFUN(shell_1_geMibKniRead,
      shell_1_geMibKniRead_cmd,
      "shell 1 geMibKniRead",
      "Executive shell command\n"
      "1\n"
      "kni mib\n"
     )
{

    int ret = 0;
    int i, j;
    int mib_sock;
    char buf[4096];
    char get_mib_msg[8];

    mib_sock = connect_dpdk(vty);
    if (mib_sock == -1)
    {
        //vty_out(vty, "connect server failed %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    memset(get_mib_msg, 0, 8);
    *(int *) &get_mib_msg[0] = REQUEST_KNI_MIB;
    *(int *) &get_mib_msg[4] = htonl(8);
    ret = send( mib_sock, get_mib_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(mib_sock);
        vty_out(vty,"send get mib message fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(mib_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(mib_sock);
        vty_out(vty,"recv mib from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);


    for (i = 0, j = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_KNI_MIB)
        {
            memcpy(&kni_stats[j], (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);
            j++;
        }

        //i += ntohl(*(int *)&buf[i+4]);
    }

    vty_out(vty, "=*=*=*=*=*=*=*=*=*=*KNI Statistics List=*=*=*=*=*=*=*=*=*=* %s", VTY_NEWLINE);
    for (i = 0; i < j; i++)
    {
#if 0
        vty_out (vty, "\nKNI Statistics for port %u ------------------------------""\nPackets rx_packets: %17" PRIu64 "\nPackets rx_dropped: %17" PRIu64 "\nPackets tx_packets: %17" PRIu64 "\nPackets tx_dropped: %17" PRIu64 "\nPackets rx_packets_ipv4: %12" PRIu64 "\nPackets rx_dropped_ipv4: %12" PRIu64 "\nPackets tx_packets_ipv4: %12" PRIu64 "\nPackets tx_dropped_ipv4: %12" PRIu64 "\nPackets rx_packets_ipv6: %12" PRIu64 "\nPackets rx_dropped_ipv6: %12" PRIu64 "\nPackets tx_packets_ipv6: %12" PRIu64 "\nPackets tx_dropped_ipv6: %12" PRIu64 "\nPackets rx_packets_arp: %13" PRIu64 "\nPackets rx_dropped_arp: %13" PRIu64 "\nPackets tx_packets_arp: %13" PRIu64 "\nPackets tx_dropped_arp: %13" PRIu64 "\nPackets rx_packets_other: %11" PRIu64 "\nPackets rx_dropped_other: %11" PRIu64 "\nPackets tx_packets_other: %11" PRIu64 "\nPackets tx_dropped_other: %11" PRIu64 "\n",
                 kni_stats[i].portid,
                 kni_stats[i].rx_packets,
                 kni_stats[i].rx_dropped,
                 kni_stats[i].tx_packets,
                 kni_stats[i].tx_dropped,
                 kni_stats[i].rx_packets_ipv4,
                 kni_stats[i].rx_dropped_ipv4,
                 kni_stats[i].tx_packets_ipv4,
                 kni_stats[i].tx_dropped_ipv4,
                 kni_stats[i].rx_packets_ipv6,
                 kni_stats[i].rx_dropped_ipv6,
                 kni_stats[i].tx_packets_ipv6,
                 kni_stats[i].tx_dropped_ipv6,
                 kni_stats[i].rx_packets_arp,
                 kni_stats[i].rx_dropped_arp,
                 kni_stats[i].tx_packets_arp,
                 kni_stats[i].tx_dropped_arp,
                 kni_stats[i].rx_packets_other,
                 kni_stats[i].rx_dropped_other,
                 kni_stats[i].tx_packets_other,
                 kni_stats[i].tx_dropped_other);
#endif

        vty_out(vty, "Pkts Received from port%-12u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_packets);
        vty_out(vty, "IPV4 Pkts Received from port%-7u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_packets_ipv4);
        vty_out(vty, "IPV6 Pkts Received from port%-7u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_packets_ipv6);
        vty_out(vty, "%s", VTY_NEWLINE);

    }
    for (i = 0; i < j; i++)
    {
        vty_out(vty, "Pkts Dropped from port%-13u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_dropped + kni_stats[i].tx_dropped);
        vty_out(vty, "IPV4 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_dropped_ipv4 + kni_stats[i].tx_dropped_ipv4);
        //vty_out(vty, "ARP Pkts Received Dropped from port%u:" "%10" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_dropped_arp);
        vty_out(vty, "IPV6 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_dropped_ipv6 + kni_stats[i].tx_dropped_ipv6);
        vty_out(vty, "%s", VTY_NEWLINE);
    }

    for (i = 0; i < j; i++)
    {
        vty_out(vty, "Pkts Transmitted to port%-11u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].tx_packets);
        vty_out(vty, "IPV4 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].tx_packets_ipv4);
        vty_out(vty, "IPV6 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].tx_packets_ipv6);
        vty_out(vty, "%s", VTY_NEWLINE);
    }
    vty_out(vty, "=*=*=*=*=*=*=*=*=*=*=*=*=*=*THE END=*=*=*=*=*=*=*=*=*=*=*=*=*=*");

    close(mib_sock);
    return CMD_SUCCESS;

}


DEFUN(shell_1_v4RouteRead,
      shell_1_v4RouteRead_cmd,
      "shell 1 v4RouteRead",
      "Executive shell command\n"
      "1\n"
      "ipv4 route table\n"
     )
{

    int i;
    int route_sock;
    int ret = 0;
    char buf[4096];
    char get_route_msg[8];
    char tmp[192];
    struct route_info rtInfo;

    route_sock = connect_dpdk(vty);
    if (route_sock == -1)
    {
        return CMD_WARNING;
    }

    memset(get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = REQUEST_V4_ROUTE_TABLE;
    *(int *) &get_route_msg[4] = htonl(8);
    ret = send( route_sock, get_route_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(route_sock);
        vty_out(vty,"send get ipv4 route table fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(route_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(route_sock);
        vty_out(vty,"recv ipv4 route table from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

#if 1

    vty_out(vty, "IPV4 ROUTE TABLE %s", VTY_NEWLINE);
    vty_out(vty, "Destination     Gateway         Netmask Forward If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_V4_ROUTE_TABLE)
        {
            memset(&rtInfo, 0, sizeof(struct route_info));
            memcpy(&rtInfo, (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);

            memset(tmp, 0, sizeof(tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.dstAddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);
            memset(tmp, 0, sizeof(tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.gateWay, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }
        //i += ntohl(*(int *)&buf[i+4]);
    }

#endif
    close(route_sock);
    return CMD_SUCCESS;

}

DEFUN(shell_1_v6RouteRead,
      shell_1_v6RouteRead_cmd,
      "shell 1 v6RouteRead",
      "Executive shell command\n"
      "1\n"
      "ipv6 route table\n"
     )
{

    int i;
    int route_sock;
    int ret = 0;
    char buf[4096];
    char get_route_msg[8];
    char tmp[192];
    char tmp_2[256];
    struct route_info rtInfo;

    route_sock = connect_dpdk(vty);
    if (route_sock == -1)
    {
        return CMD_WARNING;
    }

    memset(get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = REQUEST_V6_ROUTE_TABLE;
    *(int *) &get_route_msg[4] = htonl(8);
    ret = send( route_sock, get_route_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(route_sock);
        vty_out(vty,"send get ipv6 route table fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(route_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(route_sock);
        vty_out(vty,"recv ipv4 route table from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

#if 1

    vty_out(vty, "IPV6 ROUTE TABLE %s", VTY_NEWLINE);
    vty_out(vty, "Destination                    Next Hop                   Forward If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_V6_ROUTE_TABLE)
        {
            memset(&rtInfo, 0, sizeof(struct route_info));
            memcpy(&rtInfo, (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);

            memset(tmp, 0, sizeof(tmp));
            inet_ntop (rtInfo.af, rtInfo.dstAddr6, tmp, sizeof (tmp));
            memset(tmp_2, 0, sizeof(tmp_2));
            sprintf(tmp_2, "%s/%d", tmp, rtInfo.dstLen);
            vty_out (vty, "%-31s", tmp_2);
            //vty_out (vty, "%-31s", tmp);
            memset(tmp, 0, sizeof(tmp));
            inet_ntop (rtInfo.af, rtInfo.gateWay6, tmp, sizeof (tmp));
            vty_out (vty, "%-27s", tmp);

            vty_out (vty, "%-7u %-2s %s", rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }
        //i += ntohl(*(int *)&buf[i+4]);
    }

#endif
    close(route_sock);
    return CMD_SUCCESS;

}


DEFUN(shell_1_v4ArpRead,
      shell_1_v4ArpRead_cmd,
      "shell 1 v4ArpRead",
      "Executive shell command\n"
      "1\n"
      "ipv4 arp table\n"
     )
{

    int i;
    int arp_sock;
    int ret = 0;
    char buf[4096];
    char get_arp_msg[8];
    char tmp[192];
    char tmp_2[64];
    struct arp_info arpInfo;

    arp_sock = connect_dpdk(vty);
    if (arp_sock == -1)
    {
        return CMD_WARNING;
    }

    memset(get_arp_msg, 0, 8);
    *(int *) &get_arp_msg[0] = REQUEST_V4_ARP_TABLE;
    *(int *) &get_arp_msg[4] = htonl(8);
    ret = send(arp_sock, get_arp_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(arp_sock);
        vty_out(vty,"send get arp table fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(arp_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(arp_sock);
        vty_out(vty,"recv ipv4 arp table from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);


    vty_out(vty, "IPV4 ARP TABLE %s", VTY_NEWLINE);
    vty_out(vty, "Address         HWaddress            If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_V4_ARP_TABLE)
        {
            memset(&arpInfo, 0, sizeof(struct arp_info));
            memcpy(&arpInfo, (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);

            memset(tmp, 0, sizeof(tmp));
            inet_ntop (arpInfo.af, (char *)&arpInfo.dstAddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            memset(tmp_2, 0, sizeof(tmp_2));
            sprintf(tmp_2, "%02X:%02X:%02X:%02X:%02X:%02X", arpInfo.lladdr[0], arpInfo.lladdr[1], arpInfo.lladdr[2], arpInfo.lladdr[3], arpInfo.lladdr[4], arpInfo.lladdr[5]);
            vty_out (vty, "%-21s", tmp_2);

            vty_out (vty, "%-2s %s", arpInfo.ifName, VTY_NEWLINE);
        }
    }

    close(arp_sock);
    return CMD_SUCCESS;
}


DEFUN(shell_1_v6NdRead,
      shell_1_v6NdRead_cmd,
      "shell 1 v6NdRead",
      "Executive shell command\n"
      "1\n"
      "ipv6 neighbour table\n"
     )
{

    int i;
    int nd_sock;
    int ret = 0;
    char buf[4096];
    char get_nd_msg[8];
    char tmp[192];
    char tmp_2[64];
    struct arp_info arpInfo;

    nd_sock = connect_dpdk(vty);
    if (nd_sock == -1)
    {
        return CMD_WARNING;
    }

    memset(get_nd_msg, 0, 8);
    *(int *) &get_nd_msg[0] = REQUEST_V6_ND_TABLE;
    *(int *) &get_nd_msg[4] = htonl(8);
    ret = send(nd_sock, get_nd_msg, 8, 0 );
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        close(nd_sock);
        vty_out(vty,"send get arp table fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv(nd_sock, buf, 4096, 0);

    if (ret < 0)
    {
        close(nd_sock);
        vty_out(vty,"recv ipv4 arp table from server fail%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);


    vty_out(vty, "IPV6 NEIGHBOUR TABLE %s", VTY_NEWLINE);
    vty_out(vty, "Address                        HWaddress            If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl(*(int *)&buf[i+4]))
    {
        if ( *(int *)&buf[i] == RESPONSE_V6_ND_TABLE)
        {
            memset(&arpInfo, 0, sizeof(struct arp_info));
            memcpy(&arpInfo, (char *)&buf[i] + 8, ntohl (*(int *)&buf[i+4]) - 8);

            memset(tmp, 0, sizeof(tmp));
            inet_ntop (arpInfo.af, (char *)&arpInfo.dstAddr6, tmp, sizeof (tmp));
            vty_out (vty, "%-31s", tmp);

            memset(tmp_2, 0, sizeof(tmp_2));
            sprintf(tmp_2, "%02X:%02X:%02X:%02X:%02X:%02X", arpInfo.lladdr[0], arpInfo.lladdr[1], arpInfo.lladdr[2], arpInfo.lladdr[3], arpInfo.lladdr[4], arpInfo.lladdr[5]);
            vty_out (vty, "%-21s", tmp_2);

            vty_out (vty, "%-2s %s", arpInfo.ifName, VTY_NEWLINE);
        }
    }

    close(nd_sock);
    return CMD_SUCCESS;
}



#endif //end sangmeng add

//add by ccc for ecn
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
struct if_red_ecn
{
    char 	inuse;
    struct  tc_red_qopt red_ecn;
};
struct  if_red_ecn red_ecn_opt[4];//red head
//end add
int zebra_ivi_write_config(struct vty *vty, char *ifname)
{
    char pre[40] = "";

    vty_out(vty,"!%s",VTY_NEWLINE);
    /*ivi_prefix*/
    if(ivi_prefix_head != NULL )
    {
        memset(pre,0,40);
        inet_ntop(AF_INET6,&(ivi_prefix_head->prefix6.prefix),pre,40);
        vty_out(vty,"ivi prefix %s/%d ",pre,ivi_prefix_head->prefix6.prefixlen);
        if(ivi_prefix_head->flag == UBIT)
            vty_out(vty,"ubit%s",VTY_NEWLINE);
        else
            vty_out(vty,"no-ubit%s",VTY_NEWLINE);
        vty_out(vty,"!%s",VTY_NEWLINE);
    }
    /*ivi_pool*/
    if(ivi_pool_head !=NULL)
    {
        bzero(pre,40);
        inet_ntop(AF_INET,&(ivi_pool_head->prefix4.prefix),pre,40);
        vty_out(vty,"ivi pool %s/%d%s",pre,ivi_pool_head->prefix4.prefixlen,VTY_NEWLINE);
        vty_out(vty,"!%s",VTY_NEWLINE);
    }
    /*nat_prefix*/
    if(nat_prefix_head != NULL )
    {
        memset(pre,0,40);
        inet_ntop(AF_INET6,&(nat_prefix_head->prefix6.prefix),pre,40);
        vty_out(vty,"nat64 prefix %s/%d ",pre,nat_prefix_head->prefix6.prefixlen);
        if(nat_prefix_head->flag == UBIT)
            vty_out(vty,"ubit%s",VTY_NEWLINE);
        else
            vty_out(vty,"no-ubit%s",VTY_NEWLINE);
    }
    /*nat_pool*/
    if(nat_pool_head !=NULL)
    {
        bzero(pre,40);
        inet_ntop(AF_INET,&(nat_pool_head->prefix4.prefix),pre,40);
        vty_out(vty,"nat64 v4pool %s/%d%s",pre,nat_pool_head->prefix4.prefixlen,VTY_NEWLINE);
        vty_out(vty,"!%s",VTY_NEWLINE);
    }
    /*nat timeout*/
    if(nat_timeout_head != NULL)
    {
        char buf[10]="";
        //if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_TCP)
        {
            vty_out(vty,"nat64 timeout %s %s%s","tcp",myitoa(nat_timeout_head->nat_timeout_tcp,buf,10),VTY_NEWLINE);
            bzero(buf,10);
        }
        //else if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_UDP)
        {
            vty_out(vty,"nat64 timeout %s %s%s","udp",myitoa(nat_timeout_head->nat_timeout_udp,buf,10),VTY_NEWLINE);
            bzero(buf,10);
        }
        //else if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_ICMP)
        {
            vty_out(vty,"nat64 timeout %s %s%s","icmp",myitoa(nat_timeout_head->nat_timeout_icmp,buf,10),VTY_NEWLINE);
            bzero(buf,10);
        }
        //else
        ;

        vty_out(vty,"!%s",VTY_NEWLINE);
    }

    vty_out(vty,"!%s",VTY_NEWLINE);
    int i = 0;
    for(i=0; i<4; i++)
    {
        vty_out(vty,"ecn %d minth %d maxth %d wlog %d plog %d%s",i+1,red_ecn_opt[i].red_ecn.qth_min,red_ecn_opt[i].red_ecn.qth_max,red_ecn_opt[i].red_ecn.Wlog,red_ecn_opt[i].red_ecn.Plog,VTY_NEWLINE);
    }
    vty_out(vty,"!%s",VTY_NEWLINE);
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
            vty_out (vty, "%s"
                     , VTY_NEWLINE);
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
    if(nat_timeout_head == NULL)
    {
        nat_timeout_head = (struct nat_timeout_message*)malloc(sizeof(struct nat_timeout_message));
        //vty_out(vty,"this type is already exist%s",VTY_NEWLINE);
        //return CMD_WARNING;
    }
    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_timeout_message *p_nat_timeout = (struct nat_timeout_message *)malloc(sizeof(struct nat_timeout_message));
    memset(p_nat_timeout,0,sizeof(struct nat_timeout_message));
    p_ivi->data = p_nat_timeout;

    //int ret = 0;
    /*start get info and fill ivi message*/
    p_ivi->type = ADD_NAT64_TIMEOUT;//type

    if( !strcmp(argv[0],"tcp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_TCP;
        p_nat_timeout->nat_timeout_tcp = atoi(argv[1]);
    }
    else if( !strcmp(argv[0],"udp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_UDP;	//flag
        p_nat_timeout->nat_timeout_udp = atoi(argv[1]);
    }
    else if( !strcmp(argv[0],"icmp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_ICMP;	//flag
        p_nat_timeout->nat_timeout_icmp = atoi(argv[1]);
    }
    else
    {
        free(p_ivi);
        free(p_nat_timeout);
        vty_out (vty, "%% Malformed arg%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_timeout_message);//len

    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_timeout);
        free(p_ivi);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if( !strcmp(argv[0],"tcp") )
    {
        nat_timeout_head->nat_timeout_tcp = p_nat_timeout->nat_timeout_tcp;

    }

    if( !strcmp(argv[0],"udp") )
    {
        nat_timeout_head->nat_timeout_udp = p_nat_timeout->nat_timeout_udp;
    }
    if( !strcmp(argv[0],"icmp") )
    {
        nat_timeout_head->nat_timeout_icmp = p_nat_timeout->nat_timeout_icmp;
    }
    free(p_nat_timeout);
    return CMD_SUCCESS;
    /*
         #define TYPE_LEN 10
         #define NAT64_CONFIG_TIMER (SIOCCHGTUNNEL + 12)
     struct ifreq ifr;
         struct nat64_timer{
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
    */


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

    if(nat_timeout_head == NULL)
        return CMD_WARNING;

    struct ivi_message *p_ivi = (struct ivi_message *)malloc(sizeof(struct ivi_message));
    memset(p_ivi,0,sizeof(struct ivi_message));
    struct nat_timeout_message *p_nat_timeout = (struct nat_timeout_message *)malloc(sizeof(struct nat_timeout_message));
    memset(p_nat_timeout,0,sizeof(struct nat_timeout_message));
    if( !strcmp(argv[0],"tcp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_TCP;
    }
    else if( !strcmp(argv[0],"udp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_UDP;
    }
    else if( !strcmp(argv[0],"icmp") )
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_ICMP;
    }
    else
    {
        free(p_nat_timeout);
        free(p_ivi);
        vty_out (vty, "%% Malformed arg%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_ivi->data = p_nat_timeout;
    p_ivi->type = DEL_NAT64_TIMEOUT;//type
    p_ivi->len = sizeof(struct ivi_message) + sizeof(struct nat_timeout_message);//len

    if ( -1 == ivi_client_connect(p_ivi,p_ivi->len) )
    {
        free(p_nat_timeout);
        free(p_ivi);
        vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    if( !strcmp(argv[0],"tcp") )
    {
        nat_timeout_head->nat_timeout_tcp = 0;
    }

    if( !strcmp(argv[0],"udp") )
    {
        nat_timeout_head->nat_timeout_udp = 0;
    }

    if( !strcmp(argv[0],"icmp") )
    {
        nat_timeout_head->nat_timeout_icmp = 0;
    }
    free(p_nat_timeout);
    //free(nat_timeout_head);
    free(p_ivi);
    return CMD_SUCCESS;
    //nat_timeout_head = NULL;
    /*
         #define TYPE_LEN 10
         #define NAT64_DEL_TIMER (SIOCCHGTUNNEL + 13)
     struct ifreq ifr;
         struct nat64_timer{
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
    */
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

    //与dns64进程进行socket通信
}

void dns64_prfix_dns_unset()
{
    memset(&v6prefix,0x0,sizeof(struct prefix));
    v4Dns =0;
    //与dns64进程进行socket通信
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
#if 0
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
#endif
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
#if 0
    zebra_nat64_write_config(vty, "nat64");
    //
#endif
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
    red_ecn_opt[p_num-1].red_ecn.Scell_log = tc_red_eval_idle_damping(sbuf);
    //fill in msg
    tail = NLMSG_TAIL(&req.n);
    addattr_l(&req.n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(&req.n, 1024, TCA_RED_PARMS, &red_ecn_opt[p_num-1].red_ecn, sizeof(struct tc_red_qopt));
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
        printf("idx = %d \n",idx);
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
DEFUN(ecn_politic,
      ecn_politic_cmd,
      "ecn <1-4> minth <0-10000> maxth <0-10000> wlog <0-32> plog <0-32>",
      "set ecn parms\n"
      "ecn politic num\n"
      "set red parms :min threshold value -> bandwidth(Mbps)\n"
      "min threshold value\n"
      "set red parms :max threshold value -> bandwidth(Mbps)\n"
      "max threshold value\n"
      "set red parms :weight value\n"
      "weight value:if you want weight value is 0.5,you should set wlog 1 (weight value = 2^-Wlog)\n"
      "set red parms :probability for mark packet\n"
      "probability value:if you want probability value is 0.5,you should set plog 1 (weight value = 2^-Plog)\n"
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
    if (red_ecn_opt[num-1].inuse != 0)
    {
        vty_out(vty,"this politic is already in use%s",VTY_NEWLINE);
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
    unsigned char wlog = atoi(argv[3]);
    if(wlog<0 || wlog>32)
    {
        vty_out(vty,"wlog should be 0-32%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    unsigned char plog = atoi(argv[4]);
    if(plog<0 || plog>32)
    {
        vty_out(vty,"plog should be 0-32%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    red_ecn_opt[num-1].red_ecn.limit = 125*1024*1024;
    red_ecn_opt[num-1].red_ecn.qth_min = minth;//(<<17)==(1024*1024/8)
    red_ecn_opt[num-1].red_ecn.qth_max = maxth;
    red_ecn_opt[num-1].red_ecn.Wlog = wlog;
    red_ecn_opt[num-1].red_ecn.Plog = plog;
    red_ecn_opt[num-1].red_ecn.flags |= TC_RED_ECN;
    vty_out(vty,"parms is min:%d max:%d wlog:%d plog:%d %s",red_ecn_opt[num-1].red_ecn.qth_min,red_ecn_opt[num-1].red_ecn.qth_max,red_ecn_opt[num-1].red_ecn.Wlog,red_ecn_opt[num-1].red_ecn.Plog,VTY_NEWLINE);
    return CMD_SUCCESS;

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




    return CMD_SUCCESS;
}
DEFUN(ecn_enable,
      ecn_enable_cmd,
      "ecn IFNAME politic <1-4>",
      "enable ecn\n"
      "enable interface name\n"
      "ecn politic\n"
      "ecn politic num\n")
{
    struct interface *ifp;
    ifp = if_lookup_by_name (argv[0]);
    if (ifp == NULL)
    {
        vty_out (vty, "No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int num = atoi(argv[1]);
    if( num < 1 || num > 4)
    {
        vty_out(vty,"ecn politic num should be <1-4>");
        return CMD_WARNING;
    }
    if(start_rt_talk(REPLACE,argv[0],num) < 0)
    {
        vty_out(vty,"cannot enable rtlink%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    red_ecn_opt[num-1].inuse++;
    return CMD_SUCCESS;
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
        vty_out(vty,"cannot enable rtlink%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(red_ecn_opt[num-1].inuse!=0)
        red_ecn_opt[num-1].inuse--;
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
//add by ccc for tunnel
static int tunnel_config_write(struct vty *vty)
{
    struct tunnel_info * p = tunnel_head;
    char buf[40] = "";
    //struct ivi_message *test = (struct ivi_message*)malloc(sizeof(struct ivi_message));
    //bzero(test,sizeof(struct ivi_message));
    //if(0 == ivi_client_connect(test,sizeof(struct ivi_message)))
    {
        while(p != NULL)
        {
            bzero(buf,40);
            vty_out(vty,"interface tunnel %d%s",p->tunnel_num,VTY_NEWLINE);
            inet_ntop(AF_INET6,&(p->tunnel_source),buf,40);
            vty_out(vty," tunnel source %s%s",buf,VTY_NEWLINE);
            bzero(buf,40);
            inet_ntop(AF_INET6,&(p->tunnel_dest),buf,40);
            vty_out(vty," tunnel destination %s%s",buf,VTY_NEWLINE);
            bzero(buf,40);
            inet_ntop(AF_INET,&(p->ip_prefix.prefix),buf,40);
            vty_out(vty," ip prefix %s/%d%s",buf,p->ip_prefix.prefixlen,VTY_NEWLINE);

            p = p->tunnel_next;
        }
        vty_out(vty,"!%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //else
    //{
    //vty_out(vty,"connect server fail,config write%s",VTY_NEWLINE);
    //	return CMD_WARNING;
    //}
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
//add by ccc for tunnel
struct cmd_node tunnel_node =
{
    TUNNEL_NODE,
    "%s(config-tunnel)# ",
    1
};

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
    //add by ccc for ecn
    install_element (CONFIG_NODE, &ecn_enable_cmd);
    install_element (CONFIG_NODE, &no_ecn_enable_cmd);
    install_element (CONFIG_NODE, &ecn_politic_cmd);
    install_element (VIEW_NODE , &show_qdisc_cmd);
    install_element (ENABLE_NODE,&show_qdisc_cmd);

#if 1  //add by myj in 2016.12.23
    install_element (CONFIG_NODE, &header_compression_interface_enable_cmd);
    install_element (CONFIG_NODE, &no_header_compression_interface_enable_cmd);
#endif

    //add end
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
    ////add by ccc for cmd
    install_element (CONFIG_NODE, &ivi_pool_cmd);
    install_element (CONFIG_NODE, &no_ivi_pool_cmd);
    install_element (VIEW_NODE, &show_ipv6_tunnel_cmd);
    install_element (ENABLE_NODE, &show_ipv6_tunnel_cmd);

//sangmeng add for get mib
    install_element (VIEW_NODE, &shell_1_geMibFwdRead_cmd);
    install_element (ENABLE_NODE, &shell_1_geMibFwdRead_cmd);
    install_element (VIEW_NODE, &shell_1_geMibKniRead_cmd);
    install_element (ENABLE_NODE, &shell_1_geMibKniRead_cmd);
//sangmeng add for get v4&v6 route
    install_element (VIEW_NODE, &shell_1_v4RouteRead_cmd);
    install_element (ENABLE_NODE, &shell_1_v4RouteRead_cmd);
    install_element (VIEW_NODE, &shell_1_v6RouteRead_cmd);
    install_element (ENABLE_NODE, &shell_1_v6RouteRead_cmd);
//sangmeng add for get arp&nd
    install_element (VIEW_NODE, &shell_1_v4ArpRead_cmd);
    install_element (ENABLE_NODE, &shell_1_v4ArpRead_cmd);
    install_element (VIEW_NODE, &shell_1_v6NdRead_cmd);
    install_element (ENABLE_NODE, &shell_1_v6NdRead_cmd);


    install_node(&tunnel_node,tunnel_config_write);
    install_default(TUNNEL_NODE);
    //install_node(&tunnel_node,tunnel_config_write);

    install_element(CONFIG_NODE,&interface_tunnel_cmd);
    install_element(CONFIG_NODE, &no_interface_tunnel_cmd);
    install_element (TUNNEL_NODE, &tunnel_source_cmd);
    install_element (TUNNEL_NODE, &tunnel_destination_cmd);
    install_element (TUNNEL_NODE, &tunnel_ip_prefix_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_source_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_destination_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_ip_prefix_cmd);
    ////add end
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
        printf("idx = %d \n",idx);
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
