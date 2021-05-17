/*
 * Route filtering function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _ZEBRA_FILTER_H
#define _ZEBRA_FILTER_H
#include <zebra.h>
#include "command.h"
#include "if.h"
#define HAVE_SEQUENCE
#define HAVE_ICMP
#define HAVE_TCP
#define HAVE_UDP

/* Filter type is made by `permit', `deny' and `dynamic'. */
enum filter_type
{
    FILTER_DENY,
    FILTER_PERMIT,
    FILTER_DYNAMIC
};

enum access_type
{
    ACCESS_TYPE_STRING,
    ACCESS_TYPE_NUMBER
};

/* Access list */
struct access_list
{
    char *name;
    char *remark;

    struct access_master *master;

    enum access_type type;

    struct access_list *next;
    struct access_list *prev;

    struct filter *head;
    struct filter *tail;
    int ipv4_filter_count;
    int ipv6_filter_count;
};

/*iptables list*/
#if 1
char filter_name[16];           //sangmeng add for ipv4 acl name

char ipv6_filter_name[16];      //sangmeng add for ipv6 acl name

/*
* sangmeng add for interface list
*iptables_name_list_list
* use_rule_name
*/
struct rule_name_ipv4
{
    char name_in[16];
    char name_out[16];
};

struct rule_name_ipv6
{
    char name_in[16];
    char name_out[16];
};

/*sangmeng add for iptables interface list*/
//接口和规则名字对应的链表
struct iptables_interface_list
{
    char ifp_name[64];
    struct rule_name_ipv4 rname_ipv4;
    struct rule_name_ipv6 rname_ipv6;
    struct iptables_interface_list *next;
    struct iptables_interface_list *prev;
};

//链表头
struct iptables_name_list_list
{
    struct iptables_interface_list *head;
    struct iptables_interface_list *tail;
};

struct iptables_name_list_list ilist;

#if 1                           //sangmeng move

/* List of access_list. */
struct access_list_list
{
    struct access_list *head;
    struct access_list *tail;
};

/*ssangmeng add for list of iptables_list*/
struct iptables_list_list
{
    struct iptables_list *head;
    struct iptables_list *tail;
};

/* Master structure of access_list. */
struct access_master
{
    /* List of access_list which name is number. */
    struct access_list_list num;

    /* List of access_list which name is string. */
    struct access_list_list str;

    /* Hook function which is executed when new access_list is added. */
    void (*add_hook) (struct access_list *);

    /* Hook function which is executed when access_list is deleted. */
    void (*delete_hook) (struct access_list *);
};
#endif                          //end move
#if 1                           //sangmeng add for filter

extern int
filter_delete_from_interface(struct vty *, struct interface *,
                             const char *, const char *, afi_t);
extern int
filter_add_to_interface(struct vty *vty, struct interface *ifp,
                        const char *name, const char *rule, afi_t afi);
extern void delete_iptables_from_kernel(struct vty *vty,
                                        const char *name_str, afi_t afi);
extern struct access_list *access_list_lookup(afi_t afi, const char *name);

extern void access_list_delete(struct access_list *access);

extern struct access_list *access_list_get(struct vty *vty, afi_t afi,
        const char *name);

extern int config_write_access_ipv4(struct vty *vty);

extern int config_write_access_ipv6(struct vty *vty);

void filter_name_get(struct vty *vty, const char *name_str,
                     const char *num_str, afi_t afi);

extern int
vty_access_list_remark_unset(struct vty *vty, afi_t afi, const char *name);
extern int
filter_set_zebra(struct vty *vty, const char *name_str,
                 const char *type_str, const char *src_prefix_str,
                 const char *dst_prefix_str, const char *protocol, int set,
                 const char *num_str);

extern int
filter_set_cisco(struct vty *vty, const char *name_str,
                 const char *type_str, const char *addr_str,
                 const char *addr_mask_str, const char *mask_str,
                 const char *mask_mask_str, const char *protocol,
                 int set, const char *num_str);
extern int
filter_set_icmp(struct vty *vty, const char *name_str,
                const char *type_str, const char *addr_str,
                const char *addr_mask_str, const char *mask_str,
                const char *mask_mask_str, const char *protocol,
                int set, const char *num_str, const char *icmp_type,
                const char *icmp_code);

extern int
filter_set_tcp_udp(struct vty *vty, const char *name_str,
                   const char *type_str, const char *addr_str,
                   const char *addr_mask_str, const char *mask_str,
                   const char *mask_mask_str, const char *protocol,
                   int set, const char *num_str, const char *sport_type,
                   const char *sport, const char *dport_type,
                   const char *dport, const char *sport_rang,
                   const char *dport_rang);
extern int
filter_set_icmp_ipv6(struct vty *vty, const char *name_str,
                     const char *type_str, const char *src_prefix_str,
                     const char *dst_prefix_str, const char *protocol,
                     int set, const char *num_str, const char *icmp_type,
                     const char *icmp_code);
extern int filter_set_tcp_udp_ipv6(struct vty *vty, const char *name_str,
                                   const char *type_str,
                                   const char *src_prefix_str,
                                   const char *dst_prefix_str,
                                   const char *protocol, int set,
                                   const char *num_str,
                                   const char *sport_type,
                                   const char *sport,
                                   const char *dport_type,
                                   const char *dport,
                                   const char *sport_rang,
                                   const char *dport_rang);

#endif

#endif

/* Prototypes for access-list. */
extern void access_list_init (void);
extern void access_list_reset (void);
extern void access_list_add_hook (void (*func)(struct access_list *));
extern void access_list_delete_hook (void (*func)(struct access_list *));
extern struct access_list *access_list_lookup (afi_t, const char *);
extern enum filter_type access_list_apply (struct access_list *, void *);

#endif /* _ZEBRA_FILTER_H */
