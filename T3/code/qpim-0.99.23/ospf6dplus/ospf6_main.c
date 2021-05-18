/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
#include <lib/version.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "if.h"
#include "filter.h"
#include "prefix.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"

#include "ospf6d.h"
#include "ospf6_top.h"
#include "ospf6_message.h"
#include "ospf6_asbr.h"
#include "ospf6_lsa.h"
#include "ospf6_area.h"

#include "ospf6_interface.h"
#include "ospf6_zebra.h"
#include "ospf6_neighbor.h"
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

/* Default configuration file name for ospf6d. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

stl_link_list stl_link_head = NULL;
/* ospf6d privileges */
zebra_capabilities_t _caps_p [] =
{
    ZCAP_NET_RAW,
    ZCAP_BIND
};

struct zebra_privs_t ospf6d_privs =
{
#if defined(QUAGGA_USER)
    .user = QUAGGA_USER,
#endif
#if defined QUAGGA_GROUP
    .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
    .vty_group = VTY_GROUP,
#endif
    .caps_p = _caps_p,
    .cap_num_p = 2,
    .cap_num_i = 0
};

/* ospf6d options, we use GNU getopt library. */
struct option longopts[] =
{
    { "daemon",      no_argument,       NULL, 'd'},
    { "config_file", required_argument, NULL, 'f'},
    { "pid_file",    required_argument, NULL, 'i'},
    { "socket",      required_argument, NULL, 'z'},
    { "vty_addr",    required_argument, NULL, 'A'},
    { "vty_port",    required_argument, NULL, 'P'},
    { "user",        required_argument, NULL, 'u'},
    { "group",       required_argument, NULL, 'g'},
    { "version",     no_argument,       NULL, 'v'},
    { "dryrun",      no_argument,       NULL, 'C'},
    { "help",        no_argument,       NULL, 'h'},
    { 0 }
};

/* Configuration file and directory. */
char config_default[] = SYSCONFDIR OSPF6_DEFAULT_CONFIG;

/* ospf6d program name. */
char *progname;

/* is daemon? */
int daemon_mode = 0;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_OSPF6D_PID;

/* Help information display. */
static void
usage (char *progname, int status)
{
    if (status != 0)
        fprintf (stderr, "Try `%s --help' for more information.\n", progname);
    else
    {
        printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages OSPF version 3.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-C, --dryrun       Check configuration for validity and exit\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

    exit (status);
}

static void __attribute__ ((noreturn))
ospf6_exit (int status)
{
    struct listnode *node;
    struct interface *ifp;

    if (ospf6)
        ospf6_delete (ospf6);

    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
        if (ifp->info != NULL)
            ospf6_interface_delete(ifp->info);

    ospf6_message_terminate ();
    ospf6_asbr_terminate ();
    ospf6_lsa_terminate ();

    if_terminate ();
    vty_terminate ();
    cmd_terminate ();

    if (zclient)
        zclient_free (zclient);

    if (master)
        thread_master_free (master);

    if (zlog_default)
        closezlog (zlog_default);

    exit (status);
}

/* SIGHUP handler. */
static void
sighup (void)
{
    zlog_info ("SIGHUP received");
}

/* SIGINT handler. */
static void
sigint (void)
{
    zlog_notice ("Terminating on signal SIGINT");
    ospf6_exit (0);
}

/* SIGTERM handler. */
static void
sigterm (void)
{
    zlog_notice ("Terminating on signal SIGTERM");
    ospf6_clean();
    ospf6_exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
    zlog_info ("SIGUSR1 received");
    zlog_rotate (NULL);
}

struct quagga_signal_t ospf6_signals[] =
{
    {
        .signal = SIGHUP,
        .handler = &sighup,
    },
    {
        .signal = SIGINT,
        .handler = &sigint,
    },
    {
        .signal = SIGTERM,
        .handler = &sigterm,
    },
    {
        .signal = SIGUSR1,
        .handler = &sigusr1,
    },
};

static int create_pthread (void *(*start_routine) (void *), void *arg, int stacksize, pthread_t * ptid)
{
    int code;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init (&attr);

    pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize (&attr, stacksize);
    if ((code = pthread_create (&tid, &attr, start_routine, arg)) != 0)
    {
        zlog_err ("Create new thread failed: %s\n", strerror (code));
        // FIXME: How to do? retry some times.
        return -1;
    }
    else
    {
        *ptid = tid;
        zlog_debug ("[%d]New thread %lu created.\n", getpid (), tid);
    }
    pthread_attr_destroy (&attr);

    return code;
}

#if 1
static struct ospf6_neighbor *ospf6_neighbor_lookup_by_ipv6_address (struct in6_addr *ipv6_address, struct ospf6_interface *oi)
{
    struct listnode *n;
    struct ospf6_neighbor *on;

    for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, n, on))
        if (!memcmp (&on->linklocal_addr, ipv6_address, sizeof (struct in6_addr)))
            return on;

    return (struct ospf6_neighbor *) NULL;
}
#endif
#define INTERFACE_NUM 24
static void update_neighbor_period (struct in6_addr *ipv6_addr)
{
    struct ospf6_neighbor *on;
    struct ospf6_interface *oi;
    unsigned int ifindex_array[INTERFACE_NUM];
    int i = 0, j, k;
    for (k = 0; k < INTERFACE_NUM; k++)
        ifindex_array[k] = 0;

    unsigned int ifindex = 0;

    struct ifaddrs *ifa = NULL, *ifList;
    if (getifaddrs (&ifList) < 0)
        return;
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!strcmp (ifa->ifa_name, "lo"))
            continue;

        if ((!strcmp (ifa->ifa_name, "ivi")) || (!strcmp(ifa->ifa_name, "nat64")) || (!strncmp(ifa->ifa_name, "ip6tnl", 6)))
            continue;

        ifindex = if_nametoindex (ifa->ifa_name);

        for (j = 0; j < INTERFACE_NUM; j++)
        {
            if (ifindex_array[j] == ifindex)
                break;

        }
        if (j == INTERFACE_NUM)
        {
            ifindex_array[i] = ifindex;
            i++;
#ifdef OSPF6_DEBUG
            zlog_debug ("\n interfaceName: %s, ifindex:%d\n", ifa->ifa_name, ifindex);
#endif
            oi = ospf6_interface_lookup_by_ifindex (ifindex);
            if (oi == NULL || oi->area == NULL)
            {
#ifdef OSPF6_DEBUG
                zlog_debug ("the interface:%s is disabled, contiune", ifa->ifa_name);
#endif
                continue;
            }
            on = ospf6_neighbor_lookup_by_ipv6_address (ipv6_addr, oi);
            if (on == NULL)
            {
#ifdef OSPF6_DEBUG
                zlog_debug ("the neighbor don't exist on %s, coutinue", ifa->ifa_name);
#endif
                continue;
            }
            else
            {
                THREAD_OFF (on->connection_period_timer);
                THREAD_OFF (on->circle_period_timer);
                on->connection_period_timer_state = 0;
                on->first_hello_state = 0;
#ifdef OSPF6_DEBUG
                zlog_debug ("find the neighbor on the interface:%s, on->first_hello_state is:%d\n", ifa->ifa_name, on->first_hello_state);
#endif
                break;
            }
        }
    }
    freeifaddrs (ifList);
    return;
}

static int check_stl_num_in_list (struct statellite_period *period)
{
    char ipv6_address_string[128];
    stl_link_list p;

    p = stl_link_head;
    while (p)
    {
#if 0
        memset (ipv6_address_string, 0, sizeof (ipv6_address_string));
        inet_ntop (AF_INET6, &p->stl_msg_all.neighbor_ipv6_address, ipv6_address_string, sizeof (ipv6_address_string));
        zlog_debug ("p>>>>>>>neighbor_ipv6_address:%s", ipv6_address_string);

        zlog_debug ("period>>>>>>>fe80:%s", period->fe80);
#endif

        //if (!memcmp (&p->stl_msg_all.neighbor_ipv6_address, &stl_msg_all->neighbor_ipv6_address, sizeof (struct in6_addr)))
        if (p->stl_msg_all.stl_num == ntohs(period->stl_num))
        {

            p->stl_msg_all.circle_period = period->circle_period;
            inet_pton(AF_INET6, period->fe80, p->stl_msg_all.neighbor_ipv6_address.s6_addr);

            memset (ipv6_address_string, 0, sizeof (ipv6_address_string));
            inet_ntop (AF_INET6, &p->stl_msg_all.neighbor_ipv6_address, ipv6_address_string, sizeof (ipv6_address_string));
            zlog_debug ("[%d]The neighbor ipv6 address:%s already exist in list", __LINE__, ipv6_address_string);
            return 1;
        }
        p = p->next;
    }

    return 0;
}
static void insert_orbital_period_msg_to_list(struct statellite_period *period)
{

    //first: check the msg is exist in list
    if (check_stl_num_in_list (period))
        return;

    //insert into list
    stl_link_list p;
    p = (stl_link_list) malloc (sizeof (struct statellite_predict_list));
    if (p == NULL)
    {
        zlog_err ("%s\n", "malloc for statellite node failed");
        return;
    }
    memset (p, 0, sizeof (struct statellite_predict_list));
    p->stl_msg_all.stl_num = ntohs(period->stl_num);
    p->stl_msg_all.circle_period = period->circle_period;
    inet_pton(AF_INET6, period->fe80, p->stl_msg_all.neighbor_ipv6_address.s6_addr);

    p->next = stl_link_head;
    stl_link_head = p;

    //FIXME: update neighbor table
    //update_neighbor_period (&stl_msg_all->neighbor_ipv6_address, stl_msg_all->connection_period, stl_msg_all->circle_period);

    return;
}

static int insert_connection_period_msg_to_list (struct statellite_msg *recv_info)
{
    stl_link_list p;
    char ipv6_address_string[128];

    p = stl_link_head;
    while (p)
    {
        //printf("p->stl_msg_all.stl_num:%d recv_info->stl_num:%d\n", p->stl_msg_all.stl_num, ntohs(recv_info->stl_num));
        if (p->stl_msg_all.stl_num == ntohs(recv_info->stl_num))
        {
            if ((p->stl_msg_all.connection_period != recv_info->connection_period) || (p->stl_msg_all.start_time != recv_info->start_time)
                    ||(p->stl_msg_all.end_time != recv_info->end_time))
            {

                zlog_debug("update start time, end time, connection period");
                /*fill statellite info */
                p->stl_msg_all.start_time = recv_info->start_time;
                p->stl_msg_all.end_time = recv_info->end_time;
                p->stl_msg_all.connection_period = recv_info->connection_period;
                update_neighbor_period (&p->stl_msg_all.neighbor_ipv6_address);
                zlog_debug("start time or end time or connection period don't same  in p, update p, now st:%f et:%f ct:%f", p->stl_msg_all.start_time, p->stl_msg_all.end_time, p->stl_msg_all.connection_period);
            }

            memset (ipv6_address_string, 0, sizeof (ipv6_address_string));
            inet_ntop (AF_INET6, &p->stl_msg_all.neighbor_ipv6_address, ipv6_address_string, sizeof (ipv6_address_string));
            zlog_debug ("The neighbor ipv6 address:%s already exist in list", ipv6_address_string);
            return 1;
        }
        p = p->next;
    }

    return 0;
}
#if 0  /*sangmeng*/
static int process_statellite_message (char *recv_buf)
{
    int total_msg_len;
    int msg_len;
    char neighbor_ipv6_address_string[128];

    struct comm_head *commhead = (struct comm_head *) recv_buf;

    total_msg_len = ntohs (commhead->len) - sizeof (struct comm_head);

    for (msg_len = 0; msg_len < total_msg_len;)
    {
        struct msg_head *msghead = (struct msg_head *) (commhead->data + msg_len);

        struct statellite_msg_all *stl_msg_all = (struct statellite_msg_all *) (msghead->data);
#ifdef OSPF6_DEBUG
        zlog_debug ("\nrecv statellite msg head len:%d ", ntohs (msghead->len));
#endif
        memset (neighbor_ipv6_address_string, 0, sizeof (neighbor_ipv6_address_string));
        inet_ntop (AF_INET6, &(stl_msg_all->neighbor_ipv6_address), neighbor_ipv6_address_string, sizeof (neighbor_ipv6_address_string));
#ifdef OSPF6_DEBUG
        zlog_debug ("neighbor ipv6 address:%s statellite connection period:%f circel period:%f\n", neighbor_ipv6_address_string, stl_msg_all->connection_period, stl_msg_all->circle_period);
#endif

        insert_stl_msg_all_to_list (stl_msg_all);
        msg_len += ntohs (msghead->len);
    }

    return 0;
}
#endif /*end sangmeng*/
#if 1 /*wlk code*/
#define STRSIZE		40

static inline void recv_local (void)
{
    uint16_t i;
    int listen_sockfd;
    int new_connect_sockfd;
    struct sockaddr_in6 local_addr, raddr;
    socklen_t raddr_len;
    char ipstr[STRSIZE];
    char info[BUFSIZE];
    struct comm_head *commhead;
    struct msg_head *msghead;
    struct statellite_msg *recv_info[10];
    struct statellite_period *period[10];

    raddr_len = sizeof (raddr);
    listen_sockfd = socket (AF_INET6, SOCK_STREAM, 0);
    printf ("listen_sockfd=%d\n", listen_sockfd);
    if (listen_sockfd < 0)
    {
        perror ("socket()");
        exit(1) ;
    }

    /* This is a server, so reuse address and port */
    sockopt_reuseaddr (listen_sockfd);
    sockopt_reuseport (listen_sockfd);

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons (atoi (LOCALPORT));
    local_addr.sin6_addr = in6addr_any;

    if (bind (listen_sockfd, (void *) &local_addr, sizeof (local_addr)) < 0)
    {
        perror ("bind()");
        return;
    }

    if (listen (listen_sockfd, 200) < 0)
    {
        perror ("listen()");
        return;
    }
    while (1)
    {
        printf ("waiting..\n");
        new_connect_sockfd = accept (listen_sockfd, (void *) &raddr, &raddr_len);
        if (new_connect_sockfd < 0)
        {
            perror ("accept()");
            continue;
        }
        inet_ntop (AF_INET6, &raddr.sin6_addr, ipstr, STRSIZE);
        printf ("Client connect:%s:%d\n", ipstr, ntohs (raddr.sin6_port));

        memset (info, 0x00, sizeof (info));
        if (recv (new_connect_sockfd, info, BUFSIZE, 0) < 0)
        {
            fprintf (stderr, "recv failed %s\n", strerror (errno));
        }

        commhead = (struct comm_head *) info;
        printf("sizeof(comm_head)=%lu\n",sizeof(struct comm_head));
        printf("sizeof(msg_head)=%lu\n",sizeof(struct msg_head));

        msghead = (struct msg_head *) (commhead->data);
        printf ("msghead->chrType=%d\n", msghead->chrType);
        printf("msghead->len=%d\n",msghead->len);
        printf("msghead->len ntohs=%d\n",ntohs(msghead->len));
        if (msghead->chrType == 0x04)
        {
            for (i = 0; i < ntohs(msghead->len) / sizeof (struct statellite_msg); i++)
            {
                recv_info[i] = (struct statellite_msg *) (msghead->data + (sizeof (struct statellite_msg) * i));

#if 1
                printf ("recv[%d].stl_num=%d\n", i, ntohs(recv_info[i]->stl_num));
                printf ("recv[%d]_info.start_time=%f\n", i, recv_info[i]->start_time);
                printf ("recv[%d]_info.end_time=%f\n", i, recv_info[i]->end_time);
                printf ("recv[%d]_info.connection_period=%f\n", i, recv_info[i]->connection_period);
#endif
                //sangmeng add
                insert_connection_period_msg_to_list (recv_info[i]);
            }
        }
        else if (msghead->chrType == 0x05)
        {
            printf("sizeofstatellite_period=%lu\n",sizeof(struct statellite_period));

            for (i = 0; i < ntohs(msghead->len) / sizeof (struct statellite_period); i++)
            {
                period[i] = (struct statellite_period *) (msghead->data + (sizeof (struct statellite_period) * i));
#if 1
                printf ("period[%d]->stl_num=%d\n", i, ntohs(period[i]->stl_num));
                printf ("period[%d]->circle_period=%f\n", i, period[i]->circle_period);
                printf ("period[%d]->fe80=%s\n", i, period[i]->fe80);
#endif
                //add
                insert_orbital_period_msg_to_list (period[i]);
            }
        }
        close (new_connect_sockfd);
    }
}
#endif /* end wlk */

static void *recv_statellite_message (void *arg)
{

    recv_local ();

    pthread_exit ((void *) 0);
}

static int thread_statellite_create (void)
{
    int code;
    pthread_t tid;
    int thread_stack_size;
    thread_stack_size = 1024 * 1024;
    if ((code = create_pthread (recv_statellite_message, NULL, thread_stack_size, &tid)) != 0)
    {
        zlog_err ("%s\n", "create pthread error");
        return -1;
    }
    return 0;
}
static void ospf6_create_iflist(void)
{
    size_t sl;
    struct ifaddrs *ifa = NULL, *ifList;
    if (getifaddrs (&ifList) < 0)
        return;
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if ((sl = strlen(ifa->ifa_name)) > INTERFACE_NAMSIZ)
            continue;

        if_get_by_name_len(ifa->ifa_name, sl);
    }

    freeifaddrs (ifList);
}
/* Main routine of ospf6d. Treatment of argument and starting ospf finite
   state machine is handled here. */
int main (int argc, char *argv[], char *envp[])
{
    char *p;
    int opt;
    char *vty_addr = NULL;
    int vty_port = 0;
    char *config_file = NULL;
    struct thread thread;
    int dryrun = 0;

    /* Set umask before anything for security */
    umask (0027);

    int i;
    for (i = 0; i < MAXINTERFACENUM; i++)
        memset(&ostats[i], 0x00, sizeof(struct ospf6_packet_stats));

    /* Preserve name of myself. */
    progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    /* Command line argument treatment. */
    while (1)
    {
        opt = getopt_long (argc, argv, "df:i:z:hp:A:P:u:g:vC", longopts, 0);

        if (opt == EOF)
            break;

        switch (opt)
        {
        case 0:
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 'f':
            config_file = optarg;
            break;
        case 'A':
            vty_addr = optarg;
            break;
        case 'i':
            pid_file = optarg;
            break;
        case 'z':
            zclient_serv_path_set (optarg);
            break;
        case 'P':
            /* Deal with atoi() returning 0 on failure, and ospf6d not
                listening on ospf6d port... */
            if (strcmp(optarg, "0") == 0)
            {
                vty_port = 0;
                break;
            }
            vty_port = atoi (optarg);
            if (vty_port <= 0 || vty_port > 0xffff)
                vty_port = OSPF6_VTY_PORT;
            break;
        case 'u':
            ospf6d_privs.user = optarg;
            break;
        case 'g':
            ospf6d_privs.group = optarg;
            break;
        case 'v':
            print_version (progname);
            exit (0);
            break;
        case 'C':
            dryrun = 1;
            break;
        case 'h':
            usage (progname, 0);
            break;
        default:
            usage (progname, 1);
            break;
        }
    }

    if (geteuid () != 0)
    {
        errno = EPERM;
        perror (progname);
        exit (1);
    }

    /* thread master */
    master = thread_master_create ();

    /* Initializations. */
    zlog_default = openzlog (progname, ZLOG_OSPF6,
                             LOG_CONS|LOG_NDELAY|LOG_PID,
                             LOG_DAEMON);
    zprivs_init (&ospf6d_privs);
    /* initialize zebra libraries */
    signal_init (master, array_size(ospf6_signals), ospf6_signals);
    cmd_init (1);
    vty_init (master);
    memory_init ();
    if_init ();
    ospf6_create_iflist();
    //0.99.21 del
    access_list_init ();
    prefix_list_init ();

    /* initialize ospf6 */
    ospf6_init ();

    /* parse config file */
    vty_read_config (config_file, config_default);

    /* Start execution only if not in dry-run mode */
    if (dryrun)
        return(0);

    if (daemon_mode && daemon (0, 0) < 0)
    {
        zlog_err("OSPF6d daemon failed: %s", strerror(errno));
        exit (1);
    }

    /* create thread for recv statellite info */
    if (thread_statellite_create () == -1)
    {
        zlog_err ("OSPF+ create thread for statellite info recv failed");
        exit (1);
    }
#ifdef OSPF6_DEBUG
    zlog_debug ("OSPF+ create thread for statellite info recv successfully");
#endif
    /* pid file create */
    pid_output (pid_file);

    /* Make ospf6 vty socket. */
    if (!vty_port)
        vty_port = OSPF6_VTY_PORT;
    vty_serv_sock (vty_addr, vty_port, OSPF6_VTYSH_PATH);

    /* Print start message */
    zlog_notice ("OSPF6d (Quagga-%s ospf6d-%s) starts: vty@%d",
                 QUAGGA_VERSION, OSPF6_DAEMON_VERSION,vty_port);

    /* Start finite state machine, here we go! */
    while (thread_fetch (master, &thread))
        thread_call (&thread);

    /* Log in case thread failed */
    zlog_warn ("Thread failed");

    /* Not reached. */
    ospf6_exit (0);
}
