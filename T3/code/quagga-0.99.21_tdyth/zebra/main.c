/* zebra daemon main routine.
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

#include <zebra.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/irdp.h"
#include "zebra/rtadv.h"
/*
#define ADD_IVI_PREFIX	1
#define DEL_IVI_PREFIX	2
#define ADD_IVI_POOL	3
#define DEL_IVI_POOL	4
#define ADD_TUNNEL		5
#define DEL_TUNNEL		6
#define ADD_TUNNEL_SRC	7
#define DEL_TUNNEL_SRC	8
#define ADD_TUNNEL_DST	9
#define DEL_TUNNEL_DEST	10
#define ADD_TUNNEL_IP	11
#define DEL_TUNNEL_IP	12
#define ADD_NAT64_POOL	13
#define DEL_NAT64_POOL	14
#define ADD_NAT64_PREFIX 15
#define DEL_NAT64_PREFIX 16
#define ADD_NAT64_TIMEOUT 17
#define DEL_NAT64_TIMEOUT 18
#define NAT_TIMEOUT_TCP  19
#define NAT_TIMEOUT_UDP  20
#define NAT_TIMEOUT_ICMP 21

#define UBIT	1
#define NO_UBIT	2
struct ivi_message
{
		unsigned int type;	//message type
			unsigned int len;	//messgae size
				void *data;		//message data
};
struct ivi_prefix_message
{
		int flag;
			struct prefix_ipv6 prefix6;
};
struct ivi_pool_message
{
		struct prefix_ipv4 prefix4;
};
struct ivi_prefix_message *ivi_prefix_head;
struct ivi_pool_message *ivi_pool_head;

struct nat_prefix_message
{
		int flag;
			struct prefix_ipv6 prefix6;
};
struct nat_pool_message
{
		struct prefix_ipv4 prefix4;
};
struct nat_timeout_message
{   int nat_timeout;
		unsigned int nat_timeout_tcp;
			unsigned int nat_timeout_udp;
				unsigned int nat_timeout_icmp;
};
struct nat_prefix_message *nat_prefix_head;
struct nat_pool_message *nat_pool_head;
struct nat_timeout_message *nat_timeout_head;

struct tunnel_info	//tunnel
{
		unsigned int tunnel_num;		//size 0-32
			struct in6_addr tunnel_source;	//tunnel_source address
				struct in6_addr tunnel_dest;	//tunnel_dest address
					struct prefix_ipv4 ip_prefix;	//ipv4_prefix

						struct tunnel_info * tunnel_next;
};
struct tunnel_info *tunnel_head;	//tunnel head
*/
/* Zebra instance */
struct zebra_t zebrad =
{
    .rtm_table_default = 0,
};

/* process id. */
pid_t pid;

/* Pacify zclient.o in libzebra, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* Don't delete kernel route. */
int keep_kernel_mode = 0;

#ifdef HAVE_NETLINK
/* Receive buffer size for netlink socket */
u_int32_t nl_rcvbufsize = 0;
#endif /* HAVE_NETLINK */

/* Command line options. */
struct option longopts[] =
{
    { "batch",       no_argument,       NULL, 'b'},
    { "daemon",      no_argument,       NULL, 'd'},
    { "keep_kernel", no_argument,       NULL, 'k'},
    { "config_file", required_argument, NULL, 'f'},
    { "pid_file",    required_argument, NULL, 'i'},
    { "socket",      required_argument, NULL, 'z'},
    { "help",        no_argument,       NULL, 'h'},
    { "vty_addr",    required_argument, NULL, 'A'},
    { "vty_port",    required_argument, NULL, 'P'},
    { "retain",      no_argument,       NULL, 'r'},
    { "dryrun",      no_argument,       NULL, 'C'},
#ifdef HAVE_NETLINK
    { "nl-bufsize",  required_argument, NULL, 's'},
#endif /* HAVE_NETLINK */
    { "user",        required_argument, NULL, 'u'},
    { "group",       required_argument, NULL, 'g'},
    { "version",     no_argument,       NULL, 'v'},
    { 0 }
};

zebra_capabilities_t _caps_p [] =
{
    ZCAP_NET_ADMIN,
    ZCAP_SYS_ADMIN,
    ZCAP_NET_RAW,
};

/* zebra privileges to run with */
struct zebra_privs_t zserv_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
    .user = QUAGGA_USER,
    .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
    .vty_group = VTY_GROUP,
#endif
    .caps_p = _caps_p,
    .cap_num_p = sizeof(_caps_p)/sizeof(_caps_p[0]),
    .cap_num_i = 0
};

/* Default configuration file path. */
char config_default[] = SYSCONFDIR DEFAULT_CONFIG_FILE;

/* Process ID saved for use by init system */
const char *pid_file = PATH_ZEBRA_PID;

/* Help information display. */
static void
usage (char *progname, int status)
{
    if (status != 0)
        fprintf (stderr, "Try `%s --help' for more information.\n", progname);
    else
    {
        printf ("Usage : %s [OPTION...]\n\n"\
                "Daemon which manages kernel routing table management and "\
                "redistribution between different routing protocols.\n\n"\
                "-b, --batch        Runs in batch mode\n"\
                "-d, --daemon       Runs in daemon mode\n"\
                "-f, --config_file  Set configuration file name\n"\
                "-i, --pid_file     Set process identifier file name\n"\
                "-z, --socket       Set path of zebra socket\n"\
                "-k, --keep_kernel  Don't delete old routes which installed by "\
                "zebra.\n"\
                "-C, --dryrun       Check configuration for validity and exit\n"\
                "-A, --vty_addr     Set vty's bind address\n"\
                "-P, --vty_port     Set vty's port number\n"\
                "-r, --retain       When program terminates, retain added route "\
                "by zebra.\n"\
                "-u, --user         User to run as\n"\
                "-g, --group	  Group to run as\n", progname);
#ifdef HAVE_NETLINK
        printf ("-s, --nl-bufsize   Set netlink receive buffer size\n");
#endif /* HAVE_NETLINK */
        printf ("-v, --version      Print program version\n"\
                "-h, --help         Display this help and exit\n"\
                "\n"\
                "Report bugs to %s\n", ZEBRA_BUG_ADDRESS);
    }

    exit (status);
}

/* SIGHUP handler. */
static void
sighup (void)
{
    zlog_info ("SIGHUP received");

    /* Reload of config file. */
    ;
}

/* SIGINT handler. */
static void
sigint (void)
{
    zlog_notice ("Terminating on signal");

    if (!retain_mode)
        rib_close ();
#ifdef HAVE_IRDP
    irdp_finish();
#endif

    exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
    zlog_rotate (NULL);
}

struct quagga_signal_t zebra_signals[] =
{
    {
        .signal = SIGHUP,
        .handler = &sighup,
    },
    {
        .signal = SIGUSR1,
        .handler = &sigusr1,
    },
    {
        .signal = SIGINT,
        .handler = &sigint,
    },
    {
        .signal = SIGTERM,
        .handler = &sigint,
    },
};

//zlw 2016-4-11 ½Ó¿ÚÐÅÏ¢Ð´Èëµ½if.xmlÎÄ¼þÖÐ
int
if_config_write_to_xml(void)
{
    struct listnode *node;
    struct interface *ifp;
    int iRetVal = 0;

    char ipv4_addr[40];//zlw
    char ipv6_addr[50];//zlw
    int ipv4_flag = 0;
    int ipv6_flag = 0;
    int shutdown  = 0;

    for(ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
    {
        struct zebra_if  *if_data;
        struct listnode  *addrnode;
        struct connected *ifc;
        struct prefix    *p;

        if_data = ifp->info;

        //added for 4over6 20130314
        iRetVal = memcmp(ifp->name, "4o6_tnl", 7);
        if(iRetVal == 0)
            continue;

        for(ALL_LIST_ELEMENTS_RO(ifp->connected, addrnode, ifc))
        {
            if(CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
            {
                char buf[46];
                p = ifc->address;
#if 0
                vty_out(vty, " ip%s address %s/%d",
                        p->family == AF_INET ? "" : "v6",
                        inet_ntop(p->family, &p->u.prefix, buf, sizeof(buf)),
                        p->prefixlen);
#endif

                inet_ntop(p->family, &p->u.prefix, buf, sizeof(buf));
                //obtain  ipv4 address
                if(p->family == AF_INET)
                {
                    ipv4_flag = 1;
                    memset(ipv4_addr,0,40);
                    sprintf(ipv4_addr,"%s",buf);
                }
                else
                {
                    //obtain  ipv6 address
                    if(strncmp("fe80::",buf,6) != 0)
                    {
                        ipv6_flag = 1;
                        memset(ipv6_addr,0,50);
                        sprintf(ipv6_addr,"%s",buf);
                    }
                }

            }
        }

        if(if_data)
        {
            if(if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)
            {
                shutdown = 1;
            }
        }

        //write interface to xml  by zlw
        if(1!=shutdown)
        {
            /*    if(1==ipv4_flag && 1==ipv6_flag)
                   zebra_write_interface_to_xml(ifp->name,ipv4_addr,ipv6_addr);
                if(0==ipv4_flag && 1==ipv6_flag)
                   zebra_write_interface_to_xml(ifp->name,NULL,ipv6_addr);
                if(1==ipv4_flag && 0==ipv6_flag)
                   zebra_write_interface_to_xml(ifp->name,ipv4_addr,NULL);
                if(0==ipv4_flag && 0==ipv6_flag)
                   zebra_write_interface_to_xml(ifp->name,NULL,NULL);
              */
            if(1==ipv4_flag)
            {
                ipv4_flag = 0;
                memset(ipv4_addr,0,40);
            }

            if(1==ipv6_flag)
            {
                ipv6_flag = 0;
                memset(ipv6_addr,0,50);
            }

        }

    }

    //set timer 5 second
    thread_add_timer(zebrad.master,if_config_write_to_xml,NULL,5);

    return 0;
}
/* Main startup routine. */
int
main (int argc, char **argv)
{
    char *p;
    char *vty_addr = NULL;
    int vty_port = ZEBRA_VTY_PORT;
    int dryrun = 0;
    int batch_mode = 0;
    int daemon_mode = 0;
    char *config_file = NULL;
    char *progname;
    struct thread thread;
    char *zserv_path = NULL;

    /* Set umask before anything for security */
    umask (0027);

    /* preserve my name */
    progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    zlog_default = openzlog (progname, ZLOG_ZEBRA,
                             LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

    while (1)
    {
        int opt;

#ifdef HAVE_NETLINK
        opt = getopt_long (argc, argv, "bdkf:i:z:hA:P:ru:g:vs:C", longopts, 0);
#else
        opt = getopt_long (argc, argv, "bdkf:i:z:hA:P:ru:g:vC", longopts, 0);
#endif /* HAVE_NETLINK */

        if (opt == EOF)
            break;

        switch (opt)
        {
        case 0:
            break;
        case 'b':
            batch_mode = 1;
        case 'd':
            daemon_mode = 1;
            break;
        case 'k':
            keep_kernel_mode = 1;
            break;
        case 'C':
            dryrun = 1;
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
            zserv_path = optarg;
            break;
        case 'P':
            /* Deal with atoi() returning 0 on failure, and zebra not
               listening on zebra port... */
            if (strcmp(optarg, "0") == 0)
            {
                vty_port = 0;
                break;
            }
            vty_port = atoi (optarg);
            if (vty_port <= 0 || vty_port > 0xffff)
                vty_port = ZEBRA_VTY_PORT;
            break;
        case 'r':
            retain_mode = 1;
            break;
#ifdef HAVE_NETLINK
        case 's':
            nl_rcvbufsize = atoi (optarg);
            break;
#endif /* HAVE_NETLINK */
        case 'u':
            zserv_privs.user = optarg;
            break;
        case 'g':
            zserv_privs.group = optarg;
            break;
        case 'v':
            print_version (progname);
            exit (0);
            break;
        case 'h':
            usage (progname, 0);
            break;
        default:
            usage (progname, 1);
            break;
        }
    }

    /* Make master thread emulator. */
    zebrad.master = thread_master_create ();

    /* privs initialise */
    zprivs_init (&zserv_privs);

    /* Vty related initialize. */
    signal_init (zebrad.master, Q_SIGC(zebra_signals), zebra_signals);
    cmd_init (1);
    vty_init (zebrad.master);
    memory_init ();

    /* Zebra related initialize. */
    zebra_init ();
    rib_init ();
    access_list_init ();
    zebra_if_init ();
    zebra_debug_init ();
    router_id_init();
    zebra_vty_init ();
    prefix_list_init ();
    rtadv_init ();
#ifdef HAVE_IRDP
    irdp_init();
#endif

    /* For debug purpose. */
    /* SET_FLAG (zebra_debug_event, ZEBRA_DEBUG_EVENT); */

    /* Make kernel routing socket. */
    kernel_init ();
    interface_list ();
#if 1
    struct listnode *node;
    struct interface *ifp;
    //sangmeng add for test
//system("ip addr del 20.0.0.1/24 dev GE4");
#if 1
    for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
    {
        //printf("ifp->name:%s\n", ifp->name);
        if(strncmp(ifp->name,"4o6",3)==0||strncmp(ifp->name,"ivi",3)==0||strncmp(ifp->name,"nat",3)==0||strncmp(ifp->name,"6o4",3)==0||strncmp(ifp->name,"ip",2)==0 || strncmp(ifp->name, "usb0", 3)==0)
            continue;

        if_down(ifp);
    }
#endif


#endif
    route_read ();

    /* Sort VTY commands. */
    sort_node ();

#ifdef HAVE_SNMP
    zebra_snmp_init ();
#endif /* HAVE_SNMP */

    /* Process the configuration file. Among other configuration
    *  directives we can meet those installing static routes. Such
    *  requests will not be executed immediately, but queued in
    *  zebra->ribq structure until we enter the main execution loop.
    *  The notifications from kernel will show originating PID equal
    *  to that after daemon() completes (if ever called).
    */
    vty_read_config (config_file, config_default);

    /* Don't start execution if we are in dry-run mode */
    if (dryrun)
        return(0);

    /* Clean up rib. */
    rib_weed_tables ();

    /* Exit when zebra is working in batch mode. */
    if (batch_mode)
        exit (0);

    /* Daemonize. */
    if (daemon_mode && daemon (0, 0) < 0)
    {
        zlog_err("Zebra daemon failed: %s", strerror(errno));
        exit (1);
    }

    /* Output pid of zebra. */
    pid_output (pid_file);

    /* After we have successfully acquired the pidfile, we can be sure
    *  about being the only copy of zebra process, which is submitting
    *  changes to the FIB.
    *  Clean up zebra-originated routes. The requests will be sent to OS
    *  immediately, so originating PID in notifications from kernel
    *  will be equal to the current getpid(). To know about such routes,
    * we have to have route_read() called before.
    */
    if (! keep_kernel_mode)
        rib_sweep_route ();

    /* Needed for BSD routing socket. */
    pid = getpid ();

    /* This must be done only after locking pidfile (bug #403). */
    zebra_zserv_socket_init (zserv_path);

    /* Make vty server socket. */
    vty_serv_sock (vty_addr, vty_port, ZEBRA_VTYSH_PATH);

    //Ïòif.xmlÎÄ¼þÖÐÐ´Èë½Ó¿ÚÐÅÏ¢ zlw 2016-4-14
    thread_add_event(zebrad.master, if_config_write_to_xml,NULL, 0);
    /* Print banner. */
    zlog_notice ("Zebra %s starting: vty@%d", QUAGGA_VERSION, vty_port);
    while(thread_fetch (zebrad.master, &thread))
        thread_call (&thread);

    /* Not reached... */
    return 0;
}
