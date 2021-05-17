/* Auto-generated from route_types.txt by . */
/* Do not edit! */

#ifndef _QUAGGA_ROUTE_TYPES_H
#define _QUAGGA_ROUTE_TYPES_H

/* Zebra route's types. */
#define ZEBRA_ROUTE_SYSTEM               0
#define ZEBRA_ROUTE_KERNEL               1
#define ZEBRA_ROUTE_CONNECT              2
#define ZEBRA_ROUTE_STATIC               3
#define ZEBRA_ROUTE_RIP                  4
#define ZEBRA_ROUTE_RIPNG                5
#define ZEBRA_ROUTE_OSPF                 6
#define ZEBRA_ROUTE_OSPF6                7
#define ZEBRA_ROUTE_ISIS                 8
#define ZEBRA_ROUTE_BGP                  9
#define ZEBRA_ROUTE_4OVER6				10//added for 4over6 20130222
#define ZEBRA_ROUTE_HSLS                 11
#define ZEBRA_ROUTE_OLSR                 12
#define ZEBRA_ROUTE_BABEL                13
#define ZEBRA_ROUTE_MAX                  14

#define SHOW_ROUTE_V4_HEADER \
  "Codes: C - connected, S - static, R - RIP, O - OSPF, B - BGP,%s" \
  "       > - selected route, * - FIB route%s%s", \
  VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE
#define SHOW_ROUTE_V6_HEADER \
  "Codes: C - connected, S - static, R - RIPng, O - OSPFv6, B - BGP,%s" \
  "       > - selected route, * - FIB route%s%s", \
  VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE

/* bgpd */
#define QUAGGA_REDIST_STR_BGPD \
  "(connected|static|rip|ripng|ospf|ospf6)"
#define QUAGGA_REDIST_HELP_STR_BGPD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n"
#define QUAGGA_IP_REDIST_STR_BGPD \
  "(connected|static|rip|ospf)"
#define QUAGGA_IP_REDIST_HELP_STR_BGPD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Open Shortest Path First (OSPFv2)\n"
#define QUAGGA_IP6_REDIST_STR_BGPD \
  "(connected|static|ripng|ospf6)"
#define QUAGGA_IP6_REDIST_HELP_STR_BGPD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n"

/* ospf6d */
#define QUAGGA_REDIST_STR_OSPF6D \
  "(connected|static|ripng|bgp)"
#define QUAGGA_REDIST_HELP_STR_OSPF6D \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ospfd */
#define QUAGGA_REDIST_STR_OSPFD \
  "(connected|static|rip|bgp)"
#define QUAGGA_REDIST_HELP_STR_OSPFD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ripd */
#define QUAGGA_REDIST_STR_RIPD \
  "(connected|static|ospf|bgp)"
#define QUAGGA_REDIST_HELP_STR_RIPD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ripngd */
#define QUAGGA_REDIST_STR_RIPNGD \
  "(connected|static|ospf6|bgp)"
#define QUAGGA_REDIST_HELP_STR_RIPNGD \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Border Gateway Protocol (BGP)\n"

/* zebra */
#define QUAGGA_REDIST_STR_ZEBRA \
  "(connected|static|rip|ripng|ospf|ospf6|bgp)"
#define QUAGGA_REDIST_HELP_STR_ZEBRA \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Border Gateway Protocol (BGP)\n"
#define QUAGGA_IP_REDIST_STR_ZEBRA \
  "(connected|static|rip|ospf|bgp)"
#define QUAGGA_IP_REDIST_HELP_STR_ZEBRA \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Border Gateway Protocol (BGP)\n"
#define QUAGGA_IP6_REDIST_STR_ZEBRA \
  "(connected|static|ripng|ospf6|bgp)"
#define QUAGGA_IP6_REDIST_HELP_STR_ZEBRA \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Border Gateway Protocol (BGP)\n"


#ifdef QUAGGA_DEFINE_DESC_TABLE

struct zebra_desc_table
{
    unsigned int type;
    const char *string;
    char chr;
};

#define DESC_ENTRY(T,S,C) [(T)] = { (T), (S), (C) }
static const struct zebra_desc_table route_types[] =
{
    DESC_ENTRY	(ZEBRA_ROUTE_SYSTEM,	 "system",	'X' ),
    DESC_ENTRY	(ZEBRA_ROUTE_KERNEL,	 "kernel",	'K' ),
    DESC_ENTRY	(ZEBRA_ROUTE_CONNECT,	 "connected",	'C' ),
    DESC_ENTRY	(ZEBRA_ROUTE_STATIC,	 "static",	'S' ),
    DESC_ENTRY	(ZEBRA_ROUTE_RIP,	 "rip",	'R' ),
    DESC_ENTRY	(ZEBRA_ROUTE_RIPNG,	 "ripng",	'R' ),
    DESC_ENTRY	(ZEBRA_ROUTE_OSPF,	 "ospf",	'O' ),
    DESC_ENTRY	(ZEBRA_ROUTE_OSPF6,	 "ospf6",	'O' ),
    DESC_ENTRY	(ZEBRA_ROUTE_ISIS,	 "isis",	'I' ),
    DESC_ENTRY	(ZEBRA_ROUTE_BGP,	 "bgp",	'B' ),
    DESC_ENTRY	(ZEBRA_ROUTE_4OVER6,	 "4over6",	'4' ),
    DESC_ENTRY	(ZEBRA_ROUTE_HSLS,	 "hsls",	'H' ),
    DESC_ENTRY	(ZEBRA_ROUTE_OLSR,	 "olsr",	'o' ),
    DESC_ENTRY	(ZEBRA_ROUTE_BABEL,	 "babel",	'A' ),
};
#undef DESC_ENTRY

#endif /* QUAGGA_DEFINE_DESC_TABLE */

#endif /* _QUAGGA_ROUTE_TYPES_H */
