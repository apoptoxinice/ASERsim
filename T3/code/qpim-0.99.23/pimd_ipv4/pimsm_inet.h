#ifndef _PIM_INET_H
#define _PIM_INET_H

#define PIMSM_IP_ADDR_STRING_LEN 20

#define PIM_IP_ADDR_ANY 0x0001
//#define PIM_IP_ADDR_UNSPEC ND_IPV6_ADDR_ANY
#define PIM_IP_ADDR_UNICAST 0x0002
#define PIM_IP_ADDR_MULTICAST 0x0004
#define PIM_IP_ADDR_ANYCAST 0x0008
#define PIM_IP_ADDR_LOOPBACK 0x0010
#define PIM_IP_ADDR_LINKLOCAL 0x0020
#define PIM_IP_ADDR_SITELOCAL 0x0040
#define PIM_IP_ADDR_COMPATv4 0x0080
#define PIM_IP_ADDR_SCOPE_MASK 0x00f0
#define PIM_IP_ADDR_MAPPED 0x1000
#define PIM_IP_ADDR_RESERVED 0x2000
#define PIM_IP_ADDR_MCSOLICIT 0x8000

#define GET_IP_VER(v) (((v) & 0xf0) >> 4)
#define SET_IP_VER(p,v) ((p) = ((v) << 4))

extern uint8_t ip_isAnyAddress(VOS_IP_ADDR  *pAddress);
extern uint8_t ip_isLinklocalAddress(VOS_IP_ADDR  *pAddress);
extern int 	ip_AddressCompare(VOS_IP_ADDR  *pAddress1, VOS_IP_ADDR  *pAddress2);
extern int ip_printAddress(VOS_IP_ADDR  *pAddress, char *buf, int buf_len);
extern int pimsm_BitMapIndex(uint32_t data, int index[32], int *count);
extern int ip_GetPrefixFromAddr(VOS_IP_ADDR *pAddr, int iPrefixLen);
extern uint32_t pim_addr_type(VOS_IP_ADDR *pAddr);
extern uint8_t pim_MatchPrefix(VOS_IP_ADDR *ar1, VOS_IP_ADDR *ar2, uint16_t prefixlen);
extern uint8_t pimsm_IsSsmRangeAddr(VOS_IP_ADDR *pstAddr);

uint8_t ip_isMulticastAddress(VOS_IP_ADDR  *pAddress);
uint8_t ip_isMulticastLocalAddr(VOS_IP_ADDR *pAddress);
char *pimsm_GetIfName(uint32_t ifindex);
char *pim_InetFmt(VOS_IP_ADDR *addr);
int pimsm_BitMapIndex(uint32_t data, int index[32], int *count);
int ip_AddressCompare(VOS_IP_ADDR  *pAddress1, VOS_IP_ADDR  *pAddress2);
#endif
