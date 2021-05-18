#include "pimsm_define.h"

#if INCLUDE_PIMSM

#include "pimsm.h"
#include "pimsm_msg.h"
#include "pimsm_inet.h"
#include "pimsm_interface.h"

#define TMP_BUF_COUNT (10)
#define PIMSM_IP_ADDR_STRING_LEN 50

static int pimsm_InetNtop(VOS_IPV6_ADDR *addr, char *buf, int buf_len)
{
    if ((addr == NULL) || (buf == NULL) || (buf_len == 0))
    {
        return VOS_ERROR;
    }

    memset(buf, 0, buf_len);

    inet_ntop(AF_INET6, (void*)addr, (char*)buf, buf_len);

    return VOS_OK;
}
char *pim_InetFmt(VOS_IPV6_ADDR *addr)
{
    static char str[TMP_BUF_COUNT][PIMSM_IP_ADDR_STRING_LEN];
    static int n = 0;

    if (NULL == addr)
    {
        return "null";
    }

    n = n % TMP_BUF_COUNT;
    memset(str[n], 0, sizeof(str[n]));

    pimsm_InetNtop(addr, str[n], sizeof(str[n]));

    return str[n++];
}
#if 0
char *pim_InetFmt(VOS_IPV6_ADDR *addr)
{

    static char cstr[] = "null";
    struct in6_addr addr1;

    if (addr == NULL)
        return cstr;

    PIM_DEBUG("*******%p\n", addr);
    memset(&addr1, 0, sizeof(struct in6_addr));
    memcpy(&addr1, addr, sizeof(struct in6_addr));
    char buf[100];
    memset(buf, 0, sizeof(buf));
    inet_ntop(AF_INET6, &addr1, buf, sizeof(buf));
    return buf;

#if 0
    static char str[TMP_BUF_COUNT][PIMSM_IP_ADDR_STRING_LEN];
    static int n = 0;
    static char cstr[] = "null";

    if (NULL == addr)
        return cstr;

    n = n % TMP_BUF_COUNT;

    memset(str[n], 0, sizeof(str[n]));
    sprintf(str[n], "%d.%d.%d.%d", addr->u8_addr[0], addr->u8_addr[1], addr->u8_addr[2], addr->u8_addr[3]); //网络序
    //sprintf(str[n], "%d.%d.%d.%d", addr->u8_addr[3], addr->u8_addr[2], addr->u8_addr[1], addr->u8_addr[0]); //主机序

    return str[n++];
#endif
}
#endif

void pimsm_EmptyIpAddr(VOS_IPV6_ADDR *pAddress)
{
    if (NULL != pAddress)
    {
        memset(pAddress, 0, sizeof(VOS_IPV6_ADDR));
    }
}

//Link-Local Unicast Addresses Fe80::/10
uint8_t ip_isLinklocalAddress(VOS_IPV6_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    if ((ntohs(pAddress->u16_addr[0]) & 0xFFC0) == 0xFE80)
    {
        return TRUE;//FE80::/10
    }
    return FALSE;
}

/*  1>2---return 1;1=2 return 0; 1<2 return -1*/
int ip_AddressCompare(VOS_IPV6_ADDR *pAddress1, VOS_IPV6_ADDR *pAddress2)
{
    if((!pAddress1)||(!pAddress2))
        return -1;

    return (memcmp(pAddress1, pAddress2, sizeof(VOS_IPV6_ADDR)));
}
uint8_t ip_isAnyAddress(VOS_IPV6_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    VOS_IPV6_ADDR addr;
    pimsm_EmptyIpAddr(&addr);

    if (ip_AddressCompare(&addr, pAddress) == 0)
        return TRUE;

    return FALSE;
}
int ip_GetPrefixFromAddr(VOS_IPV6_ADDR *pAddr, int iPrefixLen)
{
    int iByte, iBit;
    VOS_IPV6_ADDR stMask;
    char *pMask;
    unsigned int i;

    memset (&stMask, 0, sizeof(VOS_IPV6_ADDR));

    iByte = iPrefixLen/8;
    iBit = iPrefixLen%8;

    memset(&stMask, 0xff, iByte);
    pMask = (char*)&stMask;
    if (iBit != 0)
    {
        *( pMask  + iByte ) = (((char)0xff) << (8-iBit));
    }

    for (i = 0; i < sizeof(VOS_IPV6_ADDR); i++)
    {
        pAddr->u8_addr[i] &= stMask.u8_addr[i];
    }

    return (VOS_OK);
}
//IPv6中没有广播, 用组播代替, FF00::/8
uint8_t ip_isMulticastAddress(VOS_IPV6_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    if( (pAddress->u8_addr[0] & 0xFF) == 0xFF ) //网络字节序
        return TRUE; //FF00::/8

    return FALSE;
}
//IPv6 node local multicast address 本地接口范围FF01::
//IPv6 link local multicast address 本地链路范围FF02::
uint8_t ip_isMulticastLocalAddr(VOS_IPV6_ADDR *pAddress)
{
    if(!pAddress)
        return FALSE;

    if ((ntohs(pAddress->u16_addr[0]) & 0xFF) == 0xFF01)
    {
        return TRUE;//FF01::/16
    }

    if ((ntohs(pAddress->u16_addr[0]) & 0xFF) == 0xFF02)
    {
        return TRUE;//FF02::/16
    }

    return FALSE;
}


uint32_t pim_addr_type(VOS_IPV6_ADDR *pAddr)
{
    if (pAddr == NULL)
    {
        return VOS_ERROR;
    }

    if ((pAddr->u32_addr[0] | pAddr->u32_addr[1] | pAddr->u32_addr[2] | pAddr->u32_addr[3]) == 0)
    {
        return PIMSM_IP_ADDR_UNSPEC;//PIMSM_IP_ADDR_ANY
    }

    if (pAddr->u8_addr[0] == 0xFF)
    {
        return PIMSM_IP_ADDR_MULTICAST;//FF00::/8
    }

    if (((pAddr->u32_addr[0] | pAddr->u32_addr[1] | pAddr->u32_addr[2]) == 0) &&
            (ntohl(pAddr->u32_addr[3]) == 0x00000001))
    {
        return PIMSM_IP_ADDR_LOOPBACK;//::1/128
    }

    if ((ntohs(pAddr->u16_addr[0]) & 0xFFC0) == 0xFE80)
    {
        return PIMSM_IP_ADDR_LINKLOCAL;//FE80::/10
    }

    if ((ntohs(pAddr->u16_addr[0]) & 0xFFC0) == 0xFEC0)
    {
        return PIMSM_IP_ADDR_SITELOCAL;//FEC0::/10
    }

    return PIMSM_IP_ADDR_UNICAST;
}

int ip_printAddress(VOS_IPV6_ADDR  *pAddress, char *buf, int buf_len)
{
    if ( (pAddress == NULL) || (buf == NULL) || (buf_len == 0) )
    {
        return VOS_ERROR;
    }

    inet_ntop (AF_INET6, (void*)pAddress, (char*)buf, buf_len);

    return VOS_OK;
}

//0x00000000 : return 0 , index[]={0} , *count = 0.
//0x00000001 : return 1 , index[] = {0,} , *count = 1.
//0x00000003 : return 2 , index[] = {0,1,} , *count = 2.
//0x0000000F : return 4 , index[] = {0,1,2,3,} , *count = 4.
//...
int pimsm_BitMapIndex(uint32_t data, int index[32], int *count)
{
    uint32_t value = data;
    int n = 0;
    uint32_t i = 0;

    if(0 == value)
    {
        if(NULL != count)
        {
            *count = 0;
        }
        return n;
    }

    for(i = 0, n = 0; i < (sizeof(data) * 8); ++i)
    {
        if(0 != (value & 0x01))
        {
            index[n] = i;
            n++;
        }
        value = value >> 1;
    }

    if(NULL != count)
    {
        *count = n;
    }

    return n;
}
const char *pimsm_GetIfName(uint32_t ifindex)
{
    return ifindex2ifname(ifindex);
}


/********************************************************************
*
* inet6_match_prefix - if the ar1 has the same prefix with ar2.
*
* RETURNS:
* YES: TRUE
* NO : FALSE
*********************************************************************/
uint8_t pim_MatchPrefix(VOS_IPV6_ADDR *ar1,VOS_IPV6_ADDR *ar2,uint16_t prefixlen)
{
    VOS_IPV6_ADDR prefix1;
    VOS_IPV6_ADDR prefix2;

    memcpy(&prefix1, ar1, sizeof(VOS_IPV6_ADDR));
    memcpy(&prefix2, ar2, sizeof(VOS_IPV6_ADDR));

    ip_GetPrefixFromAddr(&prefix1, prefixlen);
    ip_GetPrefixFromAddr(&prefix2, prefixlen);

    if (0 == ip_AddressCompare(&prefix1, &prefix2))
    {
        return TRUE;
    }

    return FALSE;

}

/********************************************************************
  Func Name   	: pimsm_IsSsmRangeAddr
  Description   : 查看指定的地址是否属于当前的ssm范围
  Input        	: 无
  Output       	:
  Return       	: TRUE -- 成功
               	  FALSE -- 失败
  Author      	: madongchao
  Create date	: 2005.11
*********************************************************************/
uint8_t pimsm_IsSsmRangeAddr(VOS_IPV6_ADDR *pstAddr)
{
    return FALSE;
}

#endif
