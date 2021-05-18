#include "pimsm_define.h"

#if INCLUDE_PIMSM

#include "pimsm.h"
#include "pimsm_msg.h"
#include "pimsm_inet.h"
#include "pimsm_interface.h"

#define TMP_BUF_COUNT (10)
char *pim_InetFmt(VOS_IP_ADDR *addr)
{
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
}


uint8_t ip_isAnyAddress(VOS_IP_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    if( pAddress->u32_addr[0] == 0 )
        return TRUE;

    return FALSE;
}

//Link-Local Unicast Addresses          169.254.0.0/16
uint8_t ip_isLinklocalAddress(VOS_IP_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    if( (pAddress->u8_addr[0] == 169) && (pAddress->u8_addr[1] == 254)
            && (pAddress->u16_addr[1] == 0) )
        return TRUE;

    return FALSE;
}

/*  1>2---return 1;1=2 return 0; 1<2 return -1*/
int ip_AddressCompare(VOS_IP_ADDR  *pAddress1, VOS_IP_ADDR  *pAddress2)
{
    if((!pAddress1)||(!pAddress2))
        return -1;

    return (memcmp(pAddress1->u8_addr, pAddress2->u8_addr, sizeof(VOS_IP_ADDR)));
}

int ip_GetPrefixFromAddr(VOS_IP_ADDR *pAddr, int iPrefixLen)
{
    int iByte, iBit;
    VOS_IP_ADDR stMask;
    char *pMask;

    memset (&stMask, 0, sizeof(VOS_IP_ADDR));

    iByte = iPrefixLen/8;
    iBit = iPrefixLen%8;

    memset(&stMask, 0xff, iByte);
    pMask = (char*)&stMask;
    if (iBit != 0)
    {
        *( pMask  + iByte ) = (((char)0xff) << (8-iBit));
    }
    //modify by wuyan 2017-11-24
    pAddr->u32_addr[0] &= stMask.u32_addr[0]; //网络字节序
    //pAddr->u32_addr[0] &= ntohl(stMask.u32_addr[0]); //主机字节序
    //modify end

    return (VOS_OK);
}

//组播地址是D类IP地址，范围是从224.0.0.0到239.255.255.255, 第一个字节的前4位固定位1110
uint8_t ip_isMulticastAddress(VOS_IP_ADDR  *pAddress)
{
    if(!pAddress)
        return FALSE;

    if( (pAddress->u8_addr[0] & 0xE0) == 0xE0 ) //网络字节序
        //if( (pAddress->u8_addr[3] & 0xE0) == 0xE0 ) //主机字节序
        return TRUE;

    return FALSE;
}

//239.0.0.0 ~ 239.255.255.255 本地管理组播地址, 仅在特定的本地范围内有效
//224.0.0.0 ~ 224.0.0.255 保留地址, 不管ttl值是多少, 都不被路由转发
uint8_t ip_isMulticastLocalAddr(VOS_IP_ADDR *pAddress)
{
    if(!pAddress)
        return FALSE;

    if( (pAddress->u8_addr[0] & 0xEF) == 0xEF ) //网络字节序
        //if( (pAddress->u8_addr[3] & 0xEF) == 0xEF ) //主机字节序
        return TRUE;

    if( (pAddress->u32_addr[0] & 0x00FFFFE0) == 0x000000E0 ) //网络字节序
        //if( (pAddress->u32_addr[0] & 0xE0FFFF00) == 0xE0000000 ) //主机字节序
        return TRUE;

    return FALSE;
}


uint32_t pim_addr_type(VOS_IP_ADDR *pAddr)
{
    if (pAddr == NULL)
    {
        return VOS_ERROR;
    }

    if ( pAddr->u8_addr[0] == 127 )
    {
        return PIM_IP_ADDR_LOOPBACK;
    }

    if (pAddr->u32_addr[0] == 0)
    {
        return PIM_IP_ADDR_ANY;
    }

    if( (pAddr->u8_addr[0] & 0xe0) == 0xe0 )
    {
        return PIM_IP_ADDR_MULTICAST;
    }

    return PIM_IP_ADDR_UNICAST;
}

int     ip_printAddress(VOS_IP_ADDR  *pAddress, char *buf, int buf_len)
{
    if ( (pAddress == NULL) || (buf == NULL) || (buf_len == 0) )
    {
        return VOS_ERROR;
    }

    inet_ntop (AF_INET, (void*)pAddress, (char*)buf, buf_len);

    return VOS_OK;
}

#if 0 //sangmeng change
//0x00000000 return 0
//0x00000001 return 1
//0x00000002 return 2
//...
//0x00000010 return 5
//...
int pimsm_BitIndex(uint32_t flag)
{
    int i = 0;

    if (0 == flag)
    {
        return 0;
    }
    else
    {
        for(i = 1; i < (sizeof(flag) * 8); ++i)
        {
            if(0 != (flag & 0x01))
            {
                return i;
            }
            flag = flag >> 1;
        }
    }
}
#endif

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

char *pimsm_GetIfName(uint32_t ifindex)
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
uint8_t pim_MatchPrefix(VOS_IP_ADDR *ar1,VOS_IP_ADDR *ar2,uint16_t prefixlen)
{
    VOS_IP_ADDR prefix1;
    VOS_IP_ADDR prefix2;

    memcpy(&prefix1, ar1, sizeof(VOS_IP_ADDR));
    memcpy(&prefix2, ar2, sizeof(VOS_IP_ADDR));

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
uint8_t pimsm_IsSsmRangeAddr(VOS_IP_ADDR *pstAddr)
{
    return FALSE;
}

#endif
