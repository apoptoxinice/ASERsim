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

#include <stdint.h>
#include <zebra.h>


#include "pimd.h"
#include "pim_pim.h"
#include "pim_msg.h"
#include "pim_util.h"
#include "pimsm_define.h"


void pim_msg_build_header(uint8_t *pim_msg, int pim_msg_size,
                          uint8_t pim_msg_type)
{
    uint16_t checksum;

    zassert(pim_msg_size >= PIM_PIM_MIN_LEN);

    /*
     * Write header
     */

    *(uint8_t *) PIM_MSG_HDR_OFFSET_VERSION(pim_msg) = (PIM_PROTO_VERSION << 4) | pim_msg_type;
    *(uint8_t *) PIM_MSG_HDR_OFFSET_RESERVED(pim_msg) = 0;

    /*
     * Compute checksum
     */

    *(uint16_t *) PIM_MSG_HDR_OFFSET_CHECKSUM(pim_msg) = 0;
    checksum = in_cksum(pim_msg, pim_msg_size);
    *(uint16_t *) PIM_MSG_HDR_OFFSET_CHECKSUM(pim_msg) = checksum;
}

uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf,
                                        int buf_size,
                                        struct in_addr addr)
{
    const int ENCODED_IPV4_UCAST_SIZE = 6;

    if (buf_size < ENCODED_IPV4_UCAST_SIZE)
    {
        return 0;
    }

    buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
    buf[1] = '\0';    /* native encoding */
    memcpy(buf+2, &addr, sizeof(struct in_addr));

    return buf + ENCODED_IPV4_UCAST_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf,
                                        int buf_size,
                                        struct in_addr addr)
{
    const int ENCODED_IPV4_GROUP_SIZE = 8;

    if (buf_size < ENCODED_IPV4_GROUP_SIZE)
    {
        return 0;
    }

    buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
    buf[1] = '\0';    /* native encoding */
    buf[2] = '\0';    /* reserved */
    buf[3] = 32;      /* mask len */
    memcpy(buf+4, &addr, sizeof(struct in_addr));

    return buf + ENCODED_IPV4_GROUP_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_source(uint8_t *buf,
        int buf_size,
        struct in_addr addr)
{
    const int ENCODED_IPV4_SOURCE_SIZE = 8;

    if (buf_size < ENCODED_IPV4_SOURCE_SIZE)
    {
        return 0;
    }

    buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
    buf[1] = '\0';    /* native encoding */
    buf[2] = 4;       /* reserved = 0 | S bit = 1 | W bit = 0 | R bit = 0 */
    buf[3] = 32;      /* mask len */
    memcpy(buf+4, &addr, sizeof(struct in_addr));

    return buf + ENCODED_IPV4_SOURCE_SIZE;
}
#if INCLUDE_PIMSM

static union
{
    u_int16_t phs[4];
    struct
    {
        u_int32_t ph_len;
        u_int8_t ph_zero[3];
        u_int8_t ph_nxt;
    } ph;
} uph;
/*
 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
 * sequential 16 bit words to it, and at the end, fold back all the
 * carry bits from the top 16 bits into the lower 16 bits.
 */
int pim6_cksum(u_int16_t *addr, struct in6_addr *src ,struct in6_addr *dst , int len )
{
    int nleft = len;
    u_int16_t *w;
    int32_t sum = 0;
    u_int16_t answer = 0;

    /*
     *      * First create IP6 pseudo header and calculate a summary.
     *           */
    w = (u_int16_t *)src;
    uph.ph.ph_len = htonl(len);
    uph.ph.ph_nxt = IPPROTO_PIM;

    /* IPv6 source address */
    sum += w[0];
    /* XXX: necessary? */
    if (!(IN6_IS_ADDR_LINKLOCAL(src) || IN6_IS_ADDR_MC_LINKLOCAL(src)))
        sum += w[1];
    sum += w[2];
    sum += w[3];
    sum += w[4];
    sum += w[5];
    sum += w[6];
    sum += w[7];
    /* IPv6 destination address */
    w = (u_int16_t *)dst;
    sum += w[0];
    /* XXX: necessary? */
    if (!(IN6_IS_ADDR_LINKLOCAL(dst) || IN6_IS_ADDR_MC_LINKLOCAL(dst)))
        sum += w[1];
    sum += w[2];
    sum += w[3];
    sum += w[4];
    sum += w[5];
    sum += w[6];
    sum += w[7];
    /* Payload length and upper layer identifier */
    sum += uph.phs[0];
    sum += uph.phs[1];
    sum += uph.phs[2];
    sum += uph.phs[3];

    /*
     *      * Secondly calculate a summary of the first mbuf excluding offset.
     *           */
    w = addr;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}

void pimsm_msg_build_header(struct pim_msg_header *header, int pim_msg_size,
                            uint8_t pim_msg_type, struct in6_addr *src, struct in6_addr *dst)
{
    uint16_t checksum;

    zassert(pim_msg_size >= PIM_PIM_MIN_LEN);

    header->type = pim_msg_type;
    header->ver = PIM_PROTO_VERSION;
    header->reserved = 0;
    header->checksum = 0;

#if 1
    if(header->type == PIM_TYPE_REGISTER)
    {
        //FIXME:
        pim_msg_size = sizeof(struct pim_msg_header) + sizeof(struct pimsm_register);
    }
#endif
    checksum = pim6_cksum((u_int16 *)header, src, dst, pim_msg_size);

    header->checksum = checksum;
}

#endif
