#ifndef _PIM_RP_H
#define _PIM_RP_H

#include "pimsm.h"
#include "vty.h"

extern int pimsm_StaticRpAdd (VOS_IPV6_ADDR *pstGroupAddr, uint32_t , VOS_IPV6_ADDR *pstRpAddr);
extern int pimsm_staticrpconfig (struct vty *vty);
extern int pimsm_StaticRpDel (VOS_IPV6_ADDR *pstGroupAddr, uint32_t , VOS_IPV6_ADDR *pstRpAddr);
extern int pimsm_RpSearch (VOS_IPV6_ADDR* pstGrpAddr, VOS_IPV6_ADDR *pstRpAddr);
extern int pimsm_RpChangeCheck(VOS_IPV6_ADDR *pstGrpAddr, uint16_t wMaskLen);
extern int pimsm_IsAcceptSource (VOS_IPV6_ADDR * src_addr);
extern int pimsm_AcceptSourceAdd(VOS_IPV6_ADDR * src_addr, uint32_t );
extern int pimsm_AcceptSourceDel(VOS_IPV6_ADDR * src_addr, uint32_t );

uint8_t pimsm_IamRP(VOS_IPV6_ADDR *pstGrpAddr);


extern int pimsm_acceptsourceconfig(struct vty *vty);

#endif
