#ifndef _PIM_RP_H
#define _PIM_RP_H

#include "pimsm.h"
#include "vty.h"

extern int pimsm_StaticRpAdd (VOS_IP_ADDR *pstGroupAddr, VOS_IP_ADDR *pstGroupMask, VOS_IP_ADDR *pstRpAddr);
extern int pimsm_staticrpconfig (struct vty *vty);
extern int pimsm_StaticRpDel (VOS_IP_ADDR *pstGroupAddr, VOS_IP_ADDR *pstGroupMask, VOS_IP_ADDR *pstRpAddr);
extern int pimsm_RpSearch (VOS_IP_ADDR* pstGrpAddr, VOS_IP_ADDR *pstRpAddr);
extern int pimsm_RpChangeCheck(VOS_IP_ADDR *pstGrpAddr, uint16_t wMaskLen);
extern int pimsm_IsAcceptSource (VOS_IP_ADDR * src_addr);
extern int pimsm_AcceptSourceAdd(VOS_IP_ADDR * src_addr, VOS_IP_ADDR * pstSrcMask);
extern int pimsm_AcceptSourceDel(VOS_IP_ADDR * src_addr, VOS_IP_ADDR * pstSrcMask);

uint8_t pimsm_IamRP(VOS_IP_ADDR *pstGrpAddr);


extern int pimsm_acceptsourceconfig(struct vty *vty);

#endif
