/**
 * @file  vlong_const.h
 * @brief Very Long Integer Library Constant Time Operatons Header
 *
 * Copyright Digicert 2023. All Rights Reserved.
 * Proprietary and Confidential Material.
 */

#ifndef __VLONG_CONST_HEADER__
#define __VLONG_CONST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS VLONG_allocVlongZero (
  vlong **ppNew,
  ubyte4 vlongNewLength,
  vlong **ppVlongQueue
  );

MOC_EXTERN vlong_unit VLONG_constTimeCmp (
  vlong_unit *pA,
  vlong_unit *pB,
  ubyte4 numUnits
  );

MOC_EXTERN vlong_unit VLONG_constTimeAdd (
  vlong_unit *pR,
  vlong_unit *pA,
  vlong_unit *pB, 
  ubyte4 numUnits
  );

MOC_EXTERN vlong_unit VLONG_constTimeSubtract (
  vlong_unit *pR,
  vlong_unit *pA,
  vlong_unit *pB, 
  ubyte4 numUnits
  );

MOC_EXTERN void VLONG_constTimeMultiply (
  vlong_unit *pRes,
  ubyte4 resLen,
  vlong_unit *pX,
  ubyte4 xLen,
  vlong_unit *pY,
  ubyte4 yLen
  );

MOC_EXTERN void VLONG_constTimeSquare (
  vlong_unit *pRes,
  ubyte4 resLen,
  vlong_unit *pX,
  ubyte4 xLen
  );

MOC_EXTERN MSTATUS VLONG_constTimeDiv(
  vlong_unit *pQuotient,
  vlong_unit *pRemainder,
  vlong_unit *pDividend,
  ubyte4 dividendLen,
  vlong_unit *pDivisor,
  ubyte4 divisorLen
  ); 

MOC_EXTERN MSTATUS VLONG_constTimeMontExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) 
  MontgomeryCtx *pMonty,
  vlong *pBase,
  vlong *pExp, 
  vlong_unit *pResult
  );

#ifdef __cplusplus
}
#endif

#endif /* __VLONG_CONST_HEADER__ */
