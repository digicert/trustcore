/**
 * @file  vlong_mul.c
 * @brief Very Long Integer Multiplication Function Implementations
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../../common/vlong.h"
#include "../../common/vlong_priv.h"

#ifndef __DISABLE_DIGICERT_VLONG_MATH__

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
#include "../../common/bn_mul.h"

#if defined(__arm__) && !defined(__OPTIMIZE__)
#warning Assembly multiplication routine will default back to C code. Must compile with the -O1 option to use the assembly code.
#endif

/*----------------------------------------------------------------------------*/

static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
void VLONG_mul_assembly( ubyte4 i, vlong_unit *s, vlong_unit *d, vlong_unit b )
{
    vlong_unit c = 0;
#ifdef ASM_COLDFIRE_BACKUP_VARS
    ASM_COLDFIRE_BACKUP_VARS(vlong_unit)
#endif
    vlong_unit t = 0;
    
#if defined(MOC_MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_HUIT
        MOC_MULADDC_STOP
    }
    
    for( ; i > 0; i-- )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
#else /* MOC_MULADDC_HUIT */

#ifdef __ENABLE_FULL_UNLOOP_BI_MUL__
    for( ; i >= 64; i -= 64 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE

        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE

        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE

        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
#endif

    for( ; i >= 16; i -= 16 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
    
    for( ; i >= 8; i -= 8 )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_CORE   MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
    
    for( ; i > 0; i-- )
    {
        MOC_MULADDC_INIT
        MOC_MULADDC_CORE
        MOC_MULADDC_STOP
    }
#endif /* MOC_MULADDC_HUIT */
    
    t++;
    
    do
    {
        *d += c; c = ( *d < c ); d++;
    }
    while( c );
}
#endif /* __ENABLE_DIGICERT_BI_MUL_ASM__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_vlongSignedMultiply (
  vlong *pProduct, 
  const vlong *pFactorX, 
  const vlong *pFactorY
  )
{
  MSTATUS status;

  if (pFactorX == pFactorY)
  {
    status = VLONG_FAST_SQR(pProduct, pFactorX, pFactorX->numUnitsUsed * 2);
    pProduct->negative = FALSE;
  }
  else
  {
    status = VLONG_FAST_MULT(pProduct, pFactorX, pFactorY, pFactorX->numUnitsUsed + pFactorY->numUnitsUsed);

    pProduct->negative = pFactorX->negative ^ pFactorY->negative;
  }

  return status;

} /* VLONG_vlongSignedMultiply */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_unsignedMultiply (
  vlong *pProduct, 
  const vlong *pFactorX, 
  const vlong *pFactorY
  )
{
  if (pFactorX == pFactorY)
  {
    return VLONG_FAST_SQR(pProduct, pFactorX, pFactorX->numUnitsUsed * 2);
  }
  return VLONG_FAST_MULT(pProduct, pFactorX, pFactorY, pFactorX->numUnitsUsed + pFactorY->numUnitsUsed);

} /* VLONG_unsignedMultiply */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_vlongSignedSquare (
  vlong *pProduct, 
  const vlong *pFactor
  )
{
  MSTATUS status;

  status = VLONG_FAST_SQR(pProduct, pFactor, 2 * pFactor->numUnitsUsed);
  pProduct->negative = FALSE;

  return status;

} /* VLONG_vlongSignedSquare */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS fastUnsignedMultiplyVlongs (
  vlong *pProduct,
  const vlong *pFactorX, 
  const vlong *pFactorY, 
  ubyte4 x_limit
  )
{
  MSTATUS status = OK;
  
#ifndef __ENABLE_DIGICERT_BI_MUL_ASM__
  
#ifndef MACRO_MULTIPLICATION_LOOP
  vlong_unit result0, result1, result2;
  ubyte4 i, j, x;
  ubyte4 j_upper;
#endif
  ubyte4 i_limit, j_limit;
  vlong_unit *pFactorA;
  vlong_unit *pFactorB;
  vlong_unit *pResult;
  
  if ((NULL == pProduct) || (NULL == pFactorX) || (NULL == pFactorY))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

#if ((defined(__ASM_CAVIUM__)) && (defined(MACRO_MULTIPLICATION_LOOP)))
  if (pFactorX->numUnitsUsed < pFactorY->numUnitsUsed)
  {
    /* swap values */
    vlong *pTemp = pFactorX;

    pFactorX = pFactorY;
    pFactorY = pTemp;
  }
#endif

  pFactorA = pFactorX->pUnits;
  pFactorB = pFactorY->pUnits;

  if ((0 == pFactorX->numUnitsUsed) || (0 == pFactorY->numUnitsUsed))
  {
    status = VLONG_clearVlong(pProduct);
    goto exit;
  }

  if (pProduct->numUnitsAllocated < (ubyte4)x_limit)
    if (OK > (status = expandVlong(pProduct, x_limit)))
      goto exit;

#if ((defined(__ASM_CAVIUM__)) && (defined(MACRO_MULTIPLICATION_LOOP)))
  i_limit = pFactorX->numUnitsUsed;
  j_limit = pFactorY->numUnitsUsed;
#else
  i_limit = pFactorX->numUnitsUsed - 1;
  j_limit = pFactorY->numUnitsUsed - 1;
#endif
  pResult = pProduct->pUnits;

#ifndef MACRO_MULTIPLICATION_LOOP
  result0 = result1 = result2 = 0;
  
  for (x = 0; x < x_limit; x++)
  {
    i = (x <= i_limit) ? x : i_limit;
    j = x - i;

    j_upper = ((x <= j_limit) ? x : j_limit);

    while (j <= j_upper)
    {
      /* result2:result1:result0 += pFactorX->pUnits[i] * pFactorY->pUnits[j]; */
      MULT_ADDCX(pFactorA, pFactorB, i, j, result0, result1, result2);
      i--;
      j++;
    }

    *pResult++ = result0;

    result0 = result1;
    result1 = result2;
    result2 = 0;
  }
#else
  MACRO_MULTIPLICATION_LOOP(pResult, pFactorA, pFactorB, i_limit, j_limit, x_limit);
#endif
  
  /* calculate numUnitsUsed */
  while (x_limit && (ZERO_UNIT == pProduct->pUnits[x_limit - 1]))
    x_limit--;
  
  pProduct->numUnitsUsed = x_limit;

#else /* __ENABLE_DIGICERT_BI_MUL_ASM__ */
  
  ubyte4 j;

  if ((NULL == pProduct) || (NULL == pFactorX) || (NULL == pFactorY))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }
  
  if (pProduct->numUnitsAllocated < x_limit)
    if (OK > (status = expandVlong(pProduct, x_limit)))
      goto exit;
  
  /* set the units to all zero, must do all the way to x_limit for VLONG_montyMultiply */
  for (j = 0; j < x_limit; ++j)
  {
    pProduct->pUnits[j] = ZERO_UNIT;
  }
  
  for(j = pFactorY->numUnitsUsed; j > 0; --j)
  {
    VLONG_mul_assembly( pFactorX->numUnitsUsed, pFactorX->pUnits, pProduct->pUnits + j - 1, pFactorY->pUnits[j - 1] );
  }
  
  /* remove zero padding, ok to modify passed by value x_limit */
  while (x_limit && (ZERO_UNIT == pProduct->pUnits[x_limit - 1]))
    x_limit--;
  
  pProduct->numUnitsUsed = x_limit;

#endif

exit:
  
  return status;
  
} /* fastUnsignedMultiplyVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS fastUnsignedSqrVlong (
  vlong *pProduct,
  const vlong *pFactorSqrX, 
  ubyte4 x_limit
  )
{
#ifndef __ENABLE_DIGICERT_BI_MUL_ASM__
  
#ifndef MACRO_SQR_LOOP
  vlong_unit result0, result1, result2;
  vlong_unit half0, half1, half2;
  ubyte4 i, j, x;
#endif
  ubyte4 i_limit;
  vlong_unit *pFactorA;
  vlong_unit *pResult;
  MSTATUS status = OK;

  if ((NULL == pProduct) || (NULL == pFactorSqrX))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  pFactorA = pFactorSqrX->pUnits;

  if (0 == pFactorSqrX->numUnitsUsed)
  {
    status = VLONG_clearVlong(pProduct);
    goto exit;
  }

  if (pProduct->numUnitsAllocated < (ubyte4)x_limit)
    if (OK > (status = expandVlong(pProduct, x_limit)))
      goto exit;

  i_limit = (pFactorSqrX->numUnitsUsed - 1);
  pResult = pProduct->pUnits;

#ifndef MACRO_SQR_LOOP
  result0 = result1 = result2 = 0;

  for (x = 0; x < x_limit; x++)
  {
    half0 = half1 = half2 = 0;

    i = (x <= i_limit) ? x : i_limit;
    j = x - i;

    while (j < i)
    {
      /* result2:result1:result0 += pFactorSqrX->pUnits[i] * pFactorSqrX->pUnits[j]; */
      MULT_ADDCX(pFactorA, pFactorA, i, j, half0, half1, half2);
      i--;
      j++;
    }

    ADD_DOUBLE(result0, result1, result2, half0, half1, half2);

    /* add odd-even case */
    if (i == j)
    {
      MULT_ADDCX(pFactorA, pFactorA, i, j, result0, result1, result2);
    }

    *pResult++ = result0;

    result0 = result1;
    result1 = result2;
    result2 = 0;
  }
#else
  MACRO_SQR_LOOP(pResult, pFactorA, i_limit, x_limit);
#endif

  /* calculate numUnitsUsed */
  while (x_limit && (ZERO_UNIT == pProduct->pUnits[x_limit - 1]))
    x_limit--;

  pProduct->numUnitsUsed = x_limit;

exit:
  return status;

#else
  /* No assembly squaring method, multiply by itself */
  return fastUnsignedMultiplyVlongs(pProduct, pFactorSqrX, pFactorSqrX, x_limit);
#endif /* __ENABLE_DIGICERT_BI_MUL_ASM__ */
  
} /* fastUnsignedSqrVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS operatorMultiplySignedVlongs (
  const vlong* pFactorX, 
  const vlong* pFactorY,
  vlong **ppProduct, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  if (NULL == ppProduct)
    return ERR_NULL_POINTER;

  if (OK <= (status = VLONG_allocVlong(ppProduct, ppVlongQueue)))
  {
    DEBUG_RELABEL_MEMORY(*ppProduct);

    status = VLONG_unsignedMultiply(*ppProduct, pFactorX, pFactorY);

    (*ppProduct)->negative = pFactorX->negative ^ pFactorY->negative;
  }

  return status;

} /* operatorMultiplySignedVlongs */
#endif
