/**
 * @file  vlong_karatsuba.c
 * @brief Very Long Integer Karatsuba Function Implementations
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

#if defined(__RTOS_THREADX__) && !defined(__RTOS_AZURE__)
#include "common/vlong.h"
#else
#include "../../common/vlong.h"
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__DISABLE_MOCANA_KARATSUBA__) && !defined(__DISABLE_MOCANA_VLONG_MATH__)

#ifdef __ASM_COLDFIRE_MCF__
extern "C" {
#endif

static void MATH_8x8 (
  vlong_unit *pProduct, 
  const vlong_unit *pFactorA,
  const vlong_unit *pFactorB
  );

static void MATH_SQR8 (
  vlong_unit *pProduct, 
  const vlong_unit* pFactorA
  );

#ifdef __ASM_COLDFIRE_MCF__
}
#endif

static MSTATUS MATH_compareValues (
  const vlong_unit *a, 
  const vlong_unit *b, 
  sbyte4 len
  );

static MSTATUS MATH_sumValues (
  vlong_unit *result, 
  const vlong_unit *a, 
  const vlong_unit *b,
  sbyte4 length
  );

static MSTATUS MATH_subtractValues (
  vlong_unit *result, 
  const vlong_unit *a, 
  const vlong_unit *b,
  sbyte4 length
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS fasterUnsignedMultiplyVlongs (
  vlong *pProduct,
  const vlong *pFactorA, 
  const vlong *pFactorB,
  ubyte4 numUnits
  )
{
  vlong_unit *pWorkspace = NULL;
  sbyte4 lengthA;
  sbyte4 lengthB;
  sbyte4 limit;
  sbyte4 diff;
  sbyte4 sizeofWorkspace;
  sbyte4 twoPowerX;
  MSTATUS status = OK;

  pProduct->numUnitsUsed = 0;

  lengthA = pFactorA->numUnitsUsed;
  lengthB = pFactorB->numUnitsUsed;

  if ((0 == lengthA) || (0 == lengthB))
  {
    status = VLONG_clearVlong(pProduct);
    goto exit;
  }

  limit = lengthA + lengthB;

  if (limit == (sbyte4) numUnits)
  {
    if ((0 == (diff = lengthA - lengthB)) && (8 == lengthA))
    {
      if (pProduct->numUnitsAllocated < 16)
        if (OK > (status = expandVlong(pProduct, 16)))
          goto exit;

      MATH_8x8(pProduct->pUnits, pFactorA->pUnits, pFactorB->pUnits);
      while (limit && (ZERO_UNIT == pProduct->pUnits[limit - 1]))
        limit--;

      pProduct->numUnitsUsed = limit;

      goto exit;
    }

    if ((0 == diff) && (lengthA >= 16))
    {
      twoPowerX = 1 << (BITLENGTH((ubyte4)lengthA) - 1);
      sizeofWorkspace = twoPowerX + twoPowerX;

      if (lengthA == twoPowerX) /* lengthA is equal to 2^x */
      {
        if (NULL == (pWorkspace = (vlong_unit *)MALLOC(sizeofWorkspace * 2 * sizeof(vlong_unit))))
        {
          status = ERR_MEM_ALLOC_FAIL;
          goto exit;
        }

        if (pProduct->numUnitsAllocated < (ubyte4)(sizeofWorkspace))
          if (OK > (status = expandVlong(pProduct, sizeofWorkspace)))
            goto exit;

        karatsubaMultiply(pProduct->pUnits,
                          pFactorA->pUnits, pFactorB->pUnits,
                          pWorkspace, lengthA);

        while (limit && (ZERO_UNIT == pProduct->pUnits[limit - 1]))
          limit--;

        pProduct->numUnitsUsed = limit;

        goto exit;
      }
    }
  }

  status = fastUnsignedMultiplyVlongs(pProduct, pFactorA, pFactorB, numUnits);

exit:
  if (NULL != pWorkspace)
    FREE(pWorkspace);

  return (status);

} /* fasterUnsignedMultiplyVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS fasterUnsignedSqrVlong (
  vlong *pProduct, 
  const vlong *pFactorA,
  ubyte4 numUnits
  )
{
  vlong_unit *pWorkspace = NULL;
  sbyte4 lengthA;
  sbyte4 limit;
  sbyte4 sizeofWorkspace;
  sbyte4 twoPowerX;
  MSTATUS status = OK;

  pProduct->numUnitsUsed = 0;

  lengthA = pFactorA->numUnitsUsed;

  if (0 == lengthA)
  {
    status = VLONG_clearVlong(pProduct);
    goto exit;
  }

  limit = 2 * lengthA;

  if (limit == (sbyte4) numUnits)
  {
    if ((8 == lengthA))
    {
      if (pProduct->numUnitsAllocated < 16)
        if (OK > (status = expandVlong(pProduct, 16)))
          goto exit;

      MATH_SQR8(pProduct->pUnits, pFactorA->pUnits);
      while (limit && (ZERO_UNIT == pProduct->pUnits[limit - 1]))
        limit--;

      pProduct->numUnitsUsed = limit;
      goto exit;
    }

    if ((lengthA >= 16))
    {
      twoPowerX = 1 << (BITLENGTH((ubyte4)lengthA) - 1);
      sizeofWorkspace = twoPowerX + twoPowerX;

      if (lengthA == twoPowerX) /* lengthA is equal to 2^x */
      {
        if (NULL == (pWorkspace = (vlong_unit *)MALLOC(sizeofWorkspace * 2 * sizeof(vlong_unit))))
        {
          status = ERR_MEM_ALLOC_FAIL;
          goto exit;
        }

        if (pProduct->numUnitsAllocated < (ubyte4)(sizeofWorkspace))
          if (OK > (status = expandVlong(pProduct, sizeofWorkspace)))
            goto exit;

        karatsubaSqr(pProduct->pUnits,
                     pFactorA->pUnits,
                     pWorkspace, lengthA);

        while (limit && (ZERO_UNIT == pProduct->pUnits[limit - 1]))
          limit--;

        pProduct->numUnitsUsed = limit;

        goto exit;
      }
    }
  }

  status = fastUnsignedSqrVlong(pProduct, pFactorA, numUnits);

exit:
  if (NULL != pWorkspace)
    FREE(pWorkspace);

  return (status);

} /* fasterUnsignedSqrVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN void karatsubaMultiply (
  vlong_unit *pProduct, 
  const vlong_unit *pFactorA,
  const vlong_unit *pFactorB, 
  vlong_unit *pWorkspace, 
  sbyte4 n
  )
{
  sbyte4 half_n = n >> 1;
  intBoolean negative;
  intBoolean zeroFlag;
  sbyte4 compA;
  sbyte4 compB;

  if (8 == n)
  {
    MATH_8x8(pProduct, pFactorA, pFactorB);
    return;
  }

  /* recycle stack space during recursion */
  {
    compA = MATH_compareValues(&(pFactorA[half_n]), pFactorA, half_n);
    compB = MATH_compareValues(&(pFactorB[half_n]), pFactorB, half_n);

    zeroFlag = negative = FALSE;

    switch ((compA * 4) + compB)
    {
    case -5: /* negative times negative */
      MATH_subtractValues(pWorkspace, pFactorA, &(pFactorA[half_n]), half_n);
      MATH_subtractValues(&(pWorkspace[half_n]), pFactorB, &(pFactorB[half_n]), half_n);
      break;
    case -3: /* negative times positive */
      MATH_subtractValues(pWorkspace, pFactorA, &(pFactorA[half_n]), half_n);
      MATH_subtractValues(&(pWorkspace[half_n]), &(pFactorB[half_n]), pFactorB, half_n);
      negative = TRUE;
      break;
    case 3: /* positive times negative */
      MATH_subtractValues(pWorkspace, &(pFactorA[half_n]), pFactorA, half_n);
      MATH_subtractValues(&(pWorkspace[half_n]), pFactorB, &(pFactorB[half_n]), half_n);
      negative = TRUE;
      break;
    case 5: /* positive times positive */
      MATH_subtractValues(pWorkspace, &(pFactorA[half_n]), pFactorA, half_n);
      MATH_subtractValues(&(pWorkspace[half_n]), &(pFactorB[half_n]), pFactorB, half_n);
      break;
    default: /* some combination of a zero times some x */
      zeroFlag = TRUE;
      break;
    }
  }
  /* A1 - A0 is stored in w[0...half_n-1] B1 - B0 is stored in w[half_n...2*half_n -1] */

  if (8 != half_n)
  {
    /* deal with the inner tree first to avoid an extra jump on leaf node case */
    /* multiply A1 - A0 by B1 - B0 in the w[2*half_n...4*half_n-1] or w[n..2*n-1] */
    /* the space w[2*n...] is used as "workspace" */
    if (!zeroFlag)
      karatsubaMultiply(&(pWorkspace[n]), pWorkspace, &(pWorkspace[half_n]), &(pWorkspace[n << 1]), half_n);
    else
    {
      register int i;
      for (i = n - 1; i >= 0; i--)
        pWorkspace[n + i] = 0;
    }

    karatsubaMultiply(pProduct, pFactorA, pFactorB, &(pWorkspace[n << 1]), half_n);
    karatsubaMultiply(&(pProduct[n]), &(pFactorA[half_n]), &(pFactorB[half_n]), &(pWorkspace[n << 1]), half_n);
  }
  else
  {
    if (!zeroFlag)
      MATH_8x8(&(pWorkspace[n]), pWorkspace, &(pWorkspace[half_n])); /* D2 = A1-A0 * B1-B0 */
    else
    {
      register int i; /* D2 = A1-A0 * B1-B0 */
      for (i = 15; i >= 0; i--)
        pWorkspace[n + i] = 0;
    }

    MATH_8x8(pProduct, pFactorA, pFactorB);                             /* D0 = A0 * B0 */
    MATH_8x8(&(pProduct[n]), &(pFactorA[half_n]), &(pFactorB[half_n])); /* D1 = A1 * B1 */
  }

  /* recycle stack space for recursion */
  {
    sbyte4 carryFlag;

    carryFlag = MATH_sumValues(pWorkspace, pProduct, &(pProduct[n]), n); /* D0 + D1 */

    if (!negative) /* D0 + D1 - D2 */
      carryFlag -= MATH_subtractValues(&(pWorkspace[n]), pWorkspace, &(pWorkspace[n]), n);
    else
      carryFlag += MATH_sumValues(&(pWorkspace[n]), &(pWorkspace[n]), pWorkspace, n);

    carryFlag += MATH_sumValues(&(pProduct[half_n]), &(pProduct[half_n]), &(pWorkspace[n]), n);

    if (0 != carryFlag)
    {
      /* add carry for D2 term */
      vlong_unit *pTemp = &(pProduct[half_n + n]);

      *pTemp = (*pTemp + carryFlag);

      /* handle carryFlag */
      if (*pTemp < (vlong_unit)carryFlag)
      {
        do
        {
          pTemp++;
          (*pTemp)++;
        } while (ZERO_UNIT == *pTemp);
      }
    }
  }
} /* karatsubaMultiply */

/*----------------------------------------------------------------------------*/

MOC_EXTERN void karatsubaSqr (
  vlong_unit *pProduct, 
  const vlong_unit *pFactorA, 
  vlong_unit *pWorkspace,
  sbyte4 n
  )
{
  sbyte4 half_n = n >> 1;
  intBoolean zeroFlag;
  sbyte4 compA;
  sbyte4 i;

  if (8 == n)
  {
    MATH_SQR8(pProduct, pFactorA);
    return;
  }

  compA = MATH_compareValues(&(pFactorA[half_n]), pFactorA, half_n);

  zeroFlag = FALSE;

  switch (compA)
  {
  case -1: /* negative times negative */
    MATH_subtractValues(pWorkspace, pFactorA, &(pFactorA[half_n]), half_n);
    for (i = 0; i < half_n; ++i)
    {
      pWorkspace[half_n + i] = pWorkspace[i];
    }
    /*MOC_MEMCPY( (ubyte*) ( pWorkspace+half_n),
          (ubyte*) pWorkspace, half_n * sizeof(ubyte4)); */
    break;
  case 1: /* positive times positive */
    MATH_subtractValues(pWorkspace, &(pFactorA[half_n]), pFactorA, half_n);
    for (i = 0; i < half_n; ++i)
    {
      pWorkspace[half_n + i] = pWorkspace[i];
    }

    /*MOC_MEMCPY( (ubyte*) (pWorkspace+half_n),
          (ubyte*) pWorkspace, half_n * sizeof(ubyte4));*/
    break;
  default: /* some combination of a zero times some x */
    zeroFlag = TRUE;
    break;
  }

  if (8 != half_n)
  {
    /* deal with the inner tree first to avoid an extra jump on leaf node case */
    if (!zeroFlag)
      karatsubaSqr(&(pWorkspace[n]), pWorkspace, &(pWorkspace[n << 1]), half_n);
    else
    {
      register int i;
      for (i = n - 1; i >= 0; i--)
        pWorkspace[n + i] = 0;
    }

    karatsubaSqr(pProduct, pFactorA, &(pWorkspace[n << 1]), half_n);
    karatsubaSqr(&(pProduct[n]), &(pFactorA[half_n]), &(pWorkspace[n << 1]), half_n);
  }
  else
  {
    if (!zeroFlag)
      MATH_SQR8(&(pWorkspace[n]), pWorkspace); /* D2 = A1-A0 * B1-B0 */
    else
    {
      register int i; /* D2 = A1-A0 * B1-B0 */
      for (i = 15; i >= 0; i--)
        pWorkspace[n + i] = 0;
    }

    MATH_SQR8(pProduct, pFactorA);                  /* D0 = A0 * B0 */
    MATH_SQR8(&(pProduct[n]), &(pFactorA[half_n])); /* D1 = A1 * B1 */
  }

  {
    sbyte4 carryFlag;

    carryFlag = MATH_sumValues(pWorkspace, pProduct, &(pProduct[n]), n); /* D0 + D1 */
    carryFlag -= MATH_subtractValues(&(pWorkspace[n]), pWorkspace, &(pWorkspace[n]), n);
    carryFlag += MATH_sumValues(&(pProduct[half_n]), &(pProduct[half_n]), &(pWorkspace[n]), n);

    if (0 != carryFlag)
    {
      /* add carry for D2 term */
      vlong_unit *pTemp = &(pProduct[half_n + n]);

      *pTemp = (*pTemp + carryFlag);

      /* handle carryFlag */
      if (*pTemp < (vlong_unit)carryFlag)
      {
        do
        {
          pTemp++;
          (*pTemp)++;
        } while (ZERO_UNIT == *pTemp);
      }
    }
  }
} /* karatsubaSqr */

/*----------------------------------------------------------------------------*/

#ifndef ASM_MATH_8x8_DEFINED

static void MATH_8x8 (
  vlong_unit *pProduct, 
  const vlong_unit *pFactorA,
  const vlong_unit *pFactorB
  )
{
  vlong_unit result0, result1, result2;

  result0 = result1 = result2 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 0, result0, result1, result2);
  pProduct[0] = result0;
  result0 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 1, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 1, 0, result1, result2, result0);
  pProduct[1] = result1;
  result1 = 0;

  MULT_ADDC(pFactorA, pFactorB, 2, 0, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 1, 1, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 0, 2, result2, result0, result1);
  pProduct[2] = result2;
  result2 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 3, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 1, 2, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 2, 1, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 3, 0, result0, result1, result2);
  pProduct[3] = result0;
  result0 = 0;

  MULT_ADDC(pFactorA, pFactorB, 4, 0, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 3, 1, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 2, 2, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 1, 3, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 0, 4, result1, result2, result0);
  pProduct[4] = result1;
  result1 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 5, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 1, 4, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 2, 3, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 3, 2, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 4, 1, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 5, 0, result2, result0, result1);
  pProduct[5] = result2;
  result2 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 6, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 1, 5, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 2, 4, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 3, 3, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 4, 2, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 5, 1, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 6, 0, result0, result1, result2);
  pProduct[6] = result0;
  result0 = 0;

  MULT_ADDC(pFactorA, pFactorB, 0, 7, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 1, 6, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 2, 5, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 3, 4, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 4, 3, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 5, 2, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 6, 1, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 7, 0, result1, result2, result0);
  pProduct[7] = result1;
  result1 = 0;

  MULT_ADDC(pFactorA, pFactorB, 7, 1, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 6, 2, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 5, 3, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 4, 4, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 3, 5, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 2, 6, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 1, 7, result2, result0, result1);
  pProduct[8] = result2;
  result2 = 0;

  MULT_ADDC(pFactorA, pFactorB, 2, 7, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 3, 6, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 4, 5, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 5, 4, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 6, 3, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 7, 2, result0, result1, result2);
  pProduct[9] = result0;
  result0 = 0;

  MULT_ADDC(pFactorA, pFactorB, 7, 3, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 6, 4, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 5, 5, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 4, 6, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 3, 7, result1, result2, result0);
  pProduct[10] = result1;
  result1 = 0;

  MULT_ADDC(pFactorA, pFactorB, 4, 7, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 5, 6, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 6, 5, result2, result0, result1);
  MULT_ADDC(pFactorA, pFactorB, 7, 4, result2, result0, result1);
  pProduct[11] = result2;
  result2 = 0;

  MULT_ADDC(pFactorA, pFactorB, 7, 5, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 6, 6, result0, result1, result2);
  MULT_ADDC(pFactorA, pFactorB, 5, 7, result0, result1, result2);
  pProduct[12] = result0;
  result0 = 0;

  MULT_ADDC(pFactorA, pFactorB, 6, 7, result1, result2, result0);
  MULT_ADDC(pFactorA, pFactorB, 7, 6, result1, result2, result0);
  pProduct[13] = result1;
  result1 = 0;

  MULT_ADDC1(pFactorA, pFactorB, 7, 7, result2, result0);
  pProduct[14] = result2;
  pProduct[15] = result0;

} /* MATH_8x8 */

/*----------------------------------------------------------------------------*/

static void MATH_SQR8 (
  vlong_unit *pProduct, 
  const vlong_unit* pFactorA
  )
{
  vlong_unit result0, result1, result2;
  vlong_unit half0, half1, half2;

  result0 = result1 = result2 = 0;

  MULT_ADDC(pFactorA, pFactorA, 0, 0, result0, result1, result2);
  pProduct[0] = result0;
  result0 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 0, 1, half0, half1, half2);
  ADD_DOUBLE(result1, result2, result0, half0, half1, half2);
  pProduct[1] = result1;
  result1 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 2, 0, half0, half1, half2);
  ADD_DOUBLE(result2, result0, result1, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 1, 1, result2, result0, result1);
  pProduct[2] = result2;
  result2 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 0, 3, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 1, 2, half0, half1, half2);
  ADD_DOUBLE(result0, result1, result2, half0, half1, half2);
  pProduct[3] = result0;
  result0 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 4, 0, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 3, 1, half0, half1, half2);
  ADD_DOUBLE(result1, result2, result0, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 2, 2, result1, result2, result0);
  pProduct[4] = result1;
  result1 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 0, 5, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 1, 4, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 2, 3, half0, half1, half2);
  ADD_DOUBLE(result2, result0, result1, half0, half1, half2);
  pProduct[5] = result2;
  result2 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 0, 6, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 1, 5, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 2, 4, half0, half1, half2);
  ADD_DOUBLE(result0, result1, result2, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 3, 3, result0, result1, result2);
  pProduct[6] = result0;
  result0 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 0, 7, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 1, 6, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 2, 5, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 3, 4, half0, half1, half2);
  ADD_DOUBLE(result1, result2, result0, half0, half1, half2);
  pProduct[7] = result1;
  result1 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 7, 1, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 6, 2, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 5, 3, half0, half1, half2);
  ADD_DOUBLE(result2, result0, result1, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 4, 4, result2, result0, result1);
  pProduct[8] = result2;
  result2 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 2, 7, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 3, 6, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 4, 5, half0, half1, half2);
  ADD_DOUBLE(result0, result1, result2, half0, half1, half2);
  pProduct[9] = result0;
  result0 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 7, 3, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 6, 4, half0, half1, half2);
  ADD_DOUBLE(result1, result2, result0, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 5, 5, result1, result2, result0);
  pProduct[10] = result1;
  result1 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 4, 7, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 5, 6, half0, half1, half2);
  ADD_DOUBLE(result2, result0, result1, half0, half1, half2);
  pProduct[11] = result2;
  result2 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 7, 5, half0, half1, half2);
  ADD_DOUBLE(result0, result1, result2, half0, half1, half2);
  MULT_ADDC(pFactorA, pFactorA, 6, 6, result0, result1, result2);
  pProduct[12] = result0;
  result0 = 0;

  half0 = half1 = half2 = 0;
  MULT_ADDC(pFactorA, pFactorA, 6, 7, half0, half1, half2);
  ADD_DOUBLE(result1, result2, result0, half0, half1, half2);
  pProduct[13] = result1;
  result1 = 0;

  MULT_ADDC1(pFactorA, pFactorA, 7, 7, result2, result0);
  pProduct[14] = result2;
  pProduct[15] = result0;

} /* MATH_SQR8 */

#endif /* ifndef ASM_MATH_8x8_DEFINED */

/*----------------------------------------------------------------------------*/

static MSTATUS MATH_compareValues (
  const vlong_unit *a, 
  const vlong_unit *b, 
  sbyte4 len
  )
{
  while ((1 < len) && (a[len - 1] == b[len - 1]))
    len--;

  return (a[len - 1] == b[len - 1]) ? 0 : ((a[len - 1] > b[len - 1]) ? 1 : -1);
}

/*----------------------------------------------------------------------------*/

static MSTATUS MATH_sumValues (
  vlong_unit *result, 
  const vlong_unit *a, 
  const vlong_unit *b,
  sbyte4 length
  )
{
#ifdef ASM_ADD3
  return ASM_ADD3(result, a, b, length);
#else
  vlong_unit carry = 0;
  vlong_unit temp1;
  vlong_unit temp0;

  if (0 >= length)
    goto exit;

  while (4 <= length)
  {
    temp0 = a[0] + carry;
    carry = (temp0 < carry) ? 1 : 0;
    temp1 = temp0 + b[0];
    carry += (temp1 < temp0) ? 1 : 0;
    result[0] = temp1;

    temp0 = a[1] + carry;
    carry = (temp0 < carry) ? 1 : 0;
    temp1 = temp0 + b[1];
    carry += (temp1 < temp0) ? 1 : 0;
    result[1] = temp1;

    temp0 = a[2] + carry;
    carry = (temp0 < carry) ? 1 : 0;
    temp1 = temp0 + b[2];
    carry += (temp1 < temp0) ? 1 : 0;
    result[2] = temp1;

    temp0 = a[3] + carry;
    carry = (temp0 < carry) ? 1 : 0;
    temp1 = temp0 + b[3];
    carry += (temp1 < temp0) ? 1 : 0;
    result[3] = temp1;

    a += 4;
    b += 4;
    result += 4;
    length -= 4;
  }

  if (0 == length)
    goto exit;

  temp0 = a[0] + carry;
  carry = (temp0 < carry) ? 1 : 0;
  temp1 = temp0 + b[0];
  carry += (temp1 < temp0) ? 1 : 0;
  result[0] = temp1;
  if (0 == --length)
    goto exit;

  temp0 = a[1] + carry;
  carry = (temp0 < carry) ? 1 : 0;
  temp1 = temp0 + b[1];
  carry += (temp1 < temp0) ? 1 : 0;
  result[1] = temp1;
  if (0 == --length)
    goto exit;

  temp0 = a[2] + carry;
  carry = (temp0 < carry) ? 1 : 0;
  temp1 = temp0 + b[2];
  carry += (temp1 < temp0) ? 1 : 0;
  result[2] = temp1;

exit:
  return (sbyte4)carry;

#endif /* ifdef ASM_ADD3 */

} /* MATH_sumValues */

/*----------------------------------------------------------------------------*/

static MSTATUS MATH_subtractValues (
  vlong_unit *result, 
  const vlong_unit *a, 
  const vlong_unit *b,
  sbyte4 length
  )
{
#ifdef ASM_SUB3
  return ASM_SUB3(result, a, b, length);
#else

  sbyte4 carry = 0;
  vlong_unit unitA, unitB;

  if (0 >= length)
    goto exit;

  while (4 <= length)
  {
    unitA = a[0];
    unitB = b[0];
    result[0] = (unitA - unitB - carry);
    if (unitA != unitB)
      carry = (unitA < unitB) ? 1 : 0;

    unitA = a[1];
    unitB = b[1];
    result[1] = (unitA - unitB - carry);
    if (unitA != unitB)
      carry = (unitA < unitB) ? 1 : 0;

    unitA = a[2];
    unitB = b[2];
    result[2] = (unitA - unitB - carry);
    if (unitA != unitB)
      carry = (unitA < unitB) ? 1 : 0;

    unitA = a[3];
    unitB = b[3];
    result[3] = (unitA - unitB - carry);
    if (unitA != unitB)
      carry = (unitA < unitB) ? 1 : 0;

    a += 4;
    b += 4;
    result += 4;
    length -= 4;
  }

  if (0 == length)
    goto exit;

  unitA = a[0];
  unitB = b[0];
  result[0] = (unitA - unitB - carry);
  if (unitA != unitB)
    carry = (unitA < unitB) ? 1 : 0;
  if (0 == --length)
    goto exit;

  unitA = a[1];
  unitB = b[1];
  result[1] = (unitA - unitB - carry);
  if (unitA != unitB)
    carry = (unitA < unitB) ? 1 : 0;
  if (0 == --length)
    goto exit;

  unitA = a[2];
  unitB = b[2];
  result[2] = (unitA - unitB - carry);
  if (unitA != unitB)
    carry = (unitA < unitB) ? 1 : 0;

exit:
  return carry;

#endif /* ifdef ASM_SUB3 */

} /* MATH_subtractValues */

#endif /* ifndef __DISABLE_MOCANA_KARATSUBA__ */
