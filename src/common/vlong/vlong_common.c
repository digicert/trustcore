/**
 * @file  vlong_common.c
 * @brief Very Long Integer Common Function Implementations
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
/*----------------------------------------------------------------------------*/

 MOC_EXTERN MSTATUS VLONG_allocVlong (
  vlong **ppRetVlongValue,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = OK;

  if (NULL == ppRetVlongValue)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if ((NULL == ppVlongQueue) || (NULL == *ppVlongQueue))
  {
    if (NULL == (*ppRetVlongValue = (vlong *)MALLOC(sizeof(vlong))))
    {
      status = ERR_MEM_ALLOC_FAIL;
      goto exit;
    }
    else
    {
      /* status = MOC_MEMSET((ubyte *)(*ppRetVlongValue), 0x00, sizeof(vlong)); */
      (*ppRetVlongValue)->numUnitsAllocated = 0;
      (*ppRetVlongValue)->pUnits = NULL;
    }
  }
  else
  {
    *ppRetVlongValue = *ppVlongQueue;            /* remove head of list */
    *ppVlongQueue = (*ppVlongQueue)->pNextVlong; /* adjust head of list */
  }

  (*ppRetVlongValue)->negative = 0;
  (*ppRetVlongValue)->numUnitsUsed = 0;
  (*ppRetVlongValue)->pNextVlong = NULL;

exit:
  return status;

} /* VLONG_allocVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_freeVlong (
  vlong **ppFreeVlong,
  vlong **ppVlongQueue
  )
{
  sbyte4 i;
  MSTATUS status = OK;

  if ((NULL == ppFreeVlong) || (NULL == *ppFreeVlong))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (NULL == ppVlongQueue)
  {
    if (NULL != (*ppFreeVlong)->pUnits)
    {
#ifdef __ZEROIZE_TEST__
      FIPS_PRINT("\nVlong Unit - Before Zeroization\n");

      i = (*ppFreeVlong)->numUnitsAllocated;

      /* clear vlong memory */
      while (i)
      {
        i--;
        FIPS_PRINT(" %d", (*ppFreeVlong)->pUnits[i]);
      }

      FIPS_PRINT("\n");
#endif

      i = (*ppFreeVlong)->numUnitsAllocated;

      /* clear vlong memory */
      while (i)
      {
        i--;
        (*ppFreeVlong)->pUnits[i] = 0x00;
      }

#ifdef __ZEROIZE_TEST__
      FIPS_PRINT("\nVlong Unit - After Zeroization\n");

      i = (*ppFreeVlong)->numUnitsAllocated;

      /* clear vlong memory */
      while (i)
      {
        i--;
        FIPS_PRINT(" %d", (*ppFreeVlong)->pUnits[i]);
      }

      FIPS_PRINT("\n");
#endif

      UNITS_FREE(((void **)&((*ppFreeVlong)->pUnits)));
    }

    FREE(*ppFreeVlong);
  }
  else
  {
    /* add released vlong to head of vlong queue */
    (*ppFreeVlong)->pNextVlong = *ppVlongQueue;
    *ppVlongQueue = *ppFreeVlong;
  }

  /* clear pointer */
  *ppFreeVlong = NULL;

exit:
  return status;

} /* VLONG_freeVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_freeVlongQueue (
  vlong **ppVlongQueue
  )
{
  vlong *pVlong;

  if (NULL != ppVlongQueue)
  {
    while (NULL != (pVlong = *ppVlongQueue))
    {
      *ppVlongQueue = pVlong->pNextVlong;
      VLONG_freeVlong(&pVlong, NULL);
    }
  }

  return OK;

} /* VLONG_freeVlongQueue */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_reallocVlong (
  vlong *pThis,
  ubyte4 vlongNewLength
  )
{
  MSTATUS status = OK;

  if (VLONG_MAX_LENGTH < vlongNewLength)
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }

  if (vlongNewLength > pThis->numUnitsAllocated)
  {
    vlong_unit *pNewArrayUnits;
    ubyte4 index;

    vlongNewLength += 3;
#if defined(__ALTIVEC__) || defined(__SSE2__)
    vlongNewLength = MOC_PAD(vlongNewLength, 4);
#elif defined(__ARM_NEON__) || defined(__ARM_V6__)
    vlongNewLength = MOC_PAD(vlongNewLength, 2);
#endif

    status = UNITS_MALLOC(
        ((void **)&pNewArrayUnits), (vlongNewLength * sizeof(vlong_unit)));
    if (OK != status)
      goto exit;

    for (index = 0; index < pThis->numUnitsUsed; index++)
      pNewArrayUnits[index] = pThis->pUnits[index];

    if (NULL != pThis->pUnits)
      UNITS_FREE(((void **)&(pThis->pUnits)));

    pThis->pUnits = pNewArrayUnits;
    pThis->numUnitsAllocated = vlongNewLength;
  }

exit:
  return status;

} /* VLONG_reallocVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS expandVlong (
  vlong *pThis,
  ubyte4 vlongNewLength
  )
{
  MSTATUS status = OK;

  if (VLONG_MAX_LENGTH < vlongNewLength)
  {
    status = ERR_BAD_LENGTH;
    goto exit;
  }

  if (vlongNewLength > pThis->numUnitsAllocated)
  {
    vlong_unit *pNewArrayUnits;

    vlongNewLength += 1;
#if defined(__ALTIVEC__) || defined(__SSE2__)
    vlongNewLength = MOC_PAD(vlongNewLength, 4);
#elif defined(__ARM_NEON__) || defined(__ARM_V6__)
    vlongNewLength = MOC_PAD(vlongNewLength, 2);
#endif

    status = UNITS_MALLOC(
        ((void **)&pNewArrayUnits), (vlongNewLength * sizeof(vlong_unit)));
    if (OK != status)
      goto exit;

    if (NULL != pThis->pUnits)
      UNITS_FREE(((void **)&(pThis->pUnits)));

    pThis->pUnits = pNewArrayUnits;
    pThis->numUnitsAllocated = vlongNewLength;
    pThis->numUnitsUsed = 0;
  }

exit:
  return status;

} /* expandVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN vlong_unit VLONG_getVlongUnit (
  const vlong *pThis,
  ubyte4 index
  )
{
  vlong_unit result = 0;

  if (index < pThis->numUnitsUsed)
    if (NULL != pThis->pUnits)
      result = pThis->pUnits[index];

  return result;

} /* VLONG_getVlongUnit */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_setVlongUnit (
  vlong *pThis, 
  ubyte4 index, 
  vlong_unit unitValue
  )
{
  MSTATUS status = OK;

  if (NULL == pThis)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  if (index < pThis->numUnitsUsed)
  {
    pThis->pUnits[index] = unitValue;

    /* remove leading zeros */
    if (ZERO_UNIT == unitValue)
      while ((pThis->numUnitsUsed) && (ZERO_UNIT == pThis->pUnits[pThis->numUnitsUsed - 1]))
        pThis->numUnitsUsed--;
  }
  else if (unitValue)
  {
    ubyte4 j;

    if (OK > (status = VLONG_reallocVlong(pThis, index + 1)))
      goto exit;

    for (j = pThis->numUnitsUsed; j < index; j++)
      pThis->pUnits[j] = 0;

    pThis->pUnits[index] = unitValue;
    pThis->numUnitsUsed = index + 1;
  }

exit:
  return status;

} /* VLONG_setVlongUnit */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_clearVlong (
  vlong *pThis
  )
{
  MSTATUS status = OK;

  if (NULL == pThis)
    status = ERR_NULL_POINTER;
  else
  {
    pThis->numUnitsUsed = 0;
    pThis->negative = FALSE;
  }

  return status;

} /* VLONG_clearVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN intBoolean VLONG_isVlongZero (
  const vlong *pThis
  )
{
  return (0 == pThis->numUnitsUsed) ? TRUE : FALSE;
} /* VLONG_isVlongZero */

/*----------------------------------------------------------------------------*/

MOC_EXTERN intBoolean VLONG_isVlongBitSet (
  const vlong *pThis,
  ubyte4 testBit
  )
{
  return (ZERO_UNIT !=
         (VLONG_getVlongUnit(pThis, testBit/BPU) &
         (((vlong_unit)1)<<(testBit%BPU)))) ? TRUE : FALSE;
} /* VLONG_isVlongBitSet */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_setVlongBit (
  vlong *pThis, 
  ubyte4 setBit
  )
{
  vlong_unit unit = VLONG_getVlongUnit(pThis, setBit / BPU);

  unit |= (((vlong_unit)1) << (setBit % BPU));

  return VLONG_setVlongUnit(pThis, setBit / BPU, unit);

} /* VLONG_setVlongBit */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS assignUnsignedToVlong (
  vlong *pThis, 
  vlong_unit x
  )
{
  MSTATUS status;

  if (OK <= (status = VLONG_clearVlong(pThis)))
    status = VLONG_setVlongUnit(pThis, 0, x);

  return status;

} /* assignUnsignedToVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS copyUnsignedValue (
  vlong *pDest, 
  const vlong *pSource
  )
{
  sbyte4 numUnits;
  MSTATUS status;

  if ((NULL == pDest) || (NULL == pSource))
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  VLONG_clearVlong(pDest);
  numUnits = pSource->numUnitsUsed;

  if (OK > (status = VLONG_reallocVlong(pDest, numUnits)))
    goto exit;

  pDest->numUnitsUsed = numUnits;

  while (numUnits)
  {
    numUnits--;

    pDest->pUnits[numUnits] = pSource->pUnits[numUnits];
  }

exit:
  return status;

} /* copyUnsignedValue */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_copySignedValue (
  vlong *pDest, 
  const vlong *pSource
  )
{
  MSTATUS status;

  if (OK <= (status = copyUnsignedValue(pDest, pSource)))
    pDest->negative = pSource->negative;

  return status;

} /* VLONG_copySignedValue */

/*----------------------------------------------------------------------------*/

MOC_EXTERN ubyte4 VLONG_bitLength (
  const vlong *pThis
  )
{
  ubyte4 numBits;

  if (0 != (numBits = pThis->numUnitsUsed))
  {
    numBits--;
    numBits *= BPU;
    numBits += BITLENGTH(pThis->pUnits[pThis->numUnitsUsed - 1]);
  }

  return numBits;

} /* VLONG_copySignedValue */

/*----------------------------------------------------------------------------*/

#ifdef ASM_BIT_LENGTH
MOC_EXTERN ubyte4 BITLENGTH (
  vlong_unit w
  )
{
  vlong_unit bitlen;
  ASM_BIT_LENGTH(w, bitlen);
  return (ubyte4)bitlen;
} /* BITLENGTH */

#else

#ifdef __ENABLE_MOCANA_64_BIT__
MOC_EXTERN ubyte4 BITLENGTH (
  vlong_unit w
  )
{
  ubyte4 hi = (ubyte4)HI_HUNIT(w);
  return (hi) ? 32 + MOC_BITLENGTH(hi) : MOC_BITLENGTH((ubyte4)LO_HUNIT(w));
} /* BITLENGTH */

#endif /* ifdef __ENABLE_MOCANA_64_BIT__ */
#endif /* ifdef ASM_BIT_LENGTH */
