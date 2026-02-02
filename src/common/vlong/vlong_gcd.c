/**
 * @file  vlong_gcd.c
 * @brief Very Long Integer Greatest Common Denominator Function Implementation
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

#ifndef __DISABLE_DIGICERT_VLONG_MATH__

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_greatestCommonDenominator (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *pValueX,
  const vlong *pValueY, 
  vlong **ppGcd, 
  vlong **ppVlongQueue
  )
{
  vlong *pTempX = NULL;
  vlong *pTempY = NULL;
  ubyte4 shift = 0;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromVlong(pValueX, &pTempX, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_makeVlongFromVlong(pValueY, &pTempY, ppVlongQueue)))
    goto exit;

  if (TRUE == VLONG_isVlongZero(pTempX))
  {
    *ppGcd = pTempY;
    pTempY = NULL;
    goto exit;
  }

  if (TRUE == VLONG_isVlongZero(pTempY))
  {
    *ppGcd = pTempX;
    pTempX = NULL;
    goto exit;
  }

  /* while both numbers are even shift right */
  while ((FALSE == VLONG_isVlongBitSet(pTempX, 0)) && (FALSE == VLONG_isVlongBitSet(pTempY, 0)))
  {
    if (OK > (status = VLONG_shrVlong(pTempX)))
      goto exit;

    if (OK > (status = VLONG_shrVlong(pTempY)))
      goto exit;

    shift++;
  }

  /* make sure x is odd */
  while (FALSE == VLONG_isVlongBitSet(pTempX, 0))
    if (OK > (status = VLONG_shrVlong(pTempX)))
      goto exit;

  do
  {
    /* make sure y is odd */
    while (FALSE == VLONG_isVlongBitSet(pTempY, 0))
      if (OK > (status = VLONG_shrVlong(pTempY)))
        goto exit;

    if (VLONG_compareSignedVlongs(pTempX, pTempY) > 0)
    {
      /* swap, if x > y */
      vlong *pTemp = pTempX;
      pTempX = pTempY;
      pTempY = pTemp;
    }

    if (OK > (status = VLONG_subtractSignedVlongs(pTempY, pTempX, ppVlongQueue)))
      goto exit;
  } while (FALSE == VLONG_isVlongZero(pTempY));

  /* multiple by common factors of 2 */
  if (OK > (status = VLONG_shlXvlong(pTempX, shift)))
    goto exit;

  /* return result */
  *ppGcd = pTempX;
  pTempX = NULL;

exit:
  VLONG_freeVlong(&pTempX, ppVlongQueue);
  VLONG_freeVlong(&pTempY, ppVlongQueue);

  return status;

} /* VLONG_greatestCommonDenominator */
#endif
