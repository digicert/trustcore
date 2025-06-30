/**
 * @file  vlong_sub.c
 * @brief Very Long Integer Subtraction Function Implementations
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

#ifndef __DISABLE_MOCANA_VLONG_MATH__

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS subtractUnsignedVlongs (
  vlong *pResultAndValue, 
  const vlong *pValue
  )
{
  MSTATUS status = OK;
#ifdef ASM_SUBTRACT
  /* NOTE: pResultAndValue must be greater than pValue */
  ASM_SUBTRACT(pResultAndValue->pUnits, pValue->pUnits,
               pValue->numUnitsUsed);

#else
  /* NOTE: pResultAndValue must be greater than pValue */
  vlong_unit carry = 0;
  ubyte4 N = pValue->numUnitsUsed;
  ubyte4 i;
  vlong_unit ux, u, nu;

  for (i = 0; i < N; i++)
  {
    ux = pValue->pUnits[i];
    ux += carry;

    if (ux >= carry)
    {
      u = pResultAndValue->pUnits[i];
      nu = u - ux;
      carry = nu > u;

      pResultAndValue->pUnits[i] = nu;
    }
  }

  while ((carry) && (i < pResultAndValue->numUnitsUsed))
  {
    u = pResultAndValue->pUnits[i];
    nu = u - carry;
    carry = nu > u;

    pResultAndValue->pUnits[i] = nu;

    i++;
  }
#endif /* ifdef ASM_SUBTRACT */

  while ((pResultAndValue->numUnitsUsed) && (ZERO_UNIT == pResultAndValue->pUnits[pResultAndValue->numUnitsUsed - 1]))
    pResultAndValue->numUnitsUsed--;

  return status;

} /* subtractUnsignedVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_subtractSignedVlongs (
  vlong *pSumAndValue, 
  const vlong *pValue, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  if (pSumAndValue->negative != pValue->negative)
  {
    status = addUnsignedVlongs(pSumAndValue, pValue);
  }
  else if (0 <= compareUnsignedVlongs(pSumAndValue, pValue))
  {
    status = subtractUnsignedVlongs(pSumAndValue, pValue);
  }
  else
  {
    vlong *pTmpValue = NULL;

    if (OK <= (status = VLONG_makeVlongFromVlong(pSumAndValue, &pTmpValue, ppVlongQueue)))
      if (OK <= (status = VLONG_copySignedValue(pSumAndValue, pValue)))
        status = subtractUnsignedVlongs(pSumAndValue, pTmpValue);

    pSumAndValue->negative = 1 - pSumAndValue->negative;
    VLONG_freeVlong(&pTmpValue, ppVlongQueue);
  }

  return status;

} /* VLONG_subtractSignedVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_subtractImmediate (
  vlong *pThis, 
  ubyte4 immVal, 
  vlong **ppVlongQueue
  )
{
  vlong *pImmVal = NULL;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(immVal, &pImmVal, ppVlongQueue)))
    goto exit;

  status = VLONG_subtractSignedVlongs(pThis, pImmVal, ppVlongQueue);

  VLONG_freeVlong(&pImmVal, ppVlongQueue);

exit:
  return status;

} /* VLONG_subtractImmediate */

/*----------------------------------------------------------------------------*/

#ifdef __ALTIVEC__
MOC_EXTERN MSTATUS operatorMinusSignedVlongs (
  vlong* pValueX, 
  vlong* pValueY, 
  vlong **ppSum, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  if (OK <= (status = VLONG_makeVlongFromVlong(pValueX, ppSum, ppVlongQueue)))
    status = VLONG_subtractSignedVlongs(*ppSum, pValueY, ppVlongQueue);

  return status;

} /* operatorMinusSignedVlongs */

#endif /* ifdef __ALTIVEC__ */
#endif
