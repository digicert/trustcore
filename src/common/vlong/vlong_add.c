/**
 * @file  vlong_add.c
 * @brief Very Long Integer Addition Function Implementations
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

#ifndef __DISABLE_MOCANA_VLONG_MATH__

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS addUnsignedVlongs (
  vlong *pSumAndValue,
  const vlong *pValue
  )
{
  vlong_unit u, carry = 0;
  ubyte4 i;
  MSTATUS status = OK;

#ifdef ASM_ADD
  if (pSumAndValue->numUnitsUsed >= pValue->numUnitsUsed)
  {
    carry = ASM_ADD(pSumAndValue->pUnits,
                    pValue->pUnits,
                    pValue->numUnitsUsed);
    /* handle carry */
    i = pValue->numUnitsUsed;

    while (carry)
    {
      u = VLONG_getVlongUnit(pSumAndValue, i);
      u += carry;
      carry = (u < carry) ? 1 : 0;

      if (OK > (status = VLONG_setVlongUnit(pSumAndValue, i, u)))
        break;
      i++;
    }
  }
  else
  {
    ubyte4 max = pValue->numUnitsUsed;

    if (OK <= (status = VLONG_reallocVlong(pSumAndValue, max + 1)))
    {
      for (i = pSumAndValue->numUnitsUsed;
           i < pSumAndValue->numUnitsAllocated;
           ++i)
      {
        pSumAndValue->pUnits[i] = 0;
      }

      pSumAndValue->numUnitsUsed = max;

      carry = ASM_ADD(pSumAndValue->pUnits,
                      pValue->pUnits,
                      pValue->numUnitsUsed);
      if (carry)
      {
        if (OK > (status = VLONG_setVlongUnit(pSumAndValue,
                                              max, carry)))
        {
          return status;
        }
      }
    }
  }

#else /* ifdef ASM_ADD */
  if (pSumAndValue->numUnitsUsed >= pValue->numUnitsUsed)
  {
    vlong_unit ux;

    for (i = 0; i < pValue->numUnitsUsed; i++)
    {
      u = pSumAndValue->pUnits[i];
      u = u + carry;
      carry = (u < carry) ? 1 : 0;

      ux = pValue->pUnits[i];
      u = u + ux;
      carry += ((u < ux) ? 1 : 0);

      pSumAndValue->pUnits[i] = u;
    }

    /* handle carry */
    while (carry)
    {
      u = VLONG_getVlongUnit(pSumAndValue, i);
      u = u + carry;
      carry = (u < carry) ? 1 : 0;

      if (OK > (status = VLONG_setVlongUnit(pSumAndValue, i, u)))
        break;
      ++i;
    }
  }
  else
  {
    ubyte4 max = pValue->numUnitsUsed;
    vlong_unit ux;

    if (OK <= (status = VLONG_reallocVlong(pSumAndValue, max + 1)))
    {
      for (i = 0; i < max + 1; i++)
      {
        u = VLONG_getVlongUnit(pSumAndValue, i);
        u = u + carry;
        carry = (u < carry) ? 1 : 0;

        ux = VLONG_getVlongUnit(pValue, i);
        u = u + ux;
        carry += ((u < ux) ? 1 : 0);

        if (OK > (status = VLONG_setVlongUnit(pSumAndValue, i, u)))
          break;
      }
    }
  }
#endif /* ifdef ASM_ADD */

  return status;

} /* addUnsignedVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_addSignedVlongs (
  vlong *pSumAndValue,
  const vlong *pValue,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  if (pSumAndValue->negative == pValue->negative)
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

    VLONG_freeVlong(&pTmpValue, ppVlongQueue);
  }

  return status;

} /* VLONG_addSignedVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_addImmediate (
  vlong *pThis,
  ubyte4 immVal,
  vlong **ppVlongQueue
  )
{
  vlong *pImmVal = NULL;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(immVal, &pImmVal, ppVlongQueue)))
    goto exit;

  status = VLONG_addSignedVlongs(pThis, pImmVal, ppVlongQueue);

  VLONG_freeVlong(&pImmVal, ppVlongQueue);

exit:
  return status;

} /* VLONG_addImmediate */

#endif
