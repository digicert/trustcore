/**
 * @file  vlong_cmp.c
 * @brief Very Long Integer Comparison Function Implementations
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

 MOC_EXTERN MSTATUS compareUnsignedVlongs (
  const vlong *pValueX, 
  const vlong *pValueY
  )
{
  sbyte4 i;
  sbyte4 result = 0;

  if (pValueX->numUnitsUsed > pValueY->numUnitsUsed)
  {
    result = 1;
    goto exit;
  }

  if (pValueX->numUnitsUsed < pValueY->numUnitsUsed)
  {
    result = -1;
    goto exit;
  }

  i = pValueX->numUnitsUsed;

  while (i)
  {
    i--;

    if (pValueX->pUnits[i] > pValueY->pUnits[i])
    {
      result = 1;
      goto exit;
    }

    if (pValueX->pUnits[i] < pValueY->pUnits[i])
    {
      result = -1;
      goto exit;
    }
  }

exit:
  return result;

} /* compareUnsignedVlongs */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_compareUnsigned (
  const vlong* pTest, 
  vlong_unit immValue
  )
{
  sbyte4 result;

  if (pTest->negative)
    result = -1; /* unsigned value is greater */
  else if (1 < pTest->numUnitsUsed)
    result = 1; /* vlong is greater */
  else if (0 == pTest->numUnitsUsed)
  {
    if (ZERO_UNIT == immValue)
      result = 0; /* both values are zero */
    else
      result = -1; /* unsigned value is greater */
  }
  else
  {
    if (pTest->pUnits[0] == immValue)
      result = 0; /* both values are equal */
    else if (pTest->pUnits[0] > immValue)
      result = 1; /* vlong is greater */
    else
      result = -1; /* unsigned value is greater */
  }

  return result;

} /* VLONG_compareUnsigned */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_compareSignedVlongs (
  const vlong *pValueX, 
  const vlong* pValueY
  )
{
  /* X == Y = 0; X > Y == +1; X < Y == -1*/
  sbyte4 neg = (pValueX->negative && !VLONG_isVlongZero(pValueX)) ? TRUE : FALSE;
  sbyte4 retValue;

  if (neg == ((pValueY->negative && !VLONG_isVlongZero(pValueY)) ? TRUE : FALSE))
  {
    retValue = compareUnsignedVlongs(pValueX, pValueY);
    if (neg)
    {
      retValue = -retValue;
    }
  }
  else if (neg)
  {
    retValue = -1;
  }
  else
  {
    retValue = 1;
  }
  return retValue;

} /* VLONG_compareSignedVlongs */
#endif
