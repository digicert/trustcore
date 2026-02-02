/**
 * @file  vlong_shift.c
 * @brief Very Long Integer Bitshift Function Implementations
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

#ifndef __DISABLE_DIGICERT_VLONG_MATH__

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

#ifndef ASM_SHIFT_LEFT_DEFINED

 MOC_EXTERN MSTATUS shlVlong (
  vlong *pThis
  )
{
  vlong_unit carry = 0;
  ubyte4 N = pThis->numUnitsUsed; /* necessary, since numUnitsUsed can change */
  ubyte4 i = 0;
  MSTATUS status = OK;

#ifndef MACRO_SHIFT_LEFT
  while (i < N)
  {
    vlong_unit u;

    u = pThis->pUnits[i];
    pThis->pUnits[i] = (u << 1) | carry;

    carry = u >> (BPU - 1);
    i++;
  }

#else
  carry = MACRO_SHIFT_LEFT(pThis->pUnits, N);

  i = N;
#endif

  if (ZERO_UNIT == carry)
  {
    while ((pThis->numUnitsUsed) && (ZERO_UNIT == pThis->pUnits[pThis->numUnitsUsed - 1]))
      pThis->numUnitsUsed--;
  }
  else
  {
    status = VLONG_setVlongUnit(pThis, i, carry);
  }

  return status;

} /* shlVlong */

#endif /* ifndef ASM_SHIFT_LEFT_DEFINED */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_shlVlong (
  vlong *pThis
  )
{
  MSTATUS status = OK;

  if (NULL == pThis)
    status = ERR_NULL_POINTER;
  else
    status = shlVlong(pThis);

  return status;

} /* VLONG_shlVlong */

/*----------------------------------------------------------------------------*/

#ifndef ASM_SHIFT_RIGHT_DEFINED

MOC_EXTERN void shrVlong (
  vlong *pThis
  )
{
#ifndef MACRO_SHIFT_RIGHT
  vlong_unit carry = 0;
  sbyte4 i = pThis->numUnitsUsed;
  vlong_unit u;

  while (i)
  {
    i--;

    u = pThis->pUnits[i];
    pThis->pUnits[i] = ((u >> 1) | carry);

    carry = u << (BPU - 1);
  }
#else
  MACRO_SHIFT_RIGHT(pThis->pUnits, pThis->numUnitsUsed);
#endif

  /* remove leading zeros */
  while ((pThis->numUnitsUsed) && (ZERO_UNIT == pThis->pUnits[pThis->numUnitsUsed - 1]))
    pThis->numUnitsUsed--;

} /* shrVlong */

#endif /* ifndef ASM_SHIFT_RIGHT_DEFINED */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_shrVlong (
  vlong *pThis
  )
{
  MSTATUS status = OK;

  if (NULL == pThis)
    status = ERR_NULL_POINTER;
  else
    shrVlong(pThis);

  return status;

} /* VLONG_shrVlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_shrXvlong (
  vlong *pThis, 
  ubyte4 numBits
  )
{
  sbyte4 delta;
  sbyte4 i, i_limit;
  vlong_unit u;
  MSTATUS status = OK;

  if (0 == numBits)
    goto exit;

  delta = numBits / BPU;

  if (delta >= (sbyte4)pThis->numUnitsUsed)
  {
    pThis->numUnitsUsed = 0;
    goto exit;
  }

  numBits %= BPU;

  i_limit = ((sbyte4)pThis->numUnitsUsed) - delta - 1;

  for (i = 0; i < i_limit; i++)
  {
    u = pThis->pUnits[i + delta];

    if (numBits)
    {
      u >>= numBits;
      u |= ((vlong_unit)pThis->pUnits[i + delta + 1]) << (BPU - numBits);
    }

    pThis->pUnits[i] = u;
  }

  /* handle highest unit */
  u = pThis->pUnits[i + delta];

  if (numBits)
    u >>= numBits;

  pThis->pUnits[i] = u;

  pThis->numUnitsUsed -= delta;

  /* adjust top */
  while ((pThis->numUnitsUsed) && (ZERO_UNIT == pThis->pUnits[pThis->numUnitsUsed - 1]))
    pThis->numUnitsUsed--;

exit:
  return status;

} /* VLONG_shrXvlong */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_shlXvlong (
  vlong *pThis, 
  ubyte4 numBits
  )
{
  ubyte4 delta;
  sbyte4 i;
  vlong_unit u, u1;
  MSTATUS status = OK;

  /* nothing to do */
  if ((0 == numBits) || (0 == pThis->numUnitsUsed))
    goto exit;

  delta = numBits / BPU;
  numBits %= BPU;

  if ((pThis->numUnitsUsed + delta + 1) > pThis->numUnitsAllocated)
    if (OK > (status = VLONG_reallocVlong(pThis, pThis->numUnitsUsed + delta + 1)))
      goto exit;

  /* zero out new space */
  for (i = pThis->numUnitsUsed; i < (sbyte4)(pThis->numUnitsUsed + delta + 1); i++)
    pThis->pUnits[i] = 0x00;

  for (i = pThis->numUnitsUsed - 1; i >= 0; i--)
  {
    /* handle upper portion */
    u = pThis->pUnits[i];
    u1 = pThis->pUnits[i + delta + ((numBits) ? 1 : 0)];

    u1 |= ((0 != numBits) ? u >> (BPU - numBits) : (u));
    pThis->pUnits[i + delta + ((numBits) ? 1 : 0)] = u1;

    /* clear it */
    pThis->pUnits[i] = 0;

    /* handle lower portion*/
    if (numBits)
    {
      u <<= numBits;
      pThis->pUnits[i + delta] = u;
    }
  }

  /* fix top */
  pThis->numUnitsUsed += delta + ((numBits) ? 1 : 0);

  while ((pThis->numUnitsUsed) && (ZERO_UNIT == pThis->pUnits[pThis->numUnitsUsed - 1]))
    pThis->numUnitsUsed--;

exit:
  return status;

} /* VLONG_shlXvlong */
#endif
