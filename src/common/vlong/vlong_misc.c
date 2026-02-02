/**
 * @file  vlong_misc.c
 * @brief Very Long Integer Miscellaneous Function Implementations
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

MOC_EXTERN MSTATUS VLONG_N_mod_2powX (
  vlong *pThis,
  ubyte4 X
  )
{
  vlong_unit unit;
  ubyte4 newNumUnitsUsed;
  MSTATUS status = OK;

  if (NULL == pThis)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  /* 2^0 == 1; (N mod 1) always equals zero */
  if (0 == X)
  {
    status = VLONG_clearVlong(pThis);
    goto exit;
  }

  /* 2^N: we want to keep the lowest N bits only */
  newNumUnitsUsed = ((X + BPU - 1) / BPU);
  if (pThis->numUnitsUsed > newNumUnitsUsed)
    pThis->numUnitsUsed = newNumUnitsUsed;

  unit = VLONG_getVlongUnit(pThis, (X - 1) / BPU);

  if (X % BPU)
    unit &= ((((vlong_unit)1) << (X % BPU)) - 1);

  /* in-case we have leading zeros to adjust numUnitsUsed */
  status = VLONG_setVlongUnit(pThis, (X - 1) / BPU, unit);

exit:
  return status;

} /* VLONG_N_mod_2powX */

/*----------------------------------------------------------------------------*/

#ifndef __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__

MOC_EXTERN MSTATUS VLONG_operatorModSignedVlongs (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong* pDividend,
  const vlong* pDivisor,
  vlong **ppRemainder,
  vlong **ppVlongQueue
  )
{
  vlong *pQuotient = NULL;
  vlong *pRemainder = NULL;
  MSTATUS status;

  if (NULL == ppRemainder)
    return ERR_NULL_POINTER;

  if (OK > (status = VLONG_allocVlong(&pRemainder, ppVlongQueue)))
  {
    goto exit;
  }

  DEBUG_RELABEL_MEMORY(pRemainder);

  if (OK > (status = VLONG_allocVlong(&pQuotient, ppVlongQueue)))
  {
    goto exit;
  }

  DEBUG_RELABEL_MEMORY(pQuotient);

  if (OK > (status = VLONG_unsignedDivide(pQuotient, pDividend, pDivisor, pRemainder, ppVlongQueue)))
  {
    goto exit;
  }

  pRemainder->negative = pDividend->negative; /* this is correct */

  *ppRemainder = pRemainder;
  pRemainder = NULL;

exit:

  VLONG_freeVlong(&pRemainder, ppVlongQueue);
  VLONG_freeVlong(&pQuotient, ppVlongQueue);

  return status;

} /* VLONG_operatorModSignedVlongs */

#endif /* __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_increment (
  vlong *pThis,
  vlong **ppVlongQueue
  )
{
  vlong *pOne = NULL;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pOne, ppVlongQueue)))
    goto exit;

  status = VLONG_addSignedVlongs(pThis, pOne, ppVlongQueue);

  VLONG_freeVlong(&pOne, ppVlongQueue);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_decrement (
  vlong *pThis,
  vlong **ppVlongQueue
  )
{
  vlong *pOne = NULL;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pOne, ppVlongQueue)))
    goto exit;

  status = VLONG_subtractSignedVlongs(pThis, pOne, ppVlongQueue);

exit:
  VLONG_freeVlong(&pOne, ppVlongQueue);

  return status;
}
#endif
