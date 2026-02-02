/**
 * @file  vlong_modexp.c
 * @brief Very Long Integer Modular Exponentiation Function Implementations
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

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_modExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) CModExpHelper meh,  
  const vlong *x, 
  const vlong *e,
  vlong **ppRetModExp, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  if (VLONG_isVlongZero(x))
  {
    status = VLONG_allocVlong(ppRetModExp, ppVlongQueue);
    if (NULL != ppRetModExp)
    {
      DEBUG_RELABEL_MEMORY(*ppRetModExp);
    }
    goto exit;
  }

  if (VLONG_isVlongZero(e))
  {
    status = VLONG_makeVlongFromUnsignedValue(1, ppRetModExp, ppVlongQueue);
    goto exit;
  }

#ifdef __DISABLE_DIGICERT_MODEXP_SLIDING_WINDOW__
  status = VLONG_montgomeryExpBin(MOC_MOD(hwAccelCtx) meh, x, e,
                                  ppRetModExp, ppVlongQueue);
#else
  status = VLONG_montgomeryExp(MOC_MOD(hwAccelCtx) meh, x, e,
                               ppRetModExp, ppVlongQueue);
#endif
exit:

  return status;

} /* VLONG_modExp */

/*----------------------------------------------------------------------------*/

#ifndef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

MOC_EXTERN MSTATUS VLONG_modexp (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x, 
  const vlong *e,
  const vlong *n, 
  vlong **ppRet, 
  vlong **ppVlongQueue
  )
{
/* value to switch to montgomery -- assuming exponent has half of bits sets */
#define USE_MONTY_LIMIT (2)

  if ((NULL == x) || (NULL == e) || (NULL == n) || (NULL == ppRet))
  {
    return ERR_NULL_POINTER;
  }

  if (VLONG_isVlongZero(n))
  {
    return ERR_BAD_MODULO;
  }

  if (VLONG_isVlongZero(x))
  {
    MSTATUS status = VLONG_allocVlong(ppRet, ppVlongQueue);

    if (NULL != ppRet)
    {
      DEBUG_RELABEL_MEMORY(*ppRet);
    }
    
    return status;
  }

  if (VLONG_isVlongZero(e))
  {
    return VLONG_makeVlongFromUnsignedValue(1, ppRet, ppVlongQueue);
  }
  if ((n->pUnits[0] & 1) && e->numUnitsUsed >= USE_MONTY_LIMIT)
  {
    return VLONG_modexp_montgomery(MOC_MOD(hwAccelCtx) x, e, n, ppRet, ppVlongQueue);
  }
  else
  {
#if defined(__DISABLE_DIGICERT_BARRETT__)
    return VLONG_modexp_classic(MOC_MOD(hwAccelCtx) x, e, n, ppRet,
                                ppVlongQueue);
#else
    return VLONG_modexp_barrett(MOC_MOD(hwAccelCtx) x, e, n, ppRet,
                                ppVlongQueue);
#endif
  }
} /* VLONG_modexp */

/*----------------------------------------------------------------------------*/

#if defined(__DISABLE_DIGICERT_BARRETT__) || defined(__ENABLE_DIGICERT_MODEXP_CLASSIC__)

MOC_EXTERN MSTATUS VLONG_modexp_classic (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x, 
  const vlong *e,
  const vlong *n, 
  vlong **ppRet, 
  vlong **ppVlongQueue
  )
{
  vlong *result = NULL;
  vlong *t = NULL;
  vlong *tmp = NULL;
  vlong *S = NULL;
  ubyte4 i, bits, N;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &result, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_makeVlongFromVlong(x, &S, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_allocVlong(&tmp, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_allocVlong(&t, ppVlongQueue)))
    goto exit;

  bits = VLONG_bitLength(e);
  N = VLONG_bitLength(n);
  i = 0;
  while (1)
  {
    if (VLONG_isVlongBitSet(e, i))
    {
      /* tmp = result * S */
      if (OK > (status = VLONG_FAST_MULT(tmp, result, S, 2 * N)))
        goto exit;

      /* result = tmp % n */
      if (OK > (status = VLONG_unsignedDivide(t, tmp, n, result, ppVlongQueue)))
        goto exit;
    }

    i++;

    if (i == bits)
      break;

    /* tmp = S * S */
    if (OK > (status = VLONG_FAST_SQR(tmp, S, 2 * N)))
      goto exit;

    /* S = tmp % n */
    if (OK > (status = VLONG_unsignedDivide(t, tmp, n, S, ppVlongQueue)))
      goto exit;
  }

  *ppRet = result;
  result = 0;

exit:
  VLONG_freeVlong(&result, ppVlongQueue);
  VLONG_freeVlong(&t, ppVlongQueue);
  VLONG_freeVlong(&tmp, ppVlongQueue);
  VLONG_freeVlong(&S, ppVlongQueue);

  DIGICERT_YIELD_PROCESSOR();

  return status;

} /* VLONG_modexp_classic */

#endif  /* __DISABLE_DIGICERT_BARRETT__ || __ENABLE_DIGICERT_MODEXP_CLASSIC__ */

#endif /* __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */
#endif /* __DISABLE_DIGICERT_VLONG_MATH__ */
