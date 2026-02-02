/**
 * @file  vlong_barrett.c
 * @brief Very Long Integer Barrett Function Implementations
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

#if !defined(__DISABLE_DIGICERT_BARRETT__) && !defined(__DISABLE_DIGICERT_VLONG_MATH__)

static MSTATUS VLONG_barrettReduction ( 
  vlong* pResult, 
  const vlong* pX, 
  const vlong* pM,
  const vlong* pMu, 
  vlong** ppVlongQueue
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_barrettMultiply (
  vlong* pResult, 
  const vlong* pX, 
  const vlong* pY,
  const vlong* pM, 
  const vlong* pMu, 
  vlong** ppVlongQueue
  )
{
  MSTATUS status;
  vlong *pProduct = 0;

  if (OK > (status = VLONG_allocVlong(&pProduct, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_unsignedMultiply(pProduct, pX, pY)))
    goto exit;

  if (OK > (status = VLONG_barrettReduction(pResult, pProduct, pM, pMu,
                                            ppVlongQueue)))
  {
    goto exit;
  }

exit:

  VLONG_freeVlong(&pProduct, ppVlongQueue);
  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_barrettReduction ( 
  vlong* pResult, 
  const vlong* pX, 
  const vlong* pM,
  const vlong* pMu, 
  vlong** ppVlongQueue
  )
{
  /*
   * q1 = floor(x / b^(k-1))
   * q2 = q1 * mu
   * q3 = floor(q2 / b^(k+1))
   * r2 = (q3 * m) mod b^(k+1)
   * r1 = x mod b^(k+1)
   * r1  -=  r2
   *
   * if(r1 < 0)
   *   r1 = r1 + b^(k+1)
   * while(r1 >= m)
   *   r1 = r1 - m
   * return r1
   */
  
  vlong *q1 = NULL;
  vlong *q2 = NULL;
  ubyte4 i, j;
  ubyte4 k;
  MSTATUS status;

  /* q1 = floor(x / b^(k-1)) <=>  X shifted right by k-1 units */
  k = pM->numUnitsUsed;

  if (compareUnsignedVlongs(pX, pM) < 0)
  {
    status = VLONG_copySignedValue(pResult, pX);
    goto exit;
  }

  if (OK > (status = VLONG_allocVlong(&q1, ppVlongQueue)) ||
      OK > (status = VLONG_allocVlong(&q2, ppVlongQueue)))
  {
    goto exit;
  }

  if (OK > (status = expandVlong(q1, pX->numUnitsUsed - k + 1)))
    goto exit;

  j = 0;
  for (i = k - 1; i < pX->numUnitsUsed; ++i)
  {
    q1->pUnits[j++] = pX->pUnits[i];
  }
  q1->numUnitsUsed = j;

  /* q2 = q1 * mu */
  if (OK > (status = VLONG_unsignedMultiply(q2, q1, pMu)))
    goto exit;

  /* q3 = floor(q2 / b^(k+1)) <=> q2 shifted right by k+1 units */
  j = 0;
  for (i = k + 1; i < q2->numUnitsUsed; ++i)
  {
    q2->pUnits[j++] = q2->pUnits[i];
  }
  q2->numUnitsUsed = j;

  /* r2 = (q3 * m) mod b^(k+1) <=> multiply and keep only the k+1 least significant units */
  /* reuse q1. */

#ifdef __ENABLE_DIGICERT_BI_MUL_ASM__
  if (OK > (status = fastUnsignedMultiplyVlongs(q1, q2, pM, 2*(k + 1))))
#else
  if (OK > (status = fastUnsignedMultiplyVlongs(q1, q2, pM, k + 1)))
#endif
    goto exit;

  if (q1->numUnitsUsed > k + 1)
    q1->numUnitsUsed = k + 1;

  /* r1 = x mod b^(k+1) r1 = (k+1) least significant units */
  if (OK > (status = expandVlong(pResult, k + 1)))
    goto exit;

  /* sometimes there are less than k+1 least significant units
     copy only significant units, at most k+1 */
  pResult->numUnitsUsed = (pX->numUnitsUsed > k + 1) ? k + 1 : pX->numUnitsUsed;
  for (i = 0; i < pResult->numUnitsUsed; ++i)
  {
    pResult->pUnits[i] = pX->pUnits[i];
  }
  /*  r1 -=  r2  ( remember that q1 = r2 in this code)
        if(r1 < 0)
            r1 = r1 + b^(k+1)
    */
  /* we can't call subtractUnsignedVlongs if pResult < q1 */
  if (compareUnsignedVlongs(pResult, q1) < 0)
  {
    if (OK > (status = VLONG_setVlongUnit(pResult, k + 1, 1)))
      goto exit;
  }
  if (OK > (status = subtractUnsignedVlongs(pResult, q1)))
    goto exit;

  while (compareUnsignedVlongs(pResult, pM) >= 0)
  {
    if (OK > (status = subtractUnsignedVlongs(pResult, pM)))
    {
      goto exit;
    }
  }

exit:

  VLONG_freeVlong(&q1, ppVlongQueue);
  VLONG_freeVlong(&q2, ppVlongQueue);

  return status;

} /* VLONG_barrettReduction */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_newBarrettMu (
  vlong** ppMu, 
  const vlong* m, 
  vlong** ppVlongQueue
  )
{
  /* pMu = floor( (2 ^ digit_size ) ^ (2 * m->numUnitsUsed) / m) */
  vlong *p = NULL;
  vlong *r = NULL;
  vlong *mu = NULL;
  MSTATUS status;

  if (OK > (status = VLONG_allocVlong(&p, ppVlongQueue)) ||
      OK > (status = VLONG_allocVlong(&r, ppVlongQueue)) ||
      OK > (status = VLONG_allocVlong(&mu, ppVlongQueue)))
  {
    goto exit;
  }

  DEBUG_RELABEL_MEMORY(p);
  DEBUG_RELABEL_MEMORY(r);
  DEBUG_RELABEL_MEMORY(mu);

  /* p = 2 ^ (digit_size * 2 * m->numUnitsUsed) */
  if (OK > (status = VLONG_setVlongUnit(p, m->numUnitsUsed * 2, 1)))
    goto exit;

  if (OK > (status = VLONG_unsignedDivide(mu, p, m, r, ppVlongQueue)))
    goto exit;

  *ppMu = mu;
  mu = 0;

exit:

  VLONG_freeVlong(&p, ppVlongQueue);
  VLONG_freeVlong(&r, ppVlongQueue);
  VLONG_freeVlong(&mu, ppVlongQueue);

  return status;

} /* VLONG_newBarrettMu */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_modexp_barrett (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x, 
  const vlong *e,
  const vlong *n, 
  vlong **ppRet, 
  vlong **ppVlongQueue
  )
{
  vlong *result = NULL;
  vlong *tmp = NULL;
  vlong *S = NULL;
  vlong *mu = NULL;
  ubyte4 i, bits;
  MSTATUS status;

  if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &result, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_makeVlongFromVlong(x, &S, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_allocVlong(&tmp, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(tmp);

  if (OK > (status = VLONG_newBarrettMu(&mu, n, ppVlongQueue)))
    goto exit;

  bits = VLONG_bitLength(e);

  i = 0;
  while (1)
  {
    vlong *swap;
    if (VLONG_isVlongBitSet(e, i))
    {
      /* tmp = (result * S) mod n */
      if (OK > (status = VLONG_barrettMultiply(tmp, result, S, n, mu, ppVlongQueue)))
        goto exit;

      swap = result;
      result = tmp;
      tmp = swap;
    }

    i++;

    if (i == bits)
      break;

    /* tmp = (S * S)  mod n*/
    if (OK > (status = VLONG_barrettMultiply(tmp, S, S, n, mu, ppVlongQueue)))
      goto exit;

    swap = S;
    S = tmp;
    tmp = swap;
  }

  *ppRet = result;
  result = 0;

exit:
  VLONG_freeVlong(&result, ppVlongQueue);
  VLONG_freeVlong(&tmp, ppVlongQueue);
  VLONG_freeVlong(&S, ppVlongQueue);
  VLONG_freeVlong(&mu, ppVlongQueue);

  DIGICERT_YIELD_PROCESSOR();

  return status;

} /* VLONG_modexp_barrett */

#endif /* ifndef __DISABLE_DIGICERT_BARRETT__ */
