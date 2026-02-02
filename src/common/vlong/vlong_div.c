/**
 * @file  vlong_div.c
 * @brief Very Long Integer Division Function Implementations
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

static vlong_unit VLONG_DoubleDiv (
  vlong_unit hi, 
  vlong_unit lo, 
  vlong_unit d
  );

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_unsignedDivide (
  vlong *pQuotient, 
  const vlong *pDividend, 
  const vlong *pDivisor,
  vlong *pRemainder, 
  vlong **ppVlongQueue
  )
{
  vlong *pY = NULL;
  vlong *pYBnt = NULL;
  ubyte4 normShift;
  sbyte4 n, t;
  sbyte4 i, j;
  vlong_unit *q, *x, *y;
  MSTATUS status;

  if (VLONG_isVlongZero(pDivisor))
  {
    status = ERR_DIVIDE_BY_ZERO;
    goto exit;
  }

  if (OK > (status = copyUnsignedValue(pRemainder, pDividend)))
    goto exit;

  if (compareUnsignedVlongs(pDividend, pDivisor) < 0)
  {
    status = assignUnsignedToVlong(pQuotient, 0);
    goto exit;
  }

  if (OK > (status = VLONG_makeVlongFromVlong(pDivisor, &pY, ppVlongQueue)))
    goto exit;

  /* normalize */
  normShift = BPU - BITLENGTH(pY->pUnits[pY->numUnitsUsed - 1]);

  if (OK > (status = VLONG_shlXvlong(pRemainder, normShift)) ||
      OK > (status = VLONG_shlXvlong(pY, normShift)))
  {
    goto exit;
  }
  n = ( (sbyte4) (pRemainder->numUnitsUsed - 1) );
  t = ( (sbyte4) (pY->numUnitsUsed - 1) );

  if (OK > (status = expandVlong(pQuotient, n - t + 1)))
    goto exit;
  pQuotient->numUnitsUsed = n - t + 1;
  q = pQuotient->pUnits;
  DIGI_MEMSET((ubyte *)q, 0, (n - t + 1) * sizeof(vlong_unit));

  /* generate Y << n - t i.e. y(B^ (n-t)) Step 2*/
  if (OK > (status = VLONG_allocVlong(&pYBnt, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(pYBnt);

  j = n;
  for (i = t; i >= 0; --i)
  {
    if (OK > (status = VLONG_setVlongUnit(pYBnt, j--, pY->pUnits[i])))
      goto exit;
  }

  /* Step 2. done only once if normalized */
  if (compareUnsignedVlongs(pRemainder, pYBnt) >= 0)
  {
    subtractUnsignedVlongs(pRemainder, pYBnt);
    q[n - t]++;
  }
  VLONG_freeVlong(&pYBnt, ppVlongQueue);

  x = pRemainder->pUnits;
  y = pY->pUnits;

  /* Step 3. */
  for (i = n; i > t; --i)
  {
    vlong_unit borrow;
    vlong_unit r0, r1, r2, r3;
    sbyte4 index0;

    index0 = i - t - 1; /* this is always >= 0 */

    /* 3.1 */
    if (ELEM_0(x, i) == y[t])
    {
      q[i - t - 1] = FULL_MASK;
    }
    else
    {
      q[i - t - 1] = VLONG_DoubleDiv(ELEM_0(x, i), ELEM_0(x, i - 1), y[t]);
    }
    /* 3.2 */
    for (;;)
    {
      r3 = r2 = r1 = r0 = 0;
      if (t > 0)
      {
        sbyte4 u = t - 1;
        MULT_ADDCX(q, y, index0, u, r0, r1, r2);
      }

      MULT_ADDCX(q, y, index0, t, r1, r2, r3); /* r3 should be 0 */
      if (r2 > ELEM_0(x, i) ||
          (r2 == ELEM_0(x, i) && r1 > ELEM_0(x, i - 1)) ||
          (r2 == ELEM_0(x, i) && r1 == ELEM_0(x, i - 1) && r0 > ELEM_0(x, i - 2)))
      {
        q[index0]--;
      }
      else
      {
        break;
      }
    }
    /* 3.3 */
    r3 = r2 = r1 = r0 = 0;
    for (j = 0; j <= t; ++j)
    {
      /* multiply the j digit of y by q[i-t-1] */
      MULT_ADDCX(q, y, index0, j, r0, r1, r2);
      /* subtract the low digit from x[i+j-t-1] */
      borrow = (x[index0 + j] < r0) ? 1 : 0;
      x[index0 + j] -= r0;
      /* add the other digits including the borrow */
      r0 = r1;
      r0 += borrow;
      borrow = (r0 >= r1) ? 0 : 1;
      r1 = r2;
      r1 += borrow;
      borrow = (r1 >= r2) ? 0 : 1;
      r2 = borrow;
    }
    /* Step 3.4 */
    if (x[i] < r0)
    {
      vlong_unit carry = 0;

      x[i] -= r0;
      for (j = 0; j <= t; ++j)
      {
        x[index0 + j] += carry;
        carry = (x[index0 + j] < carry) ? 1 : 0;

        x[index0 + j] += y[j];
        carry += (x[index0 + j] < y[j]) ? 1 : 0;
      }
      x[i] += carry;
      q[index0]--;
    }
    else
    {
      x[i] -= r0;
    }
  }

  while ((pQuotient->numUnitsUsed) && 
         (ZERO_UNIT == pQuotient->pUnits[pQuotient->numUnitsUsed - 1]))
    pQuotient->numUnitsUsed--;

  pRemainder->numUnitsUsed = t + 1;
  while ((pRemainder->numUnitsUsed) && 
         (ZERO_UNIT == pRemainder->pUnits[pRemainder->numUnitsUsed - 1]))
    pRemainder->numUnitsUsed--;

  if (OK > (status = VLONG_shrXvlong(pRemainder, normShift)))
    goto exit;

exit:
  VLONG_freeVlong(&pY, ppVlongQueue);
  VLONG_freeVlong(&pYBnt, ppVlongQueue);

  return status;

} /* VLONG_unsignedDivide */

/*----------------------------------------------------------------------------*/

/* 64 divided by 32 return only the least significant 32 bits of the quotient
which is all that's needed for VLONG_unsignedDivide because of normalization
This algorithm (HAC 14.20) is twice as fast as the algorithm based on shifts.
The implementation of this is as fast as the OpenSSL implementation and
contrarily to the latter, returns the correct result all of the time, not
only for normalized d (i.e. d >= 0x7FFFFFFF) */
static vlong_unit VLONG_DoubleDiv (
  vlong_unit hi, 
  vlong_unit lo, 
  vlong_unit d
  )
{
  vlong_unit normShift;
  vlong_unit hihi = 0; /* normalization overflow */
  ubyte4 bitLen;
  sbyte4 n, i;
  vlong_unit temp;
  hvlong_unit q[5] = {0}; /* quotient */
  hvlong_unit xx[8];      /* xx[0] = xx[1] = 0 used for negative indices */
  hvlong_unit *x = xx + 2;
  vlong_unit lod, hid;

  if (!hi)
  {
    return lo / d;
  }

  xx[0] = xx[1] = 0;

  bitLen = BITLENGTH(d);

  normShift = BPU - bitLen;
  if (normShift)
  {
    hihi = (hi >> (BPU - normShift));
    hi <<= normShift;
    hi |= (lo >> (BPU - normShift));
    lo <<= normShift;
    d <<= normShift;
  }

  if (HI_HUNIT(hihi))
  {
    n = 5;
    while (hihi >= d)
    {
      hihi -= d;
      q[4]++;
    }
  }
  else if (hihi)
  {
    n = 4;
    temp = MAKE_HI_HUNIT(hihi) + HI_HUNIT(hi);
    while (temp >= d)
    {
      temp -= d;
      q[3]++;
    }
    hihi = HI_HUNIT(temp);
    hi = MAKE_UNIT(temp, LO_HUNIT(hi));
  }
  else
  {
    n = 3;
    while (hi >= d)
    {
      hi -= d;
      q[2]++;
    }
  }

  x[5] = (hvlong_unit)HI_HUNIT(hihi);
  x[4] = (hvlong_unit)LO_HUNIT(hihi);
  x[3] = (hvlong_unit)HI_HUNIT(hi);
  x[2] = (hvlong_unit)LO_HUNIT(hi);
  x[1] = (hvlong_unit)HI_HUNIT(lo);
  x[0] = (hvlong_unit)LO_HUNIT(lo);

  lod = LO_HUNIT(d);
  hid = HI_HUNIT(d);

  for (i = n; i >= 2; --i)
  {
    vlong_unit t0, t1;
    vlong_unit borrow;

    if (x[i] == hid)
    {
      q[i - 2] = LO_MASK;
    }
    else
    {
      q[i - 2] = (hvlong_unit)(MAKE_UNIT(x[i], x[i - 1]) / hid);
    }

    for (;;)
    {
      /* multiply q[i-2] * d and compare with 3 digits of x */
      t0 = q[i - 2] * lod;
      t1 = q[i - 2] * hid;
      t1 += HI_HUNIT(t0);
      /* 3 digits: t1 has the first 2, t0 & 0xFFFF has the last one */
      temp = MAKE_UNIT(x[i], x[i - 1]);
      if ((t1 > temp) || (t1 == temp && LO_HUNIT(t0) > x[i - 2]))
      {
        q[i - 2]--;
      }
      else
      {
        break;
      }
    }
    /* now subtract d * q[i-2] from x[i-2]...
        we know because of above that d * q[i-2] <= x[i-2].... so
        we don't need to keep track of the borrow or whether this
        can end up being negative */
    borrow = 0;
    if (x[i - 2] < LO_HUNIT(t0))
    {
      ++borrow;
    }
    x[i - 2] -= (hvlong_unit)LO_HUNIT(t0);
#ifdef VERIFY_DIV_ALGO
    if (x[i - 1] > borrow)
    {
      x[i - 1] -= borrow;
      borrow = 0;
    }
    if (x[i - 1] < LO_HUNIT(t1))
    {
      ++borrow;
    }
    x[i - 1] -= LO_HUNIT(t1);
    x[i] -= borrow + HI_HUNIT(t1); /* and verify x[i] = 0 */
#else
    x[i - 1] -= (hvlong_unit)(borrow + LO_HUNIT(t1));
#endif
  }
  return MAKE_UNIT(q[1], q[0]);

} /* VLONG_DoubleDiv */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_operatorDivideSignedVlongs (
  const vlong* pDividend, 
  const vlong* pDivisor,
  vlong **ppQuotient, 
  vlong **ppVlongQueue
  )
{
  vlong *pRemainder = NULL;
  MSTATUS status;

  if (NULL == ppQuotient)
    return ERR_NULL_POINTER;

  *ppQuotient = NULL;

  if (OK <= (status = VLONG_allocVlong(ppQuotient, ppVlongQueue)))
  {
    DEBUG_RELABEL_MEMORY(*ppQuotient);

    if (OK <= (status = VLONG_allocVlong(&pRemainder, ppVlongQueue)))
    {
      DEBUG_RELABEL_MEMORY(pRemainder);

      status = VLONG_unsignedDivide(*ppQuotient, pDividend, pDivisor, pRemainder, ppVlongQueue);
      (*ppQuotient)->negative = pDividend->negative ^ pDivisor->negative;
    }
  }

  if (OK > status)
    VLONG_freeVlong(ppQuotient, ppVlongQueue);

  VLONG_freeVlong(&pRemainder, ppVlongQueue);

  return status;

} /* VLONG_operatorDivideSignedVlongs */
#endif
