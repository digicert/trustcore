/**
 * @file  vlong_monty.c
 * @brief Very Long Integer Montgomery Multiplication Function Implementations
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

static MSTATUS VLONG_initMontgomeryCtx (
  MOC_MOD(hwAccelDescr hwAccelCtx) MontgomeryCtx *pMonty,
  const vlong *pM, 
  vlong **ppVlongQueue
  );

static void VLONG_cleanMontgomeryCtx (
  MontgomeryCtx *pMonty, 
  vlong **ppVlongQueue
  );

static MSTATUS VLONG_initMontgomeryWork (
  MontgomeryWork *pMW, 
  const MontgomeryCtx *pMonty,
  vlong **ppVlongQueue
  );

static void VLONG_cleanMontgomeryWork ( 
  MontgomeryWork* pMW, 
  vlong **ppVlongQueue
  );

static vlong_unit VLONG_rho ( 
  const vlong* modulus
  );

static MSTATUS VLONG_montyMultiply (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  const vlong* b,
  MontgomeryWork* pMW
  );

static MSTATUS VLONG_montySqr (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  MontgomeryWork *pMW
  );  

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_newModExpHelper (
  MOC_MOD(hwAccelDescr hwAccelCtx) ModExpHelper* pMEH, 
  const vlong* m, 
  vlong** ppVlongQueue
  )
{
  MSTATUS status;
  MontgomeryCtx *pNewMonty = 0;

  pNewMonty = (MontgomeryCtx *)MALLOC(sizeof(MontgomeryCtx));
  if (!pNewMonty)
    return ERR_MEM_ALLOC_FAIL;

  if (OK > (status = VLONG_initMontgomeryCtx(MOC_MOD(hwAccelCtx) pNewMonty, m, ppVlongQueue)))
    goto exit;

  *pMEH = pNewMonty;
  pNewMonty = 0;

exit:

  if (pNewMonty)
  {
    FREE(pNewMonty);
  }

  return status;

} /* VLONG_newModExpHelper */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_deleteModExpHelper( 
  ModExpHelper* pMEH, 
  vlong** ppVlongQueue
  )
{
  if (pMEH && *pMEH)
  {
    VLONG_cleanMontgomeryCtx(*pMEH, ppVlongQueue);
    FREE(*pMEH);
    *pMEH = NULL;
  }
  return OK;

} /* VLONG_deleteModExpHelper */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_makeModExpHelperFromModExpHelper ( 
  CModExpHelper meh,
  ModExpHelper* pMEH,
  vlong **ppVlongQueue
  )
{
  MontgomeryCtx *pNewMonty = 0;
  MSTATUS status = OK;
  sbyte4 i;

  if ((NULL == meh) || (NULL == pMEH))
  {
    return ERR_NULL_POINTER;
  }

  pNewMonty = (MontgomeryCtx *)MALLOC(sizeof(MontgomeryCtx));
  if (!pNewMonty)
  {
    status = ERR_MEM_ALLOC_FAIL;
    goto exit;
  }

  DIGI_MEMSET((ubyte *)pNewMonty, 0x00, sizeof(MontgomeryCtx));

#ifndef __ALTIVEC__
  pNewMonty->rho = meh->rho;
#endif

  for (i = 0; i < NUM_MONTY_VLONG; ++i)
  {
    if (OK > (status = VLONG_makeVlongFromVlong(meh->v[i], &pNewMonty->v[i], ppVlongQueue)))
      goto exit;
  }

  *pMEH = pNewMonty;
  pNewMonty = 0;

exit:
  if (pNewMonty)
  {
    VLONG_cleanMontgomeryCtx(pNewMonty, ppVlongQueue);
    FREE(pNewMonty);
  }

  return status;

} /* VLONG_makeModExpHelperFromModExpHelper */

/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_initMontgomeryCtx (
  MOC_MOD(hwAccelDescr hwAccelCtx) MontgomeryCtx *pMonty,
  const vlong *pM, 
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
#ifdef __ALTIVEC__
  vlong *tmp = 0;
#endif

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
  vlong *pRraw = 0;
#endif

  DIGI_MEMSET((ubyte *)pMonty, 0x00, sizeof(MontgomeryCtx));

#ifndef __ALTIVEC__
  pMonty->rho = VLONG_rho(pM);
#endif

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__

  if (OK > (status = VLONG_allocVlong(&pRraw, ppVlongQueue)))
    goto cleanup;

  DEBUG_RELABEL_MEMORY(pRraw);

  if (OK > (status = VLONG_setVlongUnit(pRraw, pM->numUnitsUsed, 1)))
  {
    goto cleanup;
  }

  /* reduce R mod m */
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) pRraw,
                                                   pM, &MONTY_R(pMonty),
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }
  
#else

  if (OK > (status = VLONG_allocVlong(&MONTY_R(pMonty), ppVlongQueue)))
    goto cleanup;

  DEBUG_RELABEL_MEMORY(MONTY_R(pMonty));

  if (OK > (status = VLONG_setVlongUnit(MONTY_R(pMonty),
                                        pM->numUnitsUsed, 1)))
  {
    goto cleanup;
  }

#endif

  if (OK > (status = VLONG_makeVlongFromVlong(pM, &MONTY_N(pMonty),
                                              ppVlongQueue)))
  {
    goto cleanup;
  }

  DEBUG_RELABEL_MEMORY(MONTY_N(pMonty));

  /* MONTY_R1(pMonty) = VLONG_modularInverse(pMonty->R, MONTY_N(pMonty)) */
  if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx)
                                              MONTY_R(pMonty),
                                          pM,
                                          &MONTY_R1(pMonty), ppVlongQueue)))
  {
    goto cleanup;
  }

#ifdef __ALTIVEC__
  /* MONTY_N1(pMonty) = pMonty->R - VLONG_modularInverse(MONTY_M(pMonty), pMonty->R) */
  if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx)
                                              MONTY_N(pMonty),
                                          MONTY_R(pMonty),
                                          &tmp, ppVlongQueue)))
  {
    goto cleanup;
  }

  if (OK > (status = operatorMinusSignedVlongs(MONTY_R(pMonty), tmp,
                                               &MONTY_N1(pMonty),
                                               ppVlongQueue)))
  {
    goto cleanup;
  }
#endif

  goto exit;

cleanup:
  VLONG_cleanMontgomeryCtx(pMonty, ppVlongQueue);

exit:

#ifdef __ENABLE_DIGICERT_VLONG_CONST_TIME__
  VLONG_freeVlong(&pRraw, ppVlongQueue);
#endif

#ifdef __ALTIVEC__
  VLONG_freeVlong(&tmp, ppVlongQueue);
#endif

  return status;

} /* VLONG_initMontgomeryCtx */

/*----------------------------------------------------------------------------*/

static void VLONG_cleanMontgomeryCtx (
  MontgomeryCtx *pMonty, 
  vlong **ppVlongQueue
  )
{
  sbyte4 i;
  for (i = 0; i < NUM_MONTY_VLONG; ++i)
  {
    VLONG_freeVlong(&pMonty->v[i], ppVlongQueue);
  }
} /* VLONG_cleanMontgomeryCtx */

/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_initMontgomeryWork (
  MontgomeryWork *pMW, 
  const MontgomeryCtx *pMonty,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 numUnits = 2 * MONTY_N(pMonty)->numUnitsUsed + 1;

  DIGI_MEMSET((ubyte *)pMW, 0x00, sizeof(MontgomeryWork));

  if (OK > (status = VLONG_allocVlong(&MW_T(pMW), ppVlongQueue)))
    goto cleanup;

  if (OK > (status = expandVlong(MW_T(pMW), numUnits)))
  {
    goto cleanup;
  }

#ifdef __ALTIVEC__
  if (OK > (status = VLONG_allocVlong(&MW_K(pMW), ppVlongQueue)))
    goto cleanup;

  if (OK > (status = expandVlong(MW_K(pMW), numUnits)))
  {
    goto cleanup;
  }
#endif

  goto exit;

cleanup:
  VLONG_cleanMontgomeryWork(pMW, ppVlongQueue);

exit:

  return status;

} /* VLONG_initMontgomeryWork */

/*----------------------------------------------------------------------------*/

static void VLONG_cleanMontgomeryWork ( 
  MontgomeryWork* pMW, 
  vlong **ppVlongQueue
  )
{
  sbyte4 i;
  for (i = 0; i < NUM_MW_VLONG; ++i)
  {
    VLONG_freeVlong(&pMW->vw[i], ppVlongQueue);
  }
} /* VLONG_cleanMontgomeryWork */

/*----------------------------------------------------------------------------*/

#ifndef __ALTIVEC__
static vlong_unit VLONG_rho( 
  const vlong* modulus
  )
{
  vlong_unit b = modulus->pUnits[0];
  vlong_unit x;

  x = (((b + 2) & 4) << 1) + b;
  x *= 2 - b * x; /* 8 BIT */
  x *= 2 - b * x; /* 16 BIT */
  x *= 2 - b * x; /* 32 BIT */
#if defined(__ENABLE_DIGICERT_64_BIT__)
  x *= 2 - b * x; /* 64 BIT */
#endif
  return (ZERO_UNIT - x);
}
#endif /* ifndef __ALTIVEC__ */

/*----------------------------------------------------------------------------*/

#ifdef __ALTIVEC__

static MSTATUS VLONG_montyMultiply (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  const vlong* b,
  MontgomeryWork* pMW
  )
{
  MSTATUS status;
  ubyte4 j;
  vlong_unit borrow;
  const vlong *pModulus = MONTY_N(pMonty);
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  vlong *T = MW_T(pMW);
  vlong *k = MW_K(pMW);
  vlong_unit *pTUnits;
  vlong_unit *pAUnits;
  ubyte4 numModUnits;

  numModUnits = pModulus->numUnitsUsed;

  /* T = x*y */
  status = VLONG_FAST_MULT(T, a, b, 2 * numModUnits);
  if (OK > status)
    goto exit;

  /* k = ( T * n1 ) % R */
  status = VLONG_FAST_MULT(k, T, MONTY_N1(pMonty), numModUnits);
  if (OK > status)
    goto exit;

  /* x = ( T + k*n ) / R */
  status = VLONG_FAST_MULT(a, k, MONTY_N(pMonty), 2 * numModUnits);
  if (OK > status)
    goto exit;

  /* x += pMonty->T */
  status = addUnsignedVlongs(a, T);
  if (OK > status)
    goto exit;

  pTUnits = T->pUnits;
  pAUnits = a->pUnits;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit n_unit;
    vlong_unit a_unit = pAUnits[j + numModUnits];
    vlong_unit bbb = (a_unit < borrow) ? 1 : 0;

    pTUnits[j] = a_unit - borrow;

    n_unit = pModulusUnits[j];
    bbb += (pTUnits[j] < n_unit) ? 1 : 0;
    pTUnits[j] -= n_unit;
    borrow = bbb;
  }
  if ((a->numUnitsUsed <= 2 * numModUnits && borrow) ||
      pAUnits[2 * numModUnits] < borrow)
  {
    pTUnits = pAUnits + numModUnits;
  }

  /* copy in place */
  for (j = numModUnits - 1; pTUnits[j] == ZERO_UNIT && j != 0; --j)
  {
  }
  a->numUnitsUsed = j + 1;
  for (j = 0; j < a->numUnitsUsed; ++j)
  {
    pAUnits[j] = pTUnits[j];
  }

exit:
  return status;

} /* ALTIVEC VLONG_montyMultiply */

/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_montySqr (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  MontgomeryWork *pMW
  )
{
  MSTATUS status;
  ubyte4 j;
  vlong_unit borrow;
  const vlong *pModulus = MONTY_N(pMonty);
  vlong *T = MW_T(pMW);
  vlong *k = MW_K(pMW);
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  vlong_unit *pTUnits;
  vlong_unit *pAUnits;
  ubyte4 numModUnits;

  numModUnits = pModulus->numUnitsUsed;

  /* T = x*y */
  status = VLONG_FAST_SQR(T, a, 2 * numModUnits);
  if (OK > status)
    goto exit;
  /* k = ( T * n1 ) % R */
  status = VLONG_FAST_MULT(k, T, MONTY_N1(pMonty), numModUnits);
  if (OK > status)
    goto exit;

  /* x = ( T + k*n ) / R */
  status = VLONG_FAST_MULT(a, k, MONTY_N(pMonty), 2 * numModUnits);
  if (OK > status)
    goto exit;

  /* x += pMonty->T */
  status = addUnsignedVlongs(a, T);
  if (OK > status)
    goto exit;

  pTUnits = T->pUnits;
  pAUnits = a->pUnits;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit n_unit;
    vlong_unit a_unit = pAUnits[j + numModUnits];
    vlong_unit bbb = (a_unit < borrow) ? 1 : 0;

    pTUnits[j] = a_unit - borrow;

    n_unit = pModulusUnits[j];
    bbb += (pTUnits[j] < n_unit) ? 1 : 0;
    pTUnits[j] -= n_unit;
    borrow = bbb;
  }
  if ((a->numUnitsUsed <= 2 * numModUnits && borrow) ||
      pAUnits[2 * numModUnits] < borrow)
  {
    pTUnits = pAUnits + numModUnits;
  }

  /* copy in place */
  for (j = numModUnits - 1; pTUnits[j] == ZERO_UNIT && j != 0; --j)
  {
  }
  a->numUnitsUsed = j + 1;
  for (j = 0; j < a->numUnitsUsed; ++j)
  {
    pAUnits[j] = pTUnits[j];
  }

exit:
  return status;

} /* ALTIVEC VLONG_montySqr */

/*----------------------------------------------------------------------------*/
#else /* ifdef __ALTIVEC__ */
/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_montyMultiply (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  const vlong* b,
  MontgomeryWork* pMW
  )
{
  MSTATUS status;
  vlong *T = MW_T(pMW);
  const vlong *pModulus = MONTY_N(pMonty);
  vlong_unit rho = pMonty->rho;
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  vlong_unit *pTUnits;
  ubyte4 numModUnits;
#ifndef MONT_MULT_REDUCTION
  ubyte4 i, j;
  vlong_unit r0, r1, r2, m[1];
  vlong_unit borrow;
  vlong_unit *pAUnits;
#endif

  numModUnits = pModulus->numUnitsUsed;

#ifdef MONT_MULT_MULTIPLY
  if (numModUnits > 1 && a->numUnitsUsed == numModUnits &&
      b->numUnitsUsed == numModUnits)
  {
    MONT_MULT_MULTIPLY(a->pUnits, b->pUnits, pModulusUnits,
                       rho, numModUnits, T->pUnits);
    a->numUnitsUsed = numModUnits;
    return OK;
  }
#endif

  if (OK > (status = expandVlong(a, numModUnits)))
  {
    goto exit;
  }

  T->pUnits[2 * numModUnits] = ZERO_UNIT;

  /* T = x*y */
  status = VLONG_FAST_MULT(T, a, b, 2 * numModUnits);
  if (OK > status)
    goto exit;

  pTUnits = T->pUnits;

#ifdef MONT_MULT_REDUCTION
  a->numUnitsUsed = MONT_MULT_REDUCTION(pTUnits, pModulusUnits, rho,
                                        numModUnits, a->pUnits);
#else
  r2 = 0;
  for (i = 0; i < numModUnits; ++i)
  {
    r0 = 0;
    m[0] = pTUnits[i] * rho;
    for (j = 0; j < numModUnits; ++j)
    {
#ifdef MULT_ADD_MONT
      MULT_ADD_MONT(pTUnits, i + j, pModulusUnits, j, m, 0, r0, r1);
#else
      /* r0 = t[i+j] + r0; */
      r0 += pTUnits[i + j];
      /* carry ? */
      r1 = (r0 < pTUnits[i + j]) ? 1 : 0;
      /* r1:r0 +=  m * n[j] */
      MULT_ADDC1(pModulusUnits, m, j, 0, r0, r1);
#endif
      pTUnits[i + j] = r0;
      r0 = r1;
      r1 = 0;
    }
    r0 += r2;
    r2 = (r0 < r2) ? 1 : 0;
    pTUnits[i + j] += r0;
    if (pTUnits[i + j] < r0)
    {
      r2++;
    }
  }
  pTUnits[2 * numModUnits] += r2;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit nunit = pModulusUnits[j];
    vlong_unit tunit = pTUnits[j + numModUnits];
    vlong_unit bbb = (tunit < borrow) ? 1 : 0;

    pTUnits[j] = tunit - borrow;

    bbb += (pTUnits[j] < nunit) ? 1 : 0;
    pTUnits[j] -= nunit;
    borrow = bbb;
  }
  if (pTUnits[2 * numModUnits] < borrow)
  {
    pTUnits += numModUnits;
  }

  /* copy */
  for (j = numModUnits - 1; pTUnits[j] == ZERO_UNIT && j != 0; --j)
  {
  }
  a->numUnitsUsed = j + 1;
  pAUnits = a->pUnits;
  for (j = 0; j < a->numUnitsUsed; ++j)
  {
    pAUnits[j] = pTUnits[j];
  }
#endif

exit:
  return status;

} /* VLONG_montyMultiply */

/*----------------------------------------------------------------------------*/

static MSTATUS VLONG_montySqr (
  const MontgomeryCtx *pMonty,
  vlong* a, 
  MontgomeryWork *pMW
  )
{
  MSTATUS status;
  vlong *T = MW_T(pMW);
  const vlong *pModulus = MONTY_N(pMonty);
  vlong_unit rho = pMonty->rho;
  const vlong_unit *pModulusUnits = pModulus->pUnits;
  vlong_unit *pTUnits;
  ubyte4 numModUnits;

#ifndef MONT_MULT_REDUCTION
  ubyte4 i, j;
  vlong_unit r0, r1, r2, m[1];
  vlong_unit borrow;
  vlong_unit *pAUnits;
#endif

  numModUnits = pModulus->numUnitsUsed;

#ifdef MONT_MULT_SQR
  if (numModUnits > 1 && a->numUnitsUsed == numModUnits)
  {
    MONT_MULT_SQR(a->pUnits, pModulusUnits,
                  rho, numModUnits, T->pUnits);
    a->numUnitsUsed = numModUnits;
    return OK;
  }
#endif

  if (OK > (status = expandVlong(a, numModUnits)))
  {
    goto exit;
  }

  T->pUnits[2 * numModUnits] = ZERO_UNIT;

  /* T = x*x */
  status = VLONG_FAST_SQR(T, a, 2 * numModUnits);
  if (OK > status)
    goto exit;

  pTUnits = T->pUnits;

#ifdef MONT_MULT_REDUCTION
  a->numUnitsUsed = MONT_MULT_REDUCTION(pTUnits, pModulusUnits, rho,
                                        numModUnits, a->pUnits);
#else
  r2 = 0;
  for (i = 0; i < numModUnits; ++i)
  {
    r0 = 0;
    m[0] = pTUnits[i] * rho;
    for (j = 0; j < numModUnits; ++j)
    {

#ifdef MULT_ADD_MONT
      MULT_ADD_MONT(pTUnits, i + j, pModulusUnits, j, m, 0, r0, r1);
#else
      /* r0 = t[i+j] + r0; */
      r0 += pTUnits[i + j];
      /* carry ? */
      r1 = (r0 < pTUnits[i + j]) ? 1 : 0;
      /* r1:r0 +=  m * n[j] */
      MULT_ADDC1(pModulusUnits, m, j, 0, r0, r1);
#endif
      pTUnits[i + j] = r0;
      r0 = r1;
    }
    r0 += r2;
    r2 = (r0 < r2) ? 1 : 0;
    pTUnits[i + j] += r0;
    if (pTUnits[i + j] < r0)
    {
      r2++;
    }
  }
  pTUnits[2 * numModUnits] += r2;

  /* always do the subtraction for protection against side channel attacks */
  borrow = 0;
  for (j = 0; j < numModUnits; ++j)
  {
    vlong_unit nunit = pModulusUnits[j];
    vlong_unit tunit = pTUnits[j + numModUnits];
    vlong_unit bbb = (tunit < borrow) ? 1 : 0;

    pTUnits[j] = tunit - borrow;

    bbb += (pTUnits[j] < nunit) ? 1 : 0;
    pTUnits[j] -= nunit;
    borrow = bbb;
  }
  if (pTUnits[2 * numModUnits] < borrow)
  {
    pTUnits += numModUnits;
  }

  /* copy */
  for (j = numModUnits - 1; pTUnits[j] == ZERO_UNIT && j != 0; --j)
  {
  }
  a->numUnitsUsed = j + 1;
  pAUnits = a->pUnits;
  for (j = 0; j < a->numUnitsUsed; ++j)
  {
    pAUnits[j] = pTUnits[j];
  }
#endif

exit:
  return status;

} /* VLONG_montySqr */

#endif /* ifdef __ALTIVEC__ */

/*----------------------------------------------------------------------------*/

#ifndef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__

MOC_EXTERN MSTATUS VLONG_modexp_montgomery (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *x, 
  const vlong *e, 
  const vlong *n,
  vlong **ppRetModExp, 
  vlong **ppVlongQueue
  )
{
  /* (x^e) mod m */
  MontgomeryCtx me;
  MSTATUS status = ERR_FALSE;

  if (1 != (n->pUnits[0] & 1))
  {
    status = ERR_BAD_MODULO;
    goto exit;
  }

  DIGICERT_YIELD_PROCESSOR();

  if (OK <= (status = VLONG_initMontgomeryCtx(MOC_MOD(hwAccelCtx) & me, n, ppVlongQueue)))
  {
#ifdef __DISABLE_DIGICERT_MODEXP_SLIDING_WINDOW__
    status = VLONG_montgomeryExpBin(MOC_MOD(hwAccelCtx) & me, x, e,
                                    ppRetModExp, ppVlongQueue);
#else
    status = VLONG_montgomeryExp(MOC_MOD(hwAccelCtx) & me, x, e,
                                 ppRetModExp, ppVlongQueue);
#endif
  }

  VLONG_cleanMontgomeryCtx(&me, ppVlongQueue);

exit:

  return status;

} /* VLONG_modexp_montgomery */

#endif /* ifndef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_MODEXP_SLIDING_WINDOW__

MOC_EXTERN MSTATUS VLONG_montgomeryExp (
  MOC_MOD(hwAccelDescr hwAccelCtx) const MontgomeryCtx *pMonty,
  const vlong *x, 
  const vlong *e, 
  vlong **ppRetMontyExp,
  vlong **ppVlongQueue
  )
{
  MontgomeryWork mw = {{0}};
  vlong *result = NULL;
  vlong *tmp = NULL;
  ubyte4 bits = VLONG_bitLength(e);
  sbyte4 i;
  MSTATUS status;
  vlong *g[32] = {0};
  sbyte4 winSize; /* windowSize */

  winSize = (bits > 671 ? 6 : bits > 239 ? 5 : bits > 79 ? 4 : bits > 23 ? 3 : 2);

  if (OK > (status = VLONG_initMontgomeryWork(&mw, pMonty, ppVlongQueue)))
  {
    goto cleanup;
  }

  /* result = pMonty->R % MONTY_M(pMonty)  = (1 * R) mod m */
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) MONTY_R(pMonty),
                                                   MONTY_N(pMonty), &result,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }

  /* g[0] = (x * R) % m */
  if (OK > (status = operatorMultiplySignedVlongs(x, MONTY_R(pMonty), &tmp,
                                                  ppVlongQueue)))
  {
    goto cleanup;
  }

  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                   MONTY_N(pMonty), g,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }

  /* tmp = g[0] * g[0] */
  if (OK > (status = VLONG_copySignedValue(tmp, g[0])))
    goto cleanup;
  if (OK > (status = VLONG_montySqr(pMonty, tmp, &mw)))
    goto cleanup;

  for (i = 1; i < (1 << (winSize - 1)); i++)
  {
    if (OK > (status = VLONG_makeVlongFromVlong(g[i - 1], g + i, ppVlongQueue)))
      goto cleanup;

    if (OK > (status = VLONG_montyMultiply(pMonty, g[i], tmp, &mw)))
      goto cleanup;
  }
  VLONG_freeVlong(&tmp, ppVlongQueue);

  i = bits - 1;
  while (i >= 0)
  {
    if (!VLONG_isVlongBitSet(e, i))
    {
      VLONG_montySqr(pMonty, result, &mw);
      --i;
    }
    else
    {
      /* find the longest bitstring of size <= window where last bit = 1 */
      sbyte4 j, L, index;

      index = 1; /* window value used as index for g[] */
      L = 1;     /* window length */

      if (i > 0)
      {
        sbyte4 max = (i + 1 < winSize) ? i : winSize;

        for (j = 1; j < max; ++j)
        {
          index <<= 1;
          if (VLONG_isVlongBitSet(e, i - j))
          {
            L = j + 1;
            index += 1;
          }
        }
        index >>= (max - L);
      }

      /* assert( index & 1); index should be odd! */

      for (j = 0; j < L; ++j)
      {
        VLONG_montySqr(pMonty, result, &mw);
      }
      VLONG_montyMultiply(pMonty, result, g[index >> 1], &mw);

      i -= L;
    }
  }

  /* convert from Monty residue to "real" number */
  /* *ppRetMontyExp = (result * MONTY_R1(pMonty)) % MONTY_M(pMonty) */
  if (OK > (status = operatorMultiplySignedVlongs(result, MONTY_R1(pMonty),
                                                  &tmp, ppVlongQueue)))
  {
    goto cleanup;
  }
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                   MONTY_N(pMonty),
                                                   ppRetMontyExp,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }
cleanup:
  VLONG_freeVlong(&result, ppVlongQueue);
  VLONG_freeVlong(&tmp, ppVlongQueue);
  VLONG_cleanMontgomeryWork(&mw, ppVlongQueue);

  for (i = 0; i < (1 << (winSize - 1)); ++i)
  {
    VLONG_freeVlong(g + i, ppVlongQueue);
  }

  return status;

} /* VLONG_montgomeryExp */

#endif /* ifndef __DISABLE_DIGICERT_MODEXP_SLIDING_WINDOW__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS VLONG_montgomeryExpBin (
  MOC_MOD(hwAccelDescr hwAccelCtx) const MontgomeryCtx *pMonty,
  const vlong *x, 
  const vlong *e, 
  vlong **ppRetMontyExp,
  vlong **ppVlongQueue
  )
{
  vlong *result = NULL;
  vlong *t = NULL;
  vlong *tmp = NULL;
  ubyte4 bits = VLONG_bitLength(e);
  ubyte4 i = 0;
  MontgomeryWork mw = {{0}};
  MSTATUS status;

  if (OK > (status = VLONG_initMontgomeryWork(&mw, pMonty, ppVlongQueue)))
  {
    goto cleanup;
  }

  /* result = pMonty->R % MONTY_M(pMonty) */
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) MONTY_R(pMonty),
                                                   MONTY_N(pMonty), &result,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }

  DIGICERT_YIELD_PROCESSOR();

  /* t = (x * pMonty->R) % MONTY_M(pMonty) */
  if (OK > (status = operatorMultiplySignedVlongs(x, MONTY_R(pMonty),
                                                  &tmp, ppVlongQueue)))
  {
    goto cleanup;
  }
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                   MONTY_N(pMonty), &t,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }

  VLONG_freeVlong(&tmp, ppVlongQueue);

  while (1)
  {
    /* if (e->test(i)) then montyMultiply(pMonty,result,t) */
    if (TRUE == VLONG_isVlongBitSet(e, i))
      if (OK > (status = VLONG_montyMultiply(pMonty, result, t, &mw)))
        goto cleanup;

    i++;

    if (i == bits)
      break;

    /* montyMultiply(pMonty,pMonty->t,pMonty->t) */
    if (OK > (status = VLONG_montySqr(pMonty, t, &mw)))
      goto cleanup;
  }

  /* *ppRetMontyExp = (result * MONTY_R1(pMonty)) % MONTY_M(pMonty) */
  if (OK > (status = operatorMultiplySignedVlongs(result, MONTY_R1(pMonty),
                                                  &tmp, ppVlongQueue)))
  {
    goto cleanup;
  }
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) tmp,
                                                   MONTY_N(pMonty),
                                                   ppRetMontyExp,
                                                   ppVlongQueue)))
  {
    goto cleanup;
  }

cleanup:
  VLONG_cleanMontgomeryWork(&mw, ppVlongQueue);
  VLONG_freeVlong(&result, ppVlongQueue);
  VLONG_freeVlong(&t, ppVlongQueue);
  VLONG_freeVlong(&tmp, ppVlongQueue);

  DIGICERT_YIELD_PROCESSOR();

  return status;

} /* VLONG_montgomeryExpBin */

#endif
