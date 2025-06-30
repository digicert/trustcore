/**
 * @file  vlong_modinv.c
 * @brief Very Long Integer Modular Inverse Function Implementation
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

#ifndef __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__

MOC_EXTERN MSTATUS VLONG_modularInverse (
  MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *pA,
  const vlong *pModulus, 
  vlong **ppRetModularInverse,
  vlong **ppVlongQueue
  )
{
  vlong *j = NULL;
  vlong *i = NULL;
  vlong *b = NULL;
  vlong *c = NULL;
  vlong *x = NULL;
  vlong *y = NULL;
  vlong *z = NULL;
  MSTATUS status;

  if ((NULL == pA) || (NULL == pModulus) || (NULL == ppRetModularInverse))
  {
    return ERR_NULL_POINTER;
  }

  *ppRetModularInverse = NULL;

  if ((OK > (status = VLONG_makeVlongFromUnsignedValue(1, &j, ppVlongQueue))) ||
      (OK > (status = VLONG_makeVlongFromUnsignedValue(0, &i, ppVlongQueue))) ||
      (OK > (status = VLONG_makeVlongFromVlong(pModulus, &b, ppVlongQueue))) ||
      (OK > (status = VLONG_makeVlongFromVlong(pA, &c, ppVlongQueue))) ||
      (OK > (status = VLONG_allocVlong(&y, ppVlongQueue))) ||
      (OK > (status = VLONG_allocVlong(&x, ppVlongQueue))))
  {
    goto cleanup;
  }

  while (!VLONG_isVlongZero(c))
  {
    /* x = b / c  -- y = b % c */
    if (OK > (status = VLONG_unsignedDivide(x, b, c, y, ppVlongQueue)))
      goto cleanup;

    /* z = old b storage */
    z = b;

    b = c;
    c = y;
    y = j;

    /*** j = i - j*x  or (since y = j)   j = i - y*x ****/
    /* z = y * x */
    if (OK > (status = VLONG_vlongSignedMultiply(z, y, x)))
    {
      /* set y back to z so the original b will get freed */
      y = z;
      goto cleanup;
    }

    /* i -= z */
    if (OK > (status = VLONG_subtractSignedVlongs(i, z, ppVlongQueue)))
    {
      /* set y back to z so the original b will get freed */
      y = z;
      goto cleanup;
    }

    /* j = i */
    j = i;
    /* i = y */
    i = y;
    y = z; /* y use old b storage */
  }

  if ((i->negative) && (!VLONG_isVlongZero(i)))
    if (OK > (status = VLONG_addSignedVlongs(i, pModulus, ppVlongQueue)))
      goto cleanup;

  *ppRetModularInverse = i;
  i = NULL;

cleanup:

  VLONG_freeVlong(&j, ppVlongQueue);
  VLONG_freeVlong(&i, ppVlongQueue);
  VLONG_freeVlong(&b, ppVlongQueue);
  VLONG_freeVlong(&c, ppVlongQueue);
  VLONG_freeVlong(&x, ppVlongQueue);
  VLONG_freeVlong(&y, ppVlongQueue);
  /* z's storage is cleaned up when we free y */

  return status;

} /* VLONG_modularInverse */

#endif /* ifndef __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__ */
#endif
