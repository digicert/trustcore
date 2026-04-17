/**
 * @file  vlong_rand.c
 * @brief Very Long Integer Random Function Implementations
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#include "../common/vlong.h"

#ifndef __DISABLE_DIGICERT_VLONG_MATH__

MOC_EXTERN MSTATUS VLONG_makeRandomVlong (
  void *pRandomContext,
  vlong **ppRetPrime,
  ubyte4 numBitsLong,
  vlong **ppVlongQueue
  )
{
  vlong *pPrime = NULL;
  ubyte *pBuffer = NULL;
  ubyte4 bufLen;
  ubyte4 shiftBits;
  MSTATUS status;

  *ppRetPrime = NULL;

  bufLen = ((7 + numBitsLong) >> 3);

  if (NULL == (pBuffer = (ubyte *)MALLOC(bufLen)))
  {
    status = ERR_MEM_ALLOC_FAIL;
    goto exit;
  }

  /* generate a random number of numBitsLong length */
  if (OK > (status = RANDOM_numberGenerator(pRandomContext, pBuffer, bufLen)))
    goto exit;

  if (OK > (status = VLONG_vlongFromByteString(pBuffer, bufLen, &pPrime, ppVlongQueue)))
    goto exit;

  DEBUG_RELABEL_MEMORY(pPrime);

  /* deal with primes that are not multiples of 8 */
  shiftBits = numBitsLong - (numBitsLong & 0xfffff8);

  if (0 < shiftBits)
  {
    /* shrink prime candidate to non byte multiple length */
    if (OK > (status = VLONG_shrXvlong(pPrime, shiftBits)))
      goto exit;
  }

  /* set highest and lowest bits */
  if (OK > (status = VLONG_setVlongBit(pPrime, 0)))
    goto exit;

  if (OK > (status = VLONG_setVlongBit(pPrime, numBitsLong - 1)))
    goto exit;

  /* result */
  *ppRetPrime = pPrime;
  pPrime = NULL;

exit:
  if (NULL != pPrime)
    VLONG_freeVlong(&pPrime, ppVlongQueue);

  if (NULL != pBuffer)
    FREE(pBuffer);

  return status;

} /* VLONG_makeRandomVlong */

#endif /* __DISABLE_DIGICERT_VLONG_MATH__ */