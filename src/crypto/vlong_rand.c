/**
 * @file  vlong_rand.c
 * @brief Very Long Integer Random Function Implementations
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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