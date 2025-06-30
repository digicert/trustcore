/*
 * cmptemplate.c
 *
 * Compare templates.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../asn1/mocasn1.h"

MSTATUS MAsn1CompareTemplates (
  MAsn1Element *pElement1,
  MAsn1Element *pElement2,
  MAsn1Element **ppNext1,
  MAsn1Element **ppNext2,
  ubyte4 *pCount,
  sbyte4 *pCmpResult
  )
{
  MSTATUS status;
  sbyte4 cmpRet, newCmp;
  ubyte4 val1, val2, count, totalCount, currentCount, newCount;
  MAsn1Element *pCurrent1, *pCurrent2, *pNext1, *pNext2;

  /* Use this as a flag. If it is 2, don't set the *pCount and *pCmpResult.
   * If those args are not NULL, then we'll set them if cmpRet is 0 or 1.
   */
  cmpRet = 2;
  totalCount = 0;
  pNext1 = NULL;
  pNext2 = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement1) || (NULL == pElement2) ||
       (NULL == ppNext1) || (NULL == ppNext2) ||
       (NULL == pCount) || (NULL == pCmpResult) )
    goto exit;

  /* Compare the types. Ignore the NO_VALUE bit.
   */
  val1 = pElement1->type & (~(MASN1_NO_VALUE));
  val2 = pElement2->type & (~(MASN1_NO_VALUE));

  /* Init to not equal results.
   */
  cmpRet = 1;

  if (0 == (pElement1->bufFlag & MASN1_BUF_FLAG_LAST))
    pNext1 = pElement1 + 1;

  if (0 == (pElement2->bufFlag & MASN1_BUF_FLAG_LAST))
    pNext2 = pElement2 + 1;

  /* If the types are not equal, the Templates are not.
   */
  status = OK;
  if (val1 != val2)
    goto exit;

  /* If this is constructed, we need to check the sub elements.
   */
  currentCount = 1;
  if (0 != (val1 & MASN1_CONSTRUCTED_MASK))
  {
    count = 1;
    pCurrent1 = pNext1;
    pCurrent2 = pNext2;

    /* They must have the same number of sub elements.
     */
    if (0 == (val1 & MASN1_TYPE_OF))
    {
      if (pElement1->valueLen != pElement2->valueLen)
        goto exit;

      count = pElement1->valueLen;
    }

    while ( (NULL != pCurrent1) && (NULL != pCurrent2) )
    {
      count--;

      status = MAsn1CompareTemplates (
        pCurrent1, pCurrent2, &pNext1, &pNext2, &newCount, &newCmp);
      if (OK != status)
        goto exit;

      /* If these don't compare, we're done.
       */
      if (0 != newCmp)
        goto exit;

      pCurrent1 = pNext1;
      pCurrent2 = pNext2;
      currentCount += newCount;
      if (0 == count)
        break;
    }

    /* If count is not 0, that means we broke out before we completed one or both
     * of the Templates (NULL current), which means they are not equal, so just
     * exit.
     */
    if (0 != count)
      goto exit;
  }

  /* If we reach this code, they are equal, set the return values.
   */
  cmpRet = 0;
  totalCount = currentCount;

exit:

  if (2 != cmpRet)
  {
    *pCmpResult = cmpRet;
    *pCount = totalCount;
    *ppNext1 = pNext1;
    *ppNext2 = pNext2;
  }

  return (status);
}
