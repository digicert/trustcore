/*
 * subelement.c
 *
 * Accessing sub Elements.
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

MSTATUS MAsn1GetOfElementAtIndex (
  MAsn1Element *pElement,
  ubyte4 index,
  MAsn1Element **ppNextElement
  )
{
  MSTATUS status;
  ubyte4 count;
  MAsn1OfEntry *pCurrent;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == ppNextElement) )
    goto exit;

  *ppNextElement = NULL;

  /* This is only valid with OF.
   */
  status = OK;
  if (0 == (pElement->type & MASN1_TYPE_OF))
    goto exit;

  /* At this point, we know it is OF. Run through the link list until hitting
   * index.
   */
  count = 0;
  pCurrent = &(pElement->value.pOfTemplate->entry);
  while (pCurrent != NULL)
  {
    if (count == index)
    {
      *ppNextElement = pCurrent->pElement;
      goto exit;
    }

    pCurrent = pCurrent->pNext;
    count++;
  }

exit:

  return (status);
}
