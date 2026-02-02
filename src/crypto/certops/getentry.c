/*
 * getentry.c
 *
 * Functions for getting elements out of an object.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../crypto/certops.h"
#include "../../crypto/certops/certobj.h"

MSTATUS MGetCountOrEntryByIndex (
  MAsn1Element *pOfElement,
  ubyte4 *pCount,
  ubyte4 index,
  MAsn1Element **ppElement
  )
{
  MSTATUS status;
  ubyte4 listIndex;
  MAsn1OfEntry *pCurrent;

  /* Make sure this is indeed an OfElement.
   */
  status = ERR_INVALID_INPUT;
  if (0 == (pOfElement->type & MASN1_TYPE_OF))
    goto exit;

  pCurrent = &(pOfElement->value.pOfTemplate->entry);
  listIndex = 0;

  /* The OF is a link list. Count until reaching NULL if requesting the count, or
   * until listIndex == index if not.
   */
  do
  {
    if ( (NULL == pCount) && (listIndex == index) )
      break;

    pCurrent = (MAsn1OfEntry *)(pCurrent->pNext);
    listIndex++;
  } while (NULL != pCurrent);

  /* If pCount is not NULL, the caller wanted the count, ignore the other args.
   */
  if (NULL != pCount)
  {
    *pCount = listIndex;
    status = OK;
    goto exit;
  }

  /* pCount is NULL, so return the Element at index.
   */
  status = ERR_NULL_POINTER;
  if (NULL == ppElement)
    goto exit;

  *ppElement = NULL;

  status = ERR_INDEX_OOB;
  if (NULL == pCurrent)
    goto exit;

  *ppElement = pCurrent->pElement;
  status = OK;

exit:

  return (status);
}

MSTATUS MGetSimpleValue (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult, theLen;
  ubyte4 theTag, lenLen;

  status = ERR_NULL_POINTER;
  if (NULL == pGetData)
    goto exit;

  /* If the OID is not the same, this is not the Type that can get the value.
   */
  status = ERR_UNKNOWN_DATA;
  if (pGetData->oidLen != oidLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)(pGetData->pOid), (void *)pOid, oidLen, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_UNKNOWN_DATA;
  if (0 != cmpResult)
    goto exit;

  /* The value we return is the V of TLV of the encoded value.
   */
  status = ASN1_readTagAndLen (
    pGetData->pEncodedValue, pGetData->encodedValueLen, &theTag,
    &theLen, &lenLen);
  if (OK != status)
    goto exit;

  pGetData->pDecodedValue = pGetData->pEncodedValue + lenLen;
  pGetData->decodedValueLen = (ubyte4)theLen;

exit:

  return (status);
}
