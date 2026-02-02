/*
 * copytemplate.c
 *
 * Copy a template.
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

#if (!defined(__DISABLE_DIGICERT_ASN1_COPY_TEMPLATE__))

/* A helper function to add a new entry to an Of link list.
 */
MSTATUS MAsn1AddOfEntry (
  MAsn1Element *pOfElement,
  MAsn1Element *pContentsElement
  );

/* Copy pElement. This creates a new MAsn1Element struct and sets it with the
 * type and special of the original.
 * <p>If the original is a SEQUENCE or SET, this will build the same template,
 * the same subArray.
 * <p>The function will make sure the new Element has the same type and special
 * as the original. If the original is a SEQUENCE or SET, it will create a new
 * subArray and make sure those Elements have the same type and special.
 * <p>If the original contains an OF (or is an OF itself), the function will
 * determine the type of the OF entries, and create one copy and add it to the OF
 * Element.
 *
 * @param pElement The original Element to copy.
 * @param OfFunction The function that performs Of Operations.
 * @param ppCopy The address where the function will deposit the newly created
 * copy.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS MAsn1CopyTemplate (
  MAsn1Element *pElement,
  MOfFunction OfFunction,
  MAsn1Element **ppCopy
  );

/* How many Elements are needed to copy pElement.
 * <p>This function will count 1 for the pElement itself. If it is not SEQUENCE
 * or SET, we're done, set *pCount to 1.
 * <p>If it is SEQUENCE or SET, count each of its Elements.
 * <p>If it is OF, then there could be more than one entry in the link list. Look
 * at one entry only and count that Element.
 * <p>This returns the next element. You might not need it, but if you're
 * counting a constructed, it will help you skip over a sub element that is also
 * constructed.
 * <p>This function does not check the args, don't make mistakes.
 */
MSTATUS MAsn1CountElements (
  MAsn1Element *pElement,
  ubyte4 *pCount,
  MAsn1Element **ppNextElement
  );

MSTATUS MAsn1CopyAddOfEntry (
  MAsn1Element *pOfElement,
  MAsn1Element **ppNewElement
  )
{
  MSTATUS status;
  MAsn1Element *pCopy = NULL;

  /* Make sure the src Element is an OF.
   */
  status = ERR_NULL_POINTER;
  if ( (NULL == pOfElement) || (NULL == ppNewElement) )
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (0 == (pOfElement->type & MASN1_TYPE_OF))
    goto exit;

  /* Now get the Element that is the contents of the OF.
   */
  status = ERR_ASN_INVALID_DATA;
  if (NULL == pOfElement->value.pOfTemplate)
    goto exit;

  status = MAsn1CopyTemplate (
    pOfElement->value.pOfTemplate->entry.pElement,
    pOfElement->value.pOfTemplate->OfFunction, &pCopy);
  if (OK != status)
    goto exit;

  status = MAsn1AddOfEntry (pOfElement, pCopy);
  if (OK != status)
    goto exit;

  *ppNewElement = pCopy;
  pCopy = NULL;

exit:

  if (NULL != pCopy)
  {
    MAsn1FreeElementArray (&pCopy);
  }

  return (status);
}

MSTATUS MAsn1AddOfEntry (
  MAsn1Element *pOfElement,
  MAsn1Element *pContentsElement
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 count;
  MAsn1OfEntry *pNewEntry = NULL;
  MAsn1OfEntry *pCurrent;
  MAsn1Element *pNext1, *pNext2;

  status = ERR_NULL_POINTER;
  if ( (NULL == pOfElement) || (NULL == pContentsElement) )
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (0 == (pOfElement->type & MASN1_TYPE_OF))
    goto exit;

  /* Make sure the new template matches the one in the OfTemplate.
   */
  status = MAsn1CompareTemplates (
    pOfElement->value.pOfTemplate->entry.pElement, pContentsElement,
    &pNext1, &pNext2, &count, &cmpResult);
  if (OK != status)
    goto exit;

  /* If they are not equal, don't add.
   */
  status = ERR_ASN_INVALID_DATA;
  if (0 != cmpResult)
    goto exit;

  /* Build a new OfEntry.
   */
  status = DIGI_CALLOC ((void **)&pNewEntry, sizeof (MAsn1OfEntry), 1);
  if (OK != status)
    goto exit;

  /* Copy a reference to the input Element.
   */
  pNewEntry->pElement = pContentsElement;
  pNewEntry->entryFlag = MASN1_OF_FREE_ELEMENT | MASN1_OF_FREE_ENTRY;

  /* Now place it at the end of the link list.
   */
  pCurrent = &(pOfElement->value.pOfTemplate->entry);

  while (NULL != pCurrent->pNext)
    pCurrent = pCurrent->pNext;

  pCurrent->pNext = pNewEntry;
  pNewEntry = NULL;

  status = OK;

exit:

  if (NULL != pNewEntry)
  {
    DIGI_FREE ((void **)&pNewEntry);
  }

  return (status);
}

MSTATUS MAsn1CopyTemplate (
  MAsn1Element *pElement,
  MOfFunction OfFunction,
  MAsn1Element **ppCopy
  )
{
  MSTATUS status;
  ubyte4 count, index;
  MAsn1Element *pNewTemplate = NULL;
  MAsn1Element *pTemp;
  MAsn1TypeAndCount *pDefinition = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == ppCopy) )
    goto exit;

  /* How many Elements do we need to create?
   */
  status = MAsn1CountElements (pElement, &count, &pTemp);
  if (OK != status)
    goto exit;

  /* Build an array of TypeAndCount the same size. We want to use
   * CreateElementArray so that we build an Element array with the extra space
   * for pBuf.
   */
  status = DIGI_CALLOC (
    (void **)&pDefinition, count * sizeof (MAsn1TypeAndCount), 1);
  if (OK != status)
    goto exit;

  /* Now copy the tagSpecial and count.
   */
  for (index = 0; index < count; ++index)
  {
    pDefinition[index].tagSpecial = pElement[index].type;
    if (0 != (pElement[index].type & MASN1_CONSTRUCTED_MASK))
      pDefinition[index].count = pElement[index].valueLen;
  }

  /* Now we can build the template.
   * Build it for ENCODE. We don't know whether it will be used for encoding or
   * decoding, and ENCODE works for both.
   */
  status = MAsn1CreateElementArray (
    pDefinition, count, MASN1_FNCT_ENCODE, OfFunction, &pNewTemplate);
  if (OK != status)
    goto exit;

  *ppCopy = pNewTemplate;
  pNewTemplate = NULL;

exit:

  if (NULL != pDefinition)
  {
    DIGI_FREE ((void **)&pDefinition);
  }
  if (NULL != pNewTemplate)
  {
    MAsn1FreeElementArray (&pNewTemplate);
  }

  return (status);
}

MSTATUS MAsn1CountElements (
  MAsn1Element *pElement,
  ubyte4 *pCount,
  MAsn1Element **ppNextElement
  )
{
  MSTATUS status;
  ubyte4 retVal, countC, newCount;
  MAsn1Element *pCurrent, *pNext;

  retVal = 1;

  /* If this is not the last, the next is just + 1.
   */
  pNext = NULL;
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_LAST))
    pNext = pElement + 1;

  if (0 != (pElement->type & MASN1_CONSTRUCTED_MASK))
  {
    /* This is constructed, so we need to count each of the sub elements.
     */
    pCurrent = pNext;

    /* Start counting with the next element.
     * How many sub elements are we expected to encounter?
     */
    countC = 1;
    if (0 == (pElement->type & MASN1_TYPE_OF))
      countC = pElement->valueLen;

    while (NULL != pCurrent)
    {
      countC--;
      status = MAsn1CountElements (pCurrent, &newCount, &pNext);
      if (OK != status)
        goto exit;

      pCurrent = pNext;
      retVal += newCount;
      if (0 == countC)
        break;
    }

    /* If we broke out because pCurrent was NULL, but count is not yet 0, then
     * that's an error.
     */
    status = ERR_ASN_UNEXPECTED_END;
    if (0 != countC)
      goto exit;
  }

  *ppNextElement = pNext;
  *pCount = retVal;
  status = OK;

exit:

  *pCount = retVal;

  return (status);
}

#endif /* (!defined(__DISABLE_DIGICERT_ASN1_COPY_TEMPLATE__)) */
