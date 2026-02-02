/*
 * ofindef.c
 *
 * Operate on SET OF or SEQUENCE OF. Allow for indefinite length.
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

/* Decode the OF. This means decode each of the entries in the link list.
 */
MSTATUS MAsn1OfDecodeIndef (
  MAsn1OfEntry *pEntry,
  MAsn1OfDecodeInput *pDecodeInput,
  MAsn1OfDecodeOutput *pDecodeOutput
  );

/* We found the 00 tag that indicates the end of an indef OF.
 */
#define MOC_INDEF_OF_DECODE_00_TAG   1

MSTATUS MAsn1OfFunction (
  struct MAsn1OfEntry *pEntry,
  ubyte4 operation,
  void *pInput,
  void *pOutput
  )
{
  MSTATUS status;
  MAsn1OfDecodeInput decodeInput;

  status = ERR_NOT_IMPLEMENTED;
  switch (operation)
  {
    default:
      goto exit;

    case MASN1_OF_FREE:
      status = MAsn1OfFree ((MAsn1OfEntry *)pEntry);
      break;

    case MASN1_OF_DECODE:
      decodeInput = *((MAsn1OfDecodeInput *)pInput);
      decodeInput.decodeFlag |= MASN1_DECODE_NO_INDEF;
      status = MAsn1OfDecodeIndef (
        (MAsn1OfEntry *)pEntry, &decodeInput, (MAsn1OfDecodeOutput *)pOutput);
      break;
  }

exit:

  return (status);
}

MSTATUS MAsn1OfIndefFunction (
  struct MAsn1OfEntry *pEntry,
  ubyte4 operation,
  void *pInput,
  void *pOutput
  )
{
  MSTATUS status;

  status = ERR_NOT_IMPLEMENTED;
  switch (operation)
  {
    default:
      goto exit;

    case MASN1_OF_FREE:
      status = MAsn1OfFree ((MAsn1OfEntry *)pEntry);
      break;

    case MASN1_OF_DECODE:
      status = MAsn1OfDecodeIndef (
        (MAsn1OfEntry *)pEntry, (MAsn1OfDecodeInput *)pInput,
        (MAsn1OfDecodeOutput *)pOutput);
      break;
  }

exit:

  return (status);
}

MSTATUS MAsn1OfFree (
  MAsn1OfEntry *pEntry
  )
{
  MSTATUS status, fStatus;
  MAsn1OfEntry *pTemp;
  MAsn1OfEntry *pNext = NULL;

  status = OK;
  if (NULL != pEntry)
  {
    pNext = (MAsn1OfEntry *)(pEntry->pNext);

    if (NULL != pEntry->pElement)
    {
      if (0 != (pEntry->entryFlag & MASN1_OF_FREE_ELEMENT))
      {
        fStatus = MAsn1FreeElementArray (&(pEntry->pElement));
        if (OK == status)
          status = fStatus;
      }
    }

    if (0 != (pEntry->entryFlag & MASN1_OF_FREE_ENTRY))
    {
      pTemp = pEntry;
      fStatus = DIGI_FREE ((void **)&pTemp);
      if (OK == status)
        status = fStatus;
    }

    if (NULL != pNext)
    {
      fStatus = MAsn1OfFree (pNext);
      if (OK == status)
        status = fStatus;
    }
  }

  return (status);
}

MSTATUS MAsn1OfDecodeIndef (
  MAsn1OfEntry *pEntry,
  MAsn1OfDecodeInput *pDecodeInput,
  MAsn1OfDecodeOutput *pDecodeOutput
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 currentLen, totalLen, isIndef, localState, bytesRead;
  MAsn1OfEntry *pPrevious, *pCurrent, *pNext;
  MAsn1Element *pElement;

  status = ERR_NULL_POINTER;
  if ( (NULL == pEntry) || (NULL == pDecodeInput) ||
       (NULL == pDecodeOutput) )
    goto exit;

  if (NULL == pDecodeOutput->pBytesRead)
    goto exit;

  currentLen = pDecodeInput->encodingLen;

  *(pDecodeOutput->pBytesRead) = 0;

  isIndef = pDecodeInput->pOfElement->bufFlag & MASN1_BUF_FLAG_INDEF;

  /* Init the Entries.
   */
  pPrevious = NULL;
  pCurrent = NULL;
  pNext = pEntry;

  totalLen = 0;
  localState = 0;

  /* There are two behaviors. If the OF element (pDecodeInput->pOfElement) is
   * indefinite, keep reading until hitting 00 00.
   * If it is not indefinite, then buffer.remaining is the number of bytes total
   * remaining to be read, keep reading until there are no more bytes.
   */
  do
  {
    pPrevious = pCurrent;
    pCurrent = pNext;

    /* If we're out of data, break out.
     */
    if (0 == currentLen)
      break;

    /* If this is not indefinite, check for a 0 remaining. This should never be
     * 0, because the currentLen should never be > remaining. But check anyway,
     * just to be paranoid.
     */
    if ( (0 == isIndef) && (0 == pDecodeInput->pOfElement->buffer.remaining) )
      break;

    if (NULL == pCurrent)
    {
      /* If we reach this code, then that means we have completely decoded a
       * previous Element (at the very least, the original OF Entry existed, so
       * that one had been decoded). This means we're looking for a tag. If the
       * tag is 00, then we don't need a new entry. If it is not 00, create a new
       * entry to use to decode the new data.
       * If we're not in the middle of an indefinite OF, then a 00 tag will be an
       * error anyway, so we won't need a new entry.
       */
      if (0 == pDecodeInput->pEncoding[totalLen])
      {
        /* The next tag is 00. If this is not indefinite, error.
         */
        status = ERR_ASN_UNEXPECTED_TAG;
        if (0 == isIndef)
          goto exit;

        /* This is indefinite, we can break out now.
         */
        localState = MOC_INDEF_OF_DECODE_00_TAG;
        totalLen++;
        break;
      }

      status = MAsn1CopyAddOfEntry (
        pDecodeInput->pOfElement, &pElement);
      if (OK != status)
        goto exit;

      pCurrent = pPrevious->pNext;
      pNext = NULL;
    }
    else
    {
      pElement = pCurrent->pElement;
      pNext = pCurrent->pNext;

      /* If the current entry is COMPLETE, there's no need to try to decode, just
       * move on.
       */
      if ( (MASN1_STATE_DECODE_COMPLETE == pElement->state) ||
           (MASN1_STATE_DECODE_COMPLETE_INDEF == pElement->state) )
        continue;
    }

    /* Decode the Element.
     */
    status = MAsn1DecodeIndefiniteUpdateFlag (
      pDecodeInput->pEncoding + totalLen, currentLen, pDecodeInput->decodeFlag,
      pElement, pDecodeInput->DataReturn, pDecodeInput->pCallbackInfo,
      &bytesRead, &isComplete);
    if (OK != status)
      goto exit;

    currentLen -= bytesRead;
    totalLen += bytesRead;

    /* If this is not indefinite, update the remaining. If it is indefinite, the
     * remaining is 0, so we don't update it.
     */
    if (0 == isIndef)
      pDecodeInput->pOfElement->buffer.remaining -= bytesRead;

  } while (1);

  *(pDecodeOutput->pBytesRead) = totalLen;
  status = OK;

  /* We have either read all the OF entries, or we ran out of data.
   * If this is an indefinite, then check to see if the localState is
   * DECODE_00_TAG.
   * If so, we have completed the OF, we can set the OF Element's state to
   * MASN1_STATE_DECODE_INDEF_00_1, meaning we have read the first 00 of the end
   * 00 00. Otherwise, we ran out of input.
   */
  if (0 != isIndef)
  {
    pDecodeInput->pOfElement->state = MASN1_STATE_DECODE_PARTIAL_INDEF;
    if (MOC_INDEF_OF_DECODE_00_TAG == localState)
      pDecodeInput->pOfElement->state = MASN1_STATE_DECODE_INDEF_00_1;

    goto exit;
  }

  /* Because this is not indefinite, we kept track of how much data we needed to
   * read total in remaining. So if that is now 0, we're done.
   */
  pDecodeInput->pOfElement->state = MASN1_STATE_DECODE_PARTIAL;
  if (0 == pDecodeInput->pOfElement->buffer.remaining)
    pDecodeInput->pOfElement->state = MASN1_STATE_DECODE_COMPLETE;

exit:

  return (status);
}
