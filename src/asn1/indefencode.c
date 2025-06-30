/*
 * indefencode.c
 *
 * Encode by parts, using indefinite length if necessary.
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

MSTATUS MAsn1EncodeIndefiniteUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 bufSize, spaceNeeded;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == pEncodingLen) ||
       (NULL == pIsComplete) )
    goto exit;

  bufSize = 0;
  if (NULL != pEncoding)
    bufSize = bufferSize;

  /* Make sure this Element was set up to encode indefinite.
   */
  status = ERR_ASN_INDEFINITE_LEN_NOT_ALLOWED;
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE_INDEF))
    goto exit;

  /* How big does the output buffer need to be?
   * Note that this will determine if the write will be complete or not.
   */
  status = MAsn1ComputeRequiredLenIndef (
    pElement, &spaceNeeded, &isComplete);
  if (OK != status)
    goto exit;

  *pEncodingLen = spaceNeeded;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufferSize < spaceNeeded)
    goto exit;

  status = MAsn1EncodeIndefUpdate (
    pElement, pEncoding, bufSize, pEncodingLen, pIsComplete);

exit:

  return (status);
}

MSTATUS MAsn1EncodeIndefUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 offset, index, count, subLen;
  MAsn1Element *pCurrent;
  MAsn1OfTemplate *pOfTemplate;
  MAsn1OfEntry *pOfEntry;

  *pIsComplete = FALSE;
  offset = 0;

  /* If this entry is already complete, no need to do anything.
   */
  status = OK;
  isComplete = TRUE;
  if (MASN1_STATE_ENCODE_COMPLETE == pElement->state)
    goto exit;

  /* count is the number of sub Elements for a constructed, so if this is not
   * constructed, count should be 0.
   */
  count = pElement->valueLen;
  if (0 == (pElement->type & MASN1_CONSTRUCTED_MASK))
    count = 0;

  /* If the state is SET_COMPLETE (with or without INDEF), then this write will
   * complete the Element.
   * If this is NO_VALUE_SKIP, then there is nothing more to write out so this
   * completes the Element.
   */
  if (MASN1_NO_VALUE_SKIP == (pElement->type & MASN1_NO_VALUE_SKIP))
    goto exit;

  if (MASN1_STATE_SET_COMPLETE != (pElement->state & MASN1_STATE_ENCODE_MASK))
    isComplete = FALSE;

  /* If there is anything in pBuf, write that out.
   */
  if (0 != pElement->bufLen)
  {
    if (NULL == pEncoding)
    {
      status = ERR_NULL_POINTER;
      goto exit;
    }

    status = MOC_MEMCPY (
      (void *)pEncoding, (void *)(pElement->buffer.pBuf), pElement->bufLen);
    if (OK != status)
      goto exit;

    offset = pElement->bufLen;

    /* Set to 0 to indicate it has been written out.
     */
    pElement->bufLen = 0;
    pElement->state &= MASN1_STATE_ENCODE_INDEF;
    pElement->state |= MASN1_STATE_ENCODE_TAG_LEN;
  }

  /* If this is constructed, call each of the sub Elements.
   * If this is not constructed, count is 0 and we won't enter this if.
   */
  if (0 != count)
  {
    pOfTemplate = (MAsn1OfTemplate *)(pElement->value.pOfTemplate);
    pCurrent = pElement + 1;

    pOfEntry = NULL;
    if (0 != (pElement->type & MASN1_TYPE_OF))
      pOfEntry = &(pOfTemplate->entry);

    while (NULL != pCurrent)
    {
      status = MAsn1EncodeIndefUpdate (
        pCurrent, pEncoding + offset, bufferSize - offset, &subLen,
        &isComplete);
      if (OK != status)
        goto exit;

      count--;
      offset += subLen;

      /* If this did not complete, stop encoding.
       */
      if (FALSE == isComplete)
        break;

      /* If this is not OF, get the next Element normally.
       */
      if (NULL == pOfEntry)
      {
        /* If count is now 0, we have run through all the sub Elements.
         */
        if (0 == count)
          break;

        pCurrent = (MAsn1Element *)(pCurrent->pNext);
        continue;
      }

      /* If this is OF, get the next Element through the pOfEntry.
       * If there is no next, it could be because we are complete or UNKNOWN_OF.
       */
      pOfEntry = (MAsn1OfEntry *)(pOfEntry->pNext);
      if (NULL != pOfEntry)
      {
        pCurrent = pOfEntry->pElement;
        continue;
      }

      /* If the OF is UNKNOWN_OF, simply set isComplete to FALSE.
       */
      if (0 != (pElement->type & MASN1_UNKNOWN_OF))
        isComplete = FALSE;

      break;
    }

    /* The lopp finished. Either we finished or not, it doesn't matter, just set
     * the ENCODE_PARTIAL bit, the code after the exit label will change it if it
     * needs to.
     */
    pElement->state &= MASN1_STATE_ENCODE_INDEF;
    pElement->state |= MASN1_STATE_ENCODE_PARTIAL;
    goto exit;
  }

  /* If we reach this point, this is a regular element, just write out the value.
   * It's possible valueLen is 0.
   */
  if (0 != pElement->valueLen)
  {
    status = MOC_MEMCPY (
      (void *)(pEncoding + offset), (void *)(pElement->value.pValue),
      pElement->valueLen);
    if (OK != status)
      goto exit;

    offset += pElement->valueLen;
    pElement->state &= MASN1_STATE_ENCODE_INDEF;
    pElement->state |= MASN1_STATE_ENCODE_PARTIAL;
  }

  /* Actually, there's one more possibility. If this is a BIT STRING, we might
   * have an alternate last octet.
   * Note that bit strings are not allowed to be indefinite.
   */
  if ( (MASN1_TYPE_BIT_STRING == (pElement->type & MASN1_TAG_MASK)) &&
       (0 != pElement->bitStringLast) )
  {
    pEncoding[offset] = (ubyte)(pElement->bitStringLast);
    offset++;
  }

exit:

  /* If this call completed the encoding, there are possibly two things left to
   * do. One is reset the state to complete. The other is to write out any 00 00
   * octets if necessary.
   * But only if status is OK and everything was a success.
   */
  if (OK == status)
  {
    /* Set this to indicate that we have not determined the length of the next
     * call to Encode.
     */
    pElement->encodingLen = 0;
    pElement->bufFlag &= ~(MASN1_BUF_FLAG_WILL_COMPLETE);

    if (FALSE != isComplete)
    {
      /* If there are any trailing 00 00 bytes to write out, do so now.
       */
      count =
        ((pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) >>
        MASN1_BUF_FLAG_ZERO_COUNT_SHIFT) * 2;
      for (index = 0; index < count; ++index)
      {
        pEncoding[offset] = 0;
        offset++;
      }

      /* Clear the number of 00 00 bytes to write out, now that we've written them
       * out.
       */
      pElement->bufFlag &= (~MASN1_BUF_FLAG_ZERO_COUNT_MASK);
      pElement->state = MASN1_STATE_ENCODE_COMPLETE;
      *pIsComplete = TRUE;
    }
  }

  *pEncodingLen = offset;

  return (status);
}

MSTATUS MAsn1ComputeRequiredLenIndef (
  MAsn1Element *pElement,
  ubyte4 *pSpaceRequired,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;
  intBoolean isComplete, subComplete;
  ubyte4 spaceNeeded, newLen, count, constructed;
  MAsn1Element *pCurrent;
  MAsn1OfTemplate *pOfTemplate;
  MAsn1OfEntry *pOfEntry;

  /* If this is done already, no need to do any computations.
   */
  isComplete = TRUE;
  spaceNeeded = pElement->encodingLen;
  status = OK;
  if (MASN1_STATE_ENCODE_COMPLETE == pElement->state)
    goto exit;

  if (0 != pElement->encodingLen)
  {
    if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_WILL_COMPLETE))
      isComplete = FALSE;

    goto exit;
  }

  constructed = pElement->type & MASN1_CONSTRUCTED_MASK;

  /* Have we initialized this Element?
   */
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE_INDEF_INIT))
  {
    /* To initialize, set the tag and len.
     */
    status = MAsn1ComputeTagAndLenIndef (
      pElement, 0, &isComplete, &spaceNeeded);
    if (OK != status)
      goto exit;

    /* If isComplete is TRUE, then the spaceNeeded is the answer.
     */
    if (FALSE != isComplete)
      goto exit;
  }

  /* If the NO_VALUE bit is set, we're done.
   */
  if (0 != (pElement->type & MASN1_NO_VALUE))
    goto exit;

  /* If the UNKNOWN_VALUE bit is set, we don't need to go any further, but we do
   * need to reset isComplete to FALSE.
   */
  isComplete = FALSE;
  if (0 != (pElement->type & MASN1_UNKNOWN_VALUE))
    goto exit;

  subComplete = FALSE;

  /* count is the number of sub Elements for a constructed, so if this is not
   * constructed, count should be 0.
   */
  count = pElement->valueLen;
  if (0 == (pElement->type & MASN1_CONSTRUCTED_MASK))
    count = 0;

  /* If this is constructed, find the space needed by each sub Element.
   */
  spaceNeeded = 0;
  if (0 != constructed)
  {
    pCurrent = pElement + 1;
    pOfTemplate = (MAsn1OfTemplate *)(pElement->value.pOfTemplate);

    pOfEntry = NULL;
    if (0 != (pElement->type & MASN1_TYPE_OF))
      pOfEntry = &(pOfTemplate->entry);

    while (NULL != pCurrent)
    {
      /* Find the sub Element's space needed.
       */
      status = MAsn1ComputeRequiredLenIndef (
        pCurrent, &newLen, &subComplete);
      if (OK != status)
        goto exit;

      spaceNeeded += newLen;
      count--;

      /* If this sub Element won't complete, no need to go further.
       */
      if (FALSE == subComplete)
        break;

      /* Find the next element.
       * If this is not OF, get the next Element normally.
       */
      if (NULL == pOfEntry)
      {
        /* If count is now 0, we have run through all the sub Elements.
         */
        if (0 == count)
          break;

        pCurrent = (MAsn1Element *)(pCurrent->pNext);
        continue;
      }

      /* If this is OF, get the next Element through the pOfEntry.
       * If there is no next, it could be because we are complete or UNKNOWN_OF.
       */
      pOfEntry = (MAsn1OfEntry *)(pOfEntry->pNext);
      if (NULL != pOfEntry)
      {
        pCurrent = pOfEntry->pElement;
        continue;
      }

      /* If we reach this point we have no more OF entries. It's possible this
       * is the last entry, but it is also possible the caller set UNKNOWN_OF,
       * in which case we don't want to complete this Element.
       */
      if (0 != (pElement->type & MASN1_UNKNOWN_OF))
        subComplete = FALSE;

      break;
    }
  }

  /* If constructed, the space required is bufLen plus the space required for the
   * sub Elements we just computed.
   * If not constructed, it is bufLen and valueLen. If not constructed,
   * spaceNeeded was init to 0.
   * We also need to determine if this write will be complete or not.
   * If this will be complete, add in the trailing 00 00 bytes.
   */
  spaceNeeded += pElement->bufLen;
  if (0 == constructed)
  {
    spaceNeeded += pElement->valueLen;
    /* Will this be the last of the data to write out? It will be if the state is
     * SET_COMPLETE (with or without INDEF).
     */
    if (MASN1_STATE_SET_COMPLETE == (pElement->state & MASN1_STATE_ENCODE_MASK))
      subComplete = TRUE;
  }

  /* If this is constructed, and every sub Element was complete, then subComplete
   * will be TRUE. Otherwise someone was not complete (set subComplete to FALSE)
   * and we broke out early.
   * If this is not constructed, we init subComplete to FALSE, but reset it to
   * TRUE just above if the state indicated to do so.
   * Hence, subComplete is the result we want to return.
   */
  isComplete = subComplete;

  if (FALSE != subComplete)
  {
    spaceNeeded +=
      (((pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) >>
      MASN1_BUF_FLAG_ZERO_COUNT_SHIFT) * 2);
  }

exit:

  if (OK == status)
  {
    *pSpaceRequired = spaceNeeded;
    *pIsComplete = isComplete;

    pElement->encodingLen = spaceNeeded;
    if (FALSE != isComplete)
      pElement->bufFlag |= MASN1_BUF_FLAG_WILL_COMPLETE;
  }

  return (status);
}

MSTATUS MAsn1ComputeTagAndLenIndef (
  MAsn1Element *pElement,
  ubyte4 flag,
  intBoolean *pIsComplete,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  intBoolean isComplete, subComplete;
  ubyte4 newFlag, constructed, count;
  ubyte4 totalLen, newLen, indef, subCount;
  MAsn1Element *pCurrent;
  MAsn1OfTemplate *pOfTemplate;
  MAsn1OfEntry *pOfEntry;

  constructed = pElement->type & MASN1_CONSTRUCTED_MASK;
  newFlag = flag;
  indef = 0;
  totalLen = 0;
  isComplete = FALSE;
  *pEncodingLen = 0;

  /* If the input flag is 0, we want to use whatever the Element's type says.
   * If the input flag is UNKNOWN_OF, that just tells us this is a sub Element of
   * an OF but we want to write out this Element if we can. So use the Element's
   * type.
   */
  if ( (0 == flag) || (MASN1_UNKNOWN_OF == flag) )
    newFlag = pElement->type & MASN1_VALUE_TYPE_MASK;

  /* If constructed, this is the number of sub Elements. If not, this is the
   * input data length.
   */
  count = pElement->valueLen;

  /* At this point, if newFlag is UNKNOWN_VALUE, there's nothing we can do.
   */
  status = OK;
  if (MASN1_UNKNOWN_VALUE == newFlag)
    goto exit;

  /* If constructed, query all the sub Elements. Get the totalLen from them.
   */
  if (0 != constructed)
  {
    pOfTemplate = (MAsn1OfTemplate *)(pElement->value.pOfTemplate);
    pCurrent = pElement + 1;

    pOfEntry = NULL;
    if (0 != (pElement->type & MASN1_TYPE_OF))
      pOfEntry = &(pOfTemplate->entry);

    /* This is the number of sub Elements that are NOT complete.
     */
    subCount = 0;

    /* What do we send to the sub Elements? Normally it is the same flag as we're
     * using for this constructed. But if the constructed is NO_VALUE, that means
     * the subs are NO_VALUE_SKIP (write out nothing no matter what).
     */
    if (MASN1_NO_VALUE == newFlag)
      newFlag = MASN1_NO_VALUE_SKIP;

    /* For each of the sub Elements, determine the tag/len. If that determines
     * the encodingLen, we can know that length is added to this Element's len.
     */
    while (NULL != pCurrent)
    {
      status = MAsn1ComputeTagAndLenIndef (
        pCurrent, newFlag, &subComplete, &newLen);
      if (OK != status)
        goto exit;

      count--;

      /* If the length of the sub Element is 0, then it might be indef, or it
       * might be UNKNOWN_VALUE or UNKNOWN_OF. If so, then this Element becomes
       * indef. But it is possible that the sub Element is 0 len for other
       * reasons. Note that a sub Element can be UNKNOWN_VALUE and still not set
       * the INDEF bit. This happens when it is OPTIONAL. If the state of the
       * sub Element is NONE, we assume that it is UNKNOWN_VALUE.
       */
      if (0 == newLen)
      {
        if ( (MASN1_STATE_NONE == pCurrent->state) ||
             (0 != (pCurrent->state & MASN1_STATE_ENCODE_INDEF)) ||
             (0 != (pCurrent->state & MASN1_UNKNOWN_VALUE)) )
          indef = 1;
      }

      if (FALSE == subComplete)
        subCount++;

      /* Add newLen to totalLen.
       */
      totalLen += newLen;

      /* If this is not OF, get the next Element normally.
       */
      if (NULL == pOfEntry)
      {
        /* If count is now 0, we have run through all the sub Elements.
         */
        if (0 == count)
          break;

        pCurrent = (MAsn1Element *)(pCurrent->pNext);
        continue;
      }

      /* If this is OF, get the next Element through the pOfEntry.
       * If there is no next, it could be because we are complete or UNKNOWN_OF.
       */
      pOfEntry = (MAsn1OfEntry *)(pOfEntry->pNext);
      pCurrent = NULL;
      if (NULL != pOfEntry)
      {
        pCurrent = pOfEntry->pElement;
        continue;
      }

      /* We're out of OF Elements. If that's because of UNKNOWN_OF, we know this
       * is indefinite.
       * If the input flag was UNKNOWN_OF, we set newFlag to this Element's type.
       * So if newFlag is UNKNOWN_OF, this type is UNKNOWN_OF.
       */
      if (MASN1_UNKNOWN_OF == newFlag)
        indef = 1;

      break;
    }

    if (MASN1_NO_VALUE_SKIP == newFlag)
    {
      /* If we're skipping, make sure we return no data output and set the state
       * to COMPLETE so we never deal with this again.
       */
      pElement->bufLen = 0;
      pElement->state = MASN1_STATE_ENCODE_COMPLETE;
      goto exit;
    }

    /* We init isComplete to FALSE. If all the sub Elements are complete and this
     * Element is not indefinite, switch to TRUE.
     */
    if ( (0 == subCount) && (0 == indef) )
      isComplete = TRUE;
  }
  else
  {
    /* The Element is not constructed.
     */
    totalLen = 0;
    isComplete = TRUE;

    /* Determine if this is to be encoded and if so, is it going to be indefinite
     * or not.
     */
    if (MASN1_NO_VALUE_SKIP == newFlag)
    {
      /* If we're skipping, make sure we return no data output and set the state
       * to COMPLETE so we never deal with this again.
       */
      pElement->bufLen = 0;
      pElement->state = MASN1_STATE_ENCODE_COMPLETE;
      goto exit;
    }

    if (MASN1_NO_VALUE == newFlag)
    {
      /* If it is simply NO_VALUE, then we might or might not write out the tag
       * and len (depending on OPTIONAL/DEFAULT).
       * So we're SET_COMPLETE, go to write the tag and len.
       */
      pElement->bufLen = 0;
      pElement->state = MASN1_STATE_SET_COMPLETE;
    }
    else
    {
      /* If we get to this point, there is supposed to be data.
       * For non-constructed, the totalLen is count.
       */
      totalLen = count;

      /* If the data set is not complete, set isComplete to FALSE.
       */
      if ( (MASN1_STATE_SET_COMPLETE != pElement->state) &&
           (MASN1_STATE_SET_COMPLETE_INDEF != pElement->state) )
        isComplete = FALSE;

      /* If the state is NONE, then nothing has been done to this Element. This
       * generally happens when the input flag is UNKNOWN_OF.
       * If this is UNKNOWN_OF, don't do anything (set newFlag to UNKNOWN_VALUE
       * and nothing will be done).
       * If this is not UNKNOWN_OF, this is supposed to be indefinite length.
       */
      if (MASN1_STATE_NONE == pElement->state)
      {
        newFlag = MASN1_UNKNOWN_VALUE;
        goto exit;
      }

      /* If the state is SET_LEN, SET_PARTIAL, or SET_COMPLETE (no INDEF bit),
       * then we know the length and don't need indefinite length. It's possible
       * the tag and length will have been set under these states, and if so,
       * there's no need to call SetTagAndLen.
       */
      if ( (MASN1_STATE_SET_LEN == pElement->state) ||
           (MASN1_STATE_SET_PARTIAL == pElement->state) ||
           (MASN1_STATE_SET_COMPLETE == pElement->state) )
      {
        status = OK;

        /* If the bufLen is not 0, then we've computed the tag and len already.
         * However, we're going to return totalLen + bufLen. Currently totalLen
         * is not correct if the state is PARTIAL or LEN. The totalLen is the
         * data length, which will be valueLen + remaining.
         * Also ...
         * If this is ENCODED and not EXPLICIT, we're done (no tag to compute).
         * However, the length needs to include the remaining as well as the
         * valueLen.
         */
        if ( (0 != pElement->bufLen) ||
             ((0 != (MASN1_TYPE_ENCODED & pElement->type)) &&
              (0 == (MASN1_EXPLICIT & pElement->type))) )
        {
          totalLen = pElement->valueLen + pElement->encoding.remaining;
          goto exit;
        }

        /* If we reach this point, either it is ENCODED and EXPLICIT, or regular,
         * and the TL has not been computed yet, so drop down to the code that
         * will compute it.
         */
      }
      else
      {
        /* At this point, we don't know what the actual length will be, so it is
         * indefinite.
         */
        indef = 1;

        /* We will need indefinite length. Make sure that is allowed with this type.
         */
        status = ERR_ASN_INVALID_TAG_INFO;
        if (0 == (pElement->type & MASN1_TYPE_INDEF_ALLOWED))
          goto exit;

        /* If the state is SET_PARTIAL or COMPLETE_INDEF, then we've already
         * written the tag and len to pBuf.
         */
        status = OK;
        if ( (MASN1_STATE_SET_PARTIAL_INDEF == pElement->state) ||
             (MASN1_STATE_SET_COMPLETE_INDEF == pElement->state) )
          goto exit;
      }
    }
  }

  status = MAsn1TagAndLenIndef (0, pElement, totalLen, indef);

exit:

  *pIsComplete = isComplete;

  if (FALSE != isComplete)
    pElement->bufFlag |= MASN1_BUF_FLAG_WILL_COMPLETE;

  /* If everything worked, indicate that this Element has been initialized,
   * and set *pEncodingLen if this is not indefinite.
   */
  if ( (OK == status) && (MASN1_UNKNOWN_VALUE != newFlag) )
  {
    pElement->bufFlag |= MASN1_BUF_FLAG_ENCODE_INDEF_INIT;
    if (0 == indef)
      *pEncodingLen = (totalLen + pElement->bufLen);
  }

  return (status);
}

MSTATUS MAsn1TagAndLenIndef (
  ubyte4 inType,
  MAsn1Element *pElement,
  ubyte4 valueLen,
  ubyte4 indefFlag
  )
{
  MSTATUS status;
  ubyte4 type, tag, tagX, constructed, special, vLen;
  ubyte4 index, offset, lenLen, lenLenX, tagLen, currentLen;

  type = inType;
  if (0 == inType)
    type = pElement->type;

  status = OK;
  constructed = type & MASN1_CONSTRUCTED_MASK;
  tag = type & MASN1_TYPE_MASK;
  special = type & MASN1_SPECIAL_MASK;
  vLen = valueLen;

  /* If the tag is ANY_TIME, determine which we will use based on the length of
   * the value.
   */
  if (MASN1_TYPE_ANY_TIME == tag)
  {
    tag = MASN1_TYPE_GEN_TIME;
    if (15 > vLen)
      tag = MASN1_TYPE_UTC_TIME;
  }

  /* If this is not indefinite, and if the valueLen is 0, and if this is OPTIONAL
   * or DEFAULT, don't write anything out.
   */
  if ( (0 == indefFlag) && (0 == valueLen) &&
       (0 != (pElement->type & (MASN1_OPTIONAL | MASN1_DEFAULT))) )
    goto exit;

  /* Do we have explicit?
   * The path with no branches should be the most common branch, the one with no
   * EXPLICIT.
   */
  tagX = 0xA0 | (special & 0x0f);
  if (0 == (MASN1_EXPLICIT & special))
    tagX = 0;

  /* Do we have IMPLICIT?
   * If this is ENCODED, error. We can have ENCODED with EXPLICIT, but not
   * IMPLICIT.
   */
  if (0 != (MASN1_IMPLICIT & special))
  {
    status = ERR_ASN_INVALID_TAG_INFO;
    if (MASN1_TYPE_ENCODED == tag)
      goto exit;

    tag = 0x80 | (special & 0x0f);
    if (0 != constructed)
      tag |= 0xA0;

    status = OK;
    tag <<= MASN1_TYPE_SHIFT_COUNT;
  }

  /* Determine the length len for tagX and tag.
   * If this is indefinite, the lengths len of both is 1 and we don't need to
   * compute. Set index to 2 so the loop won't execute.
   * Also, in indefinite, a non-constructed tag becomes constructed.
   */
  lenLen = 0;
  lenLenX = 0;
  index = 0;
  currentLen = vLen;
  if (0 != indefFlag)
  {
    index = 2;
    lenLen = 1;
    lenLenX = 1;
    currentLen = 0x80;
    vLen = 0x80;
    tag |= MASN1_CONSTRUCTED_MASK;
  }

  tagLen = 1;
  for (; index < 2; ++index)
  {
    if (MASN1_TYPE_ENCODED == tag)
    {
      /* If this is encoded, we're just going to copy the data.
       * So generally we don't need to determine a tag.
       * But if this is EXPLICIT, we need to determine that tag and len.
       * Set tagLen to 0, meaning there is no tag to consider when computing the
       * length of the EXPLICIT.
       */
      if (0 == tagX)
        goto exit;

      tagLen = 0;

      /* Set index to 1 to skip the first iteration and go straight to
       * computation for EXPLICIT.
       */
      index = 1;
    }

    /* Always put the answer into lenLenX. If this is the first time through,
     * we're really computing the length len of the regular tag. So after the
     * first time completes (we know that is the case when we are in the second
     * iteration), transfer it to lenLen.
     * Now the second time will compute EXPLICIT's length len and put it into
     * lenLenX, where it should be.
     * This is simply an efficiency (exercise for the reader).
     */
    if (1 == index)
    {
      /* For the second iteration, transfer to lenLen.
       * If there is no EXPLICIT, we're done.
       */
      lenLen = lenLenX;
      if (0 == tagX)
        break;

      /* If we're computing the length len of the EXPLICIT, its length is the
       * value len plus the TL of the regular tag.
       * In normal cases, tagLen is 1 (there is one tag octet to consider when
       * computing the length of the EXPLICIT). But if the type is ENCODED, that
       * will be 0.
       */
      currentLen = valueLen + lenLen + tagLen;
    }

    /* How many bytes will it take to write out the length.
     *   (hex values)
     *        00  -        7f   1
     *        80  -        ff   2
     *       100  -      ffff   3
     *     10000  -    ffffff   4
     *   1000000  -  ffffffff   5
     * Compute this in the lenLenX variable. If this is the first time through,
     * we really want this value for lenLen. We'll copy this to lenLen the second
     * time through.
     */
    lenLenX = 1;
    if (0x7F >= currentLen)
      continue;

    lenLenX = 2;
    if (0xff >= currentLen)
      continue;

    lenLenX = 3;
    if (0xffff >= currentLen)
      continue;

    lenLenX = 4;
    if (0xffffff >= currentLen)
      continue;

    lenLenX = 5;
  }

  /* At this point, write tags and lengths into pBuf.
   */
  offset = pElement->bufLen;
  if (0 != tagX)
  {
    pElement->bufLen += lenLenX + 1;
    pElement->buffer.pBuf[offset] = tagX;
    if (1 == lenLenX)
    {
      pElement->buffer.pBuf[offset + 1] = (ubyte)currentLen;
      offset += 2;
    }
    else
    {
      pElement->buffer.pBuf[offset + 1] = 0x80 + (lenLenX - 1);
      for (index = lenLenX; index > 1; --index)
      {
        pElement->buffer.pBuf[offset + index] = (ubyte)(currentLen & 0xff);
        currentLen >>= 8;
      }
      offset += lenLenX + 1;
    }

    /* If this is ENCODED, we're done.
     */
    if (MASN1_TYPE_ENCODED == tag)
      goto exit;
  }

  /* Now the regular tag. Its length is in vLen.
   */
  pElement->bufLen += (lenLen + 1);
  pElement->buffer.pBuf[offset] = (ubyte)(tag >> MASN1_TYPE_SHIFT_COUNT);
  if (1 == lenLen)
  {
    pElement->buffer.pBuf[offset + 1] = (ubyte)vLen;
  }
  else
  {
    pElement->buffer.pBuf[offset + 1] = 0x80 + (lenLen - 1);
    for (index = lenLen; index > 1; --index)
    {
      pElement->buffer.pBuf[offset + index] = (ubyte)(vLen & 0xff);
      vLen >>= 8;
    }
  }

  /* If this is indefinite, make sure the state shows that.
   * Also, set the count of how many 00 00 bytes we will need.
   */
  if (0 != indefFlag)
  {
    pElement->state |= MASN1_STATE_ENCODE_INDEF;
    index = 2;
    if (0 == tagX)
      index = 1;

    pElement->bufFlag += (ubyte2)(index << MASN1_BUF_FLAG_ZERO_COUNT_SHIFT);
  }

exit:

  return (status);
}
