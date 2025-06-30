/*
 * indefdecode.c
 *
 * DER decode by parts, if any element is indefinite length, handle it, using the
 * callback if necessary.
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

/* Check to see if this Element can be empty. If so, set it (and any sub
 * Elements) to empty.
 */
MSTATUS MCheckAndSetEmpty (
  MAsn1Element *pElement
  );

/* Set the Element as empty. This does not check, it simply sets it. This is
 * generally for sub Elements of an OPTIONAL constructed.
 */
MSTATUS MSetEmpty (
  MAsn1Element *pElement
  );

/* Read the tag at pEncoding.
 * <p>The caller must guarantee that there is at least one byte of data at
 * pEncoding (encodingLen is at least 1).
 * <p>The function will determine, based on the type and state, whether it should
 * read the EXPLICIT tag or regular tag. It will then verify that the tag is
 * correct. It will also determine if the tag indicates indefinite length.
 * <p>If the tag is not correct, the function will set *bytesRead to 0 and
 * *pIsMatch to FALSE. It will determine if the Element is OPTIONAL. If so, the
 * return will be OK, otherwise, an error.
 * <p>The function will update the state.
 */
MSTATUS MReadTag (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 *pBytesRead
  );

/* Read the length octets. Update appropriate fields in the Element.
 * <p>The caller guarantees at least one byte of data at pEncoding.
 * <p>If the length consists of more than one octet, and all the bytes are not
 * available, the state can be set to indicate the length has not been completely
 * read.
 * <p>If the indefFlag is 0, then  indefinite length is allowed. If it is not 0,
 * then indefinite is not allowed.
 */
MSTATUS MReadLength (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 indefFlag,
  ubyte4 *pBytesRead
  );

/* pElement is constructed, (SET, SEQUENCE).
 * To read this Element, read the subordinate elements.
 */
MSTATUS MReadConstructed (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  );

/* pElement is an OF (SET OF, SEQ OF).
 * To read an OF, read the subordinate, then if there is more data, clone the
 * subordinate and read another.
 */
MSTATUS MReadOf (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  );

/* The Element is a simple type, so we need to read the data.
 * This simply sets pValue to point to the data, or if indefinite, it calls the
 * DataReturn function.
 */
MSTATUS MReadData (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  );

/* The encoding is indefinite, but the Element is ENCODED. So this function will
 * know how to skip over the data. It will pass data to the DataReturn, but it
 * won't try to actually decode anything.
 * Note that there is a bytesRead arg, indicating how many of this Element's
 * bytes have been read so far (this will likely never be more than 2). Add that
 * value to the bytes read in this function to get the total number of bytes read
 * to return at *pBytesRead.
 */
MSTATUS MReadIndefiniteEncoded (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 bytesRead,
  ubyte4 *pBytesRead
  );

MSTATUS MAsn1DecodeIndefiniteUpdate (
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  MAsn1Element *pElement,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  )
{
  return MAsn1DecodeIndefiniteUpdateFlag(pEncoding,
                                         encodingLen,
                                         MASN1_DECODE_UPDATE,
                                         pElement,
                                         DataReturn,
                                         pCallbackInfo,
                                         pBytesRead,
                                         pIsComplete);
}

MSTATUS MAsn1DecodeIndefiniteUpdateFlag (
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  MAsn1Element *pElement,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;
  ubyte4 bytesRead, totalRead, currentLen;
  ubyte4 constructed, ofTag;

  totalRead = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || (NULL == DataReturn) ||
       (NULL == pBytesRead) || (NULL == pIsComplete) )
    goto exit;

  *pBytesRead = 0;
  *pIsComplete = TRUE;

  /* We can have a NULL encoding, so long as the length is 0.
   * Otherwise it is an error.
   */
  if ( (NULL == pEncoding) && (0 != encodingLen) )
    goto exit;

  /* If this Element is done, just return.
   */
  status = OK;
  if (MASN1_STATE_DECODE_COMPLETE == (pElement->state & MASN1_STATE_DECODE_COMPLETE))
    goto exit;

  /* If there is no data and this is not the last Update (LAST_CALL bit is not set),
   * there's no need to do anything.
   * If there is no data and it is the last, then we need to decode to OPTIONAL.
   */
  *pIsComplete = FALSE;
  if ( (encodingLen == 0) && (0 == (decodeFlag & MASN1_DECODE_LAST_CALL)) )
    goto exit;

  currentLen = encodingLen;
  constructed = pElement->type & MASN1_CONSTRUCTED_MASK;
  ofTag = pElement->type & MASN1_TYPE_OF;

  /* If this is not constructed, make sure pValue is NULL and valueLen is 0.
   * If this is decode by parts, there might be previous data.
   */
  if (0 == constructed)
  {
    pElement->value.pValue = NULL;
    pElement->valueLen = 0;
  }

  do
  {
    /* If we're continuing an encoded indef, call that routine.
     */
    if (0 != (pElement->state & MASN1_STATE_DECODE_INDEF_ENCODED))
    {
      status = MReadIndefiniteEncoded (
        pElement, pEncoding + totalRead, currentLen, decodeFlag,
        DataReturn, pCallbackInfo, totalRead, &totalRead);
      goto exit;
    }

    switch (pElement->state)
    {
      default:
        status = ERR_ASN_INVALID_STATE;
        goto exit;

      case MASN1_STATE_DECODE_LEN_INDEF:
        /* If we just read an indefinite length, we usually need to read a tag
         * for actual data. However, if this element is constructed, there is no
         * tag with actual data, we need to move on to the next element.
         * Set the state to PARTIAL so it will read contents.
         */
        if (0 != constructed)
        {
          pElement->state = MASN1_STATE_DECODE_PARTIAL_INDEF;
          break;
        }

      case MASN1_STATE_NONE:
      case MASN1_STATE_DECODE_START:
      case MASN1_STATE_DECODE_LENX:
      case MASN1_STATE_DECODE_LENX_INDEF:
      case MASN1_STATE_DECODE_INDEF_BLOCK:
        /* It's possible someone init the array for ENCODE and there is indeed a
         * buffer (so remaining is not 0). Init to this to indicate we don't have
         * any length yet.
         */
        pElement->buffer.remaining = 0;

        /* First, read the tag.
         * This function will try to read the explicit tag if there is one, or
         * the regular tag if not.
         * It will determine if the tag is correct or not. If not, it will
         * determine if this is OPTIONAL. If not, error.
         * If no error, it will reset the state, just update currentLen and
         * totalRead and move on.
         */
        status = MReadTag (
          pElement, pEncoding + totalRead, currentLen, &bytesRead);
        if (OK != status)
          goto exit;

        currentLen -= bytesRead;
        totalRead += bytesRead;
        break;

      case MASN1_STATE_DECODE_TAGX:
      case MASN1_STATE_DECODE_TAG:
      case MASN1_STATE_DECODE_TAG_INDEF:
      case MASN1_STATE_DECODE_INDEF_TAG:
      case MASN1_STATE_DECODE_LEN_LENX:
      case MASN1_STATE_DECODE_PARTIAL_LENX:
      case MASN1_STATE_DECODE_LEN_LEN:
      case MASN1_STATE_DECODE_INDEF_LEN_LEN:
      case MASN1_STATE_DECODE_PARTIAL_LEN:
      case MASN1_STATE_DECODE_INDEF_PARTIAL_LEN:
      case MASN1_STATE_DECODE_INDEF_00_1:
        status = MReadLength (
          pElement, pEncoding + totalRead, currentLen,
          (decodeFlag & MASN1_DECODE_NO_INDEF), &bytesRead);
        if (OK != status)
          goto exit;

        currentLen -= bytesRead;
        totalRead += bytesRead;
        break;

      case MASN1_STATE_DECODE_LEN:
      case MASN1_STATE_DECODE_INDEF_LEN:
      case MASN1_STATE_DECODE_PARTIAL:
      case MASN1_STATE_DECODE_PARTIAL_INDEF:
        /* Begin reading the data.
         */
        if (0 != constructed)
        {
          if (0 != ofTag)
          {
            status = MReadOf (
              pElement, pEncoding + totalRead, currentLen, decodeFlag,
              DataReturn, pCallbackInfo, &bytesRead);
            if (OK != status)
              goto exit;

            currentLen -= bytesRead;
            totalRead += bytesRead;
            break;
          }

          status = MReadConstructed (
            pElement, pEncoding + totalRead, currentLen, decodeFlag,
            DataReturn, pCallbackInfo, &bytesRead);
          if (OK != status)
            goto exit;

          currentLen -= bytesRead;
          totalRead += bytesRead;
          break;
        }

        status = MReadData (
          pElement, pEncoding + totalRead, currentLen,
          DataReturn, pCallbackInfo, &bytesRead);
        if (OK != status)
          goto exit;

        currentLen -= bytesRead;
        totalRead += bytesRead;
        break;

      case MASN1_STATE_DECODE_INDEF_00_2:
        pElement->state = MASN1_STATE_DECODE_COMPLETE_INDEF;
        /* fall through */

      case MASN1_STATE_DECODE_COMPLETE:
      case MASN1_STATE_DECODE_COMPLETE_INDEF:
        /* This will likely happen if we are reading by parts. We just started
         * reading a constructed again and need to skip the complete elements to
         * get to the element in progress.
         */
        status = OK;
        goto exit;
    }

  } while (currentLen > 0);

  /* There's no more data. If this completes the Element, we're done.
   * If not, then either we are in the middle of the data (we'll get the next
   * data from the next Update call), or there will be no more data.
   * If isLast is FALSE, it doesn't matter, we'll figure it out the next call, so
   * just quit.
   * But if this is the last call, and this Element is not complete, check to see
   * if it is allowed to be OPTIONAL.
   */
  if ( (MASN1_STATE_DECODE_COMPLETE == (pElement->state & MASN1_STATE_DECODE_COMPLETE)) ||
       (0 == (decodeFlag & MASN1_DECODE_LAST_CALL)) )
    goto exit;

  /* If this call returns an error, convert it to unexpected end, because if
   * this Element is not allowed to be empty, that's the error we want to
   * return now. The Check function can return a different error because it
   * might be called from another place.
   */
  status = MCheckAndSetEmpty (pElement);
  if (OK != status)
    status = ERR_ASN_UNEXPECTED_END;

exit:

  /* If there was no error, set the return values.
   */
  if (OK == status)
  {
    *pBytesRead = totalRead;
    if (MASN1_STATE_DECODE_COMPLETE == (pElement->state & MASN1_STATE_DECODE_COMPLETE))
      *pIsComplete = TRUE;
  }

  return (status);
}

MSTATUS MReadTag (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  ubyte4 theTag, constructed, newState, indefState, optFlag;
  ubyte4 expectedTag, expectedTagX, checkTag;

  /* Init as if the tag will be correct. If we get a mismatch, change this.
   */
  *pBytesRead = 1;
  status = OK;

  constructed = pElement->type & MASN1_CONSTRUCTED_MASK;
  optFlag = pElement->type & (MASN1_OPTIONAL | MASN1_DEFAULT);
  newState = MASN1_STATE_NONE;

  theTag = 0;
  if (0 != encodingLen)
  {
    theTag = (ubyte4)(pEncoding[0]) & 0xff;
  }
  else if (0 != optFlag)
  {
    /* If we reach this code, the data was ready for reading.
     * If this is OPTIONAL or DEFAULT, that's fine. */
    *pBytesRead = 0;
    newState = MASN1_STATE_NONE;
    goto exit;
  }

  /* Isolate the tag and EXPLICIT tag (if there is one).
   */
  expectedTag = (pElement->type & MASN1_TAG_MASK) >> MASN1_TYPE_SHIFT_COUNT;
  expectedTagX = 0xA0 | (pElement->type & 0x0f);
  if (0 == (pElement->type & MASN1_EXPLICIT))
    expectedTagX = 0;

  switch (pElement->state)
  {
    default:
      *pBytesRead = 0;
      status = ERR_ASN_INVALID_STATE;
      goto exit;

    case MASN1_STATE_NONE:
      /* If the state is NONE, we've done nothing, check the EXPLICIT tag. If
       * there is no EXPLICIT tag, just drop through to the START state.
       */
      if (0 != expectedTagX)
      {
        pElement->encoding.pEncoding = (ubyte *)pEncoding;
        pElement->encodingLen = 1;

        /* If this Element is EXPLICIT, we check the TagX, even if the type is
         * ENCODED. It's possible someone has an EXPLICIT and OPTIONAL along with
         * ENCODED.
         */
        newState = MASN1_STATE_DECODE_TAGX;
        if (expectedTagX == theTag)
          goto exit;

        /* If the explicit tag does not match, break out of this switch statement
         * to the code that handles a non-matching tag.
         */
        pElement->encoding.pEncoding = NULL;
        pElement->encodingLen = 0;
        break;
      }

    case MASN1_STATE_DECODE_START:
    case MASN1_STATE_DECODE_LENX:
    case MASN1_STATE_DECODE_LENX_INDEF:
      /* If this is being called after LENX_INDEF, we want to make sure we
       * remember that this is part of an indefinite.
       */
      indefState = pElement->bufFlag & MASN1_BUF_FLAG_INDEF_EXP;

      /* If this is IMPLICIT, the tag changes.
       */
      if (0 != (pElement->type & MASN1_IMPLICIT))
      {
        expectedTag = 0x80 | (pElement->type & 0x0f);
        if (0 != constructed)
          expectedTag |= 0xA0;
      }

      /* If there is an EXPLICIT, then we read the tag and len and set the
       * encoding.pEncoding to point to the full encoding.
       * If not, this tag starts the full encoding.
       */
      if (0 == expectedTagX)
        pElement->encoding.pEncoding = (ubyte *)pEncoding;

      pElement->encodingLen++;

      /* If everything works, the state will be DECODE_TAG.
       * Unless this was under an EXPLICIT indefinite, then it will be INDEF_TAG
       * if the tag is exact, or TAG_INDEF if the tag is indefinite.
       */
      if (MASN1_STATE_DECODE_LENX_INDEF == pElement->state)
      {
        newState = MASN1_STATE_DECODE_TAG_INDEF;
      }
      else
      {
        newState = MASN1_STATE_DECODE_INDEF_TAG;
        if (0 == indefState)
          newState = MASN1_STATE_DECODE_TAG;
      }

      /* If the type is ENCODED, and the caller did not specify a tag, we accept
       * the tag as correct.
       * Also, we need to set the pValue and valueLen.
       * Save this tag to pass to the DatReturn callback if the length
       * turns out to be indefinite.
       * Use the bitStringLast field because that is not used in decoding.
       */
      if (0 != (MASN1_TYPE_ENCODED & pElement->type))
      {
        expectedTag = (pElement->type >> 8) & 0xff;

        /* Someone can set ENCODED and a tag. This is generally used for
         * OPTIONAL. That is, something is OPTIONAL, and if it's there, just
         * copy it as ENCODED. And if it is not, skip it and move on.
         */
        if ( (0 != expectedTag) && (expectedTag != theTag) )
        {
          /* If the EXPLICIT bit was set and we get this far, then the
           * EXPLICIT passed. If the tag is wrong now, that's an error.
           */
          if (0 != expectedTagX)
          {
            status = ERR_ASN_UNEXPECTED_TAG;
            goto exit;
          }

          break;
        }

        pElement->value.pValue = (ubyte *)pEncoding;
        pElement->valueLen = 1;
        pElement->bitStringLast = (ubyte2)theTag;
        goto exit;
      }

      /* If the tag is correct, we're done.
       */
      if (expectedTag == theTag)
        goto exit;

      /* The tag does not match. But there is one other possibility.
       * If this is ANY_TIME, make sure the tag is either UTC or GenTime.
       */
      if (MASN1_TYPE_ANY_TIME_TAG == expectedTag)
      {
        if ( (MASN1_TYPE_UTC_TIME_TAG == theTag) ||
             (MASN1_TYPE_GEN_TIME_TAG == theTag) )
          goto exit;
      }

      /* The tag does not match.
       * The tag might be indefinite length. To find out, check to see if this tag
       * is allowed to be indefinite length, if so, determine what that tag would
       * be.
       * If this is constructed, the tag does not change, so we know this is not a
       * match.
       */
      checkTag = pElement->type & MASN1_TAG_MASK;
      if (0 != constructed)
        break;

      if ( (MASN1_TYPE_BIT_STRING != checkTag) &&
           (MASN1_TYPE_OCTET_STRING != checkTag) &&
           (MASN1_TYPE_UTF8_STRING != checkTag) &&
           (MASN1_TYPE_PRINT_STRING != checkTag) &&
           (MASN1_TYPE_IA5_STRING != checkTag) &&
           (MASN1_TYPE_BMP_STRING != checkTag) )
        break;

      expectedTag |= MASN1_TYPE_INDEF_BIT;
      newState = MASN1_STATE_DECODE_TAG_INDEF;
      if (expectedTag == theTag)
      {
        /* If this is indefinite, then check to see if there was an EXPLICIT. If
         * so, then that length must be indefinite as well.
         */
        if ( (0 == expectedTagX) || (0 != indefState) )
          goto exit;
      }

      break;

    case MASN1_STATE_DECODE_LEN_INDEF:
    case MASN1_STATE_DECODE_INDEF_BLOCK:
      pElement->encodingLen++;

      /* If the state is LEN_INDEF, we now need to start reading blocks.
       *
       * If the state is INDEF_BLOCK, we completed reading a block of data
       * underneath an indefinite tag. We're expecting either 00 00 or another
       * tag.
       */
      newState = MASN1_STATE_DECODE_INDEF_00_1;
      if (0 == theTag)
        goto exit;

      /* The tag wasn't 00, so it should be expectedTag. It is not allowed to be
       * indefinite. Also, even if the Element is IMPLICIT, we don't change this
       * tag.
       */
      newState = MASN1_STATE_DECODE_INDEF_TAG;
      if (expectedTag == theTag)
        goto exit;

      break;

    case MASN1_STATE_DECODE_INDEF_00_2:
      /* This happens if we have an EXPLICIT that is indefinite length, and the
       * tag is also. There are two 00 00 pairs for this Element.
       */
      pElement->encodingLen++;
      if (0 == theTag)
      {
        newState = MASN1_STATE_DECODE_INDEF_00_1;
        goto exit;
      }

      break;
  }

  /* If we reach this code, the tag was not expected.
   * If this is OPTIONAL, that's fine, if not, error.
   * Note that the subroutine will expect the state to be NONE. It is possible to
   * get the wrong tag and this will return an error. For example, if this had been
   * EXPLICIT where the EXPLICIT tag was correct but the regular tag was wrong,
   * then we're calling this subroutine with a state of READ_EXP_TAG.
   */
  *pBytesRead = 0;
  newState = MASN1_STATE_NONE;

  status = MCheckAndSetEmpty (pElement);

exit:

  if (MASN1_STATE_NONE != newState)
    pElement->state = newState;

  return (status);
}

MSTATUS MReadLength (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 indefFlag,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  ubyte4 constructed, encoded, currentLen, offset, count, theVal;

  constructed = pElement->type & MASN1_CONSTRUCTED_MASK;
  encoded =  pElement->type & MASN1_TYPE_ENCODED;
  currentLen = encodingLen;
  offset = 0;
  count = 0;
  *pBytesRead = 0;
  status = OK;

  /* If this is encoded, and we have not yet set value.pValue, do so now.
   */
  if ( (0 != encoded) && (NULL == pElement->value.pValue) )
    pElement->value.pValue = (ubyte *)pEncoding;

  while (0 < currentLen)
  {
    /* Read the next byte.
     */
    theVal = (ubyte4)(pEncoding[offset]) & 0xff;

    switch (pElement->state)
    {
      default:
        status = ERR_ASN_INVALID_STATE;
        goto exit;

      case MASN1_STATE_DECODE_TAG_INDEF:
        /* If the state is TAG_INDEF, the length must be 80.
         * This happens when a regular tag was changed to an indefinite tag.
         */
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (0x80 != theVal)
          goto exit;

        /* We know the state is LEN_INDEF, because if the tag for which we are
         * reading the length were EXPLICIT, we would not have been in the state
         * TAG_INDEF.
         */
        count++;
        pElement->encodingLen++;
        pElement->bufFlag |= (MASN1_BUF_FLAG_INDEF_TAG | MASN1_BUF_FLAG_INDEF);
        pElement->state = MASN1_STATE_DECODE_LEN_INDEF;
        status = OK;
        goto exit;

      case MASN1_STATE_DECODE_TAGX:
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (theVal > 0x84)
          goto exit;

        /* If the current byte is < 0x80, that's the length, we're done reading
         * the length.
         */
        count++;
        pElement->encodingLen++;
        pElement->buffer.remaining = theVal;
        pElement->state = MASN1_STATE_DECODE_LENX;
        status = OK;
        if (theVal < 0x80)
          goto exit;

        /* If the current byte is 0x80, this EXPLICIT is indefinite length. It's
         * the only byte for length, so we're done reading length.
         * However, if the Element is also ENCODED, we need to reset the state to
         * an INDEF_ENCODED value
         */
        pElement->buffer.remaining = 0;
        if (theVal == 0x80)
        {
          pElement->bufFlag |= (MASN1_BUF_FLAG_INDEF_EXP | MASN1_BUF_FLAG_INDEF);
          pElement->state = MASN1_STATE_DECODE_LENX_INDEF;
          if (0 == encoded)
            goto exit;

          /* This is EXPLICIT, ENCODED, and indefinite.
           */
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_LENX;
          goto exit;
        }

        /* The current byte is the length of the length.
         */
        pElement->bufLen = theVal & 0x0f;
        pElement->state = MASN1_STATE_DECODE_LEN_LENX;
        break;

      case MASN1_STATE_DECODE_TAG:
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (theVal > 0x84)
          goto exit;

        /* If the current byte is < 0x80, that's the length, we're done reading
         * the length.
         */
        count++;
        pElement->encodingLen++;

        pElement->state = MASN1_STATE_DECODE_LEN;
        status = OK;
        if (theVal < 0x80)
        {
          pElement->buffer.remaining = theVal;
          pElement->encodingLen += theVal;
          if (0 != encoded)
          {
            /* If the type is ENCODED, update the valueLen.
             * The valueLen was init to 1 for the tag, now we need to add on to
             * the valueLen 1 for the length octet.
             */
            pElement->valueLen += 1;
            pElement->state = MASN1_STATE_DECODE_LEN;
          }
          else if (0 == constructed)
          {
            /* If this is not constructed, we know how long the value is.
             * If it is constructed, the valueLen is the number of subelements so
             * we don't want to touch that.
             */
            pElement->valueLen = theVal;
          }
          goto exit;
        }

        /* If the current byte is 0x80, this is indefinite length. It's
         * the only byte for length, so we're done reading length.
         * However, if the Element is also ENCODED, we need to reset the state to
         * an INDEF_ENCODED value
         */
        if (theVal == 0x80)
        {
          /* If this is not constructed, we're going to pass the data to the
           * DataReturn callback, so the valueLen should be 0.
           */
          if (0 == constructed)
            pElement->valueLen = 0;

          pElement->bufFlag |= (MASN1_BUF_FLAG_INDEF_TAG | MASN1_BUF_FLAG_INDEF);
          pElement->buffer.remaining = 0;

          pElement->state = MASN1_STATE_DECODE_LEN_INDEF;
          if (0 == encoded)
            goto exit;

          /* We have read the tag but not passed it to the DataReturn. Normally
           * we don't pass the tag to the DataReturn, but if this is ENCODED, we
           * need to, so set the state to indicate we still need to send the tag
           * to the DataReturn.
           */
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_LEN_NO_TAG;
          goto exit;
        }

        /* The current byte is the length of the length.
         * Also, if this is ENCODED, add in this octet to the valueLen.
         */
        if (0 != encoded)
          pElement->valueLen += 1;

        pElement->state = MASN1_STATE_DECODE_LEN_LEN;
        pElement->bufLen = theVal & 0x0f;
        pElement->buffer.remaining = 0;
        break;

      case MASN1_STATE_DECODE_INDEF_TAG:
        /* This state means we are in an indefinite, but reading a block. E.g.
         * there is 24 80 04 len --- 04 len etc. We have just read one of the 04
         * tags. In this case, the length is not allowed to be indefinite.
         */
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if ( (0x80 == theVal) || (0x84 < theVal) )
          goto exit;

        /* We know this is not constructed because of the state. The state is
         * INDEF_TAG, which means the tag was changed based on indefinite, and
         * constructeds don't change.
         */
        count++;
        pElement->encodingLen++;
        pElement->buffer.remaining = theVal;
        pElement->valueLen = theVal;
        pElement->state = MASN1_STATE_DECODE_INDEF_LEN;
        status = OK;
        if (theVal < 0x80)
        {
          pElement->encodingLen += theVal;
          goto exit;
        }

        /* The current byte is the length of the length.
         */
        pElement->buffer.remaining = 0;
        pElement->valueLen = 0;
        pElement->state = MASN1_STATE_DECODE_INDEF_LEN_LEN;
        pElement->bufLen = theVal & 0x0f;
        break;

      case MASN1_STATE_DECODE_LEN_LENX:
      case MASN1_STATE_DECODE_PARTIAL_LENX:
        /* We have bufLen more bytes of the length to read.
         */
        pElement->bufLen--;
        pElement->buffer.remaining =
          (pElement->buffer.remaining << 8) + ((ubyte4)theVal & 0xff);
        pElement->encodingLen++;

        count++;
        pElement->state = MASN1_STATE_DECODE_LENX;
        if (0 == pElement->bufLen)
          goto exit;

        pElement->state = MASN1_STATE_DECODE_PARTIAL_LENX;
        break;

      case MASN1_STATE_DECODE_LEN_LEN:
      case MASN1_STATE_DECODE_PARTIAL_LEN:
        /* We have bufLen more bytes of the length to read.
         */
        pElement->bufLen--;
        pElement->buffer.remaining =
          (pElement->buffer.remaining << 8) + ((ubyte4)theVal & 0xff);
        pElement->encodingLen++;

        /* If this is ENCODED, we need to add this octet to the valueLen.
         */
        if (0 != encoded)
          pElement->valueLen += 1;

        count++;
        pElement->state = MASN1_STATE_DECODE_LEN;
        if (0 == pElement->bufLen)
        {
          pElement->encodingLen += pElement->buffer.remaining;
          goto exit;
        }

        pElement->state = MASN1_STATE_DECODE_PARTIAL_LEN;
        break;

      case MASN1_STATE_DECODE_INDEF_LEN_LEN:
      case MASN1_STATE_DECODE_INDEF_PARTIAL_LEN:
        /* We have bufLen more bytes of the length to read.
         */
        pElement->bufLen--;
        pElement->buffer.remaining =
          (pElement->buffer.remaining << 8) + ((ubyte4)theVal & 0xff);
        pElement->encodingLen++;

        /* If this is ENCODED, we need to add this octet to the valueLen.
         */
        if (0 != encoded)
          pElement->valueLen += 1;

        count++;
        pElement->state = MASN1_STATE_DECODE_INDEF_LEN;
        if (0 == pElement->bufLen)
        {
          pElement->encodingLen += pElement->buffer.remaining;
          goto exit;
        }

        pElement->state = MASN1_STATE_DECODE_INDEF_PARTIAL_LEN;
        break;

      case MASN1_STATE_DECODE_INDEF_00_1:
        /* We read an 00 as a tag. We expect to see an 00 now.
         */
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (0 != theVal)
          goto exit;

        count++;
        pElement->encodingLen++;

        /* If the INDEF_TAG bit is set, this is the 00 00 for the tag. We've read
         * it so now take out that tag.
         * If the INDEF_TAG bit is not set, then this is for the EXPLICIT.
         * If the INDEF_EXP is set, we still need to read the 00 00 for the
         * EXPLICIT.
         * If there are no more bits set afterwards, we are done with this
         * Element.
         */
        if (0 != (pElement->bufFlag & MASN1_BUF_FLAG_INDEF_TAG))
        {
          /* If this is ENCODED, we need to add this octet to the valueLen.
           */
          if (0 != encoded)
            pElement->valueLen += 1;

          pElement->bufFlag ^= MASN1_BUF_FLAG_INDEF_TAG;
          pElement->state = MASN1_STATE_DECODE_INDEF_BLOCK;
          if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_INDEF_EXP))
            pElement->state = MASN1_STATE_DECODE_COMPLETE_INDEF;
        }
        else
        {
          pElement->bufFlag &= ~MASN1_BUF_FLAG_INDEF_EXP;
          pElement->state = MASN1_STATE_DECODE_COMPLETE_INDEF;
        }

        status = OK;
        goto exit;
    }

    currentLen--;
    offset++;
  }

exit:

  if ( (0 != indefFlag) && (0 != (pElement->state & MASN1_STATE_DECODE_INDEF)) &&
       (OK == status) )
    status = ERR_ASN_INDEFINITE_LEN_NOT_ALLOWED;

  *pBytesRead = count;

  return (status);
}

MSTATUS MReadConstructed (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 newFlag;
  ubyte4 index, currentLen, bytesRead, totalRead, isIndef;
  MAsn1Element *pNext;

  totalRead = 0;
  currentLen = encodingLen;
  newFlag = decodeFlag;
  isIndef = pElement->bufFlag & MASN1_BUF_FLAG_INDEF;
  pNext = pElement + 1;

  /* Read the subordinate elements.
   * We might be reading them only to find the next. For example, it might happen
   * that we're reading by parts and we're done with an element. We just need to
   * know the next.
   */
  index = 1;
  isComplete = FALSE;
  do
  {
    status = MAsn1DecodeIndefiniteUpdateFlag (
      pEncoding + totalRead, currentLen, newFlag, pNext,
      DataReturn, pCallbackInfo, &bytesRead, &isComplete);
    if (OK != status)
      goto exit;

    currentLen -= bytesRead;
    totalRead += bytesRead;

    /* If this is indefinite, then how many bytes we read are added to the
     * encodingLen.
     * If it is not indefinite, decrement the bytes read from the remaining.
     */
    if (0 != isIndef)
    {
      pElement->encodingLen += bytesRead;
    }
    else
    {
      /* If bytesRead > remaining, then there was a bad sub Element.
       */
      status = ERR_ASN_INCONSISTENT_LENGTH;
      if (bytesRead > pElement->buffer.remaining)
        goto exit;

      pElement->buffer.remaining -= bytesRead;

      /* If this completes the number of bytes to read, then set newFlag to
       * LAST_CALL and the input INDEF bit so that when we read the remaining sub
       * Elements, we know they have no data.
       */
      if (0 == pElement->buffer.remaining)
        newFlag = MASN1_DECODE_LAST_CALL | (decodeFlag & MASN1_DECODE_NO_INDEF);
    }

    /* If this was the last sub Element, quit the loop.
     */
    if (index >= pElement->valueLen)
      break;

    index++;
    pNext = (MAsn1Element *)(pNext->pNext);

  } while (1);

  *pBytesRead = totalRead;
  status = OK;

  /* If the last sub Element is complete, this Element is complete.
   */
  if (FALSE != isComplete)
  {
    /* If this is indefinite, then we need to read the 00 00.
     */
    pElement->state = MASN1_STATE_DECODE_INDEF_BLOCK;
    if (0 == isIndef)
      pElement->state = MASN1_STATE_DECODE_COMPLETE;
  }
  else
  {
    pElement->state = MASN1_STATE_DECODE_PARTIAL_INDEF;
    if (0 == isIndef)
      pElement->state = MASN1_STATE_DECODE_PARTIAL;
  }

exit:

  return (status);
}

MSTATUS MReadOf (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  MAsn1OfDecodeInput ofInput;
  MAsn1OfDecodeOutput ofOutput;

  ofInput.pOfElement = pElement;
  ofInput.pEncoding = (ubyte *)pEncoding;
  ofInput.encodingLen = encodingLen;
  ofInput.decodeFlag = decodeFlag;
  ofInput.DataReturn = DataReturn;
  ofInput.pCallbackInfo = pCallbackInfo;
  ofOutput.pBytesRead = pBytesRead;

  /* If this is not indefinite (the OF Element is not indefinite), then we want
   * to make sure we have the exact length of data. If the length remaining is
   * less than encodingLen, that's all we want to pass to the OfFunction.
   * If the OF is indefinite, we want to read subordinate Elements until we reach
   * an 00 00. So we need to know how many bytes we have to work with.
   */
  if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_INDEF))
  {
    if (ofInput.encodingLen > pElement->buffer.remaining)
      ofInput.encodingLen = pElement->buffer.remaining;
  }

  status = pElement->value.pOfTemplate->OfFunction (
    &(pElement->value.pOfTemplate->entry), MASN1_OF_DECODE,
    (void *)&ofInput, (void *)&ofOutput);
  if (OK != status)
    goto exit;

exit:

  return (status);
}

MSTATUS MReadData (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  ubyte4 dataLen;

  *pBytesRead = 0;

  /* The dataLen is the bytes remaining.
   * If the encodingLen is shorter than remaining, that's the number of bytes we
   * will return.
   */
  dataLen = pElement->buffer.remaining;
  if (encodingLen < dataLen)
    dataLen = encodingLen;

  status = OK;
  *pBytesRead = dataLen;

  if (0 == encodingLen)
    goto exit;

  /* If this is indefinite, call the DataReturn.
   */
  if (0 != (pElement->bufFlag & MASN1_BUF_FLAG_INDEF))
  {
    status = DataReturn (pCallbackInfo, (ubyte *)pEncoding, dataLen, pElement);
    if (OK != status)
      goto exit;

    /* Reduce remaining.
     * If remaining is now 0, we're done with a block. If not, we're only partial.
     */
    pElement->buffer.remaining -= dataLen;

    pElement->state = MASN1_STATE_DECODE_PARTIAL_INDEF;
    if (0 == pElement->buffer.remaining)
      pElement->state = MASN1_STATE_DECODE_INDEF_BLOCK;

    goto exit;
  }

  /* If this is not indefinite, set pValue to the encoding and valueLen to
   * dataLen.
   * The exception is if this is ENCODED, in which case we might already have
   * pValue set, we just need to add dataLen to valueLen.
   */
  if (0 == (MASN1_TYPE_ENCODED & pElement->type))
  {
    pElement->value.pValue = (ubyte *)pEncoding;
    pElement->valueLen = dataLen;
  }
  else
  {
    /* If we have not yet set value.pValue, do so now.
     */
    if (NULL == pElement->value.pValue)
      pElement->value.pValue = (ubyte *)pEncoding;

    pElement->valueLen += dataLen;
  }

  pElement->buffer.remaining -= dataLen;

  pElement->state = MASN1_STATE_DECODE_PARTIAL;
  if (0 == pElement->buffer.remaining)
    pElement->state = MASN1_STATE_DECODE_COMPLETE;

exit:

  return (status);
}

MSTATUS MReadIndefiniteEncoded (
  MAsn1Element *pElement,
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 bytesAlreadyRead,
  ubyte4 *pBytesRead
  )
{
  MSTATUS status;
  ubyte4 totalRead, currentLen, offset, theVal, count, copyLen;
  ubyte pTemp[2];

  currentLen = encodingLen;
  totalRead = bytesAlreadyRead;
  offset = 0;
  *pBytesRead = 0;

  while (currentLen > 0)
  {
    switch (pElement->state)
    {
      default:
        status = ERR_ASN_INVALID_STATE;
        goto exit;

      case MASN1_STATE_DECODE_INDEF_ENCODED_LENX:
        /* We have an ENCODED, EXPLICIT and we have read the EXPLICIT tag and the
         * length. The length is 0x80.
         * Set the count to 1 (the number of 00 00 pairs we're looking for).
         * Now read the regular tag and pass it to the DataReturn callback.
         */
        pElement->bufFlag |= (1 << MASN1_BUF_FLAG_ZERO_COUNT_SHIFT);
        /* fall through */

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_DATA:
        /* We have just finished decoding a sub TLV. We should now be seeing a
         * tag.
         * We can just drop through to the code that reads the initial regular
         * tag after EXPLICIT. That will do just what we need to do now.
         */
      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_INDEF_LEN:
        /* We have decoded a sub tag and it is indefinite as well.
         * We can just drop through to the code that reads the initial regular
         * tag after EXPLICIT. That will do just what we need to do now.
         */
      case MASN1_STATE_DECODE_INDEF_ENCODED_LEN:
        /* We have decoded the main tag with 80, we now expect to see a tag.
         * We can just drop through to the code that reads the initial regular
         * tag after EXPLICIT. That will do just what we need to do now.
         */

        /* If the octet we read is 00, then this is the 00 00 that ends an
         * indefinite.
         * We generally return the 00 00. There is one exception. If this is
         * EXPLICIT and this is the 00 00 for the EXPLICIT, then we don't return
         * that. If this is EXPLICIT ENCODED, we return the data that is the TLV
         * excluding the EXPLICIT.
         * So check the count, if the count is 1, don't return the data.
         */
        copyLen = 1;
        if (0 == pEncoding[offset])
        {
          count =
            (pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) >>
            MASN1_BUF_FLAG_ZERO_COUNT_SHIFT;
          if ( (0 != (pElement->type & MASN1_EXPLICIT)) && (1 == count) )
          {
            copyLen = 0;
          }
        }

        if (0 != copyLen)
        {
          status = DataReturn (
            pCallbackInfo, (ubyte *)pEncoding + offset, 1, pElement);
          if (OK != status)
            goto exit;
        }

        /* This might be the first 00 of the 00 00 that indicates the end.
         */
        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_00_1;
        if (0 != pEncoding[offset])
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_TAG;

        totalRead++;
        currentLen--;
        offset++;
        pElement->encodingLen++;

        break;

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_TAG:
        /* We have just read a sub tag, we need to read the length.
         * Just drop through to the code that reads the length of the main
         * indefinite tag, theat does just what we need done for this case.
         */

      case MASN1_STATE_DECODE_INDEF_ENCODED_TAG:
        /* We've read a tag and passed it to the DataReturn. Now we expect to
         * read a 0x80. It's possible someone has written out 0xA0 80 30 len (the
         * EXPLICIT is indefinite but the regular is definite). That's not
         * likely, but possible, so we need to read the length.
         */

        theVal = (ubyte4)(pEncoding[offset]) & 0xff;

        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (theVal > 0x84)
          goto exit;

        status = DataReturn (
          pCallbackInfo, (ubyte *)pEncoding + offset, 1, pElement);
        if (OK != status)
          goto exit;

        totalRead++;
        currentLen--;
        offset++;
        pElement->encodingLen++;
        if (0x80 == theVal)
        {
          /* Set this value so we know we are looking for one more 00 00 pair.
           */
          count =
            (pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) +
            (1 << MASN1_BUF_FLAG_ZERO_COUNT_SHIFT);
          pElement->bufFlag =
            ((~MASN1_BUF_FLAG_ZERO_COUNT_MASK) & pElement->bufFlag) + count;
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_LEN;
          break;
        }

        /* If the value is 0x7f or lower, that's how many bytes we need to pass
         * to the DataReturn callback.
         */
        if (0x7f >= theVal)
        {
          pElement->buffer.remaining = theVal;
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN;
          break;
        }

        /* The byte indicates how many bytes make up the length.
         */
        pElement->bufLen = theVal & 0x0f;
        pElement->buffer.remaining = 0;
        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN_LEN;
        break;

      case MASN1_STATE_DECODE_INDEF_ENCODED_LEN_NO_TAG:
        /* We have decoded a tag and len, it is tag with indefinite length. But
         * we have not passed those values to the DataReturn.
         * Pass those values then set the state. The tag is in bitStringLast.
         */
        pTemp[0] = (ubyte)(pElement->bitStringLast);
        pTemp[1] = 0x80;
        status = DataReturn (
          pCallbackInfo, (ubyte *)pTemp, 2, pElement);
        if (OK != status)
          goto exit;

        /* We also need to set the count to 1.
         */
        pElement->bufFlag += (1 << MASN1_BUF_FLAG_ZERO_COUNT_SHIFT);

        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_LEN;
        break;

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN_LEN:
      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL_LEN:
        status = DataReturn (
          pCallbackInfo, (ubyte *)pEncoding + offset, 1, pElement);
        if (OK != status)
          goto exit;

        theVal = (ubyte4)(pEncoding[offset]) & 0xff;

        /* We have read the first byte of a sub TLV's length. It was the number
         * of bytes. We set pElement->bufLen to the number of bytes we are
         * expecting to read, and pElement->buffer.remaining to the actual length.
         */
        pElement->bufLen--;
        pElement->buffer.remaining =
          (pElement->buffer.remaining << 8) + ((ubyte4)theVal & 0xff);

        totalRead++;
        currentLen--;
        offset++;
        pElement->encodingLen++;

        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL_LEN;
        if (0 == pElement->bufLen)
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN;
        break;

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN:
      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL:
        /* We have the number of bytes we need to read in buffer.remaining. Pass
         * those bytes to DataReturn.
         */
        copyLen = currentLen;
        if (currentLen > pElement->buffer.remaining)
          copyLen = pElement->buffer.remaining;

        status = DataReturn (
          pCallbackInfo, (ubyte *)pEncoding + offset, copyLen, pElement);
        if (OK != status)
          goto exit;

        totalRead += copyLen;
        currentLen -= copyLen;
        offset += copyLen;
        pElement->buffer.remaining -= copyLen;
        pElement->encodingLen += copyLen;

        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL;
        if (0 == pElement->buffer.remaining)
          pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_DATA;

        break;

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_00_1:
        /* We encountered a 00 tag, that means we want a 00 length.
         */
        status = ERR_ASN_BAD_LENGTH_FIELD;
        if (0 != pEncoding[offset])
          goto exit;

        /* Don't return this if this is the 00 00 for EXPLICIT.
         */
        count =
          (pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) >>
          MASN1_BUF_FLAG_ZERO_COUNT_SHIFT;
        copyLen = 0;
        if ( (0 == (pElement->type & MASN1_EXPLICIT)) || (1 != count) )
          copyLen = 1;

        /* We have read the first 00 of an 00 00. Make sure the next byte is also
         * 00, and decrement the count.
         */
        if (0 != copyLen)
        {
          status = DataReturn (
            pCallbackInfo, (ubyte *)pEncoding + offset, 1, pElement);
          if (OK != status)
            goto exit;
        }

        totalRead++;
        currentLen--;
        offset++;
        pElement->encodingLen++;
        /* fall through */

      case MASN1_STATE_DECODE_INDEF_ENCODED_SUB_00_2:
        /* If count is 0, we're done with this encoded. If not, we need to read
         * the next tag.
         */
        count =
          (pElement->bufFlag & MASN1_BUF_FLAG_ZERO_COUNT_MASK) >>
          MASN1_BUF_FLAG_ZERO_COUNT_SHIFT;
        if (0 != count)
          count -= 1;

        pElement->state = MASN1_STATE_DECODE_INDEF_ENCODED_SUB_DATA;
        pElement->bufFlag =
          ((~MASN1_BUF_FLAG_ZERO_COUNT_MASK) & pElement->bufFlag) +
          (count << MASN1_BUF_FLAG_ZERO_COUNT_SHIFT);
        if (0 != count)
          break;

        pElement->state = MASN1_STATE_DECODE_COMPLETE_INDEF;
        status = OK;
        goto exit;
    }
  }

  /* If this Element is now done, there's nothing more to do. If not, then we're
   * expecting more data. If decodeFlag says this is the last call, however, there
   * will be no more data, so this is unexpected end.
   */
  status = ERR_ASN_UNEXPECTED_END;
  if ( (0 == (decodeFlag & MASN1_DECODE_LAST_CALL)) ||
       (MASN1_STATE_DECODE_COMPLETE == (pElement->state & MASN1_STATE_DECODE_COMPLETE)) )
    status = OK;

exit:

  if (OK == status)
  {
    *pBytesRead = totalRead;
  }

  return (status);
}

MSTATUS MCheckAndSetEmpty (
  MAsn1Element *pElement
  )
{
  MSTATUS status;

  /* If we read a tag and length and the length was 0, that is acceptable.
   */
  if (MASN1_STATE_DECODE_LEN != pElement->state)
  {
    /* If we have already started to decode (any state other than DECODE_LEN) and
     * now want to say empty, error.
     */
    status = ERR_ASN_INVALID_DATA;
    if (MASN1_STATE_NONE != pElement->state)
      goto exit;

    /* If this is not OPTIONAL or DEFAULT, it is not allowed to be empty.
     */
    if (0 == (pElement->type & (MASN1_OPTIONAL|MASN1_DEFAULT)))
      goto exit;
  }

  /* We are allowed to set empty, do so.
   */
  status = MSetEmpty (pElement);

exit:

  return (status);
}

MSTATUS MSetEmpty (
  MAsn1Element *pElement
  )
{
  MSTATUS status;
  ubyte4 index;
  MAsn1Element *pNext;

  /* If this is not constructed, make sure the pValue is NULL and the valueLen is
   * 0.
   * If it is constructed, we need to set each of the sub Elements.
   */
  if (0 == (pElement->type & MASN1_CONSTRUCTED_MASK))
  {
    pElement->value.pValue = NULL;
    pElement->valueLen = 0;
  }
  else
  {
    pNext = pElement + 1;
    index = 1;
    do
    {
      status = MSetEmpty (pNext);
      if ( (OK != status) || (index >= pElement->valueLen) )
        break;

      pNext = (MAsn1Element *)(pNext->pNext);
      index++;
    } while (1);
  }

  /* If the state is DECODE_LEN, we want to leave the encoding field as is (it
   * points to the TL). Otherwise, make sure it is NULL/0.
   */
  if (MASN1_STATE_DECODE_LEN != pElement->state)
  {
    pElement->encoding.pEncoding = NULL;
    pElement->encodingLen = 0;
  }

  pElement->state = MASN1_STATE_DECODE_COMPLETE;

  return (OK);
}
