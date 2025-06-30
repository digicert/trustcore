/*
 * intasn1.c
 *
 * Operate on INTEGER.
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

MOC_EXTERN MSTATUS MAsn1SetInteger (
  MAsn1Element *pIntegerElement,
  ubyte *pCanonicalInt,
  ubyte4 intLen,
  intBoolean isPositive,
  sbyte4 intValue
  )
{
  MSTATUS status;
  intBoolean isPos;
  ubyte4 index, byteCount, addByte, stripByte, bitCheck, count;

  status = ERR_NULL_POINTER;
  if (NULL == pIntegerElement)
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (MASN1_TYPE_INTEGER != (pIntegerElement->type & MASN1_TYPE_MASK))
    goto exit;

  /* Make sure this Element was set up to encode.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pIntegerElement->buffer.pBuf)
    goto exit;

  /* Init to the byte array.
   * If we are working on the intValue, change it.
   */
  pIntegerElement->value.pValue = pCanonicalInt;
  pIntegerElement->valueLen = intLen;
  byteCount = intLen - 1;
  isPos = isPositive;

  /* If the canonical value is NULL, get the int as a byte array.
   */
  if ( (NULL == pCanonicalInt) || (0 == intLen) )
  {
    /* Convert the number to a byte array. Use pBuf, we know there are at least 8
     * bytes available.
     * Put the data into the last 4 bytes, then move the pointer ahead until
     * reaching the first byte of the array we want to use.
     */
    index = 7;
    pIntegerElement->buffer.pBuf[index] = (ubyte)(intValue & 0xFF);
    pIntegerElement->buffer.pBuf[index - 1] = (ubyte)((intValue >>  8) & 0xFF);
    pIntegerElement->buffer.pBuf[index - 2] = (ubyte)((intValue >> 16) & 0xFF);
    pIntegerElement->buffer.pBuf[index - 3] = (ubyte)((intValue >> 24) & 0xFF);

    pIntegerElement->value.pValue = pIntegerElement->buffer.pBuf + 4;
    pIntegerElement->valueLen = 4;
    byteCount = 3;

    isPos = FALSE;
    if (0 <= intValue)
      isPos = TRUE;
  }

  /* Check the msByte. If the sign (isPos) does not match the msBit, add the
   * extra byte.
   */
  addByte = 0;
  stripByte = 0;
  bitCheck = (ubyte4)(pIntegerElement->value.pValue[0] & 0x80);
  if (FALSE == isPos)
  {
    /* If the number is negative then we want a nonzero bitCheck.
     */
    if (0 == bitCheck)
    {
      /* The msBit is not 1, so we need to prepend an ff byte.
       */
      addByte = 0x80ff;
    }
    else
    {
      /* The msBit is set, so we need to check for bytes to strip.
       */
      stripByte = 0xFF;
      bitCheck = 0;
    }
  }
  else
  {
    /* If the number is positive then we want a zero bitCheck.
     */
    if (0 != bitCheck)
    {
      /* The msBit is not 1, so we need to prepend a 00 byte.
       */
      addByte = 0x8000;
    }
    else
    {
      /* The msBit is not set, so we need to check for bytes to strip.
       */
      bitCheck = 0x80;
    }
  }

  /* If we're not adding a byte, check for stripping.
   */
  count = 0;
  if (0 == addByte)
  {
    /* Start with the most significant byte. If it is the strip byte, see if the
     * next byte's leading bit requires us to strip the current byte.
     */
    index = 0;
    while ( (index < byteCount) && (pIntegerElement->value.pValue[index] == stripByte) )
    {
      /* If the leading bit is the "wrong" bit, we need the strip byte after all,
       * so don't strip, we're done.
       */
      if ((pIntegerElement->value.pValue[index + 1] & 0x80) == bitCheck)
        break;

      index++;
      count++;
    }

    pIntegerElement->value.pValue += count;
    pIntegerElement->valueLen -= count;
    count = 0;
  }
  else
  {
    /* We need to add a byte.
     * After we compute the tag and len, we'll take this extra byte off the
     * length.
     */
    pIntegerElement->valueLen++;
    count = 1;
  }

  pIntegerElement->state = MASN1_STATE_SET_COMPLETE;
  status = MAsn1ComputeTagAndLenIndef (pIntegerElement, 0, &isPos, &index);
  if (OK != status)
    goto exit;

  if (0 != addByte)
  {
    pIntegerElement->buffer.pBuf[pIntegerElement->bufLen] = (ubyte)(addByte & 0xFF);
    pIntegerElement->bufLen++;
  }

  pIntegerElement->valueLen -= count;

exit:

  return (status);
}
