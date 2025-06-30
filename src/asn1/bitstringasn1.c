/*
 * bitstringasn1.c
 *
 * Operate on BIT STRING.
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

MSTATUS MAsn1SetBitString (
  MAsn1Element *pBitStringElement,
  intBoolean isNamed,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 bitCount
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte currentOctet;
  ubyte4 unusedBits, lenToUse, position, stripCount, index;

  status = ERR_NULL_POINTER;
  if (NULL == pBitStringElement)
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (MASN1_TYPE_BIT_STRING != (pBitStringElement->type & MASN1_TYPE_MASK))
    goto exit;

  /* Make sure this Element was set up to encode.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pBitStringElement->buffer.pBuf)
    goto exit;

  lenToUse = (bitCount + 7) / 8;

  /* Init this value to 0, meaning we are not going to write out an alternate
   * last octet. We might have an alternate value if there is padding.
   */
  pBitStringElement->bitStringLast = 0;

  /* How many of the bits in the lsOctet of the data are unused?
   */
  unusedBits = (lenToUse * 8) - bitCount;

  /* There can be extra bytes in the data passed in (we'll ignore them), but
   * there cannot be fewer bytes than expected. Even if one (or more) byte is all
   * 0 bits, the caller must still pass in at least bitCount bits.
   */
  if (dataLen < lenToUse)
    goto exit;

  if (FALSE == isNamed)
  {
    /* For Unnamed BIT STRINGs, this function requires a bitCount that is a
     * multiple of 8. If unusedBits is 0, then we know bitCount was a multiple of
     * 8.
     */
    status = ERR_INVALID_INPUT;
    if (0 != unusedBits)
      goto exit;
  }
  else
  {
    /* This is a Named BIT STRING.
     */

    /* How many of the trailing bits are 0?
     */
    position = unusedBits;
    stripCount = 0;
    for (index = lenToUse; index > 0; --index)
    {
      currentOctet = pData[index - 1];
      while (position < 8)
      {
        if (0 != (currentOctet & (1 << position)))
          break;

        unusedBits++;
        position++;
        if (8 <= unusedBits)
          unusedBits = 0;
      }

      /* If position < 8, then we found a non-zero bit, we're done.
       */
      if (8 > position)
        break;

      /* At this point, an entire octet (or at least the contents of an entire
       * octet we examine) is 0. So move on to the next octet.
       */
      position = 0;
      stripCount++;
    }

    /* The stripCount is the number of octets of the data we don't write out.
     * If stripCount is not 0, we're going to print out lenToUse - stripCount
     * bytes, and there's no need to store an alternate last octet.
     * But if stripCount is 0, we're using all the octets passed in. We need to
     * make sure all the pad bits are 0. The last octet we have might have stray
     * bits. But we can't overwrite the buffer we were given, so we need to make
     * an alternate last octet.
     * Of course, if there are no unused bits, then there is no padding, so
     * there's no need for the alternate last byte there, either.
     */
    lenToUse -= stripCount;
    if ( (0 == stripCount) && (0 != unusedBits) )
    {
      position = 0xff << unusedBits;
      currentOctet = (pData[lenToUse - 1]) & (ubyte)position;
      pBitStringElement->bitStringLast = 0x0100 | (ubyte2)currentOctet;
    }
  }

  /* Store the input.
   * Set the valueLen to the length plus 1 for the unused bits octet. But only
   * for the computation of the tag and len.
   */
  pBitStringElement->value.pValue = pData;
  pBitStringElement->valueLen = lenToUse + 1;

  /* Determine the tag and len.
   */
  pBitStringElement->state = MASN1_STATE_SET_COMPLETE;
  status = MAsn1ComputeTagAndLenIndef (pBitStringElement, 0, &isComplete, &index);
  if (OK != status)
    goto exit;

  /* Now take away the unusedBits 1 from the valueLen.
   */
  pBitStringElement->valueLen--;

  /* If we have an alternate last byte, decrement valueLen again.
   * If we have an alternate byte, we know the length is at least 1. If there is
   * no data to output (it's possible if all the bits are 0), then the unusedBits
   * would be 0 and we would not have an alternate.
   */
  if (0 != (pBitStringElement->bitStringLast & 0xff00))
  {
    pBitStringElement->valueLen--;
  }

  /* Place the unusedBits into the pBuf after the len octet[s].
   */
  pBitStringElement->buffer.pBuf[pBitStringElement->bufLen] = (ubyte)unusedBits;
  pBitStringElement->bufLen++;

exit:

  return (status);
}
