/*
 * tagandlen.c
 *
 * Determine the tag and length of an encoding.
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

MOC_EXTERN MSTATUS ASN1_getTagLen(
  ubyte expectedTag,
  ubyte *pDerEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte byteCount, j;

  if ( (NULL == pDerEncoding) || (NULL == pEncodingLen) )
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *pEncodingLen = 0;

  if (*pDerEncoding != expectedTag)
  {
    status = ERR_ASN_UNEXPECTED_TAG;
    goto exit;
  }

  pDerEncoding++;

  /* If the length byte is 0x80 then the encoding is indefinite which will
   * not be supported.
   * 
   * If the length byte is less then 0x80 then the byte itself is the length
   * of the certificate along with 2 extra bytes for the tag and length byte.
   * 
   * If the length byte is greater then 0x80 (cannot exceed 0x84) then the
   * next few bytes are the length bytes along with the extra 2 bytes for the
   * tag and the length.
   */
  if (0x80 == *pDerEncoding)
  {
    status = ERR_ASN_INDEFINITE_LEN_UNSUPPORTED;
    goto exit;
  }
  else if (0x80 > *pDerEncoding)
  {
    *pEncodingLen = *pDerEncoding;
  }
  else
  {
    byteCount = *pDerEncoding - 0x80;
    if (4 < byteCount)
    {
      status = ERR_ASN_BAD_LENGTH_FIELD;
      goto exit;
    }

    for (j = 0; j < byteCount; ++j)
      *pEncodingLen |= (*(pDerEncoding + byteCount - j) << (j * 8));

    *pEncodingLen += byteCount;
  }
  *pEncodingLen += 2;

  status = OK;

exit:

  return status;
}

MOC_EXTERN MSTATUS ASN1_readTagAndLen (
  const ubyte *pDerEncoding,
  ubyte4      derEncodingLen,
  ubyte4      *pTheTag,
  sbyte4      *pTheLen,
  ubyte4      *pTagAndLenLen
  )
{
  MSTATUS status;
  ubyte4 totalLen, count, index;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDerEncoding) || (NULL == pTheTag) ||
       (NULL == pTheLen) || (NULL == pTagAndLenLen) )
    goto exit;

  status = ERR_ASN_INVALID_DATA;
  if (2 > derEncodingLen)
    goto exit;

  *pTheTag = (ubyte4)(pDerEncoding[0]);
  totalLen = (ubyte4)(pDerEncoding[1]);

  /* If the length octet is > 0x84, it's either a length we don't support or a
   * bad encoding.
   */
  status = ERR_BAD_LENGTH;
  if (0x84 < totalLen)
    goto exit;

  /* Init for indefinite length. If it is, we're done.
   */
  status = OK;
  *pTagAndLenLen = 2;
  *pTheLen = -1;
  if (0x80 == totalLen)
    goto exit;

  /* Is the length made up of more than one byte?
   */
  count = 0;
  if (0x80 < totalLen)
  {
    /* How many bytes make up the length?
     */
    count = totalLen & 7;

    /* Make sure we have enough bytes to read.
     */
    status = ERR_ASN_INVALID_DATA;
    if ((2 + count) > derEncodingLen)
      goto exit;

    totalLen = 0;
    for (index = 0; index < count; ++index)
    {
      totalLen <<= 8;
      totalLen += (ubyte4)(pDerEncoding[index + 2]);
    }

    /* If the msBit is set, we don't support that length.
     */
    status = ERR_BAD_LENGTH;
    if (0 != (totalLen & 0x80000000))
      goto exit;
  }

  /* Now set the return values.
   */
  *pTagAndLenLen = 2 + count;
  *pTheLen = (sbyte4)totalLen;

  /* Make sure the buffer is big enough for the given length.
   */
  status = ERR_BUFFER_OVERFLOW;
  if ((2 + count + totalLen) > derEncodingLen)
    goto exit;

  status = OK;

exit:

  return (status);
}

MOC_EXTERN MSTATUS ASN1_compareOID (
  const ubyte *pTargetOID,
  ubyte4      targetLen,
  const ubyte *pCheckOID,
  ubyte4      checkLen,
  ubyte4      *pLastByte,
  sbyte4      *pCmpResult
  )
{
  MSTATUS status, fStatus;
  ubyte4 theTag, lenLen, offset1, offset2;
  sbyte4 len1, len2;

  /* Init to not equal. If some OID is bad, we'll just say not equal.
   */
  *pCmpResult = 1;
  status = OK;

  /* If the first tag is 06, it's an OID.
   */
  fStatus = ASN1_readTagAndLen (
    pTargetOID, targetLen, &theTag, &len1, &lenLen);
  if (OK != fStatus)
    goto exit;

  offset1 = lenLen;
  if (6 != theTag)
  {
    /* If not OID, it must be SEQUENCE.
     */
    if (0x30 != theTag)
      goto exit;

    /* The tag after the SEQUENCE should be 06.
     */
    fStatus = ASN1_readTagAndLen (
      pTargetOID + lenLen, targetLen - lenLen, &theTag, &len1, &lenLen);
    if (OK != fStatus)
      goto exit;

    if (6 != theTag)
      goto exit;

    offset1 += lenLen;
  }

  fStatus = ASN1_readTagAndLen (
    pCheckOID, checkLen, &theTag, &len2, &lenLen);
  if (OK != fStatus)
    goto exit;

  offset2 = lenLen;
  if (6 != theTag)
  {
    if (0x30 != theTag)
      goto exit;

    fStatus = ASN1_readTagAndLen (
      pCheckOID + lenLen, checkLen - lenLen, &theTag, &len2, &lenLen);
    if (OK != fStatus)
      goto exit;

    if (6 != theTag)
      goto exit;

    offset2 += lenLen;
  }

  if (len1 != len2)
    goto exit;

  if (NULL != pLastByte)
  {
    len1--;
    *pLastByte = (ubyte4)(pCheckOID[offset2 + len1]);
  }

  status = DIGI_MEMCMP (
    (void *)(pTargetOID + offset1), (void *)(pCheckOID + offset2), len1,
    pCmpResult);

exit:

  return (status);
}
