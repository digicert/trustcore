/*
 * encasn1.c
 *
 * Operate on ENCODED.
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

MSTATUS MAsn1SetEncoded (
  MAsn1Element *pEncodedElement,
  ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status;
  sbyte4 theLen;
  ubyte4 theTag, tlLen, leftTag;

  status = ERR_NULL_POINTER;
  if (NULL == pEncodedElement)
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (MASN1_TYPE_ENCODED != (pEncodedElement->type & MASN1_TYPE_MASK))
    goto exit;

  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pEncodedElement->buffer.pBuf)
    goto exit;

  /* It's possible to have no data. This might be how someone writes out an
   * OPTIONAL component, for example.
   */
  status = OK;
  if ( (NULL == pData) || (0 == dataLen) )
    goto exit;

  /* Try to read the tag and len.
   */
  status = ASN1_readTagAndLen (
    pData, dataLen, &theTag, &theLen, &tlLen);
  if (OK != status)
    goto exit;

  /* If theLen is < 0, this was indefinite length. That's not allowed in DER.
   */
  status = ERR_ASN_INDEFINITE_LEN_UNSUPPORTED;
  if (0 > theLen)
    goto exit;

  /* theLen plus tlLen should equal dataLen.
   */
  status = ERR_ASN_INCONSISTENT_LENGTH;
  if (((ubyte4)theLen + tlLen) != dataLen)
    goto exit;

  /* Look at the tag, see if we can find an invalid value.
   */
  status = ERR_ASN_INVALID_TAG_INFO;
  leftTag = theTag >> 4;
  if (0x31 < theTag)
  {
    /* If > 31 (greater than SET), then we only accept A0 (EXPLICIT) and 80
     * (IMPLICIT).
     */
    if ( (0xA != leftTag) && (0x8 != leftTag) )
      goto exit;
  }
  else
  {
    /* If 31 or less, it must be a valid tag.
     * Invalid tags:
     *   0E - 11
     *   1F - 2F
     */
    if ( (0x0E <= theTag) && (0x11 >= theTag) )
      goto exit;
    if ( (0x1F <= theTag) && (0x2F >= theTag) )
      goto exit;
  }

  pEncodedElement->value.pValue = pData;
  pEncodedElement->valueLen = dataLen;
  pEncodedElement->state = MASN1_STATE_SET_COMPLETE;
  status = OK;

exit:

  return (status);
}
