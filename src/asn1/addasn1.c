/*
 * addasn1.c
 *
 * Functions to add data by parts for EncodeUpdate.
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

#if ((!defined(__DISABLE_DIGICERT_ASN1_DER_ENCODE_BY_PARTS__)) && \
     (!defined(__DISABLE_DIGICERT_ASN1_DER_ENCODE_ALL_OPERATIONS__)))

MSTATUS MAsn1SetValueLenSpecial (
  MAsn1Element *pElement,
  ubyte4 flag
  )
{
  MSTATUS status;
  ubyte4 newFlag, noVal;

  status = ERR_NULL_POINTER;
  if (NULL == pElement)
    goto exit;

  /* This is only valid for encoding.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pElement->buffer.pBuf)
    goto exit;

  /* If this is not a CLEAR call, this is only valid if the state is NONE. We
   * can't set this after trying to do other things.
   * Well, the INDEF bit can be set.
   */
  if (0 == (flag & (MASN1_CLEAR_UNKNOWN_VALUE | MASN1_CLEAR_UNKNOWN_OF)))
  {
    status = ERR_ASN_INVALID_STATE;
    if (MASN1_STATE_NONE != (pElement->state & (~MASN1_STATE_ENCODE_INDEF)))
      goto exit;
  }

  /* Once an Element has been set with NO_VAL, it can't be reset.
   */
  noVal = pElement->state & MASN1_NO_VALUE;

  /* This is what we will OR into type. Init to 0 in case the input is a CLEAR
   * call.
   */
  newFlag = 0;
  switch (flag)
  {
    default:
      status = ERR_INVALID_INPUT;
      goto exit;

    case MASN1_NO_VALUE:
      newFlag = MASN1_NO_VALUE;

      /* If no val, then also make sure the bufLen is 0 and the bufFlag indicates
       * no trailing 00 00 bytes.
       */
      pElement->bufLen = 0;
      pElement->bufFlag &= (~MASN1_BUF_FLAG_ZERO_COUNT_MASK);

      /* Set the state to COMPLETE.
       */
      pElement->state = MASN1_STATE_ENCODE_COMPLETE;
      /* fall through */

    case MASN1_CLEAR_UNKNOWN_VALUE:
      /* Clear these bits. We're assuming they never were set if not allowed, so
       * we assume this is allowed.
       */
      pElement->type &= (~(MASN1_UNKNOWN_VALUE | MASN1_CLEAR_UNKNOWN_OF));
      break;

    case MASN1_UNKNOWN_VALUE:
      /* This is valid only for Elements that were created for ENCODE_INDEF and
       * are allowed to be INDEF.
       */
      status = ERR_ASN_INVALID_TAG_INFO;
      if (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE_INDEF))
        goto exit;

      if (0 == (pElement->type & MASN1_CONSTRUCTED_MASK))
      {
        if (0 == (pElement->type & MASN1_TYPE_INDEF_ALLOWED))
          goto exit;
      }

      newFlag = MASN1_UNKNOWN_VALUE;
      break;

    case MASN1_UNKNOWN_OF:
      newFlag = MASN1_UNKNOWN_OF;
      /* fall through */

    case MASN1_CLEAR_UNKNOWN_OF:
      /* This is valid only for Elements that were created for ENCODE_INDEF and
       * are OF.
       */
      status = ERR_ASN_INVALID_TAG_INFO;
      if ( (0 == (pElement->bufFlag & MASN1_BUF_FLAG_ENCODE_INDEF)) ||
           (0 == (pElement->type & MASN1_TYPE_OF)) )
        goto exit;

      pElement->type &= (~(MASN1_UNKNOWN_VALUE | MASN1_UNKNOWN_OF));
      break;
  }

  /* If it is currently NO_VALUE, it is illegal to set it to anything else.
   * status is currently set to STATE error.
   */
  if ( (0 != noVal) && (MASN1_NO_VALUE != newFlag) )
    goto exit;

  pElement->type |= newFlag;
  status = OK;

exit:

  return (status);
}

MSTATUS MAsn1SetValueLen (
  MAsn1Element *pElement,
  ubyte4 valueLen
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 tag, eLen;

  status = ERR_NULL_POINTER;
  if (NULL == pElement)
    goto exit;

  /* Make sure this Element was set up to encode.
   * And it can't be constructed.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pElement->buffer.pBuf)
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (0 != (pElement->type & MASN1_CONSTRUCTED_MASK))
    goto exit;

  tag = pElement->type & MASN1_TYPE_MASK;

  /* We can set the length only if the state is NONE, meaning we have not done
   * anything yet to this Element.
   */
  status = ERR_ASN_INVALID_STATE;
  if (MASN1_STATE_NONE != pElement->state)
    goto exit;

  /* We allow this for INTEGER, OCTET STRING, strings (UTF8String, etc.), and
   * ENCODED.
   */
  status = ERR_ASN_INVALID_TAG_INFO;
  if ( (MASN1_TYPE_INTEGER != tag) && (MASN1_TYPE_OCTET_STRING != tag) &&
       (MASN1_TYPE_UTF8_STRING != tag) && (MASN1_TYPE_PRINT_STRING != tag) &&
       (MASN1_TYPE_BMP_STRING != tag) && (MASN1_TYPE_ENCODED != tag) )
    goto exit;

  /* If the UNKNOWN_VALUE bit is set, clear it.
   */
  pElement->type &= (~(MASN1_UNKNOWN_VALUE | MASN1_CLEAR_UNKNOWN_OF));

  /* Set the valueLen and call ComputeTagAndLen.
   */
  pElement->valueLen = valueLen;

  /* Set the state to know that we have set the length, but no data yet.
   */
  pElement->state = MASN1_STATE_SET_LEN;
  status = MAsn1ComputeTagAndLenIndef (pElement, 0, &isComplete, &eLen);
  if (OK != status)
    goto exit;

  /* Now set the remaining field to the bytes remaining to be added.
   */
  pElement->encoding.remaining = valueLen;

  /* Set pElement->valueLen to 0 to indicate there's currently no data to output.
   */
  pElement->valueLen = 0;

exit:

  return (status);
}

MSTATUS MAsn1AddData (
  MAsn1Element *pElement,
  const ubyte *pNewData,
  ubyte4 newDataLen
  )
{
  MSTATUS status;
  ubyte4 newLen;

  status = ERR_NULL_POINTER;
  if (NULL == pElement)
    goto exit;

  /* We can only add data if the state is MASN1_STATE_SET_LEN,
   * MASN1_STATE_ENCODE_TAG_LEN, or MASN1_STATE_ENCODE_PARTIAL.
   * And the remaining must be >= newValueLen.
   * If the state is SET_PARTIAL, that means we called AddData, then didn't call
   * EncodeUpdate and generate that output.
   */
  status = ERR_ASN_INVALID_STATE;
  if ( (MASN1_STATE_SET_LEN != pElement->state) &&
       (MASN1_STATE_ENCODE_TAG_LEN != pElement->state) &&
       (MASN1_STATE_ENCODE_PARTIAL != pElement->state) )
    goto exit;

  newLen = 0;
  if (NULL != pNewData)
    newLen = newDataLen;

  status = ERR_ASN_INCONSISTENT_LENGTH;
  if (pElement->encoding.remaining < newLen)
    goto exit;

  /* Now copy a reference to the new data, decrement remaining, and update the
   * state. If remaining is 0, the Set is complete, otherwise it is partial.
   */
  pElement->encoding.remaining -= newLen;
  pElement->value.pValue = (ubyte *)pNewData;
  pElement->valueLen = newLen;
  pElement->state = MASN1_STATE_SET_COMPLETE;
  if (0 != pElement->encoding.remaining)
    pElement->state = MASN1_STATE_SET_PARTIAL;

  status = OK;

exit:

  return (status);
}

#endif /* ((!defined(__DISABLE_DIGICERT_ASN1_DER_ENCODE_BY_PARTS__)) etc */
