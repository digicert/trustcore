/*
 * addindef.c
 *
 * Functions to add data by parts for EncodeIndefiniteUpdate.
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

MSTATUS MAsn1AddIndefiniteData (
  MAsn1Element *pElement,
  const ubyte *pNewData,
  ubyte4 newDataLen,
  intBoolean isComplete
  )
{
  MSTATUS status;
  intBoolean subComplete;
  ubyte4 checkTag, eLen;

  status = ERR_NULL_POINTER;
  if ( (NULL == pElement) || ((NULL == pNewData) && (0 != newDataLen)) )
    goto exit;

  checkTag = pElement->type & MASN1_TAG_MASK;

  /* We can call this function only if the Element was built to ENCODE_INDEF.
   */
  status = ERR_ASN_INVALID_TAG_INFO;
  if (0 == (MASN1_BUF_FLAG_ENCODE_INDEF & pElement->bufFlag))
    goto exit;

  /* We allow adding data only for INTEGER, OCTET STRING, strings (UTF8String,
   * etc.), and ENCODED.
   * This is just all the indefinite allowed plus INTEGER and ENCODED.
   * Later on, if the length ends up being indefinite, INTEGER won't be allowed.
   * But if the valueLen is set, we can add data to INTEGER.
   */
  if ( (0 == (pElement->type & MASN1_TYPE_INDEF_ALLOWED)) &&
       (MASN1_TYPE_INTEGER != checkTag) &&
       (MASN1_TYPE_ENCODED != checkTag) )
    goto exit;

  /* There are certain states not allowed.
   * If the state is SET_PARTIAL, we have set some data, but have not written it
   * out yet, so we can't add new data.
   * If the state is SET_COMPLETE, we have completely set this Element, so we
   * can't add new data.
   * If this is a set after a SetValueLen, then the remaining must be >=
   * newDataLen.
   */
  switch (pElement->state)
  {
    default:
      status = ERR_ASN_INVALID_STATE;
      goto exit;

    case MASN1_STATE_SET_LEN:
    case MASN1_STATE_ENCODE_TAG_LEN:
    case MASN1_STATE_ENCODE_PARTIAL:
      /* We know the total length.
       */
      status = ERR_ASN_INCONSISTENT_LENGTH;
      if (pElement->encoding.remaining < newDataLen)
        goto exit;

      pElement->encoding.remaining -= newDataLen;
      pElement->value.pValue = (ubyte *)pNewData;
      pElement->valueLen = newDataLen;
      pElement->state = MASN1_STATE_SET_COMPLETE;
      if (0 != pElement->encoding.remaining)
      {
        pElement->state = MASN1_STATE_SET_PARTIAL;
        /* If the caller is saying the input is complete, yet we are still
         * expecting data, error.
         */
        if (FALSE != isComplete)
          goto exit;
      }

      break;

    case MASN1_STATE_NONE:
      /* If the UNKNOWN_VALUE bit was set, clear it.
       */
      pElement->type &= ~(MASN1_UNKNOWN_VALUE);

      /* If the state is NONE, then we have done nothing.
       */
      if (FALSE != isComplete)
      {
        /* If the input is all the data (isComplete is TRUE), then we can use the
         * actual length, unless the input forces the INDEF format
         * (value = MASN1_BUF_FLAG_ENCODE_INDEF).
         */
        if (MASN1_BUF_FLAG_ENCODE_INDEF != (int)isComplete)
        {
          status = MAsn1SetValue (pElement, pNewData, newDataLen);
          goto exit;
        }
      }

      /* If we reach this code, we are adding data expecting it to be indefinite.
       * Set the indefinite tag and len.
       * We need that set before we add any data, because when we add data to
       * indefinite, we also need to add the extra tag.
       */
      pElement->state = MASN1_STATE_ENCODE_INDEF;
      status = MAsn1ComputeTagAndLenIndef (pElement, 0, &subComplete, &eLen);
      if (OK != status)
        goto exit;
      /* fall through */

    case MASN1_STATE_ENCODE_TAG_LEN_INDEF:
    case MASN1_STATE_ENCODE_PARTIAL_INDEF:
      /* Load up the data and set the state.
       * We also need to set the extra tag and len.
       */
      pElement->value.pValue = (ubyte *)pNewData;
      pElement->valueLen = newDataLen;
      pElement->state = MASN1_STATE_SET_COMPLETE;
      if ((FALSE == isComplete) ||
          (MASN1_BUF_FLAG_ENCODE_INDEF == (int)isComplete))
        pElement->state = MASN1_STATE_SET_PARTIAL_INDEF;

      status = MAsn1TagAndLenIndef (
        pElement->type & MASN1_TAG_MASK, pElement, newDataLen, 0);
      if (OK != status)
        goto exit;

      if (FALSE != isComplete)
      {
          if (MASN1_BUF_FLAG_ENCODE_INDEF == (int)isComplete)
              pElement->state = MASN1_STATE_SET_COMPLETE_INDEF;
          else
              pElement->state = MASN1_STATE_SET_COMPLETE;
      }
      break;
  }

  status = OK;

exit:

  return (status);
}
