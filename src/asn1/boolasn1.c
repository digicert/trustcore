/*
 * boolasn1.c
 *
 * Operate on BOOLEAN.
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

MSTATUS MAsn1SetBoolean (
  MAsn1Element *pBooleanElement,
  intBoolean boolValue
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pBooleanElement)
    goto exit;

  status = ERR_ASN_INVALID_TAG_INFO;
  if (MASN1_TYPE_BOOLEAN != (pBooleanElement->type & MASN1_TYPE_MASK))
    goto exit;

  /* Make sure this Element was set up to encode.
   */
  status = ERR_ASN_INITIALIZED_TO_DECODE;
  if (NULL == pBooleanElement->buffer.pBuf)
    goto exit;

  /* Simply set the value to point to a byte inside pBuf.
   */
  if (FALSE == boolValue)
    pBooleanElement->buffer.pBuf[2] = 0;
  else
    pBooleanElement->buffer.pBuf[2] = 0xff;

  pBooleanElement->value.pValue = pBooleanElement->buffer.pBuf + 2;
  pBooleanElement->valueLen = 1;
  pBooleanElement->state = MASN1_STATE_SET_COMPLETE;

  status = OK;

exit:

  return (status);
}
