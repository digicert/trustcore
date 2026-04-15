/*
 * boolasn1.c
 *
 * Operate on BOOLEAN.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
