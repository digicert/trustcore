/*
 * valueasn1.c
 *
 * Set any Element, just add the value as is.
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

#if (!defined(__DISABLE_MOCANA_ASN1_SET_ARRAY_ELEMENT__))

MSTATUS MAsn1SetValue (
  MAsn1Element *pElement,
  const ubyte *pValue,
  ubyte4 valueLen
  )
{
  MSTATUS status;
  intBoolean isComplete;
  ubyte4 eLen;

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

  /* We can set the value only if the state is NONE, meaning we have not done
   * anything yet to this Element.
   */
  status = ERR_ASN_INVALID_STATE;
  if (MASN1_STATE_NONE != pElement->state)
    goto exit;

  /* Set the valueLen and call ComputeTagAndLen.
   */
  pElement->valueLen = valueLen;
  pElement->state = MASN1_STATE_SET_COMPLETE;
  status = MAsn1ComputeTagAndLenIndef (pElement, 0, &isComplete, &eLen);
  if (OK != status)
    goto exit;

  pElement->value.pValue = (ubyte *)pValue;
  pElement->valueLen = valueLen;

exit:

  return (status);
}

#endif /* __DISABLE_MOCANA_ASN1_SET_ARRAY_ELEMENT__ */
