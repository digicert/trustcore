/*
 * vlongasn1.c
 *
 * Operate on INTEGER from vlong.
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

MSTATUS MAsn1SetIntegerFromVlong (
  MAsn1Element *pIntegerElement,
  vlong *pIntVal,
  intBoolean isPositive
  )
{
  MSTATUS status;
  sbyte4 intLen;
  ubyte4 extraLen;
  ubyte *pNewBuf = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pIntegerElement)
    goto exit;

  /* If the incoming type is INTEGER, we're good to go.
   */
  status = ERR_ASN_INVALID_TAG_INFO;
  if (MASN1_TYPE_INTEGER != (pIntegerElement->type & MASN1_TAG_MASK))
    goto exit;

  /* Is there a value?
   */
  status = OK;
  if (NULL == pIntVal)
    goto exit;

  /* How long is this value?
   */
  intLen = (sbyte4)VLONG_bitLength (pIntVal);
  intLen = (intLen + 7) / 8;

  extraLen = 3;
  if (intLen > 0x7f)
  {
    extraLen++;
    if (intLen > 0xff)
    {
      extraLen++;
      if (intLen > 0xffff)
      {
        extraLen++;
        if (intLen > 0xffffff)
          extraLen++;
      }
    }
  }
  if (0 != (pIntegerElement->type & MASN1_EXPLICIT))
    extraLen = 2 * extraLen;

  /* Allocate a buffer to hold the value, along with tag, len, and leading octet,
   * and EXPLICIT tag and len if necessary.
   */
  status = DIGI_CALLOC ((void **)&pNewBuf, (ubyte4)intLen + extraLen, 1);
  if (OK != status)
    goto exit;

  /* Get the value as a canonical int.
   */
  status = VLONG_byteStringFromVlong (pIntVal, pNewBuf + extraLen, &intLen);
  if (OK != status)
    goto exit;

  /* Replace the pBuf.
   */
  if (0 != (pIntegerElement->bufFlag & MASN1_BUF_FLAG_FREE))
  {
    status = DIGI_FREE ((void **)&(pIntegerElement->buffer.pBuf));
    if (OK != status)
      goto exit;
  }

  pIntegerElement->buffer.pBuf = pNewBuf;
  pIntegerElement->bufFlag |= MASN1_BUF_FLAG_FREE;
  pNewBuf = NULL;

  /* And set the Element with the canonical int.
   */
  status = MAsn1SetInteger (
    pIntegerElement, pIntegerElement->buffer.pBuf + extraLen, (ubyte4)intLen,
    isPositive, 0);

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  return (status);
}
