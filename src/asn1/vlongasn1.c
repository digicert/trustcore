/*
 * vlongasn1.c
 *
 * Operate on INTEGER from vlong.
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
