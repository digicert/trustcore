/*
 * reqattr.c
 *
 * Functions for DER encoding and decoding PKCS 10 Attributes.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../crypto/certops.h"
#include "../../asn1/mocasn1.h"

extern MSTATUS MBuildAttributesAlloc (
  MRequestAttribute *pAttrArray,
  ubyte4 attrArrayCount,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 extAttrLen, index, count;
  ubyte *pExtAttr = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1Element *pGetElement;
  MSymOperatorData getEnc;
  MAsn1TypeAndCount pTemplate[2] = {
    { MASN1_TYPE_SET_OF | MASN1_IMPLICIT, 1 },
      { MASN1_TYPE_ENCODED, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == ppEncoding) || (NULL == pEncodingLen) )
    goto exit;

  *ppEncoding = NULL;
  *pEncodingLen = 0;

  /* Attributes are
   *  SET OF { Attribute }  [0] IMPLICIT
   * The extensionRequest attribute is different, it will be a collection of
   * extensions. Our API has each extension request as an individual attribute.
   * So we need to collect them. Call the function that builds the
   * extensionRequest attribute from the array. This function will find all the
   * attributes in the array that are extensions, and build a single attribute
   * out of them.
   */
  status = MBuildExtensionRequestAlloc (
    pExtensionArray, extensionCount, &pExtAttr, &extAttrLen);
  if (OK != status)
    goto exit;

  /* Build the ASN.1 array
   * Add the extension request attribute if there is one.
   */
  status = MAsn1CreateElementArray (
    pTemplate, 2, MASN1_FNCT_ENCODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  count = 0;
  if (NULL != pExtAttr)
  {
    /* Now set the Element with this encoding.
     * We're going to "cheat". We'll set the value.pValue to the data, but we'll
     * also set the buffer.pBuf to this buffer and set bufFlag to indicate the
     * Element should free this memory. This just makes the memory management
     * easier, let the pArray take care of it. We can do this because the
     * EXPLICIT tag is not set (otherwise we would need a pBuf with space in the
     * front for the EXPLICIT tag and length).
     * We also know we don't need to free any existing pBuf because we just
     * created the Element.
     */
    pGetElement = pArray + 1;
    pGetElement->value.pValue = pExtAttr;
    pGetElement->valueLen = extAttrLen;
    pGetElement->state = MASN1_STATE_SET_COMPLETE;
    pGetElement->buffer.pBuf = pExtAttr;
    pGetElement->bufFlag |= MASN1_BUF_FLAG_FREE;
    pExtAttr = NULL;

    count = 1;
  }

  /* Now add the other attributes.
   */
  for (index = 0; index < attrArrayCount; ++index)
  {
    /* If this is the first extension request, we're going to set the Element in
     * the original template/array. Otherwise we need to build a new Element.
     */
    pGetElement = pArray + 1;
    if (0 != count)
    {
      status = MAsn1CopyAddOfEntry (pArray, &pGetElement);
      if (OK != status)
        goto exit;
    }

    getEnc.pData = NULL;
    getEnc.length = 0;
    status = pAttrArray[index].AttrType (
      MOC_REQ_ATTR_OP_ENCODE, pAttrArray[index].pValue,
      pAttrArray[index].valueLen, (void *)&getEnc);
    if (OK != status)
      goto exit;

    count++;

    pGetElement->value.pValue = getEnc.pData;
    pGetElement->valueLen = getEnc.length;
    pGetElement->state = MASN1_STATE_SET_COMPLETE;
    pGetElement->buffer.pBuf = getEnc.pData;
    pGetElement->bufFlag |= MASN1_BUF_FLAG_FREE;
  }

  /* We expect this function will generate
   */
  status = MAsn1EncodeAlloc (pArray, ppEncoding, pEncodingLen);

exit:

  if (NULL != pExtAttr)
  {
    DIGI_FREE ((void **)&pExtAttr);
  }
  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

MSTATUS MBuildExtensionRequestAlloc (
  MCertExtension *pExtArray,
  ubyte4 extArrayCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 index, count;
  MAsn1Element *pArray = NULL;
  MAsn1Element *pGetElement;
  MSymOperatorData getEnc;
  ubyte pOid[MOP_EXT_REQ_OID_LEN] = {
    MOP_EXT_REQ_OID
  };
  /* The Attribute is
   *   SEQ {
   *     OID,
   *     SET OF }
   * We're going to have one entry in the SET and it will be Extensions.
   * Extensions is
   *   SEQ OF {
   *     Extension }
   * where Extension is
   *   SEQ {
   *     OID,
   *     BOOLEAN,
   *     Any }
   * The SET OF can be SET in the template because we know we will have only one
   * entry. So the total definition is
   *   SEQ {
   *     OID,
   *     SET {
   *       SEQ OF {
   *         SEQ {
   *           OID,
   *           BOOLEAN,
   *           Any } } } }
   * The last SEQ will be encoded by each ExtType.
   */
  MAsn1TypeAndCount pTemplate[5] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_SET, 1 },
        { MASN1_TYPE_SEQUENCE_OF, 1 },
          { MASN1_TYPE_ENCODED }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == ppEncoding) || (NULL == pEncodingLen) )
    goto exit;

  *ppEncoding = NULL;
  *pEncodingLen = 0;

  /* If there are no extensions, there's nothing to do.
   */
  status = OK;
  if ( (NULL == pExtArray) || (0 == extArrayCount) )
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 5, MASN1_FNCT_ENCODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = (ubyte *)(pOid + 2);
  pArray[1].valueLen = MOP_EXT_REQ_OID_LEN - 2;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;

  /* Run through each of the extensions and encode them.
   */
  count = 0;
  for (index = 0; index < extArrayCount; ++index)
  {
    /* If this is the first extension request, we're going to set the Element in
     * the original template/array. Otherwise we need to build a new Element.
     */
    pGetElement = pArray + 4;
    if (0 != count)
    {
      status = MAsn1CopyAddOfEntry (pArray + 3, &pGetElement);
      if (OK != status)
        goto exit;
    }

    getEnc.pData = NULL;
    getEnc.length = 0;
    status = pExtArray[index].ExtensionType (
      MOC_EXTENSION_OP_ENCODE, pExtArray[index].pValue,
      pExtArray[index].valueLen, (void *)&getEnc);
    if (OK != status)
      goto exit;

    count++;

    /* Now set the Element with this encoding.
     * We're going to "cheat". We'll set the value.pValue to the data, but we'll
     * also set the buffer.pBuf to this buffer and set bufFlag to indicate the
     * Element should free this memory. This just makes the memory management
     * easier, let the pArray take care of it. We can do this because the
     * EXPLICIT tag is not set (otherwise we would need a pBuf with space in the
     * front for the EXPLICIT tag and length).
     * We also know we don't need to free any existing pBuf because we just
     * created the Element.
     */
    pGetElement->value.pValue = getEnc.pData;
    pGetElement->valueLen = getEnc.length;
    pGetElement->state = MASN1_STATE_SET_COMPLETE;
    pGetElement->buffer.pBuf = getEnc.pData;
    pGetElement->bufFlag |= MASN1_BUF_FLAG_FREE;
  }

  status = MAsn1EncodeAlloc (pArray, ppEncoding, pEncodingLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
