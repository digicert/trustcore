/*
 * buildext.c
 *
 * Functions for building Extensions from a request plus CertExtension array.
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
#include "../../crypto/certops/certobj.h"

MSTATUS MBuildExtensionsAlloc (
  MRequestObj pRequestObj,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  intBoolean isOid;
  sbyte4 cmpResult;
  ubyte4 index, indexE, indexS, count, eCount, aCount, skipCount;
  ubyte4 *pSkipList = NULL;
  MCertOrRequestObject *pObj;
  MAsn1Element *pOfElement, *pGetElement, *pAddElement;
  MAsn1Element *pArray = NULL;
  MSymOperatorData getEnc;
  MAsn1TypeAndCount pTemplate[2] = {
    { MASN1_TYPE_SEQUENCE_OF, 1 },
      { MASN1_TYPE_ENCODED, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == ppEncoding) || (NULL == pEncodingLen) )
    goto exit;

  *ppEncoding = NULL;
  *pEncodingLen = 0;

  skipCount = 0;
  eCount = 0;
  if ( (NULL != pExtensionArray) && (0 != extensionCount) )
  {
    /* Create an array of indices, the indices of the entries in the
     * ExtensionArray that are also in the request object.
     */
    status = DIGI_MALLOC (
      (void **)&pSkipList, extensionCount * sizeof (ubyte4));
    if (OK != status)
      goto exit;

    eCount = extensionCount;
  }

  /* We need to collect all the extensions into one encoding. To do so, we're
   * going to get each of the extensions out of the request object and place them
   * into a new encoding.
   * Then we're going to encode each of the Extensions in the array.
   */

  aCount = 0;
  pOfElement = NULL;
  if (NULL != pRequestObj)
  {
    pObj = (MCertOrRequestObject *)pRequestObj;
    status = ERR_INVALID_INPUT;
    if (MOC_CERT_OBJ_TYPE_REQUEST != pObj->type)
      goto exit;

    status = MGetExtensionCount (
      (struct MCertOrRequestObject *)pRequestObj, &aCount);
    if (OK != status)
      goto exit;

    if (0 != aCount)
      pOfElement = pObj->pExtArray + 1;
  }

  /* If there are no extensions, there's nothing to do.
   */
  status = OK;
  if (0 == (eCount + aCount))
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 2, MASN1_FNCT_ENCODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  /* Get each extension from the request.
   */
  count = 0;
  for (index = 0; index < aCount; ++index)
  {
    status = MGetCountOrEntryByIndex (
      pOfElement, NULL, index, &pGetElement);
    if (OK != status)
      goto exit;

    /* Is this a repeat?
     */
    for (indexS = 0; indexS < count; ++indexS)
    {
      status = MGetCountOrEntryByIndex (
        pArray, NULL, indexS, &pAddElement);
      if (OK != status)
        goto exit;

      status = ASN1_compareOID (
        pGetElement->encoding.pEncoding, pGetElement->encodingLen,
        pAddElement->value.pValue, pAddElement->valueLen,
        NULL, &cmpResult);
      if (OK != status)
        goto exit;

      if (0 == cmpResult)
        break;
    }
    if (indexS < count)
      continue;

    /* Is there an entry in the Array for this extension?
     * If so, add its index to the skipList and increment skipCount.
     */
    for (indexE = 0; indexE < eCount; ++indexE)
    {
      isOid = FALSE;
      status = pExtensionArray[indexE].ExtensionType (
        MOC_EXTENSION_OP_IS_OID, pGetElement[1].encoding.pEncoding,
        pGetElement[1].encodingLen, (void *)&isOid);
      if ( (OK != status) || (FALSE == isOid) )
        continue;

      /* Place this index into the skipList.
       */
      pSkipList[skipCount] = indexE;
      skipCount++;
    }

    pAddElement = pArray + 1;
    if (0 != count)
    {
      status = MAsn1CopyAddOfEntry (pArray, &pAddElement);
      if (OK != status)
        goto exit;
    }

    pAddElement->value.pValue = pGetElement->encoding.pEncoding;
    pAddElement->valueLen = pGetElement->encodingLen;
    pAddElement->state = MASN1_STATE_SET_COMPLETE;
    count++;
  }

  /* Now run through the Extensions passed in.
   */
  for (indexE = 0; indexE < eCount; ++indexE)
  {
    /* Is this index on the skipList?
     */
    for (index = 0; index < skipCount; ++index)
    {
      if (pSkipList[index] == indexE)
        break;
    }
    if (index < skipCount)
      continue;

    pAddElement = pArray + 1;
    if (0 != count)
    {
      status = MAsn1CopyAddOfEntry (pArray, &pAddElement);
      if (OK != status)
        goto exit;
    }

    getEnc.pData = NULL;
    getEnc.length = 0;
    status = pExtensionArray[indexE].ExtensionType (
      MOC_EXTENSION_OP_ENCODE, pExtensionArray[indexE].pValue,
      pExtensionArray[indexE].valueLen, (void *)&getEnc);
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
    pAddElement->value.pValue = getEnc.pData;
    pAddElement->valueLen = getEnc.length;
    pAddElement->state = MASN1_STATE_SET_COMPLETE;
    pAddElement->buffer.pBuf = getEnc.pData;
    pAddElement->bufFlag |= MASN1_BUF_FLAG_FREE;
  }

  status = MAsn1EncodeAlloc (pArray, ppEncoding, pEncodingLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pSkipList)
  {
    DIGI_FREE ((void **)&pSkipList);
  }

  return (status);
}
