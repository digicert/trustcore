/*
 * getext.c
 *
 * Functions for getting extensions out of an object.
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

extern MSTATUS MGetExtensionCount (
  struct MCertOrRequestObject *pObject,
  ubyte4 *pCount
  )
{
  MSTATUS status;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;
  MAsn1Element *pOfElement;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObj) || (NULL == pCount) )
    goto exit;

  *pCount = 0;

  /* If the object is a request, we first need to get the extensionRequest
   * attribute.
   */
  pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_EXT;
  if (MOC_CERT_OBJ_TYPE_REQUEST == pObj->type)
  {
    if (NULL == pObj->pExtArray)
    {
      status = MDecodeExtensionRequest (pObj);
      if (OK != status)
        goto exit;
    }

    pOfElement = pObj->pExtArray + 1;
  }

  status = MGetCountOrEntryByIndex (pOfElement, pCount, 0, NULL);

exit:

  return (status);
}

extern MSTATUS MGetExtensionByIndex (
  struct MCertOrRequestObject *pObject,
  ubyte4 index,
  MExtensionType *pExtTypeArray,
  ubyte4 extTypeCount,
  sbyte4 *pExtTypeIndex,
  intBoolean *pIsCritical,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  ubyte4 typeIndex;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;
  MAsn1Element *pOfElement, *pGetElement;
  MGetAttributeData getData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObject) || (NULL == pExtTypeArray) ||
       (NULL == pExtTypeIndex) || (NULL == pIsCritical) ||
       (NULL == ppValue) || (NULL == pValueLen) )
    goto exit;

  *ppValue = NULL;
  *pValueLen = 0;
  *pExtTypeIndex = -1;
  *pIsCritical = FALSE;

  /* If the object is a request, we first need to get the extensionRequest
   * attribute.
   */
  pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_EXT;
  if (MOC_CERT_OBJ_TYPE_REQUEST == pObj->type)
  {
    if (NULL == pObj->pExtArray)
    {
      status = MDecodeExtensionRequest (pObj);
      if (OK != status)
        goto exit;
    }

    pOfElement = pObj->pExtArray + 1;
  }

  status = MGetCountOrEntryByIndex (pOfElement, NULL, index, &pGetElement);
  if (OK != status)
    goto exit;

  /* The entry we have is
   *   SEQ {
   *     OID,
   *     BOOLEAN,
   *     OCTET STRING }
   * The value is the contents of the OCTET STRING.
   * However, the decoder needs the BOOLEAN as well, so we will determine the
   * value and set the criticality field as well.
   * encoding.
   */
  getData.pObj = (struct MCertOrRequestObject *)pObj;
  getData.pOid = pGetElement[1].encoding.pEncoding;
  getData.oidLen = pGetElement[1].encodingLen;
  getData.pEncodedValue = pGetElement[3].value.pValue;
  getData.encodedValueLen = pGetElement[3].valueLen;
  getData.pDecodedValue = NULL;
  getData.decodedValueLen = 0;

  getData.criticality = FALSE;
  if (NULL != pGetElement[2].value.pValue)
  {
    if (0 != pGetElement[2].value.pValue[0])
      getData.criticality = TRUE;
  }

  *pIsCritical = getData.criticality;

  /* To decode the value, call each of the NameTypes until finding the one that
   * works.
   */
  for (typeIndex = 0; typeIndex < extTypeCount; ++typeIndex)
  {
    status = pExtTypeArray[typeIndex] (
      MOC_EXTENSION_OP_DECODE, NULL, 0, (void *)&getData);
    if (OK == status)
      break;
  }

  /* If we went through the list with no match, return OK with value/valueLen to
   * NULL/0.
   */
  if (typeIndex >= extTypeCount)
    goto exit;

  /* Return the data.
   */
  *ppValue = getData.pDecodedValue;
  *pValueLen = getData.decodedValueLen;
  *pExtTypeIndex = typeIndex;

  status = OK;

exit:

  return (status);
}

extern MSTATUS MGetExtension (
  struct MCertOrRequestObject *pObject,
  MExtensionType ExtensionType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  intBoolean isCritical;
  sbyte4 getIndex;
  ubyte4 index;
  MExtensionType pArray[1] = { ExtensionType };

  status = ERR_NULL_POINTER;
  if ( (NULL == pObject) || (NULL == ExtensionType) ||
       (NULL == ppValue) || (NULL == pValueLen) )
    goto exit;

  *ppValue = NULL;
  *pValueLen = 0;

  /* Run through the list of Elements in the object.
   * Try at each index. If an index works, we're done. If not, this object does
   * not contain the given extension.
   */
  index = 0;
  do
  {
    /* If any one call succeeds, we're done.
     */
    status = MGetExtensionByIndex (
      pObject, index, pArray, 1, &getIndex, &isCritical, ppValue, pValueLen);
    if (OK == status)
      goto exit;

    index++;

  } while (ERR_INDEX_OOB != status);

  /* "Convert" INDEX_OOB to OK. If an extension is not in a cert or request, we
   * set the value to NULL and return OK. Any other error, return it.
   */
  if (ERR_INDEX_OOB == status)
    status = OK;

exit:

  return (status);
}

MSTATUS MDecodeExtensionRequest (
  MCertOrRequestObject *pObj
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 index, bytesRead;
  MAsn1Element *pGetElement;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[6] = {
    { MASN1_TYPE_SET, 1 },
      { MASN1_TYPE_SEQUENCE_OF, 1 },    /* Extensions */
        { MASN1_TYPE_SEQUENCE, 3 },
          { MASN1_TYPE_OID, 0 },
          { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
          { MASN1_TYPE_OCTET_STRING, 0 },
  };
  ubyte pOid[MOP_EXT_REQ_OID_LEN] = {
    MOP_EXT_REQ_OID
  };

  status = ERR_NULL_POINTER;
  if (NULL == pObj)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_REQUEST != pObj->type)
    goto exit;

  /* Already decoded?
   */
  status = OK;
  if (NULL != pObj->pExtArray)
    goto exit;

  index = 0;
  do
  {
    status = MGetCountOrEntryByIndex (
      pObj->pArray + MOC_REQUEST_ARRAY_INDEX_ATTR, NULL, index, &pGetElement);
    if ( (OK != status) && (ERR_INDEX_OOB != status) )
      goto exit;

    if (NULL == pGetElement)
      break;

    /* Is this the ExtensionRequest Attribute?
     */
    status = ASN1_compareOID (
      pOid, MOP_EXT_REQ_OID_LEN + 1, pGetElement->encoding.pEncoding,
      pGetElement->encodingLen, NULL, &cmpResult);
    if (OK == status)
    {
      if (0 == cmpResult)
        break;
    }

    index++;
  } while (1);

  /* If pGetElement is NULL, there are no extensions.
   */
  status = OK;
  if (NULL == pGetElement)
    goto exit;

  /* If pGetElement is not NULL, then decode the Extensions.
   */
  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_DECODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pGetElement[2].encoding.pEncoding, pGetElement[2].encodingLen, pArray,
    &bytesRead);
  if (OK != status)
    goto exit;

  pObj->pExtArray = pArray;
  pObj->extIndex = index;
  pArray = NULL;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
