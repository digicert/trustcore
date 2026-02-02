/*
 * getattr.c
 *
 * Functions for getting attributes out of a request object.
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

extern MSTATUS MGetRequestAttributeCount (
  MRequestObj pRequestObj,
  ubyte4 *pCount
  )
{
  MSTATUS status;
  ubyte4 extCount, attrCount;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pRequestObj;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRequestObj) || (NULL == pCount) )
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_REQUEST != pObj->type)
    goto exit;

  *pCount = 0;

  /* We want the count of all attributes that are not extensionRequest.
   * So we'll get the count of extensions. If that is not 0, then there is an
   * extensionRequest attribute and we can subtract 1 from the result of the
   * attribute count.
   */
  extCount = 0;
  status = MGetExtensionCount (
    (struct MCertOrRequestObject *)pObj, &extCount);
  if (OK != status)
    goto exit;

  if (0 != extCount)
    extCount = 1;

  status = MGetCountOrEntryByIndex (
    pObj->pArray + MOC_REQUEST_ARRAY_INDEX_ATTR, &attrCount, 0, NULL);
  if (OK != status)
    goto exit;

  *pCount = attrCount - extCount;

exit:

  return (status);
}

extern MSTATUS MGetRequestAttributeByIndex (
  MRequestObj pRequestObj,
  ubyte4 index,
  MAttrType *pAttrTypeArray,
  ubyte4 attrTypeCount,
  ubyte4 *pAttrTypeIndex,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  sbyte4 theLen;
  ubyte4 typeIndex, getIndex, theTag, lenLen;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pRequestObj;
  MAsn1Element *pOfElement, *pGetElement;
  MGetAttributeData getData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRequestObj) || (NULL == pAttrTypeArray) ||
       (NULL == pAttrTypeIndex) || (NULL == ppValue) ||
       (NULL == pValueLen) )
    goto exit;

  *ppValue = NULL;
  *pValueLen = 0;

  /* We need to skip the Extensions. If we haven't computed that yet, do so now.
   */
  if (NULL == pObj->pExtArray)
  {
    status = MDecodeExtensionRequest (pObj);
    if (OK != status)
      goto exit;
  }

  /* If there are extensions, then we might need to bump up the index.
   */
  getIndex = index;
  if (NULL != pObj->pExtArray)
  {
    if (index >= pObj->extIndex)
      getIndex++;
  }

  status = ERR_INVALID_INPUT;
  pOfElement = pObj->pArray + MOC_REQUEST_ARRAY_INDEX_ATTR;

  status = MGetCountOrEntryByIndex (pOfElement, NULL, getIndex, &pGetElement);
  if (OK != status)
    goto exit;

  /* The Element we now have is the SEQUENCE.
   * The OID is the next one after, and the value is after that.
   * The value is actually a SET OF, followed by the value.
   */
  status = ASN1_readTagAndLen (
    pGetElement[2].value.pValue, pGetElement[2].valueLen, &theTag,
    &theLen, &lenLen);
  if (OK != status)
    goto exit;

  getData.pObj = (struct MCertOrRequestObject *)pObj;
  getData.pOid = pGetElement[1].encoding.pEncoding;
  getData.oidLen = pGetElement[1].encodingLen;
  getData.pEncodedValue = pGetElement[2].value.pValue + lenLen;
  getData.encodedValueLen = (ubyte4)theLen;
  getData.pDecodedValue = NULL;
  getData.decodedValueLen = 0;

  /* To decode the value, call each of the NameTypes until finding the one that
   * works.
   */
  for (typeIndex = 0; typeIndex < attrTypeCount; ++typeIndex)
  {
    status = pAttrTypeArray[typeIndex] (
      MOC_REQ_ATTR_OP_DECODE, NULL, 0, (void *)&getData);
    if (OK == status)
      break;
  }

  /* If we went through the list with no match, return OK with value/valuLen to
   * NULL/0.
   */
  if (typeIndex >= attrTypeCount)
    goto exit;

  /* Return the data.
   */
  *ppValue = getData.pDecodedValue;
  *pValueLen = getData.decodedValueLen;
  *pAttrTypeIndex = typeIndex;

  status = OK;

exit:

  return (status);
}

extern MSTATUS MGetRequestAttribute (
  MRequestObj pRequestObj,
  MAttrType AttrType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  ubyte4 index, getIndex;
  MAttrType pArray[1] = { AttrType };

  status = ERR_NULL_POINTER;
  if ( (NULL == pRequestObj) || (NULL == AttrType) ||
       (NULL == ppValue) || (NULL == pValueLen) )
    goto exit;

  *ppValue = NULL;
  *pValueLen = 0;

  /* Run through the list of Elements in the object.
   * Try at each index. If an index works, we're done. If not, we couldn't find
   * this Attribute.
   */
  index = 0;
  do
  {
    /* If any one call succeeds, we're done.
     */
    status = MGetRequestAttributeByIndex (
      pRequestObj, index, pArray, 1, &getIndex, ppValue, pValueLen);
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
