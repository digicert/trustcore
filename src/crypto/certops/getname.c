/*
 * getname.c
 *
 * Functions for getting Name elements out of an object.
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

extern MSTATUS MGetNameRdnCount (
  struct MCertOrRequestObject *pObject,
  ubyte4 whichName,
  ubyte4 *pCount
  )
{
  MSTATUS status;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;
  MAsn1Element *pOfElement;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObject) || (NULL == pCount) )
    goto exit;

  status = ERR_INVALID_INPUT;
  pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_ISSNAME;
  if (MOC_ISSUER == whichName)
  {
    /* If the caller asked for the issuerName and this is a request, error.
     */
    if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
      goto exit;
  }
  else
  {
    if (MOC_SUBJECT != whichName)
      goto exit;

    pOfElement = pObj->pArray + MOC_REQUEST_ARRAY_INDEX_NAME;
    if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
      pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_SUBJNAME;
  }

  status = MGetCountOrEntryByIndex (pOfElement, pCount, 0, NULL);

exit:

  return (status);
}

extern MSTATUS MGetNameRdnByIndex (
  struct MCertOrRequestObject *pObject,
  ubyte4 whichName,
  ubyte4 index,
  MNameType *pNameTypeArray,
  ubyte4 nameTypeCount,
  ubyte4 *pNameTypeIndex,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  ubyte4 typeIndex;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;
  MAsn1Element *pOfElement, *pGetElement, *pArray;
  MGetAttributeData getData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObject) || (NULL == pNameTypeArray) ||
       (NULL == pNameTypeIndex) || (NULL == ppValue) ||
       (NULL == pValueLen) )
    goto exit;

  status = ERR_INVALID_INPUT;
  pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_ISSNAME;
  if (MOC_ISSUER == whichName)
  {
    /* If the caller asked for the issuerName and this is a request, error.
     */
    if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
      goto exit;
  }
  else
  {
    if (MOC_SUBJECT != whichName)
      goto exit;

    pOfElement = pObj->pArray + MOC_REQUEST_ARRAY_INDEX_NAME;
    if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
      pOfElement = pObj->pArray + MOC_CERT_ARRAY_INDEX_SUBJNAME;
  }

  status = MGetCountOrEntryByIndex (pOfElement, NULL, index, &pGetElement);
  if (OK != status)
    goto exit;

  /* The Element we have is a SET OF, get its only entry, a SEQUENCE.
   */
  pArray = pGetElement->value.pOfTemplate->entry.pElement;

  getData.pObj = pObject;
  getData.pOid = pArray[1].encoding.pEncoding;
  getData.oidLen = pArray[1].encodingLen;
  getData.pEncodedValue = pArray[2].value.pValue;
  getData.encodedValueLen = pArray[2].valueLen;
  getData.pDecodedValue = NULL;
  getData.decodedValueLen = 0;

  /* To decode the value, call each of the NameTypes until finding the one that
   * works.
   */
  for (typeIndex = 0; typeIndex < nameTypeCount; ++typeIndex)
  {
    status = pNameTypeArray[typeIndex] (
      MOC_NAME_OP_DECODE_RDN, NULL, 0, (void *)&getData);
    if (OK == status)
      break;
  }

  /* If we went through the list with no match, error.
   */
  status = ERR_UNKNOWN_DATA;
  if (typeIndex >= nameTypeCount)
    goto exit;

  /* Return the data.
   */
  *ppValue = getData.pDecodedValue;
  *pValueLen = getData.decodedValueLen;
  *pNameTypeIndex = typeIndex;

  status = OK;

exit:

  return (status);
}

extern MSTATUS MGetNameRdn (
  struct MCertOrRequestObject *pObject,
  ubyte4 whichName,
  MNameType NameType,
  ubyte **ppValue,
  ubyte4 *pValueLen
  )
{
  MSTATUS status;
  ubyte4 index, getIndex;
  MNameType pArray[1] = { NameType };

  /* Run through the list of Elements in the object.
   * Try at each index. If an index works, we're done. If not, this Name does not
   * contain the given RDN.
   */
  index = 0;
  do
  {
    /* If any one call succeeds, we're done.
     */
    status = MGetNameRdnByIndex (
      pObject, whichName, index, pArray, 1, &getIndex, ppValue, pValueLen);
    if (OK == status)
      goto exit;

    index++;

  } while (ERR_INDEX_OOB != status);

  if (OK != status)
    status = ERR_UNKNOWN_DATA;

exit:

  return (status);
}
