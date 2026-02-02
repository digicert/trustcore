/*
 * subjectkeyid.c
 *
 * Functions for handling the Subject Key Identifier Extension.
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

MSTATUS MEncodeSubjectKeyId (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  );

MSTATUS MDecodeSubjectKeyId (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

extern MSTATUS ExtensionTypeSubjectKeyId (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte pOid[MOP_SUBJECT_KEY_ID_OID_LEN] = {
    MOP_SUBJECT_KEY_ID_OID
  };

  status = ERR_NULL_POINTER;
  if (NULL == pInfo)
    goto exit;

  switch (operation)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_EXTENSION_OP_IS_OID:
      status = OK;
      *((intBoolean *)pInfo) = FALSE;
      if ( (valueLen != MOP_SUBJECT_KEY_ID_OID_LEN) ||
           (NULL == pValue) )
        goto exit;

      status = DIGI_MEMCMP (
        (void *)pValue, (void *)pOid, valueLen, &cmpResult);
      if (OK != status)
        goto exit;

      if (0 == cmpResult)
        *((intBoolean *)pInfo) = TRUE;

      goto exit;

    case MOC_EXTENSION_OP_DECODE:
      status = MDecodeSubjectKeyId (
        (MGetAttributeData *)pInfo, pOid, MOP_SUBJECT_KEY_ID_OID_LEN);
      break;

    case MOC_EXTENSION_OP_ENCODE:
      status = MEncodeSubjectKeyId (
        pValue, (ubyte *)pOid, pInfo);
      break;

    /* There is nothing to verify here, return ok */
    case MOC_EXTENSION_OP_VERIFY:
      (((MVerifyExtension *)(pInfo))->verifyFailures) = 0;
      status = OK;
      break;
  }

exit:
  return status;

} /* ExtensionTypeSubjectKeyId */

/*----------------------------------------------------------------------------*/

MSTATUS MEncodeSubjectKeyId (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  )
{
  MSTATUS status;
  MSubjectKeyIdInfo *pExtensionInfo = NULL;
  MAsn1Element *pArray = NULL;
  ubyte *pEncodedInfo = NULL;
  ubyte4 encodedInfoLen;

  /* The encoding for the extension is a single OCTET STRING */
  MAsn1TypeAndCount pTemplate[1] = {
    { MASN1_TYPE_OCTET_STRING, 0 }
  };

  pExtensionInfo = (MSubjectKeyIdInfo *)pValue;

  status = ERR_NULL_POINTER;
  if (NULL == pValue)
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 1, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1SetValue (
    pArray, pExtensionInfo->pValue, pExtensionInfo->valueLen);
  if (OK != status)
    goto exit;

  /* Get the DER encoding of the extension value */
  status = MAsn1EncodeAlloc (
    pArray, &pEncodedInfo, &encodedInfoLen);
  if (OK != status)
    goto exit;

  /* Pass the newly created DER encoded value as the value for the octet string
   * in the extension encoding */
  status = MEncodeExtensionAlloc (
    pOid + 2, MOP_SUBJECT_KEY_ID_OID_LEN - 2,
    FALSE, pEncodedInfo, encodedInfoLen,
    &(((MSymOperatorData *)pInfo)->pData),
    &(((MSymOperatorData *)pInfo)->length));

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;

} /* MEncodeSubjectKeyId */

/*----------------------------------------------------------------------------*/

MSTATUS MDecodeSubjectKeyId (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 allocLen, bytesRead;
  MSubjectKeyIdInfo *pNewInfo = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[1] = {
    { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = ERR_UNKNOWN_DATA;
  if (pGetData->oidLen != oidLen)
    goto exit;

  /* Ensure the OID matches */
  status = DIGI_MEMCMP (
    (void *)(pGetData->pOid), (void *)pOid, oidLen, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_UNKNOWN_DATA;
  if (0 != cmpResult)
    goto exit;

  /* The encoding is a single OCTET STRING */
  status = MAsn1CreateElementArray (
    pTemplate, 1, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Decode the value */
  status = MAsn1Decode (
    pGetData->pEncodedValue, pGetData->encodedValueLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* If there is no data, we still need to allocate the struct itself */
  allocLen = sizeof(MSubjectKeyIdInfo);

  /* This struct must be built under a single allocation, first determine how
   * much data we need to store */
  if ( (NULL != pArray[0].value.pValue) &&
       (0 != pArray[0].valueLen) )
  {
    allocLen += pArray[0].valueLen;
  }

  /* Build a new MSubjectKeyIdInfo struct and populate it */
  status = DIGI_MALLOC ((void **)&pNewInfo, allocLen);
  if (OK != status)
    goto exit;

  pNewInfo->pValue = NULL;
  pNewInfo->valueLen = 0;

  /* If there is a value available, populate the struct with it */
  if ( (NULL != pArray[0].value.pValue) &&
       (0 != pArray[0].valueLen) )
  {
    pNewInfo->pValue = (ubyte *)pNewInfo + sizeof(MSubjectKeyIdInfo);
    pNewInfo->valueLen = pArray[0].valueLen;

    status = DIGI_MEMCPY (
      (void *)pNewInfo->pValue,
      (void *)pArray[0].value.pValue, pArray[0].valueLen);
    if (OK != status)
      goto exit;
  }

  pGetData->pDecodedValue = (ubyte *)pNewInfo;

  /* Now save ths new memory into the object */
  status = MLoadMemoryIntoCertObject (
    (MCertOrRequestObject *)(pGetData->pObj), MOC_CERT_OBJ_MEM_SUBJ_KEY_ID,
    (void **)&pNewInfo, allocLen);

exit:

  if (NULL != pNewInfo)
  {
    DIGI_FREE ((void **)&pNewInfo);
    pGetData->pDecodedValue = NULL;
  }
  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;

} /* MDecodeSubjectKeyId */
