/*
 * templatename.c
 *
 * Functions for handling the Certificate Template Name Extension.
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

MSTATUS MDecodeTemplateName (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

MSTATUS MEncodeTemplateName (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  );

MSTATUS MVerifyTemplateName (
  MTemplateNameInfo *pExtensionInfo,
  MVerifyExtension *pVfyInfo
  );

extern MSTATUS ExtensionTypeTemplateName (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte pOid[MOP_CERT_TEMPLATE_NAME_OID_LEN] = {
    MOP_CERT_TEMPLATE_NAME_OID
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
      if ( (valueLen != MOP_CERT_TEMPLATE_NAME_OID_LEN) ||
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
      status = MDecodeTemplateName (
        (MGetAttributeData *)pInfo, pOid, MOP_CERT_TEMPLATE_NAME_OID_LEN);
      break;

    case MOC_EXTENSION_OP_ENCODE:
      status = MEncodeTemplateName (
        pValue, (ubyte *)pOid, pInfo);
      break;

    case MOC_EXTENSION_OP_VERIFY:
      status = MVerifyTemplateName (
        (MTemplateNameInfo *)pValue, (MVerifyExtension *)pInfo);
      break;
  }

exit:
  return status;

} /* ExtensionTypeTemplateName */

/*----------------------------------------------------------------------------*/

MSTATUS MEncodeTemplateName (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  )
{
  MSTATUS status;
  MTemplateNameInfo *pExtensionInfo = NULL;
  MAsn1Element *pArray = NULL;
  ubyte *pEncodedInfo = NULL;
  ubyte4 encodedInfoLen;

  /* The encoding for this extension is a single BMPString */
  MAsn1TypeAndCount pTemplate[1] = {
    { MASN1_TYPE_BMP_STRING, 0 }
  };

  pExtensionInfo = (MTemplateNameInfo *)pValue;

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

  /* Get the DER encoding of the extension value as a BMPString */
  status = MAsn1EncodeAlloc (
    pArray, &pEncodedInfo, &encodedInfoLen);
  if (OK != status)
    goto exit;

  /* Pass the newly created DER encoded value as the value for the octet string
   * in the extension encoding */
  status = MEncodeExtensionAlloc (
    pOid + 2, MOP_CERT_TEMPLATE_NAME_OID_LEN - 2,
    pExtensionInfo->isCritical, pEncodedInfo, encodedInfoLen,
    &(((MSymOperatorData *)pInfo)->pData),
    &(((MSymOperatorData *)pInfo)->length));

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;

} /* MEncodeTemplateName */

/*----------------------------------------------------------------------------*/

MSTATUS MDecodeTemplateName (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 allocLen, bytesRead;
  MTemplateNameInfo *pNewInfo = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[1] = {
    { MASN1_TYPE_BMP_STRING, 0 }
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

  /* The encoding is a single BMPString */
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
  allocLen = sizeof(MTemplateNameInfo);

  /* This struct must be built under a single allocation, first determine how
   * much data we need to store */
  if ( (NULL != pArray[0].value.pValue) &&
       (0 != pArray[0].valueLen) )
  {
    allocLen += pArray[0].valueLen;
  }

  /* Build a new MTemplateNameInfo struct and populate it */
  status = DIGI_MALLOC ((void **)&pNewInfo, allocLen);
  if (OK != status)
    goto exit;

  pNewInfo->isCritical = pGetData->criticality;
  pNewInfo->pValue = NULL;
  pNewInfo->valueLen = 0;

  /* If there is a value available, populate the struct with it */
  if ( (NULL != pArray[0].value.pValue) &&
       (0 != pArray[0].valueLen) )
  {
    pNewInfo->pValue = (ubyte *)pNewInfo + sizeof(MTemplateNameInfo);
    pNewInfo->valueLen = pArray[0].valueLen;

    status = DIGI_MEMCPY (
      (void *)pNewInfo->pValue,
      (void *)pArray[0].value.pValue,
      pNewInfo->valueLen);
    if (OK != status)
      goto exit;
  }

  pGetData->pDecodedValue = (ubyte *)pNewInfo;

  /* Now save ths new memory into the object */
  status = MLoadMemoryIntoCertObject (
    (MCertOrRequestObject *)(pGetData->pObj), MOC_CERT_OBJ_MEM_TEMPLATE_NAME,
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

} /* MDecodeTemplateName */

/*----------------------------------------------------------------------------*/

MSTATUS MVerifyTemplateName (
  MTemplateNameInfo *pExtensionInfo,
  MVerifyExtension *pVfyInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 valueLen;
  ubyte *pValue;
  MTemplateNameInfo *pGetInfo;

  /* Init this bit so if there is an error and we can't complete, we report it.
   */
  pVfyInfo->verifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

  status = ERR_NULL_POINTER;
  if (NULL == pExtensionInfo)
    goto exit;

  /* Get the extension out of the cert.
   * If it is not there, check to see if the caller expected it to be critical.
   */
  status = MGetExtension (
    (struct MCertOrRequestObject *)(pVfyInfo->pCert),
    ExtensionTypeTemplateName, &pValue, &valueLen);
  if (OK != status)
  {
    /* If the error is UNKNOWN_DATA, that means the extension was not in the
     * cert. Return any other error, but with UNKNOWN_DATA, check criticality.
     */
    if (ERR_UNKNOWN_DATA != status)
      goto exit;

    /* If the caller says this is a critical extension, absence is a failure.
     * Otherwise, ignore it.
     */
    if (FALSE != pExtensionInfo->isCritical)
      pVfyInfo->verifyFailures |= MOC_ASYM_VFY_FAIL_EXT_MISSING;

    /* This is not an error. We couldn't find the extension, the verification
     * process worked.
     */
    status = OK;
    goto exit;
  }

  pGetInfo = (MTemplateNameInfo *)pValue;

  /* Ensure that the lengths are the same */
  if (pExtensionInfo->valueLen != pGetInfo->valueLen)
  {
    pVfyInfo->verifyFailures |=
      (MOC_ASYM_VFY_FAIL_EXT_VALUE | MOC_ASYM_VFY_FAIL_CERT_TEMPLATE_NAME);
    goto exit;
  }

  status = DIGI_MEMCMP (
    pExtensionInfo->pValue, pGetInfo->pValue, pGetInfo->valueLen, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 != cmpResult)
  {
    pVfyInfo->verifyFailures |=
      (MOC_ASYM_VFY_FAIL_EXT_VALUE | MOC_ASYM_VFY_FAIL_CERT_TEMPLATE_NAME);
  }

exit:

  /* If everything worked, clear the INCOMPLETE bit.
   */
  if (OK == status)
    pVfyInfo->verifyFailures ^= MOC_ASYM_VFY_FAIL_INCOMPLETE;

  return status;

} /* MVerifyTemplateName */
