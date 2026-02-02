/*
 * basicc.c
 *
 * Functions for handling the BasicConstraints Extension.
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

/* Make sure the Oid in pGetData is correct, and if so, decode the value.
 * Build the data in the Type format (MBasicConstraintsInfo) and set the decoded
 * fields in pGetData.
 */
MSTATUS MDecodeBasicConstraints (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

/* Check to see if the values the user supplies (pBasicInfo) is valid for the
 * extension in the cert itself.
 */
MSTATUS MVerifyBasicConstraints (
  MBasicConstraintsInfo *pBasicInfo,
  MVerifyExtension *pVfyInfo
  );

#define MOC_BASIC_CONSTRAINTS_VALUE_LEN 8
#define MOC_BASIC_CONSTRAINTS_VALUE \
    0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00

extern MSTATUS ExtensionTypeBasicConstraints (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 bValueLen;
  ubyte pOid[MOP_BASIC_CONSTRAINTS_OID_LEN] = {
    MOP_BASIC_CONSTRAINTS_OID
  };
  ubyte pBasicValue[MOC_BASIC_CONSTRAINTS_VALUE_LEN] = {
    MOC_BASIC_CONSTRAINTS_VALUE
  };
  MBasicConstraintsInfo *pBasicInfo;

  status = ERR_NULL_POINTER;
  if (NULL == pInfo)
    goto exit;

  switch (operation)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_EXTENSION_OP_IS_BC:
      status = OK;
      *((intBoolean *)pInfo) = TRUE;
      break;

    case MOC_EXTENSION_OP_IS_OID:
      status = OK;
      *((intBoolean *)pInfo) = FALSE;
      if ( (valueLen != MOP_BASIC_CONSTRAINTS_OID_LEN) ||
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
      status = MDecodeBasicConstraints (
        (MGetAttributeData *)pInfo, pOid, MOP_BASIC_CONSTRAINTS_OID_LEN);
      break;

    case MOC_EXTENSION_OP_ENCODE:
      pBasicInfo = (MBasicConstraintsInfo *)pValue;
      if (NULL == pValue)
        goto exit;

      /* The basic constraints value is encoded
       *   SEQUENCE {
       *     isCA      BOOLEAN DEFAULT FALSE,
       *     pathLen   INTEGER OPTIONAL }
       * If isCA is FALSE, then there is no pathLen. So for a FALSE isCA, the
       * encoding is
       *   30 00
       * If isCA is TRUE, then the encoding is
       *   30 06
       *      01 01 FF
       *      02 01 pathLen
       * We assume the pathLen will never be > 127
       */
      bValueLen = MOC_BASIC_CONSTRAINTS_VALUE_LEN;
      pBasicValue[MOC_BASIC_CONSTRAINTS_VALUE_LEN - 1] =
        (ubyte)(pBasicInfo->pathLen);
      if (FALSE == pBasicInfo->isCa)
      {
        pBasicValue[1] = 0;
        bValueLen = 2;
      }
      status = MEncodeExtensionAlloc (
        pOid + 2, MOP_BASIC_CONSTRAINTS_OID_LEN - 2,
        pBasicInfo->isCritical, pBasicValue, bValueLen,
        &(((MSymOperatorData *)pInfo)->pData),
        &(((MSymOperatorData *)pInfo)->length));

      break;

    case MOC_EXTENSION_OP_VERIFY:
      status = MVerifyBasicConstraints (
        (MBasicConstraintsInfo *)pValue, (MVerifyExtension *)pInfo);
      break;
  }

exit:

  return (status);
}

MSTATUS MDecodeBasicConstraints (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 bytesRead;
  MBasicConstraintsInfo *pNewInfo = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 }
  };

  /* If the OID is not the same, this is not the Type that can get the value.
   */
  status = ERR_UNKNOWN_DATA;
  if (pGetData->oidLen != oidLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)(pGetData->pOid), (void *)pOid, oidLen, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_UNKNOWN_DATA;
  if (0 != cmpResult)
    goto exit;

  /* The value should be
   *   SEQ {
   *     BOOLEAN DEFAULT,
   *     INTEGER OPTIONAL }
   */
  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_DECODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pGetData->pEncodedValue, pGetData->encodedValueLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* Build the BasicConstrints Info struct and populate it.
   */
  status = DIGI_MALLOC (
    (void **)&pNewInfo, sizeof (MBasicConstraintsInfo));
  if (OK != status)
    goto exit;

  /* The default is FALSE for isCa and 0 pathLen.
   */
  pNewInfo->isCritical = pGetData->criticality;
  pNewInfo->isCa = FALSE;
  pNewInfo->pathLen = 0;

  /* If there is a BOOLEAN, use that value.
   */
  if (NULL != pArray[1].value.pValue)
  {
    if (0 != pArray[1].value.pValue[0])
    {
      pNewInfo->isCa = TRUE;
      if (NULL != pArray[2].value.pValue)
        pNewInfo->pathLen = (ubyte4)(pArray[2].value.pValue[0]);
    }
  }

  pGetData->pDecodedValue = (ubyte *)pNewInfo;

  /* Now save this new memory in the object.
   */
  status = MLoadMemoryIntoCertObject (
    (MCertOrRequestObject *)(pGetData->pObj), MOC_CERT_OBJ_MEM_BASIC_CONSTRAINTS,
    (void **)&pNewInfo, sizeof (MBasicConstraintsInfo));

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

  return (status);
}

MSTATUS MVerifyBasicConstraints (
  MBasicConstraintsInfo *pBasicInfo,
  MVerifyExtension *pVfyInfo
  )
{
  MSTATUS status;
  ubyte4 valueLen;
  ubyte *pValue;
  MBasicConstraintsInfo *pGetInfo;

  /* Init this bit so if there is an error and we can't complete, we report it.
   */
  pVfyInfo->verifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

  status = ERR_NULL_POINTER;
  if (NULL == pBasicInfo)
    goto exit;

  /* Get the extension out of the cert.
   * If it is not there, check to see if the caller expected it to be critical.
   */
  status = MGetExtension (
    (struct MCertOrRequestObject *)(pVfyInfo->pCert),
    ExtensionTypeBasicConstraints, &pValue, &valueLen);
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
    if (FALSE != pBasicInfo->isCritical)
      pVfyInfo->verifyFailures |= MOC_ASYM_VFY_FAIL_EXT_MISSING;

    /* This is not an error. We couldn't find the extension, the verification
     * process worked.
     */
    status = OK;
    goto exit;
  }

  pGetInfo = (MBasicConstraintsInfo *)pValue;

  /* Compare the expeted values to the actual one.
   * If the calloer is expecting a CA cert, check the extension.
   * If the caller is not expecting a CA cert, and it is a CA cert, we do not
   * consider that a verification failure. The standard does not say anything
   * about this possibility. If this is the case, just exit, no need to check
   * anything. The KeyUsage extension will likely come into play in this case.
   */
  if (FALSE == pBasicInfo->isCa)
    goto exit;

  /* The caller expects this cert to be a CA cert.
   */
  if (FALSE == pGetInfo->isCa)
  {
    /* If we reach this code, the actual cert is not a CA cert.
     */
    pVfyInfo->verifyFailures |=
      (MOC_ASYM_VFY_FAIL_EXT_VALUE | MOC_ASYM_VFY_FAIL_BASIC_CONS);
  }
  else
  {
    /* The caller expects a CA cert and it is. How about the pathLen. The len
     * in the cert must be >= the len the caller expects.
     */
    if (pGetInfo->pathLen < pBasicInfo->pathLen)
      pVfyInfo->verifyFailures |=
        (MOC_ASYM_VFY_FAIL_EXT_VALUE | MOC_ASYM_VFY_FAIL_BASIC_CONS);
  }

exit:

  /* If everything worked, clear the INCOMPLETE bit.
   */
  if (OK == status)
    pVfyInfo->verifyFailures ^= MOC_ASYM_VFY_FAIL_INCOMPLETE;

  return (status);
}
