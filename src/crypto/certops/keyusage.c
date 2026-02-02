/*
 * keyusage.c
 *
 * Functions for handling the KeyUsage Extension.
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
 * Build the data in the Type format (MKeyUsagesInfo) and set the decoded
 * fields in pGetData.
 */
MSTATUS MDecodeKeyUsage (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

/* Check to see if the values the user supplies (pBasicInfo) is valid for the
 * extension in the cert itself.
 */
MSTATUS MVerifyKeyUsage (
  MKeyUsageInfo *pKeyUsageInfo,
  MVerifyExtension *pVfyInfo
  );

extern MSTATUS ExtensionTypeKeyUsage (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 encLen;
  MKeyUsageInfo *pUsageInfo;
  ubyte pOid[MOP_KEY_USAGE_OID_LEN] = {
    MOP_KEY_USAGE_OID
  };
  ubyte pBuf[5];
  MAsn1Element asn1Element;

  status = ERR_NOT_IMPLEMENTED;
  switch (operation)
  {
    default:
      goto exit;

    case MOC_EXTENSION_OP_IS_KU:
      status = OK;
      *((intBoolean *)pInfo) = TRUE;
      break;

    case MOC_EXTENSION_OP_IS_OID:
      status = OK;
      *((intBoolean *)pInfo) = FALSE;
      if ( (valueLen != MOP_KEY_USAGE_OID_LEN) ||
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
      status = MDecodeKeyUsage (
        (MGetAttributeData *)pInfo, pOid, MOP_KEY_USAGE_OID_LEN);
      break;

    case MOC_EXTENSION_OP_ENCODE:
      pUsageInfo = (MKeyUsageInfo *)pValue;
      if (NULL == pValue)
        goto exit;

      status = DIGI_MEMSET (
        (void *)&asn1Element, 0, sizeof (MAsn1Element));
      if (OK != status)
        goto exit;

      asn1Element.type = MASN1_TYPE_BIT_STRING;
      asn1Element.buffer.pBuf = pBuf;

      /* The KeyUsage value is encoded
       *   BIT STRING
       * Use the ASN.1 engine to figure things out.
       * Create a buffer for tag, length, unusedBits, and at most 2 value bytes.
       * Set the value as a byte array into the buffer after TL unused.
       * Then set this buffer as the pBuf
       */
      pBuf[3] = (ubyte)(pUsageInfo->keyUsageBits >> 8);
      pBuf[4] = (ubyte)(pUsageInfo->keyUsageBits);

      /* Make sure the input has no stray bits.
       */
      status = ERR_INVALID_INPUT;
      if (0 != (pBuf[4] & 0x7F))
        goto exit;

      /* This will set the asn1Element. It will set TL unusedBits in pBuf. THen
       * it will determine whether both bytes are to be used or not.
       */
      status = MAsn1SetBitString (
        &asn1Element, TRUE, (ubyte *)(pBuf + 3), 2, 9);
      if (OK != status)
        goto exit;

      encLen = 0;
      if (0 != (asn1Element.bitStringLast & 0xff00))
        encLen = 1;

      encLen += (asn1Element.bufLen + asn1Element.valueLen);

      status = MEncodeExtensionAlloc (
        pOid + 2, MOP_KEY_USAGE_OID_LEN - 2,
        pUsageInfo->isCritical, pBuf, encLen,
        &(((MSymOperatorData *)pInfo)->pData),
        &(((MSymOperatorData *)pInfo)->length));

      break;

    case MOC_EXTENSION_OP_VERIFY:
      status = MVerifyKeyUsage (
        (MKeyUsageInfo *)pValue, (MVerifyExtension *)pInfo);
      break;
  }

exit:

  return (status);
}

MSTATUS MDecodeKeyUsage (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 bytesRead, unusedBits;
  MKeyUsageInfo *pNewInfo = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[1] = {
    { MASN1_TYPE_BIT_STRING, 0 },
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
   *   BIT STRING
   */
  status = MAsn1CreateElementArray (
    pTemplate, 1, MASN1_FNCT_DECODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pGetData->pEncodedValue, pGetData->encodedValueLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* There must be at least 1 byte of value, the unused bits. There should be no
   * more than 3 (unusedBits + 9 bits of data).
   */
  status = ERR_UNKNOWN_DATA;
  if ( (NULL == pArray->value.pValue) || (0 == pArray->valueLen) ||
       (3 < pArray->valueLen) )
    goto exit;

  /* The value in the Element should be unused bits, followed by the bits
   * themselves.
   */
  unusedBits = (ubyte4)(pArray->value.pValue[0]);

  if (8 < unusedBits)
    goto exit;

  /* Build the MKeyUsageInfo Info struct and populate it.
   */
  status = DIGI_MALLOC ((void **)&pNewInfo, sizeof (MKeyUsageInfo));
  if (OK != status)
    goto exit;

  /* Set the unusedBits to mask off unused bits.
   * For example, if there are 2 unused bits, we don't want the last 2 bits, so
   * we need a mask of 0xFFFC.
   */
  unusedBits = 0xffff << unusedBits;

  pNewInfo->isCritical = pGetData->criticality;
  pNewInfo->keyUsageBits = 0;

  /* There should be 1 or 2 bytes of data available. If only 1, then only the top
   * 8 bits are represented, any others are 0.
   */
  if (1 < pArray->valueLen)
    pNewInfo->keyUsageBits = ((ubyte4)(pArray->value.pValue[1])) << 8;

  if (3 == pArray->valueLen)
    pNewInfo->keyUsageBits += (ubyte4)(pArray->value.pValue[2]);

  /* Mask off any unused bits.
   */
  pNewInfo->keyUsageBits &= unusedBits;

  pGetData->pDecodedValue = (ubyte *)pNewInfo;

  /* Now save this new memory in the object.
   */
  status = MLoadMemoryIntoCertObject (
    (MCertOrRequestObject *)(pGetData->pObj), MOC_CERT_OBJ_MEM_KEY_USAGE,
    (void **)&pNewInfo, sizeof (MKeyUsageInfo));

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

MSTATUS MVerifyKeyUsage (
  MKeyUsageInfo *pKeyUsageInfo,
  MVerifyExtension *pVfyInfo
  )
{
  MSTATUS status;
  ubyte4 valueLen;
  ubyte *pValue;
  MKeyUsageInfo *pGetInfo;

  /* Init this bit so if there is an error and we can't complete, we report it.
   */
  pVfyInfo->verifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

  status = ERR_NULL_POINTER;
  if (NULL == pKeyUsageInfo)
    goto exit;

  /* Get the extension out of the cert.
   * If it is not there, check to see if the caller expected it to be critical.
   */
  status = MGetExtension (
    (struct MCertOrRequestObject *)(pVfyInfo->pCert),
    ExtensionTypeKeyUsage, &pValue, &valueLen);
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
    if (FALSE != pKeyUsageInfo->isCritical)
      pVfyInfo->verifyFailures |= MOC_ASYM_VFY_FAIL_EXT_MISSING;

    /* This is not an error. We couldn't find the extension, the verification
     * process worked.
     */
    status = OK;
    goto exit;
  }

  pGetInfo = (MKeyUsageInfo *)pValue;

  /* Compare the expeted values to the actual one.
   * The caller specified what the cert is being used for, does the cert have the
   * permissions? It might have more, but it must have at least what is passed in.
   * So any bit set in the input must be set in the cert.
   */
  if ((pKeyUsageInfo->keyUsageBits & pGetInfo->keyUsageBits) !=
    pKeyUsageInfo->keyUsageBits)
  {
    pVfyInfo->verifyFailures |=
      (MOC_ASYM_VFY_FAIL_EXT_VALUE | MOC_ASYM_VFY_FAIL_KEY_USAGE);
  }

exit:

  /* If everything worked, clear the INCOMPLETE bit.
   */
  if (OK == status)
    pVfyInfo->verifyFailures ^= MOC_ASYM_VFY_FAIL_INCOMPLETE;

  return (status);
}
