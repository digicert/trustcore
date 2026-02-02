/*
 * authkeyid.c
 *
 * Functions for handling the Authority Key Identifier Extension.
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

MSTATUS MEncodeAuthKeyId (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  );

MSTATUS MDecodeAuthKeyId (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

extern MSTATUS ExtensionTypeAuthKeyId (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte pOid[MOP_AUTH_KEY_ID_OID_LEN] = {
    MOP_AUTH_KEY_ID_OID
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
      if ( (valueLen != MOP_AUTH_KEY_ID_OID_LEN) ||
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
      status = MDecodeAuthKeyId (
        (MGetAttributeData *)pInfo, pOid, MOP_AUTH_KEY_ID_OID_LEN);
      break;

    case MOC_EXTENSION_OP_ENCODE:
      status = MEncodeAuthKeyId (
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

} /* ExtensionTypeAuthKeyId */

/*----------------------------------------------------------------------------*/

MSTATUS MEncodeAuthKeyId (
  ubyte *pValue,
  ubyte *pOid,
  void *pInfo
  )
{
  MSTATUS status;
  MAuthKeyIdInfo *pExtInfo = NULL;
  MAsn1Element *pArray = NULL;
  ubyte *pEncodedInfo = NULL;
  ubyte *pEncodedCertIssuerInfo = NULL;
  ubyte4 encodedInfoLen, encodedCertIssuerInfoLen = 0;

  /*
   * The ASN1 definition for Authority Key Identifier is:
   *   SEQUENCE {
   *     keyIdentifier	           [0] KeyIdentifier OPTIONAL,
   *     authorityCertIssuer       [1] GeneralNames OPTIONAL,
   *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
   *
   *   KeyIdentifier           ::= OCTET STRING
   *   CertificateSerialNumber ::= INTEGER
   *   GeneralNames            ::= SEQUENCE OF GeneralName
   *   GeneralName             ::= CHOICE
   *     {
   *       otherName                 [0]  OtherName,
   *       rfc822Name                [1]  IA5String,
   *       dNSName                   [2]  IA5String,
   *       x400Address               [3]  ORAddress,
   *       directoryName             [4]  Name,
   *       ediPartyName              [5]  EDIPartyName,
   *       uniformResourceIdentifier [6]  IA5String,
   *       iPAddress                 [7]  OCTET STRING,
   *       registeredID              [8]  OBJECT IDENTIFIER
   *     }
   *
   * This encoding is a bit special. The KeyIdentifier and CertificateSerialNumber
   * fields are straightforward, but the authorityCertIssuer is complicated.
   * The GeneralName encoding is a bad fit for our ASN1 engine because it is a
   * choice of many types, this makes it difficult to build the correct template
   * for the encoding. Due to this constraint it is up to the caller to encode
   * the GeneralName. Now we have the element encoding (for example the DER
   * encoding of a Name), but the final encoding must specify an explict tag to
   * indicate the index of the general name choice (eg 0xA4). To achieve this
   * we use a nested encoding, the top level uses an explicit encoded element
   * with a fixed 1 for the explicit tag. The lower level also uses an explicit
   * encoded element, ORing the general name choice from the input struct to
   * get the correct explict tag. So the final result looks something like this:
   *
   *   80 len data   // 0th implicit item, KeyIdentifier
   *   A1 len        // 1st explicit item, GeneralNames
   *     A4 len data // 4th choice, data is DER of Name
   *   81 len data   // 1st implicit item, CertificateSerialNumber
   *
   */
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_OCTET_STRING | MASN1_OPTIONAL | MASN1_IMPLICIT | 0, 0 },
      { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL | MASN1_IMPLICIT | 2, 0 }
  };

  /* Inner template definition */
  MAsn1TypeAndCount pAuthCertIssuerTemplate[1] = {
    { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | MASN1_EXPLICIT, 0 }
  };

  pExtInfo = (MAuthKeyIdInfo *)pValue;

  status = ERR_NULL_POINTER;
  if (NULL == pExtInfo)
    goto exit;

  /* Encode the AuthCertIssuerEncoding if available */
  if ( (NULL != pExtInfo->pAuthCertIssuerEncoding) &&
       (0 != pExtInfo->authCertIssuerEncodingLen) )
  {
    /* OR in the general name choice to get the correct explicit tag */
    pAuthCertIssuerTemplate[0].tagSpecial |= pExtInfo->authCertIssuerGeneralNameChoice;

    /* Perform the first layer of encoding */
    status = MAsn1CreateElementArray (
      pAuthCertIssuerTemplate, 1, MASN1_FNCT_ENCODE, NULL, &pArray);
    if (OK != status)
      goto exit;

    status = MAsn1SetValue (
      pArray, pExtInfo->pAuthCertIssuerEncoding,
      pExtInfo->authCertIssuerEncodingLen);
    if (OK != status)
      goto exit;

    status = MAsn1EncodeAlloc (
      pArray, &pEncodedCertIssuerInfo, &encodedCertIssuerInfoLen);
    if (OK != status)
      goto exit;

    /* Free the element array for reuse */
    status = MAsn1FreeElementArray (&pArray);
    if (OK != status)
      goto exit;
    }

  /* Create the primary template */
  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Set the KeyIdentifier value */
  status = MAsn1SetValue (
    pArray + 1, pExtInfo->pKeyId, pExtInfo->keyIdLen);
  if (OK != status)
    goto exit;

  /* If available, set the value to the output of the earlier encoding */
  if ( (NULL != pExtInfo->pAuthCertIssuerEncoding) &&
       (0 != pExtInfo->authCertIssuerEncodingLen) )
  {
    status = MAsn1SetValue (
      pArray + 2, pEncodedCertIssuerInfo, encodedCertIssuerInfoLen);
    if (OK != status)
      goto exit;
  }

  /* Set the serial number */
  status = MAsn1SetInteger (
    pArray + 3, pExtInfo->pAuthCertSerialNum,
    pExtInfo->authCertSerialNumLen, TRUE, 0);
  if (OK != status)
    goto exit;

  status = MAsn1EncodeAlloc (
    pArray, &pEncodedInfo, &encodedInfoLen);
  if (OK != status)
    goto exit;

  /* Wrap this encoding into an extension encoding, this extension is always
   * non-critical so always pass FALSE */
  status = MEncodeExtensionAlloc (
    pOid + 2, MOP_AUTH_KEY_ID_OID_LEN - 2,
    FALSE, pEncodedInfo, encodedInfoLen,
    &(((MSymOperatorData *)pInfo)->pData),
    &(((MSymOperatorData *)pInfo)->length));

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;

} /* MEncodeAuthKeyId */

/*----------------------------------------------------------------------------*/

MSTATUS MDecodeAuthKeyId (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 allocLen, bytesRead;
  ubyte *pBuf = NULL;
  MAuthKeyIdInfo *pNewInfo = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1Element *pSubArray = NULL;

  /*
   * The ASN1 definition for Authority Key Identifier is:
   *   SEQUENCE {
   *     keyIdentifier	           [0] KeyIdentifier OPTIONAL,
   *     authorityCertIssuer       [1] GeneralNames OPTIONAL,
   *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
   *
   *   KeyIdentifier           ::= OCTET STRING
   *   CertificateSerialNumber ::= INTEGER
   *   GeneralNames            ::= SEQUENCE OF GeneralName
   *   GeneralName             ::= CHOICE
   *     {
   *       otherName                 [0]  OtherName,
   *       rfc822Name                [1]  IA5String,
   *       dNSName                   [2]  IA5String,
   *       x400Address               [3]  ORAddress,
   *       directoryName             [4]  Name,
   *       ediPartyName              [5]  EDIPartyName,
   *       uniformResourceIdentifier [6]  IA5String,
   *       iPAddress                 [7]  OCTET STRING,
   *       registeredID              [8]  OBJECT IDENTIFIER
   *     }
   *
   * This encoding is a bit special. The KeyIdentifier and CertificateSerialNumber
   * fields are straightforward, but the authorityCertIssuer is complicated.
   * The GeneralName encoding is a bad fit for our ASN1 engine because it is a
   * choice of many types, this makes it difficult to build the correct template
   * for the encoding. Due to this constraint it is up to the caller to encode
   * the GeneralName. Now we have the element encoding (for example the DER
   * encoding of a Name), but the final encoding must specify an explict tag to
   * indicate the index of the general name choice (eg 0xA4). To achieve this
   * we use a nested encoding, the top level uses an explicit encoded element
   * with a fixed 1 for the explicit tag. The lower level also uses an explicit
   * encoded element, ORing the general name choice from the input struct to
   * get the correct explict tag. So the final result looks something like this:
   *
   *   80 len data   // 0th implicit item, KeyIdentifier
   *   A1 len        // 1st explicit item, GeneralNames
   *     A4 len data // 4th choice, data is DER of Name
   *   81 len data   // 1st implicit item, CertificateSerialNumber
   *
   */
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_OCTET_STRING | MASN1_OPTIONAL | MASN1_IMPLICIT | 0, 0 },
      { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL | MASN1_IMPLICIT | 2, 0 }
  };

  /* Inner template definition */
  MAsn1TypeAndCount pAuthCertIssuerTemplate[1] = {
    { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | MASN1_EXPLICIT, 0 }
  };

  /* Ensure the oid matches */
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

  /* Decode the values */
  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_DECODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pGetData->pEncodedValue, pGetData->encodedValueLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* We need to build this struct under a single allocation. The allocation len
   * will minimally be the size of the struct itself, plus the size of the
   * buffer for KeyIdentifier and the size of the buffer for the serial number.
   * The final buffer will look like this:
   *   MAuthKeyIdInfo || KeyId || CertSerialNum || CertIssuerEncoding */
  allocLen = sizeof(MAuthKeyIdInfo) + pArray[1].valueLen + pArray[3].valueLen;

  /* If the authCertIssuerEncoding is not NULL, decode it to strip off the
   * extra leading explicit tag */
  if (NULL != pArray[2].value.pValue && 0 != pArray[2].valueLen)
  {
    /* Because the upper level array at index 2 contains the encoded value,
     * the first byte is guaranteed to be the explicit tag we need. */
    pAuthCertIssuerTemplate[0].tagSpecial |= (pArray[2].value.pValue[0] & 0x0F);

    /* Build the inner template */
    status = MAsn1CreateElementArray (
      pAuthCertIssuerTemplate, 1, MASN1_FNCT_DECODE, NULL, &pSubArray);
    if (OK != status)
      goto exit;

    /* Decode the value */
    status = MAsn1Decode (
      pArray[2].value.pValue, pArray[2].valueLen, pSubArray, &bytesRead);
    if (OK != status)
      goto exit;

    /* Increase the allocation size to account for the encoded value */
    allocLen += pSubArray[0].valueLen;
  }

  /* Allocate a buffer large enough for the struct and its data */
  status = DIGI_CALLOC ((void **)&pBuf, 1, allocLen);
  if (OK != status)
    goto exit;

  pNewInfo = (MAuthKeyIdInfo *)pBuf;

  /* Process the KeyID if available */
  if (NULL != pArray[1].value.pValue && 0 != pArray[1].valueLen)
  {
    pNewInfo->keyIdLen = pArray[1].valueLen;

    /* Set the struct pointer to point further along in the buffer */
    pNewInfo->pKeyId = pBuf + sizeof(MAuthKeyIdInfo);

    /* Copy the data into the buffer at that location */
    status = DIGI_MEMCPY (
      pNewInfo->pKeyId, pArray[1].value.pValue, pArray[1].valueLen);
    if (OK != status)
      goto exit;
  }

  if (NULL != pArray[3].value.pValue && 0 != pArray[3].valueLen)
  {
    pNewInfo->authCertSerialNumLen = pArray[3].valueLen;

    /* Set the struct pointer to point further along in the buffer */
    pNewInfo->pAuthCertSerialNum =
      pBuf + sizeof(MAuthKeyIdInfo) + pNewInfo->keyIdLen;

    /* Copy the data into the buffer at that location */
    status = DIGI_MEMCPY (
      pNewInfo->pAuthCertSerialNum, pArray[3].value.pValue, pArray[3].valueLen);
    if (OK != status)
      goto exit;
  }

  if (NULL != pArray[2].value.pValue && 0 != pArray[2].valueLen)
  {
    pNewInfo->authCertIssuerEncodingLen = pSubArray[0].valueLen;

    /* Set the struct pointer to point further along in the buffer */
    pNewInfo->pAuthCertIssuerEncoding =
      pBuf + sizeof(MAuthKeyIdInfo) +
      pNewInfo->keyIdLen + pNewInfo->authCertSerialNumLen;

    /* Copy the data into the buffer at that location */
    status = DIGI_MEMCPY (
      pNewInfo->pAuthCertIssuerEncoding,
      pSubArray[0].value.pValue, pSubArray[0].valueLen);
    if (OK != status)
      goto exit;

    /* Set the name choice based on the explicit tag value in the encoding */
    pNewInfo->authCertIssuerGeneralNameChoice =
      (pArray[2].value.pValue[0] & 0x0F);
  }

  pGetData->pDecodedValue = (ubyte *)pNewInfo;

  /* Load the newly created struct into the object itself */
  status = MLoadMemoryIntoCertObject (
    (MCertOrRequestObject *)(pGetData->pObj), MOC_CERT_OBJ_MEM_AUTH_KEY_ID,
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

} /* MDecodeAuthKeyId */
