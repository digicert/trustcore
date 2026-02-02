/*
 * certreq.c
 *
 * Functions for building a cert request.
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
#include "../../common/base64.h"

extern MSTATUS PKCS10_buildCertRequestAlloc (
  MocAsymKey pPubKey,
  MocAsymKey pPriKey,
  ubyte4 digestAlg,
  ubyte4 sigDetails,
  MocCtx pMocCtx,
  randomContext *pRandom,
  MCertNameElement *pNameArray,
  ubyte4 nameArrayCount,
  MRequestAttribute *pAttributeArray,
  ubyte4 attributeCount,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte4 format,
  ubyte **ppRequest,
  ubyte4 *pRequestLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte version = 0;
  ubyte4 nameDerLen, attrDerLen, pubKeyDerLen, requestInfoLen, alg, sigLen;
  ubyte4 digestAlgToUse, digestInfoLen, algIdLen, vfyFailures, requestLen;
  ubyte *pNameDer = NULL;
  ubyte *pAttrDer = NULL;
  ubyte *pPubKeyDer = NULL;
  ubyte *pRequestInfo = NULL;
  ubyte *pSig = NULL;
  ubyte *pAlgId = NULL;
  ubyte *pRequest = NULL;
  MocSymCtx pDigester = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[5] = {
    { MASN1_TYPE_SEQUENCE, 4 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 },
  };
  MAsn1TypeAndCount pTemplateFull[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_BIT_STRING, 0 },
  };
  ubyte pDigestInfo[MOC_MAX_DIGEST_INFO_LEN];

  attrDerLen = 0;

  /* Some of the subroutines we call will check for NULL, so we don't have to
   * check all args right now.
   */
  status = ERR_NULL_POINTER;
  if ( (NULL == pPubKey) || (NULL == pPriKey) )
    goto exit;

  /* A cert request is
   *   SEQUENCE {
   *     certRequestInfo,
   *     signatureAlg,    -- AlgId
   *     signature        -- BIT STRING }
   * certRequestInfo is
   *   SEQUENCE {
   *     version         INTEGER,
   *     subject         Name,
   *     key             SubjectPublicKeyInfo,
   *     attributes  [0] Attributes
   * Start by building the Name.
   */
  status = MBuildNameDerAlloc (
    pNameArray, nameArrayCount, &pNameDer, &nameDerLen);
  if (OK != status)
    goto exit;

  /* Now build the attributes, if there are any.
   */
  status = MBuildAttributesAlloc (
    pAttributeArray, attributeCount, pExtensionArray, extensionCount,
    &pAttrDer, &attrDerLen);
  if (OK != status)
    goto exit;

  /* Get the DER of the public key.
   */
  status = CRYPTO_serializeMocAsymKeyAlloc (
    pPubKey, publicKeyInfoDer, &pPubKeyDer, &pubKeyDerLen);
  if (OK != status)
    goto exit;

  /* We now have all the elements of CertRequestInfo, encode.
   */
  status = MAsn1CreateElementArray (
    pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = &version;
  pArray[1].valueLen = 1;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  pArray[2].value.pValue = pNameDer;
  pArray[2].valueLen = nameDerLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;
  pArray[3].value.pValue = pPubKeyDer;
  pArray[3].valueLen = pubKeyDerLen;
  pArray[3].state = MASN1_STATE_SET_COMPLETE;

  if ( (NULL != pAttrDer) && (0 != attrDerLen) )
  {
    pArray[4].value.pValue = pAttrDer;
    pArray[4].valueLen = attrDerLen;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;
  }

  status = MAsn1EncodeAlloc (pArray, &pRequestInfo, &requestInfoLen);
  if (OK != status)
    goto exit;

  /* Now that we have CertRequestInfo, we can sign it.
   * First we need to digest it.
   * Which algorithm? If not specified, pick an algorithm based on key size.
   */
  digestAlgToUse = digestAlg;
  if (ht_none == digestAlg)
  {
    status = MGetDigestFlagFromKeySize (pPriKey, &digestAlgToUse);
    if (OK != status)
      goto exit;
  }

  /* Digest the CertRequestInfo.
   * Get an object based on the flag.
   */
  status = CRYPTO_getDigestObjectFromFlag (
    digestAlgToUse, pMocCtx, &pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInit (pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInfoFinal (
    pDigester, pRequestInfo, requestInfoLen, (ubyte *)pDigestInfo,
    MOC_MAX_DIGEST_INFO_LEN, &digestInfoLen);
  if (OK != status)
    goto exit;

  /* Compute the signature.
   * First, which algorithm?
   * If the key is not RSA, there's only one choice. If the key is RSA, either
   * use the value passed in or the default.
   */
  alg = pPriKey->localType & MOC_LOCAL_KEY_COM_MASK;
  switch (alg)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_LOCAL_KEY_RSA:
      alg = sigDetails;
      if (0 == sigDetails)
        alg = MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD;
      break;

    case MOC_LOCAL_KEY_DSA:
      alg = MOC_ASYM_KEY_ALG_DSA;
      break;

    case MOC_LOCAL_KEY_ECC:
      alg = MOC_ASYM_KEY_ALG_ECDSA;
  }

  /* Call the sign function with a NULL output buffer to determine the size. If
   * the return is OK, that's an error.
   */
  status = CRYPTO_asymSignDigestInfo (
    pPriKey, NULL, 0, alg, NULL, RANDOM_rngFun, pRandom,
    (ubyte *)pDigestInfo, digestInfoLen, NULL, 0, &sigLen, ppVlongQueue);
  if (OK == status)
    status = ERR_RETURN_OK;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = DIGI_MALLOC ((void **)&pSig, sigLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_asymSignDigestInfo (
    pPriKey, NULL, 0, alg, NULL, RANDOM_rngFun, pRandom,
    (ubyte *)pDigestInfo, digestInfoLen, pSig, sigLen, &sigLen, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* Verify the signature. We're doing this just to verify that the public and
   * private key are indeed partners.
   */
  status = CRYPTO_asymVerifyDigestInfo (
    pPubKey, NULL, 0, alg, NULL, RANDOM_rngFun, pRandom,
    (ubyte *)pDigestInfo, digestInfoLen, pSig, sigLen, &vfyFailures, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != vfyFailures)
    goto exit;

  /* Get the signature algId.
   */
  status = CRYPTO_getAsymAlgId (pPriKey, NULL, 0, &algIdLen);
  if (OK == status)
    status = ERR_RETURN_OK;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = DIGI_MALLOC ((void **)&pAlgId, algIdLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_getAsymAlgId (pPriKey, pAlgId, algIdLen, &algIdLen);
  if (OK != status)
    goto exit;

  /* Now that we have all the pieces, combine them.
   * Use the same pArray variable, we don't need it anymore. We need to free the
   * old contents first.
   */
  status = MAsn1FreeElementArray (&pArray);
  if (OK != status)
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplateFull, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = pRequestInfo;
  pArray[1].valueLen = requestInfoLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  pArray[2].value.pValue = pAlgId;
  pArray[2].valueLen = algIdLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1SetBitString (pArray + 3, FALSE, pSig, sigLen, sigLen * 8);
  if (OK != status)
    goto exit;

  /* Build the DER of the request.
   */
  status = MAsn1EncodeAlloc (pArray, &pRequest, &requestLen);
  if (OK != status)
    goto exit;

  /* If the caller wants the request in DER format, we're done.
   */
  if (format != MOC_CERT_REQUEST_FORMAT_PEM)
  {
    *ppRequest = pRequest;
    *pRequestLen = requestLen;
    pRequest = NULL;
    goto exit;
  }

  /* Build the result as PEM.
   */
  status = BASE64_makePemMessageAlloc (
    MOC_PEM_TYPE_CERT_REQUEST, pRequest, requestLen,
    ppRequest, pRequestLen);

exit:

  if (NULL != pRequest)
  {
    DIGI_FREE ((void **)&pRequest);
  }
  if (NULL != pAlgId)
  {
    DIGI_FREE ((void **)&pAlgId);
  }
  if (NULL != pSig)
  {
    DIGI_FREE ((void **)&pSig);
  }
  if (NULL != pDigester)
  {
    CRYPTO_freeMocSymCtx (&pDigester);
  }
  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pRequestInfo)
  {
    DIGI_FREE ((void **)&pRequestInfo);
  }
  if (NULL != pPubKeyDer)
  {
    DIGI_FREE ((void **)&pPubKeyDer);
  }
  if (NULL != pAttrDer)
  {
    DIGI_FREE ((void **)&pAttrDer);
  }
  if (NULL != pNameDer)
  {
    DIGI_FREE ((void **)&pNameDer);
  }

  return (status);
}
