/*
 * certfromreq.c
 *
 * Functions for building a cert from a request.
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
#include "../../common/base64.h"

MOC_EXTERN MSTATUS X509_buildCertFromRequestAlloc (
  MRequestObj pRequestObj,
  MocAsymKey pIssuerPriKey,
  ubyte4 digestAlg,
  ubyte4 sigDetails,
  MocCtx pMocCtx,
  randomContext *pRandom,
  MCertNameElement *pIssuerNameArray,
  ubyte4 issuerNameArrayCount,
  ubyte *pSerialNum,
  ubyte4 serialNumLen,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter,
  ubyte *pSubjUniqueId,
  ubyte4 subjUniqueIdLen,
  ubyte *pIssuerUniqueId,
  ubyte4 issuerUniqueIdLen,
  MCertExtension *pExtensionArray,
  ubyte4 extensionCount,
  ubyte4 format,
  ubyte **ppCert,
  ubyte4 *pCertLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte version = 2;
  sbyte4 timeDiff;
  ubyte4 nameDerLen, extensionsLen, digestAlgToUse, digestInfoLen;
  ubyte4 alg, algIdLen, sigLen, tbsCertLen, certLen;
  MocSymCtx pDigester = NULL;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pRequestObj;
  ubyte *pAlgId;
  ubyte *pNameDer = NULL;
  ubyte *pExtensionsDer = NULL;
  ubyte *pSignature = NULL;
  ubyte *pTbsCert = NULL;
  ubyte *pCert = NULL;
  ubyte pDigestInfo[MOC_MAX_DIGEST_INFO_LEN];
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[13] = {
    { MASN1_TYPE_SEQUENCE, 10 },
      { MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT, 0 }, /* version */
      { MASN1_TYPE_INTEGER, 0 },                  /* serialNum */
      { MASN1_TYPE_ENCODED, 0 },                  /* sig algId */
      { MASN1_TYPE_ENCODED, 0 },                  /* issuerName */
      { MASN1_TYPE_SEQUENCE, 2 },                 /* validity */
        { MASN1_TYPE_ANY_TIME, 0 },
        { MASN1_TYPE_ANY_TIME, 0 },
      { MASN1_TYPE_ENCODED, 0 },                  /* subjectName */
      { MASN1_TYPE_ENCODED, 0 },                  /* subjectPubKeyInfo */
      { MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 1, 0 },
      { MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 2, 0 },
      { MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_OPTIONAL | 3, 0 }
  };
  MAsn1TypeAndCount pTemplateFull[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_BIT_STRING, 0 },
  };

  /* Some of the subroutines we call will check for NULL, so we don't have to
   * check all args right now.
   */
  status = ERR_NULL_POINTER;
  if ( (NULL == pRequestObj) || (NULL == pIssuerPriKey) ||
       (NULL == pSerialNum) || (0 == serialNumLen) ||
       (NULL == pNotBefore) || (NULL == pNotAfter) ||
       (NULL == ppCert) || (NULL == pCertLen) )
    goto exit;

  /* A cert is
   *   SEQUENCE {
   *     tbsCertificate,
   *     signatureAlg,    -- AlgId
   *     signature        -- BIT STRING }
   * tbsCertificate is
   *   SEQUENCE {
   *     version         [0] EXPLICIT INTEGER DEFAULT,
   *     serialNum           INTEGER,
   *     sigAlg              AlgId,
   *     issuer              Name,
   *     validity            Validity,
   *     subject             Name,
   *     subjectKey          SubjectPublicKeyInfo,
   *     IssuerUniqueId  [1] IMPLICIT BIT STRING OPTIONAL
   *     SubjUniqueId    [2] IMPLICIT BIT STRING OPTIONAL
   *     extensions      [3] EXPLICIT Extensions OPTIONAL
   * Start by building the Issuer Name.
   */
  status = MBuildNameDerAlloc (
    pIssuerNameArray, issuerNameArrayCount, &pNameDer, &nameDerLen);
  if (OK != status)
    goto exit;

  /* Verify that the validity times make sense.
   * Namely, the notAfter time must be later than notBefore.
   */
  status = DATETIME_diffTime (pNotBefore, pNotAfter, &timeDiff);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 <= timeDiff)
    goto exit;

  status = MBuildExtensionsAlloc (
    pRequestObj, pExtensionArray, extensionCount,
    &pExtensionsDer, &extensionsLen);
  if (OK != status)
    goto exit;

  /* We need the Algorithm Identifier of the signature algorithm.
   * To get that, we call on the private key. However, that can give us the AlgId
   * only after computing a signature.
   * First, get the digest algorithm.
   */
  digestAlgToUse = digestAlg;
  if (ht_none == digestAlg)
  {
    status = MGetDigestFlagFromKeySize (pIssuerPriKey, &digestAlgToUse);
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

  /* Get a digestInfo.
   * This will be a "fake" digestInfo to use just to get the signature size and
   * algId.
   * DigestInfo is
   *   30 len
   *      AlgId
   *      04 dLen
   *         digest
   * The longest DigestInfo we support has a SEQUENCE len of 61 (0x51), so we
   * know the length octet will be just that, one octet. Similarly, we know that
   * the OCTET STRING length will be one octet.
   * Get the algId.
   */
  status = CRYPTO_getAlgorithmId (
    pDigester, pDigestInfo + 2, sizeof (pDigestInfo) - 2, &algIdLen);
  if (OK != status)
    goto exit;

  /* Get the digest size.
   */
  digestInfoLen = 0;
  status = ((MocSymContext *)pDigester)->SymOperator (
    pDigester, NULL, MOC_SYM_OP_DIGEST_SIZE, NULL, (void *)&digestInfoLen);
  if (OK != status)
    goto exit;

  /* Currently we support no digest algorithm longer than 0x7f (127), so we know
   * the length octets will be one byte.
   */
  pDigestInfo[algIdLen + 2] = 4;
  pDigestInfo[algIdLen + 3] = (ubyte)digestInfoLen;
  pDigestInfo[0] = 0x30;
  pDigestInfo[1] = (ubyte)(algIdLen + digestInfoLen + 2);

  digestInfoLen += (algIdLen + 4);

  /* Compute the signature.
   * First, which algorithm?
   * If the key is not RSA, there's only one choice. If the key is RSA, either
   * use the value passed in or the default.
   */
  alg = pIssuerPriKey->localType & MOC_LOCAL_KEY_COM_MASK;
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

  /* Call the sign function with a NULL output buffer to determine the size. This
   * will also determine the algId. If the return is OK, that's an error.
   */
  status = CRYPTO_asymSignDigestInfo (
    pIssuerPriKey, NULL, 0, alg, NULL, RANDOM_rngFun, pRandom,
    (ubyte *)pDigestInfo, digestInfoLen, NULL, 0, &sigLen, ppVlongQueue);
  if (OK == status)
    status = ERR_RETURN_OK;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = CRYPTO_getAsymAlgId (pIssuerPriKey, NULL, 0, &algIdLen);
  if (OK == status)
    status = ERR_RETURN_OK;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* Now build a buffer big enough for the signature algId and the signature.
   */
  status = DIGI_MALLOC ((void **)&pSignature, sigLen + algIdLen);
  if (OK != status)
    goto exit;

  pAlgId = pSignature + sigLen;
  status = CRYPTO_getAsymAlgId (pIssuerPriKey, pAlgId, algIdLen, &algIdLen);
  if (OK != status)
    goto exit;

  /* We now have everything needed to build the tbsCert.
   */
  status = MAsn1CreateElementArray (
    pTemplate, 13, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = &version;
  pArray[1].valueLen = 1;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1SetInteger (pArray + 2, pSerialNum, serialNumLen, TRUE, 0);
  if (OK != status)
    goto exit;

  pArray[3].value.pValue = pAlgId;
  pArray[3].valueLen = algIdLen;
  pArray[3].state = MASN1_STATE_SET_COMPLETE;
  pArray[4].value.pValue = pNameDer;
  pArray[4].valueLen = nameDerLen;
  pArray[4].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1SetTime (pArray + 6, pNotBefore);
  if (OK != status)
    goto exit;

  status = MAsn1SetTime (pArray + 7, pNotAfter);
  if (OK != status)
    goto exit;

  /* Use the subjectName from the request.
   */
  pArray[8].value.pValue =
    pObj->pArray[MOC_REQUEST_ARRAY_INDEX_NAME].encoding.pEncoding;
  pArray[8].valueLen =
    pObj->pArray[MOC_REQUEST_ARRAY_INDEX_NAME].encodingLen;
  pArray[8].state = MASN1_STATE_SET_COMPLETE;

  /* Use the subjectPublicKeyInfo from the request.
   */
  pArray[9].value.pValue =
    pObj->pArray[MOC_REQUEST_ARRAY_INDEX_KEY].encoding.pEncoding;
  pArray[9].valueLen =
    pObj->pArray[MOC_REQUEST_ARRAY_INDEX_KEY].encodingLen;
  pArray[9].state = MASN1_STATE_SET_COMPLETE;

  if ( (NULL != pIssuerUniqueId) && (0 != issuerUniqueIdLen) )
  {
    status = MAsn1SetBitString (
      pArray + 10, FALSE, pIssuerUniqueId, issuerUniqueIdLen,
      issuerUniqueIdLen * 8);
    if (OK != status)
      goto exit;
  }
  if ( (NULL != pSubjUniqueId) && (0 != subjUniqueIdLen) )
  {
    status = MAsn1SetBitString (
      pArray + 11, FALSE, pSubjUniqueId, subjUniqueIdLen,
      subjUniqueIdLen * 8);
    if (OK != status)
      goto exit;
  }

  if ( (NULL != pExtensionsDer) && (0 != extensionsLen) )
  {
    pArray[12].value.pValue = pExtensionsDer;
    pArray[12].valueLen = extensionsLen;
    pArray[12].state = MASN1_STATE_SET_COMPLETE;
  }

  status = MAsn1EncodeAlloc (pArray, &pTbsCert, &tbsCertLen);
  if (OK != status)
    goto exit;

  /* Now digest and sign
   */
  status = CRYPTO_digestInit (pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInfoFinal (
    pDigester, pTbsCert, tbsCertLen, (ubyte *)pDigestInfo,
    MOC_MAX_DIGEST_INFO_LEN, &digestInfoLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_asymSignDigestInfo (
    pIssuerPriKey, NULL, 0, alg, NULL, RANDOM_rngFun, pRandom,
    (ubyte *)pDigestInfo, digestInfoLen, pSignature, sigLen, &sigLen, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* Now put together the final cert.
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

  pArray[1].value.pValue = pTbsCert;
  pArray[1].valueLen = tbsCertLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  pArray[2].value.pValue = pAlgId;
  pArray[2].valueLen = algIdLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1SetBitString (pArray + 3, FALSE, pSignature, sigLen, sigLen * 8);
  if (OK != status)
    goto exit;

  /* Build the DER of the cert.
   */
  status = MAsn1EncodeAlloc (pArray, &pCert, &certLen);
  if (OK != status)
    goto exit;

  /* If the caller wants the request in DER format, we're done.
   */
  if (format != MOC_CERT_REQUEST_FORMAT_PEM)
  {
    *ppCert = pCert;
    *pCertLen = certLen;
    pCert = NULL;
    goto exit;
  }

  /* Build the result as PEM.
   */
  status = BASE64_makePemMessageAlloc (
    MOC_PEM_TYPE_CERT, pCert, certLen,
    ppCert, pCertLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pDigester)
  {
    CRYPTO_freeMocSymCtx (&pDigester);
  }
  if (NULL != pCert)
  {
    DIGI_FREE ((void **)&pCert);
  }
  if (NULL != pTbsCert)
  {
    DIGI_FREE ((void **)&pTbsCert);
  }
  if (NULL != pSignature)
  {
    DIGI_FREE ((void **)&pSignature);
  }
  if (NULL != pExtensionsDer)
  {
    DIGI_FREE ((void **)&pExtensionsDer);
  }
  if (NULL != pNameDer)
  {
    DIGI_FREE ((void **)&pNameDer);
  }

  return (status);
}
