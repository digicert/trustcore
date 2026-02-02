/*
 * parsereq.c
 *
 * Functions for parsing a cert request.
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
#include "../../crypto/certops/certobj.h"

/* method commented since CRYPTO_getDigestObjectFromSigAlgId is not available */
/* unused code as of this, dummy define flag */
#ifdef __0_parseCertReq__

extern MSTATUS PKCS10_parseCertRequest (
  ubyte *pRequest,
  ubyte4 requestLen,
  MocCtx pMocCtx,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  MRequestObj *ppRequestObj,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 pemType, derLen, bytesRead;
  ubyte4 digestLen;
  ubyte *pDer = NULL;
  MocSymCtx pDigester = NULL;
  MAsn1Element *pArray = NULL;
#define MOC_REQ_TEMPLATE_COUNT 19
  MAsn1TypeAndCount pTemplate[MOC_REQ_TEMPLATE_COUNT] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_SEQUENCE, 4 },                     /* CertRequestInfo */
        { MASN1_TYPE_INTEGER, 0 },                    /* version */
        { MASN1_TYPE_SEQUENCE_OF, 1 },                /* Name */
          { MASN1_TYPE_SET_OF, 1 },                   /* RDN */
            { MASN1_TYPE_SEQUENCE, 2 },
              { MASN1_TYPE_OID, 0 },
              { MASN1_TYPE_ENCODED, 0 },
        { MASN1_TYPE_SEQUENCE, 2 },                   /* key */
          { MASN1_TYPE_SEQUENCE, 2 },                 /* key algID */
            { MASN1_TYPE_OID, 0 },                    /* key OID */
            { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
          { MASN1_TYPE_BIT_STRING, 0 },
        { MASN1_TYPE_SET_OF | MASN1_IMPLICIT, 1 },    /* Attributes */
          { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_ENCODED, 0 },                    /* signature algId */
      { MASN1_TYPE_BIT_STRING, 0 }                  /* signature */
  };
  ubyte pDigestInfo[MOC_MAX_DIGEST_INFO_LEN];
  MocAsymKey pPubKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRequest) || (0 == requestLen) ||
       (NULL == pVerifyFailures) || (NULL == ppRequestObj) )
    goto exit;

  *ppRequestObj = NULL;
  *pVerifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

  /* If the request is PEM, Base64 decode it.
   * If it is DER, copy it. We'll need a copy for the object, we need it to
   * remain alive as long as the object is alive.
   */
  derLen = requestLen;
  if (0x30 != pRequest[0])
  {
    status = BASE64_decodePemMessageAlloc (
      pRequest, requestLen, &pemType, &pDer, &derLen);
    if (OK != status)
      goto exit;
  }
  else
  {
    status = DIGI_MALLOC_MEMCPY (
      (void **)&pDer, requestLen, pRequest, requestLen);
    if (OK != status)
      goto exit;
  }

  /* Decode the request.
   */
  status = MAsn1CreateElementArray (
    pTemplate, MOC_REQ_TEMPLATE_COUNT, MASN1_FNCT_DECODE, MAsn1OfFunction,
    &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pDer, derLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  status = CRYPTO_deserializeMocAsymKey (
    pArray[MOC_REQUEST_ARRAY_INDEX_KEY].encoding.pEncoding,
    pArray[MOC_REQUEST_ARRAY_INDEX_KEY].encodingLen, pMocCtx,
    &pPubKey, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* Get the digest algorithm from the signature AlgId.
   */
  status = CRYPTO_getDigestObjectFromSigAlgId (
    pArray[MOC_REQUEST_ARRAY_INDEX_SIG_ALGID].value.pValue,
    pArray[MOC_REQUEST_ARRAY_INDEX_SIG_ALGID].valueLen,
    pMocCtx, &pDigester);
  if (OK != status)
    goto exit;

  /* Digest the CertRequestInfo.
   */
  status = CRYPTO_digestInit (pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInfoFinal (
    pDigester, pArray[MOC_REQUEST_ARRAY_INDEX_TBS].encoding.pEncoding,
    pArray[MOC_REQUEST_ARRAY_INDEX_TBS].encodingLen,
    pDigestInfo, MOC_MAX_DIGEST_INFO_LEN, &digestLen);
  if (OK != status)
    goto exit;

  /* Verify the signature.
   * Note that the signature is a BIT STRING, so we need to skip the unusedBits
   * octet.
   */
  status = CRYPTO_asymVerifyDigestInfo (
    pPubKey, pArray[MOC_REQUEST_ARRAY_INDEX_SIG_ALGID].value.pValue,
    pArray[MOC_REQUEST_ARRAY_INDEX_SIG_ALGID].valueLen, 0, NULL,
    RANDOM_rngFun, pRandom, pDigestInfo, digestLen,
    pArray[MOC_REQUEST_ARRAY_INDEX_SIG].value.pValue + 1,
    pArray[MOC_REQUEST_ARRAY_INDEX_SIG].valueLen - 1,
    pVerifyFailures, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* Now store the decoded request as an object.
   */
  status = MCreateCertObj (
    MOC_CERT_OBJ_TYPE_REQUEST, &pDer, derLen, &pArray,
    (MCertOrRequestObject **)ppRequestObj, ppVlongQueue);

exit:

  if (NULL != pDigester)
  {
    CRYPTO_freeMocSymCtx (&pDigester);
  }
  if (NULL != pPubKey)
  {
    CRYPTO_freeMocAsymKey(&pPubKey, ppVlongQueue);
  }
  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pDer)
  {
    DIGI_FREE ((void **)&pDer);
  }

  return (status);
}

extern MSTATUS PKCS10_freeRequestObject (
  MRequestObj *ppRequestObj,
  struct vlong **ppVlongQueue
  )
{
  return (MFreeCertObj ((MCertOrRequestObject **)ppRequestObj, ppVlongQueue));
}

#endif
