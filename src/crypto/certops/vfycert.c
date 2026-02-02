/*
 * vfycert.c
 *
 * Functions for verifying a cert.
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

/* method commented (via dummy flag) since CRYPTO_getDigestObjectFromSigAlgId is not available */
#ifdef __0_verifyCert__

extern MSTATUS X509_verifyCert (
  MCertObj pCertObj,
  MocAsymKey pVerificationKey,
  MocCtx pMocCtx,
  TimeDate *pVerifyTime,
  MCertExtension *pExtensions,
  ubyte4 extCount,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  intBoolean isCritical;
  sbyte4 cmpResult, timeDiff, getIndex;
  ubyte4 vfyFail, sigFails, extFails, getValueLen;
  ubyte4 digestLen, index, count, eCount;
  ubyte *pGetValue;
  MocSymCtx pDigester = NULL;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pCertObj;
  TimeDate notBefore, notAfter;
  MVerifyExtension vfyExt;
  MExtensionType *pExtArray = NULL;
  ubyte pDigestInfo[MOC_MAX_DIGEST_INFO_LEN];

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertObj) || (NULL == pVerifyTime) ||
       (NULL == pVerifyFailures) )
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
    goto exit;

  *pVerifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;
  vfyFail = 0;

  /* Build an object to digest the data.
   * Get the digest algorithm from the signature AlgId.
   * While we're at it, make sure the signature algId inside the TBS data is the
   * same as the algId outside.
   */
  vfyFail |= MOC_ASYM_VFY_FAIL_ALG_ID;
  if (pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].valueLen ==
      pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID].valueLen)
  {
    status = DIGI_MEMCMP (
      (void *)pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].value.pValue,
      (void *)pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID].value.pValue,
      pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].valueLen, &cmpResult);
    if (OK != status)
      goto exit;

    /* If this comparison passes, get rid of the bit in vfyFail.
     */
    if (0 == cmpResult)
      vfyFail ^= MOC_ASYM_VFY_FAIL_ALG_ID;
  }

  status = CRYPTO_getDigestObjectFromSigAlgId (
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].valueLen,
    pMocCtx, &pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInit (pDigester);
  if (OK != status)
    goto exit;

  status = CRYPTO_digestInfoFinal (
    pDigester, pObj->pArray[MOC_CERT_ARRAY_INDEX_TBS].encoding.pEncoding,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_TBS].encodingLen,
    (ubyte *)pDigestInfo, MOC_MAX_DIGEST_INFO_LEN, &digestLen);
  if (OK != status)
    goto exit;

  /* We can now verify.
   * Note that the signature is a BIT STRING, so skip the first byte of the
   * value, the unused bits octet.
   */
  status = CRYPTO_asymVerifyDigestInfo (
    pVerificationKey, pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED].valueLen, 0, NULL,
    RANDOM_rngFun, pRandom, (ubyte *)pDigestInfo, digestLen,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SIGNATURE].value.pValue + 1,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_SIGNATURE].valueLen - 1,
    &sigFails, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* Now make sure the verification time falls within the notBefore and notAfter
   * times.
   */
  status = DATETIME_convertFromValidityString2 (
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_BEFORE].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_BEFORE].valueLen, &notBefore);
  if (OK != status)
    goto exit;

  status = DATETIME_convertFromValidityString2 (
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_AFTER].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_AFTER].valueLen, &notAfter);
  if (OK != status)
    goto exit;

  /* The verifyTime must be on or after notBefore, so the result of this will be
   * a positive number.
   */
  status = DATETIME_diffTime (pVerifyTime, &notBefore, &timeDiff);
  if (OK != status)
    goto exit;

  if (0 > timeDiff)
    vfyFail |= MOC_ASYM_VFY_FAIL_INVALID_TIME;

  /* The verifyTime must be on or before notBefore, so the result of this will be
   * a negative number.
   */
  status = DATETIME_diffTime (pVerifyTime, &notAfter, &timeDiff);
  if (OK != status)
    goto exit;

  if (0 < timeDiff)
    vfyFail |= MOC_ASYM_VFY_FAIL_INVALID_TIME;

  /* Check the extensions.
   */
  eCount = 0;
  if (NULL != pExtensions)
    eCount = extCount;

  /* We need the extensions as an array of ExtensionType, we have it as an
   * MCertExtension array.
   */
  if (0 != eCount)
  {
    status = DIGI_MALLOC ((void **)&pExtArray, sizeof (MExtensionType) * eCount);
    if (OK != status)
      goto exit;

    for (index = 0; index < eCount; ++index)
      pExtArray[index] = pExtensions[index].ExtensionType;
  }

  extFails = 0;

  /* Verify that any critical extension in the cert is covered by an
   * ExtensionType in the array.
   * Get each extension out of the object. If the Get succeeds, it's covered.
   * If the Get does not succeed, check to see if it is critical. If not, move
   * on. If so, add to the vfyFail value.
   */
  status = MGetExtensionCount (
    (struct MCertOrRequestObject *)pCertObj, &count);
  if (OK != status)
    goto exit;

  for (index = 0; index < count; ++index)
  {
    status = MGetExtensionByIndex (
      (struct MCertOrRequestObject *)pCertObj, index, pExtArray, eCount,
      &getIndex, &isCritical, &pGetValue, &getValueLen);
    if (OK != status)
      goto exit;

    /* If the value is not NULL, its covered, move on.
     */
    if (NULL != pGetValue)
      continue;

    /* We don't recognize this cert, is it critical? If not, we don't care, move
     * on. If it is, set the appropriate bit in extFails.
     */
    if (FALSE == isCritical)
      continue;

    extFails |= MOC_ASYM_VFY_FAIL_EXT_CRITICAL;
  }

  /* Call each of the extensions passed in, asking them to verify themselves.
   */
  for (index = 0; index < eCount; ++index)
  {
    vfyExt.pCert = pCertObj;
    vfyExt.verifyFailures = 0;
    status = pExtensions[index].ExtensionType (
      MOC_EXTENSION_OP_VERIFY, pExtensions[index].pValue,
      pExtensions[index].valueLen, (void *)&vfyExt);
    if (OK != status)
      goto exit;

    extFails |= vfyExt.verifyFailures;
  }

  /* Everything worked. Combine the signature verification result with the other
   * checks.
   */
  *pVerifyFailures = vfyFail | sigFails | extFails;

exit:

  if (NULL != pExtArray)
  {
    DIGI_FREE ((void **)&pExtArray);
  }
  if (NULL != pDigester)
  {
    CRYPTO_freeMocSymCtx (&pDigester);
  }

  return (status);
}
#endif
