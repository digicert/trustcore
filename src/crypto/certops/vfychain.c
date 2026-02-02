/*
 * vfychain.c
 *
 * Functions for verifying a cert chain.
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
#include "../../crypto/mocstore.h"
#include "../../crypto/certops/certobj.h"

/* Find the given cert's issuer from the given store.
 * <p>This function returns a reference to the cert. Do not free the object.
 * <p>If the function cannot find a matching cert, it will set *pIssuer to NULL
 * and return OK.
 * <p>This function will determine if the cert is self-signed. If it is, it will
 * set *pIsSelfSigned to TRUE. If it is self-signed, it will still check to see
 * if the cert is in the store. If it is, the function will determine if it is
 * trusted.
 * <p>This function will look for a cert in the store that is the issuer. It
 * will search by unique ID, if that exists in the certs. If not, it will look
 * for the authority key ID (an extension). If that doesn't exist, it will look
 * for the cert that has a subject name that is the same as the issuer name in
 * the leaf cert. It will also determine if the signature algorithm in the leaf
 * cert matches the key inside the issuer cert.
 * <p>There can be multiple certs with the same name, so the function will look
 * for the cert whose dates surround the leaf cert's dates. It might still be
 * possible for multiple certs to exist. Hence, you can pass in an index. For
 * index 0, the function will return the first cert it finds that matches. For an
 * index of 1, the function will return the second cert it finds that matches.
 * And so on.
 * <p>Your code will likely look something like this.
 * <pre>
 * <code>
 *    index = 0;
 *    do {
 *      GetIssuerCert (pCert, pStore, index, &pIssuer, &isTrusted);
 *
 *      flag = no issuer found
 *      if (NULL == pIssuer)
 *        break;
 *
 *      VerifyCert (pCert, etc.)
 *
 *      if verified
 *        break;
 *
 *      index++;
 *    } while (1);
 * </code>
 * </pre>
 */
MSTATUS MGetIssuerCert (
  MCertObj pCertObj,
  MocStore pCertStore,
  ubyte4 index,
  MCertObj *ppIssuerCert,
  intBoolean *pIsSelfSigned,
  intBoolean *pIsTrusted
  );

/* Determine if the two certs are the same.
 * First, check to see if they point to the same object. If so, they are the same.
 * Second, check to see if they have the same issuerNameSerialNum. If that's the
 * same, they are the same cert, otherwise they are not.
 * This function does not check the input args.
 */
MSTATUS MIsSameCert (
  MCertObj pCert1,
  MCertObj pCert2,
  intBoolean *pIsSame
  );

/* Check to see if the notBefore inside the given cert is on or before the given
 * notBefore, and the notAfter inside the cert is on or after the notAfter.
 * <p>If the dates check out, leave ppIssuerCert. Buf it not, place NULL at
 * ppIssuerCert.
 */
MSTATUS MCheckIssuerDates (
  MCertObj *ppIssuerCert,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter
  );

/* Check to see if the key inside the issuer cert is valid for the signature of
 * the cert.
 * <p>What is the alg of the cert signature, what is the alg of the issuer key?
 * Do they match?
 * <p>If they do, just return. If not, set *ppIssuerCert to NULL and return OK.
 */
MSTATUS MCheckIssuerAlg (
  MCertObj pCertObj,
  MCertObj *ppIssuerCert
  );

/* Copy the input ExtensionArray, except replace the basic constraints and key
 * usage info with updated data to reflect that the new array will be used to
 * verify a CA cert.
 * <p>This function will allocate memory for the MCertExtension array. The caller
 * must free that memory using DIGI_FREE. This is all the memory that the function
 * will allocate.
 * <p>The caller passes in pointers to existing MBasicConstraintsInfo and
 * MKeyUsageInfo structs. This is just to make it easier to manage memory, the
 * function will not have to allocate space for those structs (or worry about
 * alignment if it were to allocate memory for the new array and the two structs).
 * <p>The new array will be the same size as the old array.
 * <p>If there are no extensions (pExtenstions is NULL or extCount is 0), the
 * function will simply set *ppNewExtensions to NULL (there's nothing to copy).
 */
MSTATUS MCopyExtensionArrayAlloc (
  MCertExtension *pExtensions,
  ubyte4 extCount,
  MBasicConstraintsInfo *pBcInfo,
  MKeyUsageInfo *pKuInfo,
  MCertExtension **ppNewExtensions
  );

extern MSTATUS X509_verifyCertChain (
  MCertObj pCertObj,
  MocCtx pMocCtx,
  TimeDate *pVerifyTime,
  MCertExtension *pExtensions,
  ubyte4 extCount,
  MocStore pCertStore,
  randomContext *pRandom,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  intBoolean isTrusted, isSelfSigned, trustedOne = FALSE, signedOne = FALSE;
  ubyte4 eCount = 0, index = 0, vfyFail = 0, failOne = 0, caFail = 0;
  MCertObj pIssuer = NULL;
  MCertObj pIssuerOne = NULL;
  MCertExtension *pNewExtensions = NULL;
  MocAsymKey pPubKey = NULL;
  MBasicConstraintsInfo bcInfo;
  MKeyUsageInfo kuInfo;

  /* We'll make further calls that check the other args.
   */
  if ( (NULL == pCertObj) || (NULL == pCertStore) )
    goto exit;

  if (NULL != pExtensions)
    eCount = extCount;

  /* Find the issuer cert, then verify. If that fails, look for another issuer
   * cert that might work.
   */
  do
  {
    status = MGetIssuerCert (
      pCertObj, pCertStore, index, &pIssuer, &isSelfSigned, &isTrusted);
    if (OK != status)
      goto exit;

    /* If we can't find an issuer cert, give up.
     */
    vfyFail = MOC_ASYM_VFY_FAIL_NO_ISSUER_CERT;
    if (NULL == pIssuer)
      break;

    /* Get the key out of this cert.
     */
    status = MGetPublicKeyFromCertOrRequest (
      (struct MCertOrRequestObject *)pIssuer, pMocCtx, &pPubKey,
      NULL, NULL, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* Verify the cert.
     */
    status = X509_verifyCert (
      pCertObj, pPubKey, pMocCtx, pVerifyTime,  pExtensions, eCount,
      pRandom, &vfyFail, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* If this succeeded, we don't need to look any further.
     */
    if (0 == vfyFail)
      break;

    /* If it didn't succeed, we can see if there is another CA cert that will
     * work.
     * However, if we don't find another issuer cert, we want to return the
     * result of the verification.
     * If a later verification works, we forget the previous failure.
     * We'll save the first failure list we find. If we have multiple attempts
     * and they all fail, which one do we return? The first. There's no point in
     * trying to develop an algorithm for determining which failure to return. In
     * the real world, the probability of multiple CAs is so small we might not
     * even need to worry about it. But we do because there are CAs that have
     * multiple certs with the same name. So we need to check for that.
     */
    if (0 == failOne)
    {
      failOne = vfyFail;
      pIssuerOne = pIssuer;
      trustedOne = isTrusted;
      signedOne = isSelfSigned;
    }

    /* Free the object for the next loop.
     */
    CRYPTO_freeMocAsymKey (&pPubKey, ppVlongQueue);

    vfyFail = 0;
    index++;

  } while (1);

  /* If pIssuer is NULL, and pIssuerOne is not NULL, then we verified using one
   * issuer cert, it didn't work, so we tried another cert. In the end, we ran
   * out of certs (any other potential cert we found also did not verify). So
   * look at pIssuerOne from now on.
   */
  if ( (NULL == pIssuer) && (NULL != pIssuerOne) )
  {
    vfyFail = failOne;
    pIssuer = pIssuerOne;
    isTrusted = trustedOne;
    isSelfSigned = signedOne;
  }

  /* If we reach this code, either we could not find an issuer cert, or we found
   * one or more and the cert did not verify, or we have a verification.
   * If we could find no issuer cert, there's nothing more we can do.
   * If the verification failed, we still want to complete the chain. If the
   * verification was a success, we want to complete the chain.
   * But if the issuer cert we found is a trusted cert, we don't need to verify
   * it, so we're done.
   */
  if ( (NULL == pIssuer) || (FALSE != isTrusted) )
    goto exit;

  /* If the issuer cert is not self-signed, we're going to chain up from it. If
   * it is self-signed, we're done chaining.
   */
  if (FALSE == isSelfSigned)
  {
    /* Before we continue the verification process, we need to set up the KeyUsage
     * and BasicConstraints extensions.
     * To do this, we're going to copy the input extension array, but replace the
     * basic constraints and key usage info to reflect the fact that we're now
     * verifying an issuer cert.
     */
    status = MCopyExtensionArrayAlloc (
      pExtensions, eCount, &bcInfo, &kuInfo, &pNewExtensions);
    if (OK != status)
      goto exit;

    /* Now verify this cert and continue the chain.
     */
    status = X509_verifyCertChain (
      pIssuer, pMocCtx, pVerifyTime, pNewExtensions, eCount,
      pCertStore, pRandom, &caFail, ppVlongQueue);
    if (OK != status)
      goto exit;
  }
  else
  {
    /* If this is a self-signed cert and its verification failed, then we need to
     * make sure the FAIL_CHAIN bit is set. If this self-signed cert is not
     * trusted, set the NOT_TRUSTED_ROOT bit.
     */
    if (0 != vfyFail)
      caFail = MOC_ASYM_VFY_FAIL_CHAIN;
    if (FALSE == isTrusted)
      caFail |= MOC_ASYM_VFY_FAIL_NO_TRUSTED_ROOT;
  }

  if (0 != caFail)
    vfyFail |= (MOC_ASYM_VFY_FAIL_CHAIN | caFail);

exit:

  if (NULL != pNewExtensions)
  {
    DIGI_FREE ((void **)&pNewExtensions);
  }
  if (NULL != pPubKey)
  {
    CRYPTO_freeMocAsymKey(&pPubKey, ppVlongQueue);
  }

  /* If there was an error, we couldn't complete the operation, so report that.
   */
  if (OK != status)
    vfyFail |= MOC_ASYM_VFY_FAIL_INCOMPLETE;

  *pVerifyFailures = vfyFail;

  return (status);
}

MSTATUS MGetIssuerCert (
  MCertObj pCertObj,
  MocStore pStore,
  ubyte4 index,
  MCertObj *ppIssuerCert,
  intBoolean *pIsSelfSigned,
  intBoolean *pIsTrusted
  )
{
  MSTATUS status;
  intBoolean isTrusted;
  ubyte4 currentIndex, valueLen;
  ubyte *pValue = NULL;
  MCertObj pIssuer = NULL;
  MocStoreEntry *pEntry;
  TimeDate notBefore, notAfter;

  *ppIssuerCert = NULL;
  *pIsTrusted = FALSE;
  isTrusted = FALSE;
  currentIndex = 0;

  status = MGetValidityDates (pCertObj, &notBefore, &notAfter);
  if (OK != status)
    goto exit;

  /* Keep finding certs until the index matches.
   */
  for (currentIndex = 0; currentIndex <= index; ++currentIndex)
  {
    pEntry = NULL;
    pIssuer = NULL;
    isTrusted = FALSE;

    /* First, try the issuer UniqueId
     * Get the leaf cert's issuer unique ID, then find the cert with that ID as
     * the subject unique ID.
     */
    status = MGetUniqueId (
      pCertObj, MOC_ISSUER, &pValue, &valueLen);
    if (OK != status)
      goto exit;

    if ( (NULL != pValue) && (0 != valueLen) )
    {
      status = MocStoreFindEntry (
        pStore, 0, MStoreSearchParamSubjUniqueId,
        pValue, valueLen, currentIndex, &pEntry);
      if (OK != status)
        goto exit;
    }

    if (NULL == pEntry)
    {
      /* Search based on authrity key ID. This is an extension. We'll get the auth
       * key ID out of the leaf cert and then look for the cert with that value as
       * the subject key ID.
       */
      status = MGetExtension (
        (struct MCertOrRequestObject *)pCertObj, ExtensionTypeAuthKeyId,
        &pValue, &valueLen);
      if (OK != status)
        goto exit;

      if ( (NULL != pValue) && (0 != valueLen) )
      {
        status = MocStoreFindEntry (
          pStore, 0, MStoreSearchParamSubjKeyId,
          pValue, valueLen, currentIndex, &pEntry);
        if (OK != status)
          goto exit;
      }
    }


    if (NULL == pEntry)
    {
      /* Search by name. Get the IssuerName out of the leaf cert and find the cert
       * that has that name as the SubjectName.
       */
      status = MGetName (
        (struct MCertOrRequestObject *)pCertObj, MOC_ISSUER, &pValue, &valueLen);
      if (OK != status)
        goto exit;

      status = MocStoreFindEntry (
        pStore, 0, MStoreSearchParamSubject,
        pValue, valueLen, currentIndex, &pEntry);
      if (OK != status)
        goto exit;
    }

    if (NULL != pEntry)
    {
      /* Where is the cert?
       */
      pIssuer = pEntry->contents.keyCert.pCertObj;
      isTrusted = pEntry->contents.keyCert.isTrusted;
      if (0 != (pEntry->type & MOC_STORE_ENTRY_TYPE_DATA))
      {
        pIssuer = pEntry->contents.keyCertData.pCertObj;
        isTrusted = pEntry->contents.keyCertData.isTrusted;
      }

      status = MCheckIssuerDates (&pIssuer, &notBefore, &notAfter);
      if (OK != status)
        goto exit;

      if (NULL != pIssuer)
      {
        status = MCheckIssuerAlg (pCertObj, &pIssuer);
        if (OK != status)
          goto exit;
      }
    }

    if (NULL != pEntry)
      continue;

    /* If we reach this code, we found no cert at all. There's no need to look
     * any further.
     */
    break;
  }

  /* If pIssuer is not NULL, return that cert. If it is NULL, return NULL, so
   * just set *ppIssuerCert to pIssuer.
   * If pIssuer is not NULL, then isTrusted is the value we want to set
   * pIsTrusted to. Otherwise, leave pIsTrusted to point to FALSE.
   * Also check to see if this is a self-signed cert. Namely, check to see if
   * these two certs are really the same. Do this by checking to see if the
   * subject name in the issuer is the same as the issuer name in the leaf. If
   * that is the case, check the serial numbers. If they also are the same, this
   * is the same cert, so it is self-signed.
   */
  *ppIssuerCert = pIssuer;
  if (NULL != pIssuer)
  {
    status = MIsSameCert (pCertObj, pIssuer, pIsSelfSigned);
    if (OK != status)
      goto exit;

    *pIsTrusted = isTrusted;
  }

exit:

  return (status);
}

MSTATUS MCheckIssuerDates (
  MCertObj *ppIssuerCert,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter
  )
{
  MSTATUS status;
  sbyte4 tDiff;
  TimeDate notBefore, notAfter;

  status = MGetValidityDates ((*ppIssuerCert), &notBefore, &notAfter);
  if (OK != status)
    goto exit;

  /* We need the notBefore to be on or before the pNotBefore, so the tDiff should
   * be 0 or negative.
   */
  status = DATETIME_diffTime (&notBefore, pNotBefore, &tDiff);
  if (OK != status)
    goto exit;

  if (0 >= tDiff)
  {
    /* We need the notAfter to be on or after the pNotAfter, so the tDiff should
     * be 0 or negative.
     */
    status = DATETIME_diffTime (pNotAfter, &notAfter, &tDiff);
    if (OK != status)
      goto exit;

    if (0 >= tDiff)
      goto exit;
  }

  /* If we reach this code, the dates didn't work. So set *ppIssuerCert to NULL.
   */
  *ppIssuerCert = NULL;

exit:

  return (status);
}

MSTATUS MCheckIssuerAlg (
  MCertObj pCertObj,
  MCertObj *ppIssuerCert
  )
{
  MSTATUS status;
  ubyte4 cAlg, iAlg;

  /* Get the leaf cert's signature alg.
   */
  status = MGetSignatureKeyAlg (
    (struct MCertOrRequestObject *)pCertObj, &cAlg);
  if (OK != status)
    goto exit;

  /* Get the issuer's key alg.
   */
  status = MGetCertOrRequestKeyAlg (
    (struct MCertOrRequestObject *)(*ppIssuerCert), &iAlg);
  if (OK != status)
    goto exit;

  /* If they are the same and valid, we're done.
   */
  if (cAlg == iAlg)
  {
    if ( (cAlg == akt_rsa) || (cAlg == akt_ecc) || (cAlg == akt_dsa) )
      goto exit;
  }

  /* There's a mismatch or else the alg is bad. Just set *ppIssuerCert to NULL.
   */
  *ppIssuerCert = NULL;

exit:

  return (status);
}

MSTATUS MCopyExtensionArrayAlloc (
  MCertExtension *pExtensions,
  ubyte4 extCount,
  MBasicConstraintsInfo *pBcInfo,
  MKeyUsageInfo *pKuInfo,
  MCertExtension **ppNewExtensions
  )
{
  MSTATUS status;
  intBoolean isExt;
  ubyte4 index;
  MCertExtension *pNewArray = NULL;
  MBasicConstraintsInfo *pOldBc;
  MKeyUsageInfo *pOldKu;

  status = OK;
  *ppNewExtensions = NULL;
  if (0 == extCount)
    goto exit;

  /* Create an empty array.
   */
  status = DIGI_CALLOC (
    (void **)&pNewArray, sizeof (MCertExtension) * extCount, 1);
  if (OK != status)
    goto exit;

  /* Now run through the input list. If an entry is not BC or KU, just copy it
   * and the associated info.
   * If it is one of the special cases, create the new data.
   */
  for (index = 0; index < extCount; ++index)
  {
    pNewArray[index].ExtensionType = pExtensions[index].ExtensionType;

    /* Is this BasicConstraints?
     */
    status = pExtensions[index].ExtensionType (
      MOC_EXTENSION_OP_IS_BC, NULL, 0, (void *)&isExt);
    if ( (OK == status) && (FALSE != isExt) )
    {
      pOldBc = (MBasicConstraintsInfo *)(pExtensions[index].pValue);
      pBcInfo->isCritical = pOldBc->isCritical;
      pBcInfo->isCa = TRUE;
      pBcInfo->pathLen = 1;
      if (FALSE != pOldBc->isCa)
        pBcInfo->pathLen += pOldBc->pathLen;

      pNewArray[index].pValue = (ubyte *)pBcInfo;
      continue;
    }

    /* Is this KeyUsage?
     */
    status = pExtensions[index].ExtensionType (
      MOC_EXTENSION_OP_IS_KU, NULL, 0, (void *)&isExt);
    if ( (OK == status) && (FALSE != isExt) )
    {
      pOldKu = (MKeyUsageInfo *)(pExtensions[index].pValue);
      pKuInfo->isCritical = pOldKu->isCritical;
      pKuInfo->keyUsageBits = MOC_KEY_USAGE_KEY_CERT_SIGN;
      pNewArray[index].pValue = (ubyte *)pKuInfo;
      continue;
    }

    /* If not BC or KU, just copy the old associated info into the new.
     */
    pNewArray[index].pValue = pExtensions[index].pValue;
    pNewArray[index].valueLen = pExtensions[index].valueLen;
  }

  *ppNewExtensions = pNewArray;
  pNewArray = NULL;

exit:

  if (NULL != pNewArray)
  {
    DIGI_FREE ((void **)&pNewArray);
  }

  return (status);
}

MSTATUS MIsSameCert (
  MCertObj pCert1,
  MCertObj pCert2,
  intBoolean *pIsSame
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 len1, len2;
  ubyte *pBuf1, *pBuf2;

//  status = OK;
//  *pIsSame = TRUE;
//  if (pCert1 == pCert2)
//    goto exit;

  *pIsSame = FALSE;
  status = MGetIssuerSerial (pCert1, &pBuf1, &len1);
  if (OK != status)
    goto exit;

  status = MGetIssuerSerial (pCert2, &pBuf2, &len2);
  if (OK != status)
    goto exit;

  if (len1 != len2)
    goto exit;

  status = DIGI_MEMCMP ((void *)pBuf1, (void *)pBuf2, len1, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 == cmpResult)
    *pIsSame = TRUE;

exit:

  return (status);
}
