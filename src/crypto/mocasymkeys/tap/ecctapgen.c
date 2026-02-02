/*
 * ecctapgen.c
 *
 * Generate an ECC key pair using the TAP API.
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

#include "../../../crypto/mocasymkeys/tap/ecctap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_ECC__) && \
    defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS EccTapGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  TAP_KeyInfo keyInfo = {0};
  MocAsymKey pPub = NULL;
  MocAsymKey pPri = NULL;
  TAP_Key *pTapKey = NULL;
  MEccTapKeyData *pInfo = NULL;
  MEccTapKeyGenArgs *genArgs = NULL;
  TAP_ErrorContext errContext;

  status = ERR_NULL_POINTER;
  if ( (NULL == pInputInfo->pOperatorInfo) ||
       (NULL == pOutputInfo->ppPubKey) || 
       (NULL == pOutputInfo->ppPriKey) )
    goto exit;

  genArgs = (MEccTapKeyGenArgs *)(pInputInfo->pOperatorInfo);

  /* Private key is on the TAP hardware device */
  status = CRYPTO_createMocAsymKey (
    KeyOperatorEccTap, (void *)genArgs, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE, &pPri);
  if (OK != status)
    goto exit;

  /* Point to the newly allocated context */
  pInfo = (MEccTapKeyData *)(pPri->pKeyData);

  /* Set up the key info to create an empty shell */
  keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
  keyInfo.keyUsage = TAP_KEY_USAGE_UNDEFINED;
  keyInfo.tokenId = genArgs->tokenId;
  keyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_NONE;
  keyInfo.algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NONE;

  /* Caller must specify a curve */
  status = ERR_INVALID_ARG;
  if (TAP_ECC_CURVE_NONE == genArgs->algKeyInfo.eccInfo.curveId)
    goto exit;

  keyInfo.algKeyInfo.eccInfo.curveId = genArgs->algKeyInfo.eccInfo.curveId;

  /* Overwrite fields with the data from the argument structure as applicable */
  if (TAP_KEY_USAGE_UNDEFINED != genArgs->keyUsage)
    keyInfo.keyUsage = genArgs->keyUsage;

  if (TAP_SIG_SCHEME_NONE != genArgs->algKeyInfo.eccInfo.sigScheme)
    keyInfo.algKeyInfo.eccInfo.sigScheme = genArgs->algKeyInfo.eccInfo.sigScheme;

  status = TAP_asymGenerateKey (
    pInfo->pTapCtx, pInfo->pEntityCredentials, &keyInfo, 
    pInfo->pKeyAttributes, pInfo->pKeyCredentials, &pTapKey, &errContext);
  if (OK != status)
    goto exit;

  /* Key comes out of generate in a loaded state */
  pInfo->isKeyLoaded = TRUE;
    
  /* Load the newly created TAP key into a MocAsymKey object */
  status = EccTapLoadKeyData (
    &pTapKey, NULL, 0, NULL, genArgs->standardParams, pPri);
  if (OK != status)
    goto exit;

#if __ENABLE_DIGICERT_ALL_ECCTAP_OPERATORS__
  /* To build a public key caller must pass in a valid standardParams */
  if (NULL != genArgs->standardParams)
  {
    status = EccTapGetPubFromPri (pPri, &pPub);
    if (OK != status)
      goto exit;
  }
#endif

  *(pOutputInfo->ppPubKey) = pPub;
  *(pOutputInfo->ppPriKey) = pPri;

  pPub = NULL;
  pPri = NULL;

exit:

  if (NULL != pTapKey)
  {
    TAP_freeKey(&pTapKey);
  }
  if (NULL != pPub)
  {
    CRYPTO_freeMocAsymKey (&pPub, ppVlongQueue);
  }
  if (NULL != pPri)
  {
    CRYPTO_freeMocAsymKey (&pPri, ppVlongQueue);
  }

  return status;

} /* EccTapGenerateKeyPair */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc */
