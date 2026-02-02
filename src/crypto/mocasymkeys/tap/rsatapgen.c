/*
 * rsatapgen.c
 *
 * Generate an RSA key pair using the TAP API.
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

#include "../../../crypto/mocasymkeys/tap/rsatap.h"
 
#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS RsaTapGenerateKeyPair (
  MocCtx pMocCtx,
  MKeyPairGenInfo *pInputInfo,
  MKeyPairGenResult *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  TAP_KeyInfo keyInfo = {0};
  MRsaTapKeyData *pInfo = NULL;
  MocAsymKey pPub = NULL;
  MocAsymKey pPri = NULL;
  TAP_Key *pTapKey = NULL;
  MRsaTapKeyGenArgs *genArgs = NULL;
  TAP_ErrorContext errContext;

  status = ERR_NULL_POINTER;
  if ( (NULL == pInputInfo->pOperatorInfo) ||
       (NULL == pOutputInfo->ppPubKey) || 
       (NULL == pOutputInfo->ppPriKey) )
    goto exit;

  genArgs = (MRsaTapKeyGenArgs *)(pInputInfo->pOperatorInfo);

  /* Private key is on the TAP hardware device */
  status = CRYPTO_createMocAsymKey (
    KeyOperatorRsaTap, (void *)genArgs, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE, &pPri);
  if (OK != status)
    goto exit;

  /* Point to the newly allocated context */
  pInfo = (MRsaTapKeyData *)(pPri->pKeyData);

  /* Set up the key info to create an empty shell */
  keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
  keyInfo.keyUsage = TAP_KEY_USAGE_UNDEFINED;
  keyInfo.tokenId = genArgs->tokenId;
  keyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE;
  keyInfo.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
  keyInfo.algKeyInfo.rsaInfo.exponent = 0;

  /* Overwrite fields with the data from the argument structure as applicable */
  status = ERR_INVALID_ARG;
  if (TAP_KEY_USAGE_UNDEFINED != genArgs->keyUsage)
    keyInfo.keyUsage = genArgs->keyUsage;

  if (TAP_SIG_SCHEME_NONE != genArgs->algKeyInfo.rsaInfo.sigScheme)
    keyInfo.algKeyInfo.rsaInfo.sigScheme = genArgs->algKeyInfo.rsaInfo.sigScheme;
  
  if (TAP_ENC_SCHEME_NONE != genArgs->algKeyInfo.rsaInfo.encScheme)
    keyInfo.algKeyInfo.rsaInfo.encScheme = genArgs->algKeyInfo.rsaInfo.encScheme;
  
  if (0 != genArgs->algKeyInfo.rsaInfo.exponent)
    keyInfo.algKeyInfo.rsaInfo.exponent = genArgs->algKeyInfo.rsaInfo.exponent;
  
  switch(genArgs->algKeyInfo.rsaInfo.keySize)
  {
    case TAP_KEY_SIZE_1024:
    case TAP_KEY_SIZE_2048:
    case TAP_KEY_SIZE_3072:
    case TAP_KEY_SIZE_4096:
    case TAP_KEY_SIZE_8192:
      keyInfo.algKeyInfo.rsaInfo.keySize = genArgs->algKeyInfo.rsaInfo.keySize;
      break;

    default:
      goto exit;
  }

  status = TAP_asymGenerateKey (
    pInfo->pTapCtx, pInfo->pEntityCredentials, &keyInfo, 
    pInfo->pKeyAttributes, pInfo->pKeyCredentials, &pTapKey, &errContext);
  if (OK != status)
    goto exit;

  /* Key comes out of generation in a loaded state */
  pInfo->isKeyLoaded = TRUE;

  /* Load the newly created TAP key into a MocAsymKey object */
  status = RsaTapLoadKeyData(&pTapKey, NULL, 0, NULL, pPri);
  if (OK != status)
    goto exit;

#if __ENABLE_DIGICERT_ALL_RSATAP_OPERATORS__
  status = RsaTapGetPubFromPri (pPri, &pPub, ppVlongQueue);
  if (OK != status)
    goto exit;
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
  if (NULL != pPri)
  {
    CRYPTO_freeMocAsymKey (&pPri, ppVlongQueue);
  }
  if (NULL != pPub)
  {
    CRYPTO_freeMocAsymKey (&pPub, ppVlongQueue);
  }
  
  return status;
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc... */
