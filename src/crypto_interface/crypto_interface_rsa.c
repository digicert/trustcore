/*
 * crypto_interface_rsa.c
 *
 * Cryptographic Interface specification for RSA.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/rsa.h"
#include "../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_rsa_tap_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_CREATE(_status, _ppNewKey)                                     \
    _status = RSA_createKey(_ppNewKey);
#else
#define MOC_RSA_CREATE(_status, _ppNewKey)                                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_FREE(_status, _ppKey, _ppVlongQueue)                           \
    _status = RSA_freeKey(_ppKey, _ppVlongQueue);
#else
#define MOC_RSA_FREE(_status, _ppKey, _ppVlongQueue)                           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_CLONE(_status, _ppNewKey, pSrc, _ppVlongQueue)                 \
    _status = RSA_cloneKey(MOC_RSA(hwAccelCtx) _ppNewKey, pSrc, _ppVlongQueue);
#else
#define MOC_RSA_CLONE(_status, _ppNewKey, pSrc, _ppVlongQueue)                 \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_GET_CIPHERTEXT_LEN(_status, _pKey, _pCipherTextLen)            \
    _status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) _pKey, _pCipherTextLen);
#else
#define MOC_RSA_GET_CIPHERTEXT_LEN(_status, _pKey, _pCipherTextLen)            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_BYTESTRING_FROM_KEY(_status, _pKey, _pBuffer, _pRetLen)        \
    _status = RSA_byteStringFromKey (MOC_RSA(hwAccelCtx) _pKey, _pBuffer, _pRetLen);
#else
#define MOC_RSA_BYTESTRING_FROM_KEY(_status, _pKey, _pBuffer, _pRetLen)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_GENERATE(_status, _pRandomContext,                             \
                         _pRsaKey, _keySize, _ppVlongQueue)                    \
    _status = RSA_generateKey (                                                \
      MOC_RSA(hwAccelCtx) _pRandomContext, _pRsaKey, _keySize, _ppVlongQueue);
#else
#define MOC_RSA_GENERATE(_status, _pRandomContext,                             \
                         _pRsaKey, _keySize, _ppVlongQueue)                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_SET_PUBLIC_KEY_DATA(_status, _pKey, _pPubExpo, _pubExpoLen,    \
                                    _pModulus, _modulusLen, _ppVlongQueue)     \
    _status = RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)                       \
      _pKey, _pPubExpo, _pubExpoLen, _pModulus, _modulusLen, _ppVlongQueue);
#else
#define MOC_RSA_SET_PUBLIC_KEY_DATA(_status, _pKey, _pPubExpo, _pubExpoLen,    \
                                    _pModulus, _modulusLen, _ppVlongQueue)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_SET_ALL_KEY_DATA(_status, _pKey,                               \
                                 _pPubExpo, _pubExpoLen,                       \
                                 _pModulus, _modulusLen,                       \
                                 _pPrime1, _prime1Len, _pPrime2, _prime2Len,   \
                                 _ppVlongQueue)                                \
    _status = RSA_setAllKeyData(                                               \
      MOC_RSA (hwAccelCtx) _pKey, _pPubExpo, _pubExpoLen, _pModulus,           \
      _modulusLen, _pPrime1, _prime1Len, _pPrime2, _prime2Len, _ppVlongQueue);
#else
#define MOC_RSA_SET_ALL_KEY_DATA(_status, _pKey,                               \
                                 _pPubExpo, _pubExpoLen,                       \
                                 _pModulus, _modulusLen,                       \
                                 _pPrime1, _prime1Len, _pPrime2, _prime2Len,   \
                                 _ppVlongQueue)                                \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_KEY_FROM_BYTESTRING(_status, _ppKey, _pByteString, _len, _ppVlongQueue) \
    _status = RSA_keyFromByteString (                                                   \
      MOC_RSA(hwAccelCtx) _ppKey, _pByteString, _len, _ppVlongQueue);
#else
#define MOC_RSA_KEY_FROM_BYTESTRING(_status, _ppKey, _pByteString, _len, _ppVlongQueue) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_SIGN(_status, _pKey, _pPlainText, _plainTextLen,               \
                     _pCipherText, _ppVlongQueue)                              \
    _status = RSA_signMessage (                                                \
     MOC_RSA(hwAccelCtx) _pKey, _pPlainText, _plainTextLen, _pCipherText, _ppVlongQueue);
#else
#define MOC_RSA_SIGN(_status, _pKey, _pPlainText, _plainTextLen,               \
                     _pCipherText, _ppVlongQueue)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_VERIFY(_status, _pKey, _pCipherText, _pPlainText,              \
                       _pPlainTextLen, _ppVlongQueue)                          \
    _status = RSA_verifySignature (                                            \
      MOC_RSA(hwAccelCtx) _pKey, _pCipherText, _pPlainText, _pPlainTextLen,            \
      _ppVlongQueue);
#else
#define MOC_RSA_VERIFY(_status, _pKey, _pCipherText, _pPlainText,              \
                       _pPlainTextLen, _ppVlongQueue)                          \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__)) && \
    (defined(__ENABLE_DIGICERT_RSA_SIGN_DATA__))
#define MOC_RSA_SIGN_FULL(_status, _pKey, _pData, _dataLen, _hashId, _pSig, _ppVlongQueue) \
    _status = RSA_signData(MOC_RSA(hwAccelCtx) _pKey, _pData, _dataLen, _hashId, _pSig, _ppVlongQueue);
#else
#define MOC_RSA_SIGN_FULL(_status, _pKey, _pData, _dataLen, _hashId, _pSig, _ppVlongQueue) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__)) && \
    (defined(__ENABLE_DIGICERT_RSA_SIGN_DATA__))
#define MOC_RSA_VER_FULL(_status, _pKey, _pData, _dataLen, _hashId, _pSig, _sigLen, _pIsValid, _ppVlongQueue) \
    _status = RSA_verifyData(MOC_RSA(hwAccelCtx) _pKey, _pData, _dataLen, _hashId, _pSig, _sigLen, _pIsValid, _ppVlongQueue);
#else
#define MOC_RSA_VER_FULL(_status, _pKey, _pData, _dataLen, _hashId, _pSig, _sigLen, _pIsValid, _ppVlongQueue) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_ENCRYPT(_status, _pKey,                                        \
                        _pPlainText, _plainTextLen, _pCipherText,              \
                        _rngFun, _pRngFunArg, _ppVlongQueue)                   \
    _status = RSA_encrypt (                                                    \
      MOC_RSA(hwAccelCtx) _pKey, _pPlainText, _plainTextLen, _pCipherText,     \
      _rngFun, _pRngFunArg, _ppVlongQueue);
#else
#define MOC_RSA_ENCRYPT(_status, _pKey,                                        \
                        _pPlainText, _plainTextLen, _pCipherText,              \
                        _rngFun, _pRngFunArg, _ppVlongQueue)                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_DECRYPT(_status, _pKey, _pCipherText,                          \
                        _pPlainText, _pPlainTextLen, _rngFun, _pRngFunArg,     \
                        _ppVlongQueue)                                         \
    _status = RSA_decrypt (                                                    \
      MOC_RSA(hwAccelCtx) _pKey, _pCipherText, _pPlainText, _pPlainTextLen,    \
      _rngFun, _pRngFunArg, _ppVlongQueue);
#else
#define MOC_RSA_DECRYPT(_status, _pKey, _pCipherText,                          \
                        _pPlainText, _pPlainTextLen, _rngFun, _pRngFunArg,     \
                        _ppVlongQueue)                                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_GET_KEY_PARAMS_ALLOC(_status, _pKey, _pTemplate, _keyType)     \
    _status = RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx) _pKey, _pTemplate, _keyType);
#else
#define MOC_RSA_GET_KEY_PARAMS_ALLOC(_status, _pKey, _pTemplate, _keyType)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_FREE_KEY_TEMPLATE(_status, _pKey, _pTemplate)                  \
    _status = RSA_freeKeyTemplate(_pKey, _pTemplate);
#else
#define MOC_RSA_FREE_KEY_TEMPLATE(_status, _pKey, _pTemplate)                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_EQUAL_KEY(_status, _pKey1, _pKey2, _res)                       \
  _status = RSA_equalKey(MOC_RSA(hwAccelCtx) _pKey1, _pKey2, _res);
#else
#define MOC_RSA_EQUAL_KEY(_status, _pKey1, _pKey2, _res)                       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_APPLY_PUB_KEY(_status, _pKey, _pIn, _inLen, _ppOut, _ppQueue) \
  _status = RSA_applyPublicKey (MOC_RSA(hwAccelCtx) _pKey, _pIn, _inLen, _ppOut, _ppQueue);
#else
#define MOC_RSA_APPLY_PUB_KEY(_status, _pKey, _pIn, _inLen, _ppOut, _ppQueue) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_APPLY_PRI_KEY(_status, _rngFun, _rngArg, _pKey, _pIn, _inLen, \
                              _ppOut, _ppVlongQueue)                          \
  _status = RSA_applyPrivateKey (MOC_RSA(hwAccelCtx)                                             \
    _pKey, _rngFun, _rngArg, _pIn, _inLen, _ppOut, _ppVlongQueue);
#else
#define MOC_RSA_APPLY_PRI_KEY(_status, _rngFun, _rngArg, _pKey, _pIn, _inLen, \
                              _ppOut, _ppVlongQueue)                          \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA__))
#define MOC_RSA_VERIFY_DIGEST(_status, _pKey, _pMsgDigest, _digestLen, _pSignature, _sigLen, \
                              _pIsValid, _ppVlongQueue)                                      \
  _status = RSA_verifyDigest (MOC_RSA(hwAccelCtx)                                            \
     _pKey, _pMsgDigest, _digestLen, _pSignature, _sigLen, _pIsValid, _ppVlongQueue)
#else
#define MOC_RSA_VERIFY_DIGEST(_status, _pKey, _pMsgDigest, _digestLen, _pSignature, _sigLen, \
                              _pIsValid, _ppVlongQueue)                                      \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_createKeyAux (
  RSAKey **ppNewKey
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey,
  sbyte4 *pCipherTextLen
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyDataAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  const ubyte *pPrime1,
  ubyte4 prime1Len,
  const ubyte *pPrime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyTemplateAux (
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate
  );

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_loadKeys (
  RSAKey **ppNewKey,
  MocAsymKey *ppPriKey,
  MocAsymKey *ppPubKey
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocCtx pMocCtx = NULL;
  RSAKey *pNewKey = NULL;
  MocAsymKey pPriKeyToUse = NULL;
  MocAsymKey pPubKeyToUse = NULL;
  MocAsymKey pPriKey = NULL;
  MocAsymKey pPubKey = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppNewKey)
    goto exit;

  if (NULL != ppPriKey)
    pPriKey = *ppPriKey;
  if (NULL != ppPubKey)
    pPubKey = *ppPubKey;

  status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(RSAKey));
  if (OK != status)
    goto exit;

  if (NULL != pPriKey)
  {
    /* We have a private key to load, do we also have a public key? */
    pPriKeyToUse = pPriKey;
    if (NULL != pPubKey)
    {
      /* We also have a public key, set the pointer to simply load them in */
      pPubKeyToUse = pPubKey;
    }
    else
    {
      /* We do not have a public key, get one from the operator */
      status = CRYPTO_getPubFromPri(pPriKeyToUse, &pPubKeyToUse, NULL);
      if (OK != status)
        goto exit;
    }

    pNewKey->privateKey = TRUE;
  }
  else
  {
    /* If the private key is NULL, we need a valid public key */
    status = ERR_NULL_POINTER;
    if (NULL == pPubKey)
      goto exit;

    pPubKeyToUse = pPubKey;

    /* Is this a TAP key? */
    if (0 != (MOC_LOCAL_TYPE_TAP & pPubKey->localType))
    {
      /* We need to create a shell for the underlying private MocAsymKey */
      status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* Determine the index at which the RSA TAP operator lives */
      status = CRYPTO_INTERFACE_checkTapAsymAlgoStatus (
        moc_alg_rsa, &algoStatus, &index);
      if (OK != status)
        goto exit;
    }
    else
    {
      /* We need to create a shell for the underlying private MocAsymKey */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* Determine the index at which the RSA operator lives */
      status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
        moc_alg_rsa, &algoStatus, &index);
      if (OK != status)
        goto exit;
    }

    /* If the underlying operator is not enabled thats an error */
    status = ERR_CRYPTO_INTERFACE;
    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
      goto exit;

    /* Get a new private key shell */
    status = CRYPTO_getAsymObjectFromIndex (
      index, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PRIVATE, &pPriKeyToUse);
    if (OK != status)
      goto exit;
  }

  /* Set the keys inside of the ECCKey */
  pNewKey->pPrivateKey = pPriKeyToUse;
  pNewKey->pPublicKey = pPubKeyToUse;
  pPriKeyToUse = NULL;
  pPubKeyToUse = NULL;

  /* NULL out the callers reference */
  if (NULL != ppPriKey)
  {
    *ppPriKey = NULL;
  }
  if (NULL != ppPubKey)
  {
    *ppPubKey = NULL;
  }

  /* Mark this object as crypto interface enabled */
  pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

  *ppNewKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    DIGI_FREE((void **)&pNewKey);
  }
  if (NULL != pPriKeyToUse)
  {
    CRYPTO_freeMocAsymKey(&pPriKeyToUse, NULL);
  }
  if (NULL != pPubKeyToUse)
  {
    CRYPTO_freeMocAsymKey(&pPubKeyToUse, NULL);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_loadKey (
  RSAKey **ppNewKey,
  MocAsymKey *ppKey
  )
{
  MSTATUS status;
  MocAsymKey pKey = NULL;
  MocAsymKey pPriKey = NULL;
  MocAsymKey pPubKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppNewKey) || (NULL == ppKey) )
    goto exit;

  pKey = *ppKey;
  if (NULL == pKey)
    goto exit;

  /* Is this a private key? */
  if (0 != (MOC_LOCAL_TYPE_PRI & pKey->localType))
  {
    pPriKey = pKey;
  }
  else
  {
    pPubKey = pKey;
  }

  status = CRYPTO_INTERFACE_RSA_loadKeys(ppNewKey, &pPriKey, &pPubKey);
  if (OK != status)
    goto exit;

  *ppKey = NULL;

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_createKeyAux (
  RSAKey **ppNewKey
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocCtx pMocCtx = NULL;
  RSAKey *pNewKey = NULL;
  MocAsymKey pNewPriKey = NULL;
  MocAsymKey pNewPubKey = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppNewKey)
    goto exit;

  /* Determine if we have an RSA implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
    moc_alg_rsa, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Get an empty RSA private key from the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      index, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PRIVATE, &pNewPriKey);
    if (OK != status)
      goto exit;

    /* Get an empty RSA public key from the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      index, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPubKey);
    if (OK != status)
      goto exit;

    /* Allocate the RSAKey */
    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(RSAKey));
    if (OK != status)
      goto exit;

    /* Set the newly created keys inside the RSAKey */
    pNewKey->pPrivateKey = pNewPriKey;
    pNewPriKey = NULL;
    pNewKey->pPublicKey = pNewPubKey;
    pNewPubKey = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    /* Set the callers pointer */
    *ppNewKey = pNewKey;
    pNewKey = NULL;
  }
  else
  {
    MOC_RSA_CREATE(status, ppNewKey)
  }

exit:

  if (NULL != pNewPriKey)
  {
    CRYPTO_freeMocAsymKey(&pNewPriKey, NULL);
  }
  if (NULL != pNewPubKey)
  {
    CRYPTO_freeMocAsymKey(&pNewPubKey, NULL);
  }
  if (NULL != pNewKey)
  {
    DIGI_FREE((void **)&pNewKey);
  }

  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyAux (
  RSAKey **ppRsaKey,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  RSAKey *pRsaKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppRsaKey) || (NULL == *ppRsaKey) )
    goto exit;

  pRsaKey = *ppRsaKey;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRsaKey->enabled)
  {
    status = CRYPTO_INTERFACE_freeAsymKeys (
      (void **)ppRsaKey, pRsaKey->pPublicKey, pRsaKey->pPrivateKey);
  }
  else
  {
    MOC_RSA_FREE(status, ppRsaKey, ppVlongQueue)
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_signMessageAux (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pPlainText,
  ubyte4 plainTextLen,
  ubyte *pCipherText,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 bufferSize = 0;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPrivateKey)
      goto exit; /* status still ERR_NULL_POINTER */

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_signDigestInfo (
        pKey->pPrivateKey, (ubyte *) pPlainText, plainTextLen,
        pCipherText, ppVlongQueue);
    }
    else
    {
      /* Assume the output buffer is just large enough */
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
        MOC_RSA(hwAccelCtx)
        pKey, (sbyte4*)&bufferSize);
      if (OK != status)
        goto exit;

      status = CRYPTO_asymSignDigestInfo (
        pKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD, NULL,
        RANDOM_rngFun, g_pRandomContext, (ubyte *)pPlainText, plainTextLen,
        pCipherText, bufferSize, &bufferSize, ppVlongQueue);
    }
  }
  else
  {
    MOC_RSA_SIGN (
      status, pKey, pPlainText, plainTextLen, pCipherText,
      ppVlongQueue)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifySignatureAux (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pCipherText,
  ubyte *pPlainText,
  ubyte4 *pPlainTextLen,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 bufferSize = 0;
  ubyte4 cipherTextLen = 0;
  ubyte4 plainTextLen = 0;
  ubyte4 padCheck = 0;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPublicKey || NULL == pPlainTextLen)
      goto exit;  /* status still ERR_NULL_POINTER */

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
        MOC_RSA(hwAccelCtx)
        pKey, (sbyte4*)&cipherTextLen);
      if (OK != status)
        goto exit;

      plainTextLen = 0;
      padCheck = 0;
      bufferSize = cipherTextLen;

      status = CRYPTO_asymEncrypt (
        pKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD, NULL,
        RANDOM_rngFun, g_pRandomContext, (ubyte *)pCipherText, cipherTextLen,
        pPlainText, bufferSize, &plainTextLen, ppVlongQueue);
      if (OK != status)
        goto exit;

      status = RsaUnpadPkcs15 (
        MOC_ASYM_KEY_FUNCTION_SIGN, pPlainText, plainTextLen, &plainTextLen,
        &padCheck);
      if (OK != status)
        goto exit;

      if (0 == padCheck)
      {
        *pPlainTextLen = plainTextLen;
      }
      else
      {
        *pPlainTextLen = 0;
        status = ERR_RSA_DECRYPTION;
      }
    }
  }
  else
  {
    MOC_RSA_VERIFY (
      status, pKey, pCipherText, pPlainText, pPlainTextLen,
      ppVlongQueue)
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_signData(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte hashId,
  ubyte *pSignature,
  vlong **ppVlongQueue)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_RSA_SIGN_FULL(status, pKey, pData, dataLen, hashId, pSignature, ppVlongQueue)
  }

exit:
  
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifyData(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte hashId,
  ubyte *pSignature,
  ubyte4 signatureLen,
  intBoolean *pIsValid,
  vlong **ppVlongQueue)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_RSA_VER_FULL(status, pKey, pData, dataLen, hashId, pSignature, signatureLen, pIsValid, ppVlongQueue)
  }

exit:
  
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_encryptAux (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pPlainText,
  ubyte4 plainTextLen,
  ubyte *pCipherText,
  RNGFun rngFun,
  void *pRngFunArg,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 bufferSize = 0;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPublicKey)
      goto exit;  /* status still ERR_NULL_POINTER */

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_encrypt (
        pKey->pPublicKey, (ubyte *) pPlainText, plainTextLen,
        pCipherText, rngFun, pRngFunArg, ppVlongQueue);
    }
    else
    {
      /* Assume the output buffer is just large enough */
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
        MOC_RSA(hwAccelCtx)
        pKey, (sbyte4*)&bufferSize);
      if (OK != status)
        goto exit;

      status = CRYPTO_asymEncrypt (
        pKey->pPublicKey, NULL, 0,
        MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD, NULL,
        rngFun, pRngFunArg, (ubyte *)pPlainText, plainTextLen,
        pCipherText, bufferSize, &bufferSize, ppVlongQueue
      );
    }
  }
  else
  {
    MOC_RSA_ENCRYPT (
      status, pKey, pPlainText, plainTextLen, pCipherText,
      rngFun, pRngFunArg, ppVlongQueue)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_decryptAux (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  const ubyte *pCipherText,
  ubyte *pPlainText,
  ubyte4 *pPlainTextLen,
  RNGFun rngFun,
  void *pRngFunArg,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 bufferSize = 0;
  ubyte4 cipherTextLen = 0;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPrivateKey)
      goto exit;  /* status still ERR_NULL_POINTER */

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_decrypt (
        pKey->pPrivateKey, (ubyte *) pCipherText, pPlainText,
        pPlainTextLen, rngFun, pRngFunArg, ppVlongQueue);
    }
    else
    {
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
        MOC_RSA(hwAccelCtx)
        pKey, (sbyte4*)&cipherTextLen);
      if (OK != status)
        goto exit;

      bufferSize = cipherTextLen;

      status = CRYPTO_asymDecrypt (
        pKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD, NULL,
        RANDOM_rngFun, g_pRandomContext, (ubyte *)pCipherText, cipherTextLen,
        pPlainText, bufferSize, pPlainTextLen, ppVlongQueue);
    }
  }
  else
  {
    MOC_RSA_DECRYPT (
      status, pKey, pCipherText, pPlainText, pPlainTextLen,
      rngFun, pRngFunArg, ppVlongQueue)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_generateKey (
  MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
  RSAKey *pRsaKey,
  ubyte4 keySize,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MKeyOperator KeyOperator;
  MocCtx pMocCtx;
  ubyte4 algoStatus, index;

  status = ERR_NULL_POINTER;
  if (NULL == pRsaKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRsaKey->enabled)
  {
    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Get the operator index for this algorithm */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
      moc_alg_rsa, &algoStatus, &index);
    if (OK != status)
      goto exit;

    /* Get the operator for this algorithm */
    status = CRYPTO_getAsymOperatorAndInfoFromIndex (
      index, pMocCtx, &KeyOperator, NULL);
    if (OK != status)
      goto exit;

    /* Generate the RSA keypair, this will destory the two empty keys made
     * during CRYPTO_INTERFACE_RSA_createKey */
    status = CRYPTO_generateKeyPair (
      KeyOperator, (void *)&keySize, pMocCtx, RANDOM_rngFun, pRandomContext,
      &(pRsaKey->pPublicKey), &(pRsaKey->pPrivateKey), ppVlongQueue);
    if (OK != status)
      goto exit;

    /* Mark this key as private */
    pRsaKey->privateKey = 1;
  }
  else
  {
    MOC_RSA_GENERATE (
      status, pRandomContext, pRsaKey, keySize,
      ppVlongQueue)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_cloneKey (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey **ppNewKey,
  const RSAKey *pSrc,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  RSAKey *pNewKey = NULL;
  MocAsymKey pKeyToClone = NULL;
  MocAsymKey pClonedKey = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pSrc)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    /* Are we cloning the public or private key? We maintain this value so it
     * should be accurate */
    if (1 == pSrc->privateKey)
    {
      pKeyToClone = pSrc->pPrivateKey;
    }
    else
    {
      pKeyToClone = pSrc->pPublicKey;
    }

    /* Clone the underlying MocAsymKey */
    status = CRYPTO_cloneMocAsymKey (
      pKeyToClone, &pClonedKey, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* Allocate the RSAKey */
    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(RSAKey));
    if (OK != status)
      goto exit;

    /* If the cloned key is private, create the public key from the private key. */
    if (1 == pSrc->privateKey)
    {
      status = CRYPTO_getPubFromPri (
        pClonedKey, &(pNewKey->pPublicKey), ppVlongQueue);
      if (OK != status)
        goto exit;

      pNewKey->privateKey = 1;
      pNewKey->pPrivateKey = pClonedKey;
    }
    else
    {
      pNewKey->pPublicKey = pClonedKey;
    }

    /* Mark this key as enabled */
    pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    pClonedKey = NULL;
    *ppNewKey = pNewKey;
    pNewKey = NULL;
  }
  else
  {
    MOC_RSA_CLONE (status, ppNewKey, pSrc, ppVlongQueue)
  }

exit:

  if (NULL != pClonedKey)
  {
    CRYPTO_freeMocAsymKey(&pClonedKey, NULL);
  }
  if (NULL != pNewKey)
  {
    DIGI_FREE((void **)&pNewKey);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey,
  sbyte4 *pCipherTextLen
  )
{
  MSTATUS status;
  ubyte4 securitySize = 0;

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pKey->pPublicKey) ||
         (NULL == pCipherTextLen) )
      goto exit;

    status = CRYPTO_getSecuritySize(pKey->pPublicKey, &securitySize);
    if (OK != status)
      goto exit;

    *pCipherTextLen = (sbyte4)((securitySize + 7) / 8);
  }
  else
  {
    MOC_RSA_GET_CIPHERTEXT_LEN (status, pKey, pCipherTextLen)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyParametersAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte pPubExpo[4];

  status = ERR_BAD_EXPONENT;
  if (2 > exponent)
    goto exit;

  pPubExpo[0] = (ubyte)(exponent >> 24);
  pPubExpo[1] = (ubyte)(exponent >> 16);
  pPubExpo[2] = (ubyte)(exponent >>  8);
  pPubExpo[3] = (ubyte)(exponent);

  status = CRYPTO_INTERFACE_RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)
    pKey, pPubExpo, 4, pModulus, modulusLen, ppVlongQueue);

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_RSA_validateModulus(
  ubyte *pModulus,
  ubyte4 modulusLen)
{
  /* If the modulus is even, return an error */
  if (NULL != pModulus && 0 < modulusLen && !(pModulus[modulusLen - 1] & 0x01))
  {
    return ERR_RSA_INVALID_MODULUS;
  }

  return OK;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MRsaKeyTemplate keyTemplate = {0};

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  /* quick sanity check on the modulus */
  status = CRYPTO_INTERFACE_RSA_validateModulus((ubyte *) pModulus, modulusLen);
  if (OK != status)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pKey->pPublicKey) )
      goto exit;

    /* Prepare the key template */
    keyTemplate.pE = pPubExpo;
    keyTemplate.eLen = pubExpoLen;
    keyTemplate.pN = (ubyte *)pModulus;
    keyTemplate.nLen = modulusLen;

    /* Set the public key data */
    status = CRYPTO_setKeyData(pKey->pPublicKey, (void *)&keyTemplate);
  }
  else
  {
    MOC_RSA_SET_PUBLIC_KEY_DATA (
      status, pKey, pPubExpo, pubExpoLen, pModulus, modulusLen, ppVlongQueue)
  }

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyParameters (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *modulus,
  ubyte4 modulusLen,
  const ubyte *prime1,
  ubyte4 prime1Len,
  const ubyte *prime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte pPubExpo[4];

  status = ERR_BAD_EXPONENT;
  if (2 > exponent)
    goto exit;

  pPubExpo[0] = (ubyte)(exponent >> 24);
  pPubExpo[1] = (ubyte)(exponent >> 16);
  pPubExpo[2] = (ubyte)(exponent >>  8);
  pPubExpo[3] = (ubyte)(exponent);

  status = CRYPTO_INTERFACE_RSA_setAllKeyDataAux (
    MOC_RSA(hwAccelCtx) pKey, pPubExpo, 4, modulus, modulusLen,
    prime1, prime1Len, prime2, prime2Len, ppVlongQueue);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyDataAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  const ubyte *pPrime1,
  ubyte4 prime1Len,
  const ubyte *pPrime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MRsaKeyTemplate keyTemplate = {0};

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  /* quick sanity check on the modulus */
  status = CRYPTO_INTERFACE_RSA_validateModulus((ubyte *) pModulus, modulusLen);
  if (OK != status)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {

    /* Prepare the key template */
    keyTemplate.pE = pPubExpo;
    keyTemplate.eLen = pubExpoLen;
    keyTemplate.pN = (ubyte *)pModulus;
    keyTemplate.nLen = modulusLen;
    keyTemplate.pP = (ubyte *)pPrime1;
    keyTemplate.pLen = prime1Len;
    keyTemplate.pQ = (ubyte *)pPrime2;
    keyTemplate.qLen = prime2Len;

    /* Set the private key data */
    status = CRYPTO_setKeyData(pKey->pPrivateKey, (void *)&keyTemplate);
    if (OK != status)
      goto exit;

    /* Delete any previously created public key */
    status = CRYPTO_freeMocAsymKey(&(pKey->pPublicKey), NULL);
    if (OK != status)
      goto exit;

    /* Create a new public from the private we just made */
    status = CRYPTO_getPubFromPri (pKey->pPrivateKey, &(pKey->pPublicKey), NULL);
    if (OK != status)
      goto exit;

    pKey->privateKey = 1;
  }
  else
  {
    MOC_RSA_SET_ALL_KEY_DATA (
      status, pKey, pPubExpo, pubExpoLen,
      pModulus, modulusLen, pPrime1, prime1Len, pPrime2, prime2Len, ppVlongQueue)
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_RSA_writeKeyBlobElement (
  ubyte **ppBuffer,
  ubyte *pElement,
  ubyte4 elementLen
  )
{
  MSTATUS status;
  ubyte *pTmp = *ppBuffer;

  BIGEND32(pTmp, elementLen);
  pTmp += sizeof(ubyte4);

  status = DIGI_MEMCPY((void *)pTmp, (void *)pElement, elementLen);
  pTmp += elementLen;
  *ppBuffer = pTmp;

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_byteStringFromKey (
  MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey,
  ubyte *pBuffer,
  ubyte4 *pRetLen
  )
{
  MSTATUS status;
  ubyte4 numElements;
  MRsaKeyTemplate keyTemplate = {0};
  MocAsymKey pKeyToUse = NULL;
  ubyte *pIter = NULL;
  ubyte4 retLen = 0;
  ubyte reqType = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pRetLen) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if ( (NULL == pKey) || (NULL == pKey->pPublicKey) )
      goto exit;

    if (TRUE == pKey->privateKey)
    {
      if (NULL == pKey->pPrivateKey)
        goto exit;

      pKeyToUse = pKey->pPrivateKey;
      reqType = MOC_GET_PRIVATE_KEY_DATA;
      numElements = 4;
    }
    else
    {
      pKeyToUse = pKey->pPublicKey;
      reqType = MOC_GET_PUBLIC_KEY_DATA;
      numElements = 2;
    }

    /* Length will be at least 1 byte for version, 1 byte for private key,
     * indicator, and 4 bytes for the length of each element */
    retLen = 2 + (numElements * sizeof(ubyte4));

    status = CRYPTO_getKeyDataAlloc (
      pKeyToUse, (void *)&keyTemplate, reqType);
    if (OK != status)
      goto exit;

    retLen += keyTemplate.eLen;
    retLen += keyTemplate.nLen;
    retLen += keyTemplate.pLen;
    retLen += keyTemplate.qLen;
    pIter = pBuffer;

    if (pBuffer)
    {
      if (*pRetLen >= retLen)
      {
        *pIter++ = 2;
        *pIter++ = (pKey->privateKey) ? 1 : 0;

        status = CRYPTO_INTERFACE_RSA_writeKeyBlobElement (
          &pIter, keyTemplate.pE, keyTemplate.eLen);
        if (OK != status)
          goto exit;

        status = CRYPTO_INTERFACE_RSA_writeKeyBlobElement (
          &pIter, keyTemplate.pN, keyTemplate.nLen);
        if (OK != status)
          goto exit;

        if (pKey->privateKey)
        {
          status = CRYPTO_INTERFACE_RSA_writeKeyBlobElement (
            &pIter, keyTemplate.pP, keyTemplate.pLen);
          if (OK != status)
            goto exit;

          status = CRYPTO_INTERFACE_RSA_writeKeyBlobElement (
            &pIter, keyTemplate.pQ, keyTemplate.qLen);
          if (OK != status)
            goto exit;
        }
      }
      else
      {
        status = ERR_BUFFER_OVERFLOW;
      }
    }
    *pRetLen = retLen;
  }
  else
  {
    MOC_RSA_BYTESTRING_FROM_KEY (
      status, pKey, pBuffer, pRetLen)
  }

exit:

  CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(NULL, &keyTemplate);

  return status;
}

/*----------------------------------------------------------------------------*/

typedef struct
{
  ubyte *pData;
  ubyte4 len;
} MRsaKeyFromByteStringHelper;

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_keyFromByteString (
  MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey **ppKey,
  const ubyte* pByteString,
  ubyte4 len,
  vlong** ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 i, numElements, partLen;
  ubyte4 algoStatus;
  ubyte *pIter = NULL;
  RSAKey *pNewKey = NULL;
  MRsaKeyFromByteStringHelper pTable[4] = {0};

  status = ERR_NULL_POINTER;
  if ( (NULL == ppKey) || (NULL == pByteString) )
    goto exit;

  /* Determine if we have an RSA implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
    moc_alg_rsa, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_BAD_KEY_BLOB;
    if (2 > len)
      goto exit;

    pIter = (ubyte *)pByteString;

    /* We support blob versions 1 and 2 */
    status = ERR_BAD_KEY_BLOB_VERSION;
    if (2 < *pIter++)
      goto exit;

    /* Keep track of the length so we dont try to read beyond the buffer */
    len--;

    /* Create a new RSA key shell */
    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pNewKey);
    if (OK != status)
      goto exit;

    pNewKey->privateKey = (*pIter++) ? TRUE : FALSE;
    len--;

    if (TRUE == pNewKey->privateKey)
    {
      numElements = 4;
    }
    else
    {
      numElements = 2;
    }

    /* The keyblob format is:
    * version || { length (4 bytes big-endian) || bytes } for each of
    * e, n, p, q, dP, dQ, qInv. We will only read e and n for public keys,
    * and only e, n, p and q for private keys. The last three elements are used
    * by the internal mocana implementation, however an arbitrary implementer may
    * not be expecting them. dP, dQ, and qInv are computable from e, n, p and q,
    * so we dont include them */
    for (i = 0; i < numElements; i++)
    {
      status = ERR_BAD_KEY_BLOB;
      if (sizeof(ubyte4) > len)
        goto exit;

      partLen = ( (ubyte4)pIter[0] << 24 ) +
                ( (ubyte4)pIter[1] << 16 ) +
                ( (ubyte4)pIter[2] << 8  ) +
                ( (ubyte4)pIter[3]);
      pIter += 4;
      len -=4;
      if (len < partLen)
        goto exit;

      pTable[i].pData = pIter;
      pTable[i].len = partLen;
      pIter += partLen;
      len -= partLen;
    }

    if (TRUE == pNewKey->privateKey)
    {
      status = CRYPTO_INTERFACE_RSA_setAllKeyDataAux (
        MOC_RSA (hwAccelCtx)
        pNewKey,
        pTable[0].pData, pTable[0].len,
        pTable[1].pData, pTable[1].len,
        pTable[2].pData, pTable[2].len,
        pTable[3].pData, pTable[3].len,
        ppVlongQueue);
      if (OK != status)
        goto exit;
    }
    else
    {
      status = CRYPTO_INTERFACE_RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)
        pNewKey,
        pTable[0].pData, pTable[0].len,
        pTable[1].pData, pTable[1].len,
        ppVlongQueue);
      if (OK != status)
        goto exit;
    }

    *ppKey = pNewKey;
    pNewKey = NULL;
  }
  else
  {
    MOC_RSA_KEY_FROM_BYTESTRING (
      status, ppKey, pByteString, len, ppVlongQueue)
  }

exit:

  if (NULL != pNewKey)
  {
    CRYPTO_INTERFACE_RSA_freeKeyAux(&pNewKey, ppVlongQueue);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate,
  ubyte keyType
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  MocAsymKey pKeyToUse = NULL;

  /* Determine if we have an RSA implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
    moc_alg_rsa, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pTemplate) )
      goto exit;

    /* Identify which MocAsymKey to retrieve from within pKey */
    if (MOC_GET_PRIVATE_KEY_DATA == keyType)
    {
      /* If the caller specified they want private key data, but there is no
       * private key, that's an error */
      if (NULL == pKey->pPrivateKey)
        goto exit;

      /* If the caller specified they want private key data, but this key's type
       * is not set to be private, that's an error */
      status = ERR_INVALID_ARG;
      if (FALSE == pKey->privateKey)
        goto exit;

      pKeyToUse = pKey->pPrivateKey;
    }
    else if (MOC_GET_PUBLIC_KEY_DATA == keyType)
    {
      /* If the caller requested public key data, and a public key exists, use
       * that. If not, try to use a private key instead */
      if (NULL != pKey->pPublicKey)
        pKeyToUse = pKey->pPublicKey;
      else if (NULL != pKey->pPrivateKey)
        pKeyToUse = pKey->pPrivateKey;
      else
        goto exit;
    }
    else
    {
      status = ERR_INVALID_ARG;
      goto exit;
    }

    status = CRYPTO_getKeyDataAlloc (pKeyToUse, (void *) pTemplate, keyType);
  }
  else
  {
    MOC_RSA_GET_KEY_PARAMS_ALLOC(status, pKey, pTemplate, keyType)
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyTemplateAux (
  RSAKey *pKey,
  MRsaKeyTemplate *pTemplate
  )
{
  MSTATUS status;

  /* Do we have anything to free? */
  status = OK;
  if (NULL == pTemplate)
    goto exit;

  /* If the caller provided a key, try to use the underlying operator to free
   * the template */
  if (NULL != pKey && CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* The caller provided a key and it is crypto interface enabled, have the
     * operator free this template */
    status = CRYPTO_freeKeyTemplate(pKey->pPublicKey, (void *)pTemplate);
  }
  else
  {
    MOC_RSA_FREE_KEY_TEMPLATE(status, pKey, pTemplate);
  }

  /* If the status is not OK, it is likely that the operator did not
   * implement that op code. Attempt to free it by hand now */
  if ( (OK != status) || (NULL == pKey) )
  {
    if (NULL != pTemplate->pE)
    {
      status = DIGI_MEMSET(pTemplate->pE, 0x00, pTemplate->eLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pE);
      if (OK != status)
        goto exit;

      pTemplate->eLen = 0;
    }

    if (NULL != pTemplate->pN)
    {
      status = DIGI_MEMSET(pTemplate->pN, 0x00, pTemplate->nLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pN);
      if (OK != status)
        goto exit;

      pTemplate->nLen = 0;
    }

    if (NULL != pTemplate->pP)
    {
      status = DIGI_MEMSET(pTemplate->pP, 0x00, pTemplate->pLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pP);
      if (OK != status)
        goto exit;

      pTemplate->pLen = 0;
    }

    if (NULL != pTemplate->pQ)
    {
      status = DIGI_MEMSET(pTemplate->pQ, 0x00, pTemplate->qLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pQ);
      if (OK != status)
        goto exit;

      pTemplate->qLen = 0;
    }

    if (NULL != pTemplate->pD)
    {
        status = DIGI_MEMSET(pTemplate->pD, 0x00, pTemplate->dLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pD);
        if (OK != status)
            goto exit;

        pTemplate->dLen = 0;
    }

    if (NULL != pTemplate->pDp)
    {
        status = DIGI_MEMSET(pTemplate->pDp, 0x00, pTemplate->dpLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pDp);
        if (OK != status)
            goto exit;

        pTemplate->dpLen = 0;
    }

    if (NULL != pTemplate->pDq)
    {
        status = DIGI_MEMSET(pTemplate->pDq, 0x00, pTemplate->dqLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pDq);
        if (OK != status)
            goto exit;

        pTemplate->dqLen = 0;
    }

    if (NULL != pTemplate->pQinv)
    {
        status = DIGI_MEMSET(pTemplate->pQinv, 0x00, pTemplate->qInvLen);
        if (OK != status)
            goto exit;

        status = DIGI_FREE ((void **) &pTemplate->pQinv);
        if (OK != status)
            goto exit;

        pTemplate->qInvLen = 0;
    }

    status = OK;
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_equalKey (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey1,
  const RSAKey *pKey2,
  byteBoolean *pRes
  )
{
  MSTATUS status;
  sbyte4 cmpResult = 0;
  MRsaKeyTemplate template1 = {0};
  MRsaKeyTemplate template2 = {0};

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey1) || (NULL == pKey2) || (NULL == pRes) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey1->enabled)
  {
    *pRes = FALSE;

    /* We will be comparing the public key values */
    status = ERR_NULL_POINTER;
    if ( (NULL ==  pKey1->pPublicKey) || (NULL == pKey2->pPublicKey) )
      goto exit;

    /* Get the public key data from key1 */
    status = CRYPTO_getKeyDataAlloc (
      pKey1->pPublicKey, (void *)&template1, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
      goto exit;

    /* Get the public key data from key2 */
    status = CRYPTO_getKeyDataAlloc (
      pKey2->pPublicKey, (void *)&template2, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
      goto exit;

    /* Do they have the same exponent length? */
    if (template1.eLen != template2.eLen)
      goto exit;

    /* Do the exponents match? */
    status = DIGI_MEMCMP (
      template1.pE, template2.pE, template1.eLen, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 != cmpResult)
      goto exit;

    /* Do they have the same modulus length? */
    if (template1.nLen != template2.nLen)
      goto exit;

    /* Does the modulus match? */
    status = DIGI_MEMCMP (
      template1.pN, template2.pN, template1.nLen, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 == cmpResult)
    {
      *pRes = TRUE;
    }
  }
  else
  {
    MOC_RSA_EQUAL_KEY(status, pKey1, pKey2, pRes);
  }

exit:

  CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(NULL, &template1);
  CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(NULL, &template2);

  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPublicKeyAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pInput,
  ubyte4 inputLen,
  ubyte **ppOutput,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  sbyte4 modulusLen = 0;
  ubyte4 outputLen = 0;
  ubyte *pOutput = NULL;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPublicKey || NULL == ppOutput)
      goto exit; /* status still ERR_NULL_POINTER */

    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pKey, &modulusLen);
    if (OK != status)
      goto exit;

    outputLen = (ubyte4)modulusLen;

    status = DIGI_CALLOC((void **)&pOutput, 1, outputLen);
    if (OK != status)
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_applyPublicKey (
        pKey->pPublicKey, (const ubyte *)pInput, inputLen,
        pOutput, ppVlongQueue);
    }
    else
    {
      status = CRYPTO_asymEncrypt (
        pKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD, NULL,
        RANDOM_rngFun, g_pRandomContext, pInput, inputLen, pOutput, outputLen,
        &outputLen, ppVlongQueue);
    }
    if (OK != status)
      goto exit;

    *ppOutput = pOutput;
    pOutput = NULL;
  }
  else
  {
    MOC_RSA_APPLY_PUB_KEY (
      status, pKey, pInput, inputLen, ppOutput, ppVlongQueue);
  }

exit:

  if (NULL != pOutput)
  {
    DIGI_FREE((void **)&pOutput);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPrivateKeyAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  RNGFun rngFun,
  void *rngFunArg,
  ubyte *pInput,
  ubyte4 inputLen,
  ubyte **ppOutput,
  vlong **ppVlongQueue
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  sbyte4 modulusLen = 0;
  ubyte4 outputLen = 0;
  ubyte *pOutput = NULL;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pKey->pPrivateKey || NULL == ppOutput)
      goto exit; /* status still ERR_NULL_POINTER */

    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pKey, &modulusLen);
    if (OK != status)
      goto exit;

    outputLen = (ubyte4)modulusLen;

    status = DIGI_CALLOC((void **)&pOutput, 1, outputLen);
    if (OK != status)
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_applyPrivateKey (
        pKey->pPrivateKey, rngFun, rngFunArg, (const ubyte *)pInput,
        inputLen, pOutput, &outputLen, ppVlongQueue);
    }
    else
    {
      status = CRYPTO_asymDecrypt (
        pKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD, NULL,
        RANDOM_rngFun, g_pRandomContext, pInput, inputLen, pOutput, outputLen,
        &outputLen, ppVlongQueue);
    }
    if (OK != status)
      goto exit;

    *ppOutput = pOutput;
    pOutput = NULL;
  }
  else
  {
    MOC_RSA_APPLY_PRI_KEY (
      status, rngFun, rngFunArg, pKey, pInput, inputLen, ppOutput,
      ppVlongQueue);
  }

exit:

  if (NULL != pOutput)
  {
    DIGI_FREE((void **)&pOutput);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_verifyDigest(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pMsgDigest,
  ubyte4 digestLen,
  ubyte* pSignature,
  ubyte4 sigLen,
  intBoolean *pIsValid,
  vlong **ppVlongQueue)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 vStatus = 1;

  if (NULL == pKey || NULL == pIsValid)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* set to false just in case we error */
    *pIsValid = FALSE;

    if (NULL == pKey->pPublicKey)
      goto exit;  /* status still ERR_NULL_POINTER */

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_RSA_verifyDigestInfo (
        pKey->pPublicKey, pSignature, pMsgDigest, digestLen, ppVlongQueue);
      if (OK == status)
      {
        *pIsValid = TRUE;
      }
      else if (ERR_TAP_SIGN_VERIFY_FAIL == status)
      {
        /* *pIsValid is already FALSE */
        status = OK;
      }
      else
      {
        goto exit;
      }
    }
    else
    {
      status = CRYPTO_asymVerifyDigest(pKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD, NULL, NULL, NULL, pMsgDigest,
                                        digestLen, pSignature, sigLen, &vStatus, ppVlongQueue);
      if (OK != status)
        goto exit;
    
      if (vStatus)
      {
        *pIsValid = FALSE;
      }
      else
      {
        *pIsValid = TRUE;
      }
    }
  }
  else
  {
    MOC_RSA_VERIFY_DIGEST(status, pKey, pMsgDigest, digestLen, pSignature, sigLen, pIsValid, ppVlongQueue);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_pkcs15Pad(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 operation,
  RNGFun rngFun,
  void *pRngFunArg,
  ubyte *pM,
  ubyte4 mLen,
  ubyte **ppRetPaddedMsg,
  ubyte4 *pRetPaddedMsgLen
  )
{
  MSTATUS status;
  ubyte *pPaddedMsg = NULL;
  ubyte4 keyLen;

  if ( (NULL == pKey) || (NULL == pM) ||
       (NULL == ppRetPaddedMsg) || (NULL == pRetPaddedMsgLen) )
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppRetPaddedMsg = NULL;
  *pRetPaddedMsgLen = 0;

  status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(
    MOC_RSA(hwAccelCtx) pKey, (sbyte4 *) &keyLen);
  if (OK != status)
    goto exit;

  status = DIGI_MALLOC((void **) &pPaddedMsg, keyLen);
  if (OK != status)
    goto exit;

  status = RsaPadPkcs15(
    pM, mLen, operation, rngFun, pRngFunArg, pPaddedMsg, keyLen);
  if (OK != status)
    goto exit;

  *ppRetPaddedMsg = pPaddedMsg;
  *pRetPaddedMsgLen = keyLen;
  pPaddedMsg = NULL;

exit:

  if (NULL != pPaddedMsg)
  {
    DIGI_MEMSET_FREE(&pPaddedMsg, keyLen);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyBitLen(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 *pBitLen
)
{
  MSTATUS status = ERR_NULL_POINTER;
  MRsaKeyTemplate template = {0};
  ubyte4 i = 0;

  if (NULL == pBitLen)
    goto exit;

  *pBitLen = 0;

  status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) pKey, &template, MOC_GET_PUBLIC_KEY_DATA);
  if (OK != status)
    goto exit;

  while(i < template.nLen && 0 == template.pN[i])
  {
    i++;
  }

  if (i == template.nLen) /* all zeros */
    goto exit;

  *pBitLen = (8*(template.nLen - i - 1) + DIGI_BITLENGTH((ubyte4) template.pN[i]));

exit:

  (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pKey, &template);

  return status;
}
#endif /* if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) */
