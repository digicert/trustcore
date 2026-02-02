/*
 * crypto_interface_ecc.c
 *
 * Cryptographic Interface specification for ECC.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_INTERNAL__

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../common/base64.h"
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"
#include "../crypto/mocasymkeys/mocsw/commonecc.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_ecc_tap_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_NEWKEY_EX(_status, _curveId, _ppNewKey)                        \
  _status = EC_newKeyEx(_curveId, _ppNewKey);                                 \
  if (OK == _status)                                                          \
  {                                                                           \
    (*_ppNewKey)->pPrivateKey = NULL;                                         \
    (*_ppNewKey)->pPublicKey = NULL;                                          \
    (*_ppNewKey)->curveIndex = 0;                                             \
    (*_ppNewKey)->enabled = 0;                                                \
  }
#else
#define MOC_EC_NEWKEY_EX(_status, _curveId, _ppNewKey)                        \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_IS_PRIVATE(_status, _pKey, _pResult)                           \
    _status = EC_isKeyPrivate(_pKey, _pResult)
#else
#define MOC_EC_IS_PRIVATE(_status, _pKey, _pResult)                           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_DELETE_KEY(_status,_ppKey)                                     \
  _status = EC_deleteKeyEx(_ppKey)
#else
#define MOC_EC_DELETE_KEY(_status,_ppKey)                                     \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_GET_ELEMENT_BYTE_STRING_LEN(_status, _pKey, _pLen)             \
  _status = EC_getElementByteStringLen (_pKey, _pLen)
#else
#define MOC_EC_GET_ELEMENT_BYTE_STRING_LEN(_status, _pKey, _pLen)             \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_GET_CURVEID_FROM_KEY(_status, _pKey, _pLen)                    \
  _status = EC_getCurveIdFromKey(_pKey, _pLen)
#else
#define MOC_EC_GET_CURVEID_FROM_KEY(_status, _pKey, _pLen)                    \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_GET_POINT_BYTESTRING_CURVEID(_status, _curveId, _pLen)         \
  _status = EC_getPointByteStringLenByCurveId(_curveId, _pLen)
#else
#define MOC_EC_GET_POINT_BYTESTRING_CURVEID(_status, _curveId, _pLen)         \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_GET_POINT_BYTESTRING_EX(_status, _pKey, _pLen)                 \
  _status = EC_getPointByteStringLenEx(_pKey, _pLen)
#else
#define MOC_EC_GET_POINT_BYTESTRING_EX(_status, _pKey, _pLen)                 \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_GET_KEYPARAM_ALLOC(_status, _pKey, _pTemplate, _keyType)          \
  _status = EC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) _pKey, _pTemplate, _keyType)
#else
#define MOC_GET_KEYPARAM_ALLOC(_status, _pKey, _pTemplate, _keyType)          \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_FREE_KEY_TEMPLATE(_status, _pKey, _pTemplate)                  \
  _status = EC_freeKeyTemplate(_pKey, _pTemplate)
#else
#define MOC_EC_FREE_KEY_TEMPLATE(_status, _pKey, _pTemplate)                  \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_SET_KEY_PARAMETERS(_status, _pKey, _point, _pointLen, _scalar, \
                                  _scalarLen)                                 \
  _status = EC_setKeyParametersEx(MOC_ECC(hwAccelCtx) _pKey, _point, _pointLen, _scalar, _scalarLen)
#else
#define MOC_EC_SET_KEY_PARAMETERS(_status, _pKey, _point, _pointLen, _scalar, \
                                  _scalarLen)                                 \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_SET_PRI_KEY(_status, _pKey, _scalar, _scalarLen)               \
  _status = EC_setPrivateKeyEx(MOC_ECC(hwAccelCtx) _pKey, _scalar, _scalarLen)
#else
#define MOC_EC_SET_PRI_KEY(_status, _pKey, _scalar, _scalarLen)               \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER(_status, _pKey, _pBuffer, _bufferSize) \
  _status = EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) _pKey, _pBuffer, _bufferSize)
#else
#define MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER(_status, _pKey, _pBuffer, _bufferSize) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER_ALLOC(_status, _pKey, _pBuffer, _bufferSize) \
  _status = EC_writePublicKeyToBufferAlloc(MOC_ECC(hwAccelCtx) _pKey, _pBuffer, _bufferSize)
#else
#define MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER_ALLOC(_status, _pKey, _pBuffer, _bufferSize) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_GENERATE_KEYPAIR_EX(_status, _pKey, _rngFun, _pRngFunArg)         \
  _status = EC_generateKeyPairEx(MOC_ECC(hwAccelCtx) _pKey, _rngFun, _pRngFunArg)
#else
#define MOC_GENERATE_KEYPAIR_EX(_status, _pKey, _rngFun, _pRngFunArg)         \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_ECDSA_SIGN_DIGEST(_status, _pKey, _rngFun, _rngArg, _pHash,       \
                              _hashLen, _pSignature, _bufferSize,             \
                              _pSignatureLen)                                 \
  _status = ECDSA_signDigest(MOC_ECC(hwAccelCtx) _pKey, _rngFun, _rngArg, _pHash, _hashLen, \
                             _pSignature, _bufferSize, _pSignatureLen)
#else
#define MOC_ECDSA_SIGN_DIGEST(_status, _pKey, _rngFun, _rngArg, _pHash,       \
                              _hashLen, _pSignature, _bufferSize,             \
                              _pSignatureLen)                                 \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_ECDSA_VERIFY_SIGNATURE_DIGEST(_status, _pPubKey, _pHash, _hashLen,  \
                                       _pR, _rLen, _pS, _sLen, _pVerifyFailure) \
  _status = ECDSA_verifySignatureDigest (MOC_ECC(hwAccelCtx)                    \
    _pPubKey, _pHash, _hashLen,  _pR, _rLen, _pS, _sLen, _pVerifyFailure)
#else
#define MOC_ECDSA_VERIFY_SIGNATURE_DIGEST(_status, _pPubKey, _pHash, _hashLen,  \
                                       _pR, _rLen, _pS, _sLen, _pVerifyFailure) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_ECDH_GENERATE_SHARED_SECRET_FROM_KEYS(_status, _pPrivateKey,      \
                      _pPublicKey, _ppSharedSecret, _pSharedSecretLen,        \
                      _flag, _pKdfInfo)                                       \
  _status = ECDH_generateSharedSecretFromKeys(MOC_ECC(hwAccelCtx) _pPrivateKey, _pPublicKey, \
                      _ppSharedSecret, _pSharedSecretLen, _flag, _pKdfInfo)
#else
#define MOC_ECDH_GENERATE_SHARED_SECRET_FROM_KEYS(_status, _pPrivateKey,      \
                      _pPublicKey, _ppSharedSecret, _pSharedSecretLen,        \
                      _flag, _pKdfInfo)                                       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_CLONE_KEY(_status, _ppNew, _pSrc)                              \
  _status = EC_cloneKeyEx(MOC_ECC(hwAccelCtx) _ppNew, _pSrc);                                     \
  if (OK == _status)                                                          \
  {                                                                           \
    (*_ppNew)->pPrivateKey = NULL;                                            \
    (*_ppNew)->pPublicKey = NULL;                                             \
    (*_ppNew)->curveIndex = 0;                                                \
    (*_ppNew)->enabled = 0;                                                   \
  }
#else
#define MOC_EC_CLONE_KEY(_status, _ppNew, _pSrc)                              \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_EQUAL_KEY(_status, _pKey1, _pKey2, _res)                       \
  _status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) _pKey1, _pKey2, _res)
#else
#define MOC_EC_EQUAL_KEY(_status, _pKey1, _pKey2, _res)                       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_VERIFY_PUB_KEY(_status, _pKey, _pValid)                        \
  _status = EC_verifyPublicKeyEx(MOC_ECC(hwAccelCtx) _pKey, _pValid);
#else
#define MOC_EC_VERIFY_PUB_KEY(_status, _pKey, _pValid)                        \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_PUB_PRI_MATCH(_status, _pPri, _pPub, _pVfy)                    \
  _status = EC_verifyKeyPairEx(MOC_ECC(hwAccelCtx) _pPri, _pPub, _pVfy);
#else
#define MOC_EC_PUB_PRI_MATCH(_status, _pPri, _pPub, _pVfy)                    \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_SIGN_MSG(_status, _pPri, _rngFun, _pRngArg, _hashAlgo, _pMsg,  \
                        _msgLen, _pSig, _bufSize, _pSigLen, _pExtCtx)         \
  _status = ECDSA_signMessage(MOC_ECC(hwAccelCtx) _pPri, _rngFun, _pRngArg, _hashAlgo, _pMsg,     \
                              _msgLen, _pSig, _bufSize, _pSigLen, _pExtCtx)
#else
#define MOC_EC_SIGN_MSG(_status, _pPri, _rngFun, _pRngArg, _hashAlgo, _pMsg,  \
                        _msgLen, _pSig, _bufSize, _pSigLen, _pExtCtx)         \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_VERIFY_MSG(_status, _pPub, _hashAlgo, _pMsg, _msgLen,          \
                          _pSig, _sigLen, _pVerifyFailures, _pExtCtx)         \
  _status = ECDSA_verifyMessage(MOC_ECC(hwAccelCtx) _pPub, _hashAlgo, _pMsg, _msgLen,             \
                          _pSig, _sigLen, _pVerifyFailures, _pExtCtx)
#else
#define MOC_EC_VERIFY_MSG(_status, _pPub, _hashAlgo, _pMsg, _msgLen,          \
                          _pSig, _sigLen, _pVerifyFailures, _pExtCtx)         \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_INIT_VERIFY(_status, _pCtx, _pPub, _hashAlgo, _pSig, _sigLen, _pExtCtx)  \
  _status = ECDSA_initVerify(MOC_ECC(hwAccelCtx) _pCtx, _pPub, _hashAlgo, _pSig, _sigLen, _pExtCtx)
#else
#define MOC_EC_INIT_VERIFY(_status, _pCtx, _pPub, _hashAlgo, _pSig, _sigLen, _pExtCtx)  \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_UPDATE_VERIFY(_status, _pCtx, _pMsg, _msgLen, _pExtCtx)        \
  _status = ECDSA_updateVerify(MOC_ECC(hwAccelCtx) _pCtx, _pMsg, _msgLen, _pExtCtx)
#else
#define MOC_EC_UPDATE_VERIFY(_status, _pCtx, _pMsg, _msgLen, _pExtCtx)        \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_FINAL_VERIFY(_status, _pCtx, _pVerifyFailures, _pExtCtx)       \
  _status = ECDSA_finalVerify(MOC_ECC(hwAccelCtx) _pCtx, _pVerifyFailures, _pExtCtx)
#else
#define MOC_EC_FINAL_VERIFY(_status, _pCtx, _pVerifyFailures, _pExtCtx)       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_ED_SIGN(_status, _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx) \
  _status = EdDSA_signInput(MOC_ECC(hwAccelCtx) _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx)
#else
#define MOC_EC_ED_SIGN(_status, _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__ENABLE_DIGICERT_FIPS_700_BINARY_SUPPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_ED_VERIFY(_status, _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _signatureLen, _pVerifyFailures, _pExtCtx) \
  _status = EdDSA_verifyInput(MOC_ECC(hwAccelCtx) _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _signatureLen, _pVerifyFailures, _pExtCtx)
#else
#define MOC_EC_ED_VERIFY(_status, _pKey, _pInput, _inputLen, _isPreHash, _pCtx, _ctxLen, _pSignature, _signatureLen, _pVerifyFailures, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_CREATE_COMB_MUTEX(_status)                                     \
  _status = EC_createCombMutexes()
#else
#define MOC_EC_CREATE_COMB_MUTEX(_status)                                     \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__))
#define MOC_EC_DELETE_COMB_MUTEX(_status)                                     \
  _status = EC_deleteAllCombsAndMutexes()
#else
#define MOC_EC_DELETE_COMB_MUTEX(_status)                                     \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECDH_MODES__))
#define MOC_ECDH_KEY_AGREE(_status, _mode, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen); \
    _status = ECDH_keyAgreementScheme(MOC_ECC(hwAccelCtx) _mode, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen)
#else
#define MOC_ECDH_KEY_AGREE(_status, _mode, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen); \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_curveIdToCurveIndex (
  ubyte4 curveId,
  ubyte4 *pCurveIndex
  )
{
  if (NULL == pCurveIndex)
    return ERR_NULL_POINTER;

  switch(curveId)
  {
    case cid_EC_P192:
      *pCurveIndex = moc_alg_ecc_p192;
      break;

    case cid_EC_P224:
      *pCurveIndex = moc_alg_ecc_p224;
      break;

    case cid_EC_P256:
      *pCurveIndex = moc_alg_ecc_p256;
      break;

    case cid_EC_P384:
      *pCurveIndex = moc_alg_ecc_p384;
      break;

    case cid_EC_P521:
      *pCurveIndex = moc_alg_ecc_p521;
      break;

    case cid_EC_X25519:
      *pCurveIndex = moc_alg_ecc_x25519;
      break;

    case cid_EC_X448:
      *pCurveIndex = moc_alg_ecc_x448;
      break;

    case cid_EC_Ed25519:
      *pCurveIndex = moc_alg_ecc_ed25519;
      break;

    case cid_EC_Ed448:
      *pCurveIndex = moc_alg_ecc_ed448;
      break;

    default:
      return ERR_EC_UNSUPPORTED_CURVE;
  }

  return OK;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_loadKeys (
  ECCKey **ppNewKey,
  MocAsymKey *ppPriKey,
  MocAsymKey *ppPubKey
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocCtx pMocCtx = NULL;
  ECCKey *pNewKey = NULL;
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

  status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(ECCKey));
  if (OK != status)
    goto exit;

  if (NULL != pPriKey)
  {
    pPriKeyToUse = pPriKey;
    if (NULL != pPubKey)
    {
      pPubKeyToUse = pPubKey;
    }
    else
    {
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

      /* Determine the index at which the ECC TAP operator lives */
      status = CRYPTO_INTERFACE_checkTapAsymAlgoStatus (
        moc_alg_ecc_p256, &algoStatus, &index);
      if (OK != status)
        goto exit;
    }
    else
    {
      /* We need to create a shell for the underlying private MocAsymKey */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* Determine the index at which the ECC operator lives */
      status = CRYPTO_INTERFACE_checkAsymAlgoStatus (
        moc_alg_ecc_p256, &algoStatus, &index);
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
    
  /*
   Do not free pPriKeyToUse or pPubKeyToUse.
   Either they were existing keys allocated elsewhere,
   or only one was allocated as the last step of the
   above procedure. Any error case will happen before
   or during the allocation.
   */
    
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_loadKey (
  ECCKey **ppNewKey,
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

  status = CRYPTO_INTERFACE_EC_loadKeys(ppNewKey, &pPriKey, &pPubKey);
  if (OK != status)
  {
    goto exit;
  }

  *ppKey = NULL;

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newKeyAux (
  ubyte4 curveId,
  ECCKey** ppNewKey
  )
{
  MSTATUS status;
  ubyte4 curveIndex, operatorIndex;
  ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
  MocCtx pMocCtx = NULL;
  ECCKey *pNewKey = NULL;
  MocAsymKey pNewPriKey = NULL;
  MocAsymKey pNewPubKey = NULL;

  /* First we need to convert the curve id to an algorithm index */
  status = CRYPTO_INTERFACE_curveIdToCurveIndex(curveId, &curveIndex);
  if (OK != status)
    goto exit;

  /* Determine if we have an alternate implementation for this curve */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus(
    curveIndex, &algoStatus, &operatorIndex);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_NULL_POINTER;
    if (NULL == ppNewKey)
      goto exit;

    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Create an empty ECC private key from the corresponding operator in
     * the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      operatorIndex, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PRIVATE, &pNewPriKey);
    if (OK != status)
      goto exit;

    /* Create an empty ECC public key from the corresponding operator in
     * the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      operatorIndex, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPubKey);
    if (OK != status)
      goto exit;

    /* Allocate the ECCKey */
    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(ECCKey));
    if (OK != status)
      goto exit;

    /* Set the newly created keys inside the ECCKey */
    pNewKey->pPrivateKey = pNewPriKey;
    pNewPriKey = NULL;
    pNewKey->pPublicKey = pNewPubKey;
    pNewPubKey = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    /* Set the curve index inside the key as well, we will need this later when
     * we check for an alternate implementation with the crypto interface core */
    pNewKey->curveIndex = curveIndex;

    /* Set the callers pointer */
    *ppNewKey = pNewKey;
    pNewKey = NULL;
  }
  else
  {
    MOC_EC_NEWKEY_EX(status, curveId, ppNewKey);
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

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_isKeyPrivate (
  ECCKey *pKey,
  intBoolean *pResult
  )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if ( NULL == pKey || NULL == pResult)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        /* top level privateKey flag is still used */
        *pResult = pKey->privateKey;
        status = OK;
    }
    else
    {
        MOC_EC_IS_PRIVATE(status, pKey, pResult);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_deleteKeyAux (
  ECCKey **ppKey
  )
{
  MSTATUS status;
  ECCKey *pKey = NULL;

  /* Do we have anything to free? */
  status = ERR_NULL_POINTER;
  if ( (NULL == ppKey) || (NULL == *ppKey) )
    goto exit;

  pKey = *ppKey;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = CRYPTO_INTERFACE_freeAsymKeys (
      (void **)ppKey, pKey->pPublicKey, pKey->pPrivateKey);
  }
  else
  {
    MOC_EC_DELETE_KEY(status, ppKey);
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getElementByteStringLenAux (
  ECCKey *pKey,
  ubyte4 *pLen
  )
{
  MSTATUS status;
  ubyte4 elementLen;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pLen) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* If this is a TAP key, handle it separately */
    if (NULL != pKey->pPrivateKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen (
        pKey->pPrivateKey, (ubyte4 *) pLen);
    }
    else if (NULL != pKey->pPublicKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen (
        pKey->pPublicKey, (ubyte4 *) pLen);     
    }
    else
    {
      /* We stored the curve index in the ECC shell during key creation, use that
      * value to determine the underlying element size */
      status = ERR_BAD_KEY;
      switch(pKey->curveIndex)
      {
        case moc_alg_ecc_p192:
          elementLen = 24;
          break;

        case moc_alg_ecc_p224:
          elementLen = 28;
          break;

        case moc_alg_ecc_p256:
          elementLen = 32;
          break;

        case moc_alg_ecc_p384:
          elementLen = 48;
          break;

        case moc_alg_ecc_p521:
          elementLen = 66;
          break;

        default:
          goto exit;
      }

      status = OK;
      *pLen = elementLen;
    }
  }
  else
  {
    MOC_EC_GET_ELEMENT_BYTE_STRING_LEN(status, pKey, (ubyte4*)pLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux (
  ECCKey *pKey,
  ubyte4 *pCurveId
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pCurveId)
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (NULL != pKey->pPrivateKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_getCurveIdFromKey (
        pKey->pPrivateKey, pCurveId);
    }
    else if (NULL != pKey->pPublicKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_getCurveIdFromKey (
        pKey->pPublicKey, pCurveId);
    }
    else
    {
      /* We stored the curve index in the ECC shell during key creation, use that
      * value to determine the curve id */
      status = ERR_BAD_KEY;
      switch(pKey->curveIndex)
      {
        case moc_alg_ecc_p192:
          *pCurveId = cid_EC_P192;
          break;

        case moc_alg_ecc_p224:
          *pCurveId = cid_EC_P224;
          break;

        case moc_alg_ecc_p256:
          *pCurveId = cid_EC_P256;
          break;

        case moc_alg_ecc_p384:
          *pCurveId = cid_EC_P384;
          break;

        case moc_alg_ecc_p521:
          *pCurveId = cid_EC_P521;
          break;

        case moc_alg_ecc_x25519:
          *pCurveId = cid_EC_X25519;
          break;

        case moc_alg_ecc_x448:
          *pCurveId = cid_EC_X448;
          break;

        case moc_alg_ecc_ed25519:
          *pCurveId = cid_EC_Ed25519;
          break;

        case moc_alg_ecc_ed448:
          *pCurveId = cid_EC_Ed448;
          break;

        default:
          goto exit;
      }

      status = OK;
    }
  }
  else
  {
    MOC_EC_GET_CURVEID_FROM_KEY(status, pKey, pCurveId);
  }

exit:
  return status;

}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId (
  ubyte4 curveId,
  ubyte4 *pLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
  if (NULL == pLen)
    return status;

  status = ERR_INVALID_ARG;
  switch (curveId)
  {
#ifdef __ENABLE_DIGICERT_ECC_P192__
    case cid_EC_P192:
      *pLen = 49;
      status = OK;
      break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    case cid_EC_P224:
      *pLen = 57;
      status = OK;
      break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    case cid_EC_P256:
      *pLen = 65;
      status = OK;
      break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    case cid_EC_P384:
      *pLen = 97;
      status = OK;
      break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    case cid_EC_P521:
      *pLen = 133;
      status = OK;
      break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    case cid_EC_X25519:
      *pLen = 32;
      status = OK;
      break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    case cid_EC_Ed25519:
      *pLen = 32;
      status = OK;
      break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    case cid_EC_X448:
      *pLen = 56;
      status = OK;
      break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    case cid_EC_Ed448:
      *pLen = 57;
      status = OK;
      break;
#endif
  };

#else
  MOC_EC_GET_POINT_BYTESTRING_CURVEID(status, curveId, pLen);
#endif
  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenAux (
  ECCKey *pKey,
  ubyte4 *pLen
  )
{
  MSTATUS status;
  ubyte4 elementLen;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pLen) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pKey, &elementLen);
    if (OK != status)
      goto exit;

    *pLen = 1 + (2 *elementLen);
  }
  else
  {
    MOC_EC_GET_POINT_BYTESTRING_EX(status, pKey, pLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getKeyParametersAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  MEccKeyTemplate *pTemplate,
  ubyte keyType
  )
{
  MSTATUS status;
  MocAsymKey pKeyToUse = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pTemplate) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* If this is a private key, use the private portion */
    if (FALSE != pKey->privateKey)
    {
      pKeyToUse = pKey->pPrivateKey;
    }
    else
    {
      /* This must be a public key, ensure the internal public portion is valid */
      if (NULL == pKey->pPublicKey)
        goto exit;

      /* If this request is for private key data, we cannot fulfill it */
      status = ERR_KEY_IS_NOT_PRIVATE;
      if (MOC_GET_PRIVATE_KEY_DATA == keyType)
        goto exit;

      pKeyToUse = pKey->pPublicKey;
    }

    status = CRYPTO_getKeyDataAlloc(pKeyToUse, (void *)pTemplate, keyType);
    if (OK != status)
      goto exit;
  }
  else
  {
    MOC_GET_KEYPARAM_ALLOC(status, pKey, pTemplate, keyType);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_freeKeyTemplateAux (
  ECCKey *pKey,
  MEccKeyTemplate *pTemplate
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
    MOC_EC_FREE_KEY_TEMPLATE(status, pKey, pTemplate);
  }

  /* If the status is not OK, attempt to free it by hand now */
  if ( (OK != status) || (NULL == pKey) )
  {
    if (NULL != pTemplate->pPrivateKey)
    {
      status = DIGI_MEMSET(pTemplate->pPrivateKey, 0x00, pTemplate->privateKeyLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pPrivateKey);
      if (OK != status)
        goto exit;

      pTemplate->privateKeyLen = 0;
    }

    if (NULL != pTemplate->pPublicKey)
    {
      status = DIGI_MEMSET(pTemplate->pPublicKey, 0x00, pTemplate->publicKeyLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pPublicKey);
      if (OK != status)
        goto exit;

      pTemplate->publicKeyLen = 0;
    }

    status = OK;
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_setKeyParametersAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pPoint,
  ubyte4 pointLen,
  ubyte *pScalar,
  ubyte4 scalarLen
  )
{
  MSTATUS status;
  MEccKeyTemplate keyTemplate = {0};
  MocAsymKey pKeyToUse = NULL;
  ubyte private = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pPoint && NULL == pScalar) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* If we have a private scalar, set the data into the private key */
    if (NULL != pScalar)
    {
      /* We must have an internal private key */
      if (NULL == pKey->pPrivateKey)
        goto exit;

      pKeyToUse = pKey->pPrivateKey;
      private = 1;
    }
    else
    {
      /* We are not setting any private key data so use the public key instead.
       * Ensure we have a valid internal public key */
      if (NULL == pKey->pPublicKey)
        goto exit;

      pKeyToUse = pKey->pPublicKey;
    }

    /* Set up the key template */
    keyTemplate.pPrivateKey = (ubyte *)pScalar;
    keyTemplate.privateKeyLen = scalarLen;
    keyTemplate.pPublicKey = (ubyte *)pPoint;
    keyTemplate.publicKeyLen = pointLen;

    /* Set the data into the operator */
    status = CRYPTO_setKeyData(pKeyToUse, (void *)&keyTemplate);
    if (OK != status)
      goto exit;

    /* If the operation was a success and we were setting private key data,
     * mark this key as private and derive a new public key from it */
    if (1 == private)
    {
      /* First destroy any previously allocated key */
      if (NULL != pKey->pPublicKey)
      {
        status = CRYPTO_freeMocAsymKey(&(pKey->pPublicKey), NULL);
        if (OK != status)
          goto exit;
      }

      /* Get a new pulbic key from the private key we just set */
      status = CRYPTO_getPubFromPri (
        pKey->pPrivateKey, &(pKey->pPublicKey), NULL);
      if (OK != status)
        goto exit;

      /* Mark this key as private */
      pKey->privateKey = 1;
    }
    else
    {
      pKey->privateKey = 0;
    }
  }
  else
  {
    MOC_EC_SET_KEY_PARAMETERS(status, pKey, pPoint, pointLen, pScalar, scalarLen);
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_setPrivateKey (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pScalar,
  ubyte4 scalarLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MEccKeyTemplate keyTemplate = {0};

  if (NULL == pKey || NULL == pScalar )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* We must have an internal private key */
    if (NULL == pKey->pPrivateKey)
      goto exit; /* status still ERR_NULL_POINTER */

    /* Set up the key template */
    keyTemplate.pPrivateKey = (ubyte *)pScalar;
    keyTemplate.privateKeyLen = scalarLen;

    /* Set the data into the operator */
    status = CRYPTO_setKeyData(pKey->pPrivateKey, (void *)&keyTemplate);
    if (OK != status)
      goto exit;

    /*  destroy any previously allocated public key */
    if (NULL != pKey->pPublicKey)
    {
      status = CRYPTO_freeMocAsymKey(&(pKey->pPublicKey), NULL);
      if (OK != status)
        goto exit;
    }

    /* Mark this key as private */
    pKey->privateKey = 1;

  }
  else
  {
    MOC_EC_SET_PRI_KEY(status, pKey, pScalar, scalarLen);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte *pBuffer,
  ubyte4 bufferSize
  )
{
  MSTATUS status, fStatus;
  ubyte4 pubKeyLen;
  MEccKeyTemplate keyTemplate = {0};

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pBuffer) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* We need a public key for this operation */
    if (NULL == pKey->pPublicKey)
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_writePublicKeyToBuffer (
        pKey->pPublicKey, pBuffer, bufferSize);
    }
    else
    {
      /* Get the size of the public key encoding */
      status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pKey, &pubKeyLen);
      if (OK != status)
        goto exit;

      /* Is the buffer large enough? */
      status = ERR_BUFFER_TOO_SMALL;
      if (bufferSize < pubKeyLen)
        goto exit;

      /* Get the public key data from the operator */
      status = CRYPTO_getKeyDataAlloc (
        pKey->pPublicKey, (void *)&keyTemplate, MOC_GET_PUBLIC_KEY_DATA);
      if (OK != status)
        goto exit;

      /* Ensure the length is correct */
      status = ERR_INTERNAL_ERROR;
      if (keyTemplate.publicKeyLen != pubKeyLen)
        goto exit;

      /* Copy the public key data to the provided buffer */
      status = DIGI_MEMCPY(pBuffer, keyTemplate.pPublicKey, pubKeyLen);
    }
  }
  else
  {
    MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER(status, pKey, pBuffer, bufferSize);
  }

exit:

  if (NULL != keyTemplate.pPublicKey)
  {
    fStatus = shredMemory(&(keyTemplate.pPublicKey), keyTemplate.publicKeyLen, 1);
    if (OK == status)
      status = fStatus;
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  ubyte **ppBuffer,
  ubyte4 *pBufferSize
)
{
    MSTATUS status;
    ubyte *pKeyBuffer = NULL;
    ubyte4 pubKeyLen = 0;

    status = ERR_NULL_POINTER;
    if ( NULL == pKey )
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        if (NULL == ppBuffer || NULL == pBufferSize)
            goto exit;

        /* Get the size of the public key encoding */
        status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pKey, &pubKeyLen);
        if (OK != status)
            goto exit;

        /* allocate a buffer for the point byte string */
        status = DIGI_MALLOC((void **) &pKeyBuffer, pubKeyLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx) pKey, pKeyBuffer, pubKeyLen);
        if (OK != status)
            goto exit;

        *ppBuffer = pKeyBuffer;
        *pBufferSize = pubKeyLen;
        pKeyBuffer = NULL;
    }
    else
    {
        MOC_EC_WRITE_PUBLIC_KEY_TO_BUFFER_ALLOC(status, pKey, ppBuffer, pBufferSize);
    }

exit:

    if (NULL != pKeyBuffer)
    {
        DIGI_FREE((void **) &pKeyBuffer);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 curveId,
  ECCKey **ppNewKey,
  ubyte *pByteString,
  ubyte4 byteStringLen
  )
{
  MSTATUS status;
  ECCKey *pNewKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppNewKey) || (NULL == pByteString) )
    goto exit;

  status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pNewKey);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_EC_setKeyParametersAux (MOC_ECC(hwAccelCtx)
    pNewKey, pByteString, byteStringLen, NULL, 0);
  if (OK != status)
    goto exit;

  *ppNewKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
  }

  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_generateKeyPairAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  RNGFun rngFun,
  void *pRngFunArg
  )
{
  MSTATUS status;
  MKeyOperator KeyOperator;
  ubyte4 operatorIndex;
  MocCtx pMocCtx = NULL;
  void *pOperatorInfo = NULL;
  ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* Get the operator index */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(
      pKey->curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
      goto exit;

    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Get the operator for this curve found during the initial check */
    status = CRYPTO_getAsymOperatorAndInfoFromIndex (
      operatorIndex, pMocCtx, &KeyOperator, &pOperatorInfo);
    if (OK != status)
      goto exit;

    /* Generate the ECC keypair, this will destory the two empty keys made
     * during CRYPTO_INTERFACE_EC_newKeyEx */
    status = CRYPTO_generateKeyPair (
      KeyOperator, pOperatorInfo, pMocCtx, rngFun, pRngFunArg,
      &(pKey->pPublicKey), &(pKey->pPrivateKey), NULL);
    if (OK != status)
      goto exit;

    /* Mark this key as private */
    pKey->privateKey = 1;
  }
  else
  {
    MOC_GENERATE_KEYPAIR_EX(status, pKey, rngFun, pRngFunArg);
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_generateKeyPairAllocAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 curveId,
  ECCKey **ppKey,
  RNGFun rngFun,
  void *pRngFunArg
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ECCKey *pNewKey = NULL;

  if (NULL == ppKey)
      goto exit;

  status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pNewKey);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_EC_generateKeyPairAux (MOC_ECC(hwAccelCtx)
    pNewKey, rngFun, pRngFunArg);
  if (OK != status)
    goto exit;

  *ppKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signDigestAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  RNGFun rngFun,
  void *rngArg,
  ubyte *pHash,
  ubyte4 hashLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* We must have a private key to sign with */
    if ( NULL == pKey->pPrivateKey )
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_ECDSA_sign (
        pKey->pPrivateKey, FALSE, 0, pHash, hashLen, pSignature,
        bufferSize, pSignatureLen);
    }
    else
    {
      /* We want the data back as the concatenation of r and s */
      ubyte4 format = MOC_ECDSA_SIGN_FORMAT_RAW;

      status = CRYPTO_asymSignDigest (
        pKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_ECDSA, (void *)&format,
        rngFun, rngArg, pHash, hashLen, pSignature, bufferSize, pSignatureLen, NULL);
    }
  }
  else
  {
    MOC_ECDSA_SIGN_DIGEST(status, pKey, rngFun, rngArg, pHash, hashLen, pSignature,
                           bufferSize, pSignatureLen);
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPublicKey,
  ubyte *pHash,
  ubyte4 hashLen,
  ubyte *pR,
  ubyte4 rLen,
  ubyte *pS,
  ubyte4 sLen,
  ubyte4 *pVerifyFailures
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 format, signatureLen = 0, elementLen;
  ubyte *pSignatureBuffer = NULL;

  if (NULL == pPublicKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPublicKey->enabled)
  {
    if ( NULL == pPublicKey->pPublicKey )
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pPublicKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_ECDSA_verify (
        pPublicKey->pPublicKey, FALSE, 0, pHash, hashLen, pR, rLen,
        pS, sLen, pVerifyFailures);
    }
    else
    {
      /* Get the elementLen so we know how big to make the signature buffer */
      status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pPublicKey, &elementLen);
      if (OK != status)
        goto exit;

      /* Allocate the signature buffer */
      signatureLen = elementLen * 2;
      status = DIGI_CALLOC((void **)&pSignatureBuffer, 1, signatureLen);
      if (OK != status)
        goto exit;

      /* Ensure the bytestring values for r and s are within range */
      status = ERR_INVALID_INPUT;
      if ( (rLen > elementLen + 1) || (sLen > elementLen + 1) )
        goto exit;

      /* If the input bytestring is one byte larger than the elementLen, it is
      * a pad byte from a DER encoding to ensure the integer was encoded as
      * a positive value. In this case ensure the value of the pad byte is zero
      * and trim that byte */
      if (rLen == elementLen + 1)
      {
        /* We expect this pad byte to be zero */
        if (0 != pR[0])
          goto exit;

        /* Move the pointer past the pad byte and decrement the length */
        pR++;
        rLen--;
      }

      /* Perform the same check for s */
      if (sLen == elementLen + 1)
      {
        /* We expect this pad byte to be zero */
        if (0 != pS[0])
          goto exit;

        /* Move the pointer past the pad byte and decrement the length */
        pS++;
        sLen--;
      }

      /* Copy the r value into the signature buffer, if the length is less than
      * elementLen then it will be copied such that it ends up zero padded to
      * elementLen in the buffer */
      status = DIGI_MEMCPY (
        (void *)(pSignatureBuffer + (elementLen - rLen)),
        (void *)(pR), rLen);
      if (OK != status)
        goto exit;

      /* Copy the s value in the same way */
      status = DIGI_MEMCPY (
        (void *)(pSignatureBuffer + elementLen + (elementLen - sLen)),
        (void *)(pS), sLen);
      if (OK != status)
        goto exit;

      /* Tell the operator to expect a raw format */
      format = MOC_ECDSA_SIGN_FORMAT_RAW;

      /* Now that we have the signature buffer prepared, perform the verification */
      status = CRYPTO_asymVerifyDigest (
        pPublicKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_ECDSA, (void *)&format,
        NULL, NULL, pHash, hashLen, pSignatureBuffer,
        signatureLen, pVerifyFailures, NULL);
    }
  }
  else
  {
    MOC_ECDSA_VERIFY_SIGNATURE_DIGEST(status, pPublicKey, pHash, hashLen, pR,
                                      rLen, pS, sLen, pVerifyFailures);
  }

exit:

  if (NULL != pSignatureBuffer)
  {
    shredMemory(&pSignatureBuffer, signatureLen, TRUE);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ECCKey *pPublicKey,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen,
  sbyte4 flag,
  void *pKdfInfo
  )
{
  MSTATUS status;
  ubyte4 secretLen;
  ubyte *pSecret = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pPrivateKey) || (NULL == pPublicKey) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivateKey->enabled)
  {
    if ( (NULL == pPrivateKey->pPrivateKey) || (NULL == pPublicKey->pPublicKey) ||
         (NULL == ppSharedSecret) || (NULL == pSharedSecretLen) )
      goto exit;

    status = CRYPTO_computeSharedSecret (
      pPrivateKey->pPrivateKey, pPublicKey->pPublicKey, NULL, 0, NULL,
      NULL, 0, &secretLen, NULL);
    if (OK == status)
      status = ERR_CRYPTO_FAILURE;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC((void **)&pSecret, secretLen);
    if (OK != status)
      goto exit;

    status = CRYPTO_computeSharedSecret (
      pPrivateKey->pPrivateKey, pPublicKey->pPublicKey, NULL, 0, NULL,
      pSecret, secretLen, &secretLen, NULL);
    if (OK != status)
      goto exit;

    *ppSharedSecret = pSecret;
    *pSharedSecretLen = secretLen;
    pSecret = NULL;
  }
  else
  {
    MOC_ECDH_GENERATE_SHARED_SECRET_FROM_KEYS(status, pPrivateKey,
            pPublicKey, ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);
  }

exit:

  if (NULL != pSecret)
  {
    DIGI_FREE((void **)&pSecret);
  }

  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ubyte *pPublicPointByteString,
  ubyte4 pointByteStringLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen,
  sbyte4 flag,
  void *pKdfInfo
  )
{
  MSTATUS status;
  ubyte4 curveId;
  ECCKey *pPubKey = NULL;

  /* All input parameter validation is handled by the below called methods */

  status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pPrivateKey, &curveId);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux (MOC_ECC(hwAccelCtx)
    curveId, &pPubKey, pPublicPointByteString, pointByteStringLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux (MOC_ECC(hwAccelCtx)
    pPrivateKey, pPubKey, ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);

exit:

  if (NULL != pPubKey)
  {
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
  }

  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_keyAgreementScheme(
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ubyte4 mode, 
  ECCKey *pStatic, 
  ECCKey *pEphemeral, 
  ubyte *pOtherPartysStatic, 
  ubyte4 otherStaticLen,
  ubyte *pOtherPartysEphemeral,
  ubyte4 otherEphemeralLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte *pSS = NULL;
  ubyte4 ssLen = 0;
  ubyte *pSS1 = NULL;
  ubyte4 ss1Len = 0;
  ubyte *pSS2 = NULL;
  ubyte4 ss2Len = 0;

  if (NULL == pEphemeral && NULL == pStatic)
    goto exit;

  /* Is one of them a crypto interface key? */
  if ( (NULL != pStatic && CRYPTO_INTERFACE_ALGO_ENABLED == pStatic->enabled) || 
       (NULL != pEphemeral && CRYPTO_INTERFACE_ALGO_ENABLED == pEphemeral->enabled) )
  {

    if (NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    switch (mode)
    {
        /* no operators yet built to support MQV */
        case FULL_MQV:
        case ONE_PASS_MQV_U:
        case ONE_PASS_MQV_V:

            status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
            break;

        case FULL_UNIFIED:
                        
            /* calculate Z_s */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, 1, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pEphemeral, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, 1, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case EPHEMERAL_UNIFIED:

            /* calculate Z = Z_e */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pEphemeral, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, 1, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
            
        case ONE_PASS_UNIFIED_U:
            
            /* calculate Z_s */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, 1, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pEphemeral, pOtherPartysStatic, otherStaticLen, &pSS2, &ss2Len, 1, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case ONE_PASS_UNIFIED_V:
            
            /* calculate Z_s */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, 1, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, 1, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = (ubyte4) (ss1Len + ss2Len);
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case ONE_PASS_DH_U:
            
            /* calculate Z */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pEphemeral, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, 1, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case ONE_PASS_DH_V:
            
            /* calculate Z */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, 1, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case STATIC_UNIFIED:
            
            /* calculate Z = Z_s */
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(hwAccelCtx) pStatic, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, 1, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        default:
            status = ERR_INVALID_ARG;    
    }
  }
  else
  {
    MOC_ECDH_KEY_AGREE(status, mode, pStatic, pEphemeral, pOtherPartysStatic, otherStaticLen, pOtherPartysEphemeral, otherEphemeralLen, ppSharedSecret, pSharedSecretLen);
  }

exit:

  if (NULL != pSS)
  {
      (void) DIGI_MEMSET_FREE(&pSS, ssLen);
  }

  if (NULL != pSS1)
  {
      (void) DIGI_MEMSET_FREE(&pSS1, ss1Len);
  }

  if (NULL != pSS2)
  {
      (void) DIGI_MEMSET_FREE(&pSS2, ss2Len);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_cloneKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey **ppNewKey,
  ECCKey *pSrc
  )
{
  MSTATUS status;
  ubyte private = 0;
  MocAsymKey pKeyToUse = NULL;
  MocAsymKey pClonedKey = NULL;
  MocAsymKey pNewPubKey = NULL;
  ECCKey *pNewKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSrc) || (NULL == ppNewKey) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    /* Use the private key if available */
    if (1 == pSrc->privateKey)
    {
      /* We must have a private key */
      if (NULL == pSrc->pPrivateKey)
        goto exit;

      pKeyToUse = pSrc->pPrivateKey;
      private = 1;
    }
    else
    {
      /* We must have a public key */
      if (NULL == pSrc->pPublicKey)
        goto exit;

      pKeyToUse = pSrc->pPublicKey;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKeyToUse->localType))
    {
      status = CRYPTO_INTERFACE_TAP_EC_cloneKey (
        ppNewKey, pKeyToUse);
    }
    else
    {
      /* Ask the operator to clone itself */
      status = CRYPTO_cloneMocAsymKey(pKeyToUse, &pClonedKey, NULL);
      if (OK != status)
        goto exit;

      /* Create the ECCKey shell */
      status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(ECCKey));
      if (OK != status)
        goto exit;

      if (1 == private)
      {
        /* If we cloned a private key, get a new public key from it and set both
        * keys inside the newly created shell */
        status = CRYPTO_getPubFromPri(pClonedKey, &pNewPubKey, NULL);
        if (OK != status)
          goto exit;

        /* Mark this key as enabled */
        pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

        /* Set the curve index from the source key */
        pNewKey->curveIndex = pSrc->curveIndex;

        /* Set the internal public and private keys */
        pNewKey->pPrivateKey = pClonedKey;
        pClonedKey = NULL;
        pNewKey->pPublicKey = pNewPubKey;
        pNewPubKey = NULL;

        /* Mark this key as private */
        pNewKey->privateKey = 1;
      }
      else
      {
        /* We cloned a public key, set the pointer and leave the private key NULL */
        pNewKey->pPublicKey = pClonedKey;
        pClonedKey = NULL;

        /* Mark this key as enabled */
        pNewKey->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

        /* Set the curve index from the source key */
        pNewKey->curveIndex = pSrc->curveIndex;
      }

      *ppNewKey = pNewKey;
      pNewKey = NULL;
    }
  }
  else
  {
    MOC_EC_CLONE_KEY(status, ppNewKey, pSrc);
  }

exit:

  if (NULL != pNewKey)
  {
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
  }
  if (NULL != pClonedKey)
  {
    CRYPTO_freeMocAsymKey(&pClonedKey, NULL);
  }
  if (NULL != pNewPubKey)
  {
    CRYPTO_freeMocAsymKey(&pNewPubKey, NULL);
  }

  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_equalKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey1,
  ECCKey *pKey2,
  byteBoolean *pRes
  )
{
  MSTATUS status;
  sbyte4 cmpResult = 0;
  MEccKeyTemplate template1 = {0};
  MEccKeyTemplate template2 = {0};

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey1) || (NULL == pKey2) || (NULL == pRes) )
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey1->enabled)
  {
    *pRes = FALSE;

    /* We will be comparing the public key values */
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

    /* Do they have the same length? */
    if (template1.publicKeyLen != template2.publicKeyLen)
      goto exit;

    /* Do they match? */
    status = DIGI_MEMCMP (
      template1.pPublicKey, template2.pPublicKey, template1.publicKeyLen, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 == cmpResult)
    {
      *pRes = TRUE;
    }
  }
  else
  {
    MOC_EC_EQUAL_KEY(status, pKey1, pKey2, pRes);
  }

exit:

  CRYPTO_INTERFACE_EC_freeKeyTemplateAux(NULL, &template1);
  CRYPTO_INTERFACE_EC_freeKeyTemplateAux(NULL, &template2);

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_verifyKeyPairAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  ECCKey *pPublicKey,
  byteBoolean *pVfy
  )
{
  MSTATUS status;
  MocAsymKey pPubKeyToUse = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pPrivateKey) || (NULL == pVfy) )
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivateKey->enabled)
  {
    /* Did the caller provide a public key to check against? */
    if (NULL != pPublicKey)
    {
      /* This key must be crypto interface enabled */
      status = ERR_INVALID_INPUT;
      if (CRYPTO_INTERFACE_ALGO_ENABLED != pPublicKey->enabled)
        goto exit;

      pPubKeyToUse = pPublicKey->pPublicKey;
    }
    else
    {
      /* If none was provided, use the public portion of the private key */
      pPubKeyToUse = pPrivateKey->pPublicKey;
    }

    status = CRYPTO_validatePubPriMatch (
      pPrivateKey->pPrivateKey, pPubKeyToUse, pVfy);
  }
  else
  {
    MOC_EC_PUB_PRI_MATCH(status, pPrivateKey, pPublicKey, pVfy);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_verifyPublicKeyAux (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pKey,
  byteBoolean *pIsValid
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = CRYPTO_validateKey(pKey->pPublicKey, pIsValid);
  }
  else
  {
    MOC_EC_VERIFY_PUB_KEY(status, pKey, pIsValid);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signMessageExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPrivateKey,
  RNGFun rngFUN,
  void *pRngArg,
  ubyte hashAlgo,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPrivateKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivateKey->enabled)
  {
    /* We must have a private key to sign with */
    if ( NULL == pPrivateKey->pPrivateKey )
      goto exit;

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pPrivateKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_ECDSA_sign (
        pPrivateKey->pPrivateKey, TRUE, hashAlgo, pMessage, messageLen, pSignature,
        bufferSize, pSignatureLen);
    }
    else
    {
      MEccDsaInfo eccDsaInfo = {0};

      /* rest of input validation done by the below call */

      /* Tell the operator what signature format we want and what hash algorithm to use */
      eccDsaInfo.format = MOC_ECDSA_SIGN_FORMAT_RAW;
      eccDsaInfo.hashAlgo = hashAlgo;

      status = CRYPTO_asymSignMessage(pPrivateKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_ECDSA, (void *) &eccDsaInfo,
                                      rngFUN, pRngArg, pMessage, messageLen, pSignature, bufferSize, pSignatureLen, NULL);
    }
  }
  else
  {
    MOC_EC_SIGN_MSG(status, pPrivateKey, rngFUN, pRngArg, hashAlgo, pMessage,
                    messageLen, pSignature, bufferSize, pSignatureLen, pExtCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_verifyMessageExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pPublicKey,
  ubyte hashAlgo,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPublicKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPublicKey->enabled)
  {
    if ( NULL == pPublicKey->pPublicKey )
      goto exit;

    /* we need to ensure signature is an even number of bytes */
    status = ERR_INVALID_INPUT;
    if (signatureLen & 0x01)
    {
      goto exit;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pPublicKey->pPublicKey->localType))
    {
      /* use the same var to no represent the rLen and sLen */
      signatureLen = signatureLen/2;

      status = CRYPTO_INTERFACE_TAP_ECDSA_verify (
        pPublicKey->pPublicKey, TRUE, hashAlgo, pMessage, messageLen, pSignature, signatureLen,
        pSignature + signatureLen, signatureLen, pVerifyFailures);
    }
    else
    {
      MEccDsaInfo eccDsaInfo = {0};

      /* rest of input validation done by the below call */

      /* Tell the operator what signature format we want and what hash algorithm to use */
      eccDsaInfo.format = MOC_ECDSA_SIGN_FORMAT_RAW;
      eccDsaInfo.hashAlgo = hashAlgo;

      /* Now that we have the signature buffer prepared, perform the verification */
      status = CRYPTO_asymVerifyMessage(pPublicKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_ECDSA, (void *) &eccDsaInfo,
                                        NULL, NULL, pMessage, messageLen, pSignature,
                                        signatureLen, pVerifyFailures, NULL);
    }
  }
  else
  {
    MOC_EC_VERIFY_MSG(status, pPublicKey, hashAlgo, pMessage, messageLen,
                      pSignature, signatureLen, pVerifyFailures, pExtCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_initVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ECCKey *pPublicKey,
  ubyte hashAlgo,
  ubyte *pSignature,
  ubyte4 signatureLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPublicKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPublicKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EC_INIT_VERIFY(status, pCtx, pPublicKey, hashAlgo, pSignature, signatureLen, pExtCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_updateVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ubyte *pMessage,
  ubyte4 messageLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx || NULL == pCtx->pKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EC_UPDATE_VERIFY(status, pCtx, pMessage, messageLen, pExtCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_finalVerifyExt (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECDSA_CTX *pCtx,
  ubyte4 *pVerifyFailures,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx || NULL == pCtx->pKey)
    goto exit;

  /* Other validation handled by the below methods */

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EC_FINAL_VERIFY(status, pCtx, pVerifyFailures, pExtCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS isCurveEnabledInNanoCrypto(byteBoolean *pEnabled)
{
    MSTATUS status = OK;
    ubyte4 curveIndex, operatorIndex;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    
    /* internal method, don't need to check for NULL */

    *pEnabled = FALSE;

    /* As soon as we find an enabled curve with no operator we can set enabled to true */

#ifdef __ENABLE_DIGICERT_ECC_P192__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_P192, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_P224, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_P256, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_P384, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_P521, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_Ed25519, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_Ed448, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_X25519, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    status = CRYPTO_INTERFACE_curveIdToCurveIndex(cid_EC_X448, &curveIndex);
    if (OK != status)
        goto exit;

    /* Determine if we have an alternate implementation for this curve */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(curveIndex, &algoStatus, &operatorIndex);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        *pEnabled = TRUE;
        goto exit;
    }
#endif

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_signInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    /* Other validation handled by the below methods */

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_EC_ED_SIGN(status, pKey, pInput, inputLen, isPreHash, pCtx, ctxLen, pSignature, bufferSize, pSignatureLen, pExtCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_verifyInput (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPreHash,
    ubyte *pCtx,
    ubyte4 ctxLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    /* Other validation handled by the below methods */

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_EC_ED_VERIFY(status, pKey, pInput, inputLen, isPreHash, pCtx, ctxLen, pSignature, signatureLen, pVerifyFailures, pExtCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_createCombMutexes()
{
    MSTATUS status = OK;
    byteBoolean nanoCryptoEnabled = FALSE;

    status = isCurveEnabledInNanoCrypto(&nanoCryptoEnabled);
    if (OK != status)
        goto exit;

    if (nanoCryptoEnabled)
    {
        MOC_EC_CREATE_COMB_MUTEX(status);
    }
    
exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes()
{
    MSTATUS status = OK;
    byteBoolean nanoCryptoEnabled = FALSE;

    status = isCurveEnabledInNanoCrypto(&nanoCryptoEnabled);
    if (OK != status)
        goto exit;

    if (nanoCryptoEnabled)
    {
        MOC_EC_DELETE_COMB_MUTEX(status);
    }
    
exit:

    return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__)) */
