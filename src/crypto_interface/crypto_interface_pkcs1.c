/*
 * crypto_interface_pkcs1.c
 *
 * Cryptographic Interface specification for RSA-PSS and RSA-OAEP.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/rsa.h"
#include "../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../crypto/pkcs1.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#include "../crypto_interface/crypto_interface_rsa_tap_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)) && \
    (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS1__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
#define MOC_RSA_PKCS1_PSS_SIGN(_status, _pRandCtx, _pKey, _hashAlgo, _mgf,     \
                               _mgfHash, _pMsg, _msgLen, _sLen,                \
                               _ppRetSig, _pRetSigLen, _pExtCtx)               \
    _status = PKCS1_rsaPssSignExt (MOC_RSA(hwAccelCtx)                         \
      _pRandCtx, _pKey, _hashAlgo, _mgf, _mgfHash, _pMsg, _msgLen, _sLen,      \
      _ppRetSig, _pRetSigLen, _pExtCtx);
#else
#define MOC_RSA_PKCS1_PSS_SIGN(_status, _pRandCtx, _pKey, _hashAlgo, _mgf,     \
                               _mgfHash, _pMsg, _msgLen, _sLen,                \
                               _ppRetSig, _pRetSigLen, _pExtCtx)               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_RSA_PKCS1_PSS_VERIFY(_status, _pKey, _hashAlgo, _mgf, _mgfHash,    \
                                 _pMsg, _msgLen, _pSig, _sigLen, _sLen,        \
                                 _pRet, _pExtCtx)                              \
    _status = PKCS1_rsaPssVerifyExt (MOC_RSA(hwAccelCtx)                       \
      _pKey, _hashAlgo, _mgf, _mgfHash, _pMsg, _msgLen, _pSig, _sigLen,        \
      _sLen, _pRet, _pExtCtx);
#else
#define MOC_RSA_PKCS1_PSS_VERIFY(_status, _pKey, _hashAlgo, _mgf, _mgfHash,    \
                                 _pMsg, _msgLen, _pSig, _sigLen, _sLen,        \
                                 _pRet, _pExtCtx)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_RSA_PKCS1_PSS_SSA_VERIFY(_status, _pKey, _hashAlgo,     \
                                 _mgf, _pMsg, _msgLen, _pSig, _sigLen,           \
                                 _sLen, _pRet)                                   \
    _status = PKCS1_rsassaPssVerify (                                            \
      MOC_RSA(hwAccelCtx) _pKey, _hashAlgo, _mgf, _pMsg, _msgLen, _pSig,      \
      _sigLen, _sLen, _pRet);
#else
#define MOC_RSA_PKCS1_PSS_SSA_VERIFY(_status, _pKey, _hashAlgo,     \
                                 _mgf, _pMsg, _msgLen, _pSig, _sigLen,           \
                                 _sLen, _pRet)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_RSA_PKCS1_OAEP_ENCRYPT(_status, _pRandCtx, _pKey, _hashAlgo, _mgf, \
                                   _mgfHash, _pM, _mLen, _pL, _lLen,           \
                                   _pRet, _pRetLen)                            \
    _status = PKCS1_rsaOaepEncrypt (MOC_RSA(hwAccelCtx)                        \
      _pRandCtx, _pKey, _hashAlgo, _mgf, _mgfHash, _pM, _mLen, _pL, _lLen,     \
      _pRet, _pRetLen);
#else
#define MOC_RSA_PKCS1_OAEP_ENCRYPT(_status, _pRandCtx, _pKey, _hashAlgo, _mgf, \
                                   _mgfHash, _pM, _mLen, _pL, _lLen,           \
                                   _pRet, _pRetLen)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
#define MOC_RSA_PKCS1_OAEP_DECRYPT(_status, _pKey, _hashAlgo, _mgf, _mgfHash,  \
                                   _pC, _cLen, _pL, _lLen, _pRet, _pRetLen)    \
    _status = PKCS1_rsaOaepDecrypt (MOC_RSA(hwAccelCtx)                        \
      _pKey, _hashAlgo, _mgf, _mgfHash, _pC, _cLen, _pL, _lLen,                \
      _pRet, _pRetLen);
#else
#define MOC_RSA_PKCS1_OAEP_DECRYPT(_status, _pKey, _hashAlgo, _mgf, _mgfHash,  \
                                   _pC, _cLen, _pL, _lLen, _pRet, _pRetLen)    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
#define MOC_RSA_PKCS1_MGF1(_status, _mgfSeed, _mgfSeedLen, _maskLen, \
                           _H, _ppRetMask)                                        \
    _status = PKCS1_MGF1_FUNC (                                                   \
      MOC_RSA(hwAccelCtx) _mgfSeed, _mgfSeedLen, _maskLen, _H, _ppRetMask)
#else
#define MOC_RSA_PKCS1_MGF1(_status, _mgfSeed, _mgfSeedLen, _maskLen, \
                           _H, _ppRetMask)                                        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  const RSAKey *pKey,
  ubyte hashAlgo,
  ubyte mgfAlgo,
  ubyte mgfHashAlgo,
  const ubyte *pMessage,
  ubyte4 mLen,
  ubyte4 saltLen,
  ubyte **ppSignature,
  ubyte4 *pSignatureLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MRsaPssInfo pssInfo;
  ubyte4 signatureLen = 0;
  ubyte *pSignature = NULL;
  MOC_UNUSED(pExtCtx);
  RSAKey *pPubKey = NULL;
  ubyte4 vfy = 1;

  if (NULL == pKey)
    goto exit;
    
  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if ( NULL == pKey->pPrivateKey || NULL == ppSignature || NULL == pSignatureLen )
    {
      goto exit;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPrivateKey->localType))
    {

      status = CRYPTO_INTERFACE_TAP_PKCS1_rsaPssSignData (
        pRandomContext, pKey->pPrivateKey, hashAlgo, mgfAlgo, mgfHashAlgo,
        (ubyte *) pMessage, mLen, saltLen, &pSignature, &signatureLen);
      if (OK != status)
        goto exit;

      /*
      From the TCG 2.0 library specification regarding RSA-PSS salt length
       *
       * Trusted Platform Module Library Specification, Family "2.0", Level
       * 00, Revision 01.38 - September 2016 in Part 1: Architecture - Annex B.7
       *
       *   For RSA-PSS the salt length will be the largest size allowed by the
       *   key size and message digest size. However, if the TPM is compliant
       *   with FIPS 186-4 then the salt length will be the largest size allowed
       *   by the FIPS 186-4 specification.
       *
       * If the TPM 2.0 is not in FIPS mode then according to RFC 8017 the
       * maximum salt length can be
       *
       *   sLen = ceil((modBits - 1) / 8) - hLen - 2
       *
       *   where
       *     modBits - RSA modulus length in bits
       *     hLen - digest length in bytes
       *     sLen - maximum salt length in bytes
       *
       * If the TPM 2.0 is in FIPS mode then according to FIPS 186-4 section 5.5
       * the maximum salt length can be
       *
       *   For a 1024 bit RSA modulus and an approved hash with an output of 64
       *   bytes
       *
       *     0 <= sLen <= hLen - 2
       *
       *   Otherwise
       *
       *     0 <= sLen <= hLen
       *
       *   where
       *     hLen - digest length in bytes
       *     sLen - maximum salt length in bytes
       *
       *   Since the TPM 2.0 uses the maximum salt length possible, a salt
       *   length of hLen - 2 or hLen will be used in FIPS mode.
       *
       * This information is specific to TPM 2.0, however the underlying
       * hardware device may not be a TPM. To verify the caller salt length is
       * correct a verification will be performed on the signature in software.
       */
      status = CRYPTO_INTERFACE_getRsaSwPubFromTapKey(
        (RSAKey *) pKey, &pPubKey);
      if (OK != status)
        goto exit;

#if defined(__ENABLE_RSA_PSS_TAP_VARIABLE_SALT_LEN__)
      saltLen = -1;
#endif

      status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt(MOC_RSA(hwAccelCtx)
        pPubKey, hashAlgo, mgfAlgo, mgfHashAlgo, pMessage, mLen, pSignature,
        signatureLen, (sbyte4) saltLen, &vfy, pExtCtx);
      if ( (OK == status) && (0 != vfy) )
        status = ERR_RSA_BAD_SIGNATURE;

      if (OK != status)
        goto exit;

    }
    else
    {
      /* Assume the output buffer is just large enough */
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (MOC_RSA(hwAccelCtx)
        pKey, (sbyte4*)&signatureLen);
      if (OK != status)
        goto exit;

      status = DIGI_MALLOC((void **)&pSignature, signatureLen);
      if (OK != status)
        goto exit;

      /* Prepare the info structure */
      pssInfo.hashAlgo = hashAlgo;
      pssInfo.mgfAlgo = mgfAlgo;
      pssInfo.mgfHashAlgo = mgfHashAlgo;
      pssInfo.saltLen = (sbyte4) saltLen;

      /* Send a request to the operator to sign this message */
      status = CRYPTO_asymSignMessage (
        pKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_PSS_PAD,
        (void *)&pssInfo, RANDOM_rngFun, pRandomContext, (ubyte *)pMessage,
        mLen, pSignature, signatureLen, &signatureLen, NULL);
      if (OK != status)
        goto exit;

    }

    *pSignatureLen = signatureLen;
    *ppSignature = pSignature;
    pSignature = NULL;
  }
  else
  {
    MOC_RSA_PKCS1_PSS_SIGN (
      status, pRandomContext, pKey, hashAlgo, mgfAlgo, mgfHashAlgo,
      pMessage, mLen, saltLen, ppSignature, pSignatureLen, pExtCtx);
  }

exit:

  if (NULL != pSignature)
  {
    (void) DIGI_FREE((void **)&pSignature);
  }

  if (NULL != pPubKey)
  {
    (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssSign (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  const RSAKey *pKey,
  ubyte hashAlgo,
  ubyte mgfAlgo,
  ubyte mgfHashAlgo,
  const ubyte *pMessage,
  ubyte4 mLen,
  ubyte4 saltLen,
  ubyte **ppSignature,
  ubyte4 *pSignatureLen
  )
{
  return CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (MOC_RSA(hwAccelCtx)
    pRandomContext, pKey, hashAlgo, mgfAlgo, mgfHashAlgo, pMessage,
    mLen, saltLen, ppSignature, pSignatureLen, NULL);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pKey,
  ubyte hashAlgo,
  ubyte mgfAlgo,
  ubyte mgfHashAlgo,
  const ubyte *pMessage,
  ubyte4 mLen,
  const ubyte *pSignature,
  ubyte4 signatureLen,
  sbyte4 saltLen,
  ubyte4 *pVerify,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MRsaPssInfo pssInfo;
  MOC_UNUSED(pExtCtx);

  if (NULL == pKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    /* We need a public key to verify with */
    if (NULL == pKey->pPublicKey)
    {
      goto exit;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {

      status = CRYPTO_INTERFACE_TAP_PKCS1_rsaPssVerifyDigest (pKey->pPublicKey, hashAlgo, mgfAlgo, mgfHashAlgo, 
                                                              (ubyte *) pMessage, mLen, (ubyte *) pSignature,
                                                              signatureLen, saltLen, pVerify);
      if (OK != status)
        goto exit;

    }
    else
    {
       /* Prepare the info structure */
      pssInfo.hashAlgo = hashAlgo;
      pssInfo.mgfAlgo = mgfAlgo;
      pssInfo.mgfHashAlgo = mgfHashAlgo;
      pssInfo.saltLen = saltLen;

      /* Send a request to the operator to verify this message */
      status = CRYPTO_asymVerifyMessage (
        pKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_PSS_PAD,
        (void *)&pssInfo, RANDOM_rngFun, g_pRandomContext, (ubyte *)pMessage,
        mLen, (ubyte *)pSignature, signatureLen, pVerify, NULL);
    }
  }
  else
  {
    MOC_RSA_PKCS1_PSS_VERIFY (
      status, pKey, hashAlgo, mgfAlgo, mgfHashAlgo, pMessage, mLen,
      pSignature, signatureLen, saltLen, pVerify, pExtCtx);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssVerify (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify
    )
{
  return CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (MOC_RSA(hwAccelCtx)
    pKey, hashAlgo, mgfAlgo, mgfHashAlgo, pMessage, mLen, pSignature,
    signatureLen, saltLen, pVerify, NULL);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsassaPssVerify(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  ubyte H_rsaAlgoId,
  mgfFunc MGF,
  const ubyte * const pMessage,
  ubyte4 mesgLen,
  const ubyte *pSignature,
  ubyte4 signatureLen,
  sbyte4 saltLen,
  intBoolean *pRetIsSignatureValid
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pRSAKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRSAKey->enabled)
  {
    /* Not implemented, placeholder to allow crypto interface unittests to build */
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_RSA_PKCS1_PSS_SSA_VERIFY(status, pRSAKey, H_rsaAlgoId,
      MGF, pMessage, mesgLen, pSignature, signatureLen, saltLen, pRetIsSignatureValid);
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherTextLen
    )
{
  MSTATUS status;
  MRsaOaepInfo oaepInfo;
  ubyte4 cipherTextLen;
  ubyte *pCipherText = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pRSAKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRSAKey->enabled)
  {
    status = ERR_NULL_POINTER;
    if (NULL == pRSAKey->pPublicKey || NULL == ppCipherText || NULL == pCipherTextLen )
    {
      goto exit;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pRSAKey->pPublicKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepEncrypt(pRSAKey->pPublicKey, hashAlgo, mgfAlgo, mgfHashAlgo, 
                                                         (ubyte *) pMessage, mLen, (ubyte *) pLabel, lLen, 
                                                         ppCipherText, pCipherTextLen);
      if (OK != status)
        goto exit;

    }
    else
    {
      /* Get the output length */
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (MOC_RSA(hwAccelCtx)
        pRSAKey, (sbyte4*)&cipherTextLen);
      if (OK != status)
        goto exit;

      /* Allocate the ciphertext buffer */
      status = DIGI_MALLOC((void **)&pCipherText, cipherTextLen);
      if (OK != status)
        goto exit;

      /* Prepare the info structure */
      oaepInfo.hashAlgo = hashAlgo;
      oaepInfo.mgfAlgo = mgfAlgo;
      oaepInfo.mgfHashAlgo = mgfHashAlgo;
      oaepInfo.pLabel = (ubyte *)pLabel;
      oaepInfo.labelLen = lLen;

      /* Have the operator perform the encryption operation */
      status = CRYPTO_asymEncrypt (
        pRSAKey->pPublicKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_OAEP_PAD,
        (void *)&oaepInfo, RANDOM_rngFun, pRandomContext, (ubyte *)pMessage,
        mLen, pCipherText, cipherTextLen, &cipherTextLen, NULL);
      if (OK != status)
        goto exit;

      *pCipherTextLen = cipherTextLen;
      *ppCipherText = pCipherText;
      pCipherText = NULL;
    }
  }
  else
  {
    MOC_RSA_PKCS1_OAEP_ENCRYPT (
      status, pRandomContext, pRSAKey, hashAlgo, mgfAlgo, mgfHashAlgo,
      pMessage, mLen, pLabel, lLen, ppCipherText, pCipherTextLen);
  }

exit:

  if (NULL != pCipherText)
  {
    DIGI_FREE((void **)&pCipherText);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pCipherText,
    ubyte4 cLen,
    const ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppPlainText,
    ubyte4 *pPlainTextLen
    )
{
  MSTATUS status;
  MRsaOaepInfo oaepInfo;
  ubyte4 plainTextLen;
  ubyte *pPlainText = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pRSAKey)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRSAKey->enabled)
  {
    status = ERR_NULL_POINTER;
    if ( NULL == pRSAKey->pPrivateKey || NULL == ppPlainText || NULL == pPlainTextLen )
    {
      goto exit;
    }

    /* If this is a TAP key, handle it separately */
    if (0 != (MOC_LOCAL_TYPE_TAP & pRSAKey->pPrivateKey->localType))
    {
      status = CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepDecrypt(pRSAKey->pPrivateKey, hashAlgo, mgfAlgo, mgfHashAlgo, 
                                                         (ubyte *) pCipherText, cLen, (ubyte *) pLabel, lLen, 
                                                         ppPlainText, pPlainTextLen);
      if (OK != status)
        goto exit;
    }
    else
    {
      /* Get the output length */
      status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (MOC_RSA(hwAccelCtx)
        pRSAKey, (sbyte4*)&plainTextLen);
      if (OK != status)
        goto exit;

      /* Allocate the plaintext buffer, must always be large enough for the
      * unpadded material */
      status = DIGI_MALLOC((void **)&pPlainText, plainTextLen);
      if (OK != status)
        goto exit;

      /* Prepare the info structure */
      oaepInfo.hashAlgo = hashAlgo;
      oaepInfo.mgfAlgo = mgfAlgo;
      oaepInfo.mgfHashAlgo = mgfHashAlgo;
      oaepInfo.pLabel = (ubyte *)pLabel;
      oaepInfo.labelLen = lLen;

      /* Have the operator perform the decryption operation */
      status = CRYPTO_asymDecrypt (
        pRSAKey->pPrivateKey, NULL, 0, MOC_ASYM_KEY_ALG_RSA_OAEP_PAD,
        (void *)&oaepInfo, RANDOM_rngFun, g_pRandomContext, (ubyte *)pCipherText,
        cLen, pPlainText, plainTextLen, &plainTextLen, NULL);
      if (OK != status)
        goto exit;

      *pPlainTextLen = plainTextLen;
      *ppPlainText = pPlainText;
      pPlainText = NULL;
    }
  }
  else
  {
    MOC_RSA_PKCS1_OAEP_DECRYPT (
      status, pRSAKey, hashAlgo, mgfAlgo, mgfHashAlgo, pCipherText, cLen,
      pLabel, lLen, ppPlainText, pPlainTextLen);
  }


exit:

  if (NULL != pPlainText)
  {
    DIGI_FREE((void **)&pPlainText);
  }

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_PKCS1_MGF1(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const ubyte *mgfSeed,
  ubyte4 mgfSeedLen,
  ubyte4 maskLen,
  BulkHashAlgo *H,
  ubyte **ppRetMask
  )
{
  MSTATUS status;
  /* Pass through for cryptointerface unittests to build */
  MOC_RSA_PKCS1_MGF1(status, mgfSeed, mgfSeedLen, maskLen, H, ppRetMask);
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssPad(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  RNGFun rngFun,
  void *rngFunArg,
  ubyte *M,
  ubyte4 mLen,
  ubyte4 sLen,
  ubyte hashAlgo,
  ubyte mgfAlgo,
  ubyte mgfHashAlgo,
  ubyte **ppRetEM,
  ubyte4 *pRetEMLen
  )
{
  MSTATUS       status = OK;
  ubyte4        emBits;
  ubyte        *pPaddedMsg = NULL;
  BulkHashAlgo *pH = NULL;
  BulkHashAlgo *pMgfH = NULL;

  if ( (NULL == pKey) || (NULL == rngFun) || (NULL == M) ||
       (NULL == ppRetEM) || (NULL == pRetEMLen) )
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  *ppRetEM = NULL;

  if ( MOC_PKCS1_ALG_MGF1 == mgfAlgo)
  {
    /* the hash algorithm must match the hash algorithm used for the MGF */
    if (hashAlgo != mgfHashAlgo)
        goto exit;

    status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pH);
    if (OK != status)
        goto exit;

    pMgfH = pH;
  }
  else if (MOC_PKCS1_ALG_SHAKE == mgfAlgo)
  {
    /* mgfHashAlgo must be an xof */
    if (mgfHashAlgo != ht_shake128 && mgfHashAlgo != ht_shake256)
        goto exit;

    /* We allow any other hashAlgo */
    status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo **)&pH);
    if (OK != status)
        goto exit;

    status = CRYPTO_getRSAHashAlgo(mgfHashAlgo, (const BulkHashAlgo **)&pMgfH);
    if (OK != status)
        goto exit;
  }
  else
  {
    status = ERR_INVALID_ARG;
    goto exit;
  }

  /* emBits is one bit less than modulus bits */
  status = CRYPTO_INTERFACE_RSA_getKeyBitLen(MOC_RSA(hwAccelCtx) pKey, &emBits);
  if (OK != status)
    goto exit;

  emBits--;

  status = RsaPadPss(MOC_HASH(hwAccelCtx)
    rngFun, rngFunArg, M, mLen, emBits, sLen, pH, pMgfH, pH->digestSize,
    mgfAlgo, &pPaddedMsg);
  if (OK != status)
    goto exit;

  *ppRetEM = pPaddedMsg;
  *pRetEMLen = (emBits + 7)/8;
  pPaddedMsg = NULL;

exit:

  if (NULL != pPaddedMsg)
  {
    DIGI_MEMSET_FREE(&pPaddedMsg, emBits);
  }

  return status;

}

#endif
