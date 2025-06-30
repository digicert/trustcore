/*
 * crypto_interface_rsa_tap_priv.h
 *
 * Cryptographic Interface header file for declaring RSA TAP functions
 * for internal use by the Crypto Interface.
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

#ifndef __CRYPTO_INTERFACE_RSA_TAP_PRIV_HEADER__
#define __CRYPTO_INTERFACE_RSA_TAP_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_signDigestInfo (
    MocAsymKey pRSAKey,
    ubyte *pDigestInfo,
    ubyte4 digestInfoLen,
    ubyte *pSignature,
    vlong **ppVlongQueue
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_verifyDigestInfo (
    MocAsymKey pRSAKey,
    ubyte *pSignature,
    ubyte *pDigest,
    ubyte4 digestLen,
    vlong **ppVlongQueue
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_encrypt (
    MocAsymKey pRSAKey,
    ubyte *pPlainText,
    ubyte4 plainTextLen,
    ubyte *pCipherText,
    RNGFun rngFun,
    void *rngFunArg,
    vlong **ppVlongQueue
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_decrypt (
    MocAsymKey pRSAKey,
    ubyte *pCipherText,
    ubyte *pPlainText,
    ubyte4 *plainTextLen,
    RNGFun rngFun,
    void *rngFunArg,
    vlong **ppVlongQueue
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaPssSignData (
    randomContext *pRandomContext,
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaPssVerifyDigest (
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepEncrypt(
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pMessage,
    ubyte4 mLen,
    ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherTextLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepDecrypt(
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pCipherText,
    ubyte4 cLen,
    ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppPlainText,
    ubyte4 *pPlainTextLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_applyPrivateKey (
    MocAsymKey pRSAKey,
    RNGFun rngFun,
    void *rngFunArg,
    const ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pOutput,
    ubyte4 *pOuputLen,
    vlong **ppVlongQueue
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_applyPublicKey (
    MocAsymKey pRSAKey,
    const ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pOutput,
    vlong **ppVlongQueue
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RSA_TAP_PRIV_HEADER__ */
