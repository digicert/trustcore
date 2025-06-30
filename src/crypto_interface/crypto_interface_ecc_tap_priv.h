/*
 * crypto_interface_ecc_tap_priv.h
 *
 * Cryptographic Interface header file for declaring ECC TAP functions
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

#ifndef __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_MOCANA_ECC__))

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getECCPublicKeyEx (
    MocAsymKey pMocAsymKey,
    void **ppPub
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_ECDSA_sign (
    MocAsymKey pECCKey,
    byteBoolean isDataNotDigest,
    ubyte hashAlgo,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_ECDSA_verify (
    MocAsymKey pPublicKey,
    byteBoolean isDataNotDigest,
    ubyte hashAlgo,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    ubyte4 *pVerifyFailures
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_getCurveIdFromKey (
    MocAsymKey pKey,
    ubyte4 *pCurveId
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen (
    MocAsymKey pKey,
    ubyte4 *pLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_writePublicKeyToBuffer (
    MocAsymKey pKey,
    ubyte *pBuffer,
    ubyte4 bufferSize
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_cloneKey (
    ECCKey **ppNew,
    MocAsymKey pSrc
    );

#endif /* if (defined(__ENABLE_MOCANA_ECC__)) */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__ */
