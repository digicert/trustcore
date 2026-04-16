/*
 * crypto_interface_ecc_tap_priv.h
 *
 * Cryptographic Interface header file for declaring ECC TAP functions
 * for internal use by the Crypto Interface.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#ifndef __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))

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

#endif /* if (defined(__ENABLE_DIGICERT_ECC__)) */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_TAP_PRIV_HEADER__ */
