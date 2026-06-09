/*
 * crypto_interface_qs_tap_priv.h
 *
 * Cryptographic Interface header file for declaring QS TAP functions
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

#ifndef __CRYPTO_INTERFACE_QS_TAP_PRIV_HEADER__
#define __CRYPTO_INTERFACE_QS_TAP_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_PQC__))

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_sign (
    MocAsymKey pPrivateKey,
    byteBoolean isDataNotDigest,
    ubyte4 digestId,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_verify (
    MocAsymKey pPublicKey,
    byteBoolean isDataNotDigest,
    ubyte4 digestId,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getAlg(
    MocAsymKey pKey,
    ubyte4 *pAlg
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getSwPubFromTap (
    MocAsymKey pPrivateKey,
    QS_CTX **ppNewPub
    );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getPublicKey (
    MocAsymKey pKey,
    ubyte *pPublicKey,
    ubyte4 pubLen
    );

#endif /* if (defined(__ENABLE_DIGICERT_PQC__)) */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_QS_TAP_PRIV_HEADER__ */
