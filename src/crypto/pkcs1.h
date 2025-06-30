/*
 * pkcs1.h
 *
 * PKCS#1 Version 2.1 Header
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
/**
@file       pkcs1.h

@brief      Header file for SoT Platform PKCS&nbsp;\#1 convenience API.
@details    Header file for SoT Platform PKCS&nbsp;\#1, version 2.1, convenience
            API, as defined by RFC&nbsp;3447.

For documentation for this file's definitions, enumerations, and functions, see
pkcs1.c.
*/


/*------------------------------------------------------------------*/

#ifndef __PKCS1_HEADER__
#define __PKCS1_HEADER__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1__
#include "../crypto_interface/crypto_interface_pkcs1_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/* exported routines */

#ifndef MOC_PKCS1_ALG_MGF1
#define MOC_PKCS1_ALG_MGF1 1
#endif

#ifndef MOC_PKCS1_ALG_SHAKE
#define MOC_PKCS1_ALG_SHAKE 2
#endif

/* For non OpenSSL builds macro the old API into the new API for backwards
 * compatability. OpenSSL builds cannot define this macro as there are namespace
 * issues with the old APIs. */
#ifndef OPENSSL_ENGINE
#ifndef PKCS1_MGF1
#define PKCS1_MGF1 PKCS1_MGF1_FUNC
#endif /* PKCS1_MGF1 */
#endif /* OPENSSL_ENGINE */

/**
@dont_show
@internal
*/
typedef MSTATUS (*mgfFunc)(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask);


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS1_rsaesOaepEncrypt(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, ubyte H_rsaAlgoId, mgfFunc MGF, const ubyte *M, ubyte4 mLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetEncrypt, ubyte4 *pRetEncryptLen);
#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN MSTATUS PKCS1_rsaesOaepDecrypt(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, ubyte H_rsaAlgoId, mgfFunc MGF, const ubyte *C, ubyte4 cLen, const ubyte *L, ubyte4 lLen, ubyte **ppRetDecrypt, ubyte4 *pRetDecryptLength);
#endif

#if (!defined(__DISABLE_MOCANA_RSA_DECRYPTION__))
MOC_EXTERN MSTATUS PKCS1_rsassaPssSign(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const RSAKey *pRSAKey, ubyte H_rsaAlgoId, mgfFunc MGF, const ubyte *pMessage, ubyte4 mesgLen, ubyte4 saltLen, ubyte **ppRetSignature, ubyte4 *pRetSignatureLen);
MOC_EXTERN MSTATUS PKCS1_rsassaFreePssSign(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte **ppSignature);
#endif
MOC_EXTERN MSTATUS PKCS1_rsassaPssVerify(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, ubyte H_rsaAlgoId, mgfFunc MGF, const ubyte * const pMessage, ubyte4 mesgLen, const ubyte *pSignature, ubyte4 signatureLen, sbyte4 saltLen, intBoolean *pRetIsSignatureValid);

/* helper function */
MOC_EXTERN MSTATUS PKCS1_MGF1_FUNC(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte *mgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, BulkHashAlgo *H, ubyte **ppRetMask);

/**
 * Perform RSA-OAEP encryption.
 *
 * @param pRandomContext The random context to use for this operation.
 * @param pRSAKey        The RSA public key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be encrypted, the length must
 *                       be less than or equal to (k - 2hlen - 2) where k is the
 *                       length in octets of the RSA modulus N.
 * @param mLen           Length in bytes of the input message to be encrypted.
 * @param pLabel         Optional label to use in the encoding.
 * @param lLen           Length in bytes of the label.
 * @param ppCipherText   Pointer to the pointer which will be allocated by this
 *                       function and which will recieve the resulting ciphertext.
 * @param pCipherTextLen Pointer to the location that will recieve the byte length
 *                       of the resulting ciphertext.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaOaepEncrypt(
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
    );

/**
 * Perform RSA-OAEP decryption.
 *
 * @param pRSAKey        The RSA private key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pCipherText    The ciphertext to be decrypted
 * @param cLen           Length in bytes of the ciphertext to be decrypted.
 * @param pLabel         Optional label to use in the decoding.
 * @param lLen           Length in bytes of the label.
 * @param ppPlainText    Pointer to the pointer which will be allocated by this
 *                       function and which will recieve the resulting plaintext.
 * @param pPlainTextLen  Pointer to the location that will recieve the byte length
 *                       of the resulting plaintext.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaOaepDecrypt(
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
    );

/**
 * Use the provided RSA Key to sign some data using the PSS scheme.
 *
 * @param pRandomContext The random context to use for this operation.
 * @param pRSAKey        The RSA private key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be signed, note this is not the
 *                       digest of the data to be signed.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param saltLen        Length in bytes of the salt.
 * @param ppSignature    Pointer to the pointer which will be allocated by this
 *                       function and which will recieve the resulting signature.
 * @param pSignatureLen  Pointer to the location that will recieve the byte length
 *                       of the resulting signature.
 * @param pExtCtx        Extended Context for future use.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaPssSignExt (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen,
    void *pExtCtx
    );

/**
 * Use the provided RSA Key to sign some data using the PSS scheme.
 *
 * @param pRandomContext The random context to use for this operation.
 * @param pRSAKey        The RSA private key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be signed, note this is not the
 *                       digest of the data to be signed.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param saltLen        Length in bytes of the salt.
 * @param ppSignature    Pointer to the pointer which will be allocated by this
 *                       function and which will recieve the resulting signature.
 * @param pSignatureLen  Pointer to the location that will recieve the byte length
 *                       of the resulting signature.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaPssSign (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    );

/**
 * Use the provided RSA Key to verify a PSS signature.
 *
 * @param pRSAKey        The RSA public key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be verified, note this is not the
 *                       digest of the data to be verified.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param pSignature     Pointer to the signature to be verified.
 * @param signatureLen   Length in bytes of the signature value.
 * @param saltLen        Length in bytes of the salt.
 * @param pVerify        Pointer to the value which will recieve the verification
 *                       result, zero if it verified successfully, nonzero otherwise.
 * @param pExtCtx        Extended Context for future use.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaPssVerifyExt (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
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
    );

/**
 * Use the provided RSA Key to verify a PSS signature.
 *
 * @param pRSAKey        The RSA public key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use...
 *                       \c MOC_PKCS1_ALG_MGF1 or \c MOC_PKCS1_ALG_SHAKE
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be verified, note this is not the
 *                       digest of the data to be verified.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param pSignature     Pointer to the signature to be verified.
 * @param signatureLen   Length in bytes of the signature value.
 * @param saltLen        Length in bytes of the salt. Use -1 to retrieve saltLen from signature.
 * @param pVerify        Pointer to the value which will recieve the verification
 *                       result, zero if it verified successfully, nonzero otherwise.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS PKCS1_rsaPssVerify (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const RSAKey *pRSAKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    const ubyte *pMessage,
    ubyte4 mLen,
    const ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify
    );

#ifdef __cplusplus
}
#endif


#endif  /* __PKCS1_HEADER__ */
