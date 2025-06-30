/*
 * crypto_interface_pkcs1.h
 *
 * Cryptographic Interface header file for declaring PKCS1 functions
 * for the Crypto Interface.
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
@file       crypto_interface_pkcs1.h
@brief      Cryptographic Interface header file for declaring PKCS1 functions.
@details    Add details here.

@filedoc    crypto_interface_pkcs1.h
*/
#ifndef __CRYPTO_INTERFACE_PKCS1_HEADER__
#define __CRYPTO_INTERFACE_PKCS1_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perform RSA-OAEP encryption.
 *
 * @param pRandomContext The random context to use for this operation.
 * @param pRSAKey        The RSA public key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
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
    );

/**
 * Perform RSA-OAEP decryption.
 *
 * @param pRSAKey        The RSA private key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(
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
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssSignExt (
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
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssSign (
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
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be verified, note this is not the
 *                       digest of the data to be verified.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param pSignature     Pointer to the signature to be verified.
 * @param signatureLen   Length in bytes of the signature value.
 * @param saltLen        Length in bytes of the salt. Pass in -1 if the salt
 *                       length should be calculated rather than verified.
 * @param pVerify        Pointer to the value which will recieve the verification
 *                       result, zero if it verified successfully, nonzero otherwise.
 * @param pExtCtx        Extended Context for future use.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (
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
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this function
 *                       currently only supports MOC_PKCS1_ALG_MGF1.
 * @param mgfHashAlgo    The hash algorithm to use for the MGF. Typically the MGF
 *                       uses the same hashAlgo.
 * @param pMessage       The plaintext message to be verified, note this is not the
 *                       digest of the data to be verified.
 * @param mLen           Length in bytes of the input message to be signed.
 * @param pSignature     Pointer to the signature to be verified.
 * @param signatureLen   Length in bytes of the signature value.
 * @param saltLen        Length in bytes of the salt. Pass in -1 if the salt
 *                       length should be calculated rather than verified.
 * @param pVerify        Pointer to the value which will recieve the verification
 *                       result, zero if it verified successfully, nonzero otherwise.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS1_rsaPssVerify (
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



/**
 * Use the provided RSA Key to verify a PSS signature.
 *
 * @param hwAccelCtx     Hardware acceleration context.
 * @param pRSAKey        The RSA public key to use for this operation.
 * @param H_rsaAlgoId    The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param MGF            The Mask Generation Function (MGF) to use in function pointer form.
 * @param pMessage       The plaintext message to be verified, note this is not the
 *                       digest of the data to be verified.
 * @param mesgLen        Length in bytes of the input message to be signed.
 * @param pSignature     Pointer to the signature to be verified.
 * @param signatureLen   Length in bytes of the signature value.
 * @param saltLen        Length in bytes of the salt. Pass in -1 if the salt
 *                       length should be calculated rather than verified.
 * @param pRetIsSignatureValid  Contents will be set to TRUE for a valid signature 
 *                              and FALSE otherwise.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
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
    );

/**
 * @brief      Generate an MGF1 mask based on a given hash function, as defined in
 *             RFC&nbsp;3447.
 *
 * @details    This function generates an MGF1 mask mask of a given length, based
 *             a given hash function, as defined in RFC&nbsp;3447.
 *
 * @ingroup    pkcs_functions
 *
 * @inc_file pkcs1.h
 *
 * @param  hwAccelCtx  Hardware acceleration context.
 * @param  mgfSeed     Seed generated from a pRandomContext.
 * @param  mgfSeedLen  Number of bytes in the MGF seed, \p mgfSeed.
 * @param  maskLen     Number of bytes in the returned mask, \p ppRetMask.
 * @param  H           Hash function.
 * @param  ppRetMask   On return, pointer to address of generated mask.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc crypto_interface_pkcs1.c
 **/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_PKCS1_MGF1(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const ubyte *mgfSeed,
    ubyte4 mgfSeedLen,
    ubyte4 maskLen,
    BulkHashAlgo *H,
    ubyte **ppRetMask
    );

/**
 * Used to generated RSA-PSS padded data. This API does NOT perform the RSA sign
 * operation on the padded data.
 *
 * @param pKey           The RSA key to use for this operation.
 * @param hashAlgo       The hash algorithm to use for this operation, must be one
 *                       of the ht_sha* values in crypto.h
 * @param rngFun         The RNG function pointer used to generated random
 *                       bytes.
 * @param rngFunArg      The RNG function pointer argument.
 * @param M              The plaintext message to be padded.
 * @param mLen           Length in bytes of the input message to be padded.
 * @param sLen           Length in bytes of the salt.
 * @param hashAlgo       RSA-PSS hash algorithm to use.
 * @param mgfAlgo        The Mask Generation Function (MGF) to use, this
 *                       function currently only supports MOC_PKCS1_ALG_MGF1.
 * @param mgfHashAlgo    MGF1 hash algorithm. Must be the same as the message
 *                       hash algorithm.
 * @param ppRetEM        Pointer to the pointer which will be allocated by this
 *                       function and which will recieve the resulting RSA-PSS
 *                       encoded message.
 * @param pRetEMLen      Pointer to the location that will recieve the byte
 *                       length of the resulting RSA-PSS encoded message.
 *
 * @return               \c OK (0) if successful; otherwise a negative number
 *                       error code definition from merrors.h.
 */
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
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_PKCS1_HEADER__ */
