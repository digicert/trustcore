/*
 * crypto_interface_nist_ctr_drbg.h
 *
 * Cryptographic Interface header file for declaring NIST CTR DRBG functions
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
@file       crypto_interface_nist_ctr_drbg.h
@brief      Cryptographic Interface header file for declaring NIST CTR DRBG functions.
@details    Add details here.

@filedoc    crypto_interface_nist_ctr_drbg.h
*/
#ifndef __CRYPTO_INTERFACE_NIST_CTR_DRBG_HEADER__
#define __CRYPTO_INTERFACE_NIST_CTR_DRBG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates and seeds a new random context of NIST Counter DRBG type
 * with no derivation function.
 *
 * @param ppNewContext       Pointer to the location that will receive the new context.
 * @param pEntropyInput      The seed. This must be keyLenBytes + outLenBytes in length.
 * @param keyLenBytes        The length of the block cipher key in bytes. This is
 *                           typically 16, 24, or 32 for AES and 21 for 3DES.
 * @param outLenBytes        The block size of the block cipher, 16 for AES, 8 for 3DES.
 * @param pPersonalization   The personalization string. This is optional and may be NULL.
 * @param personalizationLen The length of the personalization string in bytes. This
 *                           may not be bigger than keyLenBytes + outLenBytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_newContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppNewContext,
    const ubyte *pEntropyInput,
    ubyte4 keyLenBytes,
    ubyte4 outLenBytes,
    const ubyte *pPersonalization,
    ubyte4 personalizationLen
    );

/**
 * Creates and seeds a new random context of NIST Counter DRBG type
 * with the derivation function.
 *
 * @param ppNewContext       Pointer to the location that will receive the new context.
 * @param keyLenBytes        The length of the block cipher key in bytes. This is
 *                           typically 16, 24, or 32 for AES and 21 for 3DES.
 * @param outLenBytes        The block size of the block cipher, 16 for AES, 8 for 3DES.
 * @param pEntropyInput      The seed. This is required.
 * @param entropyInputLen    The length of the seed in bytes.
 * @param pNonce             The nonce. This is optional and may be NULL.
 * @param nonceLen           The length of the nonce in bytes.
 * @param pPersonalization   The personalization string. This is optional and may be NULL.
 * @param personalizationLen The length of the personalization string in bytes. No
 *                           restriction on this length.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_newDFContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppNewContext,
    ubyte4 keyLenBytes,
    ubyte4 outLenBytes,
    const ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    const ubyte *pNonce,
    ubyte4 nonceLen,
    const ubyte *pPersonalization,
    ubyte4 personalizationLen
    );

/**
 * Deletes a NIST Counter DRBG type context.
 *
 * @param ppContext Pointer to the location that holds the context to be deleted.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppContext
    );

/**
 * Reseeds a NICE counter DRBG type context.
 *
 * @param pContext           Pointer to the context to be reseeded.
 * @param pEntropyInput      The new seed.
 * @param entropyInputLen    The length of the new seed in bytes.
 * @param pAdditionalInput   Additional input. This is optional and may be NULL.
 * @param additionalInputLen The length of the additional input in bytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_reseed(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    const ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    const ubyte *pAdditionalInput,
    ubyte4 additionalInputLen
    );

/**
 * Generates determinstic random bits from a previously initialized context.
 *
 * @param pContext           Pointer to an initialized randomContext.
 * @param pAdditionalInput   Additional input. This is optional and may be NULL.
 * @param additionalInputLen The length of the additional input in bytes.
 * @param pOutput            Buffer to hold the resulting deterministic bits.
 *                           There should be enough space in this buffer to hold
 *                           the number of requested bits rounded up to the
 *                           next byte (ie multiple of 8).
 * @param outputLenBits      The number of bits requested.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_generate(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    const ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pOutput,
    ubyte4 outputLenBits
    );

/**
 * Generates determinstic random bytes from a previously initialized context.
 * This API does not allow the caller to pass in any additional entropy. Use
 * CRYPTO_INTERFACE_NIST_CTRDRBG_generate to pass in additional entropy.
 *
 * IMPORTANT: This API takes in a byte length for the output buffer as opposed
 * to CRYPTO_INTERFACE_NIST_CTRDRBG_generate which takes in a bit length for
 * the output buffer.
 *
 * @param pContext           Pointer to an initialized randomContext.
 * @param pOutput            Buffer to hold the resulting deterministic bytes.
 *                           There should be enough space in this buffer to hold
 *                           the number of requested bytes.
 * @param outputLenBytes     The number of bytes requested.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_numberGenerator(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    ubyte *pOutput,
    sbyte4 outputLenBytes
    );

/**
 * Generates a "secret" which consist of the internal state, ie the V and key,
 * followed by the deterministic random bits that can be generated by that state.
 *
 * @param pContext  Pointer to an initialized randomContext.
 * @param pSecret   Pointer to a buffer that will hold the resulting secret.
 * @param secretLen The length of the secret you desire. This must be at least
 *                  the length of the key plus the output length.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_generateSecret(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext* pContext,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pSecret,
    ubyte4 secretLen
    );

/**
 * Sets the state of a context to the state within the secret passed in. The
 * rest of the secret will be verified that it contains the deterministic bits
 * that can be generated from that state and the state will be incrememted to
 * the next state.
 *
 * @param pContext  Pointer to an initialized randomContext.
 * @param pSecret   Pointer to a buffer containing a secret.
 * @param secretLen The length of the pSecret buffer in bytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_setStateFromSecret(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext* pContext,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pSecret,
    ubyte4 secretLen
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_NIST_CTR_DRBG_HEADER__ */
