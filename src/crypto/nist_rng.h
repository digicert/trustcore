/**
 * @file nist_rng.h
 *
 * @brief Implementation of the RNGs described in NIST 800-90A
 * @filedoc nist_rng.h
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

/*------------------------------------------------------------------*/

#ifndef __NIST_RNG_HEADER__
#define __NIST_RNG_HEADER__

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_nist_ctr_drbg_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/*  Function prototypes  */
    /* CTR_DRBG */

/**
 * @brief    Allocate and initialize a new CTRDRBG context that is not using
 *           a derivation function.
 * @details  This function implements the CTR_DRBG_Instantiate_algorithm
 *           described in NIST SP 800-90A Rev1 10.2.1.3.1
 *
 * @param ppNewContext       Pointer to the address that will recieve the newly
 *                           allocated context.
 * @param entropyInput       Entropy to seed this DRBG with.  Must be equal to the
 *                           block length + key length.
 * @param keyLenBytes        Length in bytes of the key material to use, sets the
 *                           security strength of the DRBG. For example 16 for AES-128
 *                           and 32 for AES-256.
 * @param outLenBytes        Block length of the underlying block cipher to be used
 *                           for this CTRDRBG instantiation. Must be 8 to use triple
 *                           DES or 16 to use AES.
 * @param personalization    Optional personalization string.
 * @param personalizationLen Length in bytes of the personalization string.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_newContext(MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext **ppNewContext,
                            const ubyte* entropyInput,
                            ubyte4 keyLenBytes, ubyte4 outLenBytes,
                            const ubyte* personalization,
                            ubyte4 personalizationLen);

/**
 * @brief    Allocate and initialize a new CTRDRBG context that is using
 *           a derivation function.
 * @details  This function implements the CTR_DRBG_Instantiate_algorithm
 *           described in NIST SP 800-90A Rev1 10.2.1.3.2
 *
 * @param ppNewContext       Pointer to the address that will recieve the newly
 *                           allocated context.
 * @param keyLenBytes        Length in bytes of the key material to use, sets the
 *                           security strength of the DRBG. For example 16 for AES-128
 *                           and 32 for AES-256.
 * @param outLenBytes        Block length of the underlying block cipher to be used
 *                           for this CTRDRBG instantiation. Must be 8 to use triple
 *                           DES or 16 to use AES.
 * @param entropyInput       Entropy to seed this DRBG with.
 * @param entropyInputLen    Length in bytes of the entropy material. Must be
 *                           sufficient to support the given key length, see
 *                           NIST SP 800-90A Rev1 10.2.1 Table 3 for more info.
 * @param nonce              Optional nonce.
 * @param nonceLen           Length in bytes of the nonce.
 * @param personalization    Optional personalization string.
 * @param personalizationLen Length in bytes of the personalization string.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_newDFContext(MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext **ppNewContext,
                            ubyte4 keyLenBytes, ubyte4 outLenBytes,
                            const ubyte* entropyInput, ubyte4 entropyInputLen,
                            const ubyte* nonce, ubyte4 nonceLen,
                            const ubyte* personalization,
                            ubyte4 personalizationLen);

/**
 * @brief  Clear and free a previously instantiated CTRDRBG context
 *
 * @param ppNewContext  Pointer to the context to be freed.
 *
 * @return              \c OK (0) if successful; otherwise a negative number
 *                      error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_deleteContext( MOC_SYM(hwAccelDescr hwAccelCtx)
                                               randomContext **ppNewContext);

/**
 * @brief Reseed a previously instantiated CTRDRBG context.
 *
 * @param pContext           Context to be reseeded.
 * @param entropyInput       Entropy input to use for this reseed.
 * @param entropyInputLen    Length in bytes of the input entropy material.
 *                           See NIST SP 800-90A Rev1 10.2.1 Table 3 for more info.
 * @param additionalInput    Optional additional input to use for the reseed.
 * @param additionalInputLen Length in bytes of the additional input.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_reseed(MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext *pContext,
                            const ubyte* entropyInput,
                            ubyte4 entropyInputLen,
                            const ubyte* additionalInput,
                            ubyte4 additionalInputLen);

/**
 * @brief Generate random data with optional additional input.
 *
 * @param pContext           Context to use to generate the random data.
 * @param additionalInput    Optional additional input to use for the reseed.
 * @param additionalInputLen Length in bytes of the additional input.
 * @param output             Pointer to the caller allocated output buffer.
 * @param outputLenBits      Length in bits of random data to generate.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_generate(MOC_SYM(hwAccelDescr hwAccelCtx)
                                        randomContext* pContext,
                                        const ubyte* additionalInput, ubyte4 additionalInputLen,
                                        ubyte* output, ubyte4 outputLenBits);

/**
 * @brief Generate random data.
 *
 * @param pContext           Context to use to generate the random data.
 * @param pBuffer            Pointer to the caller allocated output buffer.
 * @param bufSize            Length in bytes of random data to generate.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_numberGenerator(MOC_SYM(hwAccelDescr hwAccelCtx)
                                        randomContext *pRandomContext,
                                        ubyte *pBuffer, sbyte4 bufSize);

/**
 * @brief   Callback function to generate random data.
 * @details There are many functions that take in a RNG callback to get random
 *          data, this function is a wrapper to fit the callback signature.
 *
 * @param rngFunArg          Argument to the callback, in practice it is
 *                           typically a CTRDRBG context.
 * @param length             Length in bytes of random data to generate.
 * @param buffer             Pointer to the caller allocated output buffer.
 *
 * @return                   \c OK (0) if successful; otherwise a negative number
 *                           error code definition from merrors.h.
 */
MOC_EXTERN sbyte4 NIST_CTRDRBG_rngFun(MOC_SYM(hwAccelDescr hwAccelCtx)
                                        void* rngFunArg,
                                        ubyte4 length, ubyte *buffer);


#ifdef __FIPS_OPS_TEST__

/**
 * @internal
 * @dontshow
 */
MOC_EXTERN void triggerDRBGFail(void);

/**
 * @internal
 * @dontshow
 */
MOC_EXTERN void resetDRBGFail(void);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __NIST_RNG_HEADER__ */

