/*
 * crypto_interface_sha3.h
 *
 * Header for sha3 operations.
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
@file       crypto_interface_sha3.h
@brief      Cryptographic Interface header file for declaring SHA3 functions.
@details    Add details here.

@filedoc    crypto_interface_sha3.h
*/

#ifndef __CRYPTO_INTERFACE_SHA3_HEADER__
#define __CRYPTO_INTERFACE_SHA3_HEADER__

#include "../crypto/sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @brief      Allocates the \c SHA3_CTX context data structure.
 
 @details    This method allocates a \c SHA3_CTX context data structure for
             SHA3 hashing or extendable output function computation. Be sure
             to call \c CRYPTO_INTERFACE_SHA3_freeDigest to free memory when done.
 
 @param pSha3_ctx  Double pointer to the \c SHA3_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx);


/**
 @brief      Initialize the \c SHA3_CTX context data structure.
 
 @details    This method initializes a \c SHA3_CTX context data structure for
             SHA3 hashing or extendable output function computation.
 
 @param pSha3_ctx  Pointer to the \c SHA3_CTX context to be initialized.
 @param mode       The SHA3 mode. This is one of the following macros...

                   + \c MOCANA_SHA3_MODE_SHA3_224
                   + \c MOCANA_SHA3_MODE_SHA3_256
                   + \c MOCANA_SHA3_MODE_SHA3_384
                   + \c MOCANA_SHA3_MODE_SHA3_512
                   + \c MOCANA_SHA3_MODE_SHAKE128
                   + \c MOCANA_SHA3_MODE_SHAKE256
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte4 mode);


/**
 @brief      Updates a previously initialized \c SHA3_CTX context with data.
 
 @details    This method updates a previously initialized \c SHA3_CTX context
             data structure with input data. \c CRYPTO_INTERFACE_SHA3_updateDigest may be called
             as many times as necessary.
 
 @param pSha3_ctx  Pointer to a previously initialized \c SHA3_CTX context.
 @param pMessage   Pointer to the input data.
 @param messageLen The length of the input data in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pMessage, ubyte4 messageLen);


/**
 @brief      Finalizes a \c SHA3_CTX context and outputs the resulting output.
 
 @details    Finalizes a \c SHA3_CTX context and outputs the resulting output.
 
 @param pSha3_ctx    Pointer to a previously initialized \c SHA3_CTX context.
 @param pResult      Pointer to a buffer that will hold the resulting output.
                     The buffer must have space for the number of output bytes
                     defined by the SHA3 hashing mode, or at least \c desiredResultLen
                     bytes of space for the SHA3 extendable output modes.
 @param desiredResultLen   The number of output bytes desired for SHA3 extendable
                           output modes. This value is ignored for SHA3 hashing modes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen);


/**
 @brief      Zeroes and frees the \c SHA3_CTX context data structure.
 
 @details    This method zeroes and frees the \c SHA3_CTX context data structure
             allocated by the \c CRYPTO_INTERFACE_SHA3_allocDigest method.
 
 @param pSha3_ctx   Double pointer to the \c SHA3_CTX context to be freed.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx);


/**
 @brief      A one-shot context free computation of a SHA3 hash or extenable output function.
 
 @details    A one-shot context free computation of a SHA3 hash or extenable output function.
 
 @param mode       The SHA3 mode. This is one of the following macros...
 
                   + \c MOCANA_SHA3_MODE_SHA3_224
                   + \c MOCANA_SHA3_MODE_SHA3_256
                   + \c MOCANA_SHA3_MODE_SHA3_384
                   + \c MOCANA_SHA3_MODE_SHA3_512
                   + \c MOCANA_SHA3_MODE_SHAKE128
                   + \c MOCANA_SHA3_MODE_SHAKE256
 
 @param pMessage   Pointer to the input data.
 @param messageLen The length of the input data in bytes.
 @param pResult    Pointer to a buffer that will hold the resulting output.
                   The buffer must have space for the number of output bytes
                   defined by the SHA3 hashing mode, or at least \c desiredResultLen
                   bytes of space for the SHA3 extendable output modes.
 @param desiredResultLen   The number of output bytes desired for SHA3 extendable
                           output modes. This value is ignored for SHA3 hashing modes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 mode, ubyte *pMessage, ubyte4 messageLen, ubyte *pResult, ubyte4 desiredResultLen);

/**
 * Makes a clone of a previously allocated \c SHA3_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pDest, SHA3_CTX *pSrc);

#ifdef __cplusplus
}
#endif
  
#endif /* __CRYPTO_INTERFACE_SHA3_HEADER__ */
