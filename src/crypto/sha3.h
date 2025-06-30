/*
 * sha3.h
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
 * @file       sha3.h
 *
 * @brief      Documentation file for the SHA3 APIs.
 *
 * @details    This file documents the APIs used for SHA3 hashing and extenable output.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_MOCANA_SHA3__
 *
 * @filedoc    sha3.h
 */

#ifndef __SHA3_HEADER__
#define __SHA3_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha3_priv.h"
#endif

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The size of the SHA3_512 digest output */
#define SHA3_512_RESULT_SIZE    (64)
#define SHA3_512_BLOCK_SIZE     (72)

/** The size of the SHA3_384 digest output */
#define SHA3_384_RESULT_SIZE    (48)
#define SHA3_384_BLOCK_SIZE     (104)
  
/** The size of the SHA3_256 digest output */
#define SHA3_256_RESULT_SIZE    (32)
#define SHA3_256_BLOCK_SIZE     (136)

/** The size of the SHA3_224 digest output */
#define SHA3_224_RESULT_SIZE    (28)
#define SHA3_224_BLOCK_SIZE     (144)

/** RSA and ECC default output lengths for SHAKE used as a hash */
#define SHAKE128_RESULT_SIZE (32)
#define SHAKE128_BLOCK_SIZE (168)

#define SHAKE256_RESULT_SIZE (64)
#define SHAKE256_BLOCK_SIZE (136)

#define MOCANA_SHA3_MODE_SHA3_224 0
#define MOCANA_SHA3_MODE_SHA3_256 1
#define MOCANA_SHA3_MODE_SHA3_384 2
#define MOCANA_SHA3_MODE_SHA3_512 3
#define MOCANA_SHA3_MODE_SHAKE128 4
#define MOCANA_SHA3_MODE_SHAKE256 5
  
typedef struct SHA3_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

    ubyte4 mode;
    ubyte pBuffer[168]; /* Big enough for every mode, shake128's block size  */
    ubyte4 position;
    ubyte8 pState[5][5]; /* 1600 bit cube */
    byteBoolean initialized;

} SHA3_CTX;


/**
 @brief      Allocates the \c SHA3_CTX context data structure.
 
 @details    This method allocates a \c SHA3_CTX context data structure for
             SHA3 hashing or extendable output function computation. Be sure
             to call \c SHA3_freeDigest to free memory when done.
 
 @param pSha3_ctx  Double pointer to the \c SHA3_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx);


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
MOC_EXTERN MSTATUS SHA3_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte4 mode);


/**
 @brief      Updates a previously initialized \c SHA3_CTX context with data.
 
 @details    This method updates a previously initialized \c SHA3_CTX context
             data structure with input data. \c SHA3_updateDigest may be called
             as many times as necessary.
 
 @param pSha3_ctx  Pointer to a previously initialized \c SHA3_CTX context.
 @param pMessage   Pointer to the input data.
 @param messageLen The length of the input data in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pMessage, ubyte4 messageLen);


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
                           If plannig to use \c SHA3_additionalXOF after use of this API,
                           the desiredResultLen MUST be a non-zero multiple of the rate in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen);


/**
 @brief      Zeroes and frees the \c SHA3_CTX context data structure.
 
 @details    This method zeroes and frees the \c SHA3_CTX context data structure
             allocated by the \c SHA3_allocDigest method.
 
 @param pSha3_ctx   Double pointer to the \c SHA3_CTX context to be freed.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx);


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
MOC_EXTERN MSTATUS SHA3_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 mode, ubyte *pMessage, ubyte4 messageLen, ubyte *pResult, ubyte4 desiredResultLen);


/**
 * @brief Makes a clone of a previously allocated \c SHA3_CTX.
 * @details Makes a clone of a previously allocated \c SHA3_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pDest, SHA3_CTX *pSrc);


/**
 @brief      Computes additioanl output from a \c SHA3_CTX in an XOF mode.
 
 @details    Computes additioanl output from a \c SHA3_CTX in an XOF mode.
 
 @param pSha3_ctx    Pointer to a previously initialized \c SHA3_CTX context for an XOF mode.
 @param pResult      Pointer to a buffer that will hold the resulting output.
                     The buffer must have space for the number of output bytes
                     desired.
 @param desiredResultLen   The number of output bytes desired for SHA3 extendable
                           output modes. This must be a non-zero multiple of the rate
                           in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS SHA3_additionalXOF(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen);

#ifdef __cplusplus
}
#endif
  
#endif /* __SHA3_HEADER__ */
