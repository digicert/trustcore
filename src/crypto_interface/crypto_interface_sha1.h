/*
 * crypto_interface_sha1.h
 *
 * Cryptographic Interface header file for declaring SHA1 functions
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
@file       crypto_interface_sha1.h
@brief      Cryptographic Interface header file for declaring SHA1 functions.
@details    Add details here.

@filedoc    crypto_interface_sha1.h
*/
#ifndef __CRYPTO_INTERFACE_SHA1_HEADER__
#define __CRYPTO_INTERFACE_SHA1_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a new SHA1 context. It is the callers responsibility to free this
 * object after use by calling \c CRYPTO_INTERFACE_SHA1_freeDigest.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_allocDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );

/**
 * Initialize a SHA1 context for a new digest operation.
 *
 * @param pContext The SHA1 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext
  );

/**
 * Update a digest operation.
 *
 * @param pContext The digest context to be updated.
 * @param pData    The data to update the context with.
 * @param dataLen  Length in bytes of the update data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_updateDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext,
  const ubyte *pData,
  ubyte4 dataLen
  );

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pContext The digest context used to update the data.
 * @param pOutput  Buffer of size \c SHA_HASH_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext,
  ubyte *pOutput
  );

/**
 * Perform a SHA1 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pShaOutput Buffer of size \c SHA_HASH_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  );

/**
 * Free a SHA1 context previously allocated with \c CRYPTO_INTERFACE_SHA1_allocDigest.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_freeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );


/**
 * Makes a clone of a previously allocated \c SHA1_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pDest, 
  SHA1_CTX *pSrc
  );

/**
 * Custom SHA1 for the Mocana RNG.
 *
 * @param pData   Data to process.
 * @param pOutput Buffer that will recieve the result.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_G (
  ubyte *pData,
  ubyte *pOutput
  );
  
/**
 * Second Custom SHA1 for the Mocana RNG.
 *
 * @param pData   Data to process.
 * @param pOutput Buffer that will recieve the result.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_GK (
  ubyte *pData,
  ubyte *pOutput
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA1_HEADER__ */
