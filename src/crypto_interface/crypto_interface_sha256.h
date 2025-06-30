/*
 * crypto_interface_sha256.h
 *
 * Cryptographic Interface header file for declaring SHA256 functions
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
@file       crypto_interface_sha256.h
@brief      Cryptographic Interface header file for declaring SHA256 functions.
@details    Add details here.

@filedoc    crypto_interface_sha256.h
*/
#ifndef __CRYPTO_INTERFACE_SHA256_HEADER__
#define __CRYPTO_INTERFACE_SHA256_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a new SHA context. Note that SHA224 and SHA256 share this function.
 * It is the callers responsibility to free this object after use by calling
 * \c CRYPTO_INTERFACE_SHA256_freeDigest.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_allocDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );

/**
 * Initialize a SHA224 context for a new digest operation.
 *
 * @param pContext The SHA224 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA224_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pContext
  );

/**
 * Initialize a SHA256 context for a new digest operation.
 *
 * @param pContext The SHA256 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pContext
  );

/**
 * Update a digest operation. Note that SHA224 and SHA256 share this function.
 *
 * @param pContext The digest context to be updated.
 * @param pData    The data to update the context with.
 * @param dataLen  Length in bytes of the update data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_updateDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pContext,
  const ubyte *pData,
  ubyte4 dataLen
  );

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pContext The digest context used to update the data.
 * @param pOutput  Buffer of size \c SHA224_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA224_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pContext,
  ubyte *pOutput
  );

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pContext The digest context used to update the data.
 * @param pOutput  Buffer of size \c SHA256_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pContext,
  ubyte *pOutput
  );

/**
 * Perform a SHA224 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pShaOutput Buffer of size \c SHA224_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA224_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  );

/**
 * Perform a SHA256 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pShaOutput Buffer of size \c SHA256_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  );

/**
 * Free a SHA224 or SHA256 context previously allocated with
 * \c CRYPTO_INTERFACE_SHA1_allocDigest.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_freeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );

/**
 * Makes a clone of a previously allocated \c SHA224_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
 MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA224_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pDest, 
  SHA224_CTX *pSrc
  );

/**
 * Makes a clone of a previously allocated \c SHA256_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
 MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA256_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pDest, 
  SHA256_CTX *pSrc
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA256_HEADER__ */