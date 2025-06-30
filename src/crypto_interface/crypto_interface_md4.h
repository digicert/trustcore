/*
 * crypto_interfaced_md4.h
 *
 * Cryptographic Interface header file for declaring MD4 functions
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
@file       crypto_interface_md4.h
@brief      Cryptographic Interface header file for declaring MD4 functions.
@details    Add details here.

@filedoc    crypto_interface_md4.h
*/
#ifndef __CRYPTO_INTERFACE_MD4_HEADER__
#define __CRYPTO_INTERFACE_MD4_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a new MD4 context. It is the callers responsibility to free this
 * object after use by calling \c CRYPTO_INTERFACE_MD4Free.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Alloc (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );

/**
 * Initialize a MD4 context for a new digest operation.
 *
 * @param pContext The MD4 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Init (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Update (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext,
  const ubyte *pData,
  ubyte4 dataLen
  );

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pContext The digest context used to update the data.
 * @param pOutput  Buffer of size \c MD4_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Final (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext,
  ubyte pOutput[MD4_DIGESTSIZE]
  );


/**
 * Perform a MD4 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pOutput    Buffer of size \c MD4_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pOutput
  );

/**
 * Free a MD4 context previously allocated with \c CRYPTO_INTERFACE_MD4Alloc.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Free (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  );

/**
 * Makes a clone of a previously allocated \c MD4_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
 MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pDest, 
  MD4_CTX *pSrc
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_MD4_HEADER__ */
