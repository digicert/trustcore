/**
 * @file md4.h
 *
 * @brief Header file for declaring MD4 functions.
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


#ifndef __MD4_HEADER__
#define __MD4_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_md4_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MD4_DIGESTSIZE      16
#define MD4_RESULT_SIZE     16   /* synonym */

#define MD4_BLOCK_SIZE      (64)

/*------------------------------------------------------------------*/

/* MD4 context. */
typedef struct MD4_CTX {
  MocSymCtx pMocSymCtx;
  ubyte4 enabled;
  ubyte4 hashId;
  ubyte4 state[4];                                   /* state (ABCD) */
  ubyte4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  ubyte buffer[MD4_BLOCK_SIZE];              /* input buffer */
} MD4_CTX;


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MD4__

/**
 * Allocate a new MD4 context. It is the callers responsibility to free this
 * object after use by calling MD4Free.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Free a MD4 context previously allocated with MD4Alloc.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Initialize a MD4 context for a new digest operation.
 *
 * @param pCtx The MD4 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pCtx);

/**
 * Update a digest operation.
 *
 * @param pCtx     The digest context to be updated.
 * @param pData    The data to update the context with.
 * @param dataLen  Length in bytes of the update data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pCtx, const ubyte* pData, ubyte4 dataLen);

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pCtx     The digest context used to update the data.
 * @param pOutput  Buffer of size MD4_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4Final(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pCtx, ubyte pOutput[MD4_DIGESTSIZE]);

/**
 * Perform a MD4 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pOutput    Buffer of size MD4_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pOutput);

/**
 * Makes a clone of a previously allocated \c MD4_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD4_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pDest, MD4_CTX *pSrc);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __MD4_HEADER__ */
