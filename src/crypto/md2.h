/*
 * md2.h
 *
 * Message Digest 2 (MD2) Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */


#ifndef __MD2_HEADER__
#define __MD2_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define MD2_DIGESTSIZE      16
#define MD2_RESULT_SIZE     16   /* synonym */

#define MD2_BLOCK_SIZE      (16)

/*------------------------------------------------------------------*/

typedef struct MD2_CTX {
  ubyte     state[16];
  ubyte     checksum[16];
  ubyte4    count;
  ubyte     buffer[MD2_BLOCK_SIZE];
} MD2_CTX;


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MD2__

/**
 * Allocate a new MD2 context. It is the callers responsibility to free this
 * object after use by calling MD2Free.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD2Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Free a MD2 context previously allocated with MD2Alloc.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD2Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Initialize a MD2 context for a new digest operation.
 *
 * @param pCtx The MD2 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD2Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pCtx);

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
MOC_EXTERN MSTATUS MD2Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pCtx     The digest context used to update the data.
 * @param pOutput  Buffer of size MD2_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD2Final(MOC_HASH(hwAccelDescr hwAccelCtx) MD2_CTX *pCtx, ubyte pOutput[MD2_DIGESTSIZE]);

/**
 * Perform a MD2 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pOutput    Buffer of size MD2_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD2_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pOutput);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __MD2_HEADER__ */
