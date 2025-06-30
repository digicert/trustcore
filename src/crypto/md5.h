/*
 * md5.h
 *
 * MD5 Message Digest Algorithm
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

#ifndef __MD5_HEADER__
#define __MD5_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_md5_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGESTSIZE      (16)
#define MD5_RESULT_SIZE     (16)    /* synonym */
#define MD5_BLOCK_SIZE      (64)

/* MD5 context. */
#ifndef __CUSTOM_MD5_CONTEXT__

typedef struct MD5_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

    ubyte4  hashBlocks[4];
    ubyte8  mesgLength;

    sbyte4  hashBufferIndex;
    ubyte   hashBuffer[64];

#ifdef __ENABLE_MOCANA_MINIMUM_STACK__
    ubyte4  M[16];
#endif

} MD5_CTX, MD5_CTXHS;

#endif

/**
 * Allocate a new MD5 context. It is the callers responsibility to free this
 * object after use by calling MD5Free_m.
 *
 * @param pp_context On return, pointer to the address of the allocated context.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5Alloc_m        (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Free a MD5 context previously allocated with MD5Alloc_m.
 *
 * @param pp_context Context to be freed.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5Free_m         (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * Initialize a MD5 context for a new digest operation.
 *
 * @param pCtx The MD5 context to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5Init_m         (MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pCtx);

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
MOC_EXTERN MSTATUS MD5Update_m       (MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
 * Finalize a digest operation and recieve the result.
 *
 * @param pCtx     The digest context used to update the data.
 * @param pOutput  Buffer of size MD5_RESULT_SIZE that will
 *                 recieve the digest.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5Final_m        (MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pCtx, ubyte pOutput[MD5_DIGESTSIZE]);

/**
 * Perform a MD5 digest in one step.
 *
 * @param pData      Data to digest.
 * @param dataLen    Length in bytes of the data to digest.
 * @param pOutput    Buffer of size MD5_RESULT_SIZE that will recieve
 *                   the digest.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pOutput);

/**
 * Makes a clone of a previously allocated \c MD5_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS MD5_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pDest, MD5_CTX *pSrc);

#ifdef __MD5_HARDWARE_HASH__
MOC_EXTERN MSTATUS MD5init_HandShake  (MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTXHS*);
MOC_EXTERN MSTATUS MD5update_HandShake(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTXHS*, const ubyte *, ubyte4);
MOC_EXTERN MSTATUS MD5final_HandShake (MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTXHS*, ubyte [MD5_DIGESTSIZE]);
#else

#define MD5init_HandShake   MD5Init_m
#define MD5update_HandShake MD5Update_m
#define MD5final_HandShake  MD5Final_m
#endif

#ifdef __cplusplus
}
#endif

#endif
