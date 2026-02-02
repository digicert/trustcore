/*
 * blake2.h
 *
 * Blake2 hash or mac algorithms
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

#ifndef __BLAKE2_HEADER__
#define __BLAKE2_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_blake2_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------- BLAKE 2B ----------------------------------- */
    
#define MOC_BLAKE2B_BLOCKLEN  128
#define MOC_BLAKE2B_MAX_OUTLEN 64
#define MOC_BLAKE2B_MAX_KEYLEN 64

typedef struct BLAKE2B_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;
    ubyte8 pH[8];
    ubyte8 pT[2];
    ubyte8 f;
    ubyte pBuffer[MOC_BLAKE2B_BLOCKLEN];
    ubyte4 bufPos;
    ubyte4 outLen;

} BLAKE2B_CTX;

/**
 @brief      Allocates the \c BLAKE2B_CTX context data structure.
 
 @details    This method allocates a \c BLAKE2B_CTX context data structure for
             Blake 2b hashing or mac computation. Be sure to call \c BLAKE2B_delete
             to free memory when done.
 
 @param ppCtx  Double pointer to the \c BLAKE2B_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);
    
/**
 @brief      Initialize the \c BLAKE2B_CTX context data structure.
 
 @details    This method initializes a \c BLAKE2B_CTX context data structure for
             Blake 2b hashing or mac computation.
 
 @param pCtx    Pointer to the \c BLAKE2B_CTX context to be initialized.
 @param outLen  The desired output length. Valid values are from 1 to 64.
 @param pKey    (Optional) Pointer to the key if the context is to be used to
                compute a crytographic mac. For a cryptographic hash pass \c NULL.
 @param keyLen  The length of the key in bytes. Valid values are from 1 to 64.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen);

/**
 @brief      Updates a previously initialized \c BLAKE2B_CTX context with data.
 
 @details    This method updates a previously initialized \c BLAKE2B_CTX context
             data structure with input data. \c BLAKE2B_update may be called
             as many times as necessary.
 
 @param pCtx    Pointer to a previously initialized \c BLAKE2B_CTX context.
 @param pData   Pointer to the input data.
 @param dataLen The length of the buffer pData in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 @brief      Finalizes a \c BLAKE2B_CTX context and outputs the resulting hash or mac.
 
 @details    Finalizes a \c BLAKE2B_CTX context and outputs the resulting hash or mac.
 
 @param pCtx    Pointer to a previously initialized \c BLAKE2B_CTX context.
 @param pOutput Pointer to a buffer that will hold the resulting output. The buffer
                must be at least outLen bytes where outLen was the output length
                input to your call to \c BLAKE2B_init.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput);

/**
 @brief      A one-shot context free computation of a Blake 2b hash or mac.
 
 @details    A one-shot context free computation of a Blake 2b hash or mac.

 @param pKey    (Optional) Pointer to the key if the context is to be used to
                compute a crytographic mac. For a cryptographic hash pass NULL.
 @param keyLen  The length of the key in bytes. Valid values are from 1 to 64.
 @param pData   Pointer to the input data.
 @param dataLen The length of the buffer pData in bytes.
 @param pOutput Pointer to a buffer that will hold the resulting output. The buffer
                must be at least outLen bytes.
 @param outLen  The desired output length. Valid values are from 1 to 64.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
              definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen);

/**
 @brief      Deletes the \c BLAKE2B_CTX context data structure.
 
 @details    This method frees a \c BLAKE2B_CTX context data structure allocated
             by the \c BLAKE2B_alloc method.
 
 @param ppCtx Double pointer to the \c BLAKE2B_CTX context to be deleted.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);


/**
 * @brief Makes a clone of a previously allocated \c BLAKE2B_CTX.
 *
 * @details Makes a clone of a previously allocated \c BLAKE2B_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2B_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2B_CTX *pDest, BLAKE2B_CTX *pSrc);

/* ----------------------------------- BLAKE 2S ----------------------------------- */
    
#define MOC_BLAKE2S_BLOCKLEN   64
#define MOC_BLAKE2S_MAX_OUTLEN 32
#define MOC_BLAKE2S_MAX_KEYLEN 32

typedef struct BLAKE2S_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;
    ubyte4 pH[8];
    ubyte4 pT[2];
    ubyte4 f;
    ubyte pBuffer[MOC_BLAKE2S_BLOCKLEN];
    ubyte4 bufPos;
    ubyte4 outLen;
    
} BLAKE2S_CTX;

/**
 @brief      Allocates the \c BLAKE2S_CTX context data structure.
 
 @details    This method allocates a \c BLAKE2S_CTX context data structure for
             Blake 2s hashing or mac computation. Be sure to call \c BLAKE2S_delete
             to free memory when done.
 
 @param ppCtx Double pointer to the \c BLAKE2S_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);

/**
 @brief      Initialize the \c BLAKE2S_CTX context data structure.
 
 @details    This method initializes a \c BLAKE2S_CTX context data structure for
             Blake 2s hashing or mac computation.
 
 @param pCtx    Pointer to the \c BLAKE2S_CTX context to be initialized.
 @param outLen  The desired output length. Valid values are from 1 to 32.
 @param pKey    (Optional) Pointer to the key if the context is to be used to
                compute a crytographic mac. For a cryptographic hash pass \c NULL.
 @param keyLen  The length of the key in bytes. Valid values are from 1 to 32.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen);

/**
 @brief      Updates a previously initialized \c BLAKE2S_CTX context with data.
 
 @details    This method updates a previously initialized \c BLAKE2S_CTX context
             data structure with input data. \c BLAKE2S_update may be called
             as many times as necessary.
 
 @param pCtx    Pointer to a previously initialized \c BLAKE2S_CTX context.
 @param pData   Pointer to the input data.
 @param dataLen The length of the buffer pData in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 @brief      Finalizes a \c BLAKE2S_CTX context and outputs the resulting hash or mac.
 
 @details    Finalizes a \c BLAKE2S_CTX context and outputs the resulting hash or mac.
 
 @param pCtx    Pointer to a previously initialized \c BLAKE2S_CTX context.
 @param pOutput Pointer to a buffer that will hold the resulting output. The buffer
                must be at least outLen bytes where outLen was the output length
                input to your call to \c BLAKE2S_init.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput);

/**
 @brief      A one-shot context free computation of a Blake 2s hash or mac.
 
 @details    A one-shot context free computation of a Blake 2s hash or mac.
 
 @param pKey    (Optional) Pointer to the key if the context is to be used to
                compute a crytographic mac. For a cryptographic hash pass NULL.
 @param keyLen  The length of the key in bytes. Valid values are from 1 to 32.
 @param pData   Pointer to the input data.
 @param dataLen The length of the buffer pData in bytes.
 @param pOutput Pointer to a buffer that will hold the resulting output. The buffer
                must be at least outLen bytes.
 @param outLen  The desired output length. Valid values are from 1 to 32.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen);

/**
 @brief      Deletes the \c BLAKE2S_CTX context data structure.
 
 @details    This method frees a \c BLAKE2S_CTX context data structure allocated
             by the \c BLAKE2S_alloc method.
 
 @param ppCtx Double pointer to the \c BLAKE2S_CTX context to be deleted.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);

/**
 * @brief Makes a clone of a previously allocated \c BLAKE2S_CTX.
 *
 * @details Makes a clone of a previously allocated \c BLAKE2S_CTX.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS BLAKE2S_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2S_CTX *pDest, BLAKE2S_CTX *pSrc);

#ifdef __cplusplus
}
#endif

#endif /* __BLAKE2_HEADER__ */
