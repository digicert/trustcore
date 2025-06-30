/*
 * crypto_interface_blake2.h
 *
 * Cryptographic Interface header file for declaring Blake2 methods
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
@file       crypto_interface_blake2.h
@brief      Cryptographic Interface header file for declaring Blake2 methods.
@details    Add details here.

@filedoc    crypto_interface_blake2.h
*/
#ifndef __CRYPTO_INTERFACE_BLAKE2_HEADER__
#define __CRYPTO_INTERFACE_BLAKE2_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 @brief      Allocates the \c BLAKE2B_CTX context data structure.
 
 @details    This method allocates a \c BLAKE2B_CTX context data structure for
             Blake 2b hashing or mac computation. Be sure to call \c BLAKE2B_delete
             to free memory when done.
 
 @param ppCtx  Double pointer to the \c BLAKE2B_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);
    
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen);

/**
 @brief      Deletes the \c BLAKE2B_CTX context data structure.
 
 @details    This method frees a \c BLAKE2B_CTX context data structure allocated
             by the \c BLAKE2B_alloc method.
 
 @param ppCtx Double pointer to the \c BLAKE2B_CTX context to be deleted.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);


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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2B_CTX *pDest, BLAKE2B_CTX *pSrc);
    
/* ----------------------------------- BLAKE 2S ----------------------------------- */


/**
 @brief      Allocates the \c BLAKE2S_CTX context data structure.
 
 @details    This method allocates a \c BLAKE2S_CTX context data structure for
             Blake 2s hashing or mac computation. Be sure to call \c BLAKE2S_delete
             to free memory when done.
 
 @param ppCtx Double pointer to the \c BLAKE2S_CTX context to be allocated.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen);

/**
 @brief      Deletes the \c BLAKE2S_CTX context data structure.
 
 @details    This method frees a \c BLAKE2S_CTX context data structure allocated
             by the \c BLAKE2S_alloc method.
 
 @param ppCtx Double pointer to the \c BLAKE2S_CTX context to be deleted.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);

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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2S_CTX *pDest, BLAKE2S_CTX *pSrc);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_BLAKE2_HEADER__ */
