/*
 * aes_mmo.h
 *
 * AES-MMO - AES-MMO Hash Algorithm Header
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
 * @file       aes_mmo.h
 *
 * @brief      Header file for declaring AES Matyas-Meyer-Oseas (MMO) hash functions.
 * @details    Header file for declaring AES Matyas-Meyer-Oseas (MMO) hash functions.
 *
 * @filedoc    aes_mmo.h
 */

/*------------------------------------------------------------------*/

#ifndef __AES_MMO_HEADER__
#define __AES_MMO_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*--------------------------------------------------------------------------------*/

#define AES_MMO_DIGESTSIZE      AES_BLOCK_SIZE
#define AES_MMO_BLOCK_SIZE      AES_BLOCK_SIZE


/*------------------------------------------------------------------*/

typedef struct AES_MMO_CTX
{
    ubyte   hashKey[AES_MMO_BLOCK_SIZE];
    ubyte   hashBuffer[AES_MMO_BLOCK_SIZE];
    ubyte4  hashBufferIndex;
    ubyte4  mesgLength;

} AES_MMO_CTX;


/*------------------------------------------------------------------*/

/**
 * @brief   Allocates a new AES-MMO context.
 *
 * @details Allocates a new AES-MMO context. Be sure to call \c AES_MMO_freeDigest
 *          in order to free the memory when done with the context.
 *
 * @param pp_context   Pointer to the location of the newly allocated context.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_allocDigest(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * @brief   Deletes a new AES-MMO context.
 *
 * @details Deletes a and frees the memory for an AES-MMO context.
 *
 * @param pp_context   Pointer to the location of the context to be deleted.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_freeDigest(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
 * @brief   Initializes an AES-MMO context.
 *
 * @details Initializes an AES-MMO context. This zeroes the context but does not free allocated memory.
 *
 * @param pAesMmoCtx    Pointer to the context to be initialized.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_initDigest(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx);

/**
 * @brief   Updates an AES-MMO context with a buffer of data.
 *
 * @details Updates an AES-MMO context with a buffer of data. This may be called as
 *          many times as necessary.
 *
 * @param pAesMmoCtx    Pointer to a previously initialized context.
 * @param pData         Buffer of data to be digested.
 * @param dataLen       The length of the data in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_updateDigest(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx, const ubyte *pData, ubyte4 dataLen);

/**
 * @brief   Finalizes an AES-MMO context and outputs the resulting hash.
 *
 * @details Finalizes an AES-MMO context and outputs the resulting hash.
 *
 * @param pAesMmoCtx    Pointer to a previously initialized and updated context.
 * @param pHashOutput   Buffer to hold the resulting hash. This must be 16 bytes in length.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_final(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx, ubyte *pHashOutput);

/**
 * @brief   Performs the AES-MMO hash in a context free one-shot style.
 *
 * @details Performs the AES-MMO hash in a context free one-shot style.
 *
 * @param pData         Buffer of data to be digested.
 * @param dataLen       The length of the data in bytes.
 * @param pHashOutput   Buffer to hold the resulting hash. This must be 16 bytes in length.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_MMO_completeDigest(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pHashOutput);

#ifdef __cplusplus
}
#endif

#endif /* __AES_MMO_HEADER__ */
