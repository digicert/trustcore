/*
 * crypto_interface_des.h
 *
 * Cryptographic Interface header file for declaring DES functions
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
@file       crypto_interface_des.h
@brief      Cryptographic Interface header file for declaring DES functions.

@filedoc    crypto_interface_des.h
*/
#ifndef __CRYPTO_INTERFACE_DES_HEADER__
#define __CRYPTO_INTERFACE_DES_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a raw DES-ECB object for operation. Note that this should only
 * be used when constructing a larger cryptographic scheme that requires a
 * DES-ECB primitive. It is the callers responsibility to delete
 * this context after use by calling CRYPTO_INTERFACE_DES_clearKey.
 *
 * @param pCtx   Pointer to a caller allocated DES-ECB context to be initialized.
 * @param pKey   Key material to use for this operation.
 * @param keyLen Length in bytes of key material to use, must be exactly 8 bytes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_initKey(DES_CTX *pCtx, const ubyte *pKey, sbyte4 keyLen);

/**
 * Encrypts data using the provided DES context. The data length must be
 * a multiple of the blocksize of 8 bytes.
 *
 * @param pCtx     A previously initialized context to use for the cipher operation.
 * @param pSrc     Buffer of the data to encrypt.
 * @param pDest    Buffer to hold the resulting ciphertext. This must be at least
 *                 the same length as pSrc.
 * @param numBytes Length in bytes of the buffer pSrc. Must be a multiple of the
 *                 DES blocksize of 8 bytes.
 *
 * Note that you can NOT reuse a DES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_encipher(DES_CTX *pCtx, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);

/**
 * Decrypts data using the provided DES context. The data length must be
 * a multiple of the blocksize of 8 bytes.
 *
 * @param pCtx     A previously initialized context to use for the cipher operation.
 * @param pSrc     Buffer of the data to decrypt.
 * @param pDest    Buffer to hold the resulting plaintext. This must be at least
 *                 the same length as pSrc.
 * @param numBytes Length in bytes of the buffer pSrc. Must be a multiple of the
 *                 DES blocksize of 8 bytes.
 *
 * Note that you can NOT reuse a DES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_decipher(DES_CTX *pCtx, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);

/**
 * Delete a DES-ECB context previously initialized with
 * CRYPTO_INTERFACE_DES_initKey. Note that this function frees the
 * underlying context created by the crypto interface. Even though the
 * DES_CTX pointer was originally allocated by the caller, failing to
 * call this function after use will result in a memory leak.
 *
 * @param pCtx Pointer to a DES-ECB context previously initialized with
 *             CRYPTO_INTERFACE_DES_initKey.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_clearKey(DES_CTX *pCtx);

/**
 * Creates a new DES-CBC context. This function will allocate and
 * return a new DES-CBC context to be used with CRYPTO_INTERFACE_DoDES. It is
 * the callers responsibility to free this context after use by calling
 * CRYPTO_INTERFACE_DeleteDESCtx.
 *
 * @param pKeyMaterial The key material to use for this context creation.
 * @param keyLen       Length in bytes of the key material, must be exactly
 *                     8 bytes.
 * @param encrypt      \c TRUE to prepare this object for encryption or
 *                     \c FALSE to prepare this object for decryption.
 *
 * @return             \c NULL on error, otherwise a pointer to a DES context
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial, sbyte4 keyLen, sbyte4 encrypt);

/**
 * Deletes a DES-CBC context previously created with
 * CRYPTO_INTERFACE_CreateDESCtx. Note that this function frees the
 * underlying context created by the crypto interface. Failing to
 * call this function after use will result in a memory leak.
 *
 * @param pCtx Pointer to a DES context previously created with
 *             CRYPTO_INTERFACE_CreateDESCtx.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteDESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx);

/**
 * Copy a DES context previously created with CRYPTO_INTERFACE_CreateDESCtx.
 *
 * @param pSrc  Pointer to a BulkCtx returned by CRYPTO_INTERFACE_CreateDESCtx.
 * @param pDest Double pointer to the BulkCtx to be created and populated with
 *              the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneDESCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/**
 * Encrypt or decrypt data using the provided DES context in CBC mode.
 * This function can be used to stream data. Pass in the initialization vector
 * on the first call, but each subsequent call is not guaranteed to use the
 * initialization vector passed in. Please use CRYPTO_INTERFACE_DoDESEx
 * if you need a modified iv. Note that this operation is in place,
 * so the pData buffer will contain the result.
 *
 * Note that you can NOT reuse a DES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @param pCtx    Context to use for the cipher operation.
 * @param pData   Data to encrypt or decrypt.
 * @param dataLen Length in bytes of the data to process.
 * @param encrypt \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                used in CRYPTO_INTERFACE_Create3DESCtx.
 * @param pIv     Initialization vector for the cipher operation. Must be exactly
 *                8 bytes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoDES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, sbyte4 dataLen, sbyte4 encrypt, ubyte *pIv);

/**
 * Encrypt or decrypt data using the provided DES context in CBC mode.
 * This function can be used to stream data. Pass in the initialization vector
 * and it will be updated in place. Continue to pass in new data and updated
 * initialization vector on each subsequent call. The updated iv
 * will be written to pIv upon method completion. Note that this
 * operation is in place, so the pData buffer will contain the result.
 *
 * Note that you can NOT reuse a DES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @param pCtx    Context to use for the cipher operation.
 * @param pData   Data to encrypt or decrypt.
 * @param dataLen Length in bytes of the data to process.
 * @param encrypt \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                used in CRYPTO_INTERFACE_Create3DESCtx.
 * @param pIv     Initialization vector for the cipher operation. Must be exactly
 *                8 bytes. Will contain the working IV when the method finishes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoDESEx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, sbyte4 dataLen, sbyte4 encrypt, ubyte *pIv);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DES_HEADER__ */
