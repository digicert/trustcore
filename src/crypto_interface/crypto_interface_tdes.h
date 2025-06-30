/*
 * crypto_interface_tdes.h
 *
 * Cryptographic Interface header file for declaring TDES functions
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
@file       crypto_interface_tdes.h
@brief      Cryptographic Interface header file for declaring TDES functions.

@filedoc    crypto_interface_tdes.h
*/
#ifndef __CRYPTO_INTERFACE_TDES_HEADER__
#define __CRYPTO_INTERFACE_TDES_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define THREE_DES_TWO_KEY_LENGTH  16

/**
 * Create a new Triple DES (TDES) context. This function will allocate and
 * return a new TDES context to be used with CRYPTO_INTERFACE_Do3DES. It is
 * the callers responsibility to free this context after use by calling
 * CRYPTO_INTERFACE_Delete3DESCtx.
 *
 * @param pKeyMaterial The key material to use for this context creation.
 * @param keyLen       Length in bytes of the key material, must be exactly
 *                     24 bytes.
 * @param encrypt      \c TRUE to prepare this object for encryption or
 *                     \c FALSE to prepare this object for decryption.
 *
 * @return             \c NULL on error, otherwise a pointer to a TDES context.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_Create3DESCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    );

/**
 * Create a new Triple DES (TDES) context with two keys. A final (third) key
 * will be a copy of the first key. This function will allocate and return a
 * new TDES context to be used with CRYPTO_INTERFACE_Do3DES. It is the
 * callers responsibility to free this context after use by calling
 * CRYPTO_INTERFACE_Delete3DESCtx.
 *
 * @param pKeyMaterial The key material to use for this context creation.
 * @param keyLen       Length in bytes of the key material, must be exactly
 *                     16 bytes.
 * @param encrypt      \c TRUE to prepare this object for encryption or
 *                     \c FALSE to prepare this object for decryption.
 *
 * @return             \c NULL on error, otherwise a pointer to a TDES context.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_Create2Key3DESCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt
    );

/**
 * Encrypt or decrypt data using the provided TDES context. This function uses
 * a TDES context previously created with CRYPTO_INTERFACE_Create3DESCtx to
 * encrypt or decrypt the provided data in CBC mode. This function can be used
 * to stream data, pass in the initialization vector on the first call then
 * continue to pass in new data on each subsequent call. Note this method is not
 * guaranteed to use the pIv field on each subsequent call. If you need to replace
 * the iv then use CRYPTO_INTERFACE_Do3DESEx instead. Note also the
 * operation is in place, so the pData buffer will contain the result.
 *
 * Note that you can NOT reuse a TDES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @param pCtx    Context to use for the cipher operation.
 * @param pData   Data to encrypt or decrypt.
 * @param dataLen Length in bytes of the data to process. Must be a multiple
 *                of the TDES block size (8).
 * @param encrypt \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                used in CRYPTO_INTERFACE_Create3DESCtx.
 * @param pIv     Initialization vector for the cipher operation. Must be exactly
 *                8 bytes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Do3DES (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * Encrypt or decrypt data using the provided TDES context. This function uses
 * a TDES context previously created with CRYPTO_INTERFACE_Create3DESCtx to
 * encrypt or decrypt the provided data in CBC mode. This function can be used
 * to stream data, pass in the initialization vector on the first call then
 * continue to pass in new data and the updated iv on each subsequent call.
 * Unlike CRYPTO_INTERFACE_Do3DES this method will use the pIV field and
 * update it upon completion of the method. Note that this
 * operation is in place, so the pData buffer will contain the result.
 *
 * Note that you can NOT reuse a TDES context to start a new cipher operation.
 * Ensure that each object is used for only one encrypt or decrypt operation,
 * you must create a new object to start a new cipher operation.
 *
 * @param pCtx    Context to use for the cipher operation.
 * @param pData   Data to encrypt or decrypt.
 * @param dataLen Length in bytes of the data to process. Must be a multiple
 *                of the TDES block size (8).
 * @param encrypt \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                used in CRYPTO_INTERFACE_Create3DESCtx.
 * @param pIv     Initialization vector for the cipher operation. Must be exactly
 *                8 bytes. Will contain the working IV when the method finishes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Do3DESEx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * Delete a TDES context previously created with CRYPTO_INTERFACE_Create3DESCtx.
 *
 * @param pCtx Pointer to a BulkCtx returned by CRYPTO_INTERFACE_Create3DESCtx.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Delete3DESCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
    );

/**
 * Copy a TDES context previously created with CRYPTO_INTERFACE_Create3DESCtx.
 *
 * @param pSrc  Pointer to a BulkCtx returned by CRYPTO_INTERFACE_Create3DESCtx.
 * @param pDest Double pointer to the BulkCtx to be created and populated with
 *              the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Clone3DESCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/**
 * Create a new Triple DES (TDES) context for ECB mode. This function will allocate and
 * return a new TDES context to be used with CRYPTO_INTERFACE_THREE_DES_encipher/decipher.
 * It will internally call CRYPTO_INTERFACE_THREE_DES_initKey. It is
 * the callers responsibility to free this context after use by calling
 * CRYPTO_INTERFACE_THREE_DES_deleteCtx.
 *
 * @param pKeyMaterial The key material to use for this context creation.
 * @param keyLen       Length in bytes of the key material, must be exactly
 *                     24 bytes.
 * @param encrypt      ingored.
 *
 * @return             \c NULL on error, otherwise a pointer to a TDES context.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_THREE_DES_createCtx (
    ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    );


/**
 * Create a new Triple DES (TDES) 2-key context for ECB mode. This function will allocate and
 * return a new TDES context to be used with CRYPTO_INTERFACE_THREE_DES_encipher/decipher.
 * It will internally call CRYPTO_INTERFACE_THREE_DES_initKey. It is
 * the callers responsibility to free this context after use by calling
 * CRYPTO_INTERFACE_THREE_DES_deleteCtx.
 *
 * @param pKeyMaterial The key material to use for this context creation.
 * @param keyLen       Length in bytes of the key material, must be exactly
 *                     16 bytes.
 * @param encrypt      ingored.
 *
 * @return             \c NULL on error, otherwise a pointer to a TDES context.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_THREE_DES_create2KeyCtx( 
    ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    );

/**
 * Initialize a raw TDES-ECB object for operation. Note that this should only
 * be used when constructing a larger cryptographic scheme that requires a
 * TDES-ECB primitive. It is the callers responsibility to delete
 * this context after use by calling CRYPTO_INTERFACE_THREE_DES_clearKey.
 *
 * @param pCtx   Pointer to a caller allocated TDES-ECB context to be initialized.
 * @param pKey   Key material to use for this operation.
 * @param keyLen Length in bytes of key material to use, must be exactly 24 bytes.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_initKey (
  ctx3des *pCtx,
  const ubyte *pKey,
  sbyte4 keyLen
  );

/**
 * Perform a raw TDES-ECB encrypt.
 *
 * @param pCtx     TDES context previously initialized with
 *                 CRYPTO_INTERFACE_THREE_DES_initKey to use to encrypt.
 * @param pSrc     Data to encrypt.
 * @param pDest    Buffer that will recieve the encrypted result.
 * @param numBytes Number of bytes to encrypt, must be a multiple of 8.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_encipher (
  ctx3des *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  );

/**
 * Perform a raw TDES-ECB decrypt.
 *
 * @param pCtx     TDES context previously initialized with
 *                 CRYPTO_INTERFACE_THREE_DES_initKey to use to decrypt.
 * @param pSrc     Data to decrypt.
 * @param pDest    Buffer that will recieve the decrypted result.
 * @param numBytes Number of bytes to decrypt, must be a multiple of 8.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_decipher (
  ctx3des *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  );

/**
 * Delete a TDES-ECB context previously initialized with
 * CRYPTO_INTERFACE_THREE_DES_initKey. Note that this function frees the
 * underlying context created by the crypto interface. Even though the
 * ctx3des pointer was originally allocated by the caller, failing to
 * call this function after use will result in a memory leak.
 *
 * @param pCtx Pointer to a TDES-ECB context previously created with
 *             CRYPTO_INTERFACE_THREE_DES_initKey.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_clearKey (
  ctx3des *pCtx
  );

/**
 * Delete a TDES context previously created with CRYPTO_INTERFACE_THREE_DES_createCtx.
 * This will internally call CRYPTO_INTERFACE_THREE_DES_clearKey.
 *
 * @param pCtx Pointer to a BulkCtx returned by CRYPTO_INTERFACE_THREE_DES_createCtx.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_deleteCtx (
    BulkCtx *pCtx
    );

/**
 * Copy a TDES context previously created with CRYPTO_INTERFACE_THREE_DES_createCtx.
 *
 * @param pSrc  Pointer to a BulkCtx returned by CRYPTO_INTERFACE_THREE_DES_createCtx.
 * @param pDest Double pointer to the BulkCtx to be created and populated with
 *              the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_cloneCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );


#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_TDES_HEADER__ */
