/*
 * crypto_interface_aes.h
 *
 * Cryptographic Interface header file for declaring AES functions
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
@file       crypto_interface_aes.h
@brief      Cryptographic Interface header file for declaring AES functions.
@details    Add details here.

@filedoc    crypto_interface_aes.h
*/
#ifndef __CRYPTO_INTERFACE_AES_HEADER__
#define __CRYPTO_INTERFACE_AES_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new AES-CBC context. Note it is the callers responsibility to
 * free this object after use by calling \c CRYPTO_INTERFACE_DeleteAESCtx.
 * Once created, you can use this context as input to \c CRYPTO_INTERFACE_DoAES
 * to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * Create a new AES-CFB128 context. Note it is the callers responsibility to
 * free this object after use by calling \c CRYPTO_INTERFACE_DeleteAESCtx.
 * Once created, you can use this context as input to \c CRYPTO_INTERFACE_DoAES
 * to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCFBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * Create a new AES-CFB1 context. Note it is the callers responsibility to
 * free this object after use by calling \c CRYPTO_INTERFACE_DeleteAESCtx.
 * Once created, you can use this context as input to \c CRYPTO_INTERFACE_DoAES
 * to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCFB1Ctx(
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, 
  sbyte4 keyLength, 
  sbyte4 encrypt
  );

/**
 * Create a new AES-OFB context. Note it is the callers responsibility to
 * free this object after use by calling \c CRYPTO_INTERFACE_DeleteAESCtx.
 * Once created, you can use this context as input to CRYPTO_INTERFACE_DoAES
 * to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESOFBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * Create a new AES-ECB context. Note it is the callers responsibility to
 * free this object after use by calling \c CRYPTO_INTERFACE_DeleteAESCtx.
 * Once created, you can use this context as input to \c CRYPTO_INTERFACE_DoAESECB
 * to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESECBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * "Reset" an AES context by setting the "initialized" field within the
 * aesCipherContext to 0.  This function is a helper whose purpose is to bridge
 * the gap between the standard \c DoAES & \c CRYPTO_INTERFACE_DoAES. The standard
 * \c DoAES function modifies parameter buffers in-place, whereas CI version makes
 * an internal copy of the buffers to operate on.  Therefore, calling this
 * function will allow the user to re-use the same context for multiple buffers.
 *
 * @param ppCtx   Pointer to the BulkCtx to be reset.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ResetAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  );

/**
 * Delete an AES context. Applies to CBC, CFB, and OFB modes.
 *
 * @param ppCtx Pointer to the \c BulkCtx to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  );

/**
 * Clone a AES context.
 *
 * @param pCtx     Pointer to an instantiated \c BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  );

/**
 * Encrypt or decrypt data using the provided AES context. Use this for AES
 * contexts created with the CBC, CFB, or OFB modes. This function can be used
 * to stream data, pass in the initialization vector on the first call, but
 * note each subsequent call is not guaranteed to use the pIv field passed in.
 * Please use \c CRYPTO_INTERFACE_DoAESEx if you wish to update the iv.
 * Note that this operation is in place, so the pData buffer will contain the result.
 *
 * Note that you must use ResetAESCtx to start a new cipher operation.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Must be a multiple
 *                      of the AES block size (16).
 * @param encrypt       \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                      used during context creation.
 * @param pIv           Initialization vector for the cipher operation. Must be exactly
 *                      16 bytes.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAES (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte* pIv
  );


/**
 * Encrypt or decrypt data using the provided AES context. Use this for AES
 * contexts created with the CBC, CFB, or OFB modes. This function can be used
 * to stream data, pass in the initialization vector on the first call then
 * continue to pass in new data on each subsequent call. Note that this
 * operation is in place, so the pData buffer will contain the result. This
 * method will copy the working IV into the \c pIv parameter upon completion.
 *
 * Note that you must use \c ResetAESCtx to start a new cipher operation.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Must be a multiple
 *                      of the AES block size (16).
 * @param encrypt       \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                      used during context creation.
 * @param pIv           Initialization vector for the cipher operation. Must be exactly
 *                      16 bytes. Will contain the working IV when the method finishes.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte *pIv
  );

/**
 * Same as CRYPTO_INTERFACE_DoAES but specifically for ECB mode. Note this
 * function does not take an initialization vector as it is not used in ECB mode.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Must be a multiple
 *                      of the AES block size (16).
 * @param encrypt       \c TRUE to encrypt, \c FALSE to decrypt. Must match the value
 *                      used during context creation.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESECB (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt
  );

/**
 * Initialize a raw AES object for operation. Note that this should only be
 * used when constructing a larger cryptographic scheme that requires an AES
 * primitive. To use AES for encrypting/decrypting data in general, use one of
 * the \c CRYPTO_INTERFACE_CreateAES*Ctx functions instead. It is the callers
 * responsibility to delete this context after use by calling
 * \c CRYPTO_INTERFACE_AESALGO_clearKey.
 *
 * @param pCtx         Pointer to a caller allocated AES context to be initialized.
 * @param keyLen       Length in bytes of key material to use, must be
 *                     one of {16,24,32}.
 * @param pKeyMaterial Key material to use for this operation.
 * @param encrypt      \c TRUE to encrypt, \c FALSE to decrypt.
 * @param mode         The AES mode of operation to use. Must be one of
 *                     { MODE_ECB, MODE_CBC, MODE_CFB128, MODE_OFB }
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_makeAesKey (
  aesCipherContext *pCtx,
  sbyte4 keyLen,
  const ubyte *pKeyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  );

/**
 * Initialize a raw AES object for operation. Note that this should only be
 * used when constructing a larger cryptographic scheme that requires an AES
 * primitive. To use AES for encrypting/decrypting data in general, use one of
 * the \c CRYPTO_INTERFACE_CreateAES*Ctx functions instead. It is the callers
 * responsibility to delete this context after use by calling
 * CRYPTO_INTERFACE_AESALGO_clearKey.
 *
 * @param pCtx         Pointer to a caller allocated AES context to be initialized.
 * @param keyLen       Length in bytes of key material to use, must be
 *                     one of {16,24,32}.
 * @param pKeyMaterial Key material to use for this operation.
 * @param encrypt      \c TRUE to encrypt, \c FALSE to decrypt.
 * @param mode         The AES mode of operation to use. Must be one of
 *                     { MODE_ECB, MODE_CBC, MODE_CFB128, MODE_OFB }
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_makeAesKeyEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  sbyte4 keyLen,
  const ubyte *pKeyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  );

/**
 * Encrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to encrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the encrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting ciphertext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockEncrypt (
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  );

/**
 * Encrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to encrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the encrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting ciphertext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  );

/**
 * Decrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to decrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the decrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting plaintext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockDecrypt (
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  );

/**
 * Decrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to decrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the decrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting plaintext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  );

/**
 * Delete an AES context previously initialized with
 * \c CRYPTO_INTERFACE_AESALGO_makeAesKey. Note that this function frees the
 * underlying context created by the crypto interface. Even though the
 * \c aesCipherContext pointer was originally allocated by the caller, failing to
 * call this function after use will result in a memory leak.
 *
 * @param pCtx Pointer to an AES context previously created with
 *             \c CRYPTO_INTERFACE_AESALGO_makeAesKey.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_clearKey (
  aesCipherContext *pCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_HEADER__ */
