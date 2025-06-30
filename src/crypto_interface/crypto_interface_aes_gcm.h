/*
 * crypto_interface_aes_gcm.h
 *
 * Cryptographic Interface header file for declaring AES-GCM functions
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
@file       crypto_interface_aes_gcm.h
@brief      Cryptographic Interface header file for declaring AES-GCM functions.

@filedoc    crypto_interface_aes_gcm.h
*/
#ifndef __CRYPTO_INTERFACE_AES_GCM_HEADER__
#define __CRYPTO_INTERFACE_AES_GCM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* macros and context type for last two APIs at bottom of this file */
#define GCM_MODE_GENERAL  0
#define GCM_MODE_256B   100
#define GCM_MODE_4K     101
#define GCM_MODE_64K    102

typedef struct {

    BulkCtx pTblCtx;
    ubyte4 tableSize;
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;

} AES_GCM_CTX;


/**
 * Create a new AES-GCM context for Authenticated Encrypt Authenticated Decrypt (AEAD)
 * operations. It is the callers responsibilty to delete this context after use
 * by calling CRYPTO_INTERFACE_GCM_deleteCtx_256b.
 *
 * @param pKeyData Key material to use.
 * @param keyLen   Length in bytes of the key material. Must be one of {16, 24, 32}.
 * @param encrypt  \c TRUE to initialize for encryption, /c FALSE to initialize
 *                 for decryption.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
    sbyte4 keyLen,
    sbyte4 encrypt
    );

/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Updates an AES-GCM context with data to be encrypted or decrypted.
 *
 * @details    Updates an AES-GCM context with data to be encrypted or decrypted. Which direction
 *             depends on the \c encrypt flag passed into the context creation \c GCM_createCtx_64k
 *             method. The \c GCM_update_data_64k method may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pData       Buffer holding the data to be encrypted or decrypted. It will be
 *                     processed in place, ie this buffer will also hold the resulting
 *                     ciphertext or plaintext.
 * @param  dataLen     The length of the data in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
 * Delete an AES-GCM context previously created with
 * CRYPTO_INTERFACE_GCM_createCtx_256b.
 *
 * @param pCtx Pointer to a BulkCtx returned by CRYPTO_INTERFACE_GCM_createCtx_256b.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
    );

/**
 * Perform an AES-GCM cipher operation in one step. If all of the data to process
 * is available at one time, this is the recommended function to use. When
 * encrypting, the pData buffer MUST have space for both the data to encrypt and
 * the resulting tag. The tag will be appended to the end of the buffer. When
 * decrypting, this function expects to find a tag of tagLen bytes appended to
 * the pData buffer.
 * <pre>
 * <code>
 *   // Encrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20;
 *   ubyte pData[36] = {...}; // Enough space for data + tag
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_256b(pKeyData, keyLen, TRUE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of ciphertext
 *   // followed by a 16 byte tag.
 *   status = CRYPTO_INTERFACE_GCM_cipher_256b (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, TRUE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * <pre>
 * <code>
 *   // Decrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20; // Note this is (cipherTextLen - tagLen)
 *   ubyte pCipherText[36] = {...}; // Start with ciphertext from encryption process
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_256b(pKeyData, keyLen, FALSE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of plaintext
 *   status = CRYPTO_INTERFACE_GCM_cipher_256b (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, FALSE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * @param pCtx     Context to use for this cipher operation.
 * @param pNonce   The nonce data to use for this cipher operation.
 * @param nonceLen Length in bytes of the nonce material. 12 is the default length.
 * @param pAaData  Optional additional authentication data to use.
 * @param aadLen   Length in bytes of the additional authentication data.
 * @param pData    Data to encrypt or decrypt. Note for encryption this buffer must
 *                 be large enough for the output ciphertext and tag.
 * @param dataLen  Length in bytes of the data to process. When decrypting this
 *                 value does not include the tag bytes.
 * @param tagLen   Length in bytes of the tag. Must be one of {4,8,12,13,14,15,16}.
 * @param encrypt  /c TRUE to encrypt, /c FALSE to decrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLen,
    sbyte4 encrypt
    );

/**
 * Initialize an AES-GCM context for a cipher operation.
 *
 * @param pCtx     Context returned by CRYPTO_INTERFACE_GCM_createCtx_256b.
 * @param pNonce   The nonce to use for this operation.
 * @param nonceLen Length in bytes of the nonce material.
 * @param pAaData  Optional additional authentication data.
 * @param aadLen   Length in bytes of the additional authentication data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx    Context to use for the encryption operation.
 * @param pData   Data to encrypt.
 * @param dataLen Length in bytes of the data to encrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    ubyte4 dataLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx          Context to use for the encryption operation.
 * @param pCipherText   Data to encrypt.
 * @param cipherTextLen Length in bytes of the data to encrypt.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pCipherText,
    ubyte4 cipherTextLen
    );

/**
 * Finish an AES-GCM operation to recieve the computed tag. In general this should
 * only be used if the caller needs to stream their data to encrypt/decrypt. If
 * all of the data is available at once, using CRYPTO_INTERFACE_GCM_cipher_256b
 * is recommended.
 *
 * Note that when using this to finalize a decryption operation the caller MUST
 * perform the tag comparison in constant time. Failure to do so could leave the
 * application vulnerable to timing attacks.
 *
 * @param pCtx Context used for the cipher operation.
 * @param pTag Buffer to place the computed tag value.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte pTag[/*AES_BLOCK_SIZE*/]
    );

/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_256b (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/**
 * Create a new AES-GCM context for Authenticated Encrypt Authenticated Decrypt (AEAD)
 * operations. It is the callers responsibilty to delete this context after use
 * by calling CRYPTO_INTERFACE_GCM_deleteCtx_4k.
 *
 * @param pKeyData Key material to use.
 * @param keyLen   Length in bytes of the key material. Must be one of {16, 24, 32}.
 * @param encrypt  \c TRUE to initialize for encryption, /c FALSE to initialize
 *                 for decryption.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
    sbyte4 keyLen,
    sbyte4 encrypt
    );


/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Updates an AES-GCM context with data to be encrypted or decrypted.
 *
 * @details    Updates an AES-GCM context with data to be encrypted or decrypted. Which direction
 *             depends on the \c encrypt flag passed into the context creation \c GCM_createCtx_64k
 *             method. The \c GCM_update_data_64k method may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pData       Buffer holding the data to be encrypted or decrypted. It will be
 *                     processed in place, ie this buffer will also hold the resulting
 *                     ciphertext or plaintext.
 * @param  dataLen     The length of the data in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
 * Delete an AES-GCM context previously created with
 * CRYPTO_INTERFACE_GCM_createCtx_4k.
 *
 * @param pCtx Pointer to a BulkCtx returned by CRYPTO_INTERFACE_GCM_createCtx_4k.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
    );

/**
 * Perform an AES-GCM cipher operation in one step. If all of the data to process
 * is available at one time, this is the recommended function to use. When
 * encrypting, the pData buffer MUST have space for both the data to encrypt and
 * the resulting tag. The tag will be appended to the end of the buffer. When
 * decrypting, this function expects to find a tag of tagLen bytes appended to
 * the pData buffer.
 * <pre>
 * <code>
 *   // Encrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20;
 *   ubyte pData[36] = {...}; // Enough space for data + tag
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKeyData, keyLen, TRUE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of ciphertext
 *   // followed by a 16 byte tag.
 *   status = CRYPTO_INTERFACE_GCM_cipher_4k (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, TRUE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * <pre>
 * <code>
 *   // Decrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20; // Note this is (cipherTextLen - tagLen)
 *   ubyte pCipherText[36] = {...}; // Start with ciphertext from encryption process
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKeyData, keyLen, FALSE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of plaintext
 *   status = CRYPTO_INTERFACE_GCM_cipher_4k (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, FALSE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * @param pCtx     Context to use for this cipher operation.
 * @param pNonce   The nonce data to use for this cipher operation.
 * @param nonceLen Length in bytes of the nonce material. 12 is the default length.
 * @param pAaData  Optional additional authentication data to use.
 * @param aadLen   Length in bytes of the additional authentication data.
 * @param pData    Data to encrypt or decrypt. Note for encryption this buffer must
 *                 be large enough for the output ciphertext and tag.
 * @param dataLen  Length in bytes of the data to process. When decrypting this
 *                 value does not include the tag bytes.
 * @param tagLen   Length in bytes of the tag. Must be one of {4,8,12,13,14,15,16}.
 * @param encrypt  /c TRUE to encrypt, /c FALSE to decrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLen,
    sbyte4 encrypt
    );

/**
 * Initialize an AES-GCM context for a cipher operation.
 *
 * @param pCtx     Context returned by CRYPTO_INTERFACE_GCM_createCtx_4k.
 * @param pNonce   The nonce to use for this operation.
 * @param nonceLen Length in bytes of the nonce material.
 * @param pAaData  Optional additional authentication data.
 * @param aadLen   Length in bytes of the additional authentication data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx    Context to use for the encryption operation.
 * @param pData   Data to encrypt.
 * @param dataLen Length in bytes of the data to encrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    ubyte4 dataLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx          Context to use for the encryption operation.
 * @param pCipherText   Data to encrypt.
 * @param cipherTextLen Length in bytes of the data to encrypt.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pCipherText,
    ubyte4 cipherTextLen
    );

/**
 * Finish an AES-GCM operation to recieve the computed tag. In general this should
 * only be used if the caller needs to stream their data to encrypt/decrypt. If
 * all of the data is available at once, using CRYPTO_INTERFACE_GCM_cipher_4k
 * is recommended.
 *
 * Note that when using this to finalize a decryption operation the caller MUST
 * perform the tag comparison in constant time. Failure to do so could leave the
 * application vulnerable to timing attacks.
 *
 * @param pCtx Context used for the cipher operation.
 * @param pTag Buffer to place the computed tag value.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte pTag[/*AES_BLOCK_SIZE*/]
    );

/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_4k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/**
 * Create a new AES-GCM context for Authenticated Encrypt Authenticated Decrypt (AEAD)
 * operations. It is the callers responsibilty to delete this context after use
 * by calling CRYPTO_INTERFACE_GCM_deleteCtx_64k.
 *
 * @param pKeyData Key material to use.
 * @param keyLen   Length in bytes of the key material. Must be one of {16, 24, 32}.
 * @param encrypt  \c TRUE to initialize for encryption, /c FALSE to initialize
 *                 for decryption.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
    sbyte4 keyLen,
    sbyte4 encrypt
    );


/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Updates an AES-GCM context with data to be encrypted or decrypted.
 *
 * @details    Updates an AES-GCM context with data to be encrypted or decrypted. Which direction
 *             depends on the \c encrypt flag passed into the context creation \c GCM_createCtx_64k
 *             method. The \c GCM_update_data_64k method may be called as many times as necessary.
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pData       Buffer holding the data to be encrypted or decrypted. It will be
 *                     processed in place, ie this buffer will also hold the resulting
 *                     ciphertext or plaintext.
 * @param  dataLen     The length of the data in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
 * Delete an AES-GCM context previously created with
 * CRYPTO_INTERFACE_GCM_createCtx_64k.
 *
 * @param pCtx Pointer to a BulkCtx returned by CRYPTO_INTERFACE_GCM_createCtx_64k.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
    );

/**
 * Perform an AES-GCM cipher operation in one step. If all of the data to process
 * is available at one time, this is the recommended function to use. When
 * encrypting, the pData buffer MUST have space for both the data to encrypt and
 * the resulting tag. The tag will be appended to the end of the buffer. When
 * decrypting, this function expects to find a tag of tagLen bytes appended to
 * the pData buffer.
 * <pre>
 * <code>
 *   // Encrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20;
 *   ubyte pData[36] = {...}; // Enough space for data + tag
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_64k(pKeyData, keyLen, TRUE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of ciphertext
 *   // followed by a 16 byte tag.
 *   status = CRYPTO_INTERFACE_GCM_cipher_64k (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, TRUE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * <pre>
 * <code>
 *   // Decrypting
 *   MSTATUS status;
 *   BulkCtx pCtx = NULL;
 *   sbyte4 keyLen = 32;
 *   ubyte4 nonceLen = 12;
 *   ubyte4 tagLen = 16;
 *   ubyte4 dataLen = 20; // Note this is (cipherTextLen - tagLen)
 *   ubyte pCipherText[36] = {...}; // Start with ciphertext from encryption process
 *   ubyte pNonce[12] = {...};
 *   ubyte pKeyData[32] = {...};
 *
 *   pCtx = CRYPTO_INTERFACE_GCM_createCtx_64k(pKeyData, keyLen, FALSE);
 *   if (NULL == pCtx)
 *   {
 *       status = ERR_NULL_POINTER;
 *       goto exit;
 *   }
 *
 *   // After this call, the pData buffer will contain the 20 bytes of plaintext
 *   status = CRYPTO_INTERFACE_GCM_cipher_64k (
 *       pCtx, pNonce, nonceLen, NULL, 0, pData, dataLen, tagLen, FALSE);
 *   if (OK != status)
 *       goto exit;
 *
 *    // Always delete the context when finished
 *    status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(&pCtx);
 *    if (OK != status)
 *       goto exit;
 *
 * exit:
 *   return status;
 * </code>
 * </pre>
 *
 * @param pCtx     Context to use for this cipher operation.
 * @param pNonce   The nonce data to use for this cipher operation.
 * @param nonceLen Length in bytes of the nonce material. 12 is the default length.
 * @param pAaData  Optional additional authentication data to use.
 * @param aadLen   Length in bytes of the additional authentication data.
 * @param pData    Data to encrypt or decrypt. Note for encryption this buffer must
 *                 be large enough for the output ciphertext and tag.
 * @param dataLen  Length in bytes of the data to process. When decrypting this
 *                 value does not include the tag bytes.
 * @param tagLen   Length in bytes of the tag. Must be one of {4,8,12,13,14,15,16}.
 * @param encrypt  /c TRUE to encrypt, /c FALSE to decrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLen,
    sbyte4 encrypt
    );

/**
 * Initialize an AES-GCM context for a cipher operation.
 *
 * @param pCtx     Context returned by CRYPTO_INTERFACE_GCM_createCtx_64k.
 * @param pNonce   The nonce to use for this operation.
 * @param nonceLen Length in bytes of the nonce material.
 * @param pAaData  Optional additional authentication data.
 * @param aadLen   Length in bytes of the additional authentication data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx    Context to use for the encryption operation.
 * @param pData   Data to encrypt.
 * @param dataLen Length in bytes of the data to encrypt.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    ubyte4 dataLen
    );

/**
 * Update an encryption operation. Note that AES-GCM is a stream cipher so both
 * the overall input length and the input length to any one update call does
 * not need to be a multiple of the AES block size. This function operates on
 * data in place, so the resulting ciphertext will be in the provided data
 * buffer after the encryption process is complete.
 *
 * @param pCtx          Context to use for the encryption operation.
 * @param pCipherText   Data to encrypt.
 * @param cipherTextLen Length in bytes of the data to encrypt.
 *
 * @return        \c OK (0) if successful, otherwise a negative number
 *                error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pCipherText,
    ubyte4 cipherTextLen
    );

/**
 * Finish an AES-GCM operation to recieve the computed tag. In general this should
 * only be used if the caller needs to stream their data to encrypt/decrypt. If
 * all of the data is available at once, using CRYPTO_INTERFACE_GCM_cipher_64k
 * is recommended.
 *
 * Note that when using this to finalize a decryption operation the caller MUST
 * perform the tag comparison in constant time. Failure to do so could leave the
 * application vulnerable to timing attacks.
 *
 * @param pCtx Context used for the cipher operation.
 * @param pTag Buffer to place the computed tag value.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte pTag[/*AES_BLOCK_SIZE*/]
    );

/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_64k (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

/**
 * Create a new AES-GCM context of type \c AES_GCM_CTX for Authenticated Encrypt Authenticated Decrypt (AEAD)
 * operations. It is the callers responsibilty to delete this context after use
 * by calling CRYPTO_INTERFACE_AES_GCM_deleteCtx.
 *
 * @param ppNewCtx        Location that will recieve a pointer to the newly allocated context.
 * @param tableSizeMode   The GCM internal table size, one of the macros \c GCM_MODE_256B,
 *                        \c GCM_MODE_4K, \c GCM_MODE_64K, \c GCM_MODE_GENERAL. This must be provided even
 * @param pKeyMaterial    Buffer holding the key material.
 * @param keyMaterialLen  Length of the key material in bytes. Should be 16, 24, or 32....
 * @param encrypt         Enter non-zero or \c TRUE to prepare a context for encrpytion and
 *                        \c FALSE for decryption. This is not used for \c GCM_MODE_GENERAL.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_newCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppNewCtx,
    ubyte4 tableSizeMode, 
    ubyte *pKeyMaterial, 
    sbyte4 keyMaterialLen,
    sbyte4 encrypt);

/**
 * Encrypt and tags a buffer of data via the AES-GCM algorithm. The underlying
 * implementation may or may not use the nonce that is passed in.
 *
 * @param pCtx           Pointer to a context of type \c AES_GCM_CTX to use for this cipher operation.
 * @param pNonce         Buffer to hold nonce input to the cipher operation, or
 *                       buffer that will hold the resulting nonce.
 * @param pNonceLen      Contents should be the length of the nonce passed in, in bytes.
 *                       If the underlying implementation creates the nonce this will
 *                       be set to its length in bytes.
 * @param pWasNonceUsed  Contenets will be set to \c TRUE if the underlying implementation
 *                       used the nonce passed in and \c FALSE if it created its own.
 * @param pAad           Optional additional authentication data to use.
 * @param aadLen         Length in bytes of the additional authentication data.
 * @param pData          Data to encrypt and teg. Note for encryption this buffer must
 *                       be large enough for the output ciphertext and tag.
 * @param dataLen        Length in bytes of the data to process.
 * @param tagLen         Length in bytes of the tag. Must be one of {4,8,12,13,14,15,16}.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_encrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,      
    ubyte *pNonce,
    ubyte4 *pNonceLen,
    intBoolean *pWasNonceUsed,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLen);

/**
 * Decrypt and verify a buffer of data via the AES-GCM algorithm.
 *
 * @param pCtx           Pointer to a context of type \c AES_GCM_CTX to use for this cipher operation.
 * @param pNonce         Buffer to hold nonce input to the cipher operation.
 * @param nonceLen       The length of the nonce in bytes.
 * @param pAad           Optional additional authentication data to use.
 * @param aadLen         Length in bytes of the additional authentication data.
 * @param pData          Data to decrypt and verify. The tag should be appended to the ciphertext.
 * @param dataLen        Length in bytes of the data to process. This length does not include the tag.
 * @param tagLen         Length in bytes of the tag. Must be one of {4,8,12,13,14,15,16}.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_decrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLen);

/**
 * Deletes and frees memory associated with an AES-GCM context of type \c AES_GCM_CTX.
 *
 * @param ppCtx    Location holding a pointer to the context to be deleted.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_deleteCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_GCM_HEADER__ */
