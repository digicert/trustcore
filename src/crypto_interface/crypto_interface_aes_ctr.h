/*
 * crypto_interface_aes_ctr.h
 *
 * Cryptographic Interface header file for declaring AES counter mode functions
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
@file       crypto_interface_aes_ctr.h
@brief      Cryptographic Interface header file for declaring AES functions.
@details    Add details here.

@filedoc    crypto_interface_aes_ctr.h
*/
#ifndef __CRYPTO_INTERFACE_AES_CTR_HEADER__
#define __CRYPTO_INTERFACE_AES_CTR_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new AES-CTR context. Note it is the callers responsibility to
 * free this object after use by calling CRYPTO_INTERFACE_DeleteAESCTRCtx.
 * Once created, you can use this context as input to CRYPTO_INTERFACE_DoAESCTR
 * or CRYPTO_INTERFACE_DoAESCTREx to encrypt or decrypt data. The last 16 bytes
 * of the pKeyMaterial buffer are expected to be the counter.
 *
 * @param pKeyMaterial Key material to use for the cipher operation including
 *                     the 16 byte counter.
 * @param keyLength    Length in bytes of the key material plus counter, valid
 *                     values are {32, 40, 48}.
 * @param encrypt      unused variable
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * Populates an already created AES-CTR context. Note it is the callers responsibility to
 * free this object after use by calling CRYPTO_INTERFACE_DeleteAESCTRCtx.
 * Once created, you can use this context as input to CRYPTO_INTERFACE_DoAESCTR
 * or CRYPTO_INTERFACE_DoAESCTREx to encrypt or decrypt data.
 *
 * @param pCtx         AES counter mode context to populate
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param pInitCounter A 16 byte buffer that contains the counter to be used
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCTRInit (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  AES_CTR_Ctx* pCtx,
  const ubyte* pKeyMaterial,
  sbyte4 keyLength,
  const ubyte pInitCounter[AES_BLOCK_SIZE]
  );

/**
 * Delete an AES context. Applies to CTR mode only.
 *
 * @param ppCtx Pointer to the BulkCtx to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  );

/**
 * This function is effectively a wrapper to CRYPTO_INTERFACE_DoAESCTREx.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param encrypt       This value is unused.
 *
 * @param pIv           This function does not take an IV, therefore this value is ignored
 *                      16 bytes.
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESCTR (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte* pIv
  );

/**
 * Encrypt or decrypt data using the provided AES counter mode context. This function
 * does not use an IV. This operation is in place, therefore pData will be overwritten
 * with computed ciphertext.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param encrypt       This value is unused.
 *
 * @param pIv           Optional. If provied the internal IV will be set to the 16
 *                      byte buffer and the stream offset will be set back to 0.
 * @param limit         limit specifies the last byte to increment. If AES_BLOCK_SIZE, all
 *                      bytes will be incremented. If 0, no bytes will be incremented
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESCTREx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte* pIv,
  sbyte4 limit
  );

/**
 * Extract the working IV from the AES-CTR context. The buffer must be at least
 * the size of an AES block size.
 *
 * @param pCtx              Context to retrieve the IV from.
 * @param pCounterBuffer    Buffer to store the IV in.
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GetCounterBlockAESCTR (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte pCounterBuffer[AES_BLOCK_SIZE]
  );

/**
 * Create a new AES-CTR context for ipSec specifications. This is analogous to
 * CRYPTO_INTERFACE_CreateAESCTRCtx except that instead of the key being appended
 * by the nonce, iv, and ctr, it just appended by the nonce. It is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_DeleteAESCTRCtx. Once created, you can use this context as input
 * to CRYPTO_INTERFACE_DoAesCtrEx to encrypt or decrypt data.
 *
 * @param pKeyMaterial Key material to use for the cipher operation including
 *                     the 4 byte nonce.
 * @param keyLength    Length in bytes of the key material plus nonce, valid
 *                     values are {32, 40, 48}.
 * @param encrypt      unused variable
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAesCtrCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  );

/**
 * Encrypt or decrypt data for ipSec specifications using the provided AES context.
 *
 * @param pCtx          Context to use for the cipher operation.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLength    Length in bytes of the data to process. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param encrypt       This value is unused.
 * @param pIv           The 8 byte iv to be used. The counter will be reset to [nonce || iv || 1 ]
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAesCtrEx(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte *pIv
  );

/**
 * Clone a AES-CTR context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  );


/**
 * Perform the AES-CTR stream cipher operation on a buffer of data. This API should be used in place of
 * \c CRYPTO_INTERFACE_DoAESCTR when the underlying implementation may return output of a differing length
 * from that of the input (for example if only 16 byte blocks are returned).
 *
 * @param pCtx          Pointer to an instantiated BulkCtx of \c aesCTRCipherContext type. 
 * @param pInput        Buffer of the input plaintext or ciphertext.
 * @param inputLen      The length of the input buffer in bytes.
 * @param pOutput       Buffer to hold the resulting output. This may be the same as the input buffer but
 *                      must have enough space available for the expected output.
 * @param pBytesWritten Contents will be set to the number of bytes actually written to the output buffer.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_UpdateAesCtrEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pInput,
  sbyte4 inputLen,
  ubyte *pOutput,
  sbyte4 *pBytesWritten
  );

/**
 * Finalizes the AES-CTR stream cipher operation on a buffer of data. This API should be used when the underlying
 * implementation may return output of a differing length from that of the input and there may be leftover
 * unprocessed bytes left to be encrypted or decryped.
 *
 * @param pCtx          Pointer to an instantiated BulkCtx of \c aesCTRCipherContext type. 
 * @param pOutput       Buffer to hold the resulting output. This
 *                      must have enough space available for the expected output.
 * @param pBytesWritten Contents will be set to the number of bytes actually written to the output buffer.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_FinalAesCtrEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pOutput,
  sbyte4 *pBytesWritten
  );



#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_CTR_HEADER__ */
