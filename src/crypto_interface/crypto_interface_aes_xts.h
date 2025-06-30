/*
 * crypto_interface_aes_xts.h
 *
 * Cryptographic Interface header file for declaring AES-XTS methods
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
@file       crypto_interface_aes_xts.h
@brief      Cryptographic Interface header file for declaring AES-XTS methods.
@details    Add details here.

@filedoc    crypto_interface_aes_xts.h
*/
#ifndef __CRYPTO_INTERFACE_AES_XTS_HEADER__
#define __CRYPTO_INTERFACE_AES_XTS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates and initializes a new AES-XTS context. Note it is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_DeleteAESXTSCtxExt.
 * 
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material. Two AES-128 or
 *                     AES-256 keys will be formed hence keyLength
 *                     must be either 32 or 64.
 * @param encrypt      \c TRUE to prepare the context for encryption;
 *                     \c FALSE to prepare the context for decryption.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESXTSCtxExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt,
    void *pExtCtx
    );

/**
 * Creates and initializes a new AES-XTS context. Note it is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_DeleteAESXTSCtx.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material. Two AES-128 or
 *                     AES-256 keys will be formed hence keyLength
 *                     must be either 32 or 64.
 * @param encrypt      \c TRUE to prepare the context for encryption;
 *                     \c FALSE to prepare the context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESXTSCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt
    );

/**
 * Deletes an AES-XTS context.
 *
 * @param ppCtx      Pointer to the BulkCtx to be deleted.
 * @param pExtCtx    An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESXTSCtxExt (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx,
    void *pExtCtx
    );

/**
 * Deletes an AES-XTS context.
 *
 * @param ppCtx      Pointer to the BulkCtx to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESXTSCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    );

/**
 * Performs the AES-XTS cipher operation to do an inplace encryption or decryption.
 * This is effectively a wrapper of CRYPTO_INTERFACE_AESXTSEncryptExt and
 * CRYPTO_INTERFACE_AESXTSDecryptExt.
 *
 * @param pCtx          A previously initialized context.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLen       Length in bytes of the data to process. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param encrypt       \c TRUE to prepare the context for encryption;
 *                      \c FALSE to prepare the context for decryption.
 * @param pTweak        The 16 byte tweak.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESXTSExt (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLen,
  sbyte4 encrypt,
  ubyte *pTweak,
  void *pExtCtx
  );

/**
 * Performs the AES-XTS cipher operation to do an inplace encryption or decryption.
 * This is effectively a wrapper of CRYPTO_INTERFACE_AESXTSEncrypt and
 * CRYPTO_INTERFACE_AESXTSDecrypt.
 *
 * @param pCtx          A previously initialized context.
 * @param pData         Data to encrypt or decrypt.
 * @param dataLen       Length in bytes of the data to process. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param encrypt       \c TRUE to prepare the context for encryption;
 *                      \c FALSE to prepare the context for decryption.
 * @param pTweak        The 16 byte tweak.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESXTS (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pTweak
    );

/**
 * Performs the AES-XTS cipher operation to do an inplace encryption.
 *
 * @param pCtx          A pointer to a previously inialized context.
 * @param pTweak        The 16 byte tweak.
 * @param pPlain        The plaintext to encrypt.
 * @param plainLen      Length in bytes of pPlain. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSEncryptExt (
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pPlain,
    ubyte4 plainLen,
    void *pExtCtx
    );

/**
 * Performs the AES-XTS cipher operation to do an inplace encryption.
 *
 * @param pCtx          A pointer to a previously inialized context.
 * @param pTweak        The 16 byte tweak.
 * @param pPlain        The plaintext to encrypt.
 * @param plainLen      Length in bytes of pPlain. Does not have to be a
 *                      multiple of the AES block size (16).
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSEncrypt (
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pPlain,
    ubyte4 plainLen
    );

/**
 * Performs the AES-XTS cipher operation to do an inplace decryption.
 *
 * @param pCtx          A pointer to a previously inialized context.
 * @param pTweak        The 16 byte tweak.
 * @param pCipher       The ciphertext to decrypt.
 * @param cipherLen     Length in bytes of pCipher. Does not have to be a
 *                      multiple of the AES block size (16).
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSDecryptExt (
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pCipher,
    ubyte4 cipherLen,
    void *pExtCtx
    );

/**
 * Performs the AES-XTS cipher operation to do an inplace decryption.
 *
 * @param pCtx          A pointer to a previously inialized context.
 * @param pTweak        The 16 byte tweak.
 * @param pCipher       The ciphertext to decrypt.
 * @param cipherLen     Length in bytes of pCipher. Does not have to be a
 *                      multiple of the AES block size (16).
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSDecrypt (
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pCipher,
    ubyte4 cipherLen
    );

/**
 * @brief Clones an AES-XTS context.
 *
 * @param pCtx      Pointer to an instantiated BulkCtx.
 * @param ppNewCtx  Double pointer to the BulkCtx to be created and populated
 *                    with the data from the source context.
 * @return          \c OK (0) if successful; otherwise a negative number error
 *                  code definition from merrors.h.
 */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneAESXTSCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_XTS_HEADER__ */
