/*
 * crypto_interface_aes_keywrap.h
 *
 * Cryptographic Interface specification for AES-KEYWRAP.
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
 @file       crypto_interface_aes_keywrap.h
 @brief      Cryptographic Interface header file for declaring AES-KEYWRAP functions.
 
 @filedoc    crypto_interface_aes_keywrap.h
 */
#ifndef __CRYPTO_INTERFACE_AES_KEYWRAP_HEADER__
#define __CRYPTO_INTERFACE_AES_KEYWRAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** Encrypt pDataToEncrypt using the AES key wrapping technique of RFC 3394.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 *
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pDataToEncrypt The plaintext
 * @param dataToEncryptLen The length, in bytes, of the data to encrypt.
 * @param pEncryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @param transform 1 to use AES forward transform, 0 to use inverse transform.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_encrypt3394Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  );

/** Decrypt pEncryptedData using the AES key wrapping technique of RFC 3394.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 *
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pEncryptedData The ciphertext
 * @param encryptedDataLen The length, in bytes, of the data to decrypt.
 * @param pDecryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDecryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @param transform 1 to use AES forward transform, 0 to use inverse transform.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_decrypt3394Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  );

/** Encrypt pDataToEncrypt using the AES key wrapping technique of RFC 5649.
 *
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pDataToEncrypt The plaintext
 * @param dataToEncryptLen The length, in bytes, of the data to encrypt.
 * @param pEncryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @param transform 1 to use AES forward transform, 0 to use inverse transform.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_encrypt5649Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  );

/** Decrypt pEncryptedData using the AES key wrapping technique of RFC 5649.
 *
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pEncryptedData The ciphertext
 * @param encryptedDataLen The length, in bytes, of the data to decrypt.
 * @param pDecryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDecryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @param transform 1 to use AES forward transform, 0 to use inverse transform.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESKWRAP_decrypt5649Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_KEYWRAP_HEADER__ */
