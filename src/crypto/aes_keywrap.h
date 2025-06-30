/*
 * aes_keywrap.h
 *
 * AES Key Wrap RFC 3394 and 5649 Implementation
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
@file       aes_keywrap.h
@filedoc    aes_keywrap.h
*/

/*------------------------------------------------------------------*/

#ifndef __AESKEYWRAP_HEADER__
#define __AESKEYWRAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** Encrypt pDataToEncrypt using the AES key wrapping technique of RFC 3394.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>The previous NanoCrypto AES KEy Wrap function followed RFC 3394, for
 * smaller data sizes, but not for data longer than 344 bytes.
 * <p>This version will adhere to RFC 3394 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using this function, you must decrypt it using
 * AESKWRAP_decrypt3394.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>To follow RFC 3394, the data length must be a multiple of 8 bytes. If your
 * data is not a multiple of 8 bytes, you must pad it.
 * <p>The function will produce output that is 8 bytes longer than the input.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pEncryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pEncryptedDataLen to the number of bytes placed into the buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pDataToEncrypt The plaintext
 * @param dataToEncryptLen The length, in bytes, of the data to encrypt.
 * @param pEncryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS AESKWRAP_encrypt3394 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen
  );

/** Decrypt pEncryptedData using the AES key wrapping technique of RFC 3394.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>The previous NanoCrypto AES KEy Wrap function followed RFC 3394, for
 * smaller data sizes, but not for data longer than 344 bytes.
 * <p>This version will adhere to RFC 3394 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using AESKWRAP_decrypt3394, decrypt it using this
 * function.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is 8 bytes shorter than the input.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pDecryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pDecryptedData and set
 * *pDecryptedDataLen to the number of bytes placed into the buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pEncryptedData The ciphertext
 * @param encryptedDataLen The length, in bytes, of the data to decrypt.
 * @param pDecryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDecryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS AESKWRAP_decrypt3394 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen
  );

/** Encrypt pDataToEncrypt using the AES key wrapping technique of RFC 5649.
 * <p>RFC 5649 is very similar to RFC 3394. One difference is that with RFC 5649,
 * the length of the data to encrypt does not have to be a multiple of 8 bytes.
 * With this technique, if the data to encrypt is not a multiple of 8, it will
 * pad. If it already is a multiple of 8, it will not pad.
 * <p>Another difference between 3394 and 5649 is the "Initial Value". What this
 * means is that even if the input data length is a multiple of 8, and even if
 * using the same key data, the resulting ciphertexts of each implementation will
 * be different.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>This version will adhere to RFC 5649 for all data lengths (the maximum data
 * length, specified in the standard, is 2^32 - 1, as that is the largest value
 * representable in a 32-bit integer).
 * <p>If you encrypt data using this function, you must decrypt it using
 * AESKWRAP_decrypt5649.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. If you have data encrypted using
 * AESKWRAP_encryptEx, you must decrypt it using AESKWRAP_decryptEx. If you have
 * data encrypted using AESKWRAP_encrypt3394, you must decrypt it using
 * AESKWRAP_decrypt3394. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is up to 15 bytes longer than the
 * input. If the input length requires 7 bytes of pad, the function will pad with
 * 7 bytes, then add 8 bytes to the encrypted data.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pEncryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pEncryptedDataLen to the number of bytes placed into the buffer. If you pass
 * in an output buffer that is 16 bytes longer than the input, you will be safe,
 * just make sure that you check the resulting length, it might not be exactly 8
 * bytes longer.
 *
 * @param hwAccelCtx (Reserved for future use.)
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pDataToEncrypt The plaintext
 * @param dataToEncryptLen The length, in bytes, of the data to encrypt.
 * @param pEncryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS AESKWRAP_encrypt5649 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen
  );

/** Decrypt pEncryptedData using the AES key wrapping technique of RFC 5649.
 * <p>RFC 5649 is very similar to RFC 3394. One difference is that with RFC 5649,
 * the length of the data to encrypt does not have to be a multiple of 8 bytes.
 * With this technique, if the data to encrypt is not a multiple of 8, it will
 * pad. If it already is a multiple of 8, it will not pad.
 * <p>Another difference between 3394 and 5649 is the "Initial Value". What this
 * means is that even if the input data length is a multiple of 8, and even if
 * using the same key data, the resulting ciphertexts of each implementation will
 * be different.
 * <p>When decrypting, the pad bytes are stripped.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>This version will adhere to RFC 5649 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using AESKWRAP_encrypt5649, you must decrypt it using
 * this function.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. If you have data encrypted using
 * AESKWRAP_encryptEx, you must decrypt it using AESKWRAP_decryptEx. If you have
 * data encrypted using AESKWRAP_encrypt3394, you must decrypt it using
 * AESKWRAP_decrypt3394. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is up to 15 bytes shorter than the
 * input. If the plaintext length had required 7 bytes of pad, the encrypt
 * function will pad with 7 bytes, then add 8 bytes to the encrypted data. The
 * decryption function will strip the pad and extra 8 bytes.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pDecryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pDecryptedDataLen to the number of bytes placed into the buffer. If you pass
 * in an output buffer that is the same size as the input, you will be safe,
 * just make sure that you check the resulting length, you don't know how many
 * bytes will be stripped.
 * <p>NOTE! This function will not operate until it knows the buffer is big
 * enough. However, it does not know the exact size of the output until it
 * opertes. Hence, it will expect an output buffer that is at least the maximum
 * size of output for the given input length. That will be input length minus 8.
 * That is, if there was no padding to strip, the output length will be 8 bytes
 * smaller than the input length. If there is padding, there will be fewer bytes,
 * but the function will not know until operating, so the output length can be as
 * many as input len - 8. That is the required size of the output buffer you must
 * supply, even though the actual output might be fewer bytes. Upon successful
 * return from this function, *pDecryptedDataLen will be set to the actual number
 * of bytes placed into the output buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
 * @param pKeyMaterial The AES key that will be used to wrap (encrypt) the data.
 * @param keyLength The length, in bytes, of the key data.
 * @param pEncryptedData The ciphertext
 * @param encryptedDataLen The length, in bytes, of the data to decrypt.
 * @param pDecryptedData The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDecryptedDataLen The address where the function will deposit the
 * required size (if the buffer is not big enough) or the number of bytes placed
 * into the output buffer.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS AESKWRAP_decrypt5649 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen
  );

/*---------------------------------------------------------------------------*/

/* Follwing APIs are same as above with extra option to specify the transform
 * type used in the operation */

/** Encrypt pDataToEncrypt using the AES key wrapping technique of RFC 3394.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>The previous NanoCrypto AES KEy Wrap function followed RFC 3394, for
 * smaller data sizes, but not for data longer than 344 bytes.
 * <p>This version will adhere to RFC 3394 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using this function, you must decrypt it using
 * AESKWRAP_decrypt3394.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>To follow RFC 3394, the data length must be a multiple of 8 bytes. If your
 * data is not a multiple of 8 bytes, you must pad it.
 * <p>The function will produce output that is 8 bytes longer than the input.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pEncryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pEncryptedDataLen to the number of bytes placed into the buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
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
MOC_EXTERN MSTATUS AESKWRAP_encrypt3394Ex (
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
 * <p>The previous NanoCrypto AES KEy Wrap function followed RFC 3394, for
 * smaller data sizes, but not for data longer than 344 bytes.
 * <p>This version will adhere to RFC 3394 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using AESKWRAP_decrypt3394, decrypt it using this
 * function.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is 8 bytes shorter than the input.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pDecryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pDecryptedData and set
 * *pDecryptedDataLen to the number of bytes placed into the buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
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
MOC_EXTERN MSTATUS AESKWRAP_decrypt3394Ex (
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
 * <p>RFC 5649 is very similar to RFC 3394. One difference is that with RFC 5649,
 * the length of the data to encrypt does not have to be a multiple of 8 bytes.
 * With this technique, if the data to encrypt is not a multiple of 8, it will
 * pad. If it already is a multiple of 8, it will not pad.
 * <p>Another difference between 3394 and 5649 is the "Initial Value". What this
 * means is that even if the input data length is a multiple of 8, and even if
 * using the same key data, the resulting ciphertexts of each implementation will
 * be different.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>This version will adhere to RFC 5649 for all data lengths (the maximum data
 * length, specified in the standard, is 2^32 - 1, as that is the largest value
 * representable in a 32-bit integer).
 * <p>If you encrypt data using this function, you must decrypt it using
 * AESKWRAP_decrypt5649.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. If you have data encrypted using
 * AESKWRAP_encryptEx, you must decrypt it using AESKWRAP_decryptEx. If you have
 * data encrypted using AESKWRAP_encrypt3394, you must decrypt it using
 * AESKWRAP_decrypt3394. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is up to 15 bytes longer than the
 * input. If the input length requires 7 bytes of pad, the function will pad with
 * 7 bytes, then add 8 bytes to the encrypted data.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pEncryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pEncryptedDataLen to the number of bytes placed into the buffer. If you pass
 * in an output buffer that is 16 bytes longer than the input, you will be safe,
 * just make sure that you check the resulting length, it might not be exactly 8
 * bytes longer.
 *
 * @param hwAccelCtx (Reserved for future use.)
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
MOC_EXTERN MSTATUS AESKWRAP_encrypt5649Ex (
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
 * <p>RFC 5649 is very similar to RFC 3394. One difference is that with RFC 5649,
 * the length of the data to encrypt does not have to be a multiple of 8 bytes.
 * With this technique, if the data to encrypt is not a multiple of 8, it will
 * pad. If it already is a multiple of 8, it will not pad.
 * <p>Another difference between 3394 and 5649 is the "Initial Value". What this
 * means is that even if the input data length is a multiple of 8, and even if
 * using the same key data, the resulting ciphertexts of each implementation will
 * be different.
 * <p>When decrypting, the pad bytes are stripped.
 * <p>This is generally used to wrap keys (other AES keys, RSA keys, etc.), but
 * as written, an implementation of that RFC really encrypts any data.
 * <p>This version will adhere to RFC 5649 for all data lengths (the maximum data
 * length of the NanoCrypto implementation is 2^32 - 1, as that is the largest
 * value representable in a ubyte32, the length argument).
 * <p>If you encrypt data using AESKWRAP_encrypt5649, you must decrypt it using
 * this function.
 * <p>If you have data encrypted using the function AESKWRAP_encrypt, you must
 * decrypt it using AESKWRAP_decrypt. If you have data encrypted using
 * AESKWRAP_encryptEx, you must decrypt it using AESKWRAP_decryptEx. If you have
 * data encrypted using AESKWRAP_encrypt3394, you must decrypt it using
 * AESKWRAP_decrypt3394. Use these new functions with new data.
 * <p>The keyLength must be 16, 24, or 32 (128, 192, or 256 bits), the only
 * supported key sizes of AES.
 * <p>The function will produce output that is up to 15 bytes shorter than the
 * input. If the plaintext length had required 7 bytes of pad, the encrypt
 * function will pad with 7 bytes, then add 8 bytes to the encrypted data. The
 * decryption function will strip the pad and extra 8 bytes.
 * <p>The caller supplies a buffer into which the function will place the result.
 * The output buffer cannot be the same as the input buffer.
 * <p>The caller indicates how big the output buffer is with the bufferSize arg.
 * If the buffer is not big enough, the function will set *pDecryptedDataLen to
 * the required size and return ERR_BUFFER_OVERFLOW. If the buffer is big enough,
 * the function will place the resulting data into pEncryptedData and set
 * *pDecryptedDataLen to the number of bytes placed into the buffer. If you pass
 * in an output buffer that is the same size as the input, you will be safe,
 * just make sure that you check the resulting length, you don't know how many
 * bytes will be stripped.
 * <p>NOTE! This function will not operate until it knows the buffer is big
 * enough. However, it does not know the exact size of the output until it
 * opertes. Hence, it will expect an output buffer that is at least the maximum
 * size of output for the given input length. That will be input length minus 8.
 * That is, if there was no padding to strip, the output length will be 8 bytes
 * smaller than the input length. If there is padding, there will be fewer bytes,
 * but the function will not know until operating, so the output length can be as
 * many as input len - 8. That is the required size of the output buffer you must
 * supply, even though the actual output might be fewer bytes. Upon successful
 * return from this function, *pDecryptedDataLen will be set to the actual number
 * of bytes placed into the output buffer.
 *
 * @param hwAccelCtx (Reserved for future use.)
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
MOC_EXTERN MSTATUS AESKWRAP_decrypt5649Ex (
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

/* RFC 3394: length of data must be a multiple of 8 */
MOC_EXTERN MSTATUS
AESKWRAP_encrypt( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                 sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                 ubyte* retData /* Should be dataLen + 8 */);


/* RFC 5649: no restriction on length of data */
MOC_EXTERN MSTATUS
AESKWRAP_encryptEx( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                   sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                   ubyte** retData, ubyte4* retDataLen);


/* legacy API: can only deal with RFC 3394 encoded key wraps */
MOC_EXTERN MSTATUS
AESKWRAP_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                 sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                 ubyte* retData /* dataLen - 8 */);


/* preferred API: can deal with RFC 3394 and RFC 5649 encoded key wraps */
MOC_EXTERN MSTATUS
AESKWRAP_decryptEx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                   sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                   ubyte* retData /* <= dataLen - 8 */, ubyte4* retDataLen);



#ifdef __cplusplus
}
#endif

#endif
