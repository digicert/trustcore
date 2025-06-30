/*
 * rc5algo.h
 *
 * RC5 Algorithm
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
@file       rc5algo.h

@brief      Header file for the NanoCrypto RC5 API.
@details    Header file for the NanoCrypto RC5 API.
*/

#ifndef __RC5ALGO_H__
#define __RC5ALGO_H__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rc5_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Create an RC5 context.
 * <p>Note that the RC5 code will not be compiled unless NanoCrypto is built with
 * the __ENABLE_MOCANA_RC5__ build flag set.
 * <p>RC5 is a block cipher that can operate on either 8-byte (64-bit) or 16-byte
 * (128-bit) blocks.
 * <p>A context built with this function will be able to perform either RC5-ECB,
 * RC5-ECB-Pad, RC5-CBC, or RC5-CBC-Pad.
 * <p>If you set the iv arg to NULL, the context will perform RC5-ECB. If you
 * pass in an initialization vector, the context will perform RC5-CBC. Note that
 * the IV must be the same size as the block size (see the comments on block size
 * below).
 * <p>If you set the padding arg to MOC_RC5_NO_PAD (this is #defined to 0), the
 * context will not pad, but the total input must be a multiple of the block size
 * (see below for more info on the block size).
 * <p>If you set the padding arg to MOC_RC5_PKCS5_PAD (this is #defined to 1),
 * the context will pad using the method defined in PKCS 5. This means the total
 * input length of the data to encrypt does not have to be a multiple of the
 * block size, but the encrypted data length will be as much as one full block
 * size longer than the plaintext. When decrypting, the total input length must
 * be a multiple of the block size and the ctx will strip the padding. That means
 * when decrypting, the Final function will return only the plaintext, not any of
 * the pad bytes. Furthermore, the ctx will check to make sure the pad bytes are
 * indeed appropriate pad bytes.
 * <p>If you set the encrypt arg to MOC_RC5_ENCRYPT (this is #defined to 1), the
 * context will be built to encrypt. If you set it to MOC_RC5_DECRYPT (this is
 * #defined to 0), the context will be built to decrypt.
 * <p>RC5 generally has three parameters: block size, key size, and round count.
 * <p>NanoCrypto supports block sizes of either 64 or 128 bits (there is a 32-bit
 * block size version of RC5 but is not considered secure at any key size or
 * round count). Note that DES, Triple-DES, and RC2 operate on 64-bit blocks. AES
 * operates on 128-bit blocks. Generally, if you are using RC5 in place of DES
 * you will use the 64-bit block size version, and if you are using RC5 in place
 * of AES you will use the 128-bit block size version.
 * <p>Note that the block size argument is "blockSizeBits", so pass in a value of
 * either 64 or 128.
 * <p>The key, per the original algorithm definition written by Ron Rivest, the
 * inventor of the algorithm, can be 0 to 255 bytes long (0 <= keyByteLen < 256).
 * The longer the key, the greater the security. Most applications will use a
 * 128-bit key (16 bytes), although many aplications use 256-bit keys (32 bytes).
 * <p>Note that the default compilation of this implementation of RC5 will not
 * allow keys smaller than 8 bytes (64-bits, the same size as DES). However, if
 * compiled with the flag __ENABLE_MOCANA_WEAK_RC5__, the code will be compiled
 * to support any key length greater than 0 in order to be compatible with other
 * implementations, but Mocana strongly recommends using no fewer than 128 bits
 * (16 bytes). Note that this implementation does NOT support 0-length keys.
 * <p>According to RFC 2040, the round count can be any value from 0 to 255
 * (0 <= roundCount < 256). However, small round counts are less secure.
 * Generally, a round count of 20 will likely be sufficient for most
 * applications. Note that the more rounds you select, the greater the memory use
 * and the slower the algorithm runs.
 * <p>Note that the default compilation of this implementation of RC5 will not
 * allow round counts fewer than 12. However, if compiled with the flag
 * __ENABLE_MOCANA_WEAK_RC5__, the code will be compiled to support any round
 * count greater than 0 in order to be compatible with other implementations, but
 * Mocana strongly recommends using no fewer than 20 rounds. Note that this
 * implementation does NOT support a round count of 0.
 * <p>The caller passes in the address of a BulkCtx (which is a pointer type).
 * The function will deposit at that address the context created. Use that ctx in
 * calls to MocRC5Update and MocRC5Final.
 * <p>Once you call Create, you can call Update or Final. If you want to reuse a
 * ctx, call MocReinitRC5Ctx. For example,
 * <pre>
 * <code>
 *    MocCreateRC5Ctx
 *    MocRC5Update
 *    MocRC5Update
 *    MocRC5Final
 *
 *    // This reinitializes with the same key, same padding, same encryption, etc.
 *    MocReinitRC5Ctx
 *    MocRC5Final
 *
 *    MocReinitRC5Ctx
 *      . . .
 * </code>
 * </pre>
 * <p>Note that you must call Reinit to reuse a ctx. After calling Final, if you
 * want to reuse the ctx, you must call Reinit before calling Update or Final
 * again.
 *
 * @par Flags
 * The implementation will be disabled unless the following conditions are met:
 *   + \c \__ENABLE_MOCANA_RC5__ \b must be defined
 * Weak RC5 (small keys and round counts) will be disabled unless the following
 * conditions are met:
 *   + \c \__ENABLE_MOCANA_WEAK_RC5__ \b must be defined
 *
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 * expands to an additional parameter, "hwAccelDescr hwAccelCtx". Otherwise, this
 * macro resolves to nothing.
 * @param keyMaterial The key data to use in encryption or decryption.
 * @param keyLength The length, in bytes, of the keyMaterial.
 * @param iv If NULL, the context will be built to perform RC5-ECB, but if not
 * NULL, it contains the CBC initialization vector.
 * @param ivLen the length, in bytes, of the IV. The IV must be one block long.
 * So if the blockSizeBits is 64, the ivLen must be 8, and if the blockSizeBits
 * is 128, the ivLen must be 16.
 * @param blockSizeBits The bit length of the blocks on which RC5 will operate.
 * This can only be either 64 or 128.
 * @param roundCount The number of internal rounds. Mocana recommends at least 20.
 * @param padding If MOC_RC5_NO_PAD (zero), the context will not pad when
 * encrypting or unpad when decrypting, but the total input length (whether
 * encrypting or decrypting) must be a multiple of the block size. If this is
 * MOC_RC5_PKCS5_PAD (one), the context will pad when encrypting and attempt to
 * unpad when decrypting. The ciphertext will be up to one block size longer than
 * the plaintext.
 * @param encrypt If MOC_RC5_ENCRYPT (one), the context will be built to encrypt.
 * If MOC_RC5_DECRYPT (zero), the context will be built to decrypt.
 * @param ppBulkCtx The address where the function will deposit the context to
 * use in further RC5 function calls.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocCreateRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *keyMaterial,
  sbyte4 keyLength,
  ubyte *iv,
  sbyte4 ivLen,
  sbyte4 blockSizeBits,
  sbyte4 roundCount,
  sbyte4 padding,
  sbyte4 encrypt,
  BulkCtx *ppBulkCtx
  );

#define MOC_RC5_ENCRYPT     1
#define MOC_RC5_DECRYPT     0

#define MOC_RC5_NO_PAD      0
#define MOC_RC5_PKCS5_PAD   1

/** Free the BulkCtx created by MocCreateRC5Ctx.
 * <p>This will free any memory and release any resources acquired during create,
 * update, and final.
 * <p>The caller passes in the address of the BulkCtx created. The function will
 * get the ctx to free at that address and deposit a NULL when done.
 * <p>If there is no ctx to free, the function will do nothing and return OK.
 *
 * @par Flags
 * The implementation will be disabled unless the following conditions are met:
 *   + \c \__ENABLE_MOCANA_RC5__ \b must be defined
 * Weak RC5 (small keys and round counts) will be disabled unless the following
 * conditions are met:
 *   + \c \__ENABLE_MOCANA_WEAK_RC5__ \b must be defined
 *
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 * expands to an additional parameter, "hwAccelDescr hwAccelCtx". Otherwise, this
 * macro resolves to nothing.
 * @param ppBulkCtx The address where the function will find the ctx to free and
 * where it will deposit NULL.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS MocDeleteRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ctx
  );

/** Process data, either encrypting or decrypting, depending on how the context
 * was built and the encrypt arg.
 * <p>After calling MocCreateRC5Ctx, you have a context that will be able to
 * encrypt or decrypt data using RC5. Now do the encryption or decryption.
 * <p>The encrypt arg passed to this function must be the same as the encrypt arg
 * passed to the MocCreateRC5Ctx function. It is an extra check to make sure the
 * caller is using the context correctly.
 * <p>It is possible to call Update many times. That is, it is possible to
 * process by parts, or stream the input. When you have no more data to process,
 * call MocRC5Final.
 * <p>Valid calling combinations are the following.
 * <pre>
 * <code>
 *   Update (data), Update (data), ..., Update (data), Final (no data)
 *   Update (data), Update (data), ..., Update (data), Final (last data)
 *   Final (all data)
 * </code>
 * </pre>
 * <p>The length of each input can be a multiple of the block size or not. If
 * not, the next call to Update or Final will pick up where the previous call left
 * off.
 * <p>The caller supplies the output buffer (it should NOT be the same as the
 * input buffer), and its size. If the buffer is big enough to handle the output,
 * the function will process the data and place it into the buffer, returning the
 * output length (the number of bytes placed into the output buffer) at the
 * address given by pProcessedDataLen.
 * <p>If the buffer is not big enough, the function will NOT process any of the
 * input, it will set *pProcessedDataLen to the size required, and return
 * ERR_BUFFER_TOO_SMALL. At that point, the caller can allocate a buffer big
 * enough and call Update again with the same input.
 * <p>Note that the output can be longer or shorter than the input. It is even
 * possible to have no output. This is because the function can only operate on
 * full blocks, and if the input is not a multiple of the block size, it might be
 * able to output only some of the result and keep some of the input locally
 * until it has enough to make a complete block. Or if this is a later call to
 * Update, it is possible there is "leftover" data to process from a previous
 * call and with the new data, more blocks of output can be processed than were
 * input during the current call to Update (for example, with a 16-byte block, if
 * the first Update call passes in 15 bytes, there will be no output, but if the
 * second Update passes in 17 bytes, there will be a total of 32 bytes available
 * for processing, and the output will be two full blocks).
 * <p>It is possible to call Update with a NULL output buffer just to get the
 * required output size.
 * <p>Note that the required size might be longer than the actual output length.
 * This is because the function will not process any data until it knows the
 * buffer is big enough, but might not be able to know the exact output length
 * until processing the data. Hence, it will return a "max" output length. This
 * will likely be within one block size of the actual output length.
 *
 * @par Flags
 * The implementation will be disabled unless the following conditions are met:
 *   + \c \__ENABLE_MOCANA_RC5__ \b must be defined
 * Weak RC5 (small keys and round counts) will be disabled unless the following
 * conditions are met:
 *   + \c \__ENABLE_MOCANA_WEAK_RC5__ \b must be defined
 *
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 * expands to an additional parameter, "hwAccelDescr hwAccelCtx". Otherwise, this
 * macro resolves to nothing.
 * @param pBulkCtx The context created by a call to MocCreateRC5Ctx.
 * @param encrypt If MOC_RC5_ENCRYPT (one), enrypt the dataToProcess. If
 * MOC_RC5_DECRYPT (zero), decrypt the dataToProcess.
 * @param pDataToProcess The input data.
 * @param dataToProcessLen The length, in bytes, of the input data.
 * @param pProcessedData The caller-supplied output buffer.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pProcessedDataLen The address where the function will deposit the
 * length of the output (the number of bytes placed into the output buffer) or
 * else, if the buffer is not big enough, the required size.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocRC5Update (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  sbyte4 encrypt,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

/** Finish processing the data, either encrypting or decrypting, depending on how
 * the context was built and the encrypt arg.
 * <p>This is the same as MocRC5Update except this will either apply the padding
 * (if encrypting and padding) or strip the padding (if decrypting and padding),
 * or verify that the total input length is a multiple of the block size (if not
 * padding).
 * <p>After calling MocCreateRC5Ctx, you have a context that will be able to
 * encrypt or decrypt data using RC5. Now do the encryption or decryption with
 * calls to Update and Final.
 * <p>The encrypt arg passed to this function must be the same as the encrypt arg
 * passed to the MocCreateRC5Ctx function. It is an extra check to make sure the
 * caller is using the context correctly.
 * <p>It is possible to call Update many times. That is, it is possible to
 * process by parts, or stream the input. When you have no more data to process,
 * call MocRC5Final.
 * <p>Valid calling combinations are the following.
 * <pre>
 * <code>
 *   Update (data), Update (data), ..., Update (data), Final (no data)
 *   Update (data), Update (data), ..., Update (data), Final (last data)
 *   Final (all data)
 * </code>
 * </pre>
 * <p>The caller supplies the output buffer (it should NOT be the same as the
 * input buffer), and its size. If the buffer is big enough to handle the output,
 * the function will process the data and place it into the buffer, returning the
 * output length (the number of bytes placed into the output buffer) at the
 * address given by pProcessedDataLen.
 * <p>If the buffer is not big enough, the function will NOT process any of the
 * input, it will set *pProcessedDataLen to the size required, and return
 * ERR_BUFFER_TOO_SMALL. At that point, the caller can allocate a buffer big
 * enough and call Update again with the same input.
 * <p>Note that the output can be longer or shorter than the input. It is even
 * possible to have no output. This is because the function can only operate on
 * full blocks, and if the input is not a multiple of the block size, it might be
 * able to output only some of the result and keep some of the input locally
 * until it has enought to make a complete block. Hence, the Final call might be
 * dealing with "leftover" data to process from previous calls to Update.
 * Furthermore, the Final will pad or unpad (if the context had been built with
 * MOC_RC5_PKCS5_PAD), which will add or subtract output.
 * <p>It is possible to call Final with a NULL output buffer just to get the
 * required output size.
 * <p>Note that the required size migh be longer than the actual output length.
 * This is because the function will not process any data until it knows the
 * buffer is big enough, but might not be able to know the exact output length
 * until processing the data. Hence, it will return a "max" output length. This
 * will likely be within one block size of the actual output length.
 *
 * @par Flags
 * The implementation will be disabled unless the following conditions are met:
 *   + \c \__ENABLE_MOCANA_RC5__ \b must be defined
 * Weak RC5 (small keys and round counts) will be disabled unless the following
 * conditions are met:
 *   + \c \__ENABLE_MOCANA_WEAK_RC5__ \b must be defined
 *
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 * expands to an additional parameter, "hwAccelDescr hwAccelCtx". Otherwise, this
 * macro resolves to nothing.
 * @param pBulkCtx The context created by a call to MocCreateRC5Ctx.
 * @param encrypt If MOC_RC5_ENCRYPT (one), enrypt the dataToProcess. If
 * MOC_RC5_DECRYPT (zero), decrypt the dataToProcess.
 * @param pDataToProcess The input data.
 * @param dataToProcessLen The length, in bytes, of the input data.
 * @param pProcessedData The caller-supplied output buffer.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pProcessedDataLen The address where the function will deposit the
 * length of the output (the number of bytes placed into the output buffer) or
 * else, if the buffer is not big enough, the required size.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocRC5Final (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  sbyte4 encrypt,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

/** Reinitialize the Ctx. This will make it possible to reuse an object.
 * <p>This will only set the state of the object to the same state after create.
 * The ctx will be able to process data just as it was created. That is, if the
 * ctx were created to encrypt, the reinit will allow it to encrypt again. And
 * the same goes for the key, the initialization vector, the round count, the
 * block size, and the padding.
 * <p>There is no way to reuse a ctx with a different key or setup. If you want
 * to do something different (decrypt instead of encrypt, use a different key,
 * IV, round count, etc.), then you must build a new ctx.
 * <p>Note that you must call Reinit to reuse a ctx. After calling Final, if you
 * want to reuse the ctx, you must call Reinit before calling Update or Final
 * again. If you don't call Reinit after Final, and call Update or Final again,
 * then you will get an error.
 *
 * @par Flags
 * The implementation will be disabled unless the following conditions are met:
 *   + \c \__ENABLE_MOCANA_RC5__ \b must be defined
 * Weak RC5 (small keys and round counts) will be disabled unless the following
 * conditions are met:
 *   + \c \__ENABLE_MOCANA_WEAK_RC5__ \b must be defined
 *
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 * expands to an additional parameter, "hwAccelDescr hwAccelCtx". Otherwise, this
 * macro resolves to nothing.
 * @param pBulkCtx The context created by a call to MocCreateRC5Ctx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocReinitRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx
  );

/** Obtains the latest IV of the ctx.
 *
 * @param pBulkCtx The context in question.
 * @param pIv      Buffer to hold the obtained IV.
 * @param ivLen    The length of the \c pIv buffer in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocRC5GetIv (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  ubyte *pIv,
  ubyte4 ivLen
  );

#ifdef __cplusplus
}
#endif

#endif /* __RC5ALGO_H__ */
