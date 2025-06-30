/*
 * crypto_interface_rc5.h
 *
 * Cryptographic Interface header file for declaring RC5 methods
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
@file       crypto_interface_rc5.h
@brief      Cryptographic Interface header file for declaring RC5 methods.
@details    Add details here.

@filedoc    crypto_interface_rc5.h
*/
#ifndef __CRYPTO_INTERFACE_RC5_HEADER__
#define __CRYPTO_INTERFACE_RC5_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** Create an RC5 context.
 *
 * <p>Note that you must call Reinit to reuse a ctx. After calling Final, if you
 * want to reuse the ctx, you must call Reinit before calling Update or Final
 * again.
 *
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocCreateRC5Ctx (
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

/** Free the BulkCtx created by \c CRYPTO_INTERFACE_MocCreateRC5Ctx.
 * <p>This will free any memory and release any resources acquired during create,
 * update, and final.
 *
 * @param ppBulkCtx The address where the function will find the ctx to free and
 * where it will deposit NULL.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocDeleteRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ctx
  );

/** Process data, either encrypting or decrypting, depending on how the context
 * was built and the encrypt arg.
 *
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5Update (
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5Final (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  sbyte4 encrypt,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

/** Reinitialize the Ctx.
 *
 * @param pBulkCtx The context created by a call to MocCreateRC5Ctx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocReinitRC5Ctx (
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5GetIv (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  ubyte *pIv,
  ubyte4 ivLen
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RC5_HEADER__ */
