/*
 * crypto_interface_chacha20.h
 *
 * Cryptographic Interface header file for declaring ChaCha20 functions for the
 * Crypto Interface.
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
 * @file crypto_interface_chacha20.h
 * @brief Cryptographic Interface header file for declaring ChaCha20 functions
 *
 * @filedoc crypto_interface_chacha20.h
 */
#ifndef __CRYPTO_INTERFACE_CHACHA20_HEADER__
#define __CRYPTO_INTERFACE_CHACHA20_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief           Create a new ChaCha20 context.  Note: It is the caller's
 *                  responsibility to free this object after use by calling
 *                  CRYPTO_INTERFACE_DeleteChaCha20Ctx.  Once created, you may
 *                  use this context as input to CRYPTO_INTERFACE_DoChaCha20
 *                  to encrypt or decrypt data.
 *
 * @param pKey      Key material used for the cipher operation. This key is a
 *                  concatenation of (key || counter || nonce).
 *
 * @param keyLen    Length, in bytes, of the key material.
 *                  32 bytes of key, 4 bytes of counter, 12 bytes of nonce.
 *
 * @param mode      Unused.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateChaCha20Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  const ubyte pKey[48],
  sbyte4 keyLen,
  sbyte4 mode
  );

/**
 * @brief            Encrypt or decrypt data using the provided ChaCha20 context.
 *                   This function can be used to stream data so new data may be
 *                   passed in on each subsequent call.
 *                   Note: This operation is performed in-place, meaning that
 *                         the pData buffer will contain the result.
 *
 * @param pBulkCtx   Context to use for the cipher operation.
 *
 * @param pData      Data to encrypt or decrypt.
 *
 * @param dataLen    Length, in bytes, of the data to process.
 *
 * @param mode       Unused.
 *
 * @param pIv        Optional. If provided, it will be used as the counter and
 *                   nonce in the creation of future blocks of key stream. The
 *                   latest IV (ie counter and nonce) will then be written to
 *                   this buffer. (nanocrypto mode only)
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoChaCha20 (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  ubyte* pData,
  sbyte4 dataLen,
  sbyte4 mode,
  ubyte* pIv
  );

/**
 * @brief             Delete a ChaCha20 context.
 *
 * @param ppBulkCtx   Pointer to the BulkCtx to be deleted.
 *
 * @return            \c OK (0) if successful, otherwise a negative number
 *                    error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteChaCha20Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppBulkCtx
  );

/**
 @brief      Set values for the nonce and counter blocks for ChaCha20 context.
             This function specifically is for ssh protocol, this function assumes
             an 8 byte counter and an 8 byte nonce.

 @details    Set values for the nonce and counter blocks for ChaCha20 context.
             This function specifically is for ssh protocol, this function assumes
             an 8 byte counter and an 8 byte nonce.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flag must be defined:
             + \c \__ENABLE_DIGICERT_CHACHA20__

 @inc_file   chacha20.h

 @param  pCtx          A previously initialized context.
 @param  pNonce        A buffer containing the nonce to be set.
 @param  nonceLength   The length of pNonce in bytes.
 @param  pCounter      A buffer containing the counter to be set.
 @param  counterLength The length of pCounter in bytes.

 @return \c OK (0) if successful For invalid input a negative number error code
         definition from merrors.h is returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CHACHA20_setNonceAndCounterSSH(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
    ubyte *pNonce,
    ubyte4 nonceLength,
    ubyte *pCounter,
    ubyte counterLength
    );

/**
 * @brief             Create a new ChaCha20Poly1305 context for use in the ChaCha20
 *                    Poly1305 AEAD. Note: It is the caller's responsibility
 *                    to free this object after use by calling
 *                    CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx. Once created, you may
 *                    use this context as input to CRYPTO_INTERFACE_ChaCha20Poly1305_cipher
 *                    API.
 *
 * @param pKey        Key material used for the ChaCha20 Poly1305 AEAD operation.
 * @param keyLen      The length of pKey in bytes. This must be 32 bytes.
 * @param encrypt     Enter TRUE (or non-zero) for encryption and FALSE (or zero) for decryption.
 *
 * @return            \c OK (0) if successful, otherwise a negative number
 *                    error code from merrors.h
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKey,
  sbyte4 keyLen,
  sbyte4 encrypt
  );

/**
 * @brief             Deletes a ChaCha20Poly1305 context.
 *
 * @param ppCtx       Pointer to the BulkCtx (ie ChaCha20Poly1305 context) to be deleted.
 *
 * @return            \c OK (0) if successful, otherwise a negative number
 *                    error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppCtx
  );

/**
 @brief      Performs the ChaCha20poly1305 AEAD algorithm as specified for SSH
             authentication protocol.

 @details    Performs the ChaCha20poly1305 AEAD algorithm as specified for SSH
             authentication protocol.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_DIGICERT_CHACHA20__
             + \c \__ENABLE_DIGICERT_POLY1305__

 @inc_file   chacha20.h

 @param  ctx        A previously created context.
 @param  pNonce     Buffer that holds the nonce.
 @param  nlen       The length of pNonce in bytes. This must be 8.
 @param  pAdata     Buffer that holds the additional authenticated data.
                    This buffer is unused in SSH.
 @param  alen       The length of pAdata in bytes. Unused.
 @param  pData      A buffer of data to be encrypted or decrypted.
 @param  dlen       The length of pData in bytes.
 @param  verifyLen  The length of the verification tag in bytes. This must be 16.
 @param  encrypt    Enter one (or nonzero) for encryption and 0 for decryption.

 @return \c OK (0) if successful including the tag being valid on decryption.
         For an invalid tag or invalid input a negative number error code
         definition from merrors.h is returned.

 @warning For authenticated decryption be sure to check the return code for
          OK before accepting that the decrypted data is authentic.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cipherSSH(MOC_SYM(hwAccelDescr hwAccelCtx)
                                           BulkCtx ctx,
                                           ubyte *pNonce, ubyte4 nlen,
                                           ubyte *pAdata, ubyte4 alen,
                                           ubyte *pData,  ubyte4 dlen,
                                           ubyte4 verifyLen, sbyte4 encrypt);

/**
 * @brief             Performs the ChaCha20 Poly1305 AEAD operation.
 *
 * @param pCtx        Pointer to the context to use for the AEAD cipher operation.
 * @param pNonce      Pointer to the nonce for the ChaCha20 operation.
 * @param noncelen    The length of pNonce in bytes. This must be 12.
 * @param pAad        Pointer to the additional authenticated data for the Poly1305
 *                    operation.
 * @param aadLen      The length of pAad in bytes. This may be zero.
 * @param pData       Pointer to the data to be encrypted or decrypted.
 * @param dataLen     The length of pData in bytes.
 * @param verifyLen   The length of the tag to be created or verified in bytes. This must be 16.
 * @param encrypt     Unused. The encrypt flag entered via
 *                    CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx will take precedence.
 *
 * @return            \c OK (0) if successful, otherwise a negative number
 *                    error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cipher(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 noncelen,
  ubyte *pAad,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 verifyLen,
  sbyte4 encrypt
  );


/**
 @brief      Adds the nonce value to a ChaCha20Ctx context data structure
             for use with the Poly1305 MAC algorithm.

 @details    Adds the nonce value to a ChaCha20Ctx context data structure
             for use with the Poly1305 MAC algorithm. The counter will
             be initialized to 0.

 @ingroup    chacha20_functions

 @flags      There are no flag dependencies to enable this function.

 @param pCtx      A pointer to a previously initialized context.
 @param pNonce    A pointer to a byte array holding the 12 byte nonce.
 @param nonceLen  The length of the pNonce buffer in bytes. This must be 12.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_nonce(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen
  );

/**
 @brief      Updates a ChaCha20Ctx context with additional authenticated data.

 @details    Updates an initialized context with additional authenticated
             data (AAD). One may call update as many times as needed with
             portions of the AAD. All calls to
             CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad must happen
             before calling CRYPTO_INTERFACE_ChaCha20Poly1305_update_data.

 @ingroup    chacha20_functions

 @flags      There are no flag dependencies to enable this function.

 @param  pCtx        A pointer to a previously initialized context.
 @param  pAadData    A pointer to a byte array holding the AAD.
 @param  aadDataLen  The length of the pAadData buffer in bytes.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pAadData,
  ubyte4 aadDataLen
  );

/**
 @brief      Updates a ChaCha20Ctx context with data to be encrypted or
             decrypted.

 @details    Updates an initialized context with the data to be encrypted or
             decrypted. The encryption or decryption will happen in-place.
             One may call update as many times as needed with portions of the
             data.

 @ingroup    chacha20_functions

 @flags      There are no flag dependencies to enable this function.

 @param  pCtx     A pointer to a previously initialized context.
 @param  pData    A pointer to a byte array holding the data.
 @param  dataLen  The length of the pData buffer in bytes.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_data(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pData,
  ubyte4 dataLen
  );

/**
 @brief      Finalizes a previously initialized context and computes or
             verifies the MAC.

 @details    Finalizes a previously initialized context. If the context
             was initialized for encryption then the generated Poly1305
             tag will be placed in the buffer pTag. If the context was
             initialized for decryption, then pTag is an input parameter
             for the existing tag, which will then be verified.

 @ingroup    chacha20_functions

 @flags      There are no flag dependencies to enable this function.

 @param  pCtx    A pointer to a previously initialized context.
 @param  pTag    A pointer to a byte array of data. This will hold the
                 resulting tag if the context was initialized for encryption.
                 If the context was initialized for decryption, then this is
                 an input parameter for the existing tag, which will then be
                 verified.
 @param  tagLen  The length of the pTag buffer in bytes.

 @return \c OK (0) if successful including the tag being valid on decryption.
         For an invalid tag or invalid input a negative number error code
         definition from merrors.h is returned.

 @warning For authenticated decryption be sure to check the return code for
          OK before accepting that the decrypted data is authentic.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_final(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pTag,
  ubyte4 tagLen
  );

/**
 * Clone a ChaCha20Poly1305 context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  BulkCtx *ppNewCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_CHACHA20_HEADER__ */
