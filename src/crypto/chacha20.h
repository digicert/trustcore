/*
 * chacha20.h
 *
 * ChaCha20 Implementation
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
/*------------------------------------------------------------------*/

#ifndef __CHACHA20_HEADER__
#define __CHACHA20_HEADER__

#include "../cap/capdecl.h"

#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
#include "../crypto_interface/crypto_interface_chacha20_priv.h"
#endif

#include "../crypto/poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEYSTREAM_SIZE (64)

    typedef struct ChaCha20Ctx
    {
        ubyte4  schedule[16];
        ubyte   keystream[CHACHA20_KEYSTREAM_SIZE];
        ubyte   streamOffset; /* next available position in keyStream */
#ifdef __ENABLE_MOCANA_POLY1305__
        byteBoolean encrypt;      /* encrpyt vs decrypt flag */
        byteBoolean aadFinalized;
        ubyte4  aadLen;
        ubyte4  dataLen;
        Poly1305Ctx tagCtx;
#endif
        MocSymCtx pMocSymCtx;
        ubyte enabled;
    } ChaCha20Ctx;

/* the Mocana canonical prototypes for encryption */

/**
 @brief      Creates and initializes a context for use in the chacha20 stream
             cipher algorithm.

 @details    Creates and initializes a context for use in the chacha20 stream
             cipher algorithm, ie the DoChaCha20 API. Please be sure to call
             DeleteChaCha20Ctx when finished with the context.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flag must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__

 @inc_file   chacha20.h

 @param  pKeyMaterial A pointer to a buffer holding the concatenation of the
                      32 byte key, 4 byte little Endian counter, and 12 byte nonce.
 @param  keyLength    The length of the keyMaterial in bytes. This must be 48.
 @param  encrypt      Unused.

 @return \c A new initialized context will be returned upon success. Otherwise
         NULL will be returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN BulkCtx CreateChaCha20Ctx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                      const ubyte *pKeyMaterial,
                                      sbyte4 keyLength,
                                      sbyte4 encrypt);

/**
 @brief      Deletes a previously created ChaCha20 context.

 @details    Deletes a previously created ChaCha20 context.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flag must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__

 @inc_file   chacha20.h

 @param  pCtx    A pointer to a previously created context.

 @return \c OK (0) if successful. For invalid input a negative number error
         code definition from merrors.h is returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS DeleteChaCha20Ctx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                      BulkCtx *pCtx);

/**
 @brief      Performs the ChaCha20 stream cipher operation via a previously
             created context.

 @details    Performs the ChaCha20 stream cipher operation via a previously
             created context.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flag must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__

 @inc_file   chacha20.h

 @param  ctx         A previously initialized context.
 @param  pData       A buffer of data to be encrypted or decrypted.
 @param  dataLength  The length of pData in bytes.
 @param  encrypt     Unused. ChaCha20 is a stream cipher hence the same
                     operation is done for encryption as for decryption.
 @param pIv          Optional. If provided, it will be used as the counter and
                     nonce in the creation of future blocks of key stream. The
                     latest IV (ie counter and nonce) will then be written to
                     this buffer.

 @return \c OK (0) if successful For invalid input a negative number error code
         definition from merrors.h is returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS DoChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                               ubyte *pData, sbyte4 dataLength,
                               sbyte4 encrypt, ubyte *pIv);

/**
 @brief      Set values for the nonce and counter blocks for ChaCha20 context.
             This function specifically is for ssh protocol, this function assumes
             an 8 byte counter and an 8 byte nonce.

 @details    Set values for the nonce and counter blocks for ChaCha20 context.
             This function specifically is for ssh protocol, this function assumes
             an 8 byte counter and an 8 byte nonce.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flag must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__

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
MOC_EXTERN MSTATUS CHACHA20_setNonceAndCounterSSH(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
    ubyte *pNonce,
    ubyte4 nonceLength,
    ubyte *pCounter,
    ubyte counterLength
    );

/**
 * @brief Clone a ChaCha20 context.
 *
 * @param pCtx      Pointer to an instantiated BulkCtx.
 * @param ppNewCtx  Double pointer to the BulkCtx to be created and populated
 *                    with the data from the source context.
 * @return          \c OK (0) if successful; otherwise a negative number error
 *                  code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CloneChaCha20Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

#if defined(__ENABLE_MOCANA_POLY1305__)
/* ChaCha20Poly1305 AEAD cipher */

/**
 @brief      Creates and initializes a context for use in the chacha20poly1305
             AEAD algorithm.

 @details    Creates and initializes a context for use in the chacha20poly1305
             AEAD algorithm. Please be sure to call ChaCha20Poly1305_deleteCtx
             when finished with the context.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  pKey     A pointer to a buffer holding the 32 byte key.
 @param  keyLen   The length of the keyMaterial in bytes. This must be 32.
 @param  encrypt  Enter one (or nonzero) for encryption and 0 for decryption.

 @return \c A new initialized context will be returned upon success. Otherwise
         NULL will be returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN BulkCtx ChaCha20Poly1305_createCtx( MOC_SYM(hwAccelDescr hwAccelCtx)
                                              ubyte *pKey, sbyte4 keyLen,
                                              sbyte4 encrypt);


/**
 @brief      Deletes a previously created ChaCha20Poly1305 context.

 @details    Deletes a previously created ChaCha20Poly1305 context.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  pCtx    A pointer to a previously created context.

 @return \c OK (0) if successful. For invalid input a negative number error
         code definition from merrors.h is returned.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS ChaCha20Poly1305_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                              BulkCtx *pCtx);


/**
 @brief      Performs the ChaCha20poly1305 AEAD algorithm as specified for SSH
             authentication protocol.

 @details    Performs the ChaCha20poly1305 AEAD algorithm as specified for SSH
             authentication protocol.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

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
MOC_EXTERN MSTATUS ChaCha20Poly1305_cipherSSH(MOC_SYM(hwAccelDescr hwAccelCtx)
                                           BulkCtx ctx,
                                           ubyte *pNonce, ubyte4 nlen,
                                           ubyte *pAdata, ubyte4 alen,
                                           ubyte *pData,  ubyte4 dlen,
                                           ubyte4 verifyLen, sbyte4 encrypt);

/**
 @brief      Performs the ChaCha20poly1305 AEAD algorithm all in one-shot with
             a previously created context.

 @details    Performs the ChaCha20poly1305 AEAD algorithm all in one-shot with
             a context previouly created via the ChaCha20Poly1305_createCtx API.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  ctx        A previously created context.
 @param  pNonce     Buffer that holds the nonce.
 @param  nlen       The length of pNonce in bytes. This must be 12.
 @param  pAdata     Buffer that holds the additional authenticated data.
                    This is optional and may be NULL.
 @param  alen       The length of pAdata in bytes.
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
MOC_EXTERN MSTATUS ChaCha20Poly1305_cipher(MOC_SYM(hwAccelDescr hwAccelCtx)
                                           BulkCtx ctx,
                                           ubyte *pNonce, ubyte4 nlen,
                                           ubyte *pAdata, ubyte4 alen,
                                           ubyte *pData,  ubyte4 dlen,
                                           ubyte4 verifyLen, sbyte4 encrypt);

/**
 @brief      Adds the nonce value to a ChaCha20Ctx context data structure
             for use with the Poly1305 MAC algorithm.

 @details    Adds the nonce value to a ChaCha20Ctx context data structure
             for use with the Poly1305 MAC algorithm. The counter will
             be initialized to 0.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param ctx       A pointer to a previously initialized context.
 @param pNonce    A pointer to a byte array holding the 12 byte nonce.
 @param nonceLen  The length of the pNonce buffer in bytes. This must be 12.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS ChaCha20Poly1305_update_nonce(MOC_SYM(hwAccelDescr hwAccelCtx)
                                                 BulkCtx ctx,
                                                 ubyte *pNonce,
                                                 ubyte4 nonceLen
                                                 );

/**
 @brief      Updates a ChaCha20Ctx context with additional authenticated data.

 @details    Updates an initialized context with additional authenticated
             data (AAD). One may call update as many times as needed with
             portions of the AAD. All calls to ChaCha20Poly1305_update_aad
             must happen before calling ChaCha20Poly1305_update_data.

 @ingroup    chacha20_functions

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  ctx         A pointer to a previously initialized context.
 @param  pAadData    A pointer to a byte array holding the AAD.
 @param  aadDataLen  The length of the pAadData buffer in bytes.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS ChaCha20Poly1305_update_aad(MOC_SYM(hwAccelDescr hwAccelCtx)
                                               BulkCtx ctx,
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

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  ctx      A pointer to a previously initialized context.
 @param  pData    A pointer to a byte array holding the data.
 @param  dataLen  The length of the pData buffer in bytes.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS ChaCha20Poly1305_update_data(MOC_SYM(hwAccelDescr hwAccelCtx)
                                                BulkCtx ctx,
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

 @flags      To enable this method, the following flags must be defined:
             + \c \__ENABLE_MOCANA_CHACHA20__
             + \c \__ENABLE_MOCANA_POLY1305__

 @inc_file   chacha20.h

 @param  ctx     A pointer to a previously initialized context.
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

 @funcdoc    chacha20.c
 */
MOC_EXTERN MSTATUS ChaCha20Poly1305_final(MOC_SYM(hwAccelDescr hwAccelCtx)
                                          BulkCtx ctx,
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
MOC_EXTERN MSTATUS ChaCha20Poly1305_cloneCtx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                             BulkCtx pCtx,
                                             BulkCtx *ppNewCtx
                                             );

#endif /* defined(__ENABLE_MOCANA_POLY1305__) */

#ifdef __cplusplus
}
#endif

#endif /* __CHACHA20_HEADER__ */
