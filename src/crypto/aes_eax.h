/*
 * aes_eax.h
 *
 * AES-EAX Implementation
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
 * The EAX mode of operation is not tied to the AES
 * cipher, it can be used with any cipher, but this
 * implementation does not parameterize the cipher
 * used, since AES is only used for this mode currently.
 * "Do the simplest thing that works".
 *
 */

/**
 * @file       aes_eax.h
 *
 * @brief      Header file for the NanoCrypto AES-EAX mode APIs.
 *
 * @details    Header file for the NanoCrypto AES-EAX mode APIs.
 *
 * @filedoc    aes_eax.h
 */

/*------------------------------------------------------------------*/

#ifndef __AES_EAX_HEADER__
#define __AES_EAX_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes_eax_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct AES_EAX_Ctx
{
    AES_CTR_Ctx            *pAesCTRCtx;      /* used for encryption */
    AES_OMAC_Ctx            headerOMAC;         /* tweak = 1 */
    AES_OMAC_Ctx            cipherOMAC;         /* tweak = 2 */
    ubyte                   N[AES_BLOCK_SIZE];  /* OMAC of the nonce */
    MocSymCtx               pMocSymCtx;
    ubyte                   enabled;

} AES_EAX_Ctx;

/*------------------------------------------------------------------*/

/**
 * @brief   Initializes an AES-EAX context with a key and nonce value.
 *
 * @details Initializes an AES-EAX context with a key and nonce value. Memory
 *          is allocated within the AES-EAX context so be sure to call
 *          \c AES_EAX_clear to free such memory when done with the context.
 *
 * @param keyMaterial  Buffer holding an AES key.
 * @param keyLength    The length of the key in bytes. This must be 16, 24, or 32.
 * @param nonce        Optional. Buffer holding the nonce as a byte array.
 * @param nonceLength  The length of the nonce in bytes.
 * @param pCtx         Pointer to the context to be initialized.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
                                ubyte4 keyLength,
                                const ubyte* nonce,
                                ubyte4 nonceLength,
                                AES_EAX_Ctx* pCtx);

/**
 * @brief   Updates the header portion of an AES-EAX context with a buffer of data.
 *
 * @details Updates the header portion of an AES-EAX context with a buffer of data.
 *          This method may be called as many times as necessary.
 *
 * @param headerData  Buffer holding the header data as a byte array.
 * @param dataLength  The length of the header data in bytes.
 * @param pCtx        Pointer to the context to be updated.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_updateHeader(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* headerData,
                                    sbyte4 dataLength,
                                    AES_EAX_Ctx* pCtx);

/**
 * @brief   Encrypts in-place a buffer of data with an initialized AES-EAX context.
 *
 * @details Encrypts in-place a buffer of data with an initialized AES-EAX context.
 *
 * @param msgData  Buffer holding the message data to be encrypted in place.
 * @param msgLen   The length of the message data in bytes.
 * @param pCtx     Pointer to a previously initialized context.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_encryptMessage(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* msgData,
                                       sbyte4 msgLen, AES_EAX_Ctx* pCtx);

/**
 * @brief   Decrypts in-place a buffer of data with an initialized AES-EAX context.
 *
 * @details Decrypts in-place a buffer of data with an initialized AES-EAX context.
 *          This API can be used if you wish to verify the tag after decryption.
 *          If you need to verify the tag before performing any decryption, use the
 *          \c AES_EAX_generateTag API first on an initialized context, and
 *          then \c AES_EAX_getPlainText to get the plaintext.
 *
 * @param msgData  Buffer holding the message data to be decrypted in place.
 * @param msgLen   The length of the message data in bytes.
 * @param pCtx     Pointer to a previously initialized context.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_decryptMessage(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* msgData,
                                          sbyte4 msgLen, AES_EAX_Ctx* pCtx);

/**
 * @brief   Finalizes an AES-EAX encryption or decryption and outputs the tag
 *          for authentication.
 *
 * @details Finalizes an AES-EAX encryption or decryption and outputs the tag
 *          for authentication. If decrypting/verifying it is up to the user to verify
 *          that the tag output matches the expected tag. If you need to verify the
 *          tag before performing any decryption, use the \c AES_EAX_generateTag API
 *          first on an initialized context, and then \c AES_EAX_getPlainText to
 *          get the plaintext.
 *
 * @param tag      Buffer that will hold the resulting tag.
 * @param tagLen   The desired tag length in bytes. This cannot be more than 16.
 * @param pCtx     Pointer to a previously initialized and updated context.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_final(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte tag[/*tagLen*/],
                                        sbyte4 tagLen, AES_EAX_Ctx* pCtx);

/**
 * @brief   Generates an AES-EAX tag from the ciphertext and header.
 *
 * @details Generates an AES-EAX tag from the ciphertext and header. It is
 *          up to the user to verify that the tag output here matches the expected tag.
 *          This method should be used if you need to verify the tag before
 *          decrypting. You may use the \c AES_EAX_decryptMessage and \c AES_EAX_final
 *          APIs to decrypt and then verify a tag.
 *
 * @param cipherText  Buffer holding the input ciphertext.
 * @param cipherLen   The length of the ciphertext in bytes.
 * @param header      Optional. Buffer holding the header as a byte array.
 * @param headerLen   The length of the header in bytes.
 * @param tag         Buffer that will hold the resulting tag.
 * @param tagLen      The desired tag length in bytes. This cannot be more than 16.
 * @param pCtx        Pointer to a previously initialized context.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_generateTag( MOC_SYM(hwAccelDescr hwAccelCtx)
                                   const ubyte* cipherText, sbyte4 cipherLen,
                                   const ubyte* header, sbyte4 headerLen,
                                   ubyte tag[/*tagLen*/], sbyte4 tagLen,
                                   AES_EAX_Ctx* pCtx);

/**
 * @brief   Decrypts ciphertext in-place from an initialized AES-EAX context.
 *
 * @details Decrypts ciphertext in-place from an initialized AES-EAX context. This
 *          does not compute the tag. This API may be called as many times as neccessary.
 *          This API is provided for the case that the tag has already been computed
 *          and verified via \c AES_EAX_generateTag. If you wish to verify the tag
 *          after decryption then you may also use the \c AES_EAX_decryptMessage API
 *          to decrypt.
 *
 * @param cipherText  Buffer holding the input ciphertext.
 * @param cipherLen   The length of the ciphertext in bytes.
 * @param pCtx        Pointer to a previously initialized context.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_getPlainText(  MOC_SYM(hwAccelDescr hwAccelCtx)
                                    ubyte* cipherText, sbyte4 cipherLen,
                                    AES_EAX_Ctx* pCtx);

/**
 * @brief   Zeros and frees memory allocated within an AES-EAX context.
 *
 * @details Zeros and frees memory allocated within an AES-EAX context.
 *
 * @param pCtx     Pointer to the context to be cleared.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc aes_eax.h
 */
MOC_EXTERN MSTATUS AES_EAX_clear(MOC_SYM(hwAccelDescr hwAccelCtx) AES_EAX_Ctx* pCtx);

#ifdef __cplusplus
}
#endif

#endif /* __AES_EAX_HEADER__ */

