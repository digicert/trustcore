/*
 * primeec_eg.h
 *
 * Header for Elliptic Curve El-Gamal Encryption/Decryption operations.
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
 * @file       primeec_eg.h
 *
 * @brief      Header for Elliptic Curve El-Gamal operations.
 *
 * @details    Documentation file for Elliptic Curve El-Gamal APIs.
 *
 * @flags      To enable the methods in this file one must define both flags
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             + \c \__ENABLE_DIGICERT_ECC_ELGAMAL__
 *
 * @filedoc    primeec_eg.h
 */

/*------------------------------------------------------------------*/

#ifndef __PRIMEEC_EG_HEADER__
#define __PRIMEEC_EG_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc_eg_priv.h"
#endif

#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/random.h"
/* for primefld headers just in case its enabled */
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../common/vlong.h"
#endif
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec.h"
#include "../crypto/primeec_priv.h"

#ifdef __cplusplus
extern "C" {
#endif
 
#define MOCANA_ECEG_ENCRYPT 0
#define MOCANA_ECEG_DECRYPT 1

#define MOCANA_ECEG_CTR_LEN 4
    
typedef struct ECEG_CTX
{
    ECCKey *pKey;
    ubyte *pBuffer;
    ubyte4 position;
    ubyte4 inputBlockLen;
    ubyte4 outputBlockLen;
    byteBoolean isEncrypt;
    RNGFun rngFun;
    void *pRngArg;
    byteBoolean isInitialized;
        
} ECEG_CTX;


/**
 * @brief    Initializes an \c ECEG_CTX context for encryption or decryption.
 *
 * @details  Initializes an \c ECEG_CTX context for encryption or decryption.
 *           Encryption only will require the use of an random number generator
 *           \c rngFun.
 *
 * @param pCtx        Pointer to the context to be initialized.
 * @param pKey        Pointer to an \c ECCKey. This must be a public key for encryption
 *                    and a private key for decryption.
 * @param direction   The macro MOCANA_ECEG_ENCRYPT (0) for encryption or the macro
 *                    MOCANA_ECEG_DECRYPT (1 or anything nonzero) for decryption.
 * @param rngFun      Function pointer callback to a method that will provide random entropy.
 *                    This is only required for encryption and should be NULL for decryption.
 * @param pRngArg     Optional argument that may be needed by the \c rngFun provided.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_init(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ECCKey *pKey, ubyte direction, RNGFun rngFun, void *pRngArg, void *pExtCtx);


/**
 * @brief    Updates an \c ECEG_CTX context with data to be encrypted or decrypted.
 *
 * @details  Updates an \c ECEG_CTX context with data to be encrypted or decrypted.
 *           This method may be called as many times as neccessary. Output will be
 *           written to the \c pOutputData every time at least a full block length
 *           of input data has been surpassed in total. Please see the \c ECEG_encrypt and
 *           \c ECEG_decrypt descriptions for more about input and output block lengths.
 *
 * @param pCtx          Pointer to the context to be updated.
 * @param pInputData    The buffer of input data.
 * @param inputDataLen  The length of the input data in bytes.
 * @param pOutputData   Buffer that will hold the resulting output. There will only
 *                      be output if we have surpassed another full block length
 *                      of input data in total.
 * @param outputDataBufferLen  The length of the pOutputData buffer in bytes.
 * @param pBytesWritten        Contents will be set to the number of bytes actually written
 *                             to the pOutputData buffer.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @warning           When decrypting, any bytes representing a counter prepended to a
 *                    block of plaintext during encryption, are NOT removed. If encryption
 *                    was done via MOCANA's APIs then this consists of 4 prepended bytes.
 *                    It is up to the user to remove or ignore these bytes (ie each block
 *                    of plaintext recovered will be 4 bytes longer than the original
 *                    plaintext). Encryption with other products may have a differing
 *                    protocol with respect to the size and placement of the counter.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_update(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ubyte *pInputData, ubyte4 inputDataLen, ubyte *pOutputData, ubyte4 outputDataBufferLen, ubyte4 *pBytesWritten, void *pExtCtx);


/**
 * @brief    Finalizes an \c ECEG_CTX context.
 *
 * @details  Finalizes an \c ECEG_CTX context. This will validate that the
 *           total input length of data was a valid multiple of the input block
 *           length, and if so will free and cleanup memory. Please see the
 *           \c ECEG_encrypt and \c ECEG_decrypt descriptions for more about
 *           the input block length.
 *
 * @param pCtx        Pointer to the context to be finalized.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_final(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, void *pExtCtx);


/**
 * @brief    A one-shot El-Gamal encryption API.
 *
 * @details  A one-shot El-Gamal encryption API. This will allocate a buffer to hold
 *           the resulting ciphertext. Be sure to FREE this buffer when done. Note the
 *           \c plaintextLen must be a multiple of the plaintext block size. This
 *           plaintext blocksize is 4 bytes less than the curve's coordinate size in bytes.
 *
 * @param pPublicKey    Pointer to the public key to be used for encryption.
 * @param rngFun        Function pointer callback to a method that will provide random entropy.
 * @param pRngArg       Optional argument that may be needed by the \c rngFun provided.
 * @param pPlaintext    The buffer of data to be encrypted.
 * @param plaintextLen  The length of the plaintext in bytes. This must be a
 *                      multiple of 4 bytes less than the curve's coordinate size in bytes.
 *                      You may use the following table...
 *
 *                      + P192   plaintextLen should be a multiple of 20 bytes.
 *                      + P224   plaintextLen should be a multiple of 24 bytes.
 *                      + P256   plaintextLen should be a multiple of 28 bytes.
 *                      + P384   plaintextLen should be a multiple of 44 bytes.
 *                      + P521   plaintextLen should be a multiple of 62 bytes.
 *
 * @param ppCiphertext    Pointer to an allocated buffer that will hold the resulting ciphertext.
 * @param pCiphertextLen  Contents will be set to the number of bytes written to the allocated buffer
 *                        pointed to by \c ppCiphertext.
 * @param pExtCtx         An extended context reserved for future use.
 *
 * @return              \c OK (0) if successful, otherwise a negative number error
 *                      code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_encrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte4 plaintextLen, ubyte **ppCiphertext, ubyte4 *pCiphertextLen, void *pExtCtx);

/**
 * @brief    A one-shot El-Gamal decryption API.
 *
 * @details  A one-shot El-Gamal decryption API. This will allocate a buffer to hold
 *           the resulting plaintext. Be sure to FREE this buffer when done. Note the
 *           \c ciphertextLen must be a multiple of the ciphertext block size. This
 *           ciphertext blocksize is 4 times the curve's coordinate size in bytes.
 *
 * @param pPrivateKey   Pointer to the private key to be used for decryption.
 * @param pCiphertext   The buffer of data to be decrypted.
 * @param ciphertextLen The length of the ciphertext in bytes. This must be a
 *                      multiple of 4 times the curve's coordinate size in bytes.
 *                      You may use the following table...
 *
 *                      + P192   ciphertextLen should be a multiple of 96 bytes.
 *                      + P224   ciphertextLen should be a multiple of 112 bytes.
 *                      + P256   ciphertextLen should be a multiple of 128 bytes.
 *                      + P384   ciphertextLen should be a multiple of 192 bytes.
 *                      + P521   ciphertextLen should be a multiple of 264 bytes.
 *
 * @param ppPlaintext    Pointer to an allocated buffer that will hold the resulting plaintext.
 * @param pPlaintextLen  Contents will be set to the number of bytes written to the allocated buffer
 *                       pointed to by \c ppPlaintext.
 * @param pExtCtx        An extended context reserved for future use.
 *
 * @warning             Any bytes representing a counter prepended to a block of plaintext
 *                      during encryption are NOT removed. If encryption was done via
 *                      MOCANA's APIs then this consists of 4 prepended bytes. It is
 *                      up to the user to remove or ignore these bytes (ie each block
 *                      of plaintext recovered will be 4 bytes longer than the original
 *                      plaintext). Encryption with other products may have a differing
 *                      protocol with respect to the size and placement of the counter.
 *
 * @return              \c OK (0) if successful, otherwise a negative number error
 *                      code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_decrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte **ppPlaintext, ubyte4 *pPlaintextLen, void *pExtCtx);


/**
 * @brief    Performs El-Gamal encryption with PKCS v1.5 padding of a small plaintext message.
 *
 * @details  Performs El-Gamal encryption with PKCS v1.5 padding of a small plaintext message.
 *           The \c plaintextLen will be padded up to a full input block length, and thus cannot
 *           be bigger than 15 bytes less than the curve's coordinate size. Therefore we
 *           recommend only using P256, P384, or P521 with this API.
 *
 * @param pPublicKey    Pointer to the public key to be used for encryption.
 * @param rngFun        Function pointer callback to a method that will provide random entropy.
 * @param pRngArg       Optional argument that may be needed by the \c rngFun provided.
 * @param pPlaintext    The buffer of data to be encrypted.
 * @param plaintextLen  The length of the plaintext in bytes. This cannot be more
 *                      than 15 bytes less than the curve's coordinate size...
 *
 *                      + P192   plaintextLen cannot be bigger than 9 bytes.
 *                      + P224   plaintextLen cannot be bigger than 13 bytes.
 *                      + P256   plaintextLen cannot be bigger than 17 bytes.
 *                      + P384   plaintextLen cannot be bigger than 33 bytes.
 *                      + P521   plaintextLen cannot be bigger than 51 bytes.
 *
 * @param pCiphertext   A buffer that will hold the resulting ciphertext. The length of the
 *                      ciphertext will always be 4 times the curve's coordinate size in bytes...
 *
 *                      + P192   this buffer length should be 96 bytes.
 *                      + P224   this buffer length should be 112 bytes.
 *                      + P256   this buffer length should be 128 bytes.
 *                      + P384   this buffer length should be 192 bytes.
 *                      + P521   this buffer length should be 264 bytes.
 *
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @return              \c OK (0) if successful, otherwise a negative number error
 *                      code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_encryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte4 plaintextLen, ubyte *pCiphertext, void *pExtCtx);


/**
 * @brief    Performs El-Gamal decryption and removal of PKCS v1.5 padding.
 *
 * @details  Performs El-Gamal decryption and removal of PKCS v1.5 padding. In addition
 *           it is assumed there is a 4 byte counter prepended to the padded plaintext
 *           and that is also removed. The input ciphertext must consist of a single block,
 *           and thus \c ciphertextLen must be 4 times the curve's coordinate size in bytes.
 *
 * @param pPrivateKey   Pointer to the private key to be used for decryption.
 * @param pCiphertext   The buffer of ciphertext to be decrypted.
 * @param ciphertextLen The length of the ciphertext in bytes. This must be 4 times
 *                      the curve's coordinate size in bytes. You may use the table...
 *
 *                      + P192   ciphertextLen should be 96 bytes.
 *                      + P224   ciphertextLen should be 112 bytes.
 *                      + P256   ciphertextLen should be 128 bytes.
 *                      + P384   ciphertextLen should be 192 bytes.
 *                      + P521   ciphertextLen should be 264 bytes.
 *
 * @param pPlaintext    Buffer to hold the resulting plaintext. The padding will be removed
 *                      and the original plaintext will be written. If apriori you don't
 *                      know the length of the resulting plaintext, make sure this buffer has
 *                      enough space for the curve's coordinate size in bytes minus 15.
 * @param pExtCtx       An extended context reserved for future use.
 *
 * @warning             The \c ECEG_decryptPKCSv1p5 API assumes encryption used a 4 byte
 *                      counter prepended to the padded plaintext. This API will not
 *                      work with an encrytion product that has a different counter size
 *                      or counter placement protocol.
 *
 * @return              \c OK (0) if successful, otherwise a negative number error
 *                      code from merrors.h
 */
MOC_EXTERN MSTATUS ECEG_decryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte *pPlaintext, void *pExtCtx);

#ifdef __cplusplus
}
#endif

#endif /* __PRIMEEC_EG_HEADER__ */
