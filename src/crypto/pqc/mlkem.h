/*
 * mlkem.h
 *
 * Header file for declaring ML-KEM methods.
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
 @file       mlkem.h
 @brief      Header file for declaring ML-KEM methods.
 
 @filedoc    mlkem.h
 */
#ifndef __MLKEM_HEADER__
#define __MLKEM_HEADER__

#include "../../common/mstdint.h"
#include "../../common/merrors.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum  {
    MLKEM_TYPE_ERR = 0,
    MLKEM_TYPE_512,
    MLKEM_TYPE_768,
    MLKEM_TYPE_1024
} MLKEMType;

typedef struct MLKEMParams {
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
    uint32_t du;
    uint32_t dv;
} MLKEMParams;

typedef struct MLKEMCtx {
    uint32_t tag;
    MLKEMType type;
    uint8_t *encKey;
    size_t encKeyLen;
    uint8_t *decKey;
    size_t decKeyLen;
    MLKEMParams params;
    hwAccelDescr hwAccelCtx;
} MLKEMCtx;

/**
 * @brief    Creates a new ML-KEM context.
 *
 * @details  Creates a new ML-KEM context (ctx) for the specified type of ML-KEM.
 *           Be sure to call \c MLKEM_destroyCtx
 *           to free memory when done with the key. Ensure that the ctx is
 *           either a new, zero initialized structure or has been cleaned by
 *           calling \c MLKEM_destroyCtx.
 *
 * @param[in] type          The type of ML-KEM that will be used.
 * @param[in] hwAccelCtx    An optinoal hardware accelerator context. Set to
 *                          NULL if not requested.
 * @param[out] ctx          The populated ML-KEM context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_createCtx(MLKEMType type, hwAccelDescr hwAccelCtx, MLKEMCtx *ctx);

/**
 * @brief    Generates a new key pair.
 *
 * @details  Generates a new key pair.
 *
 * @param[in] rng       Function pointer to a random number generator.
 * @param[in] rngArg    Optional context or data for the random number
 *                      generation function pointer.
 * @param[in,out] ctx   Pointer to a ML-KEM context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_generateKeyPair(RNGFun rng, void *rngArg, MLKEMCtx *ctx);

/**
 * @brief    Gets the length of a public key in bytes.
 *
 * @details  Gets the length of a public key in bytes.
 *
 * @param[in] ctx          Pointer to the ML-KEM context.
 * @param[out] publicKeyLen Contents will be set to the length of the public key in
 *                          bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getPublicKeyLen(MLKEMCtx *ctx, size_t *publicKeyLen);

/**
 * @brief    Gets the public key.
 *
 * @details  Gets the public key.
 *
 * @param[in] ctx          Pointer to the ML-KEM context that contains a public key.
 * @param[out] publicKey   Buffer to hold the resulting public key.
 * @param[in] publicKeyLen The length of the \c pPublicKey buffer in bytes. Must be
 *                         the value given from \c MLKEM_getPublicKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getPublicKey(MLKEMCtx *ctx, uint8_t *publicKey, size_t publicKeyLen);

/**
 * @brief    Sets the public key.
 *
 * @details  Sets the public key.
 *
 * @param[in] publicKey    Buffer holding the public key to be set.
 * @param[in] publicKeyLen The length of the public key in bytes.
 * @param[out] ctx         Pointer to the ML-KEM context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, MLKEMCtx *ctx);

/**
 * @brief    Gets the length of a private key in bytes.
 *
 * @details  Gets the length of a private key in bytes.
 *
 * @param[in] ctx            Pointer to the ML-KEM context.
 * @param[out] privateKeyLen Contents will be set to the length of the private
 *                           key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getPrivateKeyLen(MLKEMCtx *ctx, size_t *privateKeyLen);

/**
 * @brief    Sets the private key.
 *
 * @details  Sets the private key.
 *
 * @param[in] privateKey    Buffer holding the public key to be set.
 * @param[in] privateKeyLen The length of the public key in bytes.
 * @param[out] ctx          Pointer to the ML-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, MLKEMCtx *ctx);

/**
 * @brief    Gets the private key.
 *
 * @details  Gets the private key.
 *
 * @param[in] ctx           Pointer to the ML-KEM context that contains a private key.
 * @param[out] privateKey   Buffer to hold the resulting private key.
 * @param[in] privateKeyLen The length of the \c pprivateKey buffer in bytes. Must be
 *                          the value given from \c MLKEM_getprivateKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getPrivateKey(MLKEMCtx *ctx, uint8_t *privateKey, size_t privateKeyLen);

/**
 * @brief    Gets the length of the ciphertext associated with a ML-KEM key in bytes.
 *
 * @details  Gets the length of the ciphertext associated with a ML-KEM key in bytes.
 *
 * @param[in] ctx          Pointer to the ML-KEM key.
 * @param[out] cipherLen   Contents will be set to the length of the ciphertext in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getCipherTextLen(MLKEMCtx *ctx, size_t *cipherTextLen);

/**
 * @brief    Gets the length of a shared secret associated with a ML-KEM key in bytes.
 *
 * @details  Gets the length of a shared secret associated with a ML-KEM key in bytes.
 *
 * @param[in] ctx              Pointer to the ML-KEM key.
 * @param[out] sharedSecretLen Contents will be set to the length of the shared secret in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_getSharedSecretLen(MLKEMCtx *ctx, size_t *sharedSecretLen);

/**
 * @brief    Performs the key encapsulation algorithm.
 *
 * @details  Performs the key encapsulation algorithm.
 *
 * @param[in] ctx               Pointer to a previously allocated public (or private) key.
 * @param[in] rngFun            Function pointer to a random number generation function.
 * @param[in] pRngFunArg        Optional context or data for the random number generation function
 *                              pointer.
 * @param[out] cipherText       Buffer that will hold the resulting ciphertext.
 * @param[in] cipherTextLen     The length of the \c pCipherText buffer in bytes.
 * @param[out] sharedSecret     Buffer that will hold the resulting shared secret.
 * @param[in] sharedSecretLen   The length of the \c pSharedSecret buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_encapsulate(MLKEMCtx *ctx, RNGFun rngFun, void *rngFunArg, uint8_t *cipherText, size_t cipherTextLen,
                                     uint8_t *sharedSecret, size_t sharedSecretLen);

/**
 * @brief    Performs the key decapsulation algorithm.
 *
 * @details  Performs the key decapsulation algorithm.
 *
 * @param[in] ctx              Pointer to a previously allocated private key.
 * @param[in] cipherText       Buffer holding the input ciphertext.
 * @param[in] cipherTextLen    The length of the ciphertext in bytes.
 * @param[out] sharedSecret    Buffer that will hold the resulting shared secret.
 * @param[in sharedSecretLen   The length of the \c pSharedSecret buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_decapsulate(MLKEMCtx *ctx, uint8_t *cipherText, size_t cipherTextLen,
                                     uint8_t *sharedSecret, size_t sharedSecretLen);

/**
 * @brief    Clones a MLKEM context.
 *
 * @details  Clones a new MLKEM context from an existing context.
 *           Be sure to call \c MLKEM_destroyCtx.
 *           to free memory when done with the new context.
 *
 * @param[in] ctx      Pointer to the existing key to be cloned.
 * @param[out] newCtx  Pointer to the location that will contain the newly
 *                  cloned context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_cloneCtx(MLKEMCtx *ctx, MLKEMCtx *newCtx);

/**
 * @brief    Validates the private and public key match.
 *
 * @details  Validates the private and public key match.
 *
 * @param[in] ctx         Pointer to a context containing a private/public
 *                        key pair.
 * @param[in] rngFun      Optional, function pointer to a random number generation function. If
 *                        provided a full roundtrip encrypt/decrypt test will occur.
 * @param[in] pRngFunArg  Optional context or data for the random number generation function
 *                        pointer.
 *
 * @return   \c true if successful and the keypair is valid, 
 *           otherwise \c false
 */
MOC_EXTERN bool MLKEM_verifyKeyPair(MLKEMCtx *ctx, RNGFun rngFun, void *pRngFunArg);

/**
 * @brief    Destroys a ML-KEM context.
 *
 * @details  Deestroys a ML-KEM context including freeing internal structures
 *           and allocations.
 *
 * @param[out] ctx     Pointer to the location of the key to be deleted.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLKEM_destroyCtx(MLKEMCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __MLKEM_HEADER__ */
