/*
 * slhdsa.h
 *
 * Header file for declaring SLH-DSA methods.
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
 @file       slhdsa.h
 @brief      Header file for declaring SLH-DSA methods.
 
 @filedoc    slhdsa.h
 */
#ifndef __SLHDSA_HEADER__
#define __SLHDSA_HEADER__

#include "../../common/mstdint.h"
#include "../../common/merrors.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum  {
    SLHDSA_TYPE_ERR = 0,
    SLHDSA_TYPE_SHA2_128S,
    SLHDSA_TYPE_SHA2_128F,
    SLHDSA_TYPE_SHA2_192S,
    SLHDSA_TYPE_SHA2_192F,
    SLHDSA_TYPE_SHA2_256S,
    SLHDSA_TYPE_SHA2_256F,
    SLHDSA_TYPE_SHAKE_128S,
    SLHDSA_TYPE_SHAKE_128F,
    SLHDSA_TYPE_SHAKE_192S,
    SLHDSA_TYPE_SHAKE_192F,
    SLHDSA_TYPE_SHAKE_256S,
    SLHDSA_TYPE_SHAKE_256F,
} SLHDSAType;

typedef enum  {
    SLHDSA_DIGEST_TYPE_ERR = 0,
    SLHDSA_DIGEST_TYPE_SHA256,
    SLHDSA_DIGEST_TYPE_SHA512,
    SLHDSA_DIGEST_TYPE_SHAKE128
} SLHDSADigestType;

typedef struct SLHDSAParams {
    uint8_t n;
    uint8_t h;
    uint8_t d;
    uint8_t k;
    uint8_t a;
    uint8_t m;
} SLHDSAParams;

typedef struct SLHDSACtx {
    uint32_t tag;
    SLHDSAType type;
    uint8_t *pubKey;
    size_t pubKeyLen;
    uint8_t *privKey;
    size_t privKeyLen;
    SLHDSAParams params;
    hwAccelDescr hwAccelCtx;
    uint8_t *context;
    size_t contextLen;
} SLHDSACtx;

/**
 * @brief    Creates a new SLHDSA context.
 *
 * @details  Creates a new SLHDSA context (ctx) for the specified type of SLH-DSA.
 *           Be sure to call \c SLHDSA_destroyCtx
 *           to free memory when done with the key. Ensure that the ctx is either a new, zero initialized structure or has been
 *           cleaned by calling \c SLHDSA_destroyCtx.
 *
 * @param[in] type          The type of SLH-DSA that will be used.
 * @param[in] hwAccelCtx    An optinoal hardware accelerator context. Set to NULL if not requested.
 * @param[out] ctx          The populated SLHDSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_createCtx(SLHDSAType type, hwAccelDescr hwAccelCtx, SLHDSACtx *ctx);

/**
 * @brief    Generates a new SLH-DSA key pair and stores it in the ctx.
 *
 * @details  Generates a new key pair in the given context.
 *
 * @param[in] rng           Function pointer to a random number generator.
 * @param[in] rngArg        Optional context or data for the random number generation function
 *                          pointer.
 * @param[in,out] ctx   Pointer to a SLHDSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_generateKeyPair(RNGFun rng, void *rngArg, SLHDSACtx *ctx);

/**
 * @brief    Gets the length of a public key in bytes.
 *
 * @details  Gets the length of a public key in bytes.
 *
 * @param[in] ctx          Pointer to the SLH-DSA context.
 * @param[out] publicKeyLen Contents will be set to the length of the public key in
 *                          bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_getPublicKeyLen(SLHDSACtx *ctx, size_t *publicKeyLen);

/**
 * @brief    Gets the public key.
 *
 * @details  Gets the public key.
 *
 * @param[in] ctx          Pointer to the SLH-DSA context that contains a public key.
 * @param[out] publicKey   Buffer to hold the resulting public key.
 * @param[in] publicKeyLen The length of the \c pPublicKey buffer in bytes. Must be
 *                         the value given from \c SLHDSA_getPublicKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_getPublicKey(SLHDSACtx *ctx, uint8_t *publicKey, size_t publicKeyLen);

/**
 * @brief    Sets the public key.
 *
 * @details  Sets the public key.
 *
 * @param[in] publicKey    Buffer holding the public key to be set.
 * @param[in] publicKeyLen The length of the public key in bytes.
 * @param[out] ctx         Pointer to the SLH-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, SLHDSACtx *ctx);


/**
 * @brief    Gets the length of a private key in bytes.
 *
 * @details  Gets the length of a private key in bytes.
 *
 * @param[in] ctx            Pointer to the SLH-DSA context.
 * @param[out] privateKeyLen Contents will be set to the length of the private
 *                           key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_getPrivateKeyLen(SLHDSACtx *ctx, size_t *privateKeyLen);

/**
 * @brief    Gets the private key.
 *
 * @details  Gets the private key.
 *
 * @param[in] ctx           Pointer to the SLH-DSA context that contains a private key.
 * @param[out] privateKey   Buffer to hold the resulting private key.
 * @param[in] privateKeyLen The length of the \c pprivateKey buffer in bytes. Must be
 *                          the value given from \c SLHDSA_getprivateKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_getPrivateKey(SLHDSACtx *ctx, uint8_t *privateKey, size_t privateKeyLen);

/**
 * @brief    Sets the private key.
 *
 * @details  Sets the private key.
 *
 * @param[in] publicKey    Buffer holding the public key to be set.
 * @param[in] publicKeyLen The length of the public key in bytes.
 * @param[out] ctx         Pointer to the SLH-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, SLHDSACtx *ctx);

/**
 * @brief    Sets the context string.
 *
 * @details  Sets the context string.
 *
 * @param[in] context     Buffer holding the context bytes to be set.
 * @param[in] contextLen  The length of the context in bytes.
 * @param[out] ctx        Pointer to the SLH-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_setContext(const uint8_t *context, size_t contextLen, SLHDSACtx *ctx);

/*
 * @brief    Gets the length of a signature associated with a SLHDSA key in bytes.
 *
 * @details  Gets the length of a signature associated with a SLHDSA key in bytes.
 *
 * @param[in] ctx               Pointer to the SLHDSA key.
 * @param[out] signatureLen     Contents will be set to the length of the signature or maximum length in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_getSignatureLen(SLHDSACtx *ctx, size_t *signatureLen);

/**
 * @brief    Performs the signature generation algorithm for messages.
 *
 * @details  Performs the signature generation algorithm for messages. This
 * function works on the raw message to be signed. It is domain separated from
 * \c SLHDSA_signDigest. If you are signing the hash digest of a message, use
 * \c SLHDSA_signDigest.
 *
 * @param[in] ctx            Pointer to the SLH-DSA context.
 * @param[in] message        Buffer holding the input message of the message.
 * @param[in] messageLen     The length of the message in bytes.
 * @param[in] rng            Optional function pointer to a random number generator.
 *                           If not given then deterministic mode will be performed.
 * @param[in] rngArg         Optional context or data for the random number generation function
 *                           pointer.
 * @param[out] signature     Buffer that will hold the resulting signature.
 * @param[in] signatureLen   The length of the \c signature buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_signMessage(SLHDSACtx *ctx, uint8_t *message, size_t messageLen, RNGFun rng, void *rngArg,
                                     uint8_t *signature, size_t signatureLen);

/**
 * @brief    Performs the signature generation algorithm for the digest of a
 *           message.
 *
 * @details  Performs the signature generation algorithm for the digest of a
 * message. This function works on the message digest to be signed. It is domain
 * separated from \c SLHDSA_signMessage. If you are signing the raw message, use
 * \c SLHDSA_signMessage.
 *
 * @param[in] ctx            Pointer to the SLH-DSA context.
 * @param[in] digest         Buffer holding the input message of the message.
 * @param[in] digestLen      The length of the message in bytes.
 * @param[in] digestType     The type of hash function used to create the digest.
 * @param[in] rng            Optional function pointer to a random number generator.
 *                           If not given then deterministic mode will be performed.
 * @param[in] rngArg         Optional context or data for the random number generation function
 *                           pointer.
 * @param[out] signature     Buffer that will hold the resulting signature.
 * @param[in] signatureLen   The length of the \c signature buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_signDigest(SLHDSACtx *ctx, uint8_t *digest, size_t digestLen, SLHDSADigestType digestType, RNGFun rng, void *rngArg,
                                    uint8_t *signature, size_t signatureLen);

/**
 * @brief    Performs the signature verification algorithm for raw messages.
 *
 * @details  Performs the signature verification algorithm for raw messages.
 * This function works on the raw message to be signed. It is domain separated
 * from \c SLHDSA_verifyDigest. If you are signing the hash digest of a message,
 * use \c SLHDSA_verifyDigest.
 *
 * @param[in] ctx           Pointer to the SLHDSA key.
 * @param[in] message       Buffer holding the input messasge.
 * @param[in] messageLen    The length of the message in bytes.
 * @param[in] signature     Buffer holding the signature to be verified.
 * @param[in] signatureLen  The length of the signature in bytes.
 *
 * @return   \c OK (0) on sucessful verification of the message otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_verifyMessage(SLHDSACtx *ctx, uint8_t *message, size_t messageLen, uint8_t *signature, size_t signatureLen);

/**
 * @brief    Performs the signature verification algorithm for the digest of a
 * message.
 *
 * @details  Performs the signature verification algorithm for the digest of a.
 * message. This function works on the message digest to be verified. It is domain
 * separated from \c SLHDSA_verifyMessage. If you are signing the raw message, use
 * \c SLHDSA_verifyMessage.
 *
 * @param[in] ctx           Pointer to the SLHDSA key.
 * @param[in] digest        Buffer holding the input messasge.
 * @param[in] digestLen     The length of the message in bytes.
 * @param[in] digestType    The type of hash function used to create the digest.
 * @param[in] signature     Buffer holding the signature to be verified.
 * @param[in] signatureLen  The length of the signature in bytes.
 *
 * @return   \c OK (0) on sucessful verification of the message otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_verifyDigest(SLHDSACtx *ctx, uint8_t *digest, size_t digistLen, SLHDSADigestType digestType,
                                      uint8_t *signature, size_t signatureLen);

/**
 * @brief    Clones a SLHDSA context.
 *
 * @details  Clones a new SLHDSA context from an existing context.
 *           Be sure to call \c SLHDSA_destroyCtx.
 *           to free memory when done with the new context.
 *
 * @param[in] ctx      Pointer to the existing key to be cloned.
 * @param[out] newCtx  Pointer to the location that will contain the newly
 *                  cloned context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_cloneCtx(SLHDSACtx *ctx, SLHDSACtx *newCtx);

/**
 * @brief    Validates the private and public key match.
 *
 * @details  Validates the private and public key match.
 *
 * @param[in] ctx Pointer to a context containing a private/public
 *                key pair.
 *
 * @return   \c true if successful and the keypair is valid, 
 *           otherwise \c false
 */
MOC_EXTERN bool SLHDSA_verifyKeyPair(SLHDSACtx *ctx);

/**
 * @brief    Destroys a SLH-DSA context.
 *
 * @details  Deestroys a SLH-DSA context including freeing internal structures
 *           and allocations.
 *
 * @param[out] ctx     Pointer to the location of the key to be deleted.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS SLHDSA_destroyCtx(SLHDSACtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __SLHDSA_HEADER__ */
