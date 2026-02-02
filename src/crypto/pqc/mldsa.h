/*
 * mldsa.h
 *
 * Header file for declaring ML-DSA methods. An implementation of
 * https://csrc.nist.gov/pubs/fips/204/final
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
 @file       mldsa.h
 @brief      Header file for declaring ML-DSA methods.

 @filedoc    mldsa.h
 */
#ifndef __MLDSA_HEADER__
#define __MLDSA_HEADER__

#include "../../common/mstdint.h"
#include "../../common/merrors.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MLDSA_SEED_LEN 32

typedef enum {
    MLDSA_TYPE_ERR = 0,
    MLDSA_TYPE_44,
    MLDSA_TYPE_65,
    MLDSA_TYPE_87
} MLDSAType;

typedef enum {
    MLDSA_DIGEST_TYPE_ERR = 0,
    MLDSA_DIGEST_TYPE_SHA256,
    MLDSA_DIGEST_TYPE_SHA512,
    MLDSA_DIGEST_TYPE_SHAKE128
} MLDSADigestType;

typedef struct MLDSAParams {
    uint8_t k;
    uint8_t l;
    uint8_t beta;
    uint32_t gamma1;
    uint32_t gamma2;
    uint8_t eta;
    uint8_t tau;
    uint8_t omega;
} MLDSAParams;

typedef struct MLDSACtx {
    uint32_t tag;
    MLDSAType type;
    byteBoolean initialized;
    byteBoolean isExternalMu;
    ubyte digestId;
    BulkCtx pHCtx;
    BulkCtx pPreHashCtx;
    uint8_t *pubKey;
    size_t pubKeyLen;
    uint8_t privKeySeed[MLDSA_SEED_LEN];
    uint8_t *privKey;
    size_t privKeyLen;
    MLDSAParams params;
    int32_t (*decompose)(int32_t, int32_t *);
    hwAccelDescr hwAccelCtx;
    uint8_t *context;
    size_t contextLen;
} MLDSACtx;

/*
 * @brief    Creates a new MLDSA context.
 *
 * @details  Creates a new MLDSA context (ctx) for the specified type of ML-DSA.
 *           Be sure to call \c MLDSA_destroyCtx
 *           to free memory when done with the key. Ensure that the ctx is either a new, zero initialized structure or has been
 *           cleaned by calling \c MLDSA_destroyCtx.
 *
 * @param[in] type          The type of ML-DSA that will be used.
 * @param[in] hwAccelCtx    An optinoal hardware accelerator context. Set to NULL if not requested.
 * @param[out] ctx          The populated MLDSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
/* XXX having to pass in the RNG here just to verify is a bit annoying but it does make setting up the context the same all the time which I
 * like.
 * There is an option to allow users to pass in NULL for the RNG and we can automatically set it to RANDOM_rng with the global rng
 * context, thoughts?
 * I'm not 100% convinced to put the RNG here. putting it back in sign and keygen might be worth the extra parameters.
 */
MOC_EXTERN MSTATUS MLDSA_createCtx(MLDSAType type, hwAccelDescr hwAccelCtx, MLDSACtx *ctx);

/**
 * @brief    Generates a new ML-DSA key pair and stores it in the ctx.
 *
 * @details  Generates a new key pair in the given context.
 *
 * @param[in] rng           Function pointer to a random number generator.
 * @param[in] rngArg        Optional context or data for the random number generation function
 *                          pointer.
 * @param[in,out] ctx   Pointer to a MLDSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_generateKeyPair(RNGFun rng, void *rngArg, MLDSACtx *ctx);

/**
 * @brief    Gets the length of a public key in bytes.
 *
 * @details  Gets the length of a public key in bytes.
 *
 * @param[in] ctx          Pointer to the ML-DSA context.
 * @param[out] publicKeyLen Contents will be set to the length of the public key in
 *                          bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_getPublicKeyLen(MLDSACtx *ctx, size_t *publicKeyLen);

/**
 * @brief    Gets the public key.
 *
 * @details  Gets the public key.
 *
 * @param[in] ctx          Pointer to the ML-DSA context that contains a public key.
 * @param[out] publicKey   Buffer to hold the resulting public key.
 * @param[in] publicKeyLen The length of the \c pPublicKey buffer in bytes. Must be
 *                         the value given from \c MLDSA_getPublicKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_getPublicKey(MLDSACtx *ctx, uint8_t *publicKey, size_t publicKeyLen);

/**
 * @brief    Sets the public key.
 *
 * @details  Sets the public key.
 *
 * @param[in] publicKey    Buffer holding the public key to be set.
 * @param[in] publicKeyLen The length of the public key in bytes.
 * @param[out] ctx         Pointer to the ML-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, MLDSACtx *ctx);


/**
 * @brief    Gets the length of a private key in bytes.
 *
 * @details  Gets the length of a private key in bytes.
 *
 * @param[in] ctx            Pointer to the ML-DSA context.
 * @param[out] privateKeyLen Contents will be set to the length of the private
 *                           key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_getPrivateKeyLen(MLDSACtx *ctx, size_t *privateKeyLen);

/**
 * @brief    Gets the private key.
 *
 * @details  Gets the private key.
 *
 * @param[in] ctx           Pointer to the ML-DSA context that contains a private key.
 * @param[out] privateKey   Buffer to hold the resulting private key.
 * @param[in] privateKeyLen The length of the \c privateKey buffer in bytes. Must be
 *                          the value given from \c MLDSA_getprivateKeyLen.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_getPrivateKey(MLDSACtx *ctx, uint8_t *privateKey, size_t privateKeyLen);

/**
 * @brief    Sets the private key.
 *
 * @details  Sets the private key whether the full expanded key or the seed.
 *           Note the public key will not be set if its a full expanded key.
 *
 * @param[in] privateKey    Buffer holding the private key to be set.
 * @param[in] privateKeyLen The length of the private key or its seed in bytes.
 * @param[out] ctx          Pointer to the ML-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, MLDSACtx *ctx);

/**
 * @brief    Sets the context string.
 *
 * @details  Sets the context string.
 *
 * @param[in] context     Buffer holding the context bytes to be set.
 * @param[in] contextLen  The length of the context in bytes.
 * @param[out] ctx        Pointer to the ML-DSA context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_setContext(const uint8_t *context, size_t contextLen, MLDSACtx *ctx);

/*
 * @brief    Gets the length of a signature associated with a MLDSA key in bytes.
 *
 * @details  Gets the length of a signature associated with a MLDSA key in bytes.
 *
 * @param[in] ctx               Pointer to the MLDSA key.
 * @param[out] signatureLen     Contents will be set to the length of the signature or maximum length in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_getSignatureLen(MLDSACtx *ctx, size_t *signatureLen);


/**
 * @brief    Performs the signature generation algorithm for messages.
 *
 * @details  Performs the signature generation algorithm for messages. This
 * function works on the raw message to be signed. It is domain separated from
 * \c MLDSA_signDigest. If you are signing the hash digest of a message, use
 * \c MLDSA_signDigest.
 *
 * @param[in] ctx            Pointer to the ML-DSA context.
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
MOC_EXTERN MSTATUS MLDSA_signMessage(MLDSACtx *ctx, uint8_t *message, size_t messageLen, RNGFun rng, void *rngArg,
                                     uint8_t *signature, size_t signatureLen);

/**
 * @brief    Performs the signature generation algorithm for the digest of a
 *           message.
 *
 * @details  Performs the signature generation algorithm for the digest of a
 * message. This function works on the message digest to be signed. It is domain
 * separated from \c MLDSA_signMessage. If you are signing the raw message, use
 * \c MLDSA_signMessage.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] ctx            Pointer to the ML-DSA context.
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
MOC_EXTERN MSTATUS MLDSA_signDigest(MLDSACtx *ctx, uint8_t *digest, size_t digestLen, MLDSADigestType digestType, RNGFun rng, void *rngArg,
                                    uint8_t *signature, size_t signatureLen);
/**
 * @brief    Performs the signature verification algorithm for raw messages.
 *
 * @details  Performs the signature verification algorithm for raw messages.
 * This function works on the raw message to be signed. It is domain separated
 * from \c MLDSA_verifyDigest. If you are signing the hash digest of a message,
 * use \c MLDSA_verifyDigest.
 *
 * @param[in] ctx           Pointer to the MLDSA key.
 * @param[in] message       Buffer holding the input messasge.
 * @param[in] messageLen    The length of the message in bytes.
 * @param[in] signature     Buffer holding the signature to be verified.
 * @param[in] signatureLen  The length of the signature in bytes.
 *
 * @return   \c OK (0) on sucessful verification of the message otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_verifyMessage(MLDSACtx *ctx, uint8_t *message, size_t messageLen, uint8_t *signature, size_t signatureLen);

/**
 * @brief    Performs the signature verification algorithm for the digest of a
 * message.
 *
 * @details  Performs the signature verification algorithm for the digest of a.
 * message. This function works on the message digest to be verified. It is domain
 * separated from \c MLDSA_verifyMessage. If you are signing the raw message, use
 * \c MLDSA_verifyMessage.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] ctx           Pointer to the MLDSA key.
 * @param[in] digest        Buffer holding the input messasge.
 * @param[in] digestLen     The length of the message in bytes.
 * @param[in] digestType    The type of hash function used to create the digest.
 * @param[in] signature     Buffer holding the signature to be verified.
 * @param[in] signatureLen  The length of the signature in bytes.
 *
 * @return   \c OK (0) on sucessful verification of the message otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_verifyDigest(MLDSACtx *ctx, uint8_t *digest, size_t digistLen, MLDSADigestType digestType,
                                      uint8_t *signature, size_t signatureLen);

/**
 * @brief    Initializes the signature or verification algorithm for streaming mode.
 *
 * @details  Initializes the signature or verification algorithm for streaming mode.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] pCtx           Pointer to a previously allocated context.
 * @param[in] isExternalMu   Indicates to implicitly digest input data as per draft.
 * @param[in] digestId       For \c isExternalMu false, the identifier of the pre-hash
 *                           digest from crypto.h. For \c isExternalMu true this is ignored.
 * @param[in] pContextStr    Optional context string for cipher personalization.
 * @param[in] ctxStrLen      The length of the context string in bytes. Cannot exceed 255.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_streamingInit(MLDSACtx *pCtx, byteBoolean isExternalMu, ubyte digestId,
                                       ubyte *pContextStr, ubyte4 ctxStrLen);


/**
 * @brief    Updates an initilized context with a stream of data.
 *
 * @details  Updates an initilized context with a stream of data. This method can be called
 *           as many times as needed.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] pCtx           Pointer to a previously initialized context.
 * @param[in] pData          Buffer holding the input data.
 * @param[in] dataLen        The length of the data in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_streamingUpdate(MLDSACtx *pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief    Finalizes an updated context, producing the output signature.
 *
 * @details  Finalizes an updated context, producing the output signature.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] pCtx           Pointer to a previously updated context.
 * @param[in] rngFun         Optional function pointer to a random number generation function.
 *                           If not given then deterministic mode will be performed.
 * @param[in] pRngFunArg     Optional input data or context into the random number generation function.
 * @param[out] pSignature    Buffer that will hold the resulting signature.
 * @param[in] sigBufferLen   The length of the \c pSignature buffer in bytes.
 * @param[out] pActualSigLen Contents will be set to the actual length of the signature, 
 *                           ie the number of bytes written to \c pSignature.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_streamingSignFinal(MLDSACtx *pCtx, RNGFun rngFun, void *pRngFunArg,
                                            ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen);

/**
 * @brief    Finalizes an updated context, verifying the signature.
 *
 * @details  Finalizes an updated context, verifying the signature.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_PQC_SIG_STREAMING__
 *
 * @param[in] pCtx           Pointer to a previously updated context.
 * @param[in] pSignature     Buffer holding the signature to be verified.
 * @param[in] signatureLen   The length of the signature in bytes.
 * @param[out] pVerifyStatus Contents will be set to 0 for a valid signature
 *                           and non-zero otherwise.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pVerifyStatus
 *             of \c 0 before accepting that a signature is valid.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_streamingVerifyFinal(MLDSACtx *pCtx, ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus);

/**
 * @brief    Clones a MLDSA context.
 *
 * @details  Clones a new MLDSA context from an existing context.
 *           Be sure to call \c MLDSA_destroyCtx.
 *           to free memory when done with the new context.
 *
 * @param[in] ctx      Pointer to the existing key to be cloned.
 * @param[out] newCtx  Pointer to the location that will contain the newly
 *                  cloned context.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_cloneCtx(MLDSACtx *ctx, MLDSACtx *newCtx);

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
MOC_EXTERN bool MLDSA_verifyKeyPair(MLDSACtx *ctx);

/**
 * @brief    Destroys a ML-DSA context.
 *
 * @details  Deestroys a ML-DSA context including freeing internal structures
 *           and allocations.
 *
 * @param[out] ctx     Pointer to the location of the key to be deleted.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS MLDSA_destroyCtx(MLDSACtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __MLDSA_HEADER__ */
