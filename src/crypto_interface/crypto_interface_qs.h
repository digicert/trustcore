/*
 * crypto_interface_qs.h
 *
 * Cryptographic Interface header file for declaring common Quantum Safe methods.
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
@file       crypto_interface_qs.h
@brief      Cryptographic Interface header file for declaring common Quantum Safe methods.

@filedoc    crypto_interface_qs.h
*/
#ifndef __CRYPTO_INTERFACE_QS_HEADER__
#define __CRYPTO_INTERFACE_QS_HEADER__

#include "../common/random.h"
#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* leave 0 to use as a flag for uninitialied */
#define MOC_QS_KEM           1
#define MOC_QS_SIG           2

/** Context structure to hold the appropriate quantum safe asymmetric keys.
 * <li>pSecretKey The secret key structure.</li>
 * <li>pKey       The algorithm specific combined key structure whether secret or public.
 * <li>pPublicKey The public key structure.</li>
 * <li>enabled    Flag indicating whether the operator is enabled.</li>
 * <li>isPrivate  Flag indicating whether the secret key is defined.</li>
 * <li>type       Flag indicatint whether the context is for key encapsulation mechanisms
 *                or signature based authentication.</li>
 * <li>alg        The exact algorithm this context is to be used for.</li>
 */
typedef struct
{
    union
    {
        void *pSecretKey;
        void *pKey;
    };
    void *pPublicKey;
    ubyte4 enabled;
    ubyte4 isPrivate;
    ubyte4 type;
    ubyte4 alg;

} QS_CTX;

/**
 * @brief    Creates a new QS context.
 *
 * @details  Creates a new QS context including allocation of the internal
 *           key shells. Be sure to call \c CRYPTO_INTERFACE_QS_deleteCtx
 *           to free memory when done with the context.
 *
 * @param ppNewCtx  Pointer to the location that will contain the newly
 *                  allocated context.
 * @param algo      One of the algorithm flags to indicate which algorithm
 *                  will be performed,.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX **ppNewCtx, ubyte4 algo);

/**
 * @brief    Gets tha algorithm identifier from the context.

 * @details  Gets tha algorithm identifier from the context.
 *
 * @param pCtx      Pointer to a previously allocated context.
 * @param pAlg      Contents Will be set to the algorithm identifier macro value.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getAlg(QS_CTX *pCtx, ubyte4 *pAlg);

/**
 * @brief    Clones a QS context.
 *
 * @details  Clones a new QS context from an existing context.
 *           Be sure to call \c CRYPTO_INTERFACE_QS_deleteCtx
 *           to free memory when done with the new context.
 *
 * @param ppNewCtx  Pointer to the location that will contain the newly
 *                  allocated clone of the original context.
 * @param pCtx      Pointer to the existing context to be cloned.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_cloneCtx(QS_CTX **ppNewCtx, QS_CTX *pCtx);

/**
 * @brief    Generates a new key pair within a QS context.
 *
 * @details  Generates a new key pair within a QS context.
 *
 * @param pCtx         Pointer to the QS context that will hold the new keys.
 * @param rngFun       Function pointer to a random number generation function.
 * @param pRngFunArg   Input data or context into the random number generation function
 *                     pointer.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(hwAccelDescr hwAccelCtx) QS_CTX *pCtx,
                                                       RNGFun rngFun, void *pRngFunArg);

/**
 * @brief    Gets the length of a public key associated with a QS algorithm in bytes.
 *
 * @details  Gets the length of a public key associated with a QS algorithm in bytes.
 *
 * @param algo        The algorithm identifier.
 * @param pPubLen     Contents will be set to the length of the public key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyLenFromAlgo(ubyte4 algo, ubyte4 *pPubLen);

/**
 * @brief    Gets the length of a public key associated with a QS context in bytes.
 *
 * @details  Gets the length of a public key associated with a QS context in bytes.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pPubLen     Contents will be set to the length of the public key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyLen(QS_CTX *pCtx, ubyte4 *pPubLen);

/**
 * @brief    Gets the public key from a QS context.
 *
 * @details  Gets the public key from a QS context.
 *
 * @param pCtx        Pointer to the QS context that contains at least a public key.
 * @param pPublicKey  Buffer to hold the resulting public key.
 * @param pubLen      The length of the \c pPublicKey buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen);

/**
 * @brief    Gets the public key from a QS context and allocates a buffer for it.
 *
 * @details  Gets the public key from a QS context. A buffer is allocated
 *           to hold the public key. Be sure to free this buffer when done with it.
 *
 * @param pCtx        Pointer to the QS context that contains at least a public key.
 * @param ppPublicKey Pointer to the location that will receive the newly allocated buffer.
 * @param pPubLen     Contents will be set to the length of the public key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPublicKeyAlloc(QS_CTX *pCtx, ubyte **ppPublicKey, ubyte4 *pPubLen);

/**
 * @brief    Sets the public key within a QS context.
 *
 * @details  Sets the public key within a QS context.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pPublicKey  Buffer holding the public key to be set.
 * @param pubLen      The length of the public key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_setPublicKey(QS_CTX *pCtx, ubyte *pPublicKey, ubyte4 pubLen);

/**
 * @brief    Gets the length of a private key associated with a QS context in bytes.
 *
 * @details  Gets the length of a private key associated with a QS context in bytes.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pPriLen     Contents will be set to the length of the private key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPrivateKeyLen(QS_CTX *pCtx, ubyte4 *pPriLen);

/**
 * @brief    Gets the private key from a QS context.
 *
 * @details  Gets the private key from a QS context.
 *
 * @param pCtx        Pointer to the QS context that contains a key pair.
 * @param pPrivateKey Buffer to hold the resulting private key.
 * @param priLen      The length of the \c pPrivateKey buffer in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen);

/**
 * @brief    Gets the private key from a QS context and allocates a buffer for it.
 *
 * @details  Gets the private key from a QS context. A buffer is allocated
 *           to hold the public key. Be sure to free this buffer when done with it.
 *
 * @param pCtx         Pointer to the QS context that contains a key pair.
 * @param ppPrivateKey Pointer to the location that will receive the newly allocated buffer.
 * @param pPriLen      Contents will be set to the length of the private key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_getPrivateKeyAlloc(QS_CTX *pCtx, ubyte **ppPrivateKey, ubyte4 *pPriLen);

/**
 * @brief    Sets the private key within a QS context.
 *
 * @details  Sets the private key within a QS context.
 *
 * @param pCtx        Pointer to the QS context.
 * @param pPrivateKey Buffer holding the private key to be set.
 * @param priLen      The length of the private key in bytes.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_setPrivateKey(QS_CTX *pCtx, ubyte *pPrivateKey, ubyte4 priLen);

/**
 * @brief    Validates the public key corresponds to the private key within a QS context.
 *
 * @details  Validates the public key corresponds to the private key within a QS context.
 *
 * @param pCtx       Pointer to the QS context to be validate. This context must contain
 *                   a private key pair else an error code will be returned.
 * @param rngFun     Optional, function pointer to a random number generation function. If
 *                   provided a full roundtrip encrypt/decrypt test will occur for ML-KEM.
 * @param pRngFunArg Optional context or data for the random number generation function
 *                   pointer.
 * @param pIsValid   Will be set to \c TRUE for a valid key and \c FALSE otherwise.
 *
 * @return   \c OK (0) for successful completion of the method, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_validateKeyPair(QS_CTX *pCtx, RNGFun rngFun, void *pRngFunArg, byteBoolean *pIsValid);

/**
 * @brief    Compares public key value of two QS contexts.
 *
 * @details  Compares public key value of two QS contexts.
 *
 * @param pCtx1       Pointer to the first QS context.
 * @param pCtx2       Pointer to the second QS context.
 * @param keyType     \c MOC_ASYM_KEY_TYPE_PRIVATE for private key pair comparison
 *                    or \c MOC_ASYM_KEY_TYPE_PUBLIC for just public key comparison.
 * @param pRes        Returns TRUE if public keys match, else FALSE.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_equalKey(QS_CTX *pCtx1, QS_CTX *pCtx2, ubyte4 keyType, byteBoolean *pRes);

/**
 * @brief    Serializes a key into a basic blob format
 *
 * @details  Serializes a key into a basic blob format
 *
 * @param pCtx       Pointer to the context containing a key to be serialized.
 * @param keyType    \c MOC_ASYM_KEY_TYPE_PRIVATE for private keys or \c MOC_ASYM_KEY_TYPE_PUBLIC for public keys.
 * @param ppSerKey   Pointer to the location that will receive a newly allocated buffer holding the serialization.
 * @param pSerKeyLen Will receive the length of the new buffer in bytes.

 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_serializeKeyAlloc(QS_CTX *pCtx, ubyte4 keyType, ubyte **ppSerKey, ubyte4 *pSerKeyLen);

/**
 * @brief    Deserializes a blob format key into an empty \c QS_CTX.
 *
 * @details  Deserializes a blob format key into an empty \c QS_CTX. One must know ahead of time
 *           whether the key is a private key or public key.
 *
 * @param pCtx       Pointer to the empty context which will contain the new key.
 * @param keyType    \c MOC_ASYM_KEY_TYPE_PRIVATE for private keys or \c MOC_ASYM_KEY_TYPE_PUBLIC for public keys.
 * @param pSerKey    THe buffer holding the serialized key.
 * @param serKeyLen  The length of the serialized key in bytes.

 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_deserializeKey(QS_CTX *pCtx, ubyte4 keyType, ubyte *pSerKey, ubyte4 serKeyLen);

/**
 * @brief    Deletes a QS context.
 *
 * @details  Deletes a QS context including freeing internal keys and
 *           memory allocated for the context itself.
 *
 * @param ppCtx     Pointer to the location of the context to be deleted.
 *
 * @return   \c OK (0) if successful, otherwise a negative number
 *           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_deleteCtx(QS_CTX **ppCtx);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_QS_HEADER__ */
