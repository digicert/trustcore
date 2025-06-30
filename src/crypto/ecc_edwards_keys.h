/*
 * ecc_edwards_keys.h
 *
 * Header for Edward's Curve key operations.
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
 * @file       ecc_edwards_keys.h
 *
 * @brief      Header for curve25519 and curve448 key related methods.
 *
 * @details    Documentation file for curve25519 and curve448 key related methods.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_MOCANA_ECC__
 *             and at least one or more of the following flags
 *             + \c \__ENABLE_MOCANA_ECC_EDDH_25519__
 *             + \c \__ENABLE_MOCANA_ECC_EDDSA_25519__
 *             + \c \__ENABLE_MOCANA_ECC_EDDH_448__
 *             + \c \__ENABLE_MOCANA_ECC_EDDSA_448__
 *
 * @filedoc    ecc_edwards_keys.h
 */

/*------------------------------------------------------------------*/

#ifndef __ECC_EDWARDS_KEYS_HEADER__
#define __ECC_EDWARDS_KEYS_HEADER__

/* Macros for the desired sha output lengths */
#define MOC_EDDSA_SHA512_LEN 64
#define MOC_EDDSA_SHAKE256_LEN 114

#include "../crypto/crypto.h"
#include "../common/random.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Identifiers for the Edward's form curves and algorithms.
 *
 * @details  Identifiers for the Edward's form curves and algorithms. Note we
 *           need an algorithm specifier too because the key form and
 *           even curve form is actually different for EdDH vs that of EdDSA.
 */
typedef enum
{
    curveX25519 = 0,  /* edDH */
    curveX448 = 1,
    curveEd25519 = 2, /* edDSA */
    curveEd448 = 3

} edECCCurve;

typedef struct edECCKey
{
    intBoolean isPrivate;
    ubyte *pPrivKey;
    ubyte *pPubKey;
    edECCCurve curve;

} edECCKey;

/**
 * @brief    Creates a new Edward's curve form key.
 *
 * @details  Creates a new Edward's curve form key. The key will be allocated
 *           and be sure to call \c edECC_deleteKey to free the memory when done
 *           with the key.
 *
 * @param ppKey   Pointer that will receive the location of the newly allocated key.
 * @param curve   The curve and algorithm to associate with the new key.
 * @param pExtCtx An extended context reserved for future use.
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_newKey(edECCKey **ppKey, edECCCurve curve, void *pExtCtx);


/**
 * @brief    Gets the key length associated with the given key.
 *
 * @details  Gets the key length associated with the given key.
 *
 * @param pKey     Pointer to the input key.
 * @param pKeyLen  Contents will be set to the length of the key in bytes.
 *                 Note that a public key is the same length as a private key.
 * @param pExtCtx  An extended context reserved for future use.
 *
 * @return    \c OK (0) if successful, otherwise a negative number error
 *            code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_getKeyLen(edECCKey *pKey, ubyte4 *pKeyLen, void *pExtCtx);


/**
 * @brief    Tests if two Edward's form keys have identical public keys.
 *
 * @details  Tests if two Edward's form keys have identical public keys. This may be used
 *           on private keys but only the curves and public keys are compared.
 *
 * @param pKey1     Pointer to the first key.
 * @param pKey2     Pointer to the second key.
 * @param pMatch    Contents will be set to TRUE if the public keys are identical. FALSE otherwise.
 * @param pExtCtx   An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_equalKey(edECCKey *pKey1, edECCKey *pKey2, byteBoolean *pMatch, void *pExtCtx);


/**
 * @brief    Allocates and clones an Edward's form key.
 *
 * @details  Allocates and clones an Edward's form key. Be sure to call \c edECC_deleteKey
 *           to free the newly allocated key when done with it.
 *
 * @param ppNew     Pointer that will receive the location of the newly allocated key.
 * @param pSrc      Pointer to the existing key to be cloned.
 * @param pExtCtx   An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_cloneKey(edECCKey **ppNew, edECCKey *pSrc, void *pExtCtx);

/**
 * @brief    Generates a new Edward's form private key pair.
 *
 * @details  Generates a new Edward's form private key pair.
 *
 * @param pKey      Pointer to a previously allocated key.
 * @param rngFun    Function pointer callback to a method that will provide random entropy.
 * @param pRngArg   Optional argument that may be needed by the \c rngFun provided.
 * @param pShaSuite For EdDSA keys only, the SHA suite used by the EdDSA algorithm.
 *                  This must be SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 *                  This param should be NULL for EdDH keys.
 * @param pExtCtx   An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_generateKeyPair(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, RNGFun rngFun, void *pRngArg, BulkHashAlgo *pShaSuite, void *pExtCtx);


/**
 * @brief    Sets the key parameters in an Edward's form key.
 *
 * @details  Sets the key parameters in an Edward's form key. This may be used to set a
 *           public key or a private key. If setting a private key without a public key value
 *           input, the public key value will be generated.
 *
 * @param pKey        Pointer to a previously allocated key.
 * @param pPubKey     Buffer holding the public key value to be set. This may be NULL for
 *                    setting a private key, in which case the public value will be computed.
 * @param pubKeyLen   The length of the public key in bytes.
 * @param pPrivKey    Buffer holding the private key value to be set. This must be NULL when
 *                    setting just a public key.
 * @param privKeyLen  The length of the private key in bytes.
 * @param pShaSuite   For EdDSA private keys when \c pPubKey is NULL, the SHA suite used by the EdDSA algorithm.
 *                    This must be SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 *                    This param should be NULL for EdDH keys.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_setKeyParameters(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pPubKey, ubyte4 pubKeyLen, ubyte *pPrivKey, ubyte4 privKeyLen, BulkHashAlgo *pShaSuite, void *pExtCtx);


/**
 * @brief    Gets the key parameters in an Edward's form key.
 *
 * @details  Gets the key parameters in an Edward's form key. This may be used for a
 *           public key or a private key. This method allocates new buffers to hold
 *           the key values. Be sure to FREE them when done with them.
 *
 * @param pKey      Pointer to a an exising key.
 * @param ppPubKey  Pointer to the newly allocated buffer that will hold the resulting
 *                  public key.
 * @param pPubLen   Contents will be set to the length of the public key in bytes.
 * @param ppPrivKey Pointer to the newly allocated buffer that will hold the resulting
 *                  private key. This will be NULL for \c pKey a public key.
 * @param pPrivLen  Contents will be set to the length of the private key in bytes.
 * @param pExtCtx   An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_getKeyParametersAlloc(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte **ppPubKey, ubyte4 *pPubLen, ubyte **ppPrivKey, ubyte4 *pPrivLen, void *pExtCtx);


/**
 * @brief    Validates an Edward's form key.
 *
 * @details  Validates an Edward's form key. For private keys this consists of validating
 *           that the public key is correctly associated with the private key. For EdDSA public
 *           keys validation consists of validiting that it is a properly encoded point. For
 *           EdDH public keys no validation is needed and this method will always result in \c OK.
 *
 * @param pKey        Pointer to the key to be validated. This may be public or private.
 * @param pShaSuite   For EdDSA private keys, the SHA suite used by the EdDSA algorithm.
 *                    This must be SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 *                    This param should be NULL for EdDH keys or public keys.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful and the key is valid, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_validateKey(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, BulkHashAlgo *pShaSuite, void *pExtCtx);


/**
 * @brief    Gets the public key from an Edward's form key.
 *
 * @details  Gets the public key from an Edward's form private or public key.
 *
 * @param pKey        Pointer to a an exising key.
 * @param pOutBuffer  Buffer that will hold the output public key.
 * @param bufferLen   The length of the \c pOutBuffer in bytes.
 * @param pExtCtx     An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_getPublicKey(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pKey, ubyte *pOutBuffer, ubyte4 bufferLen, void *pExtCtx);

/**
 * @brief    Gets the raw public key from a raw private key.
 *
 * @details  Gets the raw public key from a raw private key.
 *
 * @param pPub        Buffer to hold the resulting public key. 
 * @param pPriv       Buffer holding the input private key.
 * @param curve       The curve/alg in use.
 * @param pShaSuite   For EdDSA private keys, the SHA suite used by the EdDSA algorithm.
 *                    This must be SHA2-512 for curve25519 and SHA3-SHAKE256 for curve448.
 *                    This param should be NULL for EdDH keys or public keys
 * @param isShaEvp    \c TRUE if the pShaSuite contains init/update/final EVP style methods.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_calculatePubFromPriv(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pPub, ubyte *pPriv, edECCCurve curve, BulkHashAlgo *pShaSuite, byteBoolean isShaEvp);

/**
 * @brief    Deletes an Edward's form key.
 *
 * @details  Deletes an Edward's form key. This consists of zeroing sensative data
 *           and freeing allocated memory.
 *
 * @param ppKey    Pointer that holds the location of the key to be deleted.
 * @param pExtCtx  An extended context reserved for future use.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS edECC_deleteKey(edECCKey **ppKey, void *pExtCtx);

#ifdef __cplusplus
}
#endif

#endif /* __ECC_EDWARDS_KEYS_HEADER__ */
