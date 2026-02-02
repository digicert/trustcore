/*
 * crypto_interface_rsa_tap.h
 *
 * Cryptographic Interface header file for declaring RSA TAP functions
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

#ifndef __CRYPTO_INTERFACE_RSA_TAP_HEADER__
#define __CRYPTO_INTERFACE_RSA_TAP_HEADER__

#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Sets an RSA Key to not unload the internal TAP Key upon cipher completion. 
 * @details Sets an RSA Key to not unload the internal TAP Key upon cipher completion. 
 *
 * @param pCtx      Pointer to a TAP enabled RSA Key containing a TAP Key.
 * @param keyType      One of \c MOC_ASYM_KEY_TYPE_PRIVATE or \c MOC_ASYM_KEY_TYPE_PUBLIC.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (
    RSAKey *pKey,
    ubyte4 keyType,
    byteBoolean deferredTokenUnload
    );

#ifdef __ENABLE_DIGICERT_TAP__

/**
 * @brief   Gets the key handle and token handle for an internal TAP key.
 * @details Gets the key handle and token handle for an internal TAP key. This is
 *          typically used for obtaining the key handle and token handle for a deferred
 *          unload TAP key. This method should be called after the cipher operation and
 *          before the cipher context cleanup.
 *
 * @param pCtx         Pointer to a TAP enabled RSA key containing a TAP Key.
 * @param keyType      One of \c MOC_ASYM_KEY_TYPE_PRIVATE or \c MOC_ASYM_KEY_TYPE_PUBLIC.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(
    RSAKey *pKey,
    ubyte4 keyType,
    TAP_TokenHandle *pTokenHandle, 
    TAP_KeyHandle *pKeyHandle
    );

/**
 * @brief   Unloads an internal TAP key.
 * @details Unloads an internal TAP key.
 *
 * @param pKey         Pointer to a TAP enabled RSA key containing a TAP Key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaUnloadKey(
    RSAKey *pKey
    );

/**
 * @brief   Wrap a secret key using an RSA public key.
 *
 * @param pTapContext       TAP context to use.
 * @param pUsageCredentials Usage credentials.
 * @param pKeyCredentials   Key Credentials.
 * @param pRSASwPub         Software RSA public key used to wrap. The contents of this
 *                          key will be created as an RSA public key on the Secure Element.
 * @param pKeyToBeWrappedId ID of the secret key to be wrapped. For PKCS11 Secure Elements,
 *                          it is the CKA_ID of the key. For established keys, use 
 *                          CRYPTO_INTERFACE_TAP_symGetTapObjectId() to get ID.
 * @param keyToBeWrappedIdLen Length of the ID.
 * @param useOAEP           TRUE to use RSA OAEP for key wrapping, FALSE otherwise.
 * @param hashAlgo          Hash Algorithm to use for OAEP wrapping.
 * @param pLabel            Label to use for OAEP.
 * @param labelLen          Length of label to use for OAEP.
 * @param ppWrappedKey      Location that will receive the pointer to the newly allocated
 *                          buffer containing the wrapped key. Caller is responsible for
 *                          freeing this pointer.
 * @param pWrappedKeyLen    Location that will receive the length of the wrapped key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_RSA_wrapSymKey (
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    RSAKey *pRSASwPub,
    ubyte* pKeyToBeWrappedId,
    ubyte4 keyToBeWrappedIdLen,
    ubyte useOAEP,
    ubyte hashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen,
    ubyte **ppOutDuplicate,
    ubyte4 *pOutDuplicateLen
    );

/**
 * @brief   Unwrap a secret key using an RSA private key.
 *
 * @param pTapContext       TAP context to use.
 * @param pUsageCredentials Usage credentials.
 * @param pKeyCredentials   Key Credentials.
 * @param pKeyInfo          Information about the key to be unwrapped. The pKeyInfo->keyAlgorithm
 *                          MUST be set.
 * @param pWrappingKeyId    ID of the private key to use for unwrapping. For PKCS11 
 *                          Secure Elements, it is the CKA_ID of the key. For established keys, 
 *                          use CRYPTO_INTERFACE_TAP_asymGetTapObjectId() to get ID.
 * @param wrappingKeyIdLen  Length in bytes of the wrapping key ID.
 * @param useOAEP           TRUE to use RSA OAEP for key wrapping, FALSE otherwise.
 * @param hashAlgo          Hash Algorithm to use for OAEP wrapping.
 * @param pLabel            Label to use for OAEP.
 * @param labelLen          Length of label to use for OAEP.
 * @param pWrappedKey       Buffer containing the wrapped key
 * @param wrappedKeyLen     Length in bytes of the wrapped key.
 * @param ppNewKey          Location that will receive a pointer to the new symmetric key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_unwrapSymKey (
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    TAP_KeyInfo *pKeyInfo,
    ubyte *pWrappingKeyId,
    ubyte4 wrappingKeyIdLen,
    ubyte useOAEP,
    ubyte hashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen,
    ubyte *pWrappedKey,
    ubyte4 wrappedKeyLen,
    SymmetricKey **ppNewKey
    );

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RSA_TAP_HEADER__ */
