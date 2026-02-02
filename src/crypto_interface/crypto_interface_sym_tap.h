
/*
 * crypto_interface_sym_tap.h
 *
 * Cryptographic Interface header file for declaring Symmetric TAP functions
 * for the Crypto Interface.
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

#ifndef __CRYPTO_INTERFACE_SYM_TAP_HEADER__
#define __CRYPTO_INTERFACE_SYM_TAP_HEADER__

#include "../tap/tap_smp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    ubyte4 keyType;
    void *pKeyData;
} SymmetricKey;

/**
 * @brief   Generates a new TAP Symmetric Key.
 * @details Generates a new TAP Symmetric Key. Memory is allocated so be sure to
 *          call \c CRYPTO_INTERFACE_TAP_deleteSymKey when done with the key.
 *
 * @param ppNewKey    The location that will recieve a pointer to the newly allocated
 *                    symmetric key.
 * @param keyLenBits  The length of the key in bits. It must be a multiple of 8.
 * @param pOpInfo     Pointer to the TAP operator specific data, typically a pointer to a
 *                    \c MSymTapKeyGenArgs structure.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GenerateSymKey (
    SymmetricKey **ppNewKey,
    sbyte4 keyLenBits,
    void *pOpInfo
    );

/**
 * @brief   Creates a new TAP Symmetric Key with the same numeric value as an external key.
 * @details Creates a new TAP Symmetric Key with the same numeric value as an external key.
 *          Memory is allocated so be sure to call \c CRYPTO_INTERFACE_TAP_deleteSymKey 
 *          when done with the key.
 *
 * @param ppNewKey    The location that will recieve a pointer to the newly allocated
 *                    symmetric key.
 * @param pOpInfo     Pointer to the TAP operator specific data, typically a pointer to a
 *                    \c MSymTapKeyGenArgs structure.
 * @param pArgs       Pointer to the external key specific data, typically a pointer to a 
 *                    \c MSymTapCreateArgs structure.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymImportExternalKey(
    SymmetricKey **ppNewKey,
    void *pOpInfo,
    void *pArgs
    );

/**
 * @internal This API is for internal use. Appropriate \c CRYPTO_INTERFACE_TAP_<cipher>DeferUnload should be used.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymDeferUnload (
    MocSymCtx pCtx,
    byteBoolean deferredTokenUnload
    );

#ifdef __ENABLE_DIGICERT_TAP__

/**
 * @internal This API is for internal use. Appropriate \c CRYPTO_INTERFACE_TAP_<cipher>GetKeyInfo should be used.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymGetKeyInfo (
    MocSymCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

#endif /* __ENABLE_DIGICERT_TAP__ */

/**
 * @brief   Marks a Symmetric Key containing a TAP key to not be unloaded when done with its cipher operations.
 * @details Marks a Symmetric Key containing a TAP key to not be unloaded when done with its cipher operations.
 *
 * @param pCtx                Pointer to a Symmetric Key containing a TAP key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymKeyDeferUnload (
    SymmetricKey *pKey,
    byteBoolean deferredTokenUnload
    );

/**
 * @brief   Serializes a TAP symmetric key.
 * @details Serializes a TAP symmetric key. This method allocates a buffer for
 *          the serialization. Please be sure to free this buffer when done with it.
 *
 * @param pKey              Pointer to the input symmetric key.
 * @param ppSerializedKey   Location that will recieve the buffer holding the serialization.
 * @param pSerializedKeyLen Will receive the length of the serialized key in bytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_serializeSymKey(
    SymmetricKey *pKey,
    ubyte **ppSerializedKey,
    ubyte4 *pSerializedKeyLen
    );

/**
 * @brief   Deserializes a symmetric key into a TAP form key.
 * @details Deserializes a symmetric key into a TAP form key. This method allocates a
 *          new \c SymmetricKey structure so be sure to call \c CRYPTO_INTERFACE_TAP_deleteSymKey
 *          when done with it.
 *
 * @param ppKey            Location that will receive a pointer to the new symmetric key.
 * @param pSerializedKey   The input serialized key.
 * @param serializedKeyLen The lemgth of the serialized key in bytes.
 * @param pOpInfo          Pointer to the TAP operator specific data, typically a pointer to a
 *                         \c MSymTapKeyGenArgs structure.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deserializeSymKey(
    SymmetricKey **ppKey,
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    void *pOpInfo
    );

/**
 * @brief   Deserializes a password protected symmetric key into a TAP form key.
 * @details Deserializes a password protected symmetric key into a TAP form key. This method allocates a
 *          new \c SymmetricKey structure so be sure to call \c CRYPTO_INTERFACE_TAP_deleteSymKey
 *          when done with it.
 *
 * @param ppKey            Location that will receive a pointer to the new symmetric key.
 * @param pSerializedKey   The input serialized key.
 * @param serializedKeyLen The lemgth of the serialized key in bytes.
 * @param pPassword        The input password.
 * @param passwordLen      The length of the password in bytes.
 * @param pOpInfo          Pointer to the TAP operator specific data, typically a pointer to a
 *                         \c MSymTapKeyGenArgs structure.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deserializeSymKeyWithCreds(
    SymmetricKey **ppKey,
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    void *pOpInfo
    );

/**
 * @brief   Loads the underlying TAP key with password credentials.
 * @details Loads the underlying TAP key with password credentials.
 *
 * @param pKey             The SymmetricKey containing the TAP key to be loaded.
 * @param pPassword        The input password.
 * @param passwordLen      The length of the password in bytes.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymKeyLoadWithCreds(
    SymmetricKey *pKey,
    ubyte *pPassword, 
    ubyte4 passwordLen);

/**
 * @brief   Deletes a TAP symmetric key.
 * @details Deletes a TAP symmetric key.
 *
 * @param ppKey The location of the pointer to the key to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deleteSymKey(
    SymmetricKey **ppKey
    );

/**
 * @brief   Get the TAP ID from an SymmetricKey.
 *
 * @param pKey    Pointer to the SymmetricKey.
 * @param pId     Pointer to the location that will receive the allocated pointer 
 *                that points to the buffer containing the ID.
 * @param         Pointer to the location that will receive the ID buffer length.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_symGetTapObjectId(
    SymmetricKey *pKey, 
    ubyte **ppId,
    ubyte4 *pIdLen
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SYM_TAP_HEADER__ */
