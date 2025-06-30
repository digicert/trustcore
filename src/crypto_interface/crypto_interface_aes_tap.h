/*
 * crypto_interface_aes_tap.h
 *
 * Cryptographic Interface header file for declaring AES TAP functions
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

#ifndef __CRYPTO_INTERFACE_AES_TAP_HEADER__
#define __CRYPTO_INTERFACE_AES_TAP_HEADER__

#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GCM_MODE_256B 100
#define GCM_MODE_4K   101
#define GCM_MODE_64K  102

/**
 * @brief   Create a new AES context from a previously existing TAP symmetric key.
 * @details Create a new AES context from a previously existing TAP symmetric key.
 *          This API allocates memory for the new context, and takes ownership of
 *          the input \c SymmetricKey structure, so be sure to call
 *          \c CRYPTO_INTERFACE_DeleteAESCtx in order to free these structures when done.
 *
 * @param pSymKey   Pointer to the input \c SymmetricKey structure containing
 *                  a TAP key.
 * @param ppNewCtx  Location that will recieve a pointer to the new AES context.
 *
 * @param mode      The AES mode. Must be one of
 *                  { MODE_ECB, MODE_CBC, MODE_CFB128, MODE_OFB }
 * @param encrypt   \c TRUE to prepare this context for encryption,
 *                  \c FALSE to prepare this context for decryption.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 mode,
    sbyte4 encrypt
    );

/**
 * @brief   Sets an AES context to not unload the internal TAP Key upon cipher completion.
 * @details Sets an AES context to not unload the internal TAP Key upon cipher completion.
 *
 * @param pCtx                Pointer to a TAP enabled AES context containing a TAP Key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    );

#ifdef __ENABLE_MOCANA_TAP__

/**
 * @brief   Gets the key handle and token handle for an internal TAP key.
 * @details Gets the key handle and token handle for an internal TAP key. This is
 *          typically used for obtaining the key handle and token handle for a deferred
 *          unload TAP key. This method should be called after the cipher operation and
 *          before the cipher context cleanup.
 *
 * @param pCtx         Pointer to a TAP enabled AES context containing a TAP Key.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

#endif /* __ENABLE_MOCANA_TAP__ */

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_AESALGO_blockEncrypt.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AESALGO_blockEncrypt (
    MocSymCtx pCtx,
    ubyte *pIv,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutBuffer,
    sbyte4 *pRetLength
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_AESALGO_blockDecrypt.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AESALGO_blockDecrypt (
    MocSymCtx pCtx,
    ubyte *pIv,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutBuffer,
    sbyte4 *pRetLength
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_ResetAESCtx.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_ResetAESCtx (
    MocSymCtx pCtx
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_DeleteAESCtx.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DeleteAESCtx (
    MocSymCtx pCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_TAP_HEADER__ */
