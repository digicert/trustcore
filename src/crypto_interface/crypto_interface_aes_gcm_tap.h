/*
 * crypto_interface_aes_gcm_tap.h
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

#ifndef __CRYPTO_INTERFACE_AES_GCM_TAP_HEADER__
#define __CRYPTO_INTERFACE_AES_GCM_TAP_HEADER__

#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Create a new AES-GCM context from a previously existing TAP symmetric key.
 * @details Create a new AES-GCM context from a previously existing TAP symmetric key.
 *          This API allocates memory for the new context, and takes ownership of
 *          the input \c SymmetricKey structure, so be sure to call
 *          \c CRYPTO_INTERFACE_DeleteDESCtx in order to free these structures when done.
 *          Also note this API takes in a table size \c mode which will be used to specify the
 *          context type and software implementation. An alternative implementation will
 *          not necessarily use the table size provided.
 *
 * @param pSymKey   Pointer to the input \c SymmetricKey structure containing
 *                  a TAP key.
 * @param ppNewCtx  Location that will recieve a pointer to the new AES-GCM context. 
 * @param mode      The GCM internal table size, one of the macros \c GCM_MODE_256B,
 *                  \c GCM_MODE_4K, \c GCM_MODE_64K, \c GCM_MODE_GENERAL. This must be
 *                  provided even if an alternative implementation is enabled.               
 * @param encrypt   \c TRUE to prepare this context for encryption,
 *                  \c FALSE to prepare this context for decryption.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 *
 * @warning         The param \c mode will specify the context type and table
 *                  size for the default software implementation but will not
 *                  be used for an alternative implementation.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc(
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 mode,
    sbyte4 encrypt
    );

/**
 * @brief   Sets an AES-GCM context to not unload the internal TAP Key upon cipher completion. 
 * @details Sets an AES-GCM to not unload the internal TAP Key upon cipher completion. 
 *
 * @param pCtx      Pointer to a TAP enabled AES-GCM context containing a TAP Key.
 * @param mode      The GCM internal table size, one of the macros \c GCM_MODE_256B,
 *                  \c GCM_MODE_4K, \c GCM_MODE_64K, \c GCM_MODE_GENERAL. This must be provided even
 *                  if an alternative implementation is enabled. 
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */ 
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesGcmDeferKeyUnload (
    BulkCtx pCtx,
    sbyte4 mode,
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
 * @param pCtx         Pointer to a TAP enabled AES-GCM context containing a TAP Key.
 * @param mode         The GCM internal table size, one of the macros \c GCM_MODE_256B,
 *                     \c GCM_MODE_4K, \c GCM_MODE_64K, \c GCM_MODE_GENERAL. This must be provided even
 *                     if an alternative implementation is enabled. 
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesGcmGetKeyInfo (
    BulkCtx pCtx,
    sbyte4 mode,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

#endif /* __ENABLE_DIGICERT_TAP__ */

/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_GCM_init_<size> APIs.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_init (
    MocSymCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen,
    ubyte4 tagLen,
    sbyte4 encrypt
    );


/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_GCM_update_<size> APIs.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_update (
    MocSymCtx pCtx,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutput,
    sbyte4 encrypt
    );


/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_GCM_final_<size> APIs.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_final (
    MocSymCtx pCtx,
    ubyte *pTag,
    ubyte4 tagLenBytes,
    ubyte **ppDecryptedData,
    ubyte4 *pDecryptedDataLen,
    sbyte4 encrypt
    );


/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_AES_GCM_encrypt API.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_encrypt(
    MocSymCtx pCtx,    
    ubyte *pNonce,
    ubyte4 *pNonceLen,
    intBoolean *pWasNonceUsed,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLenBytes
    );

/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_AES_GCM_decrypt API.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_decrypt(
    MocSymCtx pCtx,    
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLenBytes
    );

/**
 * @internal This API is private. One should use one of the \c CRYPTO_INTERFACE_GCM_deleteCtx APIs.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DeleteAESGCMCtx (
    MocSymCtx pCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_GCM_TAP_HEADER__ */
