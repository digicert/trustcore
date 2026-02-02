/*
 * crypto_interface_tdes_tap.h
 *
 * Cryptographic Interface header file for declaring TDES TAP functions
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

#ifndef __CRYPTO_INTERFACE_TDES_TAP_HEADER__
#define __CRYPTO_INTERFACE_TDES_TAP_HEADER__

#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Create a new TDES CBC context from a previously existing TAP symmetric key.
 * @details Create a new TDES CBC context from a previously existing TAP symmetric key.
 *          This API allocates memory for the new TDES CBC context, and takes ownership of
 *          the input \c SymmetricKey structure, so be sure to call
 *          \c CRYPTO_INTERFACE_Delete3DESCtx in order to free these structures when done.
 *
 * @param pSymKey   Pointer to the input \c SymmetricKey structure containing
 *                  a TAP key.
 * @param ppNewCtx  Location that will recieve a pointer to the new TDES CBC context.                 
 * @param encrypt   \c TRUE to prepare this context for encryption,
 *                  \c FALSE to prepare this context for decryption.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc (
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 encrypt
    );

/**
 * @brief   Initializes a new TDES ECB context from a previously existing TAP symmetric key.
 * @details Initializes a new TDES ECB context from a previously existing TAP symmetric key.
 *          This API allocates memory internally and takes ownership of
 *          the input \c SymmetricKey structure, so be sure to call
 *          \c CRYPTO_INTERFACE_THREE_DES_clearKey in order to free this memory when done.
 *
 * @param pSymKey   Pointer to the input \c SymmetricKey structure containing
 *                  a TAP key.
 * @param pCtx      Pointer to the TDES ECB context to be initialized.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_initTDesEcbCtxFromSymmetricKey (
    SymmetricKey *pSymKey,
    ctx3des *pCtx
    );

/**
 * @brief   Sets an TDES-CBC context to not unload the internal TAP Key upon cipher completion. 
 * @details Sets an TDES-CBC context to not unload the internal TAP Key upon cipher completion. 
 *
 * @param pCtx      Pointer to a TAP enabled TDES-CBC context containing a TAP Key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesCbcDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    );

/**
 * @brief   Sets an TDES-ECB context to not unload the internal TAP Key upon cipher completion. 
 * @details Sets an TDES-ECB context to not unload the internal TAP Key upon cipher completion. 
 *
 * @param pCtx      Pointer to a TAP enabled TDES-ECB context containing a TAP Key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */ 
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesEcbDeferKeyUnload (
    BulkCtx pCtx,
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
 * @param pCtx         Pointer to a TAP enabled DES-CBC context containing a TAP Key.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesCbcGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

/**
 * @brief   Gets the key handle and token handle for an internal TAP key.
 * @details Gets the key handle and token handle for an internal TAP key. This is
 *          typically used for obtaining the key handle and token handle for a deferred
 *          unload TAP key. This method should be called after the cipher operation and
 *          before the cipher context cleanup.
 *
 * @param pCtx         Pointer to a TAP enabled DES-ECB context containing a TAP Key.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_TDesEcbGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

#endif /* __ENABLE_DIGICERT_TAP__ */

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_Do3DES.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_Do3DES (
    MocSymCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_THREE_DES_encipher.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_THREE_DES_encipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_THREE_DES_decipher.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_THREE_DES_decipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_TDES_TAP_HEADER__ */
