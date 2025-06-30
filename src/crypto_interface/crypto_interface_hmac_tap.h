/*
 * crypto_interface_hmac_tap.h
 *
 * Cryptographic Interface header file for declaring TAP HMAC functions
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


#ifndef __CRYPTO_INTERFACE_HMAC_TAP_HEADER__
#define __CRYPTO_INTERFACE_HMAC_TAP_HEADER__

/* Need HMAC_CTX type but hmac.h needs the hash algo headers */
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/hmac.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Create a new HMAC context from a previously existing TAP symmetric key.
 * @details Create a new HMAC context from a previously existing TAP symmetric key.
 *          This API allocates memory for the new HMAC context, and takes ownership of
 *          the input \c SymmetricKey structure, so be sure to call
 *          \c CRYPTO_INTERFACE_HmacDelete in order to free these structures when done.
 *
 * @param pSymKey   Pointer to the input \c SymmetricKey structure containing
 *                  a TAP key.
 * @param ppCtx     Location that will recieve a pointer to the new HMAC context.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (
    SymmetricKey *pSymKey,
    HMAC_CTX **ppCtx
    );

/**
 * @brief   Sets an HMAC context to not unload the internal TAP Key upon cipher completion.
 * @details Sets an HMAC context to not unload the internal TAP Key upon cipher completion.
 *
 * @param pCtx                Pointer to a TAP enabled HMAC context containing a TAP Key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacDeferKeyUnload (
    HMAC_CTX *pCtx,
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
 * @param pCtx         Pointer to a TAP enabled HMAC context containing a TAP Key.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacGetKeyInfo (
    HMAC_CTX *pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    );

#endif /* __ENABLE_MOCANA_TAP__ */

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_HmacReset.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacReset (
    MocSymCtx pCtx
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_HmacUpdate.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacUpdate (
    MocSymCtx pCtx,
    const ubyte *pData,
    ubyte4 dataLen
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_HmacFinal.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacFinal (
    MocSymCtx pCtx,
    ubyte *pResult
    );

/**
 * @internal This API is private. One should use \c CRYPTO_INTERFACE_HmacSingle.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_HmacSingle (
    MocSymCtx pCtx,
    const ubyte *pText,
    ubyte4 textLen,
    ubyte *pResult
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_HMAC_TAP_HEADER__ */
