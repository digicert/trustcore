/*
 * crypto_interface_ecc_tap.h
 *
 * Cryptographic Interface header file for declaring ECC TAP functions.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#ifndef __CRYPTO_INTERFACE_ECC_TAP_HEADER__
#define __CRYPTO_INTERFACE_ECC_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Sets an ECC Key to not unload the internal TAP Key upon cipher completion. 
 * @details Sets an ECC Key to not unload the internal TAP Key upon cipher completion. 
 *
 * @param pCtx      Pointer to a TAP enabled ECC Key containing a TAP Key.
 * @param keyType      One of \c MOC_ASYM_KEY_TYPE_PRIVATE or \c MOC_ASYM_KEY_TYPE_PUBLIC.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccDeferKeyUnload (
    ECCKey *pKey,
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
 * @param pCtx         Pointer to a TAP enabled ECC key containing a TAP Key.
 * @param keyType      One of \c MOC_ASYM_KEY_TYPE_PRIVATE or \c MOC_ASYM_KEY_TYPE_PUBLIC.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccGetKeyInfo(
    ECCKey *pKey,
    ubyte4 keyType,
    TAP_TokenHandle *pTokenHandle, 
    TAP_KeyHandle *pKeyHandle
    );

/**
 * @brief   Unloads an internal TAP key.
 * @details Unloads an internal TAP key.
 *
 * @param pKey         Pointer to a TAP enabled ECC key containing a TAP Key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccUnloadKey(
    ECCKey *pKey
    );

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_TAP_HEADER__ */
