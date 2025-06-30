/*
 * crypto_interface_aes_xcbc_mac_96.h
 *
 * Cryptographic Interface header file for declaring AES-XCBC functions
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

/**
@file       crypto_interface_aes_xcbc_mac_96.h
@brief      Cryptographic Interface header file for declaring AES-XCBC functions.
@details    Add details here.

@filedoc    crypto_interface_aes_xcbc_mac_96.h
*/
#ifndef __CRYPTO_INTERFACE_AES_XCBC_MAC_96_HEADER__
#define __CRYPTO_INTERFACE_AES_XCBC_MAC_96_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes an AES_XCBC_MAC_96_Ctx context. Note this includes allocations
 * of internal AES contexts. Note it is the callers responsibility to
 * clear this object, and free its internals, by calling
 * CRYPTO_INTERFACE_AES_XCBC_clear.
 *
 * @param pKeyMaterial Key material to be used for the mac operation. This
 *                     must be 16 bytes.
 * @param pCtx         Pointer to the context to be initialized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_init(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte pKeyMaterial[16],
    AES_XCBC_MAC_96_Ctx *pCtx
    );

/**
 * Updates the state of an AES_XCBC_MAC_96_Ctx or AES_XCBC_PRF_128_Ctx context
 * with data.
 *
 * Note: This method is shared between AES_XCBC_MAC_96 and AES_XCBC_PRF_128.
 *       Call this method to perform the AES_XCBC_PRF_128_update operation.
 *
 * @param pData      The buffer of input data.
 * @param dataLength The length of pData in bytes.
 * @param pCtx       The already initialized context to be updated.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_update(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte *pData,
    sbyte4 dataLength,
    AES_XCBC_MAC_96_Ctx *pCtx
    );

/**
 * Finalizes an AES_XCBC_MAC_96_Ctx and outputs the resulting 96 bit (12 byte)
 * MAC.
 *
 * @param pCmac      Buffer that will hold the resulting MAC. It must be at least 12
 *                   bytes in length.
 * @param pCtx       The already initialized and updated context to be finalized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_final(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte pCmac[12],
    AES_XCBC_MAC_96_Ctx *pCtx
    );

/**
 * Resets an AES_XCBC_MAC_96_Ctx or AES_XCBC_PRF_128_Ctx context.
 *
 * Note: This method is shared between AES_XCBC_MAC_96 and AES_XCBC_PRF_128.
 *       Call this method to perform the AES_XCBC_PRF_128_reset operation.
 *
 * @param pCtx  Pointer to the context to be reset.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_MAC_96_reset(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    AES_XCBC_MAC_96_Ctx *pCtx
    );

/**
 * Initializes an AES_XCBC_PRF_128_Ctx context. Note it is the callers responsibility
 * to clear this object after use by calling CRYPTO_INTERFACE_AES_XCBC_clear.
 *
 * @param pKeyMaterial Key material to be used for the mac operation.
 * @param keyLength    The length of the buffer pKeyMaterial in bytes. This may
 *                     be any size.
 * @param pCtx         Pointer to the context to be initialized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_PRF_128_init(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte pKeyMaterial[/*keyLength*/],
    sbyte4 keyLength,
    AES_XCBC_PRF_128_Ctx *pCtx
    );

/**
 * Finalizes an AES_XCBC_PRF_128_Ctx and outputs the resulting 128 bit (16 byte)
 * MAC.
 *
 * @param pCmac      Buffer that will hold the resulting MAC. It must be at least 16
 *                   bytes in length.
 * @param pCtx       The already initialized and updated context to be finalized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_PRF_128_final(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte pCmac[16],
    AES_XCBC_PRF_128_Ctx *pCtx
    );

/**
 * Clears a AES_XCBC_MAC_96_Ctx or AES_XCBC_PRF_128_Ctx context. This
 * does free internally allocated AES contexts.
 *
 * @param pCtx  Pointer to the context to be cleared.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_XCBC_clear (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    AES_XCBC_MAC_96_Ctx *pCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_XCBC_MAC_96_HEADER__ */
