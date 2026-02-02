/*
 * aes_xcbc_mac_96.h
 *
 * AES-XCBC-MAC-96 and derived Implementation ( RFC 3566, RFC 3664, RFC 4434)
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
 * @file       aes_xcbc_mac_96.h
 *
 * @brief      Header file for declaring AES-XCBC functions.
 * @details    Header file for declaring AES-XCBC functions.
 *
 * @filedoc    aes_xcbc_mac_96.h
 */

/*------------------------------------------------------------------*/

#ifndef __AES_XCBC_MAC_96_HEADER__
#define __AES_XCBC_MAC_96_HEADER__

#include "../cap/capdecl.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_aes_xcbc_mac_96_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AES_XCBC_MAC_96_RESULT_SIZE     (12) /* 96 bits */
#define AES_XCBC_PRF_128_RESULT_SIZE    (AES_BLOCK_SIZE) /* 128 bits */

typedef struct AES_XCBC_MAC_96_Ctx
{
    aesCipherContext       *pKeyAesCtx;  /* key K */
    aesCipherContext       *pAesCtx;     /* key K1, K2 or K3 */
    ubyte                   currBlock[AES_BLOCK_SIZE];
    /* bytes received -- we delay the processing until more bytes are
    received or final is called */
    ubyte                   pending[AES_BLOCK_SIZE] ;
    /* length of bytes received above <= AES_BLOCK_SIZE */
    ubyte                   pendingLen;
    MocSymCtx               pMocSymCtx;
    ubyte                   enabled;
    
} AES_XCBC_MAC_96_Ctx, AES_XCBC_PRF_128_Ctx;


/*------------------------------------------------------------------*/

/* AES CMAC -- cf RFC 3566 for explanations of parameters. */

/**
 * @brief   Initializes an \c AES_XCBC_MAC_96_Ctx context.
 *
 * @details Initializes an \c AES_XCBC_MAC_96_Ctx context. Note this includes allocations
 *          of internal AES contexts. Note it is the callers responsibility to
 *          clear this object, and free its internals, by calling
 *          \c AES_XCBC_clear.
 *
 * @param keyMaterial  Key material to be used for the mac operation. This
 *                     must be 16 bytes.
 * @param pCtx         Pointer to the context to be initialized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_MAC_96_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte keyMaterial[AES_BLOCK_SIZE],
                                        AES_XCBC_MAC_96_Ctx* pCtx);
/**
 * @brief   Updates the state of an AES_XCBC_MAC_96_Ctx context with data.
 *
 * @details Updates the state of an AES_XCBC_MAC_96_Ctx context with data.
 *
 * @param data       The buffer of input data.
 * @param dataLength The length of pData in bytes.
 * @param pCtx       The already initialized context to be updated.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_MAC_96_update(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* data, sbyte4 dataLength,
                                        AES_XCBC_MAC_96_Ctx* pCtx);

/**
 * @brief   Finalizes an AES_XCBC_MAC_96_Ctx and outputs the resulting 96 bit (12 byte) MAC.
 *
 * @details Finalizes an AES_XCBC_MAC_96_Ctx and outputs the resulting 96 bit (12 byte) MAC.
 *
 * @param cmac       Buffer that will hold the resulting MAC. It must be at least 12
 *                   bytes in length.
 * @param pCtx       The already initialized and updated context to be finalized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_MAC_96_final( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[AES_XCBC_MAC_96_RESULT_SIZE],
                                        AES_XCBC_MAC_96_Ctx* pCtx);

/**
 * @brief   Resets an AES_XCBC_MAC_96_Ctx context.
 *
 * @details Resets an AES_XCBC_MAC_96_Ctx context. The internal buffer is cleared
 *          but the AES context and key are not cleared.
 *
 * @param pCtx  Pointer to the context to be reset.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelDescr hwAccelCtx) AES_XCBC_MAC_96_Ctx* pCtx);

/* AES CMAC -- cf RFC 4434 */

/**
 * @brief   Initializes an AES_XCBC_PRF_128_Ctx context.
 *
 * @details Initializes an AES_XCBC_PRF_128_Ctx context. Note it is the callers responsibility
 *          to clear this object after use by calling AES_XCBC_clear.
 *
 * @param keyMaterial  Key material to be used for the mac operation.
 * @param keyLength    The length of the buffer pKeyMaterial in bytes. This may
 *                     be any size.
 * @param pCtx         Pointer to the context to be initialized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_PRF_128_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte keyMaterial[/*keyLength*/],
                                        sbyte4 keyLength,
                                        AES_XCBC_PRF_128_Ctx* pCtx);

/**
 * @brief   Updates the state of an AES_XCBC_PRF_128_Ctx context with data.
 *
 * @brief   Updates the state of an AES_XCBC_PRF_128_Ctx context with data. This
 *          method is a macro which is expanded to \c AES_XCBC_MAC_96_update.
 *
 * @param data       The buffer of input data.
 * @param dataLength The length of pData in bytes.
 * @param pCtx       The already initialized context to be updated.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_PRF_128_update(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* data, sbyte4 dataLength,
                                           AES_XCBC_PRF_128_Ctx* pCtx);
#define AES_XCBC_PRF_128_update     AES_XCBC_MAC_96_update

/**
 * @brief   Finalizes an AES_XCBC_PRF_128_Ctx and outputs the resulting 128 bit (16 byte) MAC.
 *
 * @details Finalizes an AES_XCBC_PRF_128_Ctx and outputs the resulting 128 bit (16 byte) MAC.
 *
 * @param cmac       Buffer that will hold the resulting MAC. It must be at least 16
 *                   bytes in length.
 * @param pCtx       The already initialized and updated context to be finalized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_PRF_128_final( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[AES_XCBC_PRF_128_RESULT_SIZE],
                                        AES_XCBC_PRF_128_Ctx* pCtx);

/**
 * @brief   Resets an AES_XCBC_PRF_128_Ctx context.
 *
 * @details Resets an AES_XCBC_PRF_128_Ctx context. The internal buffer is cleared
 *          but the AES context and key are not cleared. This
 *          method is a macro which is expanded to \c AES_XCBC_MAC_96_reset.
 *
 * @param pCtx  Pointer to the context to be reset.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_PRF_128_reset(MOC_SYM(hwAccelDescr hwAccelCtx) AES_XCBC_PRF_128_Ctx* pCtx);
#define AES_XCBC_PRF_128_reset     AES_XCBC_MAC_96_reset
    
/**
 * @brief   Clears a AES_XCBC_MAC_96_Ctx or AES_XCBC_PRF_128_Ctx context.
 *
 * @details Clears a AES_XCBC_MAC_96_Ctx or AES_XCBC_PRF_128_Ctx context. This
 *          does free internally allocated AES contexts.
 *
 * @param pCtx  Pointer to the context to be cleared.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS AES_XCBC_clear (MOC_SYM(hwAccelDescr hwAccelCtx) AES_XCBC_MAC_96_Ctx *pCtx);

#ifdef __cplusplus
}
#endif

#endif /* __AES_XCBC_MAC_96_HEADER__ */

