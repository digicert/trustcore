/*
 * crypto_interface_aes_cmac.h
 *
 * Cryptographic Interface header file for declaring AES-CMAC methods
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
 @file       crypto_interface_aes_cmac.h
 @brief      Cryptographic Interface header file for declaring AES-CMAC methods.
 @details    Add details here.
 
 @filedoc    crypto_interface_aes_cmac.h
 */
#ifndef __CRYPTO_INTERFACE_AES_CMAC_HEADER__
#define __CRYPTO_INTERFACE_AES_CMAC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates and initializes a new AESCMAC_Ctx context. Note it is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_AESCMAC_final.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material. This must be
 *                     16, 24, or 32.
 * @param pCtx         A pointer to the context to be initialized.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_init(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
    sbyte4 keyLength,
    AESCMAC_Ctx *pCtx
    );

/**
 * Creates and initializes a new AESCMAC_Ctx context. Note it is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_AESCMAC_final.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material. This must be
 *                     16, 24, or 32.
 * @param pCtx         A pointer to the context to be initialized.
 * @param pExtCtx      An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_initExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
    sbyte4 keyLength,
    AESCMAC_Ctx *pCtx,
    void *pExtCtx
    );

/**
 * Updates a previously initialized context with the data or portion thereof.
 * CRYPTO_INTERFACE_AESCMAC_update may be called as many times as necessary.
 *
 * @param pData        The message data or portion thereof that is being MAC'd.
 * @param dataLength   The length of the pData buffer in bytes.
 * @param pCtx         A previously initialized context.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_update(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData,
    sbyte4 dataLength,
    AESCMAC_Ctx *pCtx
    );

/**
 * Updates a previously initialized context with the data or portion thereof.
 * CRYPTO_INTERFACE_AESCMAC_update may be called as many times as necessary.
 *
 * @param pData        The message data or portion thereof that is being MAC'd.
 * @param dataLength   The length of the pData buffer in bytes.
 * @param pCtx         A previously initialized context.
 * @param pExtCtx      An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_updateExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData,
    sbyte4 dataLength,
    AESCMAC_Ctx *pCtx,
    void *pExtCtx
    );

/**
 * Finalizes a context and outputs the resulting CMAC. This will also
 * free any memory allocated upon initialization.
 *
 * @param cmac         The resulting CMAC. 16 bytes must be available.
 * @param pCtx         A previously initialized and updated context.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_final(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[16],
    AESCMAC_Ctx *pCtx
    );

/**
 * Finalizes a context and outputs the resulting CMAC. This will also
 * free any memory allocated upon initialization.
 *
 * @param cmac         The resulting CMAC. 16 bytes must be available.
 * @param pCtx         A previously initialized and updated context.
 * @param pExtCtx      An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_finalExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[CMAC_RESULT_SIZE],
    AESCMAC_Ctx *pCtx,
    void *pExtCtx
    );

/**
 * Frees the internal AES Context and zeros the outer context.
 *
 * @param pCtx         A previously used context that is no longer needed.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_clear(
    MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx* pCtx
    );

/**
 * @brief Makes a clone of a previously allocated \c AESCMAC_Ctx.
 *
 * @details Makes a clone of a previously allocated \c AESCMAC_Ctx.
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_cloneCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx *pDest,
    AESCMAC_Ctx *pSrc
    );

/**
 * Finalizes a context and outputs the resulting CMAC. This does not
 * clear or free the aes-key however leaving the context ok to be re-used.
 * Please be sure tall call \c CRYPTO_INTERFACE_AESCMAC_final when
 * done to free the memory.
 *
 * @param cmac         The resulting CMAC. 16 bytes must be available.
 * @param pCtx         A previously initialized and updated context.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_finalAndReset(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[16],
    AESCMAC_Ctx* pCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_CMAC_HEADER__ */
