/*
 * crypto_interface_arc4.h
 *
 * Cryptographic Interface header file for declaring RC4 methods
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
@file       crypto_interface_arc4.h
@brief      Cryptographic Interface header file for declaring RC4 methods.
@details    Add details here.

@filedoc    crypto_interface_arc4.h
*/
#ifndef __CRYPTO_INTERFACE_ARC4_HEADER__
#define __CRYPTO_INTERFACE_ARC4_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new RC4 context. Note it is the callers responsibility to
 * free this object after use by calling CRYPTO_INTERFACE_DeleteRC4Ctx.
 * Once created, you can use this context as input to CRYPTO_INTERFACE_DoRC4
 * to encrypt, decrypt, or use as a stream cipher.
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLen       Length in bytes of the key material.
 * @param encrypt      UNUSED.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateRC4Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    );

/**
 * Deletes and frees memory allocated within an RC4 context.
 *
 * @param ppCtx  Location holding a pointer to the context to be deleted.
 *
 * @return       \c OK (0) if successful, otherwise a negative number
 *               error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteRC4Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    );


/**
 * Performs the RC4 cipher operation in-place.
 *
 * @param pCtx     A previously created RC4 context.
 * @param pData    The buffer of data to be transformed in-place.
 * @param dataLen  Length of the buffer pData in bytes.
 * @param encrypt  UNUSED. The encryption operation is the same as the
 *                 decryption operation.
 * @param pIv      UNUSED.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoRC4(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * Clone RC4 context previously created with CRYPTO_INTERFACE_CreateRC4Ctx.
 *
 * @param pCtx     Pointer to a BulkCtx returned by CRYPTO_INTERFACE_CreateRC4Ctx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneRC4Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ARC4_HEADER__ */
