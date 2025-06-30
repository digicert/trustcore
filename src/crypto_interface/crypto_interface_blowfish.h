/*
 * crypto_interface_blowfish.h
 *
 * Cryptographic Interface header file for declaring Blowfish methods
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
@file       crypto_interface_blowfish.h
@brief      Cryptographic Interface header file for declaring Blowfish methods.
@details    Add details here.

@filedoc    crypto_interface_blowfish.h
*/
#ifndef __CRYPTO_INTERFACE_BLOWFISH_HEADER__
#define __CRYPTO_INTERFACE_BLOWFISH_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates and initializes a new Blowfish context. Note it is the callers
 * responsibility to free this object after use by calling
 * CRYPTO_INTERFACE_DeleteBlowfishCtx.
 * 
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLen       Length in bytes of the key material.
 * @param encrypt      UNUSED.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateBlowfishCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    );
    
/**
 * Deletes a Blowfish context.
 *
 * @param ppCtx Pointer to the BulkCtx to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteBlowfishCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    );

/**
 * Performs the Blowfish cipher operation in CBC mode. Pass in the
 * initialization vector on the first call, but subsequent calls are
 * not guaranteed to use the pIv field. Use CRYPTO_INTERFACE_DoBlowfishEx
 * instead if you wish to use a modified iv. Note that this
 * operation is in place, so the pData buffer will contain the result.
 *
 * @param pCtx     A previously initialized context.
 * @param pData    Data to encrypt or decrypt.
 * @param dataLen  Length in bytes of the data to process. This must be
 *                 a multiple of the block size of 8 bytes.
 * @param encrypt  \c TRUE to perform encryption;
 *                 \c FALSE to perform decryption.
 * @param pIv      The 8 byte initialization vector.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoBlowfish(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * Performs the Blowfish cipher operation in CBC mode.
 * This function can be used to stream data. Pass in the initialization vector
 * and it will be updated in place. Continue to pass in new data and updated
 * initialization vector on each subsequent call. The updated iv
 * will be written to pIv upon method completion. Note that this
 * operation is in place, so the pData buffer will contain the result.
 *
 * @param pCtx     A previously initialized context.
 * @param pData    Data to encrypt or decrypt.
 * @param dataLen  Length in bytes of the data to process. This must be
 *                 a multiple of the block size of 8 bytes.
 * @param encrypt  \c TRUE to perform encryption;
 *                 \c FALSE to perform decryption.
 * @param pIv      The 8 byte initialization vector. Upon completion
 *                 of the method it will be updated to the working IV.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoBlowfishEx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    );

/**
 * Clones a Blowfish context. Be sure to free the new contex with
 *           a call to \c DeleteBlowfishCtx.
 * @param  pCtx        Source Blowfish context.
 * @param  ppNewCtx    Will point to the newly allocated copy of the source context.
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneBlowfishCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, 
    BulkCtx *ppNewCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_BLOWFISH_HEADER__ */
