/*
 * cast128.h
 *
 * CAST-128 Header
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
 * @file       cast128.h
 *
 * @brief      Header file for the NanoCrypto Cast128 APIs.
 *
 * @details    This file contains the NanoCrypto Cast128 API methods.
 *
 * @flags      To enable this file's methods define the following flag:
 *             + \c \__ENABLE_CAST128_CIPHER__
 *
 * @filedoc    cast128.h
 */

/*------------------------------------------------------------------*/

#ifndef __CAST128_HEADER__
#define __CAST128_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define CAST128_BLOCK_SIZE      (8)


/*------------------------------------------------------------------*/

typedef struct {
    ubyte4 xkey[32]; /* key */
    sbyte4 rounds;
} cast128_ctx;

#ifdef __ENABLE_CAST128_CIPHER__

/*------------------------------------------------------------------*/

/**
 * @brief   Initializes a cast128 context with a key.
 *
 * @details Initializes a cast128 context with a key.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param pCtx    Pointer to a context to be initialized with a key.
 * @param pKey    Buffer holding the input key.
 * @param keyLen  The length of the key in bytes.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN MSTATUS CAST128_initKey(cast128_ctx *pCtx, const ubyte *pKey, sbyte4 keyLen);

/**
 * @brief   Encrypts a block of plaintext.
 *
 * @details Encrypts a block of plaintext.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param pCtx       Pointer to a previously initialized context.
 * @param inblock    Buffer of the input 8 byte block of plaintext.
 * @param outblock   Buffer that will hold the resulting 8 byte block of ciphertext.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN MSTATUS CAST128_encryptBlock(cast128_ctx *pCtx, 
                                        ubyte inblock[/*CAST128_BLOCK_SIZE*/],
                                        ubyte outblock[/*CAST128_BLOCK_SIZE*/]);

/**
 * @brief   Decrypts a block of ciphertext.
 *
 * @details Decrypts a block of ciphertext.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param pCtx       Pointer to a previously initialized context.
 * @param inblock    Buffer of the input 8 byte block of ciphertext.
 * @param outblock   Buffer that will hold the resulting 8 byte block of plaintext.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN MSTATUS CAST128_decryptBlock(cast128_ctx *pCtx, 
                                        ubyte inblock[/*CAST128_BLOCK_SIZE*/],
                                        ubyte outblock[/*CAST128_BLOCK_SIZE*/]);

/**
 * @brief   Allocates and initalizes a new cast128 context.
 *
 * @details Allocates and initalizes a new cast128 context with an input key.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param keyMaterial    Buffer holding the input key material.
 * @param keyLength      The length of the input key in bytes.
 * @param encrypt        Unused.
 *
 * @return  If successful, pointer to a new cast128 context cast as a \c BulkCtx.
 *          Otherwise NULL is returned.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN BulkCtx CreateCast128Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
 * @brief   Deletes a cast128 context.
 *
 * @details Deletes and frees memory allocated for a cast128 context.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param ctx        Pointer to the location of the context to be deleted.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN MSTATUS DeleteCast128Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx);

/**
 * @brief   Performs cast128 in CBC mode on a buffer of data.
 *
 * @details Performs cast128 in CBC mode to encrypt or decrypt a buffer of data.
 *          The length of this data must be a multiple of the cast block size of
 *          8 bytes. This method may be called as many times as necessary and the
 *          initialization vector will be updated in-place.
 *
 * @flags   To enable this file's methods define the following flag:
 *          + \c \__ENABLE_CAST128_CIPHER__
 *
 * @param ctx        Pointer to a previously created context.
 * @param data       A buffer holding the data to be encrypted or decrypted. This will be
 *                   encrypted or decrypted in-place.
 * @param dataLength The length of the data in bytes. This must be a multiple of 8.
 * @param encrypt    Pass TRUE (1) for encryption and FALSE (0) for decryption.
 * @param iv         The 8 byte initialization vector. This will be updated in place
 *                   to the iv for the next input block.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc cast128.h
 */
MOC_EXTERN MSTATUS DoCast128(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
#endif /* __ENABLE_CAST128_CIPHER__ */

#ifdef __cplusplus
}
#endif

#endif /* __CAST128_HEADER__ */
