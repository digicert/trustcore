/*
 * rc4algo.h
 *
 * RC4 Algorithm
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
 * @file       rc4algo.h
 * @brief      Header file for the NanoCrypto RC4 APIs.
 *
 * @details    This file contains the NanoCrypto RC4 API methods.
 *
 * @filedoc    rc4algo.h
 */

/*------------------------------------------------------------------*/

#ifndef __RC4ALGO_H__
#define __RC4ALGO_H__

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_arc4_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __DISABLE_ARC4_CIPHERS__

/**
 * @brief   Creates and initializes a new RC4 context.
 *
 * @details Creates and initializes a new RC4 context.
 *
 * @param keyMaterial  Buffer of the input key material.
 * @param keyLength    The length of the input key material.
 * @param encrypt      Unused. RC4 is a stream cipher.
 *
 * @return  If successful, pointer to a new RC4 context cast as a \c BulkCtx.
 *          Otherwise NULL is returned.
 *
 * @funcdoc rc4algo.h
 */
MOC_EXTERN BulkCtx CreateRC4Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
 * @brief   Deletes an RC4 context.
 *
 * @details Deletes and frees memory allocated for an RC4 context.
 *
 * @param ctx         Pointer to the location of the context to be deleted.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc rc4algo.h
 */
MOC_EXTERN MSTATUS DeleteRC4Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
 * @brief   Performs the RC4 stream cipher operation to encrypt or decrypt a buffer of data.
 *
 * @details Performs the RC4 stream cipher operation to encrypt or decrypt a buffer of data.
 *
 * @param ctx         Pointer to a previously created RC4 context.
 * @param data        The buffer of data to be encrypted or decrypted in-place.
 * @param dataLength  The length of data in bytes.
 * @param encrypt     Unused. RC4 is a stream cipher.
 * @param iv          Unused. No initialization vector is needed.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc rc4algo.h
 */
MOC_EXTERN MSTATUS DoRC4(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
 * Clone RC4 context previously created with CreateRC4Ctx.
 *
 * @param pCtx     Pointer to a BulkCtx returned by CreateRC4Ctx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CloneRC4Ctx (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);
#endif

#ifdef __cplusplus
}
#endif


#endif
