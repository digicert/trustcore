/*
 * poly1305.h
 *
 * Implementation of the POLY1305 MAC
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
 * Adapted from the public domain implementation in
 *  <https://github.com/floodyberry/poly1305-donna>
 */

/**
 * @file       poly1305.h
 *
 * @brief      Header file for the NanoCrypto Poly1305 APIs.
 *
 * @details    This file contains the NanoCrypto Poly1305 API methods.
 *
 * @flags      To enable this file's methods define the following flag:
 *             + \c \__ENABLE_DIGICERT_POLY1305__
 *
 * @filedoc    poly1305.h
 */

#ifndef __POLY1305_HEADER__
#define __POLY1305_HEADER__

#include "../cap/capdecl.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
#include "../crypto_interface/crypto_interface_poly1305_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_POLY1305_STATE_INIT    0xC0DED00D
#define MOC_POLY1305_STATE_UPDATE  0xC0DED00E
#define MOC_POLY1305_STATE_FINAL   0xC0DED00F

typedef struct Poly1305Ctx
{
    ubyte4 aligner;
    ubyte opaque[136];
    ubyte4 state;

    MocSymCtx pMocSymCtx;
    ubyte enabled;
} Poly1305Ctx;


/**
 @brief      Initializes a Poly1305Ctx with a 32 byte (256 bit) key.
 
 @details    Initializes a Poly1305Ctx with a 32 byte (256 bit) key
             consisting of a 16 byte r followed by a 16 byte s.
 
 @ingroup    poly1305_functions
 
 @flags      To enable this file's methods define the following flag:
             + \c \__ENABLE_DIGICERT_POLY1305__
 
 @param ctx  A pointer to the context to be initialized.
 @param key  The 32 byte key consisting of the 16 byte r followed by the
             16 byte s.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 
 @funcdoc    poly1305.h
 */
MOC_EXTERN MSTATUS Poly1305Init(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, const ubyte key[32]);

/**
 @brief      Updates a Poly1305Ctx with message data.
 
 @details    Updates a Poly1305Ctx with message data. This may be the entire message,
             or Poly1305Update may be called multiple times each with a
             portion of the message.
 
 @ingroup    poly1305_functions
 
 @flags      To enable this file's methods define the following flag:
             + \c \__ENABLE_DIGICERT_POLY1305__
 
 @param ctx    Pointer to a Poly1305Ctx context previously initialized.
 @param m      A pointer to the message or portion of the message to be input.
 @param bytes  The number of bytes in the message or portion of the message input.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 
 @funcdoc    poly1305.h
 */
MOC_EXTERN MSTATUS Poly1305Update(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, const ubyte *m, ubyte4 bytes);
    
/**
 @brief      Finalizes a Poly1305Ctx and computes the resulting mac.
 
 @details    Finalizes a Poly1305Ctx and writes the resulting 16 byte message
             authentication code (mac) to a buffer.
 
 @ingroup    poly1305_functions
 
 @flags      To enable this file's methods define the following flag:
             + \c \__ENABLE_DIGICERT_POLY1305__
 
 @param ctx     Pointer to a Poly1305Ctx context previously initialized and updated.
 @param mac     A 16 element byte array that will hold the resulting mac.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 
 @funcdoc    poly1305.h
 */
MOC_EXTERN MSTATUS Poly1305Final(MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *ctx, ubyte mac[16]);


/**
 @brief      One shot API that will compute a poly1305 mac context free.
 
 @details    One shot API that will compute a poly1305 mac context free.
 
 @ingroup    poly1305_functions
 
 @flags      To enable this file's methods define the following flag:
             + \c \__ENABLE_DIGICERT_POLY1305__
 
 @param mac    A 16 element byte array that will hold the resulting mac.
 @param m      A pointer to the entire input message.
 @param bytes  The number of bytes in the input message.
 @param key    The 32 byte key consisting of the 16 byte r followed by the
               16 byte s.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h.
 
 @funcdoc    poly1305.h
 */
MOC_EXTERN MSTATUS Poly1305_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte mac[16], const ubyte *m, ubyte4 bytes,
                             const ubyte key[32]);

#ifdef __cplusplus
}
#endif

#endif /* POLY1305_DONNA_H */

