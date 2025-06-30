/*
 * arc4.h
 *
 * "alleged rc4" algorithm
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
 * @file       arc4.h
 * @brief      Header file for the NanoCrypto RC4 Internal APIs.
 *
 * @details    This file contains the NanoCrypto RC4 Internal API methods.
 *
 * @filedoc    arc4.h
 */

/*------------------------------------------------------------------*/

#ifndef __ARC4_H__
#define __ARC4_H__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rc4_key
{
    ubyte state[256];
    ubyte x;
    ubyte y;
    MocSymCtx         pMocSymCtx;
    ubyte             enabled;
} rc4_key;

/**
 * @brief   Computes the RC4 key schedule.
 *
 * @details Computes the RC4 key schedule.
 *
 * @param key_data_ptr  Buffer of the input key material.
 * @param key_data_len  The length of the input key material.
 * @param key           Pointer to the key to be prepared.
 *
 * @funcdoc     arc4.h
 */
MOC_EXTERN void prepare_key(ubyte *key_data_ptr, sbyte4 key_data_len, rc4_key *key);
    
/**
 * @brief   Performs the RC4 cipher operation.
 *
 * @details Performs the RC4 cipher operation. RC4 is a stream cipher and
 *          the encryption operation is the same as the decryption operation.
 *
 * @param buffer_ptr  The buffer of data to be operated on in-place.
 * @param buffer_len  The length in bytes of the data to be operated on. This
 *                    length can be anything non-zero.
 * @param key         Pointer to a prepared rc4 key.
 *
 * @funcdoc     arc4.h
 */
MOC_EXTERN void rc4(ubyte *buffer_ptr, sbyte4 buffer_len, rc4_key *key);

#ifdef __cplusplus
}
#endif

#endif
