 /*
 * crypto_interface_md5_priv.h
 *
 * Cryptographic Interface header file for redeclaring MD5 functions.
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
@file       crypto_interface_md5_priv.h
@brief      Cryptographic Interface header file for redeclaring MD5 functions.
@details    Add details here.

@filedoc    crypto_interface_md5_priv.h
*/
#ifndef __CRYPTO_INTERFACE_MD5_PRIV_HEADER__
#define __CRYPTO_INTERFACE_MD5_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5_INTERNAL__))

#define MD5Alloc_m         CRYPTO_INTERFACE_MD5Alloc_m
#define MD5Free_m          CRYPTO_INTERFACE_MD5Free_m
#define MD5Init_m          CRYPTO_INTERFACE_MD5Init_m
#define MD5Update_m        CRYPTO_INTERFACE_MD5Update_m
#define MD5Final_m         CRYPTO_INTERFACE_MD5Final_m
#define MD5_completeDigest CRYPTO_INTERFACE_MD5_completeDigest
#define MD5_cloneCtx       CRYPTO_INTERFACE_MD5_cloneCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_MD5_PRIV_HEADER__ */
