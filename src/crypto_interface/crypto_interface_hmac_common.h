/*
 * crypto_interface_hmac_common.h
 *
 * Common methods to Crypto Interface for HMAC and HMAC-KDF.
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
#ifndef __CRYPTO_INTERFACE_HMAC_COMMON_HEADER__
#define __CRYPTO_INTERFACE_HMAC_COMMON_HEADER__

#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacGetHashAlgoFlag (
    const BulkHashAlgo *pBHAlgo,
    ubyte *pHashAlgoFlag
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_HMAC_COMMON_HEADER__ */
