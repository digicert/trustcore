/*
 * crypto_interface_hmac_common.h
 *
 * Common methods to Crypto Interface for HMAC and HMAC-KDF.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
