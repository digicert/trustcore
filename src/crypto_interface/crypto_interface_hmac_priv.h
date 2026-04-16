/*
 * crypto_interface_hmac_priv.h
 *
 * Cryptographic Interface header file for redeclaring HMAC functions.
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

/**
@file       crypto_interface_hmac_priv.h
@brief      Cryptographic Interface header file for redeclaring HMAC functions.
@details    Add details here.

@filedoc    crypto_interface_hmac_priv.h
*/
#ifndef __CRYPTO_INTERFACE_HMAC_PRIV_HEADER__
#define __CRYPTO_INTERFACE_HMAC_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_INTERNAL__))

#define HmacCreate          CRYPTO_INTERFACE_HmacCreate
#define HmacKey             CRYPTO_INTERFACE_HmacKey
#define HmacReset           CRYPTO_INTERFACE_HmacReset
#define HmacUpdate          CRYPTO_INTERFACE_HmacUpdate
#define HmacFinal           CRYPTO_INTERFACE_HmacFinal
#define HmacDelete          CRYPTO_INTERFACE_HmacDelete
#define HmacQuick           CRYPTO_INTERFACE_HmacQuick
#define HmacQuicker         CRYPTO_INTERFACE_HmacQuicker
#define HmacQuickEx         CRYPTO_INTERFACE_HmacQuickEx
#define HmacQuickerEx       CRYPTO_INTERFACE_HmacQuickerEx
#define HmacQuickerInline   CRYPTO_INTERFACE_HmacQuickerInline
#define HmacQuickerInlineEx CRYPTO_INTERFACE_HmacQuickerInlineEx
#define HMAC_MD5            CRYPTO_INTERFACE_HMAC_MD5
#define HMAC_MD5_quick      CRYPTO_INTERFACE_HMAC_MD5_quick
#define HMAC_SHA1           CRYPTO_INTERFACE_HMAC_SHA1
#define HMAC_SHA1_quick     CRYPTO_INTERFACE_HMAC_SHA1_quick
#define HMAC_SHA1Ex         CRYPTO_INTERFACE_HMAC_SHA1Ex
#define HMAC_SHA256         CRYPTO_INTERFACE_HMAC_SHA256
#define HMAC_SHA512         CRYPTO_INTERFACE_HMAC_SHA512


#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_HMAC_PRIV_HEADER__ */
