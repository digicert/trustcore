/*
 * compat_funcs.c
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

#include <openssl/opensslconf.h>

#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <openssl/evp.h>
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include <crypto/evp/evp_locl.h>
#endif
#else
#include <include/crypto/evp.h>

#include <crypto/evp/evp_local.h>
#endif /* OPENSSL_VERSION_NUMBER < 0x010101060 */

void *DIGI_EVP_CIPHER_CTX_getCipherData(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

int DIGI_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}
