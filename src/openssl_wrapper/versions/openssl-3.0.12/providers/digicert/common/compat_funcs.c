/*
 * compat_funcs.c
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
