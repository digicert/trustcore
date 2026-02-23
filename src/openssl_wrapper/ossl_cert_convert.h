/*
 * ossl_cert_convert.h
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

#ifndef OSSL_CERT_CONVERT_H
#define OSSL_CERT_CONVERT_H

extern MSTATUS ossl_CERT_STORE_addGenericIdentity(SSL_CTX *ctx, EVP_PKEY *pkey);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
extern void ossl_clearCredentials(void);
#endif
#endif
