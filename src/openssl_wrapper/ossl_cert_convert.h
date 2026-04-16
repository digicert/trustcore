/*
 * ossl_cert_convert.h
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

#ifndef OSSL_CERT_CONVERT_H
#define OSSL_CERT_CONVERT_H

extern MSTATUS ossl_CERT_STORE_addGenericIdentity(SSL_CTX *ctx, EVP_PKEY *pkey);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
extern void ossl_clearCredentials(void);
#endif
#endif
