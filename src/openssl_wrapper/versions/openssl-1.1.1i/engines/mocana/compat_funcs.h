/*
 * compact_funcs.h
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
#ifndef COMPAT_FUNCS_H
#define COMPAT_FUNCS_H

void *DIGI_EVP_CIPHER_CTX_getCipherData(const EVP_CIPHER_CTX *ctx);
int DIGI_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);

#endif
