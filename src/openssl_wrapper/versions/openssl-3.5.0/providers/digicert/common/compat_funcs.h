/*
 * compat_funcs.h
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
#ifndef COMPAT_FUNCS_H
#define COMPAT_FUNCS_H

void *DIGI_EVP_CIPHER_CTX_getCipherData(const EVP_CIPHER_CTX *ctx);
int DIGI_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);

#endif
