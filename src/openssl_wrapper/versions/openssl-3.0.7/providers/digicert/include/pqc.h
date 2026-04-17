/*
 * pqc.h
 *
 * Header file for declaring DigiProv PQC Key Structure.
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

#ifndef __PQC_HEADER__
#define __PQC_HEADER__

#include "openssl/types.h"

#include "openssl/core.h"
#include "openssl/e_os2.h"
#include "openssl/crypto.h"
#include "internal/refcount.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DP_PQC_KEY
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    void *pKeyData; /* QS_CTX * */
    size_t cid;
    size_t secSize;
    int hasPrivKey;
    int hasPubKey;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;

} DP_PQC_KEY;

#ifdef __cplusplus
}
#endif

#endif /* __DIGIPROV_HEADER__ */
