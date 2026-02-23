/*
 * pqc.h
 *
 * Header file for declaring DigiProv PQC Key Structure.
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
