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
    void *pKeyData; /* (QS_CTX *) */
    size_t cid;
    size_t secSize;
    int hasPrivKey;
    int hasPubKey;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;

} DP_PQC_KEY;

typedef struct _DP_MLX_KEY
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    void *pPQCKeyData; /* (QS_CTX *) */
    void *pECCKeyData; /* (ECCKey *) */
    size_t cidECC;
    size_t secSize;

    size_t pqcPrivLen;
    size_t pqcPubLen;
    size_t pqcCipherLen;

    size_t curvePrivLen;
    size_t curvePubLen;
    size_t curveSSLen;

    int curveFirst;
    unsigned int state;

} DP_MLX_KEY;

#define DP_MLX_HAVE_NOKEYS 0
#define DP_MLX_HAVE_PUBKEY 1
#define DP_MLX_HAVE_PRVKEY 2

/* Both key parts have whatever the ML-KEM component has */
#define digi_mlx_kem_have_pubkey(key) ((key)->state > 0)
#define digi_mlx_kem_have_prvkey(key) ((key)->state > 1)

#ifdef __cplusplus
}
#endif

#endif /* __DIGIPROV_HEADER__ */
