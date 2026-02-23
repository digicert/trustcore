/*
 * digi_ecx_exch.c
 *
 * EDDH implementations for OSSL 3.0 provider ADAPTED from OPENSSL code
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
/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*---------------------------------------------------------------------------------------------------------*/
/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto_interface/crypto_interface_ecc.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#include "mocana_glue.h"
#include "digicert_common.h"

#include "openssl/evp.h"
#include "prov/names.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/objects.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "internal/deprecated.h"

#include "openssl/crypto.h"
#include "crypto/ecx.h"
#include "internal/packet.h"
#include "internal/cryptlib.h"
#include "prov/der_ecx.h"
#include "openssl/obj_mac.h"
/*
 * Based on OpenSSL's PROV_ECX_CTX
 */

typedef struct 
{
    OSSL_LIB_CTX *libctx;

    size_t keylen;
    ECX_KEY *key;
    ECX_KEY *peerkey;

} DP_ECX_CTX;

MOC_EXTERN void digiprov_ecx_key_free(ECX_KEY *key);

static void *digiprov_ecx_newctx(void *provctx, size_t keylen)
{
    MSTATUS status = OK;
    DP_ECX_CTX *pCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_ECX_CTX));
    if (OK != status)
        goto exit;

    pCtx->keylen = keylen;
    pCtx->libctx = PROV_LIBCTX_OF(provctx);

exit:

    return pCtx;
}

static void *digiprov_x25519_newctx(void *provctx)
{
    return digiprov_ecx_newctx(provctx, X25519_KEYLEN);
}

static void *digiprov_x448_newctx(void *provctx)
{
    return digiprov_ecx_newctx(provctx, X448_KEYLEN);
}

static int digiprov_ecx_init(void *vecxctx, void *vkey,
                             ossl_unused const OSSL_PARAM params[])
{
    DP_ECX_CTX *ecxctx = (DP_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    if (!digiprov_is_running())
        return 0;

    if (ecxctx == NULL
            || key == NULL
            || key->keylen != ecxctx->keylen
            || !ossl_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    digiprov_ecx_key_free(ecxctx->key);
    ecxctx->key = key;

    return 1;
}

static int digiprov_ecx_set_peer(void *vecxctx, void *vkey)
{
    DP_ECX_CTX *ecxctx = (DP_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    if (!digiprov_is_running())
        return 0;

    if (ecxctx == NULL
            || key == NULL
            || key->keylen != ecxctx->keylen
            || !ossl_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    digiprov_ecx_key_free(ecxctx->peerkey);
    ecxctx->peerkey = key;

    return 1;
}

static int digiprov_ecx_derive(void *vecxctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    MSTATUS status = OK;
    DP_ECX_CTX *ecxctx = (DP_ECX_CTX *)vecxctx;
    ECCKey *pKey = NULL;
    ubyte4 curveId = 0;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (ecxctx->key == NULL || ecxctx->key->privkey == NULL || ecxctx->peerkey == NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    switch (ecxctx->key->type) 
    {
    case ECX_KEY_TYPE_X25519:
        if (!ossl_assert(ecxctx->keylen == X25519_KEYLEN))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        curveId = cid_EC_X25519;
        break;

    case ECX_KEY_TYPE_X448:
        if (!ossl_assert(ecxctx->keylen == X448_KEYLEN))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        curveId = cid_EC_X448;
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        return 0;
    }
    
    if (NULL == secret) 
    {
        *secretlen = ecxctx->keylen;
        return 1;
    }

    if (outlen < ecxctx->keylen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pKey, (ubyte * ) ecxctx->key->pubkey, (ubyte4)ecxctx->keylen, 
                                                     (ubyte *) ecxctx->key->privkey, (ubyte4) ecxctx->keylen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (pKey, ecxctx->peerkey->pubkey,
                                                      ecxctx->peerkey->keylen, &pSS, &ssLen, 0, NULL);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) secret, pSS, ssLen);
    if (OK != status)
        goto exit;

    *secretlen = (size_t) ssLen;

exit:

    if (NULL != pSS)
    {
        (void) DIGI_MEMSET_FREE(&pSS, ssLen);
    }

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
    }

    return (OK == status ? 1 : 0);
}

static void digiprov_ecx_freectx(void *vecxctx)
{
    DP_ECX_CTX *ecxctx = (DP_ECX_CTX *)vecxctx;

    digiprov_ecx_key_free(ecxctx->key);
    digiprov_ecx_key_free(ecxctx->peerkey);

    (void) DIGI_FREE((void **) &ecxctx);
}

static void *digiprov_ecx_dupctx(void *vecxctx)
{
    MSTATUS status = OK;
    DP_ECX_CTX *srcctx = (DP_ECX_CTX *)vecxctx;
    DP_ECX_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&dstctx, 1, sizeof(DP_ECX_CTX));
    if (OK != status)
        goto exit;

    *dstctx = *srcctx;
    if (dstctx->key != NULL && !ossl_ecx_key_up_ref(dstctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        (void) DIGI_FREE((void **) &dstctx);
        return NULL;
    }

    if (dstctx->peerkey != NULL && !ossl_ecx_key_up_ref(dstctx->peerkey)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        digiprov_ecx_key_free(dstctx->key);
        (void) DIGI_FREE((void **) &dstctx);
        return NULL;
    }

exit:

    return (void *) dstctx;
}

const OSSL_DISPATCH digiprov_x25519_keyexch_functions[] = 
{
    { OSSL_FUNC_KEYEXCH_NEWCTX,  (void (*)(void))digiprov_x25519_newctx },
    { OSSL_FUNC_KEYEXCH_INIT,    (void (*)(void))digiprov_ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE,  (void (*)(void))digiprov_ecx_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER,(void (*)(void))digiprov_ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))digiprov_ecx_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX,  (void (*)(void))digiprov_ecx_dupctx },
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_x448_keyexch_functions[] = 
{
    { OSSL_FUNC_KEYEXCH_NEWCTX,  (void (*)(void))digiprov_x448_newctx },
    { OSSL_FUNC_KEYEXCH_INIT,    (void (*)(void))digiprov_ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE,  (void (*)(void))digiprov_ecx_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER,(void (*)(void))digiprov_ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))digiprov_ecx_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX,  (void (*)(void))digiprov_ecx_dupctx },
    { 0, NULL }
};
