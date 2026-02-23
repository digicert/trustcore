/*
 * digi_mac_sig.c
 *
 * MAC signature implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#ifdef SHA256_CTX
#undef SHA256_CTX
#endif
#ifdef SHA512_CTX
#undef SHA512_CTX
#endif

#include "openssl/evp.h"
#include "prov/names.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/objects.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/param_build.h"
#include "openssl/crypto.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"

#include "internal/deprecated.h"

#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/macsignature.h"

#include <string.h>
#ifndef FIPS_MODULE
# include <openssl/engine.h>
#endif

typedef struct 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    MAC_KEY *key;
    EVP_MAC_CTX *macctx;

} DP_MAC_CTX;

int digiprov_mac_key_up_ref(MAC_KEY *mackey);
void digiprov_mac_key_free(MAC_KEY *mackey);

static void *digiprov_mac_newctx(void *provctx, const char *propq, const char *macname)
{
    MSTATUS status = OK;
    DP_MAC_CTX *pmacctx;
    EVP_MAC *mac = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pmacctx, 1, sizeof(DP_MAC_CTX));
    if (OK != status)
        return NULL;

    pmacctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL)
    {
        status = digiprov_strdup((void **) &pmacctx->propq, propq);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } 
    
    mac = EVP_MAC_fetch(pmacctx->libctx, macname, propq);
    if (mac == NULL)
        goto err;

    pmacctx->macctx = EVP_MAC_CTX_new(mac);
    if (pmacctx->macctx == NULL)
        goto err;

    EVP_MAC_free(mac);

    return pmacctx;

 err:
    (void) DIGI_FREE((void **) &pmacctx->propq);
    (void) DIGI_FREE((void **) &pmacctx);
    EVP_MAC_free(mac);
    return NULL;
}

#define MAC_NEWCTX(funcname, macname) \
    static void *digiprov_mac_##funcname##_newctx(void *provctx, const char *propq) \
    { \
        return digiprov_mac_newctx(provctx, propq, macname); \
    }

MAC_NEWCTX(hmac, "HMAC")
MAC_NEWCTX(poly1305, "POLY1305")
MAC_NEWCTX(cmac, "CMAC")

static int digiprov_mac_digest_sign_init(void *vpmacctx, const char *mdname, void *vkey, const OSSL_PARAM params[])
{
    DP_MAC_CTX *pmacctx = (DP_MAC_CTX *)vpmacctx;
    const char *ciphername = NULL, *engine = NULL;

    if (!digiprov_is_running() || pmacctx == NULL)
        return 0;

    if (pmacctx->key == NULL && vkey == NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vkey != NULL)
    {
        if (!ossl_mac_key_up_ref(vkey))
            return 0;
        digiprov_mac_key_free(pmacctx->key);
        pmacctx->key = vkey;
    }

    if (pmacctx->key->cipher.cipher != NULL)
        ciphername = (char *)EVP_CIPHER_get0_name(pmacctx->key->cipher.cipher);
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
    if (pmacctx->key->cipher.engine != NULL)
        engine = (char *)ENGINE_get_id(pmacctx->key->cipher.engine);
#endif

    if (!ossl_prov_set_macctx(pmacctx->macctx, NULL,
                              (char *)ciphername,
                              (char *)mdname,
                              (char *)engine,
                              pmacctx->key->properties,
                              NULL, 0))
        return 0;

    if (!EVP_MAC_init(pmacctx->macctx, pmacctx->key->priv_key,
                      pmacctx->key->priv_key_len, params))
        return 0;

    return 1;
}

int digiprov_mac_digest_sign_update(void *vpmacctx, const unsigned char *data, size_t datalen)
{
    DP_MAC_CTX *pmacctx = (DP_MAC_CTX *)vpmacctx;

    if (pmacctx == NULL || pmacctx->macctx == NULL)
        return 0;

    return EVP_MAC_update(pmacctx->macctx, data, datalen);
}

int digiprov_mac_digest_sign_final(void *vpmacctx, unsigned char *mac, size_t *maclen, size_t macsize)
{
    DP_MAC_CTX *pmacctx = (DP_MAC_CTX *)vpmacctx;

    if (!digiprov_is_running() || pmacctx == NULL || pmacctx->macctx == NULL)
        return 0;

    return EVP_MAC_final(pmacctx->macctx, mac, maclen, macsize);
}

static void digiprov_mac_freectx(void *vpmacctx)
{
    DP_MAC_CTX *ctx = (DP_MAC_CTX *)vpmacctx;

    if (NULL != ctx->propq)
    {
        (void) DIGI_FREE((void **) &ctx->propq);
    }
    EVP_MAC_CTX_free(ctx->macctx);
    digiprov_mac_key_free(ctx->key);
    (void) DIGI_FREE((void **) &ctx);
}

static void *digiprov_mac_dupctx(void *vpmacctx)
{
    DP_MAC_CTX *srcctx = (DP_MAC_CTX *)vpmacctx;
    DP_MAC_CTX *dstctx = NULL;
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(DP_MAC_CTX));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    dstctx->propq = NULL;
    dstctx->key = NULL;
    dstctx->macctx = NULL;

    if (srcctx->propq != NULL)
    {
        status = digiprov_strdup((void **) &dstctx->propq, srcctx->propq);
        if (OK != status)
            goto err;       
    } 

    if (srcctx->key != NULL && !ossl_mac_key_up_ref(srcctx->key))
        goto err;
    dstctx->key = srcctx->key;

    if (srcctx->macctx != NULL)
    {
        dstctx->macctx = EVP_MAC_CTX_dup(srcctx->macctx);
        if (dstctx->macctx == NULL)
            goto err;
    }

    return dstctx;
 err:
    digiprov_mac_freectx(dstctx);
    return NULL;
}

static int digiprov_mac_set_ctx_params(void *vpmacctx, const OSSL_PARAM params[])
{
    DP_MAC_CTX *ctx = (DP_MAC_CTX *)vpmacctx;

    return EVP_MAC_CTX_set_params(ctx->macctx, params);
}

static const OSSL_PARAM *digiprov_mac_settable_ctx_params(ossl_unused void *ctx,
                                                          void *provctx,
                                                          const char *macname)
{
    EVP_MAC *mac = EVP_MAC_fetch(PROV_LIBCTX_OF(provctx), macname, NULL);
    const OSSL_PARAM *params;

    if (mac == NULL)
        return NULL;

    params = EVP_MAC_settable_ctx_params(mac);
    EVP_MAC_free(mac);

    return params;
}

#define MAC_SETTABLE_CTX_PARAMS(funcname, macname) \
    static const OSSL_PARAM *digiprov_mac_##funcname##_settable_ctx_params(void *ctx, \
                                                                           void *provctx) \
    { \
        return digiprov_mac_settable_ctx_params(ctx, provctx, macname); \
    }

MAC_SETTABLE_CTX_PARAMS(hmac, "HMAC")
MAC_SETTABLE_CTX_PARAMS(poly1305, "POLY1305")
MAC_SETTABLE_CTX_PARAMS(cmac, "CMAC")

#define MAC_SIGNATURE_FUNCTIONS(funcname) \
    const OSSL_DISPATCH digiprov_mac_##funcname##_signature_functions[] = { \
        { OSSL_FUNC_SIGNATURE_NEWCTX,             (void (*)(void))digiprov_mac_##funcname##_newctx }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (void (*)(void))digiprov_mac_digest_sign_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))digiprov_mac_digest_sign_update }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (void (*)(void))digiprov_mac_digest_sign_final }, \
        { OSSL_FUNC_SIGNATURE_FREECTX,            (void (*)(void))digiprov_mac_freectx }, \
        { OSSL_FUNC_SIGNATURE_DUPCTX,             (void (*)(void))digiprov_mac_dupctx }, \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (void (*)(void))digiprov_mac_set_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,(void (*)(void))digiprov_mac_##funcname##_settable_ctx_params }, \
        { 0, NULL } \
    };

MAC_SIGNATURE_FUNCTIONS(hmac)
MAC_SIGNATURE_FUNCTIONS(poly1305)
MAC_SIGNATURE_FUNCTIONS(cmac)
