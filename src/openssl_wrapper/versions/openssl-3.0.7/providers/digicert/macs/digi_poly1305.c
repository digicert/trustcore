/*
 * digi_poly1305.c
 *
 * POLY1305 implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/poly1305.h"

#include "../../../src/crypto_interface/crypto_interface_poly1305.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/core_names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

#define POLY1305_KEY_SIZE 32
#define POLY1305_OUT_SIZE 16

typedef struct poly1305_data_st 
{
    void *provctx;
    int updated;
    Poly1305Ctx *ctx;
    ubyte *key;
    ubyte4 keylen;

} DP_POLY1305_CTX;

static int digiprov_poly1305_set_ctx_params(void *vmacctx, const OSSL_PARAM *params);

static void *digiprov_poly1305_new(void *provctx)
{
    MSTATUS status = OK;
    DP_POLY1305_CTX *macctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &macctx, 1, sizeof(DP_POLY1305_CTX));
    if (OK != status)
        return NULL;

    status = DIGI_CALLOC((void **) &macctx->ctx, 1, sizeof(Poly1305Ctx));
    if (OK != status)
    {
        (void) DIGI_FREE((void **) &macctx);
        return NULL;
    }

    macctx->provctx = provctx;
    return macctx;
}

static void digiprov_poly1305_free(void *vmacctx)
{
    DP_POLY1305_CTX *macctx = (DP_POLY1305_CTX *)vmacctx;

    if (NULL != macctx) 
    {
        if (NULL != macctx->key)
        {
            (void) DIGI_MEMSET_FREE((ubyte **) &macctx->key, macctx->keylen);
        }

        if (NULL != macctx->ctx)
        {
            (void) DIGI_MEMSET_FREE((ubyte **) &macctx->ctx, sizeof(Poly1305Ctx));
        }
        
        (void) DIGI_FREE((void **) &macctx);
    }
}

static void *digiprov_poly1305_dup(void *vsrc)
{
    MSTATUS status = OK;
    DP_POLY1305_CTX *dst = NULL;
    DP_POLY1305_CTX *src = (DP_POLY1305_CTX *) vsrc;

    if (!digiprov_is_running())
        return NULL;

    if (NULL == src)
        return NULL;

    dst = digiprov_poly1305_new(NULL);
    if (NULL == dst)
        return NULL;

    /* new allocated the inner poly1305 ctx too */
    status = CRYPTO_INTERFACE_Poly1305_cloneCtx(dst->ctx, src->ctx);
    if (OK != status)
    {
        digiprov_poly1305_free(dst); /* frees the inner poly1305ctx too */
        dst = NULL;
        return NULL;
    }

    /* and copy the key */
    if (src->keylen > 0 && NULL != src->key)
    {
        status = DIGI_MALLOC((void **) &dst->key, src->keylen);
        if (OK != status)
        {
            digiprov_poly1305_free(dst);
            dst = NULL;
            return NULL;
        }

        (void) DIGI_MEMCPY(dst->key, src->key, src->keylen);
    }
   
    dst->keylen = src->keylen;
    dst->updated = src->updated;
    dst->provctx = src->provctx;

    return (void *) dst;
}

static int digiprov_poly1305_setkey(DP_POLY1305_CTX *macctx, const unsigned char *key, size_t keylen)
{
    MSTATUS status = OK;

    if (POLY1305_KEY_SIZE != keylen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    
    if (macctx->key != NULL)
    {
        status = DIGI_MEMSET_FREE(&macctx->key, macctx->keylen);
        if (OK != status)
            return 0;
    }

    status = DIGI_MALLOC((void **) &macctx->key, keylen);
    if (OK != status)
        return 0;

    status = DIGI_MEMCPY(macctx->key, key, keylen);
    if (OK != status)
    {
        (void) DIGI_FREE((void **) &macctx->key);
        return 0;
    }

    macctx->keylen = keylen;
    macctx->updated = 0;

    return 1;
}

static int digiprov_poly1305_init(void *vmacctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_POLY1305_CTX *macctx = (DP_POLY1305_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (!digiprov_poly1305_set_ctx_params(macctx, params))
        return 0;
        
    if (key != NULL)
    {
        if (!digiprov_poly1305_setkey(macctx, key, keylen))
            return 0;
    }
    else if (1 == macctx->updated)
    {
        /* no reinitialization of context with the same key is allowed */
        return 0;
    }

    status = CRYPTO_INTERFACE_Poly1305Init(macctx->ctx, macctx->key);
    if (OK != status)
        return 0;

    return 1;
}

static int digiprov_poly1305_update(void *vmacctx, const unsigned char *data, size_t datalen)
{
    DP_POLY1305_CTX *macctx = (DP_POLY1305_CTX *) vmacctx;

    macctx->updated = 1;
    if (datalen == 0)
        return 1;

    if (OK == CRYPTO_INTERFACE_Poly1305Update(macctx->ctx, data, (ubyte4) datalen))
        return 1;

    return 0;
}

static int digiprov_poly1305_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_POLY1305_CTX *macctx = vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (outsize < POLY1305_OUT_SIZE)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    macctx->updated = 1;

    if (OK == CRYPTO_INTERFACE_Poly1305Final(macctx->ctx, out))
    {
        *outl = POLY1305_OUT_SIZE;
        return 1;
    }
    
    return 0;
}

static const OSSL_PARAM digiprov_known_gettable_params[] =
{
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_poly1305_gettable_params(void *provctx)
{
    return digiprov_known_gettable_params;
}

static int digiprov_poly1305_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, POLY1305_OUT_SIZE);

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
{
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_poly1305_settable_ctx_params(ossl_unused void *ctx,
                                                               ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

static int digiprov_poly1305_set_ctx_params(void *vmacctx, const OSSL_PARAM *params)
{
    DP_POLY1305_CTX *ctx = vmacctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL
            && !digiprov_poly1305_setkey(ctx, p->data, p->data_size))
        return 0;
    return 1;
}

const OSSL_DISPATCH digiprov_poly1305_functions[] = 
{
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))digiprov_poly1305_new },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))digiprov_poly1305_dup },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))digiprov_poly1305_free },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))digiprov_poly1305_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))digiprov_poly1305_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))digiprov_poly1305_final },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,     (void (*)(void))digiprov_poly1305_gettable_params },
    { OSSL_FUNC_MAC_GET_PARAMS,          (void (*)(void))digiprov_poly1305_get_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_poly1305_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))digiprov_poly1305_set_ctx_params },
    { 0, NULL }
};
