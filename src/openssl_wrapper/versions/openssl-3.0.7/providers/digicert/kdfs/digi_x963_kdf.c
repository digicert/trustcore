/*
 * digi_x963_kdf.c
 *
 * ANSI_X963-KDF implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
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
#include "../../../src/crypto/md5.h"
#include "../../../src/crypto/sha1.h"
#include "../../../src/crypto/sha256.h"
#include "../../../src/crypto/sha512.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/ansix9_63_kdf.h"

#include "../../../src/crypto_interface/crypto_interface_ansix9_63_kdf.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

typedef struct 
{
    BulkHashAlgo *pBHAlgo;
    unsigned char *secret;
    size_t secret_len;
    unsigned char *info;
    size_t info_len;
    size_t out_len;

} DP_X963_CTX;

static int digiprov_sskdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *digiprov_sskdf_new(void *provctx)
{
    MSTATUS status = OK;
    DP_X963_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_X963_CTX));
    if (OK != status)
        return NULL;

    return ctx;
}

static void digiprov_sskdf_reset(void *vctx)
{
    DP_X963_CTX *ctx = (DP_X963_CTX *)vctx;

    if (NULL == ctx)
        return;
    
    if (NULL != ctx->secret)
        (void) DIGI_MEMSET_FREE(&ctx->secret, ctx->secret_len);
    
    if (NULL != ctx->info)
        (void) DIGI_MEMSET_FREE(&ctx->info, ctx->info_len);
    
    (void) DIGI_MEMSET((ubyte *) ctx, 0, sizeof(DP_X963_CTX)); 
}

static void digiprov_sskdf_free(void *vctx)
{
    DP_X963_CTX *ctx = (DP_X963_CTX *) vctx;

    if (NULL != ctx) 
    {
        digiprov_sskdf_reset(ctx);
        (void) DIGI_FREE((void **) &ctx);
    }
}

static int digiprov_sskdf_set_buffer(unsigned char **out, size_t *out_len, const OSSL_PARAM *p)
{
    if (p->data == NULL || p->data_size == 0)
        return 1;
    
    (void) DIGI_FREE((void **) out);
    return digiprov_get_octet_string(p, (void **)out, 0, out_len);
}

static size_t digiprov_sskdf_size(DP_X963_CTX *ctx)
{
    if (NULL == ctx->pBHAlgo) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    return ctx->out_len;
}

static int digiprov_x963kdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_X963_CTX *ctx = (DP_X963_CTX *) vctx;

    if (!digiprov_is_running())
        return 0;
    
    if(!digiprov_sskdf_set_ctx_params(ctx, params))
        return 0;

    if (NULL == ctx->secret) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        return 0;
    }

    if (NULL == ctx->pBHAlgo) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    status = CRYPTO_INTERFACE_ANSIX963KDF_generate(ctx->pBHAlgo, ctx->secret, (ubyte4) ctx->secret_len,
                                                   ctx->info, (ubyte4) ctx->info_len, (ubyte4) keylen, key);
    if (OK != status)
    {
        (void) DIGI_MEMSET(key, 0x00, keylen);
        return 0;
    }

    return 1;
}

static int digiprov_sskdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    const OSSL_PARAM *p;
    DP_X963_CTX *ctx = (DP_X963_CTX *) vctx;
    size_t sz;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (NULL != p)
    {
        ubyte4 digestLen = 0;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        status = digiprov_get_digest_data((const char *) p->data, &ctx->pBHAlgo, &digestLen, NULL);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return 0;
        }

        ctx->out_len = (size_t) digestLen;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL
        || (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
        if (!digiprov_sskdf_set_buffer(&ctx->secret, &ctx->secret_len, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL)
        if (!digiprov_sskdf_set_buffer(&ctx->info, &ctx->info_len, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {   
        return 0; /* Not supported 
        if (!digiprov_sskdf_set_buffer(&ctx->salt, &ctx->salt_len, p))
            return 0; */
    }
    
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MAC_SIZE)) != NULL) 
    {
        if (!OSSL_PARAM_get_size_t(p, &sz) || sz == 0)
            return 0;
        ctx->out_len = sz;
    }

    return 1;
}

static const OSSL_PARAM *digiprov_sskdf_settable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
   /*   OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0), NOT SUPPORTED */
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_MAC_SIZE, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

static int digiprov_sskdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_X963_CTX *ctx = (DP_X963_CTX *) vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, digiprov_sskdf_size(ctx));
    return -2;
}

static const OSSL_PARAM *digiprov_sskdf_gettable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
    {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_gettable_ctx_params;
}

const OSSL_DISPATCH digiprov_x963_kdf_functions[] =
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void))digiprov_sskdf_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void))digiprov_sskdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void))digiprov_sskdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void))digiprov_x963kdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_sskdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void))digiprov_sskdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_sskdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void))digiprov_sskdf_get_ctx_params },
    { 0, NULL }
};
