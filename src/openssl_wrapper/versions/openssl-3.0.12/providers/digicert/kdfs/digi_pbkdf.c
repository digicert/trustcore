/*
 * digi_pbkdf.c
 *
 * PBKDF2 implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/absstream.h"
#include "../../../src/common/tree.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/asn1/parseasn1.h"
#include "../../../src/crypto/pkcs5.h"
#include "../../../src/crypto_interface/crypto_interface_pkcs5.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

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

#include "prov/implementations.h"
#include "prov/provider_util.h"

#include "digiprov.h"
#include "internal/deprecated.h"

static int digiprov_pbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

typedef struct
{
    void *provctx;
    unsigned char *pass;
    size_t pass_len;
    unsigned char *salt;
    size_t salt_len;
    uint64_t iter;
    ubyte digest;
    ubyte isVersion2;

} DP_PBKDF;

static void digiprov_pbkdf2_init(DP_PBKDF *ctx)
{    
    ctx->iter = PKCS5_DEFAULT_ITER;
    ctx->digest = ht_sha1;
}

static void *digiprov_pbkdf_new(void *provctx, ubyte isVersion2)
{
    MSTATUS status = OK;
    DP_PBKDF *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_PBKDF));
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->isVersion2 = isVersion2;
    if (isVersion2)
    {
        digiprov_pbkdf2_init(ctx);
    }
    return ctx;
}

static void *digiprov_pbkdf1_new(void *provctx)
{
    return digiprov_pbkdf_new(provctx, 0);
}

static void *digiprov_pbkdf2_new(void *provctx)
{
    return digiprov_pbkdf_new(provctx, 1);
}

static void digiprov_pbkdf_cleanup(DP_PBKDF *ctx)
{
    if (NULL != ctx->salt)
    {
        (void) DIGI_MEMSET_FREE(&ctx->salt, ctx->salt_len);
    }
    if (NULL != ctx->pass)
    {
        (void) DIGI_MEMSET_FREE(&ctx->pass, ctx->pass_len);
    }

    (void) DIGI_MEMSET((ubyte *) ctx, 0, sizeof(DP_PBKDF));
}

static void digiprov_pbkdf_free(void *vctx)
{
    DP_PBKDF *ctx = (DP_PBKDF *)vctx;

    if (NULL != ctx) 
    {
        digiprov_pbkdf_cleanup(ctx);
        (void) DIGI_FREE(&vctx);
    }
}

static void digiprov_pbkdf_reset(void *vctx)
{
    DP_PBKDF *ctx = (DP_PBKDF *)vctx;
    void *provctx;
    ubyte isVersion2 = 0;

    if (NULL == ctx)
        return;

    isVersion2 = ctx->isVersion2;
    provctx = ctx->provctx;
    
    digiprov_pbkdf_cleanup(ctx);
    ctx->provctx = provctx;

    if (isVersion2)
    {
        digiprov_pbkdf2_init(ctx);
    }
}

static int digiprov_pbkdf_set_membuf(unsigned char **buffer, size_t *buflen, const OSSL_PARAM *p)
{
    MSTATUS status = OK;

    if (NULL == buffer || NULL == buflen)
        return 0;

    if (NULL != *buffer)
    {
        if (*buflen)
        {
            (void) DIGI_MEMSET(*buffer, 0x00, *buflen);
            *buflen = 0;
        }

        status = DIGI_FREE((void **) buffer);
        if (OK != status)
            return 0;
    }

    /* could be empty string, allocate 1 byte */
    if (0 == p->data_size)
    {
        status = DIGI_CALLOC((void **) buffer, 1, 1);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *buflen = 0;
    }
    else if (NULL != p->data)
    {
        if (!digiprov_get_octet_string(p, (void **)buffer, 0, buflen))
            return 0;
    }
    return 1;
}

static int digiprov_pbkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_PBKDF *ctx = (DP_PBKDF *)vctx;

    if (NULL == ctx)
        return 0;

    if (!digiprov_is_running() || !digiprov_pbkdf_set_ctx_params(ctx, params))
        return 0;

    if (NULL == ctx->pass) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return 0;
    }

    if (NULL == ctx->salt) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return 0;
    }
  
    if (ctx->isVersion2)
    {
        status = CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2((const ubyte *) ctx->salt, (ubyte4) ctx->salt_len, (ubyte4) ctx->iter, ctx->digest, 
                                                         (const ubyte *) ctx->pass, (ubyte4) ctx->pass_len, (ubyte4) keylen, key);
    }
    else
    {
        status = CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF1((const ubyte *) ctx->salt, (ubyte4) ctx->salt_len, (ubyte4) ctx->iter, (enum hashFunc) ctx->digest, 
                                                         (const ubyte *) ctx->pass, (ubyte4) ctx->pass_len, (ubyte4) keylen, key);        
    }
    if (OK != status)
        return 0;

    return 1;
}

static int digiprov_pbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    const OSSL_PARAM *p;
    DP_PBKDF *ctx = vctx;
    int pkcs5;

    if (NULL == params)
        return 1;

    if (NULL == ctx)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (NULL != p)
    {
        BulkHashAlgo *pBHAlgo = NULL;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        status = digiprov_get_digest_data((const char *) p->data, &pBHAlgo, NULL, NULL);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return 0;
        }

        ctx->digest = pBHAlgo->hashId;
    }

    if (ctx->isVersion2)
    {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PKCS5)) != NULL) 
        {
            if (!OSSL_PARAM_get_int(p, &pkcs5))
                return 0;
            /* Ok but not used */
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD)) != NULL)
    {
        if (!digiprov_pbkdf_set_membuf(&ctx->pass, &ctx->pass_len, p))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
    {
        if (!digiprov_pbkdf_set_membuf(&ctx->salt, &ctx->salt_len, p))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER)) != NULL)
    {
        if (!OSSL_PARAM_get_uint64(p, &ctx->iter))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *digiprov_pbkdf1_settable_ctx_params(ossl_unused void *ctx,
                                                             ossl_unused void *p_ctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

static const OSSL_PARAM *digiprov_pbkdf2_settable_ctx_params(ossl_unused void *ctx,
                                                             ossl_unused void *p_ctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS5, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

static int digiprov_pbkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    return -2;
}

static const OSSL_PARAM *digiprov_pbkdf_gettable_ctx_params(ossl_unused void *ctx,
                                                             ossl_unused void *p_ctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
    {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_gettable_ctx_params;
}

const OSSL_DISPATCH digiprov_pbkdf1_functions[] = 
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void))digiprov_pbkdf1_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void))digiprov_pbkdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void))digiprov_pbkdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void))digiprov_pbkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_pbkdf1_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void))digiprov_pbkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_pbkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void))digiprov_pbkdf_get_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_pbkdf2_functions[] = 
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void))digiprov_pbkdf2_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void))digiprov_pbkdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void))digiprov_pbkdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void))digiprov_pbkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_pbkdf2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void))digiprov_pbkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_pbkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void))digiprov_pbkdf_get_ctx_params },
    { 0, NULL }
};
