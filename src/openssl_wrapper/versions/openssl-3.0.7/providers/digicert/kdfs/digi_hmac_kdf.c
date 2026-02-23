/*
 * digi_hmac_kdf.c
 *
 * HMAC-KDF implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
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
#include "../../../src/crypto/hmac.h"
#include "../../../src/crypto/hmac_kdf.h"

#include "../../../src/crypto_interface/crypto_interface_hmac_kdf.h"

#define HMAC_CTX HMAC_CTX_OSSL
#include "mocana_glue.h"
#include "digicert_common.h"
#undef HMAC_CTX

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/kdf.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

#define DP_HKDF_MAXBUF 2048
#define DP_MAX_DIGEST_SIZE 64

/* Settable context parameters that are common across HKDF and the TLS KDF */
#define HKDF_COMMON_SETTABLES                                           \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),     \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),           \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0)

typedef struct 
{
    int mode;
    BulkHashAlgo *pBHAlgo;
    size_t digestLen;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char *prefix;
    size_t prefix_len;
    /* unsigned char *label; NOT needed for non-tls version
    size_t label_len; */
    unsigned char *data;
    size_t data_len;
    unsigned char info[DP_HKDF_MAXBUF];
    size_t info_len;

} DP_HKDF_CTX;

static int digiprov_kdf_hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *digiprov_kdf_hkdf_new(void *provctx)
{
    MSTATUS status = OK;
    DP_HKDF_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_HKDF_CTX));
    if (OK != status)
        return NULL;

    return ctx;
}

static void digiprov_kdf_hkdf_reset(void *vctx)
{
    DP_HKDF_CTX *ctx = (DP_HKDF_CTX *)vctx;

    if (NULL == ctx)
        return;

    if (NULL != ctx->salt)
        (void) DIGI_MEMSET_FREE(&ctx->salt, ctx->salt_len);
    
    if (NULL != ctx->prefix)
        (void) DIGI_MEMSET_FREE(&ctx->prefix, ctx->prefix_len);
    
    if (NULL != ctx->key)
        (void) DIGI_MEMSET_FREE(&ctx->key, ctx->key_len);
    
    /*
    if (NULL != ctx->label)
        (void) DIGI_MEMSET_FREE(&ctx->label, ctx->label_len); */
    
    if (NULL != ctx->data)
        (void) DIGI_MEMSET_FREE(&ctx->data, ctx->data_len);

    (void) DIGI_MEMSET(ctx->info, 0, ctx->info_len);
    (void) DIGI_MEMSET((ubyte *) ctx, 0, sizeof(DP_HKDF_CTX)); 
}

static void digiprov_kdf_hkdf_free(void *vctx)
{
    DP_HKDF_CTX *ctx = (DP_HKDF_CTX *) vctx;

    if (NULL != ctx) 
    {
        digiprov_kdf_hkdf_reset(ctx);
        (void) DIGI_FREE((void **) &ctx);
    }
}

static size_t digiprov_kdf_hkdf_size(DP_HKDF_CTX *ctx)
{
    if (EVP_KDF_HKDF_MODE_EXTRACT_ONLY != ctx->mode)
        return SIZE_MAX;

    if (NULL == ctx->pBHAlgo)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    
    return (size_t) ctx->digestLen;
}

static int digiprov_kdf_hkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_HKDF_CTX *ctx = (DP_HKDF_CTX *) vctx;

    if (!digiprov_is_running())
        return 0;

    if(!digiprov_kdf_hkdf_set_ctx_params(ctx, params))
        return 0;

    if (NULL == ctx->pBHAlgo)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    if (NULL == ctx->key) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (keylen == 0) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    switch (ctx->mode) 
    {
      case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
      default:
        {
        ubyte temp[DP_MAX_DIGEST_SIZE] = {0};
        status = CRYPTO_INTERFACE_HmacKdfExtract(ctx->pBHAlgo, ctx->salt, (ubyte4) ctx->salt_len, 
                                                 ctx->key, (ubyte4) ctx->key_len, temp, (ubyte4) ctx->digestLen);
        if (OK != status)
            return 0;

        status = CRYPTO_INTERFACE_HmacKdfExpand(ctx->pBHAlgo, temp, (ubyte4) ctx->digestLen,
                                                ctx->info, (ubyte4) ctx->info_len, ctx->prefix, 
                                                (ubyte4) ctx->prefix_len, key, (ubyte4) keylen);
        (void) DIGI_MEMSET(temp, 0x00, ctx->digestLen);
        }
        break;
  
      case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:

        status = CRYPTO_INTERFACE_HmacKdfExtract(ctx->pBHAlgo, ctx->salt, (ubyte4) ctx->salt_len, 
                                                 ctx->key, (ubyte4) ctx->key_len, key, (ubyte4) keylen);
        break;

      case EVP_KDF_HKDF_MODE_EXPAND_ONLY:

        status = CRYPTO_INTERFACE_HmacKdfExpand(ctx->pBHAlgo, ctx->key, (ubyte4) ctx->key_len,
                                                ctx->info, (ubyte4) ctx->info_len, ctx->prefix,
                                                (ubyte4) ctx->prefix_len, key, (ubyte4) keylen);
        break; 
    }

    if (OK != status)
    {
        (void) DIGI_MEMSET(key, 0x00, keylen);
        return 0;
    }

    return 1;
}

static int digiprov_hkdf_common_set_ctx_params(DP_HKDF_CTX *ctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    const OSSL_PARAM *p;
    int n;

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

        ctx->digestLen = (size_t) digestLen;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL) 
    {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
        {
            if (OPENSSL_strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (OPENSSL_strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (OPENSSL_strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                ctx->mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
        }
        else if (OSSL_PARAM_get_int(p, &n))
        {
            if (n != EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                && n != EVP_KDF_HKDF_MODE_EXTRACT_ONLY
                && n != EVP_KDF_HKDF_MODE_EXPAND_ONLY)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
            ctx->mode = n;
        }
        else 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) 
    {
        if (NULL != ctx->key)
            (void) DIGI_MEMSET_FREE(&ctx->key, ctx->key_len);

        if (!digiprov_get_octet_string(p, (void **)&ctx->key, 0, &ctx->key_len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL) 
    {
        if (NULL != ctx->salt)
            (void) DIGI_MEMSET_FREE(&ctx->salt, ctx->salt_len);

        if (!digiprov_get_octet_string(p, (void **)&ctx->salt, 0, &ctx->salt_len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX)) != NULL) 
    {
        if (NULL != ctx->prefix)
            (void) DIGI_MEMSET_FREE(&ctx->prefix, ctx->prefix_len);

        if (!digiprov_get_octet_string(p, (void **)&ctx->prefix, 0, &ctx->prefix_len))
            return 0;
    }

    return 1;
}

static int digiprov_kdf_hkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    DP_HKDF_CTX *ctx = (DP_HKDF_CTX *) vctx;

    if (params == NULL)
        return 1;

    if (!digiprov_hkdf_common_set_ctx_params(ctx, params))
        return 0;

    /* The info fields concatenate, so process them all */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO)) != NULL) 
    {
        ctx->info_len = 0;
        for (; p != NULL; p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO))
        {
            const void *q = ctx->info + ctx->info_len;
            size_t sz = 0;

            if (p->data_size != 0
                && p->data != NULL
                && !digiprov_get_octet_string(p, (void **)&q, DP_HKDF_MAXBUF - ctx->info_len, &sz))
                return 0;
            ctx->info_len += sz;
        }
    }
    return 1;
}

static const OSSL_PARAM *digiprov_kdf_hkdf_settable_ctx_params(ossl_unused void *ctx,
                                                               ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        HKDF_COMMON_SETTABLES,
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

static int digiprov_kdf_hkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_HKDF_CTX *ctx = (DP_HKDF_CTX *) vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL) 
    {
        size_t sz = digiprov_kdf_hkdf_size(ctx);

        if (sz == 0)
            return 0;
        return OSSL_PARAM_set_size_t(p, sz);
    }
    return -2;
}

static const OSSL_PARAM *digiprov_kdf_hkdf_gettable_ctx_params(ossl_unused void *ctx,
                                                               ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
    {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return digiprov_known_gettable_ctx_params;
}

const OSSL_DISPATCH digiprov_hmac_kdf_functions[] = 
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void))digiprov_kdf_hkdf_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void))digiprov_kdf_hkdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void))digiprov_kdf_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void))digiprov_kdf_hkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_kdf_hkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void))digiprov_kdf_hkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_kdf_hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void))digiprov_kdf_hkdf_get_ctx_params },
    { 0, NULL }
};

#if 0
Part of TLS version that was inadvertently modified for digiprov 
static int digiprov_kdf_tls1_3_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    DP_HKDF_CTX *ctx = vctx;

    if (params == NULL)
        return 1;

    if (!hkdf_common_set_ctx_params(ctx, params))
        return 0;

    if (ctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX)) != NULL) 
    {
        if (NULL != ctx->prefix)
            (void) DIGI_MEMSET_FREE(&ctx->prefix, ctx->prefix_len);

        if (!digiprov_get_octet_string(p, (void **)&ctx->prefix, 0, &ctx->prefix_len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL)) != NULL) 
    {
        if (NULL != ctx->label)
            (void) DIGI_MEMSET_FREE(&ctx->label, ctx->label_len);

        if (!digiprov_get_octet_string(p, (void **)&ctx->label, 0, &ctx->label_len))
            return 0;
    }

  /* why is this always freed? */
    (void) DIGI_MEMSET_FREE(&ctx->data, ctx->data_len);

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA)) != NULL
          && !digiprov_get_octet_string(p, (void **)&ctx->data, 0, &ctx->data_len))
        return 0;

    return 1;
}

static const OSSL_PARAM *digiprov_kdf_tls1_3_settable_ctx_params(ossl_unused void *ctx,
                                                                 ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        HKDF_COMMON_SETTABLES,
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

const OSSL_DISPATCH digiprov_hmac_kdf_functions[] = 
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void))digiprov_kdf_hkdf_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void))digiprov_kdf_hkdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void))digiprov_kdf_hkdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void))digiprov_kdf_tls1_3_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_kdf_tls1_3_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void))digiprov_kdf_tls1_3_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_kdf_hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void))digiprov_kdf_hkdf_get_ctx_params },
    { 0, NULL }
};
#endif
