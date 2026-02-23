/*
 * digi_cmac.c
 *
 * CMAC implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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

/*
 * CMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/aes.h"
#include "../../../src/crypto/aes_cmac.h"

#include "../../../src/crypto_interface/crypto_interface_aes_cmac.h"

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

/* local CMAC data */

typedef struct cmac_data_st 
{
    AESCMAC_Ctx *ctx;
    ubyte *key;
    ubyte4 keylen;
    size_t outSize;
    size_t blockSize;

} DP_CMAC_CTX;

static int digiprov_cmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[]);

static void *digiprov_cmac_new(void *provctx)
{
    MSTATUS status = OK;
    DP_CMAC_CTX *macctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &macctx, 1, sizeof(DP_CMAC_CTX));
    if (OK != status)
        return NULL;

    status = DIGI_CALLOC((void **) &macctx->ctx, 1, sizeof(AESCMAC_Ctx));
    if (OK != status)
    {
        (void) DIGI_FREE((void **) &macctx);
        return NULL;
    }

    macctx->outSize = CMAC_RESULT_SIZE;
    macctx->blockSize = AES_BLOCK_SIZE;
    return macctx;
}

static void digiprov_cmac_free(void *vmacctx)
{
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *)vmacctx;

    if (NULL != macctx) 
    {
        if (NULL != macctx->key)
        {
            (void) DIGI_MEMSET_FREE((ubyte **) &macctx->key, macctx->keylen);
        }

        if (NULL != macctx->ctx)
        {
            /* AESCMAC_final may have not been called, still need to call to free memory */
            (void) CRYPTO_INTERFACE_AESCMAC_clear(macctx->ctx);
            (void) DIGI_MEMSET_FREE((ubyte **) &macctx->ctx, sizeof(AESCMAC_Ctx));
        }
        
        (void) DIGI_FREE((void **) &macctx);
    }
}

static void *digiprov_cmac_dup(void *vsrc)
{
    MSTATUS status = OK;
    DP_CMAC_CTX *dst = NULL;
    DP_CMAC_CTX *src = (DP_CMAC_CTX *) vsrc;

    if (!digiprov_is_running())
        return NULL;

    if (NULL == src)
        return NULL;

    dst = digiprov_cmac_new(NULL);
    if (NULL == dst)
        return NULL;

    /* new allocated the inner poly1305 ctx too */
    status = CRYPTO_INTERFACE_AESCMAC_cloneCtx(dst->ctx, src->ctx);
    if (OK != status)
    {
        digiprov_cmac_free(dst); /* frees the inner AESCmac_Ctx too */
        dst = NULL;
        return NULL;
    }

    /* and copy the key */
    if (src->keylen > 0 && NULL != src->key)
    {
        status = DIGI_MALLOC((void **) &dst->key, src->keylen);
        if (OK != status)
        {
            digiprov_cmac_free(dst);
            dst = NULL;
            return NULL;
        }

        (void) DIGI_MEMCPY(dst->key, src->key, src->keylen);
    }
   
    dst->outSize = src->outSize;
    dst->blockSize = src->blockSize;
    dst->keylen = src->keylen;

    return (void *) dst;
}

static int digiprov_cmac_setkey(DP_CMAC_CTX *macctx, const unsigned char *key, size_t keylen)
{
    MSTATUS status = OK;

    /* We only support AES-CBC. check the keylen */
    if (16 != keylen && 24 != keylen && 32 != keylen)
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

    return 1;
}

static int digiprov_cmac_init(void *vmacctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (!digiprov_cmac_set_ctx_params(macctx, params))
        return 0;
        
    if (key != NULL)
    {
        if (!digiprov_cmac_setkey(macctx, key, keylen))
            return 0;
    }

    status = CRYPTO_INTERFACE_AESCMAC_init(macctx->key, macctx->keylen, macctx->ctx);
    if (OK != status)
        return 0;
    
    return 1;
}

static int digiprov_cmac_update(void *vmacctx, const unsigned char *data, size_t datalen)
{
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *) vmacctx;

    if (OK == CRYPTO_INTERFACE_AESCMAC_update((ubyte *) data, (ubyte4) datalen, macctx->ctx))
        return 1;

    return 0;
}

static int digiprov_cmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (outsize < macctx->outSize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (OK == CRYPTO_INTERFACE_AESCMAC_final(out, macctx->ctx))
    {
        *outl = macctx->outSize;
        return 1;
    }
    
    return 0;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
{
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_cmac_gettable_ctx_params(ossl_unused void *ctx,
                                                           ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_cmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *) vmacctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, macctx->outSize))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, macctx->blockSize))
        return 0;

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] = 
{
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_cmac_settable_ctx_params(ossl_unused void *ctx,
                                                           ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int digiprov_cmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    DP_CMAC_CTX *macctx = (DP_CMAC_CTX *) vmacctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER)) != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        /* We only support AES-CBC mode */
        if (!(0 == DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "AES-128-CBC") || 
              0 == DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "AES-192-CBC") || 
              0 == DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "AES-256-CBC")))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        return digiprov_cmac_setkey(macctx, p->data, p->data_size);
    }

    return 1;
}

const OSSL_DISPATCH digiprov_cmac_functions[] = 
{
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))digiprov_cmac_new },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))digiprov_cmac_dup },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))digiprov_cmac_free },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))digiprov_cmac_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))digiprov_cmac_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))digiprov_cmac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_cmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void (*)(void))digiprov_cmac_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_cmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))digiprov_cmac_set_ctx_params },
    { 0, NULL }
};
