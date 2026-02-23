/*
 * digi_blake2_mac.c
 *
 * Blake2 implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/blake2.h"

#include "../../../src/crypto_interface/crypto_interface_blake2.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/proverr.h"
#include "openssl/err.h"
#include "openssl/core_names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

typedef struct blake2_mac_data_st 
{
    BLAKE2_CTX *ctx;
    unsigned char key[BLAKE2_KEYBYTES];
    size_t keylen;
    size_t outSize;

} DP_BLAKE2_CTX;

static void digiprov_blake2_mac_free(void *vmacctx);
static int digiprov_blake2_mac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[]);

static void *digiprov_blake2_mac_new(void *unused_provctx)
{
    MSTATUS status = OK;
    DP_BLAKE2_CTX *macctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &macctx, 1, sizeof(*macctx));
    if (OK != status)
        return NULL;

    status = CRYPTO_INTERFACE_BLAKE_alloc((BulkCtx *) &macctx->ctx);
    if (OK != status)
    {
        (void) DIGI_FREE((void **) &macctx);
        return NULL;
    }

    macctx->outSize = BLAKE2_OUTBYTES; /* set default */
    return macctx;
}

static void *digiprov_blake2_mac_dup(void *vsrc)
{
    MSTATUS status = OK;
    DP_BLAKE2_CTX *dst = NULL;
    DP_BLAKE2_CTX *src = (DP_BLAKE2_CTX *) vsrc;

    if (!digiprov_is_running())
        return NULL;

    if (NULL == src)
        return NULL;

    dst = digiprov_blake2_mac_new(NULL);
    if (NULL == dst)
        return NULL;

    (void) DIGI_MEMCPY(dst->key, src->key, BLAKE2_KEYBYTES);
    
    status = CRYPTO_INTERFACE_BLAKE_cloneCtx(dst->ctx, src->ctx);
    if (OK != status)
    {
        digiprov_blake2_mac_free(dst);
        return NULL;
    }

    dst->keylen = src->keylen;
    dst->outSize = src->outSize;

    return (void *) dst;
}

static void digiprov_blake2_mac_free(void *vmacctx)
{
    DP_BLAKE2_CTX *macctx = vmacctx;

    if (macctx != NULL) 
    {
        (void) DIGI_MEMSET((ubyte *) macctx->key, 0x00, sizeof(macctx->key));
        if (NULL != macctx->ctx)
        {
            (void) CRYPTO_INTERFACE_BLAKE_delete((BulkCtx *)&macctx->ctx);
        }

        (void) DIGI_FREE((void **) &macctx);
    }
}

static int digiprov_blake2_setkey(DP_BLAKE2_CTX *macctx, const unsigned char *key, size_t keylen)
{
    MSTATUS status = OK;

    if (keylen > BLAKE2_KEYBYTES || keylen == 0) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    status = DIGI_MEMCPY((ubyte *) macctx->key, key, keylen);
    if (OK != status)
        return 0;

    /* Pad with zeroes at the end if required */
    if (keylen < BLAKE2_KEYBYTES)
    {
        (void) DIGI_MEMSET(macctx->key + keylen, 0x00, BLAKE2_KEYBYTES - keylen);
    }

    macctx->keylen = keylen;
    return 1;
}

static int digiprov_blake2_mac_init(void *vmacctx, const unsigned char *key,
                                    size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_BLAKE2_CTX *macctx = (DP_BLAKE2_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (!digiprov_blake2_mac_set_ctx_params(macctx, params))
        return 0;
        
    if (key != NULL)
    {
        if (!digiprov_blake2_setkey(macctx, key, keylen))
            return 0;
    }
    else if (0 == macctx->keylen)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    status = CRYPTO_INTERFACE_BLAKE_init(macctx->ctx, (ubyte4) macctx->outSize, macctx->key, (ubyte4) macctx->keylen);
    if (OK != status)
        return 0;

    return 1;
}

static int digiprov_blake2_mac_update(void *vmacctx, const unsigned char *data, size_t datalen)
{
    DP_BLAKE2_CTX *macctx = (DP_BLAKE2_CTX *) vmacctx;

    if (datalen == 0)
        return 1;

    if (OK == CRYPTO_INTERFACE_BLAKE_update(macctx->ctx, (ubyte *) data, (ubyte4) datalen))
        return 1;

    return 0;
}

static int digiprov_blake2_mac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_BLAKE2_CTX *macctx = (DP_BLAKE2_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (outsize < macctx->outSize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (OK == CRYPTO_INTERFACE_BLAKE_final(macctx->ctx, out))
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

static const OSSL_PARAM *digiprov_blake2_gettable_ctx_params(ossl_unused void *ctx,
                                                             ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_blake2_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    DP_BLAKE2_CTX *macctx = (DP_BLAKE2_CTX *) vmacctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, macctx->outSize))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, BLAKE2_BLOCKBYTES))
        return 0;

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
{
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_CUSTOM, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_SALT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_blake2_mac_settable_ctx_params(
            ossl_unused void *ctx, ossl_unused void *p_ctx)
{
    return digiprov_known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int digiprov_blake2_mac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    DP_BLAKE2_CTX *macctx = vmacctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE)) != NULL)
    {
        size_t size;

        if (!OSSL_PARAM_get_size_t(p, &size) || size < 1 || size > BLAKE2_OUTBYTES) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_XOF_OR_INVALID_LENGTH);
            return 0;
        }
        macctx->outSize = size;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL
            && !digiprov_blake2_setkey(macctx, p->data, p->data_size))
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CUSTOM)) != NULL) 
    {   
        return 0;
        /*   NOT supported
         * The OSSL_PARAM API doesn't provide direct pointer use, so we
         * must handle the OSSL_PARAM structure ourselves here
         
        if (p->data_size > BLAKE2_PERSONALBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
            return 0;
        }
        BLAKE2_PARAM_SET_PERSONAL(&macctx->params, p->data, p->data_size);*/
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SALT)) != NULL)
    {
        return 0;
        /*  NOT supported
         * The OSSL_PARAM API doesn't provide direct pointer use, so we
         * must handle the OSSL_PARAM structure ourselves here as well
         
        if (p->data_size > BLAKE2_SALTBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }
        BLAKE2_PARAM_SET_SALT(&macctx->params, p->data, p->data_size); */
    }

    return 1;
}

const OSSL_DISPATCH BLAKE2_FUNCTIONS[] =
{
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))digiprov_blake2_mac_new },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))digiprov_blake2_mac_dup },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))digiprov_blake2_mac_free },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))digiprov_blake2_mac_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))digiprov_blake2_mac_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))digiprov_blake2_mac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_blake2_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void (*)(void))digiprov_blake2_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_blake2_mac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))digiprov_blake2_mac_set_ctx_params },
    { 0, NULL }
};
