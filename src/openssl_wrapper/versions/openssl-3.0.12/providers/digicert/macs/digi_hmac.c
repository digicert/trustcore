
/*
 * digi_hmac.c
 *
 * HMAC implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
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

#define HMAC_CTX HMAC_CTX_OSSL
#include "mocana_glue.h"
#include "digicert_common.h"
#undef HMAC_CTX

#include "../../../src/crypto/hmac.h"
#include "../../../src/crypto_interface/crypto_interface_hmac.h"

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

/* local HMAC context structure */

/* typedef EVP_MAC_IMPL */
typedef struct hmac_data_st 
{
    void *provctx;
    HMAC_CTX *ctx;               /* HMAC context */
    BulkHashAlgo *pBHAlgo;
    unsigned char *key;
    size_t keylen;
    size_t outSize;
    size_t blockSize;

    /* Length of full TLS record including the MAC and any padding */
    size_t tls_data_size;
    unsigned char tls_header[13];
    int tls_header_set;
    unsigned char tls_mac_out[EVP_MAX_MD_SIZE];
    size_t tls_mac_out_size;

} DP_HMAC_CTX;

static int digiprov_hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[]);

/* Defined in ssl/s3_cbc.c  NOT SUPPORTED
int ssl3_cbc_digest_record(const EVP_MD *md,
                           unsigned char *md_out,
                           size_t *md_out_size,
                           const unsigned char header[13],
                           const unsigned char *data,
                           size_t data_size,
                           size_t data_plus_mac_plus_padding_size,
                           const unsigned char *mac_secret,
                           size_t mac_secret_length, char is_sslv3);
*/

static void *digiprov_hmac_new(void *provctx)
{
    MSTATUS status = OK;
    DP_HMAC_CTX *macctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &macctx, 1, sizeof(DP_HMAC_CTX));
    if (OK != status)
        return NULL;

    macctx->provctx = provctx;
    return (void *) macctx;
}

static void digiprov_hmac_free(void *vmacctx)
{
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;

    if (NULL != macctx) 
    {
        if (NULL != macctx->key)
        {
            (void) DIGI_MEMSET_FREE((ubyte **) &macctx->key, macctx->keylen);
        }

        if (NULL != macctx->ctx)
        {
            (void) CRYPTO_INTERFACE_HmacDelete(&macctx->ctx);
        }

        (void) DIGI_MEMSET_FREE((ubyte **) &macctx, sizeof(DP_HMAC_CTX));
    }
}

static void *digiprov_hmac_dup(void *vsrc)
{
    MSTATUS status = OK;
    DP_HMAC_CTX *dst = NULL;
    DP_HMAC_CTX *src = (DP_HMAC_CTX *) vsrc;

    if (!digiprov_is_running())
        return NULL;

    if (NULL == src)
        return NULL;

    dst = digiprov_hmac_new(NULL);
    if (NULL == dst)
        return NULL;

    (void) DIGI_MEMCPY((void *) dst, (void *) src, sizeof(DP_HMAC_CTX));
    dst->ctx = NULL; /* zero pointers, we'll copy new objects there */
    dst->key = NULL;
  
    status = CRYPTO_INTERFACE_HmacCloneCtx(&dst->ctx, src->ctx);
    if (OK != status)
    {
        digiprov_hmac_free(dst);
        dst = NULL;
        return NULL;
    }
    
    /* and copy the key */

    /* allocate 1 extra byte to empty key, now non-NULL, is different from undefined key */
    status = DIGI_MALLOC((void **) &dst->key, src->keylen + 1);
    if (OK != status)
    {
        digiprov_hmac_free(dst); /* will delete inner HMAC_CTX too */
        dst = NULL;
        return NULL;
    }

    if (src->keylen > 0)
    {
        (void) DIGI_MEMCPY(dst->key, src->key, src->keylen);
    }
    dst->key[src->keylen] = 0;

    return (void *) dst;
}

static int digiprov_hmac_setkey(DP_HMAC_CTX *macctx, const unsigned char *key, size_t keylen)
{
    MSTATUS status = OK;

    if (macctx->key != NULL)
    {
        status = DIGI_MEMSET_FREE(&macctx->key, macctx->keylen);
        if (OK != status)
            return 0;
    }

    /* allocate 1 extra byte to empty key, now non-NULL, is different from undefined key */
    status = DIGI_MALLOC((void **) &macctx->key, keylen + 1);
    if (OK != status)
        return 0;

    if (keylen > 0)
    {
        status = DIGI_MEMCPY(macctx->key, key, keylen);
        if (OK != status)
        {
            (void) DIGI_FREE((void **) &macctx->key);
            return 0;
        }
    }
    macctx->key[keylen] = 0;
    macctx->keylen = keylen;

    return 1;
}

static int digiprov_hmac_init(void *vmacctx, const unsigned char *key,
                              size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

    if (!digiprov_hmac_set_ctx_params(macctx, params))
        return 0;
        
    if (key != NULL)
    {
        if (!digiprov_hmac_setkey(macctx, key, keylen))
            return 0;
    }

    status = CRYPTO_INTERFACE_HmacKey(macctx->ctx, macctx->key, (ubyte4) macctx->keylen);
    if (OK != status)
        return 0;
    
    return 1;
}

static int digiprov_hmac_update(void *vmacctx, const unsigned char *data, size_t datalen)
{
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;

    if (macctx->tls_data_size > 0) 
        return 0;  /* not supported yet */
#if 0
    {
        /* We're doing a TLS HMAC */
        if (!macctx->tls_header_set) {
            /* We expect the first update call to contain the TLS header */
            if (datalen != sizeof(macctx->tls_header))
                return 0;
            memcpy(macctx->tls_header, data, datalen);
            macctx->tls_header_set = 1;
            return 1;
        }
        /* macctx->tls_data_size is datalen plus the padding length */
        if (macctx->tls_data_size < datalen)
            return 0;

        return ssl3_cbc_digest_record(ossl_prov_digest_md(&macctx->digest),
                                      macctx->tls_mac_out,
                                      &macctx->tls_mac_out_size,
                                      macctx->tls_header,
                                      data,
                                      datalen,
                                      macctx->tls_data_size,
                                      macctx->key,
                                      macctx->keylen,
                                      0);
    }
#endif

    if (OK == CRYPTO_INTERFACE_HmacUpdate (macctx->ctx, data, (ubyte4) datalen))
        return 1;

    return 0;
}

static int digiprov_hmac_final(void *vmacctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;

    if (!digiprov_is_running())
        return 0;

#if 0
    if (macctx->tls_data_size > 0) {
        if (macctx->tls_mac_out_size == 0)
            return 0;
        if (outl != NULL)
            *outl = macctx->tls_mac_out_size;
        memcpy(out, macctx->tls_mac_out, macctx->tls_mac_out_size);
        return 1;
    }
#endif

    if (outsize < macctx->outSize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (OK == CRYPTO_INTERFACE_HmacFinal(macctx->ctx, out))
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
static const OSSL_PARAM *digiprov_hmac_gettable_ctx_params(ossl_unused void *ctx,
                                                           ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_hmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, macctx->outSize))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) != NULL
            && !OSSL_PARAM_set_int(p, macctx->blockSize))
        return 0;

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
{
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
    OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_hmac_settable_ctx_params(ossl_unused void *ctx,
                                                           ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

static int digiprov_hmac_get_digest_data(const char *pMdname, DP_HMAC_CTX *macctx)
{
    MSTATUS status = OK;
    ubyte4 outSize = 0;
    ubyte4 blockSize = 0;

    status = digiprov_get_digest_data(pMdname, &macctx->pBHAlgo, &outSize, &blockSize);
    if (OK != status)
        return 0;

    macctx->outSize = (size_t) outSize;
    macctx->blockSize = (size_t) blockSize;

    /* set the new ctx, delete any previous one */
    if (NULL != macctx->ctx)
    {
        status = CRYPTO_INTERFACE_HmacDelete(&macctx->ctx);
        if (OK != status)
            return 0;
    }

    status = CRYPTO_INTERFACE_HmacCreate (&macctx->ctx, macctx->pBHAlgo);
    if (OK != status)
        return 0;

    return 1;
}

/*
 * ALL parameters should be set before init().
 */
static int digiprov_hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    DP_HMAC_CTX *macctx = (DP_HMAC_CTX *) vmacctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST)) != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (!digiprov_hmac_get_digest_data(p->data, macctx))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!digiprov_hmac_setkey(macctx, p->data, p->data_size))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_TLS_DATA_SIZE)) != NULL) 
    {
        return 0;
        /* not supported
        if (!OSSL_PARAM_get_size_t(p, &macctx->tls_data_size))
            return 0; */
    }

    return 1;
}

const OSSL_DISPATCH digiprov_hmac_functions[] =
{
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))digiprov_hmac_new },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))digiprov_hmac_dup },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))digiprov_hmac_free },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))digiprov_hmac_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))digiprov_hmac_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))digiprov_hmac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_hmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void (*)(void))digiprov_hmac_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_hmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))digiprov_hmac_set_ctx_params },
    { 0, NULL }
};
