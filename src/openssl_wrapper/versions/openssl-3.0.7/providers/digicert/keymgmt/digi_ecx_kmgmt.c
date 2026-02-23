/*
 * digi_ecx_keymgmt.c
 *
 * ECDSA/DH keygen implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
 * Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
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

#include "crypto/bn.h"
#include "crypto/ecx.h"

#include "internal/param_build_set.h"

#define ECX_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

struct dp_ecx_gen_ctx 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    ECX_KEY_TYPE type;
    int selection;
};

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);

static int digiprov_ecx_gen_set_params(void *genctx, const OSSL_PARAM params[]);

static ECX_KEY *digiprov_ecx_key_new(OSSL_LIB_CTX *libctx, ECX_KEY_TYPE type, int haspubkey, const char *propq)
{
    MSTATUS status = OK;
    ECX_KEY *ret = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &ret, 1, sizeof(ECX_KEY));
    if (OK != status)
        return NULL;

    ret->libctx = libctx;
    ret->haspubkey = haspubkey;
    switch (type) {
    case ECX_KEY_TYPE_X25519:
        ret->keylen = X25519_KEYLEN;
        break;
    case ECX_KEY_TYPE_X448:
        ret->keylen = X448_KEYLEN;
        break;
    case ECX_KEY_TYPE_ED25519:
        ret->keylen = ED25519_KEYLEN;
        break;
    case ECX_KEY_TYPE_ED448:
        ret->keylen = ED448_KEYLEN;
        break;
    }
    ret->type = type;
    ret->references = 1;

    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &ret->propq, propq);
        if (OK != status)
            goto err;
    }

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL)
        goto err;
    return ret;
err:
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    (void) DIGI_FREE((void **) &ret);
    return NULL;
}

static void *digiprov_x25519_new_key(void *provctx)
{
    return digiprov_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_X25519, 0, NULL);
}

static void *digiprov_x448_new_key(void *provctx)
{
    return digiprov_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_X448, 0, NULL);
}

static void *digiprov_ed25519_new_key(void *provctx)
{
    return digiprov_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_ED25519, 0, NULL);
}

static void *digiprov_ed448_new_key(void *provctx)
{
    return digiprov_ecx_key_new(PROV_LIBCTX_OF(provctx), ECX_KEY_TYPE_ED448, 0, NULL);
}

extern void digiprov_ecx_key_free(ECX_KEY *key)
{
    int i = 0;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i, key->lock);
    REF_PRINT_COUNT("ECX_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    (void) DIGI_FREE((void **)&key->propq);
    (void) DIGI_MEMSET_FREE((ubyte **) &key->privkey, key->keylen);
    
    CRYPTO_THREAD_lock_free(key->lock);
    (void) DIGI_FREE((void **) &key);
}

static int digiprov_ecx_has(const void *keydata, int selection)
{
    const ECX_KEY *key = keydata;
    int ok = 0;

    if (!digiprov_is_running())
        return 0;

    if (key != NULL) {
        /*
         * ECX keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->haspubkey;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->privkey != NULL;
    }
    return ok;
}

static int digiprov_ecx_match(const void *keydata1, const void *keydata2, int selection)
{
    const ECX_KEY *key1 = keydata1;
    const ECX_KEY *key2 = keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && key1->type == key2->type;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const unsigned char *pa = key1->haspubkey ? key1->pubkey : NULL;
            const unsigned char *pb = key2->haspubkey ? key2->pubkey : NULL;
            size_t pal = key1->keylen;
            size_t pbl = key2->keylen;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->type == key2->type
                    && pal == pbl
                    && CRYPTO_memcmp(pa, pb, pal) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const unsigned char *pa = key1->privkey;
            const unsigned char *pb = key2->privkey;
            size_t pal = key1->keylen;
            size_t pbl = key2->keylen;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->type == key2->type
                    && pal == pbl
                    && CRYPTO_memcmp(pa, pb, pal) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    return ok;
}

static int digiprov_ecx_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    ECX_KEY *key = keydata;
    int ok = 1;
    int include_private;

    if (!digiprov_is_running())
        return 0;
    
    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    ok = ok && ossl_ecx_key_fromdata(key, params, include_private);

    return ok;
}

static int digiprov_key_to_params(ECX_KEY *key, OSSL_PARAM_BLD *tmpl, OSSL_PARAM params[], int include_private)
{
    if (key == NULL)
        return 0;

    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           key->pubkey, key->keylen))
        return 0;

    if (include_private
        && key->privkey != NULL
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->privkey, key->keylen))
        return 0;

    return 1;
}

static int digiprov_ecx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    ECX_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;
    
    if (key == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

        if (!digiprov_key_to_params(key, tmpl, NULL, include_private))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

#define ECX_KEY_TYPES()                                                        \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                     \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM ecx_key_types[] = {
    ECX_KEY_TYPES(),
    OSSL_PARAM_END
};
static const OSSL_PARAM *digiprov_ecx_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ecx_key_types;
    return NULL;
}

static int digiprov_ecx_get_params(void *key, OSSL_PARAM params[], int bits, int secbits, int size)
{
    ECX_KEY *ecx = key;
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, secbits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, size))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL
            && (ecx->type == ECX_KEY_TYPE_X25519
                || ecx->type == ECX_KEY_TYPE_X448)) {
        if (!OSSL_PARAM_set_octet_string(p, ecx->pubkey, ecx->keylen))
            return 0;
    }

    return digiprov_key_to_params(ecx, NULL, params, 1);
}

static int digiprov_ed_get_params(void *key, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    return 1;
}

static int digiprov_x25519_get_params(void *key, OSSL_PARAM params[])
{
    return digiprov_ecx_get_params(key, params, X25519_BITS, X25519_SECURITY_BITS,
                          X25519_KEYLEN);
}

static int digiprov_x448_get_params(void *key, OSSL_PARAM params[])
{
    return digiprov_ecx_get_params(key, params, X448_BITS, X448_SECURITY_BITS,
                          X448_KEYLEN);
}

static int digiprov_ed25519_get_params(void *key, OSSL_PARAM params[])
{
    return digiprov_ecx_get_params(key, params, ED25519_BITS, ED25519_SECURITY_BITS,
                          ED25519_SIGSIZE)
        && digiprov_ed_get_params(key, params);
}

static int digiprov_ed448_get_params(void *key, OSSL_PARAM params[])
{
    return digiprov_ecx_get_params(key, params, ED448_BITS, ED448_SECURITY_BITS,
                          ED448_SIGSIZE)
        && digiprov_ed_get_params(key, params);
}

static const OSSL_PARAM digiprov_ecx_gettable_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    ECX_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM digiprov_ed_gettable_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    ECX_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_x25519_gettable_params(void *provctx)
{
    return digiprov_ecx_gettable_params;
}

static const OSSL_PARAM *digiprov_x448_gettable_params(void *provctx)
{
    return digiprov_ecx_gettable_params;
}

static const OSSL_PARAM *digiprov_ed25519_gettable_params(void *provctx)
{
    return digiprov_ed_gettable_params;
}

static const OSSL_PARAM *digiprov_ed448_gettable_params(void *provctx)
{
    return digiprov_ed_gettable_params;
}

static int digiprov_set_property_query(ECX_KEY *ecxkey, const char *propq)
{
    MSTATUS status = OK;

    if (NULL == ecxkey)
        return 0;

    if (NULL != ecxkey->propq)
    {
        status = DIGI_FREE((void **) &ecxkey->propq);
        if (OK != status)
            return 0;
    }

    if (propq != NULL) 
    {
        status = digiprov_strdup((void **) &ecxkey->propq, propq);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int digiprov_ecx_set_params(void *key, const OSSL_PARAM params[])
{
    ECX_KEY *ecxkey = key;
    const OSSL_PARAM *p = NULL;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        void *buf = ecxkey->pubkey;

        if (p->data_size != ecxkey->keylen
                || !digiprov_get_octet_string(p, &buf, sizeof(ecxkey->pubkey), NULL))
            return 0;
        (void) DIGI_MEMSET_FREE((ubyte **) &ecxkey->privkey, ecxkey->keylen);
        ecxkey->privkey = NULL;
        ecxkey->haspubkey = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || !digiprov_set_property_query(ecxkey, p->data))
            return 0;
    }

    return 1;
}

static int digiprov_x25519_set_params(void *key, const OSSL_PARAM params[])
{
    return digiprov_ecx_set_params(key, params);
}

static int digiprov_x448_set_params(void *key, const OSSL_PARAM params[])
{
    return digiprov_ecx_set_params(key, params);
}

static int digiprov_ed25519_set_params(void *key, const OSSL_PARAM params[])
{
    return 1;
}

static int digiprov_ed448_set_params(void *key, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM ecx_settable_params[] = 
{
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM ed_settable_params[] = 
{
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_x25519_settable_params(void *provctx)
{
    return ecx_settable_params;
}

static const OSSL_PARAM *digiprov_x448_settable_params(void *provctx)
{
    return ecx_settable_params;
}

static const OSSL_PARAM *digiprov_ed25519_settable_params(void *provctx)
{
    return ed_settable_params;
}

static const OSSL_PARAM *digiprov_ed448_settable_params(void *provctx)
{
    return ed_settable_params;
}

static void *digiprov_ecx_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[], ECX_KEY_TYPE type)
{
    MSTATUS status = OK;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct dp_ecx_gen_ctx *gctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &gctx, 1, sizeof(*gctx));
    if (OK != status)
        return NULL;

    gctx->libctx = libctx;
    gctx->type = type;
    gctx->selection = selection;

    if (!digiprov_ecx_gen_set_params(gctx, params)) {
        (void) DIGI_FREE((void **) &gctx);
        gctx = NULL;
    }
    return gctx;
}

static void *digiprov_x25519_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[])
{
    return digiprov_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X25519);
}

static void *digiprov_x448_gen_init(void *provctx, int selection,
                           const OSSL_PARAM params[])
{
    return digiprov_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X448);
}

static void *digiprov_ed25519_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[])
{
    return digiprov_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_ED25519);
}

static void *digiprov_ed448_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    return digiprov_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_ED448);
}

static int digiprov_ecx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    struct dp_ecx_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *groupname = NULL;

        /*
         * We optionally allow setting a group name - but each algorithm only
         * support one such name, so all we do is verify that it is the one we
         * expected.
         */
        switch (gctx->type) {
            case ECX_KEY_TYPE_X25519:
                groupname = "x25519";
                break;
            case ECX_KEY_TYPE_X448:
                groupname = "x448";
                break;
            default:
                /* We only support this for key exchange at the moment */
                break;
        }
        if (p->data_type != OSSL_PARAM_UTF8_STRING
                || groupname == NULL
                || OPENSSL_strcasecmp(p->data, groupname) != 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        (void) DIGI_FREE((void **) &gctx->propq);
        status = digiprov_strdup((void **) &gctx->propq, p->data);
        if (OK != status)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *digiprov_ecx_gen_settable_params(ossl_unused void *genctx,
                                                          ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = 
    {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *digiprov_ecx_gen(struct dp_ecx_gen_ctx *gctx, ubyte4 curveId)
{
    MSTATUS status = OK;
    ECX_KEY *key = NULL;
    ECCKey *pKey = NULL;
    MEccKeyTemplate template = {0};

    if (!digiprov_is_running())
        return NULL;
    
    if (gctx == NULL)
        return NULL;

    if ((key = digiprov_ecx_key_new(gctx->libctx, gctx->type, 0, gctx->propq)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    status = DIGI_MALLOC((void **) &key->privkey, key->keylen);
    if (OK != status)
        goto exit;
        
    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(curveId, (void **) &pKey, DIGI_EVP_RandomRngFun, NULL,
                                                      akt_ecc, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(pKey, &template, MOC_GET_PRIVATE_KEY_DATA);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) key->privkey, template.pPrivateKey, template.privateKeyLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) key->pubkey, template.pPublicKey, template.publicKeyLen);
    if (OK != status)
        goto exit;

    key->haspubkey = 1;

exit:

    (void) CRYPTO_INTERFACE_EC_freeKeyTemplateAux(pKey, &template);

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
    }

    if (OK != status && NULL != key)
    {
        digiprov_ecx_key_free(key);
        key = NULL;
    }

    return key;
}

static void *digiprov_x25519_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct dp_ecx_gen_ctx *gctx = genctx;
    return digiprov_ecx_gen(gctx, cid_EC_X25519);
}

static void *digiprov_x448_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct dp_ecx_gen_ctx *gctx = genctx;
    return digiprov_ecx_gen(gctx, cid_EC_X448);
}

static void *digiprov_ed25519_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct dp_ecx_gen_ctx *gctx = genctx;
    return digiprov_ecx_gen(gctx, cid_EC_Ed25519);
}

static void *digiprov_ed448_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct dp_ecx_gen_ctx *gctx = genctx;
    return digiprov_ecx_gen(gctx, cid_EC_Ed448);
}

static void digiprov_ecx_gen_cleanup(void *genctx)
{
    struct dp_ecx_gen_ctx *gctx = genctx;

    DIGI_FREE((void **) &gctx->propq);
    DIGI_FREE((void **) &gctx);
}

void *digiprov_ecx_load(const void *reference, size_t reference_sz)
{
    ECX_KEY *key = NULL;

    if (digiprov_is_running() && reference_sz == sizeof(key))
    {
        /* The contents of the reference is the address to our object */
        key = *(ECX_KEY **)reference;
        /* We grabbed, so we detach it */
        *(ECX_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *digiprov_ecx_dup(const void *keydata_from, int selection)
{
    MSTATUS status = OK;
    ECX_KEY *key = (ECX_KEY *) keydata_from;
    ECX_KEY *ret = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &ret, 1, sizeof(ECX_KEY));
    if (OK != status)
        goto exit;

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) 
    {
        status = ERR_GENERAL;
        goto exit;
    }

    ret->libctx = key->libctx;
    ret->haspubkey = key->haspubkey;
    ret->keylen = key->keylen;
    ret->type = key->type;
    ret->references = 1;

    if (key->propq != NULL) 
    {
        status = digiprov_strdup((void **) &ret->propq, key->propq);
        if (OK != status)
            goto exit;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        (void) DIGI_MEMCPY(ret->pubkey, key->pubkey, sizeof(ret->pubkey));

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && NULL != key->privkey) 
    {
        status = DIGI_MALLOC((void **) &ret->privkey, ret->keylen);
        if (OK != status)
            goto exit;

        (void) DIGI_MEMCPY(ret->privkey, key->privkey, ret->keylen);
    }

exit:
    
    if (OK != status && ret != NULL)
    {
        digiprov_ecx_key_free(ret);
        ret = NULL;
    }

    return (void *) ret;
}

static int digiprov_ecx_key_pairwise_check(const ECX_KEY *ecx, int type)
{
    MSTATUS status = OK;
    ubyte4 curveId = 0;
    ECCKey *pKey = NULL;
    byteBoolean vfy = FALSE;
    int ret = 0;

    switch (type) 
    {
    case ECX_KEY_TYPE_X25519:
        curveId = cid_EC_X25519;
        break;
    case ECX_KEY_TYPE_X448:
        curveId = cid_EC_X448;
        break;
    case ECX_KEY_TYPE_ED25519:
        curveId = cid_EC_Ed25519;
        break;
    case ECX_KEY_TYPE_ED448:
        curveId = cid_EC_Ed448;
        break;
    default:
        return 0;
    }

    status = CRYPTO_INTERFACE_EC_newKeyAux (curveId, &pKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pKey, (ubyte *) ecx->pubkey, (ubyte4) ecx->keylen, 
                                                     (ubyte *) ecx->privkey, (ubyte4) ecx->keylen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_verifyKeyPairAux (pKey, NULL, &vfy);
    if (OK != status)
        goto exit;

    if (TRUE == vfy)
        ret = 1;
    else
        ret = 0;

exit:
    
    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux (&pKey);
    }

    return ret;
}

static int digiprov_ecx_validate(const void *keydata, int selection, int type, size_t keylen)
{
    const ECX_KEY *ecx = keydata;
    int ok = keylen == ecx->keylen;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & ECX_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    if (!ok) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && ecx->haspubkey;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && ecx->privkey != NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && digiprov_ecx_key_pairwise_check(ecx, type);

    return ok;
}

static int digiprov_x25519_validate(const void *keydata, int selection, int checktype)
{
    return digiprov_ecx_validate(keydata, selection, ECX_KEY_TYPE_X25519, X25519_KEYLEN);
}

static int digiprov_x448_validate(const void *keydata, int selection, int checktype)
{
    return digiprov_ecx_validate(keydata, selection, ECX_KEY_TYPE_X448, X448_KEYLEN);
}

static int digiprov_ed25519_validate(const void *keydata, int selection, int checktype)
{
    return digiprov_ecx_validate(keydata, selection, ECX_KEY_TYPE_ED25519, ED25519_KEYLEN);
}

static int digiprov_ed448_validate(const void *keydata, int selection, int checktype)
{
    return digiprov_ecx_validate(keydata, selection, ECX_KEY_TYPE_ED448, ED448_KEYLEN);
}

#define MAKE_KEYMGMT_FUNCTIONS(alg) \
    const OSSL_DISPATCH digiprov_##alg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_##alg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_ecx_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_##alg##_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_##alg##_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,          (void (*)(void))digiprov_##alg##_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,     (void (*)(void))digiprov_##alg##_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_ecx_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_ecx_match }, \
        { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_##alg##_validate }, \
        { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_ecx_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_ecx_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_ecx_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_ecx_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_##alg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_ecx_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_##ecx_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_##alg##_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_ecx_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_ecx_load }, \
        { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_ecx_dup }, \
        { 0, NULL } \
    };



MAKE_KEYMGMT_FUNCTIONS(x25519)
MAKE_KEYMGMT_FUNCTIONS(x448)
MAKE_KEYMGMT_FUNCTIONS(ed25519)
MAKE_KEYMGMT_FUNCTIONS(ed448)
