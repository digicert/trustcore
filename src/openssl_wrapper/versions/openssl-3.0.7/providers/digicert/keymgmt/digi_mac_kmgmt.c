/*
 * digi_mac_keymgmt.c
 *
 * MAC keymgmt implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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

/* We need to use some deprecated APIs */
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

typedef struct _DP_MAC_GEN_CTX 
{
    OSSL_LIB_CTX *libctx;
    int selection;
    unsigned char *priv_key;
    size_t priv_key_len;
    PROV_CIPHER cipher;

} DP_MAC_GEN_CTX;

static int digiprov_mac_gen_set_params(void *genctx, const OSSL_PARAM params[]);
static int digiprov_cmac_gen_set_params(void *genctx, const OSSL_PARAM params[]);

static MAC_KEY *digiprov_mac_key_new(OSSL_LIB_CTX *libctx, int cmac)
{
    MSTATUS status = OK;
    MAC_KEY *mackey = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &mackey, 1, sizeof(MAC_KEY));
    if (OK != status)
        return NULL;

    mackey->lock = CRYPTO_THREAD_lock_new();
    if (mackey->lock == NULL) 
    {
        (void) DIGI_FREE((void **) &mackey);
        return NULL;
    }
    mackey->libctx = libctx;
    mackey->refcnt = 1;
    mackey->cmac = cmac;

    return mackey;
}

void digiprov_mac_key_free(MAC_KEY *mackey)
{
    int ref = 0;

    if (mackey == NULL)
        return;

    CRYPTO_DOWN_REF(&mackey->refcnt, &ref, mackey->lock);
    if (ref > 0)
        return;

    if (NULL != mackey)
    {
        (void) DIGI_MEMSET_FREE(&mackey->priv_key, mackey->priv_key_len);
    }

    if (NULL != mackey->properties)
    {
        (void) DIGI_FREE((void **)&mackey->properties);
    }

    ossl_prov_cipher_reset(&mackey->cipher);
    CRYPTO_THREAD_lock_free(mackey->lock);
    (void) DIGI_FREE((void **)&mackey);
}

/* not static, used in signer */
int digiprov_mac_key_up_ref(MAC_KEY *mackey)
{
    int ref = 0;

    /* This is effectively doing a new operation on the MAC_KEY and should be
     * adequately guarded again modules' error states.  However, both current
     * calls here are guarded propery in signature/mac_legacy.c.  Thus, it
     * could be removed here.  The concern is that something in the future
     * might call this function without adequate guards.  It's a cheap call,
     * it seems best to leave it even though it is currently redundant.
     */
    if (!digiprov_is_running())
        return 0;

    CRYPTO_UP_REF(&mackey->refcnt, &ref, mackey->lock);
    return 1;
}

static void *digiprov_mac_new(void *provctx)
{
    return digiprov_mac_key_new(PROV_LIBCTX_OF(provctx), 0);
}

static void *digiprov_mac_new_cmac(void *provctx)
{
    return digiprov_mac_key_new(PROV_LIBCTX_OF(provctx), 1);
}

static void digiprov_mac_free(void *mackey)
{
    digiprov_mac_key_free(mackey);
}

static int digiprov_mac_has(const void *keydata, int selection)
{
    const MAC_KEY *key = keydata;
    int ok = 0;

    if (digiprov_is_running() && key != NULL) {
        /*
         * MAC keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         * Similarly for public keys.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = key->priv_key != NULL;
    }
    return ok;
}

static int digiprov_mac_match(const void *keydata1, const void *keydata2, int selection)
{
    const MAC_KEY *key1 = keydata1;
    const MAC_KEY *key2 = keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if ((key1->priv_key == NULL && key2->priv_key != NULL)
                || (key1->priv_key != NULL && key2->priv_key == NULL)
                || key1->priv_key_len != key2->priv_key_len
                || (key1->cipher.cipher == NULL && key2->cipher.cipher != NULL)
                || (key1->cipher.cipher != NULL && key2->cipher.cipher == NULL))
            ok = 0;
        else
            ok = ok && (key1->priv_key == NULL /* implies key2->privkey == NULL */
                        || CRYPTO_memcmp(key1->priv_key, key2->priv_key,
                                         key1->priv_key_len) == 0);
        if (key1->cipher.cipher != NULL)
            ok = ok && EVP_CIPHER_is_a(key1->cipher.cipher,
                                       EVP_CIPHER_get0_name(key2->cipher.cipher));
    }
    return ok;
}

static int digiprov_mac_key_fromdata(MAC_KEY *key, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        
        if (NULL != key->priv_key)
        {
            (void) DIGI_MEMSET_FREE(&key->priv_key, key->priv_key_len);
            /* allocate at least one byte to distinguish empty key from no key set */
        }

        status = DIGI_MALLOC((void **) &key->priv_key, p->data_size > 0 ? p->data_size : 1);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (p->data_size > 0)
        {
            (void) DIGI_MEMCPY(key->priv_key, p->data, (ubyte4) p->data_size);
        }
        key->priv_key_len = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        if (NULL != key->properties)
        {
            (void) DIGI_FREE((void **) &key->properties);
        }
        status = digiprov_strdup((void **) &key->properties, (const char *) p->data);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (key->cmac && !ossl_prov_cipher_load_from_params(&key->cipher, params, key->libctx))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (key->priv_key != NULL)
        return 1;

    return 0;
}

static int digiprov_mac_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    MAC_KEY *key = keydata;

    if (!digiprov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 0;

    return digiprov_mac_key_fromdata(key, params);
}

static int digiprov_key_to_params(MAC_KEY *key, OSSL_PARAM_BLD *tmpl, OSSL_PARAM params[])
{
    if (key == NULL)
        return 0;

    if (key->priv_key != NULL
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->priv_key, key->priv_key_len))
        return 0;

    if (key->cipher.cipher != NULL
        && !ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_CIPHER,
                                             EVP_CIPHER_get0_name(key->cipher.cipher)))
        return 0;

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
    if (key->cipher.engine != NULL
        && !ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_ENGINE,
                                             ENGINE_get_id(key->cipher.engine)))
        return 0;
#endif

    return 1;
}

static int digiprov_mac_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    MAC_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!digiprov_is_running() || key == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
         && !digiprov_key_to_params(key, tmpl, NULL))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

static const OSSL_PARAM digiprov_mac_key_types[] = 
{
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_mac_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return digiprov_mac_key_types;
    return NULL;
}

static const OSSL_PARAM digiprov_cmac_key_types[] =
{
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ENGINE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *digiprov_cmac_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return digiprov_cmac_key_types;
    return NULL;
}

static int digiprov_mac_get_params(void *key, OSSL_PARAM params[])
{
    return digiprov_key_to_params(key, NULL, params);
}

static const OSSL_PARAM *digiprov_mac_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable_params[] =
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return gettable_params;
}

static const OSSL_PARAM *digiprov_cmac_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ENGINE, NULL, 0),
        OSSL_PARAM_END
    };
    return gettable_params;
}

static int digiprov_mac_set_params(void *keydata, const OSSL_PARAM params[])
{
    MAC_KEY *key = keydata;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL)
        return digiprov_mac_key_fromdata(key, params);

    return 1;
}

static const OSSL_PARAM *digiprov_mac_settable_params(void *provctx)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return settable_params;
}

static void *digiprov_mac_gen_init_common(void *provctx, int selection)
{
    DP_MAC_GEN_CTX *gctx = NULL;
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &gctx, 1, sizeof(DP_MAC_GEN_CTX));
    if (OK != status)
        return NULL;

    gctx->libctx = PROV_LIBCTX_OF(provctx);
    gctx->selection = selection;

    return gctx;
}

static void *digiprov_mac_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    DP_MAC_GEN_CTX *gctx = digiprov_mac_gen_init_common(provctx, selection);

    if (gctx != NULL && !digiprov_mac_gen_set_params(gctx, params))
    {
        (void) DIGI_FREE((void **)&gctx);
        gctx = NULL;
    }
    return gctx;
}

static void *digiprov_cmac_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    DP_MAC_GEN_CTX *gctx = digiprov_mac_gen_init_common(provctx, selection);

    if (gctx != NULL && !digiprov_cmac_gen_set_params(gctx, params))
    {
        (void) DIGI_FREE((void **)&gctx);
        gctx = NULL;
    }
    return gctx;
}

static int digiprov_mac_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    DP_MAC_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;
    MSTATUS status = OK;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }

        if (NULL != gctx->priv_key)
        {
            (void) DIGI_MEMSET_FREE(&gctx->priv_key, gctx->priv_key_len);
            /* allocate at least one byte to distinguish empty key from no key set */
        }
        status = DIGI_MALLOC((void **) &gctx->priv_key, p->data_size > 0 ? p->data_size : 1);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (p->data_size > 0)
        {
            (void) DIGI_MEMCPY(gctx->priv_key, p->data, (ubyte4) p->data_size);
        }
        gctx->priv_key_len = p->data_size;
    }

    return 1;
}

static int digiprov_cmac_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    DP_MAC_GEN_CTX *gctx = genctx;

    if (!digiprov_mac_gen_set_params(genctx, params))
        return 0;

    if (!ossl_prov_cipher_load_from_params(&gctx->cipher, params, gctx->libctx))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *digiprov_mac_gen_settable_params(ossl_unused void *genctx,
                                                          ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] =
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static const OSSL_PARAM *digiprov_cmac_gen_settable_params(ossl_unused void *genctx,
                                                           ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] =
    {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *digiprov_mac_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    DP_MAC_GEN_CTX *gctx = genctx;
    MAC_KEY *key = NULL;

    if (!digiprov_is_running() || gctx == NULL)
        return NULL;

    if ((key = digiprov_mac_key_new(gctx->libctx, 0)) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    if (gctx->priv_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        digiprov_mac_key_free(key);
        return NULL;
    }

    /*
     * This is horrible but required for backwards compatibility. We don't
     * actually do real key generation at all. We simply copy the key that was
     * previously set in the gctx. Hopefully at some point in the future all
     * of this can be removed and we will only support the EVP_KDF APIs.
     */
    if (!ossl_prov_cipher_copy(&key->cipher, &gctx->cipher)) {
        digiprov_mac_key_free(key);
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    ossl_prov_cipher_reset(&gctx->cipher);
    key->priv_key = gctx->priv_key;
    key->priv_key_len = gctx->priv_key_len;
    gctx->priv_key_len = 0;
    gctx->priv_key = NULL;

    return key;
}

static void digiprov_mac_gen_cleanup(void *genctx)
{
    DP_MAC_GEN_CTX *gctx = genctx;

    if (NULL != gctx->priv_key)
    {
        (void) DIGI_MEMSET_FREE(&gctx->priv_key, gctx->priv_key_len);
        /* allocate at least one byte to distinguish empty key from no key set */
    }

    ossl_prov_cipher_reset(&gctx->cipher);
    (void) DIGI_FREE((void **) &gctx);
}

const OSSL_DISPATCH digiprov_mac_keymgmt_functions[] = 
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_mac_new },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_mac_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_mac_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_mac_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,          (void (*)(void))digiprov_mac_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,     (void (*)(void))digiprov_mac_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_mac_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_mac_match },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_mac_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_mac_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_mac_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_mac_imexport_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_mac_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_mac_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_mac_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_mac_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_mac_gen_cleanup },
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_cmac_keymgmt_functions[] =
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_mac_new_cmac },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_mac_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_mac_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_cmac_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,          (void (*)(void))digiprov_mac_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,     (void (*)(void))digiprov_mac_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_mac_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_mac_match },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_mac_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_cmac_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_mac_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_cmac_imexport_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_cmac_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_cmac_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_cmac_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_mac_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_mac_gen_cleanup },
    { 0, NULL }
};

