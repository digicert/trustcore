/*
 * digi_dh_kmgmt.c
 *
 * DH keygen implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2019 Red Hat, Inc.
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
#include "../../../src/crypto/dh.h"
#include "../../../src/crypto_interface/crypto_interface_dh.h"

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

#include "openssl/bn.h"
#include "crypto/bn.h"
#include "crypto/dh.h"

#include "internal/param_build_set.h"

#define DH_POSSIBLE_SELECTIONS \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

struct dh_gen_ctx 
{
    OSSL_LIB_CTX *libctx;

    FFC_PARAMS *ffc_params;
    int selection;
    /* All these parameters are used for parameter generation only */
    /* If there is a group name then the remaining parameters are not needed */
    int group_nid;
    size_t pbits;
    size_t qbits;
   /* unsigned char *seed;  optional FIPS186-4 param for testing
    size_t seedlen; */
    int gindex; /* optional  FIPS186-4 generator index (ignored if -1) */
    int gen_type; /* see dhtype2id */
    int generator; /* Used by DH_PARAMGEN_TYPE_GENERATOR in non fips mode only */
    int pcounter;
    int hindex;
    int priv_len;

    char *mdname;
    char *mdprops;
    OSSL_CALLBACK *cb;
    void *cbarg;
    int dh_type;
};

static int digiprov_dh_gen_set_params(void *genctx, const OSSL_PARAM params[]);
int moc_generate_key(DH *pDH);
BIGNUM *DIGI_EVP_vlong2BN(vlong *v);
vlong * moc_BIGNUM_to_vlong(const BIGNUM *bn, vlong **ppVlongQueue);

randomContext *RANDOM_getMocCtx(void);

static int digiprov_dh_gen_type_name2id_w_default(const char *name, int type)
{
    if (0 == DIGI_STRCMP((const sbyte *) name, (const sbyte *) "default")) 
    {
#if defined(FIPS_MODULE) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        if (type == DH_FLAG_TYPE_DHX)
            return DH_PARAMGEN_TYPE_FIPS_186_4;

        return DH_PARAMGEN_TYPE_GROUP;
#else
        if (type == DH_FLAG_TYPE_DHX)
            return DH_PARAMGEN_TYPE_FIPS_186_2;

        return DH_PARAMGEN_TYPE_GENERATOR;
#endif
    }

    return ossl_dh_gen_type_name2id(name, type);
}

static void *digiprov_dh_newdata(void *provctx)
{
    DH *dh = NULL;

    if (!digiprov_is_running())
        return NULL;

    dh = ossl_dh_new_ex(PROV_LIBCTX_OF(provctx));
    if (dh != NULL) 
    {
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(dh, DH_FLAG_TYPE_DH);
    }
    return dh;
}

static void digiprov_dh_freedata(void *keydata)
{
    DH_free(keydata);
}

static int digiprov_dh_has(const void *keydata, int selection)
{
    const DH *dh = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if (dh == NULL)
        return 0;
    if ((selection & DH_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (DH_get0_pub_key(dh) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (DH_get0_priv_key(dh) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (DH_get0_p(dh) != NULL && DH_get0_g(dh) != NULL);
    return ok;
}

static int digiprov_dh_match(const void *keydata1, const void *keydata2, int selection)
{
    const DH *dh1 = keydata1;
    const DH *dh2 = keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        {
            const BIGNUM *pa = DH_get0_pub_key(dh1);
            const BIGNUM *pb = DH_get0_pub_key(dh2);

            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        {
            const BIGNUM *pa = DH_get0_priv_key(dh1);
            const BIGNUM *pb = DH_get0_priv_key(dh2);

            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        FFC_PARAMS *dhparams1 = ossl_dh_get0_params((DH *)dh1);
        FFC_PARAMS *dhparams2 = ossl_dh_get0_params((DH *)dh2);

        ok = ok && ossl_ffc_params_cmp(dhparams1, dhparams2, 1);
    }
    return ok;
}

static int digiprov_dh_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DH *dh = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if (dh == NULL)
        return 0;

    if ((selection & DH_POSSIBLE_SELECTIONS) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && ossl_dh_params_fromdata(dh, params);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ossl_dh_key_fromdata(dh, params, include_private);
    }

    return ok;
}

static int digiprov_dh_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    DH *dh = keydata;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if (dh == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && ossl_dh_params_todata(dh, tmpl, NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ossl_dh_key_todata(dh, tmpl, NULL, include_private);
    }

    if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        ok = 0;
        goto err;
    }

    ok = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

/* IMEXPORT = IMPORT + EXPORT */

# define DH_IMEXPORTABLE_PARAMETERS                                            \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),                      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),                          \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),                               \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),                         \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),                \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0)
# define DH_IMEXPORTABLE_PUBLIC_KEY                                            \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define DH_IMEXPORTABLE_PRIVATE_KEY                                           \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
static const OSSL_PARAM dh_all_types[] = {
    DH_IMEXPORTABLE_PARAMETERS,
    DH_IMEXPORTABLE_PUBLIC_KEY,
    DH_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM dh_parameter_types[] = {
    DH_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM dh_key_types[] = {
    DH_IMEXPORTABLE_PUBLIC_KEY,
    DH_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM *dh_types[] = {
    NULL,                        /* Index 0 = none of them */
    dh_parameter_types,          /* Index 1 = parameter types */
    dh_key_types,                /* Index 2 = key types */
    dh_all_types                 /* Index 3 = 1 + 2 */
};

static const OSSL_PARAM *digiprov_dh_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        type_select += 2;
    return dh_types[type_select];
}

static const OSSL_PARAM *digiprov_dh_import_types(int selection)
{
    return digiprov_dh_imexport_types(selection);
}

static const OSSL_PARAM *digiprov_dh_export_types(int selection)
{
    return digiprov_dh_imexport_types(selection);
}

static ossl_inline int digiprov_dh_get_params(void *key, OSSL_PARAM params[])
{
    DH *dh = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_security_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DH_size(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = ossl_dh_key2buf(dh, (unsigned char **)&p->data,
                                         p->data_size, 0);
        if (p->return_size == 0)
            return 0;
    }

    return ossl_dh_params_todata(dh, NULL, params)
        && ossl_dh_key_todata(dh, NULL, params, 1);
}

static const OSSL_PARAM digiprov_dh_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    DH_IMEXPORTABLE_PARAMETERS,
    DH_IMEXPORTABLE_PUBLIC_KEY,
    DH_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dh_gettable_params(void *provctx)
{
    return digiprov_dh_params;
}

static const OSSL_PARAM digiprov_dh_known_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dh_settable_params(void *provctx)
{
    return digiprov_dh_known_settable_params;
}

static int digiprov_dh_set_params(void *key, const OSSL_PARAM params[])
{
    DH *dh = key;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL
            && (p->data_type != OSSL_PARAM_OCTET_STRING
                || !ossl_dh_buf2key(dh, p->data, p->data_size)))
        return 0;

    return 1;
}

static int digiprov_dh_validate_public(const DH *dh, int checktype)
{
    MSTATUS status = OK;
    const BIGNUM *pub_key = NULL;
    diffieHellmanContext *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDhKeyTemplate template = {0};
    intBoolean isValid = FALSE;
    int res = 0;

    DH_get0_key(dh, &pub_key, NULL);
    if (pub_key == NULL)
        return 0;

    ffc = ossl_dh_get0_params((DH *) dh);

    /* The partial test is only valid for named group's with q = (p - 1) / 2 or if q is unknown */
    if ( (checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK && ossl_dh_is_named_safe_prime_group(dh))
         || NULL == ffc->q )
        return ossl_dh_check_pub_key_partial(dh, pub_key, &res);

    /* otherwise we have q and we use our validation */
    if (NULL == ffc->p)
        return 0;

    status = CRYPTO_INTERFACE_DH_allocate(&pKey);
    if (OK != status)
        goto exit;

    template.pLen = (ubyte4) BN_num_bytes(ffc->p);
    status = DIGI_MALLOC((void **) &template.pP, template.pLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(ffc->p, template.pP);

    template.qLen = (ubyte4) BN_num_bytes(ffc->q);
    status = DIGI_MALLOC((void **) &template.pQ, template.qLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(ffc->q, template.pQ);

    template.fLen = (ubyte4) BN_num_bytes(pub_key);
    status = DIGI_MALLOC((void **) &template.pF, template.fLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(pub_key, template.pF);

    status = CRYPTO_INTERFACE_DH_setKeyParameters(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DH_verifyPublicKey(pKey, &isValid, NULL);
    
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DH_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dh_validate_private(const DH *dh)
{
    MSTATUS status = OK;
    const BIGNUM *priv_key = NULL;
    diffieHellmanContext *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDhKeyTemplate template = {0};
    intBoolean isValid = FALSE;

    DH_get0_key(dh, NULL, &priv_key);
    if (priv_key == NULL)
        return 0;

    ffc = ossl_dh_get0_params((DH *) dh);

    /* we must have p. q is optional */
    if (NULL == ffc->p)
        return 0;
    
    status = CRYPTO_INTERFACE_DH_allocate(&pKey);
    if (OK != status)
        goto exit;

    template.pLen = (ubyte4) BN_num_bytes(ffc->p);
    status = DIGI_MALLOC((void **) &template.pP, template.pLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(ffc->p, template.pP);

    if (NULL != ffc->q)
    {
        template.qLen = (ubyte4) BN_num_bytes(ffc->q);
        if (template.qLen > 0)
        {
            status = DIGI_MALLOC((void **) &template.pQ, template.qLen);
            if (OK != status)
                goto exit;

            BN_bn2bin(ffc->q, template.pQ);
        }
    }

    template.yLen = (ubyte4) BN_num_bytes(priv_key);
    status = DIGI_MALLOC((void **) &template.pY, template.yLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(priv_key, template.pY);

    status = CRYPTO_INTERFACE_DH_setKeyParameters(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DH_verifyPrivateKey(pKey, &isValid, NULL);
     
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DH_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dh_check_pairwise(const DH *dh)
{
    MSTATUS status = OK;
    const BIGNUM *pub_key = NULL;
    const BIGNUM *priv_key = NULL;
    diffieHellmanContext *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDhKeyTemplate template = {0};
    intBoolean isValid = FALSE;

    DH_get0_key(dh, &pub_key, &priv_key);
    if (pub_key == NULL || priv_key == NULL)
        return 0;

    ffc = ossl_dh_get0_params((DH *) dh);
    if (NULL == ffc)
        return 0;
    
    /* we must have p and g to validate a public key */
    if (NULL == ffc->p || NULL == ffc->g)
        return 0;
    
    status = CRYPTO_INTERFACE_DH_allocate(&pKey);
    if (OK != status)
        goto exit;

    template.pLen = (ubyte4) BN_num_bytes(ffc->p);
    status = DIGI_MALLOC((void **) &template.pP, template.pLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(ffc->p, template.pP);

    template.gLen = (ubyte4) BN_num_bytes(ffc->g);
    status = DIGI_MALLOC((void **) &template.pG, template.gLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(ffc->g, template.pG);

    template.yLen = (ubyte4) BN_num_bytes(priv_key);
    status = DIGI_MALLOC((void **) &template.pY, template.yLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(priv_key, template.pY);

    template.fLen = (ubyte4) BN_num_bytes(pub_key);
    status = DIGI_MALLOC((void **) &template.pF, template.fLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(pub_key, template.pF);

    status = CRYPTO_INTERFACE_DH_setKeyParameters(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DH_verifyKeyPair(pKey, &isValid, NULL);
        
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DH_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dh_validate(const void *keydata, int selection, int checktype)
{
    const DH *dh = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & DH_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /*
         * Both of these functions check parameters. DH_check_params_ex()
         * performs a lightweight check (e.g. it does not check that p is a
         * safe prime)
         */
        if (checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK)
            ok = ok && DH_check_params_ex(dh);
        else
            ok = ok && DH_check_ex(dh);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && digiprov_dh_validate_public(dh, checktype);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && digiprov_dh_validate_private(dh);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && digiprov_dh_check_pairwise(dh);
    return ok;
}

static void *digiprov_dh_gen_init_base(void *provctx, int selection, const OSSL_PARAM params[], int type)
{
    MSTATUS status = OK;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct dh_gen_ctx *gctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0)
        return NULL;

    status = DIGI_CALLOC((void **) &gctx, 1, sizeof(*gctx));
    if (OK != status)
        return NULL;

    gctx->selection = selection;
    gctx->libctx = libctx;
    gctx->pbits = 2048;
    gctx->qbits = 224;
    gctx->mdname = NULL;

    gctx->gen_type = (type == DH_FLAG_TYPE_DHX)
                        ? DH_PARAMGEN_TYPE_FIPS_186_4
                        : DH_PARAMGEN_TYPE_GROUP;
    gctx->gindex = -1;
    gctx->hindex = 0;
    gctx->pcounter = -1;
    gctx->generator = DH_GENERATOR_2;
    gctx->dh_type = type;
    
    if (!digiprov_dh_gen_set_params(gctx, params)) 
    {
        (void) DIGI_FREE((void **) &gctx);
        gctx = NULL;
    }
    return gctx;
}

static void *digiprov_dh_gen_init(void *provctx, int selection,
                         const OSSL_PARAM params[])
{
    return digiprov_dh_gen_init_base(provctx, selection, params, DH_FLAG_TYPE_DH);
}

static int digiprov_dh_gen_set_template(void *genctx, void *templ)
{
    struct dh_gen_ctx *gctx = genctx;
    DH *dh = (DH *) templ;

    if (!digiprov_is_running())
        return 0;
    
    if (gctx == NULL || dh == NULL)
        return 0;
    gctx->ffc_params = ossl_dh_get0_params(dh);
    return 1;
}

static int digiprov_dh_gen_common_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct dh_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || ((gctx->gen_type =
                 digiprov_dh_gen_type_name2id_w_default(p->data, gctx->dh_type)) == -1)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const DH_NAMED_GROUP *group = NULL;

        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || p->data == NULL
            || (group = ossl_ffc_name_to_dh_named_group(p->data)) == NULL
            || ((gctx->group_nid =
                 ossl_ffc_named_group_get_uid(group)) == NID_undef)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->pbits))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
    if (p != NULL && !OSSL_PARAM_get_int(p, &gctx->priv_len))
        return 0;
    return 1;
}

static const OSSL_PARAM *digiprov_dh_gen_settable_params(ossl_unused void *genctx,
                                                         ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_dh_gen_settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_GENERATOR, NULL),
        OSSL_PARAM_END
    };
    return digiprov_dh_gen_settable;
}

static int digiprov_dh_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct dh_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (!digiprov_dh_gen_common_set_params(genctx, params))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
    if (p != NULL && !OSSL_PARAM_get_int(p, &gctx->generator))
        return 0;

    /* Parameters that are not allowed for DH */
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST) != NULL
        || OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS) != NULL) 
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    return 1;
}
  
static void *digiprov_dh_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    MSTATUS status = OK;
    int ret = 0;
    struct dh_gen_ctx *gctx = genctx;
    DH *dh = NULL;
    FFC_PARAMS *ffc;
    FFCHashType hashType = 0;
    diffieHellmanContext *pKey = NULL;
    MDhKeyTemplate template = {0};

    if (!digiprov_is_running())
        return NULL;
    
    if (gctx == NULL)
        return NULL;

    /*
     * If a group name is selected then the type is group regardless of what the
     * the user selected. This overrides rather than errors for backwards
     * compatibility.
     */
    if (gctx->group_nid != NID_undef)
        gctx->gen_type = DH_PARAMGEN_TYPE_GROUP;

    /* For parameter generation - If there is a group name just create it */
    if (gctx->gen_type == DH_PARAMGEN_TYPE_GROUP
            && gctx->ffc_params == NULL) 
    {
        /* Select a named group if there is not one already */
        if (gctx->group_nid == NID_undef)
            gctx->group_nid = ossl_dh_get_named_group_uid_from_size(gctx->pbits);
        if (gctx->group_nid == NID_undef)
            return NULL;
        dh = ossl_dh_new_by_nid_ex(gctx->libctx, gctx->group_nid);
        if (dh == NULL)
            return NULL;
        ffc = ossl_dh_get0_params(dh);
    } 
    else if (DH_PARAMGEN_TYPE_FIPS_186_4 == gctx->gen_type) 
    {
        dh = ossl_dh_new_ex(gctx->libctx);
        if (dh == NULL)
            return NULL;
        ffc = ossl_dh_get0_params(dh);

        /* Copy the template value if one was passed */
        if (gctx->ffc_params != NULL
            && !ossl_ffc_params_copy(ffc, gctx->ffc_params))
            goto end;

        /* NO support right now for using the passed in seed
        if (!ossl_ffc_params_set_seed(ffc, gctx->seed, gctx->seedlen))
            goto end; */
        if (gctx->gindex != -1) 
        {
            ossl_ffc_params_set_gindex(ffc, gctx->gindex);
            if (gctx->pcounter != -1)
                ossl_ffc_params_set_pcounter(ffc, gctx->pcounter);
        } else if (gctx->hindex != 0) 
        {
            ossl_ffc_params_set_h(ffc, gctx->hindex);
        }
        if (gctx->mdname != NULL) 
        {
            if (!ossl_ffc_set_digest(ffc, gctx->mdname, gctx->mdprops))
                goto end;
        }

        if ((gctx->selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) 
        {
            status = digiprov_get_hashType(gctx->mdname, &hashType);
            if (OK != status)
                goto end;

            status = CRYPTO_INTERFACE_DH_allocate(&pKey);
            if (OK != status)
                goto end;

            /* We have to ignore the seed in the gctx */
            status = CRYPTO_INTERFACE_DH_generateDomainParams (pKey, RANDOM_getMocCtx(), (ubyte4) gctx->pbits,
                                                              (ubyte4) gctx->qbits, hashType, NULL);
            if (OK != status)
                goto end;

            status = CRYPTO_INTERFACE_DH_getKeyParametersAlloc(&template, pKey, MOC_GET_PUBLIC_KEY_DATA);
            if (OK != status)
                goto end;

            if(ffc->p) BN_free(ffc->p);
            ffc->p = BN_bin2bn(template.pP, template.pLen, NULL);
            if (NULL == ffc->p)
                goto end;

            if(ffc->q) BN_free(ffc->q);
            ffc->q = BN_bin2bn(template.pQ, template.qLen, NULL);
            if (NULL == ffc->q)
                goto end;

            if(ffc->g) BN_free(ffc->g);
            ffc->g = BN_bin2bn(template.pG, template.gLen, NULL);
            if (NULL == ffc->g)
                goto end;
        }
    }
    else
    {
        ret = 0;
        goto end;
    }

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        if (ffc->p == NULL || ffc->g == NULL)
            goto end;
        if (gctx->priv_len > 0)
            DH_set_length(dh, (long)gctx->priv_len);
        ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY,
                                     gctx->gen_type == DH_PARAMGEN_TYPE_FIPS_186_2);

        if (moc_generate_key(dh) <= 0)
            goto end;
    }
    DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
    DH_set_flags(dh, gctx->dh_type);

    ret = 1;
end:

    if (ret <= 0)
    {
        DH_free(dh);
        dh = NULL;
    }

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DH_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
    }

    return dh;
}

static void digiprov_dh_gen_cleanup(void *genctx)
{
    struct dh_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    (void) DIGI_FREE((void **) &gctx->mdname);
    (void) DIGI_FREE((void **) &gctx->mdprops);
    (void) DIGI_FREE((void **) &gctx);
}

static void *digiprov_dh_load(const void *reference, size_t reference_sz)
{
    DH *dh = NULL;

    if (digiprov_is_running() && reference_sz == sizeof(dh))
    {
        /* The contents of the reference is the address to our object */
        dh = *(DH **)reference;
        /* We grabbed, so we detach it */
        *(DH **)reference = NULL;
        return dh;
    }
    return NULL;
}

static void *digiprov_dh_dup(const void *keydata_from, int selection)
{
    if (!digiprov_is_running())
        return NULL;
    
    return ossl_dh_dup(keydata_from, selection);
}

const OSSL_DISPATCH digiprov_dh_keymgmt_functions[] = 
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_dh_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_dh_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,    (void (*)(void))digiprov_dh_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_dh_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_dh_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_dh_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_dh_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_dh_load },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_dh_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_dh_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_dh_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,          (void (*)(void))digiprov_dh_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,     (void (*)(void))digiprov_dh_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_dh_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_dh_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_dh_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_dh_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_dh_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_dh_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_dh_export_types },
    { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_dh_dup },
    { 0, NULL }
};
