/*
 * digi_dsa_kmgmt.c
 *
 * DSA keygen implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
#include "crypto/dsa.h"
#include "crypto/dsa/dsa_local.h"

#include "internal/param_build_set.h"

#include "internal/deprecated.h"

#define DSA_DEFAULT_MD "SHA256"
#define DSA_POSSIBLE_SELECTIONS                                                \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

struct dsa_gen_ctx 
{
    OSSL_LIB_CTX *libctx;

    FFC_PARAMS *ffc_params;
    int selection;
    /* All these parameters are used for parameter generation only */
    size_t pbits;
    size_t qbits;
    unsigned char *seed; /* optional FIPS186-4 param for testing */
    size_t seedlen;
    int gindex; /* optional  FIPS186-4 generator index (ignored if -1) */
    int gen_type; /* DSA_PARAMGEN_TYPE_FIPS_186_2 or DSA_PARAMGEN_TYPE_FIPS_186_4 */
    int pcounter;
    int hindex;
    char *mdname;
    char *mdprops;
    OSSL_CALLBACK *cb;
    void *cbarg;
};

typedef struct dh_name2id_st{
    const char *name;
    int id;
} DSA_GENTYPE_NAME2ID;

static const DSA_GENTYPE_NAME2ID dsatype2id[]=
{
#if defined(FIPS_MODULE) || defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    { "default", DSA_PARAMGEN_TYPE_FIPS_186_4 },
#else
    { "default", DSA_PARAMGEN_TYPE_FIPS_DEFAULT },
#endif
    { "fips186_4", DSA_PARAMGEN_TYPE_FIPS_186_4 },
    { "fips186_2", DSA_PARAMGEN_TYPE_FIPS_186_2 },
};

static int digiprov_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[]);
int moc_dsa_keygen(DSA *dsa);
BIGNUM *DIGI_EVP_vlong2BN(vlong *v);
vlong * moc_BIGNUM_to_vlong(const BIGNUM *bn, vlong **ppVlongQueue);

randomContext *RANDOM_getMocCtx(void);

static int digiprov_dsa_gen_type_name2id(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dsatype2id); ++i) {
        if (OPENSSL_strcasecmp(dsatype2id[i].name, name) == 0)
            return dsatype2id[i].id;
    }
    return -1;
}

static int digiprov_dsa_key_todata(DSA *dsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[], int include_private)
{
    const BIGNUM *priv = NULL, *pub = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_key(dsa, &pub, &priv);
    if (include_private
        && priv != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        return 0;
    if (pub != NULL
        && !ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub))
        return 0;

    return 1;
}

static void *digiprov_dsa_newdata(void *provctx)
{
    if (!digiprov_is_running())
        return NULL;

    return ossl_dsa_new(PROV_LIBCTX_OF(provctx));
}

static void digiprov_dsa_freedata(void *keydata)
{
    DSA_free(keydata);
}

static int digiprov_dsa_has(const void *keydata, int selection)
{
    const DSA *dsa = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if (dsa == NULL)
        return 0;
    if ((selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (DSA_get0_pub_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (DSA_get0_priv_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (DSA_get0_p(dsa) != NULL && DSA_get0_g(dsa) != NULL);
    return ok;
}

static int digiprov_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const DSA *dsa1 = keydata1;
    const DSA *dsa2 = keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const BIGNUM *pa = DSA_get0_pub_key(dsa1);
            const BIGNUM *pb = DSA_get0_pub_key(dsa2);

            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const BIGNUM *pa = DSA_get0_priv_key(dsa1);
            const BIGNUM *pb = DSA_get0_priv_key(dsa2);

            if (pa != NULL && pb != NULL) {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        FFC_PARAMS *dsaparams1 = ossl_dsa_get0_params((DSA *)dsa1);
        FFC_PARAMS *dsaparams2 = ossl_dsa_get0_params((DSA *)dsa2);

        ok = ok && ossl_ffc_params_cmp(dsaparams1, dsaparams2, 1);
    }
    return ok;
}

static int digiprov_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DSA *dsa = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if (dsa == NULL)
        return 0;

    if ((selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && ossl_dsa_ffc_params_fromdata(dsa, params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ossl_dsa_key_fromdata(dsa, params, include_private);
    }

    return ok;
}

static int digiprov_dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    DSA *dsa = (DSA *) keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if (dsa == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), tmpl, NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && digiprov_dsa_key_todata(dsa, tmpl, NULL, include_private);
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

# define DSA_IMEXPORTABLE_PARAMETERS                                           \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_COFACTOR, NULL, 0),                      \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),                          \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),                               \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0)
# define DSA_IMEXPORTABLE_PUBLIC_KEY                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define DSA_IMEXPORTABLE_PRIVATE_KEY                   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM digiprov_dsa_all_types[] = 
{
    DSA_IMEXPORTABLE_PARAMETERS,
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM digiprov_dsa_parameter_types[] =
{
    DSA_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM digiprov_dsa_key_types[] =
{
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM *digiprov_dsa_types[] =
{
    NULL,                                  /* Index 0 = none of them */
    digiprov_dsa_parameter_types,          /* Index 1 = parameter types */
    digiprov_dsa_key_types,                /* Index 2 = key types */
    digiprov_dsa_all_types                 /* Index 3 = 1 + 2 */
};

static const OSSL_PARAM *digiprov_dsa_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        type_select += 2;
    return digiprov_dsa_types[type_select];
}

static const OSSL_PARAM *digiprov_dsa_import_types(int selection)
{
    return digiprov_dsa_imexport_types(selection);
}

static const OSSL_PARAM *digiprov_dsa_export_types(int selection)
{
    return digiprov_dsa_imexport_types(selection);
}

static ossl_inline int digiprov_dsa_get_params(void *key, OSSL_PARAM params[])
{
    DSA *dsa = (DSA *) key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_security_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_size(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD))
        return 0;
    return ossl_ffc_params_todata(ossl_dsa_get0_params(dsa), NULL, params)
           && digiprov_dsa_key_todata(dsa, NULL, params, 1);
}

static const OSSL_PARAM digiprov_dsa_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    DSA_IMEXPORTABLE_PARAMETERS,
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dsa_gettable_params(void *provctx)
{
    return digiprov_dsa_params;
}

static int digiprov_dsa_validate_domparams(const DSA *dsa, int checktype)
{
    int status = 0;

    return ossl_dsa_check_params(dsa, checktype, &status);
}

static int digiprov_dsa_validate_public(const DSA *dsa)
{
    MSTATUS status = OK;
    const BIGNUM *pub_key = NULL;
    DSAKey *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDsaKeyTemplate template = {0};
    intBoolean isValid = FALSE;

    DSA_get0_key(dsa, &pub_key, NULL);
    if (pub_key == NULL)
        return 0;

    ffc = ossl_dsa_get0_params((DSA *) dsa);
    if (NULL == ffc)
        return 0;

    /* we must have p and q to validate a public key */
    if (NULL == ffc->p || NULL == ffc->q)
        return 0;
    
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
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

    template.yLen = (ubyte4) BN_num_bytes(pub_key);
    status = DIGI_MALLOC((void **) &template.pY, template.yLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(pub_key, template.pY);

    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DSA_verifyPublicKey(pKey, &isValid, NULL);
        
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dsa_validate_private(const DSA *dsa)
{
    MSTATUS status = OK;
    const BIGNUM *priv_key = NULL;
    DSAKey *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDsaKeyTemplate template = {0};
    intBoolean isValid = FALSE;

    DSA_get0_key(dsa, NULL, &priv_key);
    if (priv_key == NULL)
        return 0;

    ffc = ossl_dsa_get0_params((DSA *) dsa);
    if (NULL == ffc)
        return 0;
    
    /* we must have p. q is optional */
    if (NULL == ffc->p)
        return 0;
    
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
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

    template.xLen = (ubyte4) BN_num_bytes(priv_key);
    status = DIGI_MALLOC((void **) &template.pX, template.xLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(priv_key, template.pX);

    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DSA_verifyPrivateKey(pKey, &isValid, NULL);
        
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dsa_check_pairwise(const DSA *dsa)
{
    MSTATUS status = OK;
    const BIGNUM *pub_key = NULL;
    const BIGNUM *priv_key = NULL;
    DSAKey *pKey = NULL;
    FFC_PARAMS *ffc = NULL;
    MDsaKeyTemplate template = {0};
    intBoolean isValid = FALSE;

    DSA_get0_key(dsa, &pub_key, &priv_key);
    if (pub_key == NULL || priv_key == NULL)
        return 0;

    ffc = ossl_dsa_get0_params((DSA *) dsa);
    if (NULL == ffc)
        return 0;
    
    /* we must have p and g to validate a public key */
    if (NULL == ffc->p || NULL == ffc->g)
        return 0;
    
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
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

    template.xLen = (ubyte4) BN_num_bytes(priv_key);
    status = DIGI_MALLOC((void **) &template.pX, template.xLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(priv_key, template.pX);

    template.yLen = (ubyte4) BN_num_bytes(pub_key);
    status = DIGI_MALLOC((void **) &template.pY, template.yLen);
    if (OK != status)
        goto exit;

    BN_bn2bin(pub_key, template.pY);

    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(pKey, &template);
    if (OK != status)
        goto exit;

    status =  CRYPTO_INTERFACE_DSA_verifyKeyPair(pKey, &isValid, NULL);
        
exit:

    if (NULL != pKey)
    {
        (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(pKey, &template);
        (void) CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
    }

    if (OK == status && isValid)
        return 1;
    
    return 0;
}

static int digiprov_dsa_validate(const void *keydata, int selection, int checktype)
{
    const DSA *dsa = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;
    
    if ((selection & DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && digiprov_dsa_validate_domparams(dsa, checktype);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && digiprov_dsa_validate_public(dsa);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && digiprov_dsa_validate_private(dsa);

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && digiprov_dsa_check_pairwise(dsa);
    return ok;
}

static void *digiprov_dsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct dsa_gen_ctx *gctx = NULL;

    if (!digiprov_is_running())
        return 0;
    
    if (0 == (selection & DSA_POSSIBLE_SELECTIONS))
        return NULL;

    status = DIGI_CALLOC((void **)&gctx, 1, sizeof(*gctx));
    if (OK != status)
        return NULL;

    gctx->selection = selection;
    gctx->libctx = libctx;
    gctx->pbits = 2048;
    gctx->qbits = 224;
    gctx->gen_type = DSA_PARAMGEN_TYPE_FIPS_186_4;
    gctx->gindex = -1;
    gctx->pcounter = -1;
    gctx->hindex = 0;
    
    if (!digiprov_dsa_gen_set_params(gctx, params)) 
    {
        (void) DIGI_FREE((void **) &gctx);
        gctx = NULL;
    }
    return gctx;
}

static int digiprov_dsa_gen_set_template(void *genctx, void *templ)
{
    struct dsa_gen_ctx *gctx = genctx;
    DSA *dsa = (DSA *) templ;

    if (!digiprov_is_running())
        return 0;
    
    if (gctx == NULL || dsa == NULL)
        return 0;
    gctx->ffc_params = ossl_dsa_get0_params(dsa);
    return 1;
}

static int digiprov_dsa_set_gen_seed(struct dsa_gen_ctx *gctx, unsigned char *seed, size_t seedlen)
{
    MSTATUS status = OK;
    (void) DIGI_MEMSET_FREE(&gctx->seed, gctx->seedlen);
    gctx->seed = NULL;
    gctx->seedlen = 0;
    if (seed != NULL && seedlen > 0) 
    {
        status = DIGI_MALLOC_MEMCPY((void **) &gctx->seed, seedlen, seed, seedlen);
        if (OK != status)
            return 0;

        gctx->seedlen = seedlen;
    }
    return 1;
}

static int digiprov_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    struct dsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || ((gctx->gen_type = digiprov_dsa_gen_type_name2id(p->data)) == -1)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->gindex))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->pcounter))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
    if (p != NULL
        && !OSSL_PARAM_get_int(p, &gctx->hindex))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
    if (p != NULL
        && (p->data_type != OSSL_PARAM_OCTET_STRING
            || !digiprov_dsa_set_gen_seed(gctx, p->data, p->data_size)))
            return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->pbits))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->qbits))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        (void) DIGI_FREE((void **) &gctx->mdname);
        status = digiprov_strdup((void **) &gctx->mdname, p->data);
        if (OK != status)
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        (void) DIGI_FREE((void **) &gctx->mdprops);
        status = digiprov_strdup((void **) &gctx->mdprops, p->data);
        if (OK != status)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *digiprov_dsa_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = 
    {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, NULL, 0),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_QBITS, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_GINDEX, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_SEED, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_FFC_H, NULL),
        OSSL_PARAM_END
    };
    return settable;
}

static void *digiprov_dsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    MSTATUS status = OK;
    struct dsa_gen_ctx *gctx = genctx;
    DSA *dsa = NULL;
    int ret = 0;
    FFC_PARAMS *ffc;
    FFCHashType hashType = 0;
    DSAKey *p_dsaDescr = NULL;
    MDsaKeyTemplate template = { 0 };

    if (!digiprov_is_running())
        return NULL;
    
    if (gctx == NULL)
        return NULL;
    
    dsa = ossl_dsa_new(gctx->libctx);
    if (dsa == NULL)
        return NULL;

    if (gctx->gen_type == DSA_PARAMGEN_TYPE_FIPS_DEFAULT)
        gctx->gen_type = DSA_PARAMGEN_TYPE_FIPS_186_4;
    
    ffc = ossl_dsa_get0_params(dsa);
    /* Copy the template value if one was passed */
    if (gctx->ffc_params != NULL
        && !ossl_ffc_params_copy(ffc, gctx->ffc_params))
        goto end;

    if (gctx->seed != NULL
        && !ossl_ffc_params_set_seed(ffc, gctx->seed, gctx->seedlen))
        goto end;
    if (gctx->gindex != -1) 
    {
        ossl_ffc_params_set_gindex(ffc, gctx->gindex);
        if (gctx->pcounter != -1)
            ossl_ffc_params_set_pcounter(ffc, gctx->pcounter);
    } 
    else if (gctx->hindex != 0) 
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

        status = CRYPTO_INTERFACE_DSA_createKey (&p_dsaDescr);
        if (OK != status)
            goto end;

        /* We have to ignore the seed in the gctx */
        status = CRYPTO_INTERFACE_DSA_generateKeyAux2 (RANDOM_getMocCtx(), p_dsaDescr, (ubyte4) gctx->pbits,
                                                       (ubyte4) gctx->qbits, (DSAHashType) hashType, NULL);
        if (OK != status)
            goto end;

        status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(p_dsaDescr, &template, MOC_GET_PUBLIC_KEY_DATA);
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

    ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY,
                                 gctx->gen_type == DSA_PARAMGEN_TYPE_FIPS_186_2);
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (ffc->p == NULL
            || ffc->q == NULL
            || ffc->g == NULL)
            goto end;

        if (moc_dsa_keygen(dsa) <= 0)
            goto end;
    }
    ret = 1;

end:

    if (ret <= 0) 
    {
        DSA_free(dsa);
        dsa = NULL;
    }

    if (NULL != p_dsaDescr)
    {
        (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(p_dsaDescr, &template);
        (void) CRYPTO_INTERFACE_DSA_freeKey(&p_dsaDescr, NULL);
    }

    return dsa;
}

static void digiprov_dsa_gen_cleanup(void *genctx)
{
    struct dsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    (void) DIGI_FREE((void **) &gctx->mdname);
    (void) DIGI_FREE((void **) &gctx->mdprops);
    (void) DIGI_MEMSET_FREE(&gctx->seed, gctx->seedlen);
    (void) DIGI_FREE((void **) &gctx);
}

static void *digiprov_dsa_load(const void *reference, size_t reference_sz)
{
    DSA *dsa = NULL;

    if (digiprov_is_running() && reference_sz == sizeof(dsa)) 
    {
        /* The contents of the reference is the address to our object */
        dsa = *(DSA **)reference;
        /* We grabbed, so we detach it */
        *(DSA **)reference = NULL;
        return dsa;
    }
    return NULL;
}

static ossl_inline int digiprov_dsa_bn_dup_check(BIGNUM **out, const BIGNUM *f)
{
    if (f != NULL && (*out = BN_dup(f)) == NULL)
        return 0;
    return 1;
}

static void *digiprov_dsa_dup(const void *keydata_from, int selection)
{
    DSA *dsa = (DSA *) keydata_from;
    DSA *dupkey = NULL;

    if (!digiprov_is_running())
        return NULL;

    if ((dupkey = ossl_dsa_new(dsa->libctx)) == NULL)
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0
        && !ossl_ffc_params_copy(&dupkey->params, &dsa->params))
        goto err;

    dupkey->flags = dsa->flags;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
            || !digiprov_dsa_bn_dup_check(&dupkey->pub_key, dsa->pub_key)))
        goto err;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
            || !digiprov_dsa_bn_dup_check(&dupkey->priv_key, dsa->priv_key)))
        goto err;

#if !defined(FIPS_MODULE) && !defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DSA, &dupkey->ex_data, &dsa->ex_data))
        goto err;
#endif

    return dupkey;

 err:
    DSA_free(dupkey);
    return NULL;
}

const OSSL_DISPATCH digiprov_dsa_keymgmt_functions[] = 
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_dsa_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_dsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,    (void (*)(void))digiprov_dsa_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_dsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_dsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_dsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_dsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_dsa_load },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_dsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_dsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_dsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_dsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_dsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_dsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_dsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_dsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_dsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_dsa_export_types },
    { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_dsa_dup },
    { 0, NULL }
};
