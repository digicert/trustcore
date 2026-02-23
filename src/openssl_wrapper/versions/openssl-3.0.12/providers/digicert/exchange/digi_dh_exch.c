/*
 * digi_dh_exch.c
 *
 * DH implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/crypto.h"

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
#include "prov/securitycheck.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "internal/deprecated.h"

#include "openssl/crypto.h"
#include "openssl/dh.h"
#include "crypto/dh.h"

/*
 * This type is only really used to handle some legacy related functionality.
 * If you need to use other KDF's (such as SSKDF) just use PROV_DH_KDF_NONE
 * here and then create and run a KDF after the key is derived.
 * Note that X942 has 2 variants of key derivation:
 *   (1) DH_KDF_X9_42_ASN1 - which contains an ANS1 encoded object that has
 *   the counter embedded in it.
 *   (2) DH_KDF_X941_CONCAT - which is the same as ECDH_X963_KDF (which can be
 *       done by creating a "X963KDF".
 */
enum kdf_type 
{
    PROV_DH_KDF_NONE = 0,
    PROV_DH_KDF_X9_42_ASN1
};

/*
 * Based on Openssl's PROV_DH_CTX
 */

typedef struct 
{
    OSSL_LIB_CTX *libctx;
    DH *dh;
    DH *dhpeer;
    unsigned int pad;

    /* DH KDF */
    /* KDF (if any) to use for DH */
    enum kdf_type kdf_type;
    /* Message digest to use for key derivation */
    EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
    char *kdf_cekalg;

} DP_DH_CTX;

int moc_compute_dh_key(unsigned char *pKey, const BIGNUM *pPubKey, DH *pDH, ubyte pad, ubyte4 dhSize);
static int digiprov_dh_set_ctx_params(void *vpdhctx, const OSSL_PARAM params[]);

static void *digiprov_dh_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_DH_CTX *pdhctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &pdhctx, 1, sizeof(DP_DH_CTX));
    if (OK != status)
        return NULL;

    pdhctx->libctx = PROV_LIBCTX_OF(provctx);
    pdhctx->kdf_type = PROV_DH_KDF_NONE;
    return pdhctx;
}

static int digiprov_dh_init(void *vpdhctx, void *vdh, const OSSL_PARAM params[])
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;

    if (!digiprov_is_running())
        return 0;

    if (pdhctx == NULL || vdh == NULL || !DH_up_ref(vdh))
        return 0;
    DH_free(pdhctx->dh);
    pdhctx->dh = vdh;
    pdhctx->kdf_type = PROV_DH_KDF_NONE;
    return digiprov_dh_set_ctx_params(pdhctx, params)
           && ossl_dh_check_key(pdhctx->libctx, vdh);
}

/* The 2 parties must share the same domain parameters */
static int digiprov_dh_match_params(DH *priv, DH *peer)
{
    int ret;
    FFC_PARAMS *dhparams_priv = ossl_dh_get0_params(priv);
    FFC_PARAMS *dhparams_peer = ossl_dh_get0_params(peer);

    ret = dhparams_priv != NULL
          && dhparams_peer != NULL
          && ossl_ffc_params_cmp(dhparams_priv, dhparams_peer, 1);
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    return ret;
}

static int digiprov_dh_set_peer(void *vpdhctx, void *vdh)
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;

    if (!digiprov_is_running())
        return 0;
    
    if (pdhctx == NULL || vdh == NULL || !digiprov_dh_match_params(vdh, pdhctx->dh) || !DH_up_ref(vdh))
        return 0;
    DH_free(pdhctx->dhpeer);
    pdhctx->dhpeer = vdh;
    return 1;
}

static int digiprov_dh_plain_derive(void *vpdhctx, unsigned char *secret, size_t *secretlen,
                                    size_t outlen, unsigned int pad)
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;
    int ret;
    size_t dhsize;
    const BIGNUM *pub_key = NULL;

    if (pdhctx->dh == NULL || pdhctx->dhpeer == NULL)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    dhsize = (size_t)DH_size(pdhctx->dh);
    if (secret == NULL)
    {
        *secretlen = dhsize;
        return 1;
    }
    if (outlen < dhsize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    DH_get0_key(pdhctx->dhpeer, &pub_key, NULL);

    ret = moc_compute_dh_key(secret, pub_key, pdhctx->dh, (ubyte) pad, (ubyte4) dhsize);
    if (ret <= 0)
        return 0;

    *secretlen = ret;
    return 1;
}

#if 0
/* not X9_42 not supported yet by Digicert/Mocana codebase */
static int digiprov_dh_X9_42_kdf_derive(void *vpdhctx, unsigned char *secret,
                                        size_t *secretlen, size_t outlen)
{
    MSTATUS status = OK;
    MOC_EVP_MD_CTX mdCtx = {0};
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;
    unsigned char *stmp = NULL;
    size_t stmplen = 0;
    int ret = 0;

    if (secret == NULL) 
    {
        *secretlen = pdhctx->kdf_outlen;
        return 1;
    }

    if (pdhctx->kdf_outlen > outlen)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (!digiprov_dh_plain_derive(pdhctx, NULL, &stmplen, 0, 1))
        return 0;
    
    status = DIGI_MALLOC((void **) &stmp, stmplen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!digiprov_dh_plain_derive(pdhctx, stmp, &stmplen, stmplen, 1))
        goto err;

    if (pdhctx->kdf_type == PROV_DH_KDF_X9_42_ASN1) 
    {
        int md_nid = ossl_digest_get_approved_nid_with_sha1(pdhctx->libctx, pdhctx->kdf_md, 1);

        DIGI_EVP_setDigestAlgo( &mdCtx, md_nid);
        if (NULL == mdCtx.pDigestAlgo)
            goto err;

        /* NEW API Needed */
        status = CRYPTO_INTERFACE_ANSIX942KDF_generate(
            mdCtx.pDigestAlgo->pHashAlgo, (ubyte *) stmp, (ubyte4) stmplen,
            pdhctx->kdf_ukm, (ubyte4) pdhctx->kdf_ukmlen, (ubyte4) pdhctx->kdf_outlen, secret);
        if (OK != status)
            goto err;
    }

    *secretlen = pdhctx->kdf_outlen;
    ret = 1;
err:
    (void) DIGI_MEMSET_FREE(&stmp, stmplen);
    return ret;
}
#endif

static int digiprov_dh_derive(void *vpdhctx, unsigned char *secret,
                              size_t *psecretlen, size_t outlen)
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;

    if (!digiprov_is_running())
        return 0;
    
    switch (pdhctx->kdf_type) {
        case PROV_DH_KDF_NONE:
            return digiprov_dh_plain_derive(pdhctx, secret, psecretlen, outlen, pdhctx->pad);
        case PROV_DH_KDF_X9_42_ASN1:
            return 0; /* digiprov_dh_X9_42_kdf_derive(pdhctx, secret, psecretlen, outlen); */
        default:
            break;
    }
    return 0;
}

static void digiprov_dh_freectx(void *vpdhctx)
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;

    (void) DIGI_FREE((void **) &pdhctx->kdf_cekalg);
    DH_free(pdhctx->dh);
    DH_free(pdhctx->dhpeer);
    EVP_MD_free(pdhctx->kdf_md);
    (void) DIGI_MEMSET_FREE(&pdhctx->kdf_ukm, pdhctx->kdf_ukmlen);

    (void) DIGI_FREE((void **) &pdhctx);
}

static void *digiprov_dh_dupctx(void *vpdhctx)
{
    MSTATUS status = OK;
    DP_DH_CTX *srcctx = (DP_DH_CTX *)vpdhctx;
    DP_DH_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(DP_DH_CTX));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    dstctx->dh = NULL;
    dstctx->dhpeer = NULL;
    dstctx->kdf_md = NULL;
    dstctx->kdf_ukm = NULL;
    dstctx->kdf_cekalg = NULL;

    if (srcctx->dh != NULL && !DH_up_ref(srcctx->dh))
        goto err;
    else
        dstctx->dh = srcctx->dh;

    if (srcctx->dhpeer != NULL && !DH_up_ref(srcctx->dhpeer))
        goto err;
    else
        dstctx->dhpeer = srcctx->dhpeer;

    if (srcctx->kdf_md != NULL && !EVP_MD_up_ref(srcctx->kdf_md))
        goto err;
    else
        dstctx->kdf_md = srcctx->kdf_md;

    /* Duplicate UKM data if present */
    if (srcctx->kdf_ukm != NULL && srcctx->kdf_ukmlen > 0) 
    {
        status = DIGI_MALLOC_MEMCPY((void **) &dstctx->kdf_ukm, srcctx->kdf_ukmlen, srcctx->kdf_ukm, srcctx->kdf_ukmlen);
        if (OK != status)
            goto err;
    }

    if (srcctx->kdf_cekalg != NULL) 
    {
        status = digiprov_strdup((void **) &dstctx->kdf_cekalg, srcctx->kdf_cekalg);
        if (OK != status)
            goto err;
    }

    return dstctx;
err:
    digiprov_dh_freectx(dstctx);
    return NULL;
}

static int digiprov_dh_set_ctx_params(void *vpdhctx, const OSSL_PARAM params[])
{
#if 0
    MSTATUS status = OK;
#endif
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;
    const OSSL_PARAM *p;
    unsigned int pad;
    char name[80] = { '\0' }; /* should be big enough */
    char *str = NULL;

    if (pdhctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL)
    {
        str = name;
        if (!digiprov_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        if (name[0] == '\0')
            pdhctx->kdf_type = PROV_DH_KDF_NONE;
        else if (DIGI_STRCMP((const sbyte *) name, (const sbyte *) OSSL_KDF_NAME_X942KDF_ASN1) == 0)
        {
            return 0;
            /* pdhctx->kdf_type = PROV_DH_KDF_X9_42_ASN1; */
        }
        else
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL) 
    {
        return 0;
#if 0
        char mdprops[80] = { '\0' }; /* should be big enough */

        str = name;
        if (!digiprov_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        str = mdprops;
        p = OSSL_PARAM_locate_const(params,
                                    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);

        if (p != NULL) {
            if (!digiprov_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(pdhctx->kdf_md);
        pdhctx->kdf_md = EVP_MD_fetch(pdhctx->libctx, name, mdprops);
        if (!ossl_digest_is_allowed(pdhctx->libctx, pdhctx->kdf_md)) {
            EVP_MD_free(pdhctx->kdf_md);
            pdhctx->kdf_md = NULL;
        }
        if (pdhctx->kdf_md == NULL)
            return 0;
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL) 
    {
        return 0;
#if 0
        size_t outlen;

        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return 0;
        pdhctx->kdf_outlen = outlen;
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL)
    {
        return 0;
#if 0
        void *tmp_ukm = NULL;
        size_t tmp_ukmlen;

        (void) DIGI_FREE((void **) &pdhctx->kdf_ukm);
        pdhctx->kdf_ukm = NULL;
        pdhctx->kdf_ukmlen = 0;
        /* ukm is an optional field so it can be NULL */
        if (p->data != NULL && p->data_size != 0) {
            if (!digiprov_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen))
                return 0;
            pdhctx->kdf_ukm = tmp_ukm;
            pdhctx->kdf_ukmlen = tmp_ukmlen;
        }
#endif
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        pdhctx->pad = pad ? 1 : 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
    if (p != NULL)
    {
        return 0;
#if 0
        str = name;

        (void) DIGI_FREE((void **) &pdhctx->kdf_cekalg);
        pdhctx->kdf_cekalg = NULL;
        if (p->data != NULL && p->data_size != 0) {
            if (!digiprov_get_utf8_string(p, &str, sizeof(name)))
                return 0;
            status = digiprov_strdup((void **) &pdhctx->kdf_cekalg, name);
             if (OK != status)
                return 0;
        }
#endif
    }
    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
{
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
#if 0
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
#endif
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dh_settable_ctx_params(ossl_unused void *vpdhctx,
                                                         ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
{
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dh_gettable_ctx_params(ossl_unused void *vpdhctx,
                                                         ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_dh_get_ctx_params(void *vpdhctx, OSSL_PARAM params[])
{
    DP_DH_CTX *pdhctx = (DP_DH_CTX *)vpdhctx;
    OSSL_PARAM *p;

    if (pdhctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        const char *kdf_type = NULL;

        switch (pdhctx->kdf_type) {
            case PROV_DH_KDF_NONE:
                kdf_type = "";
                break;
            case PROV_DH_KDF_X9_42_ASN1:
                kdf_type = OSSL_KDF_NAME_X942KDF_ASN1;
                break;
            default:
                return 0;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdf_type))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_md == NULL
                                           ? ""
                                           : EVP_MD_get0_name(pdhctx->kdf_md)))
    {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pdhctx->kdf_outlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, pdhctx->kdf_ukm, pdhctx->kdf_ukmlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CEK_ALG);
    if (p != NULL
            && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_cekalg == NULL
                                           ? "" :  pdhctx->kdf_cekalg))
        return 0;

    return 1;
}

const OSSL_DISPATCH digiprov_dh_keyexch_functions[] = 
{
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (void (*)(void))digiprov_dh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT,                (void (*)(void))digiprov_dh_init },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (void (*)(void))digiprov_dh_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER,            (void (*)(void))digiprov_dh_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (void (*)(void))digiprov_dh_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (void (*)(void))digiprov_dh_dupctx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (void (*)(void))digiprov_dh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_dh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,      (void (*)(void))digiprov_dh_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_dh_gettable_ctx_params },
    { 0, NULL }
};
