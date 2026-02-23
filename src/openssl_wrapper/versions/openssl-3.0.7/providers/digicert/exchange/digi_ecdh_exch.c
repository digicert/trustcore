/*
 * digi_ecdh_exch.c
 *
 * ECDH implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL code
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
#include "../../../src/common/mrtos.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto_interface/crypto_interface_ansix9_63_kdf.h"
#include "../../../src/crypto_interface/crypto_interface_ecc.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

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
#include "crypto/ec.h"

enum kdf_type 
{
    PROV_ECDH_KDF_NONE = 0,
    PROV_ECDH_KDF_X9_63
};

/*
 * Based on OpenSSL's DP_ECDH_CTX
 */

typedef struct 
{
    OSSL_LIB_CTX *libctx;

    EC_KEY *k;
    EC_KEY *peerk;

    /*
     * ECDH cofactor mode:
     *
     *  . 0  disabled
     *  . 1  enabled
     *  . -1 use cofactor mode set for k
     */
    int cofactor_mode;

    /************
     * ECDH KDF *
     ************/
    /* KDF (if any) to use for ECDH */
    enum kdf_type kdf_type;
    /* Message digest to use for key derivation */
    EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;

} DP_ECDH_CTX;

int moc_compute_ecdh_key(unsigned char **ppOut, size_t *pOutLen, const EC_POINT *pPubPoint, const EC_KEY *pKey);
static int digiprov_ecdh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[]);

static void *digiprov_ecdh_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_ECDH_CTX *pectx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pectx, 1, sizeof(DP_ECDH_CTX));
    if (OK != status)
        return NULL;

    pectx->libctx = PROV_LIBCTX_OF(provctx);
    pectx->cofactor_mode = -1;
    pectx->kdf_type = PROV_ECDH_KDF_NONE;

    return (void *)pectx;
}

static int digiprov_ecdh_init(void *vpecdhctx, void *vecdh, const OSSL_PARAM params[])
{
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;

    if (!digiprov_is_running())
        return 0;

    if (pecdhctx == NULL || vecdh == NULL || !EC_KEY_up_ref(vecdh))
        return 0;

    EC_KEY_free(pecdhctx->k);
    pecdhctx->k = vecdh;
    pecdhctx->cofactor_mode = -1;
    pecdhctx->kdf_type = PROV_ECDH_KDF_NONE;
    return digiprov_ecdh_set_ctx_params(pecdhctx, params)
           && ossl_ec_check_key(pecdhctx->libctx, vecdh, 1);
}

static int digiprov_ecdh_match_params(const EC_KEY *priv, const EC_KEY *peer)
{
    int ret;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group_priv = EC_KEY_get0_group(priv);
    const EC_GROUP *group_peer = EC_KEY_get0_group(peer);

    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(priv));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = group_priv != NULL
          && group_peer != NULL
          && EC_GROUP_cmp(group_priv, group_peer, ctx) == 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    BN_CTX_free(ctx);
    return ret;
}

static int digiprov_ecdh_set_peer(void *vpecdhctx, void *vecdh)
{
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;

    if (!digiprov_is_running())
        return 0;

    if (pecdhctx == NULL || vecdh == NULL || !digiprov_ecdh_match_params(pecdhctx->k, vecdh)
       || !ossl_ec_check_key(pecdhctx->libctx, vecdh, 1) || !EC_KEY_up_ref(vecdh))
        return 0;

    EC_KEY_free(pecdhctx->peerk);
    pecdhctx->peerk = vecdh;
    return 1;
}

static void digiprov_ecdh_freectx(void *vpecdhctx)
{
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;

    EC_KEY_free(pecdhctx->k);
    EC_KEY_free(pecdhctx->peerk);

    EVP_MD_free(pecdhctx->kdf_md);

    (void) DIGI_MEMSET_FREE(&pecdhctx->kdf_ukm, pecdhctx->kdf_ukmlen);
    (void) DIGI_FREE((void **) &pecdhctx);
}

static void *digiprov_ecdh_dupctx(void *vpecdhctx)
{
    MSTATUS status = OK;
    DP_ECDH_CTX *srcctx = (DP_ECDH_CTX *)vpecdhctx;
    DP_ECDH_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(DP_ECDH_CTX));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;

    /* clear all pointers */

    dstctx->k= NULL;
    dstctx->peerk = NULL;
    dstctx->kdf_md = NULL;
    dstctx->kdf_ukm = NULL;

    /* up-ref all ref-counted objects referenced in dstctx */

    if (srcctx->k != NULL && !EC_KEY_up_ref(srcctx->k))
        goto err;
    else
        dstctx->k = srcctx->k;

    if (srcctx->peerk != NULL && !EC_KEY_up_ref(srcctx->peerk))
        goto err;
    else
        dstctx->peerk = srcctx->peerk;

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

    return (void *) dstctx;

 err:
    digiprov_ecdh_freectx(dstctx);
    return NULL;
}

static int digiprov_ecdh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[])
{
    char name[80] = { '\0' }; /* should be big enough */
    char *str = NULL;
    DP_ECDH_CTX *pectx = (DP_ECDH_CTX *)vpecdhctx;
    const OSSL_PARAM *p;

    if (pectx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p != NULL) {
        int mode;

        if (!OSSL_PARAM_get_int(p, &mode))
            return 0;

        if (mode < -1 || mode > 1)
            return 0;

        pectx->cofactor_mode = mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        str = name;
        if (!digiprov_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        if (name[0] == '\0')
            pectx->kdf_type = PROV_ECDH_KDF_NONE;
        else if (DIGI_STRCMP((const sbyte *) name, (const sbyte *) OSSL_KDF_NAME_X963KDF) == 0)
            pectx->kdf_type = PROV_ECDH_KDF_X9_63;
        else
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL) {
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

        EVP_MD_free(pectx->kdf_md);
        pectx->kdf_md = EVP_MD_fetch(pectx->libctx, name, mdprops);
        if (!ossl_digest_is_allowed(pectx->libctx, pectx->kdf_md)) {
            EVP_MD_free(pectx->kdf_md);
            pectx->kdf_md = NULL;
        }
        if (pectx->kdf_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL) {
        size_t outlen;

        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return 0;
        pectx->kdf_outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL) {
        void *tmp_ukm = NULL;
        size_t tmp_ukmlen;

        if (!digiprov_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen))
            return 0;
        (void) DIGI_FREE((void **) &pectx->kdf_ukm);
        pectx->kdf_ukm = tmp_ukm;
        pectx->kdf_ukmlen = tmp_ukmlen;
    }

    return 1;
}

static const OSSL_PARAM digiprov_known_settable_ctx_params[] = 
{
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *digiprov_ecdh_settable_ctx_params(ossl_unused void *vpecdhctx, ossl_unused void *provctx)
{
    return digiprov_known_settable_ctx_params;
}

static int digiprov_ecdh_get_ctx_params(void *vpecdhctx, OSSL_PARAM params[])
{
    DP_ECDH_CTX *pectx = (DP_ECDH_CTX *)vpecdhctx;
    OSSL_PARAM *p = NULL;

    if (pectx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p != NULL) {
        int mode = pectx->cofactor_mode;

        if (mode == -1) {
            /* check what is the default for pecdhctx->k */
            mode = EC_KEY_get_flags(pectx->k) & EC_FLAG_COFACTOR_ECDH ? 1 : 0;
        }

        if (!OSSL_PARAM_set_int(p, mode))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        const char *kdf_type = NULL;

        switch (pectx->kdf_type) {
            case PROV_ECDH_KDF_NONE:
                kdf_type = "";
                break;
            case PROV_ECDH_KDF_X9_63:
                kdf_type = OSSL_KDF_NAME_X963KDF;
                break;
            default:
                return 0;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdf_type))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL
            && !OSSL_PARAM_set_utf8_string(p, pectx->kdf_md == NULL
                                           ? ""
                                           : EVP_MD_get0_name(pectx->kdf_md))){
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pectx->kdf_outlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, pectx->kdf_ukm, pectx->kdf_ukmlen))
        return 0;

    return 1;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
{
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *digiprov_ecdh_gettable_ctx_params(ossl_unused void *vpecdhctx, ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static ossl_inline size_t digiprov_ecdh_size(const EC_KEY *k)
{
    size_t degree = 0;
    const EC_GROUP *group;

    if (k == NULL || (group = EC_KEY_get0_group(k)) == NULL)
        return 0;

    degree = EC_GROUP_get_degree(group);

    return (degree + 7) / 8;
}

static ossl_inline int digiprov_ecdh_plain_derive(void *vpecdhctx, unsigned char *secret,
                                                  size_t *psecretlen, size_t outlen)
{
    MSTATUS status = OK;
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;
    int ret = 0;
    size_t ecdhsize, size;
    const EC_POINT *ppubkey = NULL;
    EC_KEY *privk = NULL;
    const EC_GROUP *group;
    const BIGNUM *cofactor;
    int key_cofactor_mode;
    ubyte *pOut = NULL;
    size_t tempLen = 0;

    if (pecdhctx->k == NULL || pecdhctx->peerk == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    ecdhsize = digiprov_ecdh_size(pecdhctx->k);
    if (secret == NULL) 
    {
        *psecretlen = ecdhsize;
        return 1;
    }

    if ((group = EC_KEY_get0_group(pecdhctx->k)) == NULL
            || (cofactor = EC_GROUP_get0_cofactor(group)) == NULL )
        return 0;

    /*
     * NB: unlike PKCS#3 DH, if outlen is less than maximum size this is not
     * an error, the result is truncated.
     */
    size = outlen < ecdhsize ? outlen : ecdhsize;

    /*
     * The ctx->cofactor_mode flag has precedence over the
     * cofactor_mode flag set on ctx->k.
     *
     * - if ctx->cofactor_mode == -1, use ctx->k directly
     * - if ctx->cofactor_mode == key_cofactor_mode, use ctx->k directly
     * - if ctx->cofactor_mode != key_cofactor_mode:
     *     - if ctx->k->cofactor == 1, the cofactor_mode flag is irrelevant, use
     *          ctx->k directly
     *     - if ctx->k->cofactor != 1, use a duplicate of ctx->k with the flag
     *          set to ctx->cofactor_mode
     */
    key_cofactor_mode =
        (EC_KEY_get_flags(pecdhctx->k) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    if (pecdhctx->cofactor_mode != -1
            && pecdhctx->cofactor_mode != key_cofactor_mode
            && !BN_is_one(cofactor)) {
        if ((privk = EC_KEY_dup(pecdhctx->k)) == NULL)
            return 0;

        if (pecdhctx->cofactor_mode == 1)
            EC_KEY_set_flags(privk, EC_FLAG_COFACTOR_ECDH);
        else
            EC_KEY_clear_flags(privk, EC_FLAG_COFACTOR_ECDH);
    } else {
        privk = pecdhctx->k;
    }

    ppubkey = EC_KEY_get0_public_key(pecdhctx->peerk);

    ret = moc_compute_ecdh_key(&pOut, &tempLen, ppubkey, privk);
    if (1 != ret)
        goto end;

    status = DIGI_MEMCPY(secret, pOut, (ubyte4) size);
    if (OK != status)
    {
        ret = 0;
        goto end;
    }

    *psecretlen = size;

    /* ret is still 1 */

 end:
    if (NULL != pOut)
    {
        (void) DIGI_MEMSET_FREE(&pOut, tempLen);
    }

    if (privk != pecdhctx->k)
        EC_KEY_free(privk);
    return ret;
}

static ossl_inline int digiprov_ecdh_X9_63_kdf_derive(void *vpecdhctx, unsigned char *secret,
                                                      size_t *psecretlen, size_t outlen)
{
    MSTATUS status = OK;
    MOC_EVP_MD_CTX mdCtx = {0};
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;
    unsigned char *stmp = NULL;
    size_t stmplen;
    int ret = 0;

    if (secret == NULL) 
    {
        *psecretlen = pecdhctx->kdf_outlen;
        return 1;
    }

    if (pecdhctx->kdf_outlen > outlen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (!digiprov_ecdh_plain_derive(vpecdhctx, NULL, &stmplen, 0))
        return 0;
    status = DIGI_MALLOC((void ** )&stmp, stmplen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!digiprov_ecdh_plain_derive(vpecdhctx, stmp, &stmplen, stmplen))
        goto err;

    DIGI_EVP_setDigestAlgo( &mdCtx, pecdhctx->kdf_md->type);
    if (NULL == mdCtx.pDigestAlgo)
        goto err;
    
    status = CRYPTO_INTERFACE_ANSIX963KDF_generate(
        mdCtx.pDigestAlgo->pHashAlgo, (ubyte *) stmp, (ubyte4) stmplen,
        pecdhctx->kdf_ukm, (ubyte4) pecdhctx->kdf_ukmlen, (ubyte4) pecdhctx->kdf_outlen, secret);
    if (OK != status)
        goto err;

    *psecretlen = pecdhctx->kdf_outlen;
    ret = 1;

err:
    (void) DIGI_MEMSET_FREE(&stmp, stmplen);
    return ret;
}

static int digiprov_ecdh_derive(void *vpecdhctx, unsigned char *secret,
                                size_t *psecretlen, size_t outlen)
{
    DP_ECDH_CTX *pecdhctx = (DP_ECDH_CTX *)vpecdhctx;

    switch (pecdhctx->kdf_type) {
        case PROV_ECDH_KDF_NONE:
            return digiprov_ecdh_plain_derive(vpecdhctx, secret, psecretlen, outlen);
        case PROV_ECDH_KDF_X9_63:
            return digiprov_ecdh_X9_63_kdf_derive(vpecdhctx, secret, psecretlen, outlen);
        default:
            break;
    }
    return 0;
}

const OSSL_DISPATCH digiprov_ecdh_keyexch_functions[] =
{
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (void (*)(void))digiprov_ecdh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT,                (void (*)(void))digiprov_ecdh_init },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (void (*)(void))digiprov_ecdh_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER,            (void (*)(void))digiprov_ecdh_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (void (*)(void))digiprov_ecdh_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (void (*)(void))digiprov_ecdh_dupctx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (void (*)(void))digiprov_ecdh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_ecdh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,      (void (*)(void))digiprov_ecdh_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_ecdh_gettable_ctx_params },
    { 0, NULL }
};
