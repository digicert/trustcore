/*
 * digi_rsa_keymgmt.c
 *
 * RSA keygen implementations for OSSL 3.0 provider ADAPTED from OPENSSL code
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
#include "../../../src/crypto/hw_accel.h"

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
#include "openssl/param_build.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "openssl/rsa.h"
#include "crypto/rsa.h"
#include "crypto/rsa/rsa_local.h"
#include "digiprov.h"

/*------------------------------------------------ DEFINES ------------------------------------------------*/

#define rsa_gen_basic                                           \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),          \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),        \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0)

#define rsa_gen_pss                                                     \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),        \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),  \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),   \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),   \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL)

# define RSA_KEY_MP_TYPES()                                                    \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR3, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR4, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR5, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR6, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR7, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR8, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR9, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR10, NULL, 0),                          \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT3, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT4, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT5, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT6, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT7, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT8, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT9, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT10, NULL, 0),                        \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT2, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT3, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT4, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT5, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT6, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT7, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT8, NULL, 0),                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT9, NULL, 0),

#define RSA_KEY_TYPES()                                                        \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),                                 \
RSA_KEY_MP_TYPES()

#define RSA_DEFAULT_MD "SHA256"
#define RSA_PSS_DEFAULT_MD OSSL_DIGEST_NAME_SHA1
#define RSA_POSSIBLE_SELECTIONS                                        \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

static const OSSL_PARAM digiprov_rsa_params[] = 
{
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
#if 0    
    OSSL_PARAM_octet_string("tapbuffer", NULL, 0),
    OSSL_PARAM_int("istap", NULL),
#endif
    RSA_KEY_TYPES()
    OSSL_PARAM_END
};

static const OSSL_PARAM digiprov_rsa_key_types[] = {
    RSA_KEY_TYPES()
    OSSL_PARAM_END
};

/* Based on struct rsa_gen_ctx in ossl rsa_kmgmt.c */
typedef struct DP_RSA_CTX 
{
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int rsa_type;
    size_t nbits;
    BIGNUM *pub_exp;
    size_t primes;
    RSA_PSS_PARAMS_30 pss_params;
    int pss_defaults_set;

} DP_RSA_CTX ;

int moc_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int moc_get_rsa_ex_app_data();

static const OSSL_PARAM *digiprov_rsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return digiprov_rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *digiprov_rsa_import_types(int selection)
{
    return digiprov_rsa_imexport_types(selection);
}

static const OSSL_PARAM *digiprov_rsa_export_types(int selection)
{
    return digiprov_rsa_imexport_types(selection);
}

static const OSSL_PARAM *digiprov_rsa_gettable_params(void *provctx)
{
    return digiprov_rsa_params;
}

static int digiprov_pss_params_fromdata(RSA_PSS_PARAMS_30 *pss_params, int *defaults_set,
                               const OSSL_PARAM params[], int rsa_type,
                               OSSL_LIB_CTX *libctx)
{
    if (!ossl_rsa_pss_params_30_fromdata(pss_params, defaults_set,
                                         params, libctx))
        return 0;

    /* If not a PSS type RSA, sending us PSS parameters is wrong */
    if (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
        && !ossl_rsa_pss_params_30_is_unrestricted(pss_params))
        return 0;

    return 1;
}

/*------------------------------------------- RSA KEY MANAGEMENT -------------------------------------------*/

static const OSSL_PARAM *digiprov_rsa_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        rsa_gen_basic,
        OSSL_PARAM_END
    };

    return settable;
}

static const OSSL_PARAM *digiprov_rsapss_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = 
    {
        rsa_gen_basic,
        rsa_gen_pss,
        OSSL_PARAM_END
    };

    return settable;
}

static int digiprov_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    DP_RSA_CTX *pRsaGenCtx = (DP_RSA_CTX *)genctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if (NULL == pRsaGenCtx)
    {
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &pRsaGenCtx->nbits))
            return 0;
        if (pRsaGenCtx->nbits < RSA_MIN_MODULUS_BITS) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            return 0;
        }
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL
        && !OSSL_PARAM_get_size_t(p, &pRsaGenCtx->primes))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
        && !OSSL_PARAM_get_BN(p, &pRsaGenCtx->pub_exp))
        return 0;
    
    /* Only attempt to get PSS parameters when generating an RSA-PSS key */
    if (pRsaGenCtx->rsa_type == RSA_FLAG_TYPE_RSASSAPSS
        && !digiprov_pss_params_fromdata(&pRsaGenCtx->pss_params, &pRsaGenCtx->pss_defaults_set, params,
                                pRsaGenCtx->rsa_type, pRsaGenCtx->libctx))
        return 0;

    return 1;
}

static void *digiprov_rsa_gen_init_ex(void *provctx, int selection, const OSSL_PARAM params[], int rsa_type)
{
    MSTATUS status = ERR_GENERAL;
    DP_RSA_CTX *pRsaGenCtx = NULL;
    DP_RSA_CTX *pRet = NULL;

    if (!digiprov_is_running())
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    status = DIGI_CALLOC((void **)&pRsaGenCtx, 1, sizeof(struct DP_RSA_CTX));
    if (OK != status)
        goto exit;

    pRsaGenCtx->pub_exp = BN_new();
    if (NULL == pRsaGenCtx->pub_exp)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 != BN_set_word(pRsaGenCtx->pub_exp, RSA_F4))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    /* set defaults */
    pRsaGenCtx->nbits = 2048;
    pRsaGenCtx->primes = RSA_DEFAULT_PRIME_NUM;
    pRsaGenCtx->rsa_type = rsa_type;
    pRsaGenCtx->libctx = PROV_LIBCTX_OF(provctx);

    if (1 != digiprov_rsa_gen_set_params((void *)pRsaGenCtx, params))
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = OK;
    pRet = pRsaGenCtx;
    pRsaGenCtx = NULL;

exit:

    if (NULL != pRsaGenCtx)
    {
        DIGI_FREE((void **)&pRsaGenCtx);
    }

    return pRet;
}

static void *digiprov_rsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return digiprov_rsa_gen_init_ex(provctx, selection, params, RSA_FLAG_TYPE_RSA);
}

static void *digiprov_rsapss_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return digiprov_rsa_gen_init_ex(provctx, selection, params, RSA_FLAG_TYPE_RSASSAPSS);
}

static void *digiprov_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    DP_RSA_CTX *pRsaGenCtx = (DP_RSA_CTX *)genctx;
    RSA *pRsa = NULL;
    RSA *pRet = NULL;

    if (!digiprov_is_running())
        return NULL;

    if (NULL == genctx)
    {
        return NULL;
    }

    pRsa = RSA_new();
    if (NULL == pRsa)
    {
        return NULL;
    }

    if (1 != moc_rsa_keygen(pRsa, pRsaGenCtx->nbits, pRsaGenCtx->pub_exp, NULL))
    {
        goto exit;
    }

    if (1 != ossl_rsa_pss_params_30_copy(ossl_rsa_get0_pss_params_30(pRsa),
                                     &pRsaGenCtx->pss_params))
    {
        goto exit;
    }

    RSA_clear_flags(pRsa, RSA_FLAG_TYPE_MASK);
    RSA_set_flags(pRsa, pRsaGenCtx->rsa_type);

    pRet = pRsa;
    pRsa = NULL;

exit:

    if (NULL != pRsa)
    {
        RSA_free(pRsa);
    }

    return pRet;
}

static int digiprov_rsa_get_params(void *key, OSSL_PARAM params[])
{
    RSA *rsa = (RSA *)key;
    const RSA_PSS_PARAMS_30 *pss_params = ossl_rsa_get0_pss_params_30(rsa);
    int rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);
    OSSL_PARAM *p;
    int empty = RSA_get0_n(rsa) == NULL;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && (empty || !OSSL_PARAM_set_int(p, RSA_bits(rsa))))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && (empty || !OSSL_PARAM_set_int(p, RSA_security_bits(rsa))))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && (empty || !OSSL_PARAM_set_int(p, RSA_size(rsa))))
        return 0;

    /*
     * For restricted RSA-PSS keys, we ignore the default digest request.
     * With RSA-OAEP keys, this may need to be amended.
     */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
            || ossl_rsa_pss_params_30_is_unrestricted(pss_params))) {
        if (!OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD))
            return 0;
    }

    /*
     * For non-RSA-PSS keys, we ignore the mandatory digest request.
     * With RSA-OAEP keys, this may need to be amended.
     */
    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && rsa_type == RSA_FLAG_TYPE_RSASSAPSS
        && !ossl_rsa_pss_params_30_is_unrestricted(pss_params)) {
        const char *mdname =
            ossl_rsa_oaeppss_nid2name(ossl_rsa_pss_params_30_hashalg(pss_params));

        if (mdname == NULL || !OSSL_PARAM_set_utf8_string(p, mdname))
            return 0;
    }

    return (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
            || ossl_rsa_pss_params_30_todata(pss_params, NULL, params))
        && ossl_rsa_todata(rsa, NULL, params, 1);
}

static void digiprov_rsa_gen_cleanup(void *genctx)
{
    DP_RSA_CTX *pRsaGenCtx = (DP_RSA_CTX *)genctx;
    if (NULL != genctx)
    {
        BN_clear_free(pRsaGenCtx->pub_exp);
        DIGI_FREE((void **)&pRsaGenCtx);
    }
}

static int pss_params_fromdata(RSA_PSS_PARAMS_30 *pss_params, int *defaults_set,
                               const OSSL_PARAM params[], int rsa_type,
                               OSSL_LIB_CTX *libctx)
{
    if (!ossl_rsa_pss_params_30_fromdata(pss_params, defaults_set,
                                         params, libctx))
        return 0;

    /* If not a PSS type RSA, sending us PSS parameters is wrong */
    if (rsa_type != RSA_FLAG_TYPE_RSASSAPSS
        && !ossl_rsa_pss_params_30_is_unrestricted(pss_params))
        return 0;

    return 1;
}

/* No use case for import/export of TAP keys at this point. Code here in
   case it ever is needed */
#if 0    
static int digiprov_rsa_tap_import(RSA *rsa, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    ubyte *pSerKey = NULL;
    size_t serKeyLen = 0;
    int ok = 0;

    OSSL_PARAM *p;
    MOC_EVP_KEY_DATA *pMocKeyData = NULL;

    if (NULL == rsa)
        return 0;

    p = OSSL_PARAM_locate(params, "tapbuffer");
    if (NULL != p)
    {
        if (!digiprov_get_octet_string(p, (void **) &pSerKey, 0, &serKeyLen))
            goto exit;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (NULL != p)
    {
        if(!OSSL_PARAM_get_BN(p, &rsa->n))
            goto exit;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (NULL != p)
    {
        if(!OSSL_PARAM_get_BN(p, &rsa->e))
            goto exit;
    }

    /* For now we'll allow no public key but make sure pSerKey is there */
    if (NULL == pSerKey)
        goto exit;

    status = DIGI_CALLOC((void **) &pMocKeyData, 1, sizeof(MOC_EVP_KEY_DATA));
    if (OK != status)
        goto exit;

    pMocKeyData->pContents = pSerKey; pSerKey = NULL;
    pMocKeyData->contentsLen = (ubyte4) serKeyLen;

    RSA_set_ex_data(rsa, moc_get_rsa_ex_app_data(), pMocKeyData); pMocKeyData = NULL;

    ok = 1;
    
exit:

    if (NULL != pSerKey)
    {
        (void) DIGI_MEMSET_FREE(&pSerKey, (ubyte4) serKeyLen);
    }

    /* no goto exit after allocation of of pMocKeyData, so no more cleanup needed */
    
    return ok;
}
#endif

static int digiprov_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    RSA *rsa = keydata;
    int rsa_type;
    int ok = 1;
    int pss_defaults_set = 0;

    if (!digiprov_is_running())
        return 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    rsa_type = RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK);

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && pss_params_fromdata(ossl_rsa_get0_pss_params_30(rsa),
                                       &pss_defaults_set,
                                       params, rsa_type,
                                       ossl_rsa_get0_libctx(rsa));
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) 
    {
        int include_private;
#if 0
        OSSL_PARAM *p;
        int istap = 0;

        p = OSSL_PARAM_locate(params, "istap");
        if (NULL != p)
        {
            if(!OSSL_PARAM_get_int(p, &istap))
                return 0;

            if (istap)
            {
                return (ok && digiprov_rsa_tap_import(rsa, params));
            }
        }
#endif
        include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
        ok = ok && ossl_rsa_fromdata(rsa, params, include_private);
    }

    return ok;
}

static int digiprov_rsa_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void *cbarg)
{
    RSA *rsa = keydata;
    const RSA_PSS_PARAMS_30 *pss_params = ossl_rsa_get0_pss_params_30(rsa);
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if (NULL == rsa)
        return 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && (ossl_rsa_pss_params_30_is_unrestricted(pss_params)
                    || ossl_rsa_pss_params_30_todata(pss_params, tmpl, NULL));
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && ossl_rsa_todata(rsa, tmpl, NULL, include_private);
    }

    if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
    {
        ok = 0;
        goto err;
    }

    ok = param_callback(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

static void *digiprov_rsa_newdata(void *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    RSA *rsa = NULL;

    if (!digiprov_is_running())
        return NULL;

    rsa = ossl_rsa_new_with_ctx(libctx);
    if (NULL != rsa) 
    {
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSA);
    }
    return rsa;
}

static void *digiprov_rsapss_newdata(void *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    RSA *rsa = NULL;

    if (!digiprov_is_running())
        return NULL;

    rsa = ossl_rsa_new_with_ctx(libctx);
    if (NULL != rsa) 
    {
        RSA_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
        RSA_set_flags(rsa, RSA_FLAG_TYPE_RSASSAPSS);
    }
    return rsa;
}

static int digiprov_rsa_has(const void *keydata, int selection)
{
    const RSA *rsa = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if (rsa == NULL)
        return 0;
    if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    /* OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && (RSA_get0_e(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (RSA_get0_n(rsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        /* TAP key might have keydata rather than d */
        if (NULL == RSA_get0_d(rsa) && NULL == RSA_get_ex_data(rsa, moc_get_rsa_ex_app_data()))
            ok = 0;
    }

    return ok;
}

static void *digiprov_rsa_common_load(const void *reference, size_t reference_sz, int expected_rsa_type)
{
    RSA *rsa = NULL;

    if (!digiprov_is_running())
        return NULL;

    if (reference_sz == sizeof(rsa)) {
        /* The contents of the reference is the address to our object */
        rsa = *(RSA **)reference;

        if (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) != expected_rsa_type)
            return NULL;

        /* We grabbed, so we detach it */
        *(RSA **)reference = NULL;
        return rsa;
    }
    return NULL;
}

static void *digiprov_rsa_load(const void *reference, size_t reference_sz)
{
    return digiprov_rsa_common_load(reference, reference_sz, RSA_FLAG_TYPE_RSA);
}

static void *digiprov_rsapss_load(const void *reference, size_t reference_sz)
{
    return digiprov_rsa_common_load(reference, reference_sz, RSA_FLAG_TYPE_RSASSAPSS);
}

static void digiprov_rsa_freedata(void *keydata)
{
    RSA_free(keydata);
}

static int digiprov_rsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const RSA *rsa1 = keydata1;
    const RSA *rsa2 = keydata2;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    /* There is always an |e| */
    ok = ok && BN_cmp(RSA_get0_e(rsa1), RSA_get0_e(rsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) 
        {
            const BIGNUM *pa = RSA_get0_n(rsa1);
            const BIGNUM *pb = RSA_get0_n(rsa2);

            if (pa != NULL && pb != NULL)
            {
                ok = ok && BN_cmp(pa, pb) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) 
        {
            const BIGNUM *pa = RSA_get0_d(rsa1);
            const BIGNUM *pb = RSA_get0_d(rsa2);

            if (pa != NULL && pb != NULL) 
            {
                ok = ok && BN_cmp(pa, pb) == 0;
            }
            else /* might be a TAP key */
            {
                sbyte4 cmp = -1;
                MOC_EVP_KEY_DATA *pMocKeyData1 = RSA_get_ex_data(rsa1, moc_get_rsa_ex_app_data());
                MOC_EVP_KEY_DATA *pMocKeyData2 = RSA_get_ex_data(rsa2, moc_get_rsa_ex_app_data());

                if (NULL == pMocKeyData1 || NULL == pMocKeyData2 || pMocKeyData1->contentsLen != pMocKeyData2->contentsLen)
                {
                    ok = 0;
                }
                else
                {
                    (void) DIGI_MEMCMP(pMocKeyData1->pContents, pMocKeyData2->pContents, pMocKeyData1->contentsLen, &cmp);
                    ok = ok && (0 == cmp);
                }
            }
            key_checked = 1;
        }
        ok = ok && key_checked;
    }
    return ok;
}

static void *digiprov_rsa_dup(const void *keydata_from, int selection)
{
    if (!digiprov_is_running())
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ossl_rsa_dup(keydata_from, selection);

    return NULL;
}

static int digiprov_rsa_validate(const void *keydata, int selection, int checktype)
{
    const RSA *rsa = keydata;
    int ok = 1;

    if (!digiprov_is_running())
        return 0;

    if ((selection & RSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR) 
    {
        /* might be a TAP key */
        ok = ok && (ossl_rsa_validate_pairwise(rsa) || (NULL != RSA_get_ex_data(rsa, moc_get_rsa_ex_app_data())));
    }
    else
    {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (ossl_rsa_validate_private(rsa) || (NULL != RSA_get_ex_data(rsa, moc_get_rsa_ex_app_data())));

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && ossl_rsa_validate_public(rsa);
    }
    return ok;
}

/* For any RSA key, we use the "RSA" algorithms regardless of sub-type. */
static const char *digiprov_rsa_query_operation_name(int operation_id)
{
    return "RSA";
}

/*-------------------------------------------- FUNCTION TABLES --------------------------------------------*/

const OSSL_DISPATCH digiprov_rsa_keymgmt_functions[] =
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_rsa_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_rsa_load },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_rsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_rsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_rsa_dup },    
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_rsapss_keymgmt_functions[] =
{
    { OSSL_FUNC_KEYMGMT_NEW,                 (void (*)(void))digiprov_rsapss_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,            (void (*)(void))digiprov_rsapss_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,      (void (*)(void))digiprov_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))digiprov_rsapss_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                 (void (*)(void))digiprov_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,         (void (*)(void))digiprov_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD,                (void (*)(void))digiprov_rsapss_load },
    { OSSL_FUNC_KEYMGMT_FREE,                (void (*)(void))digiprov_rsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,          (void (*)(void))digiprov_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,     (void (*)(void))digiprov_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS,                 (void (*)(void))digiprov_rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH,               (void (*)(void))digiprov_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,            (void (*)(void))digiprov_rsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT,              (void (*)(void))digiprov_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,        (void (*)(void))digiprov_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,              (void (*)(void))digiprov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,        (void (*)(void))digiprov_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,(void (*)(void))digiprov_rsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP,                 (void (*)(void))digiprov_rsa_dup },
    { 0, NULL }
};
