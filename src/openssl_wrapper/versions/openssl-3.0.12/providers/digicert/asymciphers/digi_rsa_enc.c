/*
 * digi_rsa_enc.c
 *
 * RSA enc/dec implementations for OSSL 3.0 provider ADAPTED from OPENSSL code
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
#include "internal/sizes.h"
#include "internal/constant_time.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "openssl/rsa.h"
#include "crypto/rsa.h"
#include "digiprov.h"

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END
};

static OSSL_ITEM padding_item[] = {
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_PKCS1_OAEP_PADDING,   OSSL_PKEY_RSA_PAD_MODE_OAEP }, /* Correct spelling first */
    { RSA_PKCS1_OAEP_PADDING,   "oeap"   },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { 0,                        NULL     }
};

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR,
                    NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END
};

/* Based on struct PROV_RSA_CTX in ossl rsa_enc.c */
typedef struct {
    OSSL_LIB_CTX *libctx;
    RSA *rsa;
    int pad_mode;
    int operation;
    /* OAEP message digest */
    EVP_MD *oaep_md;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
} DP_RSA_CTX;

int moc_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int moc_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

static const OSSL_PARAM *digiprov_rsa_settable_ctx_params(ossl_unused void *vprsactx,
                                                          ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static const OSSL_PARAM * digiprov_rsa_gettable_ctx_params(void *ctx, void *provctx)
{
    return known_gettable_ctx_params;
}

static int digiprov_rsa_cipher_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;
    char mdname[OSSL_MAX_NAME_SIZE];
    char mdprops[OSSL_MAX_PROPQUERY_SIZE] = { '\0' };
    char *str = NULL;

    if (prsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) 
    {
        str = mdname;
        if (!digiprov_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (p != NULL) 
        {
            str = mdprops;
            if (!digiprov_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(prsactx->oaep_md);
        prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, mdname, mdprops);

        if (prsactx->oaep_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;

                if (p->data == NULL)
                    return 0;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) padding_item[i].ptr) == 0) {
                        pad_mode = padding_item[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            return 0;
        }

        /*
         * PSS padding is for signatures only so is not compatible with
         * asymmetric cipher use.
         */
        if (pad_mode == RSA_PKCS1_PSS_PADDING)
            return 0;
        if (pad_mode == RSA_PKCS1_OAEP_PADDING && prsactx->oaep_md == NULL) {
            prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, "SHA1", mdprops);
            if (prsactx->oaep_md == NULL)
                return 0;
        }
        prsactx->pad_mode = pad_mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) 
    {
        str = mdname;
        if (!digiprov_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (p != NULL) {
            str = mdprops;
            if (!digiprov_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        } else {
            str = NULL;
        }

        EVP_MD_free(prsactx->mgf1_md);
        prsactx->mgf1_md = EVP_MD_fetch(prsactx->libctx, mdname, str);

        if (prsactx->mgf1_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void *tmp_label = NULL;
        size_t tmp_labellen;

        if (!digiprov_get_octet_string(p, &tmp_label, 0, &tmp_labellen))
            return 0;
        (void) DIGI_FREE((void **) &prsactx->oaep_label);
        prsactx->oaep_label = (unsigned char *)tmp_label;
        prsactx->oaep_labellen = tmp_labellen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        unsigned int client_version;

        if (!OSSL_PARAM_get_uint(p, &client_version))
            return 0;
        prsactx->client_version = client_version;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        unsigned int alt_version;

        if (!OSSL_PARAM_get_uint(p, &alt_version))
            return 0;
        prsactx->alt_version = alt_version;
    }

    return 1;
}

static void *digiprov_rsa_newctx(void *provctx, const char *propq)
{
    MSTATUS status;
    DP_RSA_CTX *pCtx = NULL;
    
    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_RSA_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);

exit:
    return pCtx;
}

static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;
    char mdname[OSSL_MAX_NAME_SIZE];
    char mdprops[OSSL_MAX_PROPQUERY_SIZE] = { '\0' };
    char *str = NULL;

    if (prsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) 
    {
        str = mdname;
        if (!digiprov_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (p != NULL) 
        {
            str = mdprops;
            if (!digiprov_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(prsactx->oaep_md);
        prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, mdname, mdprops);

        if (prsactx->oaep_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;

                if (p->data == NULL)
                    return 0;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) padding_item[i].ptr) == 0) {
                        pad_mode = padding_item[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            return 0;
        }

        /*
         * PSS padding is for signatures only so is not compatible with
         * asymmetric cipher use.
         */
        if (pad_mode == RSA_PKCS1_PSS_PADDING)
            return 0;
        if (pad_mode == RSA_PKCS1_OAEP_PADDING && prsactx->oaep_md == NULL) {
            prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, "SHA1", mdprops);
            if (prsactx->oaep_md == NULL)
                return 0;
        }
        prsactx->pad_mode = pad_mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        str = mdname;
        if (!digiprov_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        p = OSSL_PARAM_locate_const(params,
                                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (p != NULL) {
            str = mdprops;
            if (!digiprov_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        } else {
            str = NULL;
        }

        EVP_MD_free(prsactx->mgf1_md);
        prsactx->mgf1_md = EVP_MD_fetch(prsactx->libctx, mdname, str);

        if (prsactx->mgf1_md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void *tmp_label = NULL;
        size_t tmp_labellen;

        if (!digiprov_get_octet_string(p, &tmp_label, 0, &tmp_labellen))
            return 0;
        (void) DIGI_FREE((void **) &prsactx->oaep_label);
        prsactx->oaep_label = (unsigned char *)tmp_label;
        prsactx->oaep_labellen = tmp_labellen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        unsigned int client_version;

        if (!OSSL_PARAM_get_uint(p, &client_version))
            return 0;
        prsactx->client_version = client_version;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        unsigned int alt_version;

        if (!OSSL_PARAM_get_uint(p, &alt_version))
            return 0;
        prsactx->alt_version = alt_version;
    }

    return 1;
}

static int digiprov_rsa_encdec_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (!digiprov_is_running())
        return 0;

    if (prsactx == NULL || vrsa == NULL)
        return 0;

    if (!ossl_rsa_check_key(prsactx->libctx, vrsa, operation))
        return 0;

    if (!RSA_up_ref(vrsa))
        return 0;

    RSA_free(prsactx->rsa);
    prsactx->rsa = vrsa;
    prsactx->operation = operation;

    switch (RSA_test_flags(prsactx->rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        prsactx->pad_mode = RSA_PKCS1_PADDING;
        break;
    default:
        /* This should not happen due to the check above */
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return rsa_set_ctx_params(prsactx, params);
}

static int digiprov_rsa_encrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    return digiprov_rsa_encdec_init(ctx, provkey, params, EVP_PKEY_OP_ENCRYPT);
}

static int digiprov_rsa_encrypt(void *ctx, unsigned char *out, size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)ctx;
    int encLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == prsactx)
        return 0;

    if (NULL == out)
    {
        if (NULL == outlen)
            return 0;

        *outlen = RSA_size(prsactx->rsa);
        return 1;
    }

    if (RSA_PKCS1_OAEP_PADDING == prsactx->pad_mode)
    {
        /* we only support sha1 */
        if ( (NID_sha1 != EVP_MD_get_type(prsactx->oaep_md)) || (NULL != prsactx->mgf1_md &&
             (NID_sha1 != EVP_MD_get_type(prsactx->mgf1_md))))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return 0;
        }
    }

    encLen = moc_rsa_pub_enc((int) inlen, in, out, prsactx->rsa, prsactx->pad_mode);
    if (encLen <= 0)
        return encLen;

    if (NULL != outlen)
    {
       *outlen = (size_t) encLen;
    }

    return 1;
}

static int digiprov_rsa_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    return digiprov_rsa_encdec_init(ctx, provkey, params, EVP_PKEY_OP_DECRYPT);
}

static int digiprov_rsa_decrypt(void *ctx, unsigned char *out, size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    int decLen = 0;
    int ret = 0;
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)ctx;
 
    if (!digiprov_is_running())
        return 0;

    if (NULL == prsactx)
        return 0;

    if (NULL == out)
    {
        if (NULL == outlen)
            return 0;

        *outlen = RSA_size(prsactx->rsa);
        return 1;
    }

    if (RSA_PKCS1_OAEP_PADDING == prsactx->pad_mode)
    {
        /* we only support sha1 */
        if ( (NID_sha1 != EVP_MD_get_type(prsactx->oaep_md)) || (NULL != prsactx->mgf1_md &&
             (NID_sha1 != EVP_MD_get_type(prsactx->mgf1_md))))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return 0;
        }
    }
    
    decLen = moc_rsa_priv_dec((int) inlen, in, out, prsactx->rsa, prsactx->pad_mode);

    *outlen = constant_time_select_s(constant_time_msb_s((size_t) decLen), *outlen, (size_t) decLen);
    ret = constant_time_select_int(constant_time_msb((unsigned int) decLen), 0, 1);

    return ret;
}

static void * digiprov_rsa_cipher_dupctx(void *ctx)
{
    MSTATUS status = OK;
    DP_RSA_CTX *srcctx = (DP_RSA_CTX *)ctx;
    DP_RSA_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(*srcctx));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->rsa != NULL && !RSA_up_ref(dstctx->rsa)) {
        (void) DIGI_FREE((void **) &dstctx);
        return NULL;
    }

    if (dstctx->oaep_md != NULL && !EVP_MD_up_ref(dstctx->oaep_md)) {
        RSA_free(dstctx->rsa);
        (void) DIGI_FREE((void **) &dstctx);
        return NULL;
    }

    if (dstctx->mgf1_md != NULL && !EVP_MD_up_ref(dstctx->mgf1_md)) {
        RSA_free(dstctx->rsa);
        EVP_MD_free(dstctx->oaep_md);
        (void) DIGI_FREE((void **) &dstctx);
        return NULL;
    }

    return dstctx;
}

static int digiprov_rsa_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)ctx;
    OSSL_PARAM *p;

    if (prsactx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL)
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_set_int(p, prsactx->pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;
                const char *word = NULL;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (prsactx->pad_mode == (int)padding_item[i].id) {
                        word = padding_item[i].ptr;
                        break;
                    }
                }

                if (word != NULL) {
                    if (!OSSL_PARAM_set_utf8_string(p, word))
                        return 0;
                } else {
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                }
            }
            break;
        default:
            return 0;
        }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, prsactx->oaep_md == NULL
                                                    ? ""
                                                    : EVP_MD_get0_name(prsactx->oaep_md)))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        EVP_MD *mgf1_md = prsactx->mgf1_md == NULL ? prsactx->oaep_md
                                                   : prsactx->mgf1_md;

        if (!OSSL_PARAM_set_utf8_string(p, mgf1_md == NULL
                                           ? ""
                                           : EVP_MD_get0_name(mgf1_md)))
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL &&
        !OSSL_PARAM_set_octet_ptr(p, prsactx->oaep_label,
                                  prsactx->oaep_labellen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, prsactx->client_version))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, prsactx->alt_version))
        return 0;

    return 1;
}

static void digiprov_rsa_cipher_freectx(void *vprsactx)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *) vprsactx;
    if (NULL != prsactx)
    {
        if (NULL != prsactx->rsa)
        {
            RSA_free(prsactx->rsa);
        }
        if (NULL != prsactx->oaep_md)
        {
            EVP_MD_free(prsactx->oaep_md);
        }
        if (NULL != prsactx->mgf1_md)
        {
            EVP_MD_free(prsactx->mgf1_md);
        }
        if (NULL != prsactx->oaep_label)
        {
            (void) DIGI_FREE((void **) &prsactx->oaep_label);
        }

        (void) DIGI_FREE((void **)&prsactx);
    }
}

/*-------------------------------------------- FUNCTION TABLE --------------------------------------------*/

const OSSL_DISPATCH digiprov_rsa_cipher_functions[] =
{
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,            (void (*)(void))digiprov_rsa_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,      (void (*)(void))digiprov_rsa_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,           (void (*)(void))digiprov_rsa_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,      (void (*)(void))digiprov_rsa_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,           (void (*)(void))digiprov_rsa_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,           (void (*)(void))digiprov_rsa_cipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,            (void (*)(void))digiprov_rsa_cipher_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,    (void (*)(void))digiprov_rsa_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_rsa_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,    (void (*)(void))digiprov_rsa_cipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_rsa_settable_ctx_params },
    { 0, NULL }
};
