/*
 * digi_rsa_sig.c
 *
 * RSA s/v implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL code
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
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/mocasymkeys/mocsw/commonrsa.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#include "mocana_glue.h"
#include "digicert_common.h"

#include "internal/deprecated.h"

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
#include "openssl/rsa.h"
#include "crypto/rsa.h"
#include "prov/securitycheck.h"
#include "digiprov.h"
#include "prov/der_rsa.h"

/*------------------------------------------------ DEFINES ------------------------------------------------*/

#define RSA_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1

static const OSSL_PARAM digiprov_settable_ctx_params[] =
{
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM digiprov_settable_ctx_params_no_digest[] =
{
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static OSSL_ITEM padding_item[] =
{
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    OSSL_PKEY_RSA_PAD_MODE_PSS },
    { 0,                        NULL     }
};

/* True if PSS parameters are restricted */
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)

/* Based on struct PROV_RSA_CTX in ossl rsa_sig.c */
typedef struct 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    RSA *rsa;
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int operation;
    unsigned int flag_allow_md : 1;
    int pad_mode;
    int mdnid;
    char mdname[OSSL_MAX_NAME_SIZE];
    int saltlen;
    int min_saltlen;
    unsigned int mgf1_md_set : 1;
    EVP_MD *mgf1_md;
    int mgf1_mdnid;
    char mgf1_mdname[OSSL_MAX_NAME_SIZE]; /* Purely informational */
    
    /* Temp buffer */
    unsigned char *tbuf;

} DP_RSA_CTX;

int moc_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int moc_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md, int sha1_allowed);
const ubyte* getDigest_OID_fromNid(int nid);

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);

/* for PSS only, pss, with sha3 not supported at this point */
static ubyte convertDigest(int osslDigest)
{
    switch(osslDigest)
    {
        case NID_md4:
        case NID_md4WithRSAEncryption:
            return ht_md4;

        case NID_md5:
        case NID_md5WithRSAEncryption:
            return ht_md5;

        case NID_sha1:
        case NID_sha1WithRSAEncryption:
	        return ht_sha1;

        case NID_sha224:
        case NID_sha224WithRSAEncryption:
	        return ht_sha224;

        case NID_sha256:
        case NID_sha256WithRSAEncryption:
	        return ht_sha256;

        case NID_sha384:
        case NID_sha384WithRSAEncryption:
	        return ht_sha384;

        case NID_sha512:
        case NID_sha512WithRSAEncryption:
	        return ht_sha512;
    }

    return ht_none;
}

static int digiprov_setup_tbuf(DP_RSA_CTX *ctx)
{
    MSTATUS status = OK;

    if (NULL != ctx->tbuf)
        return 1;

    status = DIGI_MALLOC((void **) &ctx->tbuf, RSA_size(ctx->rsa));
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void digiprov_free_tbuf(DP_RSA_CTX *ctx)
{
    if (NULL != ctx->tbuf)
    {
        if (NULL != ctx->rsa)
        {   
            ubyte4 len = (ubyte4) RSA_size(ctx->rsa);
            if (len > 0)
            {
                (void) DIGI_MEMSET(ctx->tbuf, 0x00, len);
            }
        }
        (void) DIGI_FREE((void **) &ctx->tbuf);
    }
}

static int digiprov_rsa_pss_compute_saltlen(DP_RSA_CTX *ctx)
{
    int saltlen = ctx->saltlen;
 
    if (saltlen == RSA_PSS_SALTLEN_DIGEST) 
    {
        saltlen = EVP_MD_get_size(ctx->md);
    } 
    else if (saltlen == RSA_PSS_SALTLEN_AUTO || saltlen == RSA_PSS_SALTLEN_MAX)
    {
        saltlen = RSA_size(ctx->rsa) - EVP_MD_get_size(ctx->md) - 2;
        if ((RSA_bits(ctx->rsa) & 0x7) == 1)
            saltlen--;
    }
    if (saltlen < 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return -1;
    } 
    else if (saltlen < ctx->min_saltlen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL,
                       "minimum salt length: %d, actual salt length: %d",
                       ctx->min_saltlen, saltlen);
        return -1;
    }
    return saltlen;
}

/*----------------------------------------------- OSSL FUNCS -----------------------------------------------*/

/* Copied versions of static functions needed from ossl internals */

static unsigned char *digiprov_rsa_generate_signature_aid(
    DP_RSA_CTX *ctx, unsigned char *aid_buf, size_t buf_len, size_t *aid_len)
{
    WPACKET pkt;
    unsigned char *aid = NULL;
    int saltlen;
    RSA_PSS_PARAMS_30 pss_params;
    int ret;

    if (!WPACKET_init_der(&pkt, aid_buf, buf_len)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    switch(ctx->pad_mode) {
    case RSA_PKCS1_PADDING:
        ret = ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption(&pkt, -1,
                                                                 ctx->mdnid);

        if (ret > 0) {
            break;
        } else if (ret == 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "Algorithm ID generation - md NID: %d",
                       ctx->mdnid);
        goto cleanup;
    case RSA_PKCS1_PSS_PADDING:
        saltlen = digiprov_rsa_pss_compute_saltlen(ctx);
        if (saltlen < 0)
            goto cleanup;
        if (!ossl_rsa_pss_params_30_set_defaults(&pss_params)
            || !ossl_rsa_pss_params_30_set_hashalg(&pss_params, ctx->mdnid)
            || !ossl_rsa_pss_params_30_set_maskgenhashalg(&pss_params,
                                                          ctx->mgf1_mdnid)
            || !ossl_rsa_pss_params_30_set_saltlen(&pss_params, saltlen)
            || !ossl_DER_w_algorithmIdentifier_RSA_PSS(&pkt, -1,
                                                       RSA_FLAG_TYPE_RSASSAPSS,
                                                       &pss_params)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }
        break;
    default:
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "Algorithm ID generation - pad mode: %d",
                       ctx->pad_mode);
        goto cleanup;
    }
    if (WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, aid_len);
        aid = WPACKET_get_curr(&pkt);
    }
 cleanup:
    WPACKET_cleanup(&pkt);
    return aid;
}

static int digiprov_rsa_check_padding(const DP_RSA_CTX *prsactx,
                             const char *mdname, const char *mgf1_mdname,
                             int mdnid)
{
    switch (prsactx->pad_mode) 
    {
        case RSA_NO_PADDING:
            if (mdname != NULL || mdnid != NID_undef) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
                return 0;
            }
            break;
        case RSA_X931_PADDING:
            if (RSA_X931_hash_id(mdnid) == -1) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_X931_DIGEST);
                return 0;
            }
            break;
        case RSA_PKCS1_PSS_PADDING:
            if (prsactx->min_saltlen != -1)
                if ((mdname != NULL && !EVP_MD_is_a(prsactx->md, mdname))
                    || (mgf1_mdname != NULL
                        && !EVP_MD_is_a(prsactx->mgf1_md, mgf1_mdname))) {
                    ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
                    return 0;
                }
            break;
        default:
            break;
    }

    return 1;
}

static int digiprov_rsa_check_parameters(DP_RSA_CTX *prsactx, int min_saltlen)
{
    if (prsactx->pad_mode == RSA_PKCS1_PSS_PADDING)
    {
        int max_saltlen;

        /* See if minimum salt length exceeds maximum possible */
        max_saltlen = RSA_size(prsactx->rsa) - EVP_MD_get_size(prsactx->md);
        if ((RSA_bits(prsactx->rsa) & 0x7) == 1)
            max_saltlen--;
        if (min_saltlen < 0 || min_saltlen > max_saltlen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }
        prsactx->min_saltlen = min_saltlen;
    }
    return 1;
}

static int digiprov_rsa_setup_md(DP_RSA_CTX *ctx, const char *mdname, const char *mdprops)
{
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) 
    {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
        int md_nid = ossl_digest_rsa_sign_get_md_nid(ctx->libctx, md,
                                                     sha1_allowed);
        size_t mdname_len = (size_t) DIGI_STRLEN((const sbyte *) mdname);

        if (md == NULL || md_nid <= 0 || !digiprov_rsa_check_padding(ctx, mdname, NULL, md_nid)
            || mdname_len >= sizeof(ctx->mdname)) 
        {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            if (md_nid <= 0)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest=%s", mdname);
            if (mdname_len >= sizeof(ctx->mdname))
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s exceeds name buffer length", mdname);
            EVP_MD_free(md);
            return 0;
        }

        if (!ctx->flag_allow_md) 
        {
            if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname))
            {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest %s != %s", mdname, ctx->mdname);
                EVP_MD_free(md);
                return 0;
            }
            EVP_MD_free(md);
            return 1;
        }

        if (!ctx->mgf1_md_set) 
        {
            if (!EVP_MD_up_ref(md))
            {
                EVP_MD_free(md);
                return 0;
            }
            EVP_MD_free(ctx->mgf1_md);
            ctx->mgf1_md = md;
            ctx->mgf1_mdnid = md_nid;
            (void) DIGI_MEMCPY(ctx->mgf1_mdname, mdname, mdname_len + 1);
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        ctx->mdctx = NULL;
        ctx->md = md;
        ctx->mdnid = md_nid;
        (void) DIGI_MEMCPY(ctx->mdname, mdname, mdname_len + 1);
    }

    return 1;
}

static int digiprov_rsa_setup_mgf1_md(DP_RSA_CTX *ctx, const char *mdname, const char *mdprops)
{
    size_t len = 0;
    EVP_MD *md = NULL;
    int mdnid;

    if (mdprops == NULL)
        mdprops = ctx->propq;

    if ((md = EVP_MD_fetch(ctx->libctx, mdname, mdprops)) == NULL) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s could not be fetched", mdname);
        return 0;
    }
    /* The default for mgf1 is SHA1 - so allow SHA1 */
    if ((mdnid = ossl_digest_rsa_sign_get_md_nid(ctx->libctx, md, 1)) <= 0
        || !digiprov_rsa_check_padding(ctx, NULL, mdname, mdnid)) 
    {
        if (mdnid <= 0)
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                           "digest=%s", mdname);
        EVP_MD_free(md);
        return 0;
    }
    len = (size_t) DIGI_STRLEN((const sbyte *) mdname);
    if (len >= sizeof(ctx->mgf1_mdname))
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s exceeds name buffer length", mdname);
        EVP_MD_free(md);
        return 0;
    }
    (void) DIGI_MEMCPY(ctx->mgf1_mdname, mdname, len + 1);

    EVP_MD_free(ctx->mgf1_md);
    ctx->mgf1_md = md;
    ctx->mgf1_mdnid = mdnid;
    ctx->mgf1_md_set = 1;
    return 1;
}

/*-------------------------------------------- RSA SIGN/VERIFY --------------------------------------------*/

static const OSSL_PARAM *digiprov_rsa_settable_ctx_params(void *vprsactx, ossl_unused void *provctx)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx != NULL && !prsactx->flag_allow_md)
        return digiprov_settable_ctx_params_no_digest;
    return digiprov_settable_ctx_params;
}

static int digiprov_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    DP_RSA_CTX *pCtx = (DP_RSA_CTX *)vprsactx;
    int pad_mode;
    int saltlen;
    const OSSL_PARAM *p;
    char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = NULL;
    char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = NULL;
    char mgf1mdname[OSSL_MAX_NAME_SIZE] = "", *pmgf1mdname = NULL;
    char mgf1mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmgf1mdprops = NULL;

    if (NULL == pCtx)
    {
        return 0;
    }

    if (NULL == params)
    {
        return 1;
    }

    pad_mode = pCtx->pad_mode;
    saltlen = pCtx->saltlen;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        pmdname = mdname;
        if (!digiprov_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;

        if (propsp != NULL)
        {
            pmdprops = mdprops;
            if (!digiprov_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        const char *err_extra_text = NULL;

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

        switch (pad_mode) {
        case RSA_PKCS1_OAEP_PADDING:
            /*
             * OAEP padding is for asymmetric cipher only so is not compatible
             * with signature use.
             */
            err_extra_text = "OAEP padding not allowed for signing / verifying";
            goto bad_pad;
        case RSA_PKCS1_PSS_PADDING:
            if ((pCtx->operation
                 & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)) == 0) {
                err_extra_text =
                    "PSS padding only allowed for sign and verify operations";
                goto bad_pad;
            }
            break;
        case RSA_PKCS1_PADDING:
            err_extra_text = "PKCS#1 padding not allowed with RSA-PSS";
            goto cont;
        case RSA_NO_PADDING:
            err_extra_text = "No padding not allowed with RSA-PSS";
            goto cont;
        case RSA_X931_PADDING:
            err_extra_text = "X.931 padding not allowed with RSA-PSS";
        cont:
            if (RSA_test_flags(pCtx->rsa,
                               RSA_FLAG_TYPE_MASK) == RSA_FLAG_TYPE_RSA)
                break;
            /* FALLTHRU */
        default:
        bad_pad:
            if (err_extra_text == NULL)
                ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            else
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
                               err_extra_text);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (pad_mode != RSA_PKCS1_PSS_PADDING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "PSS saltlen can only be specified if "
                           "PSS padding has been specified first");
            return 0;
        }

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &saltlen))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_MAX;
            else if (DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO;
            else
                saltlen = atoi(p->data);
            break;
        default:
            return 0;
        }

        /*
         * RSA_PSS_SALTLEN_MAX seems curiously named in this check.
         * Contrary to what it's name suggests, it's the currently
         * lowest saltlen number possible.
         */
        if (saltlen < RSA_PSS_SALTLEN_MAX) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }

        if (rsa_pss_restricted(pCtx)) {
            switch (saltlen) {
            case RSA_PSS_SALTLEN_AUTO:
                if (pCtx->operation == EVP_PKEY_OP_VERIFY) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH,
                                   "Cannot use autodetected salt length");
                    return 0;
                }
                break;
            case RSA_PSS_SALTLEN_DIGEST:
                if (pCtx->min_saltlen > EVP_MD_get_size(pCtx->md)) {
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                   "Should be more than %d, but would be "
                                   "set to match digest size (%d)",
                                   pCtx->min_saltlen,
                                   EVP_MD_get_size(pCtx->md));
                    return 0;
                }
                break;
            default:
                if (saltlen >= 0 && saltlen < pCtx->min_saltlen) {
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                   "Should be more than %d, "
                                   "but would be set to %d",
                                   pCtx->min_saltlen, saltlen);
                    return 0;
                }
            }
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL)
    {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);

        pmgf1mdname = mgf1mdname;
        if (!digiprov_get_utf8_string(p, &pmgf1mdname, sizeof(mgf1mdname)))
            return 0;

        if (propsp != NULL)
        {
            pmgf1mdprops = mgf1mdprops;
            if (!digiprov_get_utf8_string(propsp, &pmgf1mdprops, sizeof(mgf1mdprops)))
                return 0;
        }

        if (pad_mode != RSA_PKCS1_PSS_PADDING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return  0;
        }
    }

    pCtx->saltlen = saltlen;
    pCtx->pad_mode = pad_mode;

    if (pCtx->md == NULL && pmdname == NULL
        && pad_mode == RSA_PKCS1_PSS_PADDING)
        pmdname = RSA_DEFAULT_DIGEST_NAME;

    if (pmgf1mdname != NULL
        && !digiprov_rsa_setup_mgf1_md(pCtx, pmgf1mdname, pmgf1mdprops))
        return 0;

    if (pmdname != NULL) {
        if (!digiprov_rsa_setup_md(pCtx, pmdname, pmdprops))
            return 0;
    } else {
        if (!digiprov_rsa_check_padding(pCtx, NULL, NULL, pCtx->mdnid))
            return 0;
    }
    return 1;
}

static void *digiprov_rsa_newctx(void *provctx, const char *propq)
{
    MSTATUS status = OK;
    DP_RSA_CTX *pCtx = NULL;
    char *propq_copy = NULL;
    
    if (!digiprov_is_running())
        return NULL;

    if (NULL != propq)
    {
        status = digiprov_strdup((void **) &propq_copy, propq);
        if (OK != status)
            goto exit;
    }

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_RSA_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);
    pCtx->flag_allow_md = 1;
    pCtx->propq = propq_copy; propq_copy = NULL;

    /* Maximum for sign, auto for verify */
    pCtx->saltlen = RSA_PSS_SALTLEN_AUTO;
    pCtx->min_saltlen = -1;

exit:

    if (NULL != propq_copy)
    {
        (void) DIGI_FREE((void **) &propq_copy);
    }

    /* last thing allocated is pCtx so no need to clean it up on err */

    return pCtx;
}

static int digiprov_rsa_sv_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (!digiprov_is_running())
        return 0;

    if (NULL == prsactx)
        return 0;

    if (NULL == vrsa && NULL == prsactx->rsa) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vrsa != NULL) 
    {
        if (!ossl_rsa_check_key(prsactx->libctx, vrsa, operation))
            return 0;

        if (!RSA_up_ref(vrsa))
            return 0;
        RSA_free(prsactx->rsa);
        prsactx->rsa = vrsa;
    }

    prsactx->operation = operation;

    /* Maximum for sign, auto for verify */
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO;
    prsactx->min_saltlen = -1;

    switch (RSA_test_flags(prsactx->rsa, RSA_FLAG_TYPE_MASK)) 
    {
        case RSA_FLAG_TYPE_RSA:
            prsactx->pad_mode = RSA_PKCS1_PADDING;
            break;
        case RSA_FLAG_TYPE_RSASSAPSS:
            prsactx->pad_mode = RSA_PKCS1_PSS_PADDING;
            {
                const RSA_PSS_PARAMS_30 *pss =
                    ossl_rsa_get0_pss_params_30(prsactx->rsa);

                if (!ossl_rsa_pss_params_30_is_unrestricted(pss)) {
                    int md_nid = ossl_rsa_pss_params_30_hashalg(pss);
                    int mgf1md_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);
                    int min_saltlen = ossl_rsa_pss_params_30_saltlen(pss);
                    const char *mdname, *mgf1mdname;
                    size_t len;

                    mdname = ossl_rsa_oaeppss_nid2name(md_nid);
                    mgf1mdname = ossl_rsa_oaeppss_nid2name(mgf1md_nid);

                    if (mdname == NULL) {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                    "PSS restrictions lack hash algorithm");
                        return 0;
                    }
                    if (mgf1mdname == NULL) {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                    "PSS restrictions lack MGF1 hash algorithm");
                        return 0;
                    }

                    len = (size_t) DIGI_STRLEN((const sbyte *) mdname);
                    if (len >= sizeof(prsactx->mdname))
                    {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                    "hash algorithm name too long");
                        return 0;
                    }
                    (void) DIGI_MEMCPY(prsactx->mdname, mdname, len + 1);

                    len = (size_t) DIGI_STRLEN((const sbyte *) mgf1mdname);
                    if (len >= sizeof(prsactx->mgf1_mdname))
                    {
                        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                                    "MGF1 hash algorithm name too long");
                        return 0;
                    }
                    (void) DIGI_MEMCPY(prsactx->mgf1_mdname, mgf1mdname, len + 1);

                    prsactx->saltlen = min_saltlen;

                    /* call rsa_setup_mgf1_md before rsa_setup_md to avoid duplication */
                    if (!digiprov_rsa_setup_mgf1_md(prsactx, mgf1mdname, prsactx->propq)
                        || !digiprov_rsa_setup_md(prsactx, mdname, prsactx->propq)
                        || !digiprov_rsa_check_parameters(prsactx, min_saltlen))
                        return 0;
                }
            }
            break;
        default:
            ERR_raise(ERR_LIB_RSA, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            return 0;
    }

    if (!digiprov_rsa_set_ctx_params(prsactx, params))
        return 0;

    return 1;
}

static int digiprov_rsa_sign_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return digiprov_rsa_sv_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static void digiprov_rsa_freectx(void *vprsactx)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    if (NULL != prsactx)
    {
        if (NULL != prsactx->mdctx)
            EVP_MD_CTX_free(prsactx->mdctx);
        
        if (NULL != prsactx->md)
            EVP_MD_free(prsactx->md);
        
        if (NULL != prsactx->mgf1_md)
            EVP_MD_free(prsactx->mgf1_md);

        if (NULL != prsactx->propq)
            (void) DIGI_FREE((void **) &prsactx->propq);

        /* free before rsa key is freed */
        digiprov_free_tbuf(prsactx);

        if (NULL != prsactx->rsa)
            RSA_free(prsactx->rsa);

        (void) DIGI_MEMSET_FREE((ubyte **)&prsactx, sizeof(*prsactx));
    }
}

static size_t digiprov_rsa_get_md_size(DP_RSA_CTX *prsactx)
{
    if (NULL != prsactx->md)
        return (size_t) EVP_MD_get_size(prsactx->md);
    return 0;
}

static int digiprov_rsa_sign(void *vprsactx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    int ret = 0;
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    ubyte *pPaddedMsg = NULL;
    BulkHashAlgo *pH = NULL;
    size_t modLen = 0;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;
    DER_ITEMPTR pSequence = NULL;
    size_t mdsize = 0;

    if (NULL == prsactx)
        return 0;

    if (!digiprov_is_running())
        return 0;

    modLen = RSA_size(prsactx->rsa);
    if (NULL == sig)
    {
        if (NULL == siglen)
            return 0;

        *siglen = modLen;
        return 1;
    }

    if (sigsize < modLen) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE, "is %zu, should be at least %zu", sigsize, modLen);
        return 0;
    }

    mdsize = digiprov_rsa_get_md_size(prsactx);
    if (0 != mdsize && tbslen != mdsize)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
        return 0;    
    }

    if (RSA_PKCS1_PSS_PADDING == prsactx->pad_mode)
    {
        int emLen = RSA_bits(prsactx->rsa) - 1;

        /* we only support matching hash algos */
        if (NULL != prsactx->md && prsactx->mdnid != prsactx->mgf1_mdnid)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return 0;
        }

        status = CRYPTO_getRSAHashAlgo(convertDigest(prsactx->mgf1_mdnid), (const BulkHashAlgo **) &pH);
        if (OK != status)
            goto exit;

        status = RsaPadPssDigest(DIGI_EVP_RandomRngFun, NULL, (ubyte *) tbs, (ubyte4) tbslen,
                                 (ubyte4) emLen, digiprov_rsa_pss_compute_saltlen(prsactx),
                                 pH, pH, MOC_PKCS1_ALG_MGF1, &pPaddedMsg);
        if (OK != status)
            goto exit;

        *siglen = moc_rsa_priv_enc((emLen + 7)/8, pPaddedMsg, sig, prsactx->rsa, RSA_NO_PADDING);
    }
    else if (RSA_X931_PADDING == prsactx->pad_mode)
    {            
        if ((size_t)RSA_size(prsactx->rsa) < tbslen + 1) 
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL,
                            "RSA key size = %d, expected minimum = %d",
                            RSA_size(prsactx->rsa), tbslen + 1);
            return 0;
        }
 
        *siglen = moc_rsa_priv_enc((int)tbslen, tbs, sig, prsactx->rsa, prsactx->pad_mode);
    }
    else
    {
        if (0 != mdsize)
        {
            ubyte *digestOid = (ubyte *) getDigest_OID_fromNid(prsactx->mdnid);

            if (NULL == digestOid)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return 0;               
            }

            /* now construct a new ASN.1 DER encoding with this */
            if ( OK > (status = DER_AddSequence( NULL, &pSequence)))
                goto exit;

            if ( OK > ( status = DER_StoreAlgoOID( pSequence, digestOid, TRUE)))
                goto exit;

            if ( OK > ( status = DER_AddItem( pSequence, OCTETSTRING, tbslen, tbs, NULL)))
                goto exit;

            if ( OK > ( status = DER_Serialize( pSequence, &pBuffer, &bufferLen)))
                goto exit;
        }
        else /* we do raw sign */
        {
            pBuffer = (ubyte *) tbs;
            bufferLen = tbslen;
        }

        *siglen = moc_rsa_priv_enc((int)bufferLen, pBuffer, sig, prsactx->rsa, prsactx->pad_mode);
    }
    if (*siglen == modLen)
    {
        ret = 1;
    }
    else
    {
        ret = 0;
        ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
    }

exit:

    if (NULL != pSequence)
    {
        (void) TREE_DeleteTreeItem((TreeItem*)pSequence);
    }
    if (NULL != pPaddedMsg)
    {
        (void) DIGI_MEMSET_FREE(&pPaddedMsg, (ubyte4) modLen);
    }
    if ( (NULL != pBuffer) && (pBuffer != tbs) )
    {
        (void) DIGI_MEMSET_FREE(&pBuffer, (ubyte4) bufferLen);
    }

    return ret;
}

static int digiprov_rsa_verify_init(void *vprsactx, void *vrsa,
                                    const OSSL_PARAM params[])
{
    return digiprov_rsa_sv_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_rsa_verify(void *vprsactx, const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    int ret = 0;
    int retLen = 0;
    intBoolean differ = TRUE;
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    BulkHashAlgo *pH = NULL;
    size_t modLen = 0;
    intBoolean isValid = FALSE;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;
    DER_ITEMPTR pSequence = NULL;

    if (NULL == prsactx)
        return 0;

    if (!digiprov_is_running())
        return 0;

    modLen = RSA_size(prsactx->rsa);

    if(!digiprov_setup_tbuf(prsactx))
        return 0;

    if (RSA_PKCS1_PSS_PADDING == prsactx->pad_mode)
    {
        /* for SALTLEN_AUTO we'll recover the saltLen, otherwise we enforce it */
        int saltlen = -1;
        ubyte4 emBits = (ubyte4) RSA_bits(prsactx->rsa) - 1;
        size_t mdsize = digiprov_rsa_get_md_size(prsactx);

        /* we only support matching hash algos */
        if (NULL != prsactx->md && prsactx->mdnid != prsactx->mgf1_mdnid)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
            return 0;
        }
        
        if (tbslen != mdsize) 
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "Should be %d, but got %d", mdsize, tbslen);
            return 0;
        }

        if (RSA_PSS_SALTLEN_AUTO != prsactx->saltlen)
        {
            saltlen = digiprov_rsa_pss_compute_saltlen(prsactx);
        }

        retLen = moc_rsa_pub_dec(siglen, sig, prsactx->tbuf, prsactx->rsa, RSA_NO_PADDING);
        if (retLen != (int) modLen)
            goto exit;

        status = CRYPTO_getRSAHashAlgo(convertDigest(prsactx->mgf1_mdnid), (const BulkHashAlgo **) &pH);
        if (OK != status)
            goto exit;

        status = RsaPadPssVerifyDigest((const ubyte *) tbs, (ubyte4) tbslen, prsactx->tbuf + ((emBits & 0x07UL) ? 0 : 1), 
                                       emBits, saltlen, pH, pH, MOC_PKCS1_ALG_MGF1, &isValid);
        if (OK != status)
            goto exit;

        if (isValid)
        {
            ret = 1;
        }
        else
        {
            ret = 0;
        }
        
        /* skip the DIGI_MEMCMP done in the other two padding cases */
        goto exit;
    }
    else if (RSA_X931_PADDING == prsactx->pad_mode)
    {
        retLen = moc_rsa_pub_dec(siglen, sig, prsactx->tbuf, prsactx->rsa, prsactx->pad_mode);
        if (retLen < 1) 
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            return 0;
        }
        /* the above API already does the padding check */
        
        if (retLen != digiprov_rsa_get_md_size(prsactx))
        {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                            "Should be %d, but got %d",
                            digiprov_rsa_get_md_size(prsactx), retLen);
            return 0;
        }

        bufferLen = (ubyte4) tbslen;
    }
    else
    {
        size_t mdsize = digiprov_rsa_get_md_size(prsactx);

        if (0 != mdsize)
        {
            ubyte *digestOid = NULL;

            if (tbslen != mdsize) 
            {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "Should be %d, but got %d", mdsize, tbslen);
                return 0;
            }
                
            digestOid = (ubyte *) getDigest_OID_fromNid(prsactx->mdnid);
            if (NULL == digestOid)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return 0;                   
            }

            /* now construct a new ASN.1 DER encoding with this */
            if ( OK > (status = DER_AddSequence( NULL, &pSequence)))
                goto exit;

            if ( OK > ( status = DER_StoreAlgoOID( pSequence, digestOid, TRUE)))
                goto exit;

            if ( OK > ( status = DER_AddItem( pSequence, OCTETSTRING, tbslen, tbs, NULL)))
                goto exit;

            if ( OK > ( status = DER_Serialize( pSequence, &pBuffer, &bufferLen)))
                goto exit;
        }
        else
        {
            pBuffer = (ubyte *) tbs;
            bufferLen = (ubyte4) tbslen;
        }

        retLen = moc_rsa_pub_dec(siglen, sig, prsactx->tbuf, prsactx->rsa, prsactx->pad_mode);
    }

    if (retLen == (int) bufferLen)
    {
        status = DIGI_CTIME_MATCH(pBuffer, prsactx->tbuf, (ubyte4) retLen, &differ);
        if (OK == status && FALSE == differ)
        {
            ret = 1;
        }
        else
        {
            ret = 0;
        }
    }

exit:

    if(NULL != pSequence)
    {
        (void) TREE_DeleteTreeItem((TreeItem*)pSequence);
    }
    
    if( (NULL != pBuffer) && (pBuffer != tbs) )
    {
        (void) DIGI_MEMSET_FREE(&pBuffer, (ubyte4) bufferLen);
    }

    return ret;
}

static int digiprov_rsa_digest_signverify_init(void *vprsactx, const char *mdname,
                                               void *vrsa, const OSSL_PARAM params[],
                                               int operation)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (!digiprov_is_running())
        return 0;

    if (!digiprov_rsa_sv_init(vprsactx, vrsa, params, operation))
        return 0;

    prsactx->flag_allow_md = 1;
    
    if (mdname != NULL
        /* was rsa_setup_md already called in digiprov_rsa_sv_init()? */
        && (mdname[0] == '\0' || OPENSSL_strcasecmp(prsactx->mdname, mdname) != 0)
        && !digiprov_rsa_setup_md(prsactx, mdname, prsactx->propq))
        return 0;

    prsactx->flag_allow_md = 0;

    if (prsactx->mdctx == NULL)
    {
        prsactx->mdctx = EVP_MD_CTX_new();
        if (prsactx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(prsactx->mdctx, prsactx->md, params))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(prsactx->mdctx);
    prsactx->mdctx = NULL;
    return 0;
}

static int digiprov_rsa_digest_signverify_update(void *vprsactx,
                                                 const unsigned char *data,
                                                 size_t datalen)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx == NULL || prsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(prsactx->mdctx, data, datalen);
}

static int digiprov_rsa_digest_sign_init(void *vprsactx, const char *mdname,
                                         void *vrsa, const OSSL_PARAM params[])
{
    return digiprov_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                               params, EVP_PKEY_OP_SIGN);
}

static int digiprov_rsa_digest_sign_final(void *vprsactx, unsigned char *sig,
                                          size_t *siglen, size_t sigsize)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *) vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (prsactx == NULL)
        return 0;
    
    prsactx->flag_allow_md = 1;
    if (prsactx->mdctx == NULL)
        return 0;
    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     */
    if (sig != NULL) {
        /*
         * The digests used here are all known (see rsa_get_md_nid()), so they
         * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
         */
        if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
            return 0;
    }

    return digiprov_rsa_sign(vprsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int digiprov_rsa_digest_verify_init(void *vprsactx, const char *mdname,
                                  void *vrsa, const OSSL_PARAM params[])
{
    return digiprov_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
                                      params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_rsa_digest_verify_final(void *vprsactx, const unsigned char *sig,
                            size_t siglen)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (prsactx == NULL)
        return 0;
    
    prsactx->flag_allow_md = 1;
    if (prsactx->mdctx == NULL)
        return 0;

    /*
     * The digests used here are all known (see rsa_get_md_nid()), so they
     * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
     */
    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
        return 0;

    return digiprov_rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
}

static int digiprov_rsa_verify_recover_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return digiprov_rsa_sv_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFYRECOVER);
}

static int digiprov_rsa_verify_recover(void *vprsactx, unsigned char *rout, size_t *routlen,
                                       size_t routsize, const unsigned char *sig, size_t siglen)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    int ret = 0;
    int retVal = 0;
    DER_ITEMPTR pSequence = NULL;
    unsigned char *pBuffer = NULL;
    ubyte4 bufferLen = 0;

    if (NULL == prsactx)
        return 0;
    
    if (!digiprov_is_running())
        return 0;

    if (rout == NULL) 
    {
        *routlen = RSA_size(prsactx->rsa);
        return 1;
    }

    if (!digiprov_setup_tbuf(prsactx))
        return 0;

    if (NULL != prsactx->md)
    {
        switch (prsactx->pad_mode) 
        {
        case RSA_X931_PADDING:

            ret = moc_rsa_pub_dec(siglen, sig, prsactx->tbuf, prsactx->rsa, prsactx->pad_mode);
            if (ret < 1) 
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }
            /* the above API already does the padding check */

            if (ret != EVP_MD_get_size(prsactx->md)) 
            {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                               "Should be %d, but got %d",
                               EVP_MD_get_size(prsactx->md), ret);
                return 0;
            }

            *routlen = (size_t) ret;
            if (rout != prsactx->tbuf)
            {
                if (routsize < (size_t)ret)
                {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                                   "buffer size is %d, should be %d",
                                   routsize, ret);
                    return 0;
                }
                (void) DIGI_MEMCPY(rout, prsactx->tbuf, ret);
            }
            break;

        case RSA_PKCS1_PADDING:
            {
                ubyte *digestOid = NULL;
                MSTATUS status = OK;
                intBoolean differ = TRUE;

                size_t mdsize = digiprov_rsa_get_md_size(prsactx);

                ret = moc_rsa_pub_dec(siglen, sig, prsactx->tbuf, prsactx->rsa, prsactx->pad_mode);
                if (ret <= 0) 
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }

                if (ret < mdsize)
                {
                    ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);   
                    return 0;
                }

                /* we construct the digestInfo from the last mdsize bytes */
                digestOid = (ubyte *) getDigest_OID_fromNid(prsactx->mdnid);
                if (NULL == digestOid)
                {
                    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                    return 0;                   
                }

                /* now construct a new ASN.1 DER encoding with this, allocations start here, goto exit on error */
                if ( OK > (status = DER_AddSequence( NULL, &pSequence)))
                {
                    ret = 0;
                    goto exit;
                }

                if ( OK > ( status = DER_StoreAlgoOID( pSequence, digestOid, TRUE)))
                {
                    ret = 0;
                    goto exit;
                }

                if ( OK > ( status = DER_AddItem( pSequence, OCTETSTRING, (ubyte4) mdsize, prsactx->tbuf + ret - mdsize, NULL)))
                {
                    ret = 0;
                    goto exit;
                }

                if ( OK > ( status = DER_Serialize( pSequence, &pBuffer, &bufferLen)))
                {
                    ret = 0;
                    goto exit;
                }

                /* now validate the digest info is proper */

                if (ret == (int) bufferLen)
                {
                    status = DIGI_CTIME_MATCH(pBuffer, prsactx->tbuf, bufferLen, &differ);
                    if (OK == status && FALSE == differ)
                    {
                        (void) DIGI_MEMCPY(rout, pBuffer + bufferLen - (ubyte4) mdsize, (ubyte4) mdsize);
                        ret = (int) mdsize;
                    }
                    else
                    {
                        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                        ret = 0;
                        goto exit;
                    }
                }                   
                else
                {
                    ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
                    ret = 0;
                    goto exit;
                }
            }
            break;

        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE, "Only X.931 or PKCS#1 v1.5 padding allowed");
            return 0;
        }
    } 
    else 
    {
        ret = moc_rsa_pub_dec(siglen, sig, rout, prsactx->rsa, prsactx->pad_mode);
        if (ret < 0) 
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
            return 0;
        }
    }

    retVal = 1;

exit:

    *routlen = (size_t) ret;

    if(NULL != pSequence)
    {
        (void) TREE_DeleteTreeItem((TreeItem*)pSequence);
    }

    if(NULL != pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pBuffer, (ubyte4) bufferLen);
    }

    return retVal;
}

static void *digiprov_rsa_dupctx(void *vprsactx)
{
    MSTATUS status = OK;
    DP_RSA_CTX *srcctx = (DP_RSA_CTX *)vprsactx;
    DP_RSA_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(*srcctx));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;

    dstctx->rsa = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->tbuf = NULL;
    dstctx->propq = NULL;

    if (srcctx->rsa != NULL && !RSA_up_ref(srcctx->rsa))
        goto err;
    dstctx->rsa = srcctx->rsa;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mgf1_md != NULL && !EVP_MD_up_ref(srcctx->mgf1_md))
        goto err;
    dstctx->mgf1_md = srcctx->mgf1_md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->propq != NULL) 
    {
        status = digiprov_strdup((void **) &dstctx->propq, srcctx->propq);
        if (OK != status)
            goto err;
    }

    /* no need to dup tbuf */

    return dstctx;

err:

    digiprov_rsa_freectx(dstctx);
    return NULL;
}

static int digiprov_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;
    OSSL_PARAM *p;

    if (prsactx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) 
    {
        /* The Algorithm Identifier of the combined signature algorithm */
        unsigned char aid_buf[128];
        unsigned char *aid;
        size_t  aid_len;

        aid = digiprov_rsa_generate_signature_aid(prsactx, aid_buf, sizeof(aid_buf), &aid_len);
        if (aid == NULL || !OSSL_PARAM_set_octet_string(p, aid, aid_len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL)
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, prsactx->pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;
                const char *word = NULL;

                for (i = 0; padding_item[i].id != 0; i++) 
                {
                    if (prsactx->pad_mode == (int)padding_item[i].id) 
                    {
                        word = padding_item[i].ptr;
                        break;
                    }
                }

                if (word != NULL)
                {
                    if (!OSSL_PARAM_set_utf8_string(p, word))
                        return 0;
                } 
                else
                {
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                }
            }
            break;
        default:
            return 0;
        }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, prsactx->mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, prsactx->mgf1_mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) 
    {
        if (p->data_type == OSSL_PARAM_INTEGER)
        {
            if (!OSSL_PARAM_set_int(p, prsactx->saltlen))
                return 0;
        } 
        else if (p->data_type == OSSL_PARAM_UTF8_STRING) 
        {
            const char *value = NULL;

            switch (prsactx->saltlen) {
            case RSA_PSS_SALTLEN_DIGEST:
                value = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
                break;
            case RSA_PSS_SALTLEN_MAX:
                value = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
                break;
            case RSA_PSS_SALTLEN_AUTO:
                value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
                break;
            default:
                {
                    int len = BIO_snprintf(p->data, p->data_size, "%d",
                                           prsactx->saltlen);

                    if (len <= 0)
                        return 0;
                    p->return_size = len;
                    break;
                }
            }
            if (value != NULL
                && !OSSL_PARAM_set_utf8_string(p, value))
                return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
{
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_rsa_gettable_ctx_params(ossl_unused void *vprsactx, ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(prsactx->mdctx, params);
}

static const OSSL_PARAM *digiprov_rsa_gettable_ctx_md_params(void *vprsactx)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(prsactx->md);
}

static int digiprov_rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(prsactx->mdctx, params);
}

static const OSSL_PARAM *digiprov_rsa_settable_ctx_md_params(void *vprsactx)
{
    DP_RSA_CTX *prsactx = (DP_RSA_CTX *)vprsactx;

    if (prsactx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(prsactx->md);
}

/*-------------------------------------------- FUNCTION TABLE --------------------------------------------*/

const OSSL_DISPATCH digiprov_rsa_sig_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))digiprov_rsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))digiprov_rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))digiprov_rsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void (*)(void))digiprov_rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void (*)(void))digiprov_rsa_verify },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))digiprov_rsa_verify_recover_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,      (void (*)(void))digiprov_rsa_verify_recover },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))digiprov_rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))digiprov_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))digiprov_rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void (*)(void))digiprov_rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,(void (*)(void))digiprov_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))digiprov_rsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))digiprov_rsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))digiprov_rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))digiprov_rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_rsa_gettable_ctx_params },    
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))digiprov_rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,   (void (*)(void))digiprov_rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_rsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,   (void (*)(void))digiprov_rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_rsa_settable_ctx_md_params },
    { 0, NULL }
};
