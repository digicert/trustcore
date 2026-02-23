/*
 * digi_ecdsa_sig.c
 *
 * ECDSA implementations for OSSL 3.0 provider ADAPTED from OPENSSL code
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
#include "prov/securitycheck.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "internal/deprecated.h"

#include "openssl/crypto.h"
#include "crypto/ec.h"
#include "prov/der_ec.h"

/* Based on struct PROV_ECDSA_CTX in ossl ecdsa_sig.c */
typedef struct 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;
    char mdname[OSSL_MAX_NAME_SIZE];

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;
    size_t mdsize;
    int operation;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;

} DP_ECDSA_CTX;

/* MUST match ECDSA_SIG structure in openssl (which is now opaque) */
typedef struct
{
   BIGNUM *r;
   BIGNUM *s;

} DP_ECDSA_SIG;

static int digiprov_ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

ECDSA_SIG *moc_ecdsa_sign(const unsigned char *pDigest, int digestLen, const BIGNUM *pKInv, 
                          const BIGNUM *pR, EC_KEY *pEcKey);

int moc_ecdsa_verify(const unsigned char *dgst, int dgst_len,
                     const ECDSA_SIG *sig, EC_KEY *eckey);

static void *digiprov_ecdsa_newctx(void *provctx, const char *propq)
{
    MSTATUS status = OK;
    DP_ECDSA_CTX *pCtx = NULL;
    char *propq_copy = NULL;
    
    if (!digiprov_is_running())
        return NULL;

    if (NULL != propq)
    {
        status = digiprov_strdup((void **) &propq_copy, propq);
        if (OK != status)
            goto exit;
    }
    
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_ECDSA_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);
    pCtx->flag_allow_md = 1;
    pCtx->propq = propq_copy; propq_copy = NULL;

exit:

    if (NULL != propq_copy)
    {
        (void) DIGI_FREE((void **) &propq_copy);
    }

    /* last thing allocated is pCtx so no need to clean it up on err */

    return pCtx;
}

static int digiprov_ecdsa_signverify_init(void *vctx, void *ec, const OSSL_PARAM params[], int operation)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (!digiprov_is_running())
        return 0;

    if (NULL == ctx)
        return 0;

    if (ec == NULL && ctx->ec == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ec != NULL)
    {
        if (!ossl_ec_check_key(ctx->libctx, ec, operation == EVP_PKEY_OP_SIGN)) 
            return 0;
        if (!EC_KEY_up_ref(ec))
            return 0;
        EC_KEY_free(ctx->ec);
        ctx->ec = ec;
    }

    ctx->operation = operation;

    if (!digiprov_ecdsa_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int digiprov_ecdsa_sign_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    return digiprov_ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_ecdsa_verify_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    return digiprov_ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    int ret = 0;
    size_t ecsize = ECDSA_size(ctx->ec);
    DP_ECDSA_SIG *pSig = NULL;
    int rLen = 0;
    int sLen = 0;
    ubyte *pSigPtr = sig;
    int extraLen = 0;

    if (!digiprov_is_running())
        return 0;
    
    if (sig == NULL) 
    {
        *siglen = ecsize;
        return 1;
    }

    if (sigsize < (size_t)ecsize)
        return 0;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    pSig = (DP_ECDSA_SIG *) moc_ecdsa_sign(tbs, (int) tbslen, NULL, NULL, ctx->ec);
    if (NULL == pSig)
        return 0;
    
    /* DER encode the signature, we only support up to P521 so rLen and sLen will only need 1 length byte */
    rLen = BN_num_bytes(pSig->r);
    sLen = BN_num_bytes(pSig->s);
    
    /* If r and s will each have a 0x00 byte, a length byte, and a 0x02 tag byte
       If total is > 127 there will be an extra length byte needed for the final seq 
       but then no pair of 0x00 padding byte (this is P521 only)*/
    if (rLen + sLen + 6 > 127)
        extraLen = -1;

    /* a 0x30 tag, a length byte minus extra if needed, and R followed by S */
    if ((int) sigsize < rLen + sLen + 6 + extraLen + 2)
        goto exit;

    *siglen = (rLen + sLen + 6 + extraLen + 2);

    *pSigPtr = (unsigned char) 0x30; /* Sequence tag */
    pSigPtr++;

    if (-1 == extraLen)
    {
       pSigPtr[0] = 0x81;
       pSigPtr[1] = (ubyte) (rLen + sLen + 4);
       pSigPtr[2] = 0x02; /* Integer tag */
       pSigPtr[3] = (ubyte) rLen;
       pSigPtr += 4;
    }
    else
    {
       pSigPtr[0] = (ubyte) (rLen + sLen + 6);
       pSigPtr[1] = 0x02; /* Integer tag */
       pSigPtr[2] = (ubyte) (rLen + 1);
       pSigPtr[3] = 0x00;
       pSigPtr += 4;
    }

    BN_bn2bin(pSig->r, pSigPtr);
    pSigPtr += rLen;

    pSigPtr[0] = 0x02; /* Integer tag */
    pSigPtr++;

    if (-1 == extraLen)
    {
        pSigPtr[0] = (ubyte) sLen;
        pSigPtr++;
    }
    else
    {
        pSigPtr[0] = (ubyte) (sLen + 1);
        pSigPtr[1] = 0x00;
        pSigPtr += 2;
    }
    BN_bn2bin(pSig->s, pSigPtr);
    ret = 1;

exit:

    if (NULL != pSig)
    {
        ECDSA_SIG_free((ECDSA_SIG *) pSig);
    }

    return ret;
}

static int digiprov_ecdsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                                 const unsigned char *tbs, size_t tbslen)
{
    int ret = 0;
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    DP_ECDSA_SIG signature = {0};
    int len = 0;
    unsigned char *pSigPtr = (unsigned char *) sig;

    if (!digiprov_is_running())
        return 0;
    
    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    /* parse the signature */
    if (siglen < 8)  /* two integers in a sequence is at least 8 bytes */
        return 0;

    if (0x30 != pSigPtr[0]) /* is sequence tag */
        return 0;

    /* no full asn1 validation, just validate it's two integers */
    if (0x81 == pSigPtr[1])
    {
        /* must be the remaining length */
        if (siglen - 3 != (size_t) pSigPtr[2])
            return 0;

        if (0x02 != pSigPtr[3]) /* is integer tag */
            return 0;

        len = (int) pSigPtr[4];
        pSigPtr += 5;
    }
    else if (0 == (pSigPtr[1] & 0x80)) /* double check it's a single length byte */
    {
        /* must be the remaining length */
        if (siglen - 2 != (size_t) pSigPtr[1])
            return 0;

        if (0x02 != pSigPtr[2]) /* is integer tag */
            return 0;

        len = (int) pSigPtr[3];
        pSigPtr += 4;
    }
    else
    {
        return 0;
    }
    
    signature.r = BN_bin2bn(pSigPtr, len, signature.r);
    if (NULL == signature.r)
        return 0;

    pSigPtr += len;

    if (0x02 != pSigPtr[0]) /* is integer tag */
        goto exit;

    len = (int) pSigPtr[1];
    pSigPtr += 2;

    signature.s = BN_bin2bn(pSigPtr, len, signature.s);
    if (NULL == signature.s)
        goto exit;

    pSigPtr += len;
    /* make sure that was all the bytes */
    if (siglen != (size_t) (pSigPtr - (unsigned char *) sig))
        goto exit;
    
    ret = moc_ecdsa_verify(tbs, (int) tbslen, (ECDSA_SIG *) &signature, ctx->ec);

exit:

    if (NULL != signature.r)
    {
        BN_clear_free(signature.r);
    }

    if (NULL != signature.s)
    {
        BN_clear_free(signature.s);
    }

    return ret;
}

static int digiprov_ecdsa_setup_md(DP_ECDSA_CTX *ctx, const char *mdname,
                                   const char *mdprops)
{
    EVP_MD *md = NULL;
    size_t mdname_len;
    int md_nid, sha1_allowed;
    WPACKET pkt;

    if (mdname == NULL)
        return 1;

    mdname_len = (size_t) DIGI_STRLEN((const sbyte *) mdname);
    if (mdname_len >= sizeof(ctx->mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s exceeds name buffer length", mdname);
        return 0;
    }
    if (mdprops == NULL)
        mdprops = ctx->propq;
    md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    if (md == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s could not be fetched", mdname);
        return 0;
    }
    sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
    md_nid = ossl_digest_get_approved_nid_with_sha1(ctx->libctx, md,
                                                    sha1_allowed);
    if (md_nid < 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                       "digest=%s", mdname);
        EVP_MD_free(md);
        return 0;
    }

    if (!ctx->flag_allow_md) {
        if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                           "digest %s != %s", mdname, ctx->mdname);
            EVP_MD_free(md);
            return 0;
        }
        EVP_MD_free(md);
        return 1;
    }

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);

    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && ossl_DER_w_algorithmIdentifier_ECDSA_with_MD(&pkt, -1, ctx->ec,
                                                        md_nid)
        && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);
    ctx->mdctx = NULL;
    ctx->md = md;
    ctx->mdsize = EVP_MD_get_size(ctx->md);
    (void) DIGI_MEMCPY(ctx->mdname, mdname, mdname_len + 1);
  
    return 1;
}

static int digiprov_ecdsa_digest_signverify_init(void *vctx, const char *mdname,
                                                 void *ec, const OSSL_PARAM params[],
                                                 int operation)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (!digiprov_is_running())
        return 0;
    
    if (!digiprov_ecdsa_signverify_init(vctx, ec, params, operation)
        || !digiprov_ecdsa_setup_md(ctx, mdname, NULL))
        return 0;

    ctx->flag_allow_md = 0;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error;
    return 1;
error:
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;
    return 0;
}

static int digiprov_ecdsa_digest_sign_init(void *vctx, const char *mdname, void *ec,
                                           const OSSL_PARAM params[])
{
    return digiprov_ecdsa_digest_signverify_init(vctx, mdname, ec, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_ecdsa_digest_verify_init(void *vctx, const char *mdname, void *ec,
                                             const OSSL_PARAM params[])
{
    return digiprov_ecdsa_digest_signverify_init(vctx, mdname, ec, params, EVP_PKEY_OP_VERIFY);
}

int digiprov_ecdsa_digest_signverify_update(void *vctx, const unsigned char *data, size_t datalen)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int digiprov_ecdsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to ecdsa_sign.
     */
    if (sig != NULL
        && !EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;
    ctx->flag_allow_md = 1;
    return digiprov_ecdsa_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

int digiprov_ecdsa_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;
    
    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;
    ctx->flag_allow_md = 1;
    return digiprov_ecdsa_verify(ctx, sig, siglen, digest, (size_t)dlen);
}

static void digiprov_ecdsa_freectx(void *vctx)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    (void) DIGI_FREE((void **) &ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    ctx->mdsize = 0;
    EC_KEY_free(ctx->ec);
    (void) DIGI_FREE((void **) &ctx);
}

static void *digiprov_ecdsa_dupctx(void *vctx)
{
    MSTATUS status = OK;
    DP_ECDSA_CTX *srcctx = (DP_ECDSA_CTX *)vctx;
    DP_ECDSA_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &dstctx, 1, sizeof(*srcctx));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->propq = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;

    dstctx->ec = srcctx->ec;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL)
    {
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

    return dstctx;

 err:

    digiprov_ecdsa_freectx(dstctx);
    return NULL;
}

static int digiprov_ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL
                                                    ? ctx->mdname
                                                    : EVP_MD_get0_name(ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = 
{
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_ecdsa_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int digiprov_ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t mdsize = 0;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!digiprov_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !digiprov_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!digiprov_ecdsa_setup_md(ctx, mdname, mdprops))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &mdsize)
            || (!ctx->flag_allow_md && mdsize != ctx->mdsize))
            return 0;
        ctx->mdsize = mdsize;
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_ecdsa_settable_ctx_params(void *vctx,
                                                   ossl_unused void *provctx)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx != NULL && !ctx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

static int digiprov_ecdsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *digiprov_ecdsa_gettable_ctx_md_params(void *vctx)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static int digiprov_ecdsa_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *digiprov_ecdsa_settable_ctx_md_params(void *vctx)
{
    DP_ECDSA_CTX *ctx = (DP_ECDSA_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(ctx->md);
}

const OSSL_DISPATCH digiprov_ecdsa_functions[] = 
{
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))digiprov_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))digiprov_ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))digiprov_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void (*)(void))digiprov_ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void (*)(void))digiprov_ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))digiprov_ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))digiprov_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))digiprov_ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void (*)(void))digiprov_ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,(void (*)(void))digiprov_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))digiprov_ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))digiprov_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))digiprov_ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))digiprov_ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_ecdsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))digiprov_ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,   (void (*)(void))digiprov_ecdsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_ecdsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,      (void (*)(void))digiprov_ecdsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_ecdsa_settable_ctx_md_params },
    { 0, NULL }
};
