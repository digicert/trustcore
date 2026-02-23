/*
 * digi_ecdsa_sig.c
 *
 * DSA implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
#include "openssl/dsa.h"
#include "internal/sizes.h"
#include "internal/nelem.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "internal/deprecated.h"
#include "internal/cryptlib.h"
#include "openssl/crypto.h"
#include "crypto/dsa.h"
#include "internal/deprecated.h"
#include <string.h>
#include "prov/der_dsa.h"

/*
 * Based on Openssl's DP_DSA_CTX
 */

typedef struct 
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    DSA *dsa;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int operation;

} DP_DSA_CTX;


/* MUST match DSA_SIG structure in openssl (which is now opaque) */
typedef struct
{
   BIGNUM *r;
   BIGNUM *s;

} DP_DSA_SIG;

static int digiprov_dsa_set_ctx_params(void *vpdsactx, const OSSL_PARAM params[]);
DSA_SIG *moc_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
int moc_dsa_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa);
int ossl_digest_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const EVP_MD *md, int sha1_allowed);

static size_t digiprov_dsa_get_md_size(const DP_DSA_CTX *pdsactx)
{
    if (pdsactx->md != NULL)
        return EVP_MD_get_size(pdsactx->md);
    return 0;
}

static void *digiprov_dsa_newctx(void *provctx, const char *propq)
{
    MSTATUS status = OK;
    DP_DSA_CTX *pdsactx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pdsactx, 1, sizeof(DP_DSA_CTX));
    if (OK != status)
        return NULL;

    pdsactx->libctx = PROV_LIBCTX_OF(provctx);
    pdsactx->flag_allow_md = 1;
    if (propq != NULL)
    {
        status = digiprov_strdup((void **) &pdsactx->propq, propq);
        if (OK != status)
        {
            (void) DIGI_FREE((void **) &pdsactx);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        }
    }
    
    return pdsactx;
}

static int digiprov_dsa_setup_md(DP_DSA_CTX *ctx, const char *mdname, const char *mdprops)
{
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) 
    {
        int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
        WPACKET pkt;
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int md_nid = ossl_digest_get_approved_nid_with_sha1(ctx->libctx, md,
                                                            sha1_allowed);
        size_t mdname_len = (size_t) DIGI_STRLEN((const sbyte *) mdname);

        if (md == NULL || md_nid < 0) 
        {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            if (md_nid < 0)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest=%s", mdname);
            if (mdname_len >= sizeof(ctx->mdname))
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s exceeds name buffer length", mdname);
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

        /*
         * We do not care about DER writing errors.
         * All it really means is that for some reason, there's no
         * AlgorithmIdentifier to be had, but the operation itself is
         * still valid, just as long as it's not used to construct
         * anything that needs an AlgorithmIdentifier.
         */
        ctx->aid_len = 0;
        if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
            && ossl_DER_w_algorithmIdentifier_DSA_with_MD(&pkt, -1, ctx->dsa,
                                                          md_nid)
            && WPACKET_finish(&pkt)) {
            WPACKET_get_total_written(&pkt, &ctx->aid_len);
            ctx->aid = WPACKET_get_curr(&pkt);
        }
        WPACKET_cleanup(&pkt);

        ctx->mdctx = NULL;
        ctx->md = md;
        (void) DIGI_MEMCPY(ctx->mdname, mdname, mdname_len + 1);
    }
    return 1;
}

static int digiprov_dsa_signverify_init(void *vpdsactx, void *vdsa, const OSSL_PARAM params[], int operation)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (!digiprov_is_running())
        return 0;

    if (pdsactx == NULL)
        return 0;

    if (vdsa == NULL && pdsactx->dsa == NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vdsa != NULL) 
    {
        if (!ossl_dsa_check_key(pdsactx->libctx, vdsa, operation == EVP_PKEY_OP_SIGN)) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!DSA_up_ref(vdsa))
            return 0;
        DSA_free(pdsactx->dsa);
        pdsactx->dsa = vdsa;
    }

    pdsactx->operation = operation;

    if (!digiprov_dsa_set_ctx_params(pdsactx, params))
        return 0;

    return 1;
}

static int digiprov_dsa_sign_init(void *vpdsactx, void *vdsa, const OSSL_PARAM params[])
{
    return digiprov_dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_dsa_verify_init(void *vpdsactx, void *vdsa,
                           const OSSL_PARAM params[])
{
    return digiprov_dsa_signverify_init(vpdsactx, vdsa, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_dsa_sign(void *vpdsactx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;
    int ret = 0;
    size_t dsasize = DSA_size(pdsactx->dsa);
    size_t mdsize = digiprov_dsa_get_md_size(pdsactx);
    DP_DSA_SIG *pSig = NULL;
    int rLen = 0;
    int sLen = 0;
    ubyte *pSigPtr = sig;
    int extraLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (sig == NULL) 
    {
        *siglen = dsasize;
        return 1;
    }

    if (sigsize < (size_t)dsasize)
        return 0;

    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    pSig = (DP_DSA_SIG *) moc_dsa_do_sign(tbs, (int)tbslen, pdsactx->dsa);
    if (NULL == pSig)
        return 0;
    
    /* DER encode the signature, we will only support up 64 byte r and s (ie q len up to 512 bits) */
    rLen = BN_num_bytes(pSig->r);
    sLen = BN_num_bytes(pSig->s);
    
    if (rLen > 64 || sLen > 64)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        goto exit;
    }

    /* If r and s will each have a 0x00 byte, a length byte, and a 0x02 tag byte
       If total is > 127 there will be an extra length byte needed for the final seq */
    if (rLen + sLen + 6 > 127)
        extraLen = 1;

    /* a 0x30 tag, a length byte with an extra if needed, and R followed by S */
    if ((int) sigsize < rLen + sLen + 6 + extraLen + 2)
        goto exit;

    *siglen = (rLen + sLen + 6 + extraLen + 2);

    *pSigPtr = (unsigned char) 0x30; /* Sequence tag */
    pSigPtr++;

    if (extraLen)
    {
       pSigPtr[0] = 0x81;
       pSigPtr[1] = (ubyte) (rLen + sLen + 6);
       pSigPtr[2] = 0x02; /* Integer tag */
       pSigPtr[3] = (ubyte) (rLen + 1);
       pSigPtr[4] = 0x00;
       pSigPtr += 5;
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
    pSigPtr[1] = (ubyte) (sLen + 1);
    pSigPtr[2] = 0x00;
    pSigPtr += 3;

    BN_bn2bin(pSig->s, pSigPtr);
    ret = 1;

exit:

    if (NULL != pSig)
    {
        DSA_SIG_free((DSA_SIG *) pSig);
    }

    return ret;
}

static int digiprov_dsa_verify(void *vpdsactx, const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs, size_t tbslen)
{
    int ret = 0;
    DP_DSA_CTX *ctx = (DP_DSA_CTX *)vpdsactx;
    size_t mdsize = digiprov_dsa_get_md_size(ctx);
    DP_DSA_SIG signature = {0};
    int len = 0;
    unsigned char *pSigPtr = (unsigned char *) sig;

    if (!digiprov_is_running())
        return 0;

    if (mdsize != 0 && tbslen != mdsize)
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

    ret = moc_dsa_do_verify(tbs, (int) tbslen, (DSA_SIG *) &signature, ctx->dsa);

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

static int digiprov_dsa_digest_signverify_init(void *vpdsactx, const char *mdname,
                                               void *vdsa, const OSSL_PARAM params[], int operation)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (!digiprov_dsa_signverify_init(vpdsactx, vdsa, params, operation))
        return 0;

    if (!digiprov_dsa_setup_md(pdsactx, mdname, NULL))
        return 0;

    pdsactx->flag_allow_md = 0;

    if (pdsactx->mdctx == NULL) 
    {
        pdsactx->mdctx = EVP_MD_CTX_new();
        if (pdsactx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(pdsactx->mdctx, pdsactx->md, params))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(pdsactx->mdctx);
    pdsactx->mdctx = NULL;
    return 0;
}

static int digiprov_dsa_digest_sign_init(void *vpdsactx, const char *mdname,
                                         void *vdsa, const OSSL_PARAM params[])
{
    return digiprov_dsa_digest_signverify_init(vpdsactx, mdname, vdsa, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_dsa_digest_verify_init(void *vpdsactx, const char *mdname,
                                           void *vdsa, const OSSL_PARAM params[])
{
    return digiprov_dsa_digest_signverify_init(vpdsactx, mdname, vdsa, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_dsa_digest_signverify_update(void *vpdsactx, const unsigned char *data, size_t datalen)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(pdsactx->mdctx, data, datalen);
}

static int digiprov_dsa_digest_sign_final(void *vpdsactx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to dsa_sign.
     */
    if (sig != NULL) {
        /*
         * There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         */
        if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
            return 0;
    }

    pdsactx->flag_allow_md = 1;

    return digiprov_dsa_sign(vpdsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}


static int digiprov_dsa_digest_verify_final(void *vpdsactx, const unsigned char *sig, size_t siglen)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     */
    if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
        return 0;

    pdsactx->flag_allow_md = 1;

    return digiprov_dsa_verify(vpdsactx, sig, siglen, digest, (size_t)dlen);
}

static void digiprov_dsa_freectx(void *vpdsactx)
{
    DP_DSA_CTX *ctx = (DP_DSA_CTX *)vpdsactx;

    (void) DIGI_FREE((void **) &ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    DSA_free(ctx->dsa);
    (void) DIGI_FREE((void **) &ctx);
}

static void *digiprov_dsa_dupctx(void *vpdsactx)
{
    MSTATUS status = OK;
    DP_DSA_CTX *srcctx = (DP_DSA_CTX *)vpdsactx;
    DP_DSA_CTX *dstctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&dstctx, 1, sizeof(DP_DSA_CTX));
    if (OK != status)
        return NULL;

    *dstctx = *srcctx;
    dstctx->dsa = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->propq = NULL;

    if (srcctx->dsa != NULL && !DSA_up_ref(srcctx->dsa))
        goto err;
    dstctx->dsa = srcctx->dsa;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

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

    return dstctx;
 err:
    digiprov_dsa_freectx(dstctx);
    return NULL;
}

static int digiprov_dsa_get_ctx_params(void *vpdsactx, OSSL_PARAM *params)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;
    OSSL_PARAM *p;

    if (pdsactx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, pdsactx->aid, pdsactx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdsactx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
{
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dsa_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_dsa_set_ctx_params(void *vpdsactx, const OSSL_PARAM params[])
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;
    const OSSL_PARAM *p;

    if (pdsactx == NULL)
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
        if (!digiprov_dsa_setup_md(pdsactx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM digiprov_settable_ctx_params[] = 
{
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM digiprov_settable_ctx_params_no_digest[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_dsa_settable_ctx_params(void *vpdsactx,ossl_unused void *provctx)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx != NULL && !pdsactx->flag_allow_md)
        return digiprov_settable_ctx_params_no_digest;
    return digiprov_settable_ctx_params;
}

static int digiprov_dsa_get_ctx_md_params(void *vpdsactx, OSSL_PARAM *params)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(pdsactx->mdctx, params);
}

static const OSSL_PARAM *digiprov_dsa_gettable_ctx_md_params(void *vpdsactx)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(pdsactx->md);
}

static int digiprov_dsa_set_ctx_md_params(void *vpdsactx, const OSSL_PARAM params[])
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(pdsactx->mdctx, params);
}

static const OSSL_PARAM *digiprov_dsa_settable_ctx_md_params(void *vpdsactx)
{
    DP_DSA_CTX *pdsactx = (DP_DSA_CTX *)vpdsactx;

    if (pdsactx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(pdsactx->md);
}

const OSSL_DISPATCH digiprov_dsa_functions[] = 
{
    { OSSL_FUNC_SIGNATURE_NEWCTX,                 (void (*)(void))digiprov_dsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,              (void (*)(void))digiprov_dsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                   (void (*)(void))digiprov_dsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,            (void (*)(void))digiprov_dsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,                 (void (*)(void))digiprov_dsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,       (void (*)(void))digiprov_dsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,     (void (*)(void))digiprov_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,      (void (*)(void))digiprov_dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,     (void (*)(void))digiprov_dsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,   (void (*)(void))digiprov_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,    (void (*)(void))digiprov_dsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX,                (void (*)(void))digiprov_dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,                 (void (*)(void))digiprov_dsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,         (void (*)(void))digiprov_dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,    (void (*)(void))digiprov_dsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,         (void (*)(void))digiprov_dsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,    (void (*)(void))digiprov_dsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,      (void (*)(void))digiprov_dsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_dsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,      (void (*)(void))digiprov_dsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_dsa_settable_ctx_md_params },
    { 0, NULL }
};
