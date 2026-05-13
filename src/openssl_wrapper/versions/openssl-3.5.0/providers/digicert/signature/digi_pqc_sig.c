/*
 * digi_pqc_sig.c
 *
 * pqc signature implementations for OSSL 3.0 provider
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

/*---------------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"

#ifdef __ENABLE_DIGICERT_PQC__

#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/ca_mgmt.h"
#include "../../../src/crypto_interface/crypto_interface_qs.h"
#include "../../../src/crypto_interface/crypto_interface_qs_sig.h"

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
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"
#include "pqc.h"
#include "internal/deprecated.h"

#include "openssl/crypto.h"

#define DP_MLDSA_MAX_CID cid_PQC_MLDSA_87

typedef struct
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    DP_PQC_KEY *pKey;
    int operation;
    char mdname[OSSL_MAX_NAME_SIZE];
    ubyte mdCid;    /* Digicert identifier, 0 (or ht_none) for none */
    unsigned int flag_allow_md;
    size_t mdsize;
    EVP_MD *md;
    EVP_MD_CTX *mdctx;

} DP_PQCSIG_CTX;

sbyte4 DIGI_EVP_RandomRngFun(void *pRngFunArg, ubyte4 length, ubyte *pBuffer);
static int digiprov_pqc_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
void digiprov_pqc_key_free(DP_PQC_KEY *pKey);
int digiprov_pqc_validate_key_for_op(DP_PQC_KEY *pKey, int operation);
extern int digiprov_pqc_key_up_ref(DP_PQC_KEY *pKey);

static void *digiprov_pqc_sig_newctx(void *provctx, const char *propq_unused)
{
    MSTATUS status = OK;
    DP_PQCSIG_CTX *pCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(DP_PQCSIG_CTX));
    if (OK != status)
        goto exit;

    pCtx->libctx = PROV_LIBCTX_OF(provctx);
    pCtx->flag_allow_md = 1;

exit:

    return pCtx;
}

static int digiprov_pqc_signverify_init(void *vctx, void *pqc, const OSSL_PARAM params[], int operation)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    DP_PQC_KEY *pKey = (DP_PQC_KEY *) pqc;

    if (!digiprov_is_running())
        return 0;
    
    /* set md back to none, it will be then overwritten if this is called from digest init function pointers  */
    pCtx->mdCid = ht_none;
    pCtx->operation = operation;

    if (pKey == NULL)
    {
        if (pCtx->pKey != NULL)
        {
            /* there is nothing to do on reinit */
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    else
    {
        if (!digiprov_pqc_key_up_ref(pKey))
            return 0;

        if (NULL != pCtx->pKey)
        {
            digiprov_pqc_key_free(pCtx->pKey);
        }

        pCtx->pKey = pKey;
    }

    if (!digiprov_pqc_sig_set_ctx_params(pCtx, params))
        return 0;

    return 1;
}

static int digiprov_pqc_sign_init(void *vctx, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_signverify_init(vctx, pqc, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_pqc_verify_init(void *vctx, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_signverify_init(vctx, pqc, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_pqc_sign(void *vctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    DP_PQC_KEY *pKey;
    ubyte4 pqcSigLen = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == pCtx)
        return 0;

    pKey = (DP_PQC_KEY *) pCtx->pKey;
    if (NULL == pKey)
        return 0;

    if (!digiprov_pqc_validate_key_for_op(pKey, pCtx->operation))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen((QS_CTX *) pKey->pKeyData, &pqcSigLen);
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET); /* only possible error case */
        return 0;        
    }

    if (sig == NULL) 
    {
        *siglen = (size_t) pqcSigLen;
        return 1;
    }

    if (sigsize < (size_t) pqcSigLen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    
    if (ht_none == pCtx->mdCid)
    {
        status = CRYPTO_INTERFACE_QS_SIG_sign((QS_CTX *) pKey->pKeyData, DIGI_EVP_RandomRngFun, NULL, (ubyte *) tbs, (ubyte4) tbslen,
                                              (ubyte *) sig, (ubyte4) sigsize, &pqcSigLen);
    }
    else
    {
        status = CRYPTO_INTERFACE_QS_SIG_signDigest((QS_CTX *) pKey->pKeyData, DIGI_EVP_RandomRngFun, NULL, pCtx->mdCid,
                                                    (ubyte *) tbs, (ubyte4) tbslen, (ubyte *) sig, (ubyte4) sigsize,
                                                    &pqcSigLen);
    }
    if (OK != status)
        goto exit;

    *siglen = (size_t) pqcSigLen;

exit:

    return (OK == status ? 1 : 0);
}

static int digiprov_pqc_verify(void *vctx, const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs, size_t tbslen)
{
    MSTATUS status = OK;
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    DP_PQC_KEY *pKey;
    ubyte4 vStatus = 1;

    if (!digiprov_is_running())
        return 0;

    if (NULL == pCtx)
        return 0;

    pKey = (DP_PQC_KEY *) pCtx->pKey;
    if (NULL == pKey)
        return 0;

    if (!digiprov_pqc_validate_key_for_op(pKey, pCtx->operation))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    if (ht_none == pCtx->mdCid)
    {
        status = CRYPTO_INTERFACE_QS_SIG_verify((QS_CTX *) pKey->pKeyData, (ubyte *) tbs, (ubyte4) tbslen,
                                                (ubyte *) sig, (ubyte4) siglen, &vStatus);
    }
    else
    {
        status = CRYPTO_INTERFACE_QS_SIG_verifyDigest((QS_CTX *) pKey->pKeyData, pCtx->mdCid, (ubyte *) tbs, (ubyte4) tbslen,
                                                (ubyte *) sig, (ubyte4) siglen, &vStatus);
            
    }
    return ((OK == status && 0 == vStatus) ? 1 : 0);
}

static int digiprov_pqc_sig_get_and_validate_md(ubyte *pMdCid, int nid, size_t secSize, size_t cid)
{
    switch(nid)
    {
        case NID_sha256:
        case NID_shake128:
    
            if(secSize > 128)
            {
                return 0;
            }
            else
            {
                if (NID_sha256 == nid)
                    *pMdCid = ht_sha256;
                else
                    *pMdCid = ht_shake128;
            }
            break;
        
        case NID_sha512:
            *pMdCid = ht_sha512;
            break;

        case NID_shake256:
            
            if (cid <= DP_MLDSA_MAX_CID) /* shake256 not allowed with ml-dsa */
            {
                return 0;
            }
            else
            {
                *pMdCid = ht_shake256;
            }
            break;

        default:
            return 0;            
    }

    return 1;
}

static int digiprov_pqc_sig_setup_md(DP_PQCSIG_CTX *pCtx, const char *mdname, const char *mdprops)
{
    EVP_MD *md = NULL;
    size_t mdname_len;
 
    if (mdname == NULL)
        return 1;

    mdname_len = (size_t) DIGI_STRLEN((const sbyte *) mdname);
    if (mdname_len >= sizeof(pCtx->mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s exceeds name buffer length", mdname);
        return 0;
    }
    
    if (mdprops == NULL)
        mdprops = pCtx->propq;

    md = EVP_MD_fetch(pCtx->libctx, mdname, mdprops);
    if (md == NULL) 
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s could not be fetched", mdname);
        return 0;
    }

    /* this setup_md method is called after digiprov_pqc_signverify_init so pKey is there */
    if (!digiprov_pqc_sig_get_and_validate_md(&pCtx->mdCid, EVP_MD_nid(md), pCtx->pKey->secSize, pCtx->pKey->cid))
    {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                       "digest=%s", mdname);
        EVP_MD_free(md);
        return 0;
    }

    if (!pCtx->flag_allow_md) 
    {
        if (pCtx->mdname[0] != '\0' && !EVP_MD_is_a(md, pCtx->mdname)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                           "digest %s != %s", mdname, pCtx->mdname);
            EVP_MD_free(md);
            return 0;
        }
        EVP_MD_free(md);
        return 1;
    }

    EVP_MD_CTX_free(pCtx->mdctx);
    EVP_MD_free(pCtx->md);

    pCtx->mdctx = NULL;
    pCtx->md = md;
    pCtx->mdsize = EVP_MD_get_size(pCtx->md);
    (void) DIGI_MEMCPY(pCtx->mdname, mdname, mdname_len + 1);
  
    return 1;
}

static int digiprov_pqc_digest_signverify_init(void *vctx, const char *mdname, void *pqc, const OSSL_PARAM params[], int operation)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;

    /* next call checks digiprov_is_running */    
    if (!digiprov_pqc_signverify_init(vctx, pqc, params, operation))
        return 0;

    if (!digiprov_pqc_sig_setup_md(pCtx, mdname, NULL))
        return 0;

    pCtx->flag_allow_md = 0;

    if (pCtx->mdctx == NULL) 
    {
        pCtx->mdctx = EVP_MD_CTX_new();
        if (pCtx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(pCtx->mdctx, pCtx->md, params))
        goto error;
    return 1;

error:

    EVP_MD_CTX_free(pCtx->mdctx);
    pCtx->mdctx = NULL;
    return 0;
}

static int digiprov_pqc_digest_sign_init(void *vctx, const char *mdname, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_digest_signverify_init(vctx, mdname, pqc, params, EVP_PKEY_OP_SIGN);
}

static int digiprov_pqc_digest_verify_init(void *vctx, const char *mdname, void *pqc, const OSSL_PARAM params[])
{
    return digiprov_pqc_digest_signverify_init(vctx, mdname, pqc, params, EVP_PKEY_OP_VERIFY);
}

static int digiprov_pqc_digest_signverify_update(void *vctx, const unsigned char *data, size_t datalen)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;

    if (pCtx == NULL || pCtx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(pCtx->mdctx, data, datalen);
}

static int digiprov_pqc_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (pCtx == NULL || pCtx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to pqc_sign.
     */
    if (sig != NULL && !EVP_DigestFinal_ex(pCtx->mdctx, digest, &dlen))
        return 0;

    pCtx->flag_allow_md = 1;

    return digiprov_pqc_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int digiprov_pqc_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!digiprov_is_running())
        return 0;

    if (pCtx == NULL || pCtx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to pqc_sign.
     */
    if (sig != NULL && !EVP_DigestFinal_ex(pCtx->mdctx, digest, &dlen))
        return 0;

    pCtx->flag_allow_md = 1;

    return digiprov_pqc_verify(vctx, sig, siglen, digest, (size_t)dlen);
}

static void digiprov_pqc_sig_freectx(void *vctx)
{
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *)vctx;

    (void) DIGI_FREE((void **) &pCtx->propq);
    EVP_MD_CTX_free(pCtx->mdctx);
    EVP_MD_free(pCtx->md);
    pCtx->mdctx = NULL;
    pCtx->md = NULL;
    pCtx->mdsize = 0;

    digiprov_pqc_key_free(pCtx->pKey); /* might just lower the ref count */

    (void) DIGI_FREE((void **) &pCtx);
}

static void *digiprov_pqc_sig_dupctx(void *vctx)
{
    MSTATUS status = OK;
    DP_PQCSIG_CTX *pCtx = (DP_PQCSIG_CTX *) vctx;
    DP_PQCSIG_CTX *pNewCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(*pNewCtx));
    if (OK != status)
        return NULL;

    pNewCtx->libctx = pCtx->libctx;
    pNewCtx->operation = pCtx->operation;
    pNewCtx->mdCid = pCtx->mdCid;
    pNewCtx->flag_allow_md = pCtx->flag_allow_md;
    pNewCtx->mdsize = pCtx->mdsize;

    (void) DIGI_MEMCPY((void *) pNewCtx->mdname, (void *) pCtx->mdname, OSSL_MAX_NAME_SIZE);

    /* we don't deep copy the key, md and md_ctx, just update the ref count */
    if (NULL != pCtx->pKey && !digiprov_pqc_key_up_ref(pCtx->pKey))
        goto err;

    pNewCtx->pKey = pCtx->pKey;

    if (NULL != pCtx->md && !EVP_MD_up_ref(pCtx->md))
        goto err;

    pNewCtx->md = pCtx->md;

    if (NULL != pCtx->mdctx)
    {
        pNewCtx->mdctx = EVP_MD_CTX_new();
        if (pNewCtx->mdctx == NULL || !EVP_MD_CTX_copy_ex(pNewCtx->mdctx, pCtx->mdctx))
            goto err;
    }

    if (NULL != pCtx->propq)
    {
        status = digiprov_strdup((void **) &pNewCtx->propq, pCtx->propq);
        if (OK != status)
            goto err;
    }

    return pNewCtx;

 err:
    digiprov_pqc_sig_freectx(pNewCtx);
    return NULL; 
}

static int digiprov_pqc_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL ? ctx->mdname : EVP_MD_get0_name(ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = 
{
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_sig_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int digiprov_pqc_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!digiprov_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL && !digiprov_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!digiprov_pqc_sig_setup_md(ctx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = 
{
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] =
{
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_pqc_sig_settable_ctx_params(void *vctx, ossl_unused void *provctx)
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;

    if (ctx != NULL && !ctx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

static int digiprov_pqc_sig_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *digiprov_pqc_sig_gettable_ctx_md_params(void *vctx)
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static int digiprov_pqc_sig_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *digiprov_pqc_sig_settable_ctx_md_params(void *vctx)
{
    DP_PQCSIG_CTX *ctx = (DP_PQCSIG_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(ctx->md);
}

const OSSL_DISPATCH digiprov_pqc_signature_functions[] =
{
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))digiprov_pqc_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))digiprov_pqc_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))digiprov_pqc_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void (*)(void))digiprov_pqc_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void (*)(void))digiprov_pqc_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))digiprov_pqc_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))digiprov_pqc_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))digiprov_pqc_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,  (void (*)(void))digiprov_pqc_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,(void (*)(void))digiprov_pqc_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))digiprov_pqc_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))digiprov_pqc_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void))digiprov_pqc_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))digiprov_pqc_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_pqc_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))digiprov_pqc_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_pqc_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,   (void (*)(void))digiprov_pqc_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_pqc_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,      (void (*)(void))digiprov_pqc_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))digiprov_pqc_sig_settable_ctx_md_params },
    { 0, NULL }
};

#endif /* #ifdef __ENABLE_DIGICERT_PQC__ */
