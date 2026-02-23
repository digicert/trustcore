/*
 * moc_dsa_pmeth.c
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

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "e_moc_EVP_ciphers.h"

#ifdef __ENABLE_DIGICERT_DSA__

/* DSA pkey context structure */

extern BIGNUM* DIGI_EVP_vlong2BN(vlong *v);

typedef struct {
    /* Parameter gen parameters */
    int nbits;                  /* size of p in bits (default: 1024) */
    int qbits;                  /* size of q in bits (default: 160) */
    const EVP_MD* pmd;          /* MD for parameter generation */
    /* Keygen callback info */
    int gentmp[2];
    /* message digest */
    const EVP_MD* md;           /* MD for the signature */
} MOC_DSA_PKEY_CTX;

static int moc_pkey_dsa_init(EVP_PKEY_CTX *ctx)
{
    MOC_DSA_PKEY_CTX *dctx;
    dctx = OPENSSL_malloc(sizeof(MOC_DSA_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->nbits = 2048;
    dctx->qbits = 256;
    dctx->pmd = NULL;
    dctx->md = NULL;

    ctx->data = dctx;
    ctx->keygen_info = dctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static int moc_pkey_dsa_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
#else
static int moc_pkey_dsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
#endif
{
    MOC_DSA_PKEY_CTX *dctx, *sctx;
    if (!moc_pkey_dsa_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->nbits = sctx->nbits;
    dctx->qbits = sctx->qbits;
    dctx->pmd = sctx->pmd;
    dctx->md = sctx->md;
    return 1;
}

static void moc_pkey_dsa_cleanup(EVP_PKEY_CTX *ctx)
{
    MOC_DSA_PKEY_CTX *dctx = ctx->data;

    if (dctx)
        OPENSSL_free(dctx);
}


static int moc_pkey_dsa_sign_init(EVP_PKEY_CTX* ctx)
{
    return 1;
}

static int moc_pkey_dsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    MOC_DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_sign(type, tbs, (int)tbslen, sig, &sltmp, dsa);

    if (ret <= 0)
        return ret;
    *siglen = sltmp;
    return 1;
}


static int moc_pkey_dsa_verify_init(EVP_PKEY_CTX* ctx)
{
    return 1;
}

static int moc_pkey_dsa_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    MOC_DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_verify(type, tbs, (int)tbslen, sig, siglen, dsa);

    return ret;
}

static int moc_pkey_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    MOC_DSA_PKEY_CTX *dctx = ctx->data;

    switch (type)
    {
        case EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
            if (p1 < 256)
                return -2;
            dctx->nbits = p1;
            return 1;

        case EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS:
            if (p1 != 160 && p1 != 224 && p1 && p1 != 256)
                return -2;
            dctx->qbits = p1;
            return 1;

        case EVP_PKEY_CTRL_DSA_PARAMGEN_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha512)
            {
                return 0;
            }
            dctx->md = p2;
            return 1;

        case EVP_PKEY_CTRL_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_dsa &&
                EVP_MD_type((const EVP_MD *)p2) != NID_dsaWithSHA &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha512)
            {
                return 0;
            }
            dctx->md = p2;
            return 1;

        case EVP_PKEY_CTRL_GET_MD:
            *(const EVP_MD **)p2 = dctx->md;
            return 1;

        case EVP_PKEY_CTRL_DIGESTINIT:
        case EVP_PKEY_CTRL_PKCS7_SIGN:
        case EVP_PKEY_CTRL_CMS_SIGN:
            return 1;

        case EVP_PKEY_CTRL_PEER_KEY:
            return -2;
        default:
            return -2;

    }
}

static int moc_pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (!strcmp(type, "dsa_paramgen_bits"))
    {
        int nbits;
        nbits = atoi(value);
        return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
    }
    if (!strcmp(type, "dsa_paramgen_q_bits"))
    {
        int qbits = atoi(value);
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits,
                                 NULL);
    }
    if (!strcmp(type, "dsa_paramgen_md"))
    {
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0,
                                 (void *)EVP_get_digestbyname(value));
    }
    return -2;
}

#ifdef __ENABLE_DIGICERT_DSA__

static int getHashSizeAndQSizeFromKeysize(int keySize, int* hashSize, int* qSize) {
    switch (keySize)
    {
#ifdef  __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
        case 1024:
        {
            *qSize = 160;
            *hashSize = DSA_sha1;
        }
        break;
#endif
        case 2048:
        {
            *qSize = 256;
            *hashSize = DSA_sha256;
        }
        break;
        case 3072:
        {
            *qSize = 256;
            *hashSize = DSA_sha256;
        }
        break;
        default: 
        {
            return ERR_DSA_INVALID_KEYLENGTH;
        }
    }
    return 0;
}

static int moc_dsa_paramgen(DSA *ret, size_t bits, size_t qbits,
                         const EVP_MD *evpmd, const unsigned char *seed_in,
                         size_t seed_len, unsigned char *seed_out,
                         int *counter_ret, unsigned long *h_ret, BN_GENCB *cb) {
    MSTATUS  status = -1;
    randomContext*  pRandomContext = NULL;
    DSAKey* pDSAKey = NULL;
    ubyte seed[64] = {0};
    DSAHashType hashType;
    int N;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MDsaKeyTemplate template = { 0 };
#endif

    if (OK > (status = getHashSizeAndQSizeFromKeysize((int)bits, (int*)&hashType, &N)))
        goto exit;

    if (g_pRandomContext == NULL)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
        {
            goto exit;
        }
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pDSAKey);
#else
    status = DSA_createKey(&pDSAKey);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if(OK > (status = CRYPTO_INTERFACE_DSA_generatePQ(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, (ubyte4)bits, N, hashType, NULL, seed, NULL)))
        goto exit;
#else
    if(OK > (status = generatePQ(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, (ubyte4)bits, N, hashType, NULL, seed, NULL)))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_DSA_generateRandomGAux(pDSAKey, pRandomContext, NULL, NULL, NULL)))
        goto exit;
#else
    if (OK != (status = DSA_generateRandomG(pDSAKey, pRandomContext, NULL, NULL)))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(
            pDSAKey, &template, MOC_GET_PUBLIC_KEY_DATA)))
        goto exit;

#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    ret->params.p = BN_bin2bn(template.pP, template.pLen, NULL);
    ret->params.q = BN_bin2bn(template.pQ, template.qLen, NULL);
    ret->params.g = BN_bin2bn(template.pG, template.gLen, NULL);
#else
    ret->p = BN_bin2bn(template.pP, template.pLen, NULL);
    ret->q = BN_bin2bn(template.pQ, template.qLen, NULL);
    ret->g = BN_bin2bn(template.pG, template.gLen, NULL);
#endif
#else
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
    ret->params.p = DIGI_EVP_vlong2BN(DSA_P(pDSAKey));
    ret->params.q = DIGI_EVP_vlong2BN(DSA_Q(pDSAKey));
    ret->params.g = DIGI_EVP_vlong2BN(DSA_G(pDSAKey));
#else
    ret->p = DIGI_EVP_vlong2BN(DSA_P(pDSAKey));
    ret->q = DIGI_EVP_vlong2BN(DSA_Q(pDSAKey));
    ret->g = DIGI_EVP_vlong2BN(DSA_G(pDSAKey));
#endif
#endif

    status = 1;
exit:
    if (pRandomContext && (g_pRandomContext != pRandomContext))
    {
        RANDOM_releaseContext(&pRandomContext);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(pDSAKey, &template);
#endif

    if(pDSAKey != NULL)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pDSAKey, NULL);
#else
        DSA_freeKey(&pDSAKey, NULL);
#endif
    }

    return status;
}
#endif

static int moc_pkey_dsa_paramgeninit(EVP_PKEY_CTX* ctx) 
{
   return 1;
}

static int moc_pkey_dsa_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;
    MOC_DSA_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    
    if (ctx->pkey_gencb)
    {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    }
    else
        pcb = NULL;

    dsa = DSA_new();
    if (!dsa)
        return 0;

    ret = moc_dsa_paramgen(dsa, dctx->nbits, dctx->qbits, dctx->pmd,
                               NULL, 0, NULL, NULL, NULL, pcb);
    if (ret)
        EVP_PKEY_assign_DSA(pkey, dsa);
    else
        DSA_free(dsa);
    return ret;
}

static int moc_pkey_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;

    if (ctx->pkey == NULL)
    {
        return 0;
    }
    dsa = DSA_new();
    if (!dsa)
        return 0;
    EVP_PKEY_assign_DSA(pkey, dsa);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return DSA_generate_key(pkey->pkey.dsa);
}

static const EVP_PKEY_METHOD moc_dsa_pkey_meth = {
    EVP_PKEY_DSA,
    EVP_PKEY_FLAG_AUTOARGLEN,
    moc_pkey_dsa_init,
    moc_pkey_dsa_copy,
    moc_pkey_dsa_cleanup,

    moc_pkey_dsa_paramgeninit,
    moc_pkey_dsa_paramgen,

    0,
    moc_pkey_dsa_keygen,

    moc_pkey_dsa_sign_init,
    moc_pkey_dsa_sign,

    moc_pkey_dsa_verify_init,
    moc_pkey_dsa_verify,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0, 0,

    moc_pkey_dsa_ctrl,
    moc_pkey_dsa_ctrl_str
};

void MOC_registerDSAMeth(EVP_PKEY_METHOD **dsa_pmeth)
{
    *dsa_pmeth = (EVP_PKEY_METHOD*)&moc_dsa_pkey_meth;
}
#endif
