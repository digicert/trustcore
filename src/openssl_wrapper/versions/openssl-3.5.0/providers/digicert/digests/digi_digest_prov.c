/*
 * digi_digest_prov.c
 *
 * Digest implementations for OSSL 3.0 provider ADAPTED FROM OPENSSL CODE
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
 * Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*---------------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/md4.h"
#include "../../../src/crypto/md5.h"
#include "../../../src/crypto/sha1.h"
#include "../../../src/crypto/sha256.h"
#include "../../../src/crypto/sha512.h"
#include "../../../src/crypto/sha3.h"
#include "../../../src/crypto/blake2.h"
#include "../../../src/crypto_interface/crypto_interface_md4.h"
#include "../../../src/crypto_interface/crypto_interface_md5.h"
#include "../../../src/crypto_interface/crypto_interface_sha1.h"
#include "../../../src/crypto_interface/crypto_interface_sha256.h"
#include "../../../src/crypto_interface/crypto_interface_sha512.h"
#include "../../../src/crypto_interface/crypto_interface_sha3.h"
#include "../../../src/crypto_interface/crypto_interface_blake2.h"

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
#include "prov/provider_ctx.h"
#include "crypto/evp.h"
#include "openssl/../../crypto/evp/evp_local.h"
#include "digiprov.h"

/*---------------------------------------------------------------------------------------------------------*/

#define PROV_DIGEST_FLAG_XOF             0x0001
#define PROV_DIGEST_FLAG_ALGID_ABSENT    0x0002

/*--------------------------------------------- COMMON DIGEST ---------------------------------------------*/

int moc_evp_digest_init(EVP_MD_CTX *ctx);
int moc_evp_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int moc_evp_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
int moc_evp_digest_copy(EVP_MD_CTX *pDest, const EVP_MD_CTX *pSrc);
int moc_evp_digest_cleanup(EVP_MD_CTX *ctx);
int moc_sha3_init(EVP_MD_CTX *pEvpCtx);
int moc_sha3_update(EVP_MD_CTX *pEvpCtx, const void *pData, size_t count);
int moc_sha3_final(EVP_MD_CTX *pEvpCtx, unsigned char *pOut);
int moc_sha3_copy(EVP_MD_CTX *pDest, const EVP_MD_CTX *pSrc);
int moc_sha3_cleanup(EVP_MD_CTX *pEvpCtx);

static MSTATUS moc_evp_sha3_224_complete(const ubyte *pIn, ubyte4 inLen, ubyte *pOut)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_224, (ubyte *) pIn, inLen, pOut, 0);
}

static MSTATUS moc_evp_sha3_256_complete(const ubyte *pIn, ubyte4 inLen, ubyte *pOut)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_256, (ubyte *) pIn, inLen, pOut, 0);
}

static MSTATUS moc_evp_sha3_384_complete(const ubyte *pIn, ubyte4 inLen, ubyte *pOut)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_384, (ubyte *) pIn, inLen, pOut, 0);
}

static MSTATUS moc_evp_sha3_512_complete(const ubyte *pIn, ubyte4 inLen, ubyte *pOut)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_512, (ubyte *) pIn, inLen, pOut, 0);
}

static int digiprov_common_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
                                                     size_t paramsz, unsigned long flags)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0)) {
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
        return 0;
    }
    return 1;
}

static void *digiprov_hash_newctx(void *provCtx)
{
    void *pCtx = NULL;

    if (!digiprov_is_running())
        return NULL;

    /* If calloc fails pCtx will be NULL */
    (void) DIGI_CALLOC((void **)&pCtx, 1, sizeof(EVP_MD_CTX));
    return pCtx;
}

static int digiprov_hash_init(void *ctx, int nid, int md_size)
{
    MSTATUS status = OK;
    int ret = 0;
    EVP_MD_CTX *pMdCtx = NULL;
    MOC_EVP_MD_CTX *pInnerCtx = NULL;
    EVP_MD *pMd = NULL;

    if (!digiprov_is_running())
        return 0;

    /* Set up the context structure that moc_evp_digest expects */
    pMdCtx = (EVP_MD_CTX *)ctx;
    status = DIGI_CALLOC((void **)&pInnerCtx, 1, sizeof(MOC_EVP_MD_CTX));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pMd, 1, sizeof(EVP_MD));
    if (OK != status)
        goto exit;

    pMd->type = nid;
    pMd->md_size = md_size;
    pMdCtx->digest = pMd;
    pMd = NULL;
    pMdCtx->md_data = pInnerCtx;
    pInnerCtx = NULL;

    ret = moc_evp_digest_init(pMdCtx);
    if (1 == ret)
    {
        status = OK;
    }
    else
    {
        status = ERR_GENERAL;
    }

exit:
    if (NULL != pInnerCtx)
    {
        DIGI_FREE((void **)&pInnerCtx);
    }
    if (NULL != pMd)
    {
        DIGI_FREE((void **)&pMd);
    }
    if (OK == status)
    {
        return 1;
    }

    return 0;
}

static int digiprov_sha3_init(void *ctx, int nid, int md_size)
{
    MSTATUS status = OK;
    int ret = 0;
    EVP_MD_CTX *pMdCtx = NULL;
    MOC_EVP_MD_SHA3_CTX *pInnerCtx = NULL;
    EVP_MD *pMd = NULL;

    if (!digiprov_is_running())
        return 0;

    /* Set up the context structure that moc_evp_digest expects */
    pMdCtx = (EVP_MD_CTX *)ctx;
    status = DIGI_CALLOC((void **)&pInnerCtx, 1, sizeof(MOC_EVP_MD_SHA3_CTX));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pMd, 1, sizeof(EVP_MD));
    if (OK != status)
        goto exit;

    pMd->type = nid;
    pMd->md_size = md_size;
    pMdCtx->digest = pMd;
    pMd = NULL;
    pMdCtx->md_data = pInnerCtx;
    pInnerCtx = NULL;

    ret = moc_sha3_init(pMdCtx);
    if (1 == ret)
    {
        status = OK;
    }
    else
    {
        status = ERR_GENERAL;
    }

exit:
    if (NULL != pInnerCtx)
    {
        DIGI_FREE((void **)&pInnerCtx);
    }
    if (NULL != pMd)
    {
        DIGI_FREE((void **)&pMd);
    }
    if (OK == status)
    {
        return 1;
    }

    return 0;
}

static int digiprov_hash_update(void *ctx, void *data, size_t len)
{
    return moc_evp_digest_update((EVP_MD_CTX *)ctx, data, len);
}

static int digiprov_sha3_update(void *ctx, void *data, size_t len)
{
    return moc_sha3_update((EVP_MD_CTX *)ctx, data, len);
}

static int digiprov_hash_final(void *ctx, void *md, size_t *outlen, size_t mdsize)
{
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == outlen)
        return 0;

    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;

    ret = moc_evp_digest_final((EVP_MD_CTX *)ctx, (unsigned char *)md);
    if (1 == ret)
    {
        *outlen = mdsize;
        return 1;
    }

    return 0;
}

static int digiprov_sha3_final(void *ctx, void *md, size_t *outlen, size_t mdsize)
{
    int ret = 0;
    EVP_MD_CTX * pCtx = (EVP_MD_CTX *) ctx;
    MOC_EVP_MD_SHA3_CTX *pMoc = NULL;

    if (!digiprov_is_running())
        return 0;

    /* ignore mdsize passed in, it's not set on xof */

    if (NULL == outlen)
        return 0;
    
    pMoc = (MOC_EVP_MD_SHA3_CTX *) pCtx->md_data;
    if (NULL == md)
    {
        *outlen = (size_t) pMoc->mdSize;
        return 1;
    }

    *outlen = 0;

    ret = moc_sha3_final(pCtx, (unsigned char *)md);
    if (1 == ret)
    {
        *outlen = (size_t) pMoc->mdSize;
        return 1;
    }

    return 0;
}

static int digiprov_complete_digest(void *provctx, const void *data, size_t len,
                                    unsigned char *md, size_t mdsize, size_t *outlen, 
                                    MSTATUS (digestFun)(const ubyte *, ubyte4, ubyte *) )
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;

    if (NULL == outlen)
        return 0;
    
    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;
    status = digestFun((const ubyte *)data, (ubyte4)len, (ubyte *)md);
    if (OK != status)
        return 0;
    
    *outlen = mdsize;
    return 1;
}

static void digiprov_hash_freectx(void *ctx)
{
    EVP_MD_CTX *pMdCtx = NULL;

    pMdCtx = (EVP_MD_CTX *)ctx;
    if (NULL != pMdCtx)
    {
        if (NULL != pMdCtx->md_data)
        {
            moc_evp_digest_cleanup(pMdCtx);
            DIGI_FREE((void **)&pMdCtx->md_data);
        }
        if (NULL != pMdCtx->digest)
        {
            DIGI_FREE((void **)&(pMdCtx->digest));
        }
    }
    DIGI_FREE((void **)&pMdCtx);
}

static void digiprov_sha3_freectx(void *ctx)
{
    EVP_MD_CTX *pMdCtx = NULL;

    pMdCtx = (EVP_MD_CTX *)ctx;
    if (NULL != pMdCtx)
    {
        if (NULL != pMdCtx->md_data)
        {
            moc_sha3_cleanup(pMdCtx);
            DIGI_FREE((void **)&pMdCtx->md_data);
        }
        if (NULL != pMdCtx->digest)
        {
            DIGI_FREE((void **)&(pMdCtx->digest));
        }
    }
    DIGI_FREE((void **)&pMdCtx);
}

static void *digiprov_hash_dupctx(void *ctx)
{
    MSTATUS status = OK;
    EVP_MD_CTX *pOrig = NULL;
    EVP_MD_CTX *pCopy = NULL;

    if (!digiprov_is_running())
        return NULL;

    if (NULL != ctx)
    {
        pOrig = (EVP_MD_CTX *)ctx;

        status = DIGI_CALLOC((void **)&pCopy, 1, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCopy, pOrig, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pCopy->digest, 1, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY((ubyte *) pCopy->digest, pOrig->digest, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pCopy->md_data, 1, sizeof(MOC_EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCopy->md_data, pOrig->md_data, sizeof(MOC_EVP_MD_CTX));
        if (OK != status)
            goto exit;
   
        if (NID_sha3_224 == pOrig->digest->type || 
            NID_sha3_256 == pOrig->digest->type ||
            NID_sha3_384 == pOrig->digest->type || 
            NID_sha3_512 == pOrig->digest->type || 
            NID_shake128 == pOrig->digest->type || 
            NID_shake256 == pOrig->digest->type )
        {
            if(1 != moc_sha3_copy(pCopy, (EVP_MD_CTX *)ctx))
            {
                status = ERR_GENERAL;
                goto exit;
            }      
        }  
        else
        {
            if(1 != moc_evp_digest_copy((EVP_MD_CTX *)ctx, pCopy))
            {
                status = ERR_GENERAL;
                goto exit;
            }
        }
    }

exit:
    if (OK != status)
    {
        if (NULL != pCopy)
        {
            if (NULL != pCopy->md_data)
            {
                DIGI_FREE((void **)&pCopy->md_data);
            }
            if (NULL != pCopy->digest)
            {
                DIGI_FREE((void **)&pCopy->digest);
            }
            DIGI_FREE((void **)&pCopy);
        }

        pCopy = NULL;
    }

    return pCopy;
}

static const OSSL_PARAM known_shake_settable_ctx_params[] = 
{
    {OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_shake_settable_ctx_params(void *ctx, void *provctx)
{
    return known_shake_settable_ctx_params;
}

static int digiprov_shake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    EVP_MD_CTX *ctx = (EVP_MD_CTX *) vctx;
    MOC_EVP_MD_SHA3_CTX *pMocCtx = NULL;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    /* we'll set the size in both the ctx's digest and the moc ctx */
    pMocCtx = (MOC_EVP_MD_SHA3_CTX *) ctx->md_data;

    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, (size_t *) &ctx->digest->md_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    pMocCtx->mdSize = ctx->digest->md_size;
    return 1;
}

/*-------------------------------------------- SPECIFIC DIGEST --------------------------------------------*/

/*------------------------------------------------ MD-4 ------------------------------------------------*/

static int digiprov_md4_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_md4, MD4_RESULT_SIZE);
}

static int digiprov_md4_digest(void *provctx, const void *data, size_t len,
                               unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_MD4_completeDigest);
}

static int digiprov_md4_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, MD4_BLOCK_SIZE, MD4_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ MD-5 ------------------------------------------------*/

static int digiprov_md5_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_md5, MD5_RESULT_SIZE);
}

static int digiprov_md5_digest(void *provctx, const void *data, size_t len,
                               unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_MD5_completeDigest);
}

static int digiprov_md5_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, MD5_BLOCK_SIZE, MD5_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA-1 ------------------------------------------------*/

static int digiprov_sha1_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_sha1, SHA1_RESULT_SIZE);
}

static int digiprov_sha1_digest(void *provctx, const void *data, size_t len,
                                unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_SHA1_completeDigest);
}

static int digiprov_sha1_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA1_BLOCK_SIZE, SHA1_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA-224 ------------------------------------------------*/

static int digiprov_sha224_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_sha224, SHA224_RESULT_SIZE);
}

static int digiprov_sha224_digest(void *provctx, const void *data, size_t len,
                                  unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_SHA224_completeDigest);
}

static int digiprov_sha224_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA224_BLOCK_SIZE, SHA224_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA-256 ------------------------------------------------*/

static int digiprov_sha256_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_sha256, SHA256_RESULT_SIZE);
}

static int digiprov_sha256_digest(void *provctx, const void *data, size_t len,
                                  unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_SHA256_completeDigest);
}

static int digiprov_sha256_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA256_BLOCK_SIZE, SHA256_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA-384 ------------------------------------------------*/

static int digiprov_sha384_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_sha384, SHA384_RESULT_SIZE);
}


static int digiprov_sha384_digest(void *provctx, const void *data, size_t len,
                                  unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_SHA384_completeDigest);
}

static int digiprov_sha384_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA384_BLOCK_SIZE, SHA384_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA-512 ------------------------------------------------*/

static int digiprov_sha512_init(void *ctx)
{
    return digiprov_hash_init(ctx, NID_sha512, SHA512_RESULT_SIZE);
}

static int digiprov_sha512_digest(void *provctx, const void *data, size_t len,
                                  unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, CRYPTO_INTERFACE_SHA512_completeDigest);
}

static int digiprov_sha512_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA512_BLOCK_SIZE, SHA512_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA 3-224 ------------------------------------------------*/

static int digiprov_sha3_224_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_sha3_224, SHA3_224_RESULT_SIZE);
}

static int digiprov_sha3_224_digest(void *provctx, const void *data, size_t len,
                                    unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, moc_evp_sha3_224_complete);
}

static int digiprov_sha3_224_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA3_224_BLOCK_SIZE, SHA3_224_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA 3-256 ------------------------------------------------*/

static int digiprov_sha3_256_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_sha3_256, SHA3_256_RESULT_SIZE);
}

static int digiprov_sha3_256_digest(void *provctx, const void *data, size_t len,
                                    unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, moc_evp_sha3_256_complete);
}

static int digiprov_sha3_256_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA3_256_BLOCK_SIZE, SHA3_256_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA 3-384 ------------------------------------------------*/

static int digiprov_sha3_384_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_sha3_384, SHA3_384_RESULT_SIZE);
}

static int digiprov_sha3_384_digest(void *provctx, const void *data, size_t len,
                                    unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, moc_evp_sha3_384_complete);
}

static int digiprov_sha3_384_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA3_384_BLOCK_SIZE, SHA3_384_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHA 3-512 ------------------------------------------------*/

static int digiprov_sha3_512_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_sha3_512, SHA3_512_RESULT_SIZE);
}

static int digiprov_sha3_512_digest(void *provctx, const void *data, size_t len,
                                    unsigned char *md, size_t mdsize, size_t *outlen)
{
    return digiprov_complete_digest(provctx, data, len, md, mdsize, outlen, moc_evp_sha3_512_complete);
}

static int digiprov_sha3_512_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHA3_512_BLOCK_SIZE, SHA3_512_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ SHAKE 128 ------------------------------------------------*/

static int digiprov_shake_128_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_shake128, 0);
}

static int digiprov_shake_128_digest(void *provctx, const void *data, size_t len,
                                     unsigned char *md, size_t mdsize, size_t *outlen)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;

    if (NULL == outlen)
        return 0;
    
    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }
    
    *outlen = 0;
    status = CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE128, (ubyte *) data, (ubyte4) len, 
                                                  (ubyte *) md, (ubyte4) mdsize);
    if (OK != status)
        return 0;
    
    *outlen = mdsize;
    return 1;
}

static int digiprov_shake_128_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHAKE128_BLOCK_SIZE, SHAKE128_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT | PROV_DIGEST_FLAG_XOF);
}

/*------------------------------------------------ SHAKE 256 ------------------------------------------------*/

static int digiprov_shake_256_init(void *ctx)
{
    return digiprov_sha3_init(ctx, NID_shake256, 0);
}

static int digiprov_shake_256_digest(void *provctx, const void *data, size_t len,
                                     unsigned char *md, size_t mdsize, size_t *outlen)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;

    if (NULL == outlen)
        return 0;
    
    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }
    
    *outlen = 0;
    status = CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE256, (ubyte *) data, (ubyte4) len, 
                                                  (ubyte *) md, (ubyte4) mdsize);
    if (OK != status)
        return 0;
    
    *outlen = mdsize;
    return 1;
}


static int digiprov_shake_256_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, SHAKE256_BLOCK_SIZE, SHAKE256_RESULT_SIZE, PROV_DIGEST_FLAG_ALGID_ABSENT | PROV_DIGEST_FLAG_XOF);
}

/*------------------------------------------------ BLAKE 2S ------------------------------------------------*/

static int digiprov_blake2s256_init(void *ctx)
{
    MSTATUS status = OK;
    int ret = 0;
    EVP_MD_CTX *pMdCtx = NULL;
    BulkCtx pInnerCtx = NULL;
    EVP_MD *pMd = NULL;

    if (!digiprov_is_running())
        return 0;

    /* Set up the context structure that moc_evp_digest expects */
    pMdCtx = (EVP_MD_CTX *)ctx;

    status = CRYPTO_INTERFACE_BLAKE_2S_alloc(&pInnerCtx);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pMd, sizeof(EVP_MD));
    if (OK != status)
        goto exit;

    pMd->type = NID_blake2s256;
    pMd->md_size = MOC_BLAKE2S_MAX_OUTLEN; /* 32 */
    pMdCtx->digest = pMd;
    pMd = NULL;
    pMdCtx->md_data = pInnerCtx;
    pInnerCtx = NULL;

    status = CRYPTO_INTERFACE_BLAKE_2S_init(pMdCtx->md_data, MOC_BLAKE2S_MAX_OUTLEN, NULL, 0);
    if (OK != status)
        goto exit;
    
    ret = 1;

exit:

    if (NULL != pInnerCtx)
    {
        DIGI_FREE((void **)&pInnerCtx);
    }
    if (NULL != pMd)
    {
        DIGI_FREE((void **)&pMd);
    }

    return ret;
}

static int digiprov_blake2s256_update(void *ctx, void *data, size_t len)
{
    MSTATUS status = CRYPTO_INTERFACE_BLAKE_2S_update(((EVP_MD_CTX *) ctx)->md_data, (ubyte *) data, (ubyte4) len);
    return OK == status ? 1 : 0;
}

static int digiprov_blake2s256_final(void *ctx, void *md, size_t *outlen, size_t mdsize)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;
    
    if (NULL == outlen)
        return 0;

    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;

    status = CRYPTO_INTERFACE_BLAKE_2S_final(((EVP_MD_CTX *)ctx)->md_data, (ubyte *) md);
    if (OK != status)
        goto err;

    *outlen = mdsize;
    return 1;

err:

    return 0;
}

static int digiprov_blake2s256_digest(void *provctx, const void *data, size_t len,
                                      unsigned char *md, size_t mdsize, size_t *outlen)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;
    
    if (NULL == outlen)
        return 0;
    
    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;
    status = CRYPTO_INTERFACE_BLAKE_2S_complete(NULL, 0, (ubyte *) data, (ubyte4) len, (ubyte *) md, (ubyte4) mdsize);
    if (OK != status)
        return 0;
    
    *outlen = mdsize;
    return 1;
}

static void digiprov_blake2s256_freectx(void *ctx)
{
    EVP_MD_CTX *pMdCtx = NULL;

    pMdCtx = (EVP_MD_CTX *)ctx;
    if (NULL != pMdCtx)
    {
        if (NULL != pMdCtx->md_data)
        {
            (void) CRYPTO_INTERFACE_BLAKE_2S_delete(&pMdCtx->md_data);
        }
        if (NULL != pMdCtx->digest)
        {
            DIGI_FREE((void **)&(pMdCtx->digest));
        }
    }
    DIGI_FREE((void **)&pMdCtx);
}

static void *digiprov_blake2s256_dupctx(void *ctx)
{
    MSTATUS status = OK;
    EVP_MD_CTX *pOrig = NULL;
    EVP_MD_CTX *pCopy = NULL;

    if (!digiprov_is_running())
        return NULL;

    if (NULL != ctx)
    {
        pOrig = (EVP_MD_CTX *)ctx;

        status = DIGI_CALLOC((void **)&pCopy, 1, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCopy, pOrig, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pCopy->digest, 1, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY((ubyte *) pCopy->digest, pOrig->digest, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_BLAKE_2S_alloc(&pCopy->md_data);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_BLAKE_2S_cloneCtx((BLAKE2S_CTX *) pCopy->md_data, (BLAKE2S_CTX *) pOrig->md_data);
        if (OK != status)
            goto exit;
    }

exit:

    if (OK != status)
    {
        if (NULL != pCopy)
        {
            digiprov_blake2s256_freectx(pCopy);
        }
        pCopy = NULL;
    }

    return (void *) pCopy;
}

static int digiprov_blake2s256_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, MOC_BLAKE2S_BLOCKLEN, MOC_BLAKE2S_MAX_OUTLEN, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*------------------------------------------------ BLAKE 2B ------------------------------------------------*/

static int digiprov_blake2b512_init(void *ctx)
{
    MSTATUS status = OK;
    int ret = 0;
    EVP_MD_CTX *pMdCtx = NULL;
    BulkCtx pInnerCtx = NULL;
    EVP_MD *pMd = NULL;

    if (!digiprov_is_running())
        return 0;
    
    /* Set up the context structure that moc_evp_digest expects */
    pMdCtx = (EVP_MD_CTX *)ctx;

    status = CRYPTO_INTERFACE_BLAKE_2B_alloc(&pInnerCtx);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pMd, sizeof(EVP_MD));
    if (OK != status)
        goto exit;

    pMd->type = NID_blake2b512;
    pMd->md_size = MOC_BLAKE2B_MAX_OUTLEN; /* 64 */
    pMdCtx->digest = pMd;
    pMd = NULL;
    pMdCtx->md_data = pInnerCtx;
    pInnerCtx = NULL;

    status = CRYPTO_INTERFACE_BLAKE_2B_init(pMdCtx->md_data, MOC_BLAKE2B_MAX_OUTLEN, NULL, 0);
    if (OK != status)
        goto exit;

    ret = 1;

exit:

    if (NULL != pInnerCtx)
    {
        DIGI_FREE((void **)&pInnerCtx);
    }
    if (NULL != pMd)
    {
        DIGI_FREE((void **)&pMd);
    }

    return ret;
}

static int digiprov_blake2b512_update(void *ctx, void *data, size_t len)
{
    MSTATUS status = CRYPTO_INTERFACE_BLAKE_2B_update(((EVP_MD_CTX *) ctx)->md_data, (ubyte *) data, (ubyte4) len);
    return OK == status ? 1 : 0;
}

static int digiprov_blake2b512_final(void *ctx, void *md, size_t *outlen, size_t mdsize)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;
    
    if (NULL == outlen)
        return 0;

    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;

    status = CRYPTO_INTERFACE_BLAKE_2B_final(((EVP_MD_CTX *)ctx)->md_data, (ubyte *) md);
    if (OK != status)
        goto err;

    *outlen = mdsize;
    return 1;

err:

    return 0;
}

static int digiprov_blake2b512_digest(void *provctx, const void *data, size_t len,
                                      unsigned char *md, size_t mdsize, size_t *outlen)
{
    MSTATUS status = OK;

    if (!digiprov_is_running())
        return 0;
    
    if (NULL == outlen)
        return 0;
    
    if (NULL == md)
    {
        *outlen = mdsize;
        return 1;
    }

    *outlen = 0;
    status = CRYPTO_INTERFACE_BLAKE_2B_complete(NULL, 0, (ubyte *) data, (ubyte4) len, (ubyte *) md, (ubyte4) mdsize);
    if (OK != status)
        return 0;
    
    *outlen = mdsize;
    return 1;
}

static void digiprov_blake2b512_freectx(void *ctx)
{
    EVP_MD_CTX *pMdCtx = NULL;

    pMdCtx = (EVP_MD_CTX *)ctx;
    if (NULL != pMdCtx)
    {
        if (NULL != pMdCtx->md_data)
        {
            (void) CRYPTO_INTERFACE_BLAKE_2B_delete(&pMdCtx->md_data);
        }
        if (NULL != pMdCtx->digest)
        {
            DIGI_FREE((void **)&(pMdCtx->digest));
        }
    }
    DIGI_FREE((void **)&pMdCtx);
}

static void *digiprov_blake2b512_dupctx(void *ctx)
{
    MSTATUS status = OK;
    EVP_MD_CTX *pOrig = NULL;
    EVP_MD_CTX *pCopy = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    if (NULL != ctx)
    {
        pOrig = (EVP_MD_CTX *)ctx;

        status = DIGI_CALLOC((void **)&pCopy, 1, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCopy, pOrig, sizeof(EVP_MD_CTX));
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pCopy->digest, 1, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY((ubyte *) pCopy->digest, pOrig->digest, sizeof(EVP_MD));
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_BLAKE_2B_alloc(&pCopy->md_data);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_BLAKE_2B_cloneCtx((BLAKE2B_CTX *) pCopy->md_data, (BLAKE2B_CTX *) pOrig->md_data);
        if (OK != status)
            goto exit;
    }

exit:

    if (OK != status)
    {
        if (NULL != pCopy)
        {
            digiprov_blake2b512_freectx(pCopy);
        }
        pCopy = NULL;
    }

    return (void *) pCopy;
}

static int digiprov_blake2b512_get_params(OSSL_PARAM params[])
{
    return digiprov_common_digest_default_get_params(params, MOC_BLAKE2B_BLOCKLEN, MOC_BLAKE2B_MAX_OUTLEN, PROV_DIGEST_FLAG_ALGID_ABSENT);
}

/*-------------------------------------------- FUNCTION TABLES --------------------------------------------*/

const OSSL_DISPATCH digiprov_md4_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_md4_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_md4_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_md4_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_md5_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_md5_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_md5_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_md5_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha1_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha1_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha1_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha1_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha224_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha224_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha224_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha224_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha256_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha256_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha256_get_params},
    { 0, NULL }
};
const OSSL_DISPATCH digiprov_sha384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha384_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha384_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha384_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha512_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_hash_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_hash_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha512_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_hash_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha512_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha3_224_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha3_224_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha3_224_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha3_224_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha3_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha3_256_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha3_256_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha3_256_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha3_384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha3_384_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha3_384_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha3_384_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_sha3_512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_sha3_512_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_sha3_512_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_sha3_512_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_shake_128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_shake_128_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_shake_128_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_shake_128_get_params},
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,      (void (*)(void))digiprov_shake_set_ctx_params }, \
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_shake_settable_ctx_params },  
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_shake_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_shake_256_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_sha3_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_shake_256_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_sha3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_hash_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_shake_256_get_params},
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,      (void (*)(void))digiprov_shake_set_ctx_params }, \
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_shake_settable_ctx_params },  
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_blake2s256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_blake2s256_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_blake2s256_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_blake2s256_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_blake2s256_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_blake2s256_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_blake2s256_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_blake2s256_get_params},
    { 0, NULL }
};

const OSSL_DISPATCH digiprov_blake2b512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,     (void (*)(void)) digiprov_hash_newctx },
    { OSSL_FUNC_DIGEST_INIT,       (void (*)(void)) digiprov_blake2b512_init },
    { OSSL_FUNC_DIGEST_UPDATE,     (void (*)(void)) digiprov_blake2b512_update },
    { OSSL_FUNC_DIGEST_FINAL,      (void (*)(void)) digiprov_blake2b512_final },
    { OSSL_FUNC_DIGEST_DIGEST,     (void (*)(void)) digiprov_blake2b512_digest },
    { OSSL_FUNC_DIGEST_FREECTX,    (void (*)(void)) digiprov_blake2b512_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,     (void (*)(void)) digiprov_blake2b512_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) digiprov_blake2b512_get_params},
    { 0, NULL }
};
