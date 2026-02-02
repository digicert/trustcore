/*
 * hmac.c
 *
 * Hash Message Authentication Code
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
@file       hmac.c

@brief      Documentation file for the NanoCrypto HMAC API.

@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto HMAC API.

@flags
There are no flag dependencies to enable the functions in the NanoCrypto HMAC API.

@filedoc    hmac.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_INTERNAL__

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"

#ifndef __DISABLE_DIGICERT_SHA256__
#include "../crypto/sha256.h"
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
#include "../crypto/sha512.h"
#endif

#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../harness/harness.h"

/* hmac specific definitions */
#define IPAD                    0x36
#define OPAD                    0x5c

/*------------------------------------------------------------------*/

#ifndef __HMAC_MD5_HARDWARE_HASH__

extern MSTATUS
HMAC_MD5(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
         const ubyte* text, sbyte4 textLen,
         const ubyte* textOpt, sbyte4 textOptLen,
         ubyte result[MD5_DIGESTSIZE])
{
    FIPS_LOG_DECL_SESSION;
    MD5_CTX     context = { 0 };
    ubyte       kpad[MD5_BLOCK_SIZE];
    ubyte       tk[MD5_DIGESTSIZE];
    sbyte4      i;
    MSTATUS     status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_HMAC_MD5,0);

    status = ERR_NULL_POINTER;
    if ((NULL == key) && (0 < keyLen))
        goto exit;

    if ((NULL == text) && (0 < textLen))
        goto exit;

    /* if key is longer than MD5_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > MD5_BLOCK_SIZE)
    {
        if (OK > (status = MD5_completeDigest(MOC_HASH(hwAccelCtx) key, keyLen, tk)))
            goto exit;

        key = tk;
        keyLen = MD5_DIGESTSIZE;
    }

    /*
     * HMAC_MD5 transform:
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated MD5_BLOCK_SIZE times
     * opad is the byte 0x5c repeated MD5_BLOCK_SIZE times
     * and text is the data being protected
     */

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x36 */
    for (i=0; i < keyLen; ++i)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < MD5_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner MD5 */
    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &context, kpad, MD5_BLOCK_SIZE)))
        goto exit;

    if ((NULL != text) && (0 < textLen))
        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &context, text, textLen)))
            goto exit;

    if ((NULL != textOpt) && (0 < textOptLen))
        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &context, textOpt, textOptLen)))
            goto exit;

    if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCtx) &context, result)))
        goto exit;

    /* XOR key padded with 0 to MD5_BLOCK_SIZE with 0x5C*/
    for (i=0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < MD5_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ OPAD;

    /* perform outer MD5 */
    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &context, kpad, MD5_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &context, result, MD5_DIGESTSIZE)))
        goto exit;
    status = MD5Final_m(MOC_HASH(hwAccelCtx) &context, result);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_HMAC_MD5,0);
    return status;
}

#endif /* __HMAC_MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifndef __HMAC_MD5_HARDWARE_HASH__

MOC_EXTERN MSTATUS
HMAC_MD5_quick(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
               const ubyte* pText, sbyte4 textLen,
               ubyte* pResult /* MD5_DIGESTSIZE */)
{
    /* try to use the quick version; for hw acceleration */
    return HMAC_MD5(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult);
}
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
        (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif


#ifndef __DISABLE_DIGICERT_SHA512__
static MSTATUS
HMAC_SHA512_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA512_RESULT_SIZE])
{
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA512Suite);
}
#endif

/*------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_SHA512__
extern MSTATUS
HMAC_SHA512(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen,
          ubyte result[SHA512_RESULT_SIZE])
{
    MSTATUS status;
    ubyte* newString = NULL;

    if ((NULL == key) && (0 < keyLen))
        return ERR_NULL_POINTER;

    if ((NULL == text) && (0 < textLen))
        return ERR_NULL_POINTER;

    if (0 < (textLen + textOptLen))
    {
        if(OK > (status = DIGI_MALLOC((void **)&newString,sizeof(ubyte)*(textLen + textOptLen)))){
            return status;
        }
    }
    DIGI_MEMCPY(newString,text,textLen);
    DIGI_MEMCPY(newString+textLen,textOpt,textOptLen);
    status = HMAC_SHA512_quick(MOC_HASH(hwAccelCtx) key,keyLen,newString,textLen+textOptLen,result);
    DIGI_FREE((void **)&newString);
    return status;

} /* HMAC_SHA512 */
#endif /* __DISABLE_DIGICERT_SHA512__ */

#ifndef __DISABLE_DIGICERT_SHA256__
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif


#ifndef __DISABLE_DIGICERT_SHA256__
static MSTATUS
HMAC_SHA256_quick(MOC_HASH(hwAccelDescr hwAccelCtx)
                  const ubyte* pKey, sbyte4 keyLen,
                  const ubyte* pText, sbyte4 textLen,
                  ubyte result[SHA256_RESULT_SIZE])
{
    return HmacQuick(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, result, &SHA256Suite);
}
#endif


#ifndef __DISABLE_DIGICERT_SHA256__
extern MSTATUS
HMAC_SHA256(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen,
          ubyte result[SHA256_RESULT_SIZE])
{

    MSTATUS status;
    ubyte* newString = NULL;

    if ((NULL == key) && (0 < keyLen))
        return ERR_NULL_POINTER;

    if ((NULL == text) && (0 < textLen))
        return ERR_NULL_POINTER;

    if (0 < (textLen + textOptLen))
    {
        if(OK > (status = DIGI_MALLOC((void **)&newString,sizeof(ubyte)*(textLen + textOptLen)))){
            return status;
        }
    }
    DIGI_MEMCPY(newString,text,textLen);
    DIGI_MEMCPY(newString+textLen,textOpt,textOptLen);
    status = HMAC_SHA256_quick(MOC_HASH(hwAccelCtx) key,keyLen,newString,textLen+textOptLen,result);
    DIGI_FREE((void **)&newString);
    return status;
} /* HMAC_SHA256 */
#endif /* __DISABLE_DIGICERT_SHA256__ */


#ifndef __HMAC_SHA1_HARDWARE_HASH__

/* compute the HMAC output using SHA1 the textOpt can be null */
extern MSTATUS
HMAC_SHA1(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen,
          ubyte result[SHA_HASH_RESULT_SIZE])
{
    FIPS_LOG_DECL_SESSION;
    shaDescr    context = { 0 };
    ubyte       kpad[SHA1_BLOCK_SIZE];
    ubyte       tk[SHA1_RESULT_SIZE];
    sbyte4      i;
    MSTATUS     status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC_SHA1,0);

    status = ERR_NULL_POINTER;
    if ((NULL == key) && (0 < keyLen))
        goto exit;

    if ((NULL == text) && (0 < textLen))
        goto exit;

    /* if key is longer than SHA1_BLOCK_SIZE bytes reset it to key = SHA1(key) */
    if (keyLen > SHA1_BLOCK_SIZE)
    {
        if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) key, keyLen, tk)))
            goto exit;

        key = tk;
        keyLen = SHA1_RESULT_SIZE;
    }

    /*
     * HMAC_SHA1 transform:
     * SHA1(K XOR opad, SHA1(K XOR ipad, (text | textOpt)))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated SHA1_BLOCK_SIZE times
     * opad is the byte 0x5c repeated SHA1_BLOCK_SIZE times
     * and text is the data being protected
     */

    /* XOR key padded with 0 to SHA1_BLOCK_SIZE with 0x36 */
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < SHA1_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner SHA1 */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, kpad, SHA1_BLOCK_SIZE)))
        goto exit;

    if ((NULL != text) && (0 < textLen))
        if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, text, textLen)))
            goto exit;

    if ((NULL != textOpt) && (0 < textOptLen))
        if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, textOpt, textOptLen)))
            goto exit;
    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &context, result)))
        goto exit;

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x5C*/
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < SHA1_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ OPAD;

    /* perform outer SHA1 */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, kpad, SHA1_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, result, SHA1_RESULT_SIZE)))
        goto exit;
    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &context, result);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC_SHA1,0);
    return status;

} /* HMAC_SHA1 */

#endif /* __HMAC_SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifndef __HMAC_SHA1_HARDWARE_HASH__

MOC_EXTERN MSTATUS
HMAC_SHA1_quick(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                const ubyte* pText, sbyte4 textLen,
                ubyte* pResult /* SHA_HASH_RESULT_SIZE */)
{
    /* try to use the quick version; for hw acceleration */
    return HMAC_SHA1(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult);

}
#endif /* __HMAC_SHA1_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifndef __HMAC_SHA1_HARDWARE_HASH__

/* compute the HMAC output using SHA1 */
/**
@private
@internal
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        hashing_ungrouped
*/
extern MSTATUS
HMAC_SHA1Ex(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
                        const ubyte* texts[], sbyte4 textLens[],
                        sbyte4 numTexts, ubyte result[SHA_HASH_RESULT_SIZE])
{
    FIPS_LOG_DECL_SESSION;
    shaDescr    context = { 0 };
    ubyte       kpad[SHA1_BLOCK_SIZE];
    ubyte       tk[SHA1_RESULT_SIZE];
    sbyte4      i;
    MSTATUS     status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC_SHA1,0);

    status = ERR_NULL_POINTER;

    if ((NULL == texts) || (NULL == textLens))
        goto exit;

    if ((NULL == key) && (0 < keyLen))
        goto exit;

    /* if key is longer than HMAC_BUFFER_SIZE bytes reset it to key = SHA1(key) */
    if (keyLen > SHA1_BLOCK_SIZE)
    {
        if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) key, keyLen, tk)))
            goto exit;

        key = tk;
        keyLen = SHA1_RESULT_SIZE;
    }

    /*
     * HMAC_SHA1 transform:
     * SHA1(K XOR opad, SHA1(K XOR ipad, (text | textOpt)))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x36 */
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < SHA1_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner SHA1 */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, kpad, SHA1_BLOCK_SIZE)))
        goto exit;
    for (i = 0; i < numTexts; ++i)
    {
        if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, texts[i], textLens[i])))
            goto exit;
    }
    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &context, result)))
        goto exit;

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x5C*/
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < SHA1_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ OPAD;

    /* perform outer SHA1 */
    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, kpad, SHA1_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &context, result, SHA1_RESULT_SIZE)))
        goto exit;
    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &context, result);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC_SHA1,0);
    return status;

} /* HMAC_SHA1Ex */

#endif /* __HMAC_SHA1_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacCreate(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **pctx,
            const BulkHashAlgo *pBHAlgo)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    status = ERR_NULL_POINTER;
    if((NULL == pctx) || (NULL == pBHAlgo))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, sizeof(HMAC_CTX), TRUE, (void **)pctx)))
        goto exit;

    (*pctx)->pBHAlgo = pBHAlgo;
    (*pctx)->hashCtxt = NULL;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacCreate */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacDelete(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **pctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    MSTATUS fstatus = OK;
    HMAC_CTX *ctx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    if(NULL == pctx)
        goto exit;

    ctx = *pctx;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    if (NULL == ctx) goto exit;

    status = ctx->pBHAlgo->freeFunc(MOC_HASH(hwAccelCtx) &(ctx->hashCtxt));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nHMAC - Before Zeroization\n");
        for( counter = 0; counter < sizeof(HMAC_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

    /* Zeroize the sensitive information before deleting the memory */
    (void) DIGI_MEMSET((unsigned char *)ctx,0x00,sizeof(HMAC_CTX));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nHMAC - After Zeroization\n");
        for( counter = 0; counter < sizeof(HMAC_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

    fstatus = CRYPTO_FREE(hwAccelCtx, TRUE, (void **)pctx);
    if (OK == status)
        status = fstatus;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacDelete */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacKey(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, const ubyte *key, ubyte4 keyLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    ubyte4  keyBlkSize = 0;
    const BulkHashAlgo* pBHAlgo = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    status = ERR_NULL_POINTER;
    if (NULL == ctx)
        goto exit;

    if ((NULL == key) && (0 < keyLen))
        goto exit;

    pBHAlgo = ctx->pBHAlgo;
    keyBlkSize = pBHAlgo->blockSize;

    /* if key is longer than the hash algo block size reset it to key=hash(key) */
    if (keyLen > keyBlkSize)
    {
        BulkCtx             hash_ctx = NULL;

        if ((NULL == ctx->hashCtxt) &&
            (OK > (status = pBHAlgo->allocFunc(MOC_HASH(hwAccelCtx) &ctx->hashCtxt))))
        {
            goto exit;
        }

        hash_ctx = ctx->hashCtxt;

        if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) hash_ctx)))
            goto exit;
        if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hash_ctx, key, keyLen)))
            goto exit;
        if (OK > (status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) hash_ctx, ctx->key)))
            goto exit;

        ctx->keyLen = pBHAlgo->digestSize;
    }
    else
    {
        DIGI_MEMCPY(ctx->key, key, keyLen);
        ctx->keyLen = keyLen;
    }

    status = HmacReset(MOC_HASH(hwAccelCtx) ctx);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacKey */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacReset(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    const BulkHashAlgo* pBHAlgo;
    BulkCtx             hash_ctx = NULL;
    ubyte4              keyLen;
    ubyte*              kpad;
    ubyte*              key;
    ubyte4              i;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    if(NULL == ctx)
        goto exit;

    pBHAlgo = ctx->pBHAlgo;
    keyLen = ctx->keyLen;
    kpad = ctx->kpad;
    key = ctx->key;

    if ((NULL == ctx->hashCtxt) &&
        (OK > (status = pBHAlgo->allocFunc(MOC_HASH(hwAccelCtx) &ctx->hashCtxt))))
    {
        goto exit;
    }

    hash_ctx = ctx->hashCtxt;

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x36 */
    for (i=0; i < keyLen; ++i)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < pBHAlgo->blockSize; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner hash */
    if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) hash_ctx)))
        goto exit;
    status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hash_ctx, kpad, pBHAlgo->blockSize);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacReset */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacUpdate(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, const ubyte *text, ubyte4 textLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    if (NULL == ctx || (NULL == text && textLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (textLen)
    {
        status = ctx->pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) ctx->hashCtxt, text, textLen);
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacUpdate */

/*------------------------------------------------------------------*/

extern MSTATUS
HmacFinal(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, ubyte *result)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    const BulkHashAlgo *pBHAlgo;
    BulkCtx hash_ctx;
    ubyte4 keyLen;
    ubyte *kpad;
    ubyte *key;
    ubyte4 i;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    if (NULL == ctx)
        goto exit;

    pBHAlgo = ctx->pBHAlgo;
    hash_ctx = ctx->hashCtxt;
    keyLen = ctx->keyLen;
    kpad = ctx->kpad;
    key = ctx->key;

    if (OK > (status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) hash_ctx, result)))
        goto exit;

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x5C*/
    for (i=0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < pBHAlgo->blockSize; i++)
        kpad[i] = 0 ^ OPAD;

    /* perform outer hash */
    if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) hash_ctx)))
        goto exit;
    if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hash_ctx, kpad, pBHAlgo->blockSize)))
        goto exit;
    if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) hash_ctx, result, pBHAlgo->digestSize)))
        goto exit;
    status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) hash_ctx, result);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacFinal */


/*------------------------------------------------------------------*/

extern MSTATUS
HmacQuick(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
          const ubyte* pText, sbyte4 textLen, ubyte* pResult,
          const BulkHashAlgo *pBHAlgo)
{
    return HmacQuickEx(MOC_HASH( hwAccelCtx) pKey, keyLen,
          pText, textLen, NULL, 0, pResult, pBHAlgo);
} /* HmacQuick */


/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    hmac_functions
*/
extern MSTATUS
HmacQuicker(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
            const ubyte* pText, sbyte4 textLen, ubyte* pResult,
            const BulkHashAlgo *pBHAlgo,
            HMAC_CTX *ctx)
{
    return HmacQuickerEx(MOC_HASH( hwAccelCtx) pKey, keyLen,
                         pText, textLen, NULL, 0, pResult, pBHAlgo, ctx);
} /* HmacQuick */


/*------------------------------------------------------------------*/


extern MSTATUS
HmacQuickEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
          const ubyte* pText, sbyte4 textLen,
          const ubyte* pOptText, ubyte4 optTextLen,
          ubyte* pResult, const BulkHashAlgo *pBHAlgo)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    HMAC_CTX *ctx = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    status = ERR_NULL_POINTER;
    if ((NULL == pResult) || (NULL == pBHAlgo))
        goto exit;

    if ((NULL == pText) && (0 < textLen))
        goto exit;

    if (OK > (status = HmacCreate(MOC_HASH(hwAccelCtx) &ctx, pBHAlgo)))
        goto exit;
    if (OK > (status = HmacKey(MOC_HASH(hwAccelCtx) ctx, pKey, keyLen)))
        goto exit;

    if ((NULL != pText) && (0 < textLen))
        if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) ctx, pText, textLen)))
            goto exit;

    if ((NULL != pOptText) && (0 < optTextLen))
        if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) ctx, pOptText, optTextLen)))
            goto exit;

    status = HmacFinal(MOC_HASH(hwAccelCtx) ctx, pResult);

exit:
    if (ctx) HmacDelete(MOC_HASH(hwAccelCtx) &ctx);

    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacQuickEx */



/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    hmac_functions
*/
extern MSTATUS
HmacQuickerEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
              const ubyte* pText, sbyte4 textLen,
              const ubyte* pOptText, ubyte4 optTextLen,
              ubyte* pResult,
              const BulkHashAlgo *pBHAlgo,
              HMAC_CTX *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    MOC_UNUSED(pBHAlgo);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    status = ERR_NULL_POINTER;
    if ((NULL == pResult) || (NULL == ctx))
        goto exit;

    if ((NULL == pText) && (0 < textLen))
        goto exit;

    if (OK > (status = HmacKey(MOC_HASH(hwAccelCtx) ctx, pKey, keyLen)))
        goto exit;
    if ((NULL != pText) && (0 < textLen))
        if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) ctx, pText, textLen)))
            goto exit;

    if ((NULL != pOptText) && (0 < optTextLen))
        if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) ctx, pOptText, optTextLen)))
            goto exit;
    status = HmacFinal(MOC_HASH(hwAccelCtx) ctx, pResult);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
} /* HmacQuickerEx */

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    hmac_functions
*/
extern MSTATUS
HmacQuickerInline(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
          const ubyte* pText, sbyte4 textLen, ubyte* pResult,
          const BulkHashAlgo *pBHAlgo,BulkCtx context)
{
    return HmacQuickerInlineEx(MOC_HASH( hwAccelCtx) pKey, keyLen,
          pText, textLen, NULL, 0, pResult, pBHAlgo,context);
} /* HmacQuickerInline */

/*------------------------------------------------------------------*/
/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    hmac_functions
*/
extern MSTATUS
HmacQuickerInlineEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
         const ubyte* text, sbyte4 textLen,
         const ubyte* textOpt, sbyte4 textOptLen,
         ubyte* pResult,const BulkHashAlgo *pBHAlgo,BulkCtx context)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS     status = ERR_NULL_POINTER;
    ubyte4 		  blockSize, digestSize;
    ubyte       kpad[HMAC_BLOCK_SIZE];
    ubyte       tk[HMAC_BLOCK_SIZE];
    sbyte4      i;

    if (NULL == pBHAlgo)
        goto exit;

    blockSize = pBHAlgo->blockSize;
    digestSize = pBHAlgo->digestSize;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_HMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_HMAC,0);

    if ((NULL == context) || (NULL == pResult))
        goto exit;

    if ((NULL == key) && (0 < keyLen))
        goto exit;

    if ((NULL == text) && (0 < textLen))
        goto exit;

    /* if key is longer than blockSize bytes reset it to key=MD5(key) */
    if (keyLen > (sbyte4)blockSize)
    {
    	if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) context)))
			goto exit;
		if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, key, keyLen)))
			goto exit;
		if (OK > (status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) context, tk)))
			goto exit;
        key = tk;
        keyLen = digestSize;
    }

    /* XOR key padded with 0 to HMAC_BUFFER_SIZE with 0x36 */
    for (i=0; i < keyLen; ++i)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < (sbyte4)blockSize; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner hash */
    if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) context)))
        goto exit;
    if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, kpad, blockSize)))
        goto exit;

    if ((NULL != text) && (0 < textLen))
        if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, text, textLen)))
            goto exit;

    if ((NULL != textOpt) && (0 < textOptLen))
        if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, textOpt, textOptLen)))
            goto exit;

    if (OK > (status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) context, pResult)))
        goto exit;

    /* XOR key padded with 0 to blockSize with 0x5C*/
    for (i=0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < (sbyte4)blockSize; i++)
        kpad[i] = 0 ^ OPAD;

    /* perform outer hash */
    if (OK > (status = pBHAlgo->initFunc(MOC_HASH(hwAccelCtx) context)))
        goto exit;
    if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, kpad, blockSize)))
        goto exit;
    if (OK > (status = pBHAlgo->updateFunc(MOC_HASH(hwAccelCtx) context, pResult, digestSize)))
        goto exit;
    status = pBHAlgo->finalFunc(MOC_HASH(hwAccelCtx) context, pResult);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_HMAC,0);
    return status;
}/* HmacQuickerInlineEx */
