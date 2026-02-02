/*
 * crypto_hash_fips.c
 *
 * Hash suite operations for FIPS
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

/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../common/mdefs.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#ifdef __ENABLE_DIGICERT_ECC__

/*
 We define a NO HASH algorithm that just copies the message
 over to a buffer. Note for ECDSA, the largest curve P521,
 uses only the leftmost 521 bits, so in theory we can ignore
 the message after the first 521 bits. In practice our implmentation
 first truncates the hash after the first 72 bytes though, so we'll
 be content to still copy over up to 72 bytes.
 */
#define ECC_MAX_DIGEST_LEN 72

typedef struct NO_HASH_CTX
{
    ubyte pMsgCopy[ECC_MAX_DIGEST_LEN];
    ubyte4 msgCopyLen;

} NO_HASH_CTX;

static MSTATUS NO_HASH_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx)
{
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    return DIGI_MALLOC(pCtx, sizeof(NO_HASH_CTX));
}

static MSTATUS NO_HASH_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    ((NO_HASH_CTX *) ctx)->msgCopyLen = 0;
    return OK;
}

static MSTATUS NO_HASH_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, const ubyte *pMessage, ubyte4 messageLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    NO_HASH_CTX *pCtx = (NO_HASH_CTX *) ctx;
    ubyte4 copyLen = 0;

    if (NULL == pCtx || (messageLen && NULL == pMessage))
        goto exit;

    copyLen = messageLen < (ECC_MAX_DIGEST_LEN - pCtx->msgCopyLen) ? messageLen : ECC_MAX_DIGEST_LEN - pCtx->msgCopyLen;

    if (copyLen)
    {
        status = DIGI_MEMCPY(pCtx->pMsgCopy + pCtx->msgCopyLen, pMessage, copyLen);
        if (OK != status)
            goto exit;

        pCtx->msgCopyLen += copyLen;
    }
    /* else no-op */

exit:

    return status;
}

static MSTATUS NO_HASH_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult)
{
    NO_HASH_CTX *pCtx = (NO_HASH_CTX *) ctx;

    if (NULL == pCtx || NULL == pResult)
        return ERR_NULL_POINTER;

    if (pCtx->msgCopyLen)
    {
        /* ok to ignore return codes */
        DIGI_MEMCPY(pResult, pCtx->pMsgCopy, pCtx->msgCopyLen);
        DIGI_MEMSET(pCtx->pMsgCopy, 0x00, pCtx->msgCopyLen);
        pCtx->msgCopyLen = 0;
    }

    return OK;
}

static MSTATUS NO_HASH_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx)
{
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    return DIGI_FREE(pCtx);
}

/********************************************************************/

static const BulkHashAlgo NoHashSuite =
{
    ECC_MAX_DIGEST_LEN /* special case, max digest len */, 0, NO_HASH_allocDigest, NO_HASH_freeDigest,
    NO_HASH_initDigest, NO_HASH_updateDigest, NO_HASH_finalDigest, NULL, NULL, NULL, ht_none
};
#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_MD2__
static const BulkHashAlgo MD2Suite =
    { MD2_RESULT_SIZE, MD2_BLOCK_SIZE, MD2Alloc, MD2Free,
        (BulkCtxInitFunc)MD2Init, (BulkCtxUpdateFunc)MD2Update, (BulkCtxFinalFunc)MD2Final, NULL, NULL, NULL, ht_md2};
#endif

#ifdef __ENABLE_DIGICERT_MD4__
static const BulkHashAlgo MD4Suite =
    { MD4_RESULT_SIZE, MD4_BLOCK_SIZE, MD4Alloc, MD4Free,
        (BulkCtxInitFunc)MD4Init, (BulkCtxUpdateFunc)MD4Update, (BulkCtxFinalFunc)MD4Final, NULL, NULL, NULL, ht_md4 };
#endif

static const BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE, MD5_BLOCK_SIZE, MD5Alloc_m, MD5Free_m,
        (BulkCtxInitFunc)MD5Init_m, (BulkCtxUpdateFunc)MD5Update_m, (BulkCtxFinalFunc)MD5Final_m, NULL, NULL, NULL, ht_md5 };

static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
        (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };

#ifndef __DISABLE_DIGICERT_SHA224__
static const BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest,
        (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224 };
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
        (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
        (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

#ifdef __ENABLE_DIGICERT_SHA3__

static MSTATUS SHA3_initDigest224(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_224);
}

static MSTATUS SHA3_initDigest256(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_256);
}

static MSTATUS SHA3_initDigest384(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_384);
}

static MSTATUS SHA3_initDigest512(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHA3_512);
}

static MSTATUS SHAKE128_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHAKE128);
}

static MSTATUS SHAKE256_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    return SHA3_initDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, MOCANA_SHA3_MODE_SHAKE256);
}

static MSTATUS SHA3_FINAL(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult)
{
    return SHA3_finalDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, pResult, 0 /* ignored */);
}

static MSTATUS SHAKE128_FINAL(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult)
{
    return SHA3_finalDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, pResult, SHAKE128_RESULT_SIZE);
}

static MSTATUS SHAKE256_FINAL(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult)
{
    return SHA3_finalDigest(MOC_HASH(hwAccelCtx) (SHA3_CTX *) ctx, pResult, SHAKE256_RESULT_SIZE);
}

static const BulkHashAlgo SHA3_224Suite =
{
    SHA3_224_RESULT_SIZE, SHA3_224_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest224, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_FINAL,
    NULL, NULL, NULL, ht_sha3_224
};

static const BulkHashAlgo SHA3_256Suite =
{
    SHA3_256_RESULT_SIZE, SHA3_256_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest256, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_FINAL,
    NULL, NULL, NULL, ht_sha3_256
};

static const BulkHashAlgo SHA3_384Suite =
{
    SHA3_384_RESULT_SIZE, SHA3_384_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest384, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_FINAL,
    NULL, NULL, NULL, ht_sha3_384
};

static const BulkHashAlgo SHA3_512Suite =
{
    SHA3_512_RESULT_SIZE, SHA3_512_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHA3_initDigest512, (BulkCtxUpdateFunc)SHA3_updateDigest, (BulkCtxFinalFunc) SHA3_FINAL,
    NULL, NULL, NULL, ht_sha3_512
};

static const BulkHashAlgo SHAKE128Suite = 
{
    SHAKE128_RESULT_SIZE, SHAKE128_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHAKE128_initDigest, (BulkCtxUpdateFunc) SHA3_updateDigest, SHAKE128_FINAL, (BulkCtxFinalXOFFunc) SHA3_finalDigest,
    NULL, NULL, ht_shake128
};

static const BulkHashAlgo SHAKE256Suite = 
{
    SHAKE256_RESULT_SIZE, SHAKE256_BLOCK_SIZE, SHA3_allocDigest, SHA3_freeDigest,
    SHAKE256_initDigest, (BulkCtxUpdateFunc) SHA3_updateDigest, SHAKE256_FINAL, (BulkCtxFinalXOFFunc) SHA3_finalDigest,
    NULL, NULL, ht_shake256
};
#endif /* __ENABLE_DIGICERT_SHA3__ */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_FIPS_getRSAHashAlgo( ubyte rsaAlgoId, const BulkHashAlgo **ppBulkHashAlgo)
{
    MSTATUS status = OK;

    switch (rsaAlgoId)
    {
#ifdef __ENABLE_DIGICERT_ECC__
        case ht_none:
            *ppBulkHashAlgo = &NoHashSuite;
            break;
#endif

#ifdef __ENABLE_DIGICERT_MD2__
        case ht_md2: /* md2withRSAEncryption */
            *ppBulkHashAlgo = &MD2Suite;
            break;
#endif

#ifdef __ENABLE_DIGICERT_MD4__
        case ht_md4: /* md4withRSAEncryption: */
            *ppBulkHashAlgo = &MD4Suite;
            break;
#endif

        case ht_md5: /* md5withRSAEncryption: */
            *ppBulkHashAlgo = &MD5Suite;
            break;

        case ht_sha1: /* sha1withRSAEncryption: */
            *ppBulkHashAlgo = &SHA1Suite;
            break;

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256: /* sha256withRSAEncryption: */
            *ppBulkHashAlgo = &SHA256Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384: /* sha384withRSAEncryption: */
            *ppBulkHashAlgo = &SHA384Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512: /* sha512withRSAEncryption: */
            *ppBulkHashAlgo = &SHA512Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224: /* sha224withRSAEncryption: */
            *ppBulkHashAlgo = &SHA224Suite;
            break;
#endif

#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
            *ppBulkHashAlgo = &SHA3_224Suite;
            break;

        case ht_sha3_256:
            *ppBulkHashAlgo = &SHA3_256Suite;
            break;

        case ht_sha3_384:
            *ppBulkHashAlgo = &SHA3_384Suite;
            break;

        case ht_sha3_512:
            *ppBulkHashAlgo = &SHA3_512Suite;
            break;

        case ht_shake128:
            *ppBulkHashAlgo = &SHAKE128Suite;
            break;

        case ht_shake256:
            *ppBulkHashAlgo = &SHAKE256Suite;
            break;
#endif

        default:
            status = ERR_INVALID_ARG;
            break;
    }

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
MOC_EXTERN MSTATUS CRYPTO_FIPS_getECCHashAlgo(ubyte eccAlgoId, BulkHashAlgo **ppBulkHashAlgo)
{
    MSTATUS status = OK;

    /* The MD hashes are not allowed for ECC */
    if (ht_md2 == eccAlgoId || ht_md4 == eccAlgoId || ht_md5 == eccAlgoId)
    {
        return ERR_EC_INVALID_HASH_ALGO;
    }

    /* call the legacy common method with RSA in the name */
    status = CRYPTO_FIPS_getRSAHashAlgo(eccAlgoId, (const BulkHashAlgo **) ppBulkHashAlgo);
    /* Convert error code to EC specific one */
    if (OK != status)
    {
        status = ERR_EC_INVALID_HASH_ALGO;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */
