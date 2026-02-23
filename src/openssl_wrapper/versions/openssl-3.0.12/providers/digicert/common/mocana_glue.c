/*
 * mocana_glue.c
 *
 * Defines a structures used for providing algogithm implementation through Openssl's EVP.
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

#include <openssl/obj_mac.h>
#include "mocana_glue.h"

#ifndef __DISABLE_3DES_CIPHERS__
int
DIGI_EVP_do3DESECB(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
       sbyte4 encrypt, ubyte* iv);
#endif

#ifdef __ENABLE_DIGICERT_MD2__
static const BulkHashAlgo MD2Suite =
{ MD2_RESULT_SIZE, MD2_BLOCK_SIZE, MD2Alloc, MD2Free, (BulkCtxInitFunc)MD2Init, (BulkCtxUpdateFunc)MD2Update, (BulkCtxFinalFunc)MD2Final };
#endif

/* we put the completeDigest APIs into the BulkHashAlgo for OPENSSL 3.0, and iff crypto interface is enabled */
#ifdef __ENABLE_DIGICERT_MD4__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo MD4Suite =
    { MD4_RESULT_SIZE, MD4_BLOCK_SIZE,
      CRYPTO_INTERFACE_MD4Alloc,
      CRYPTO_INTERFACE_MD4Free,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_MD4Init,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_MD4Update,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_MD4Final, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_MD4_completeDigest, NULL, ht_md4 };
#else
static const BulkHashAlgo MD4Suite =
    { MD4_RESULT_SIZE, MD4_BLOCK_SIZE, MD4Alloc, MD4Free, (BulkCtxInitFunc)MD4Init, (BulkCtxUpdateFunc)MD4Update, (BulkCtxFinalFunc)MD4Final, NULL, NULL, NULL, ht_md4 };
#endif
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE, MD5_BLOCK_SIZE,
      CRYPTO_INTERFACE_MD5Alloc_m,
      CRYPTO_INTERFACE_MD5Free_m,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_MD5Init_m,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_MD5Update_m,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_MD5Final_m, NULL, 
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_MD5_completeDigest, NULL, ht_md5 };
#else
static const BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE, MD5_BLOCK_SIZE, MD5Alloc_m, MD5Free_m, (BulkCtxInitFunc)MD5Init_m, (BulkCtxUpdateFunc)MD5Update_m, (BulkCtxFinalFunc)MD5Final_m, NULL, NULL, NULL, ht_md5 };
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA1_allocDigest,
      CRYPTO_INTERFACE_SHA1_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA1_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA1_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA1_finalDigest, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA1_completeDigest, NULL, ht_sha1 };
#else
static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest, (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA256_allocDigest,
      CRYPTO_INTERFACE_SHA256_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA256_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA256_finalDigest, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA256_completeDigest, NULL, ht_sha256 };
#else
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest, (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, {(BulkCtxFinalFunc)SHA256_finalDigest}, {NULL}, ht_sha256 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA256_allocDigest,
      CRYPTO_INTERFACE_SHA256_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA224_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA224_finalDigest, NULL, 
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA224_completeDigest, NULL, ht_sha224 };
#else
static const BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest, (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA512_allocDigest,
      CRYPTO_INTERFACE_SHA512_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA384_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA384_finalDigest, NULL, 
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA384_completeDigest, NULL, ht_sha384 };
#else
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest, (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA512_allocDigest,
      CRYPTO_INTERFACE_SHA512_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA512_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA512_finalDigest, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA512_completeDigest, NULL, ht_sha512 };
#else
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest, (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif
#endif

#ifdef __ENABLE_DIGICERT_MD2__
static const MOC_EVP_MD EVP_MD2Suite = { &MD2Suite, MD2_RESULT_SIZE, NID_md2WithRSAEncryption };
#endif
#ifdef __ENABLE_DIGICERT_MD4__
static const MOC_EVP_MD EVP_MD4Suite = { &MD4Suite, MD4_RESULT_SIZE, NID_md4WithRSAEncryption };
#endif
static const MOC_EVP_MD EVP_MD5Suite = { &MD5Suite, MD5_RESULT_SIZE, NID_md5WithRSAEncryption };

static const MOC_EVP_MD EVP_SHA1Suite = { &SHA1Suite, SHA1_RESULT_SIZE, NID_sha1WithRSAEncryption };

#if 0
static const MOC_EVP_MD EVP_DSS1Suite = { &SHA1Suite, SHA1_RESULT_SIZE, NID_dsaWithSHA1 };
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
static const MOC_EVP_MD EVP_SHA256Suite = { &SHA256Suite, SHA256_RESULT_SIZE, NID_sha256WithRSAEncryption };
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
static const MOC_EVP_MD EVP_SHA224Suite = { &SHA224Suite, SHA224_RESULT_SIZE, NID_sha224WithRSAEncryption };
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
static const MOC_EVP_MD EVP_SHA384Suite = { &SHA384Suite, SHA384_RESULT_SIZE, NID_sha384WithRSAEncryption };
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
static const MOC_EVP_MD EVP_SHA512Suite = { &SHA512Suite, SHA512_RESULT_SIZE, NID_sha512WithRSAEncryption };
#endif

#if defined(__ENABLE_DIGICERT_SHA3__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static MSTATUS CRYPTO_INTERFACE_SHA3_224_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pSha3_ctx)
{
    return CRYPTO_INTERFACE_SHA3_initDigest(MOC_HASH(hwAccelCtx) pSha3_ctx, MOCANA_SHA3_MODE_SHA3_224);
}
static MSTATUS CRYPTO_INTERFACE_SHA3_224_completeDigest(MOC_HASH(hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_224, pData, dataLen, pResult, SHA3_224_RESULT_SIZE);
}

static MSTATUS CRYPTO_INTERFACE_SHA3_256_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pSha3_ctx)
{
    return CRYPTO_INTERFACE_SHA3_initDigest(MOC_HASH(hwAccelCtx) pSha3_ctx, MOCANA_SHA3_MODE_SHA3_256);
}
static MSTATUS CRYPTO_INTERFACE_SHA3_256_completeDigest(MOC_HASH(hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_256, pData, dataLen, pResult, SHA3_256_RESULT_SIZE);
}

static MSTATUS CRYPTO_INTERFACE_SHA3_384_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pSha3_ctx)
{
    return CRYPTO_INTERFACE_SHA3_initDigest(MOC_HASH(hwAccelCtx) pSha3_ctx, MOCANA_SHA3_MODE_SHA3_384);
}
static MSTATUS CRYPTO_INTERFACE_SHA3_384_completeDigest(MOC_HASH(hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_384, pData, dataLen, pResult, SHA3_384_RESULT_SIZE);
}

static MSTATUS CRYPTO_INTERFACE_SHA3_512_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pSha3_ctx)
{
    return CRYPTO_INTERFACE_SHA3_initDigest(MOC_HASH(hwAccelCtx) pSha3_ctx, MOCANA_SHA3_MODE_SHA3_512);
}
static MSTATUS CRYPTO_INTERFACE_SHA3_512_completeDigest(MOC_HASH(hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult)
{
    return CRYPTO_INTERFACE_SHA3_completeDigest(MOCANA_SHA3_MODE_SHA3_512, pData, dataLen, pResult, SHA3_512_RESULT_SIZE);
}

static MSTATUS CRYPTO_INTERFACE_SHA3_finalDigestAux(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pSha3_ctx, ubyte *pResult)
{
    return CRYPTO_INTERFACE_SHA3_finalDigest(MOC_HASH(hwAccelCtx) pSha3_ctx, pResult, 0);
}

static const BulkHashAlgo SHA3_224Suite =
    { SHA3_224_RESULT_SIZE, SHA3_224_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA3_allocDigest,
      CRYPTO_INTERFACE_SHA3_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA3_224_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA3_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA3_finalDigestAux, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA3_224_completeDigest, NULL, ht_sha3_224 };

static const BulkHashAlgo SHA3_256Suite =
    { SHA3_256_RESULT_SIZE, SHA3_256_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA3_allocDigest,
      CRYPTO_INTERFACE_SHA3_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA3_256_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA3_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA3_finalDigestAux, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA3_256_completeDigest, NULL, ht_sha3_256 };

static const BulkHashAlgo SHA3_384Suite =
    { SHA3_384_RESULT_SIZE, SHA3_384_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA3_allocDigest,
      CRYPTO_INTERFACE_SHA3_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA3_384_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA3_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA3_finalDigestAux, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA3_384_completeDigest, NULL, ht_sha3_384 };

static const BulkHashAlgo SHA3_512Suite =
    { SHA3_512_RESULT_SIZE, SHA3_512_BLOCK_SIZE,
      CRYPTO_INTERFACE_SHA3_allocDigest,
      CRYPTO_INTERFACE_SHA3_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA3_512_initDigest,
      (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA3_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA3_finalDigestAux, NULL,
      (BulkCtxDigestFunc)CRYPTO_INTERFACE_SHA3_512_completeDigest, NULL, ht_sha3_512 };

static const MOC_EVP_MD EVP_SHA3_224Suite = { &SHA3_224Suite, SHA3_224_RESULT_SIZE, NID_sha3_224 };
static const MOC_EVP_MD EVP_SHA3_256Suite = { &SHA3_256Suite, SHA3_256_RESULT_SIZE, NID_sha3_256 };
static const MOC_EVP_MD EVP_SHA3_384Suite = { &SHA3_384Suite, SHA3_384_RESULT_SIZE, NID_sha3_384 };
static const MOC_EVP_MD EVP_SHA3_512Suite = { &SHA3_512Suite, SHA3_512_RESULT_SIZE, NID_sha3_512 };
#endif

void
DIGI_EVP_setDigestAlgo(MOC_EVP_MD_CTX *ctx, int digesttype)
{
    ctx->pDigestAlgo = NULL;
    switch(digesttype)
    {
#ifdef __ENABLE_DIGICERT_MD2__
        case NID_md2:
            ctx->pDigestAlgo = &EVP_MD2Suite;
            break;
#endif
#ifdef __ENABLE_DIGICERT_MD4__
        case NID_md4:
            ctx->pDigestAlgo = &EVP_MD4Suite;
            break;
#endif
        case NID_md5:
            ctx->pDigestAlgo = &EVP_MD5Suite;
            break;
        case NID_sha:
            break;
        case NID_sha1:
            ctx->pDigestAlgo = &EVP_SHA1Suite;
            break;
        case NID_sha224:
            ctx->pDigestAlgo = &EVP_SHA224Suite;
            break;
        case NID_sha256:
            ctx->pDigestAlgo = &EVP_SHA256Suite;
            break;
        case NID_sha384:
            ctx->pDigestAlgo = &EVP_SHA384Suite;
            break;
        case NID_sha512:
            ctx->pDigestAlgo = &EVP_SHA512Suite;
            break;
#if defined(__ENABLE_DIGICERT_SHA3__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case NID_sha3_224:
            ctx->pDigestAlgo = &EVP_SHA3_224Suite;
            break;
        case NID_sha3_256:
            ctx->pDigestAlgo = &EVP_SHA3_256Suite;
            break;
        case NID_sha3_384:
            ctx->pDigestAlgo = &EVP_SHA3_384Suite;
            break;
        case NID_sha3_512:
            ctx->pDigestAlgo = &EVP_SHA3_512Suite;
            break;
#endif
        default:
            break;
    }
}

void
DIGI_EVP_MD_CTX_init(MOC_EVP_MD_CTX *ctx)
{
    ctx->pDigestAlgo = 0;
    ctx->pDigestData = 0;
}


/*------------------------------------------------------------------*/

int
DIGI_EVP_MD_CTX_cleanup(MOC_HASH(hwAccelDescr hwAccelCtx) MOC_EVP_MD_CTX *ctx)
{
    if (ctx->pDigestData && ctx->pDigestAlgo)
    {
        ctx->pDigestAlgo->pHashAlgo->freeFunc(MOC_HASH(hwAccelCtx) &ctx->pDigestData);
        ctx->pDigestData = 0;
    }
    ctx->pDigestAlgo = 0;

    return 1; /* like OpenSSL implementation */
}

int
DIGI_EVP_digestUpdate(MOC_HASH(hwAccelDescr hwAccelCtx) MOC_EVP_MD_CTX *ctx, const void *d, unsigned int cnt)
{
    return (OK <= ctx->pDigestAlgo->pHashAlgo->updateFunc(MOC_HASH(hwAccelCtx) ctx->pDigestData, (const ubyte*) d, cnt));
}


/*------------------------------------------------------------------*/

int
DIGI_EVP_digestFinal(MOC_HASH(hwAccelDescr hwAccelCtx)MOC_EVP_MD_CTX *ctx, unsigned char *md)
{
    int success = 0;
    if(ctx && ctx->pDigestData && ctx->pDigestAlgo) {
        success = (OK <= ctx->pDigestAlgo->pHashAlgo->finalFunc(MOC_HASH(hwAccelCtx) ctx->pDigestData, md));
    }
    return success;
}

MSTATUS
DIGI_EVP_doAESCCM(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    return 0;
}

#ifdef __ENABLE_DES_CIPHER__
MSTATUS
DIGI_EVP_doDESECB(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    des_ctx*    pDesContext = (des_ctx *)ctx;
    MSTATUS     status;

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        return status;
    }

    if (encrypt)
	{
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_DES_encipher(pDesContext, data, data, dataLength);
#else
        status = DES_encipher(pDesContext, data, data, dataLength);
#endif
	}
    else
	{
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_DES_decipher(pDesContext, data, data, dataLength);
#else
        status = DES_decipher(pDesContext, data, data, dataLength);
#endif
	}

    return status == OK ? 1 : 0;
}
#endif

#ifndef __DISABLE_3DES_CIPHERS__
int
DIGI_EVP_do3DESECB(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength,
       sbyte4 encrypt, ubyte* iv)
{
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    ctx3des*  p_3desContext = (ctx3des *)ctx;
#else
    DES3Ctx*  p_3desContext = (DES3Ctx *)ctx;
#endif
    MSTATUS   status;

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        return status;
    }

    if (encrypt)
	{
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_THREE_DES_encipher(p_3desContext, data, data, dataLength);
#else
        status = THREE_DES_encipher(&(p_3desContext->encryptKey), data, data, dataLength);
#endif
	}
    else
	{
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_THREE_DES_decipher(p_3desContext, data, data, dataLength);
#else
        status = THREE_DES_decipher(&(p_3desContext->decryptKey), data, data, dataLength);
#endif
	}

    return status == OK ? 1 : 0;
}

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkEncryptionAlgo CRYPTO_TripleDESECBSuite = {
    THREE_DES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CRYPTO_INTERFACE_THREE_DES_createCtx,
    (DeleteBulkCtxFunc)CRYPTO_INTERFACE_THREE_DES_deleteCtx,
    (CipherFunc)DIGI_EVP_do3DESECB,
    CRYPTO_INTERFACE_THREE_DES_cloneCtx
};
#else
/* We can use the cbc des ctx since it begins with the ecb version 
   This can be simplified next time we get a chance to modify 
   three_des.h/c in the fips boundary.
*/
static const BulkEncryptionAlgo CRYPTO_TripleDESECBSuite = {
    THREE_DES_BLOCK_SIZE,
    (CreateBulkCtxFunc)Create3DESCtx,
    (DeleteBulkCtxFunc)Delete3DESCtx,
    (CipherFunc)DIGI_EVP_do3DESECB,
    Clone3DESCtx
};
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && !defined(__DISABLE_3DES_TWO_KEY_CIPHER__)
static const BulkEncryptionAlgo CRYPTO_DESEDECBCSuite = {
    THREE_DES_BLOCK_SIZE, 
    CRYPTO_INTERFACE_Create2Key3DESCtx,
    CRYPTO_INTERFACE_Delete3DESCtx,
    CRYPTO_INTERFACE_Do3DESEx,
    CRYPTO_INTERFACE_Clone3DESCtx
};

static const BulkEncryptionAlgo CRYPTO_DESEDEECBSuite = {
    THREE_DES_BLOCK_SIZE,
    (CreateBulkCtxFunc)CRYPTO_INTERFACE_THREE_DES_create2KeyCtx,
    (DeleteBulkCtxFunc)CRYPTO_INTERFACE_THREE_DES_deleteCtx,
    (CipherFunc)DIGI_EVP_do3DESECB,
    CRYPTO_INTERFACE_THREE_DES_cloneCtx
};

static const MOC_EVP_CIPHER EVP_DESEDECBCSuite  = { &CRYPTO_DESEDECBCSuite, THREE_DES_TWO_KEY_LENGTH, NID_des_ede_cbc };
static const MOC_EVP_CIPHER EVP_DESEDEECBSuite  = { &CRYPTO_DESEDEECBSuite, THREE_DES_TWO_KEY_LENGTH, NID_des_ede_ecb };
#endif /* #if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && !defined(__DISABLE_3DES_TWO_KEY_CIPHER__) */

static const MOC_EVP_CIPHER EVP_TripleDESCBCSuite  = { &CRYPTO_TripleDESSuite, THREE_DES_KEY_LENGTH, NID_des_ede3_cbc };
static const MOC_EVP_CIPHER EVP_TripleDESECBSuite  = { &CRYPTO_TripleDESECBSuite, THREE_DES_KEY_LENGTH, NID_des_ede3_ecb };
#endif /* __DISABLE_3DES_CIPHERS__*/

#ifdef __ENABLE_DES_CIPHER__
static const MOC_EVP_CIPHER EVP_DESSuite  = { &CRYPTO_DESSuite, DES_KEY_LENGTH, NID_des_cbc };
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkEncryptionAlgo CRYPTO_DESEcbSuite = {
    DES_BLOCK_SIZE,
    CRYPTO_INTERFACE_CreateDESCtx,
    CRYPTO_INTERFACE_DeleteDESCtx,
    DIGI_EVP_doDESECB,
    CRYPTO_INTERFACE_CloneDESCtx
};
#else
static const BulkEncryptionAlgo CRYPTO_DESEcbSuite = {
    DES_BLOCK_SIZE,
    CreateDESCtx,
    DeleteDESCtx,
    DIGI_EVP_doDESECB,
    CloneDESCtx
};
#endif
static const MOC_EVP_CIPHER EVP_DESEcbSuite  = { &CRYPTO_DESEcbSuite, DES_KEY_LENGTH, NID_des_ecb };
#endif

#ifndef __DISABLE_ARC4_CIPHERS__
static const MOC_EVP_CIPHER EVP_RC4Suite        = { &CRYPTO_RC4Suite, 16, NID_rc4 };
static const MOC_EVP_CIPHER EVP_RC440Suite        = { &CRYPTO_RC4Suite, 5, NID_rc4_40 };
#endif

/* RC2 Algorithms
 */
#ifdef __ENABLE_ARC2_CIPHERS__

/* RC2 ECB Implementation
 */
MSTATUS DIGI_EVP_DoRC2Ecb(
    BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 cryptMode,
    ubyte *pIv
    )
{
    MSTATUS status;
    void (*rc2Crypt)(const ubyte2 xkey[64], void *pPlain, void *pCipher);
    
    MOC_UNUSED(pIv);
    
    if (NULL == pCtx)
    {
        status = ERR_RC2_NULL_CONTEXT;
        goto exit;
    }
    
    /* Input must be a multiple of block size.
     */
    if (0 != (dataLen % RC2_BLOCK_SIZE))
    {
        status = ERR_RC2_BAD_DATA_LENGTH;
        goto exit;
    }
    
    /* Set the appropriate RC2 method.
     */
    if (cryptMode)
    {
        rc2Crypt = (void (*)(const ubyte2 [64], void *, void *)) rc2_encrypt;
    }
    else
    {
        rc2Crypt = (void (*)(const ubyte2 [64], void *, void *)) rc2_decrypt;
    }
    
    /* Process the input data.
     */
    while (dataLen > 0)
    {
        rc2Crypt(pCtx, pData, pData);
        
        pData += RC2_BLOCK_SIZE;
        dataLen -= RC2_BLOCK_SIZE;
    }
    
    status = OK;
    
exit:
    
    return status;
}

/* There is already a BulkEncryptionAlgo for RC2 CBC, but there is none for
 * RC2 ECB so one will have to be created here.
 */
static const BulkEncryptionAlgo CRYPTO_RC2EcbSuite = {
    RC2_BLOCK_SIZE,
    CreateRC2Ctx2,
    DeleteRC2Ctx,
    DIGI_EVP_DoRC2Ecb,
    CloneRC2Ctx
};

/* RC2 ECB
 */
static const MOC_EVP_CIPHER EVP_RC2EcbSuite = {
    &CRYPTO_RC2EcbSuite,
    16,
    NID_rc2_ecb
};

/* RC2 CBC
 */
static const MOC_EVP_CIPHER EVP_RC2CbcSuite = {
    &CRYPTO_RC2EffectiveBitsSuite,
    16,
    NID_rc2_cbc
};

/* RC2 CBC 40
 */
static const MOC_EVP_CIPHER EVP_RC2Cbc40Suite = {
    &CRYPTO_RC2EffectiveBitsSuite,
    8,
    NID_rc2_40_cbc
};

#endif /* __ENABLE_ARC2_CIPHERS__ */

#if defined(__ENABLE_BLOWFISH_CIPHERS__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static const MOC_EVP_CIPHER EVP_BlowfishCBCSuite = { &CRYPTO_BlowfishSuite, 16 /* default, variable */, NID_bf_cbc };
#endif

#ifndef __DISABLE_AES_CIPHERS__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkEncryptionAlgo EVP_AESEcbSuite = { AES_BLOCK_SIZE, (CreateBulkCtxFunc)CRYPTO_INTERFACE_CreateAESECBCtx, (DeleteBulkCtxFunc)CRYPTO_INTERFACE_DeleteAESCtx, (CipherFunc)CRYPTO_INTERFACE_DoAESECB, CRYPTO_INTERFACE_CloneAESCtx };
static const BulkEncryptionAlgo CRYPTO_AESCfbSuite =
    { AES_BLOCK_SIZE, CRYPTO_INTERFACE_CreateAESCFBCtx, CRYPTO_INTERFACE_DeleteAESCtx, CRYPTO_INTERFACE_DoAESEx, CRYPTO_INTERFACE_CloneAESCtx };
static const BulkEncryptionAlgo CRYPTO_AESOfbSuite =
    { AES_BLOCK_SIZE, CRYPTO_INTERFACE_CreateAESOFBCtx, CRYPTO_INTERFACE_DeleteAESCtx, CRYPTO_INTERFACE_DoAESEx, CRYPTO_INTERFACE_CloneAESCtx };
#else
static const BulkEncryptionAlgo EVP_AESEcbSuite = { AES_BLOCK_SIZE, (CreateBulkCtxFunc)CreateAESECBCtx, (DeleteBulkCtxFunc)DeleteAESECBCtx, (CipherFunc)DoAESECB, CloneAESCtx };
static const BulkEncryptionAlgo CRYPTO_AESCfbSuite =
    { AES_BLOCK_SIZE, CreateAESCFBCtx, DeleteAESCtx, DoAES, CloneAESCtx };
static const BulkEncryptionAlgo CRYPTO_AESOfbSuite =
    { AES_BLOCK_SIZE, CreateAESOFBCtx, DeleteAESCtx, DoAES, CloneAESCtx };
#endif
#endif

static const MOC_EVP_CIPHER EVP_AES128EcbSuite     = { &EVP_AESEcbSuite, 16, NID_aes_128_ecb };
static const MOC_EVP_CIPHER EVP_AES192EcbSuite     = { &EVP_AESEcbSuite, 24, NID_aes_192_ecb };
static const MOC_EVP_CIPHER EVP_AES256EcbSuite     = { &EVP_AESEcbSuite, 32, NID_aes_256_ecb };
static const MOC_EVP_CIPHER EVP_AES128CbcSuite     = { &CRYPTO_AESSuite, 16, NID_aes_128_cbc };
static const MOC_EVP_CIPHER EVP_AES192CbcSuite     = { &CRYPTO_AESSuite, 24, NID_aes_192_cbc };
static const MOC_EVP_CIPHER EVP_AES256CbcSuite     = { &CRYPTO_AESSuite, 32, NID_aes_256_cbc };
static const MOC_EVP_CIPHER EVP_AES128OfbSuite     = { &CRYPTO_AESOfbSuite, 16, NID_aes_128_ofb128 };
static const MOC_EVP_CIPHER EVP_AES192OfbSuite     = { &CRYPTO_AESOfbSuite, 24, NID_aes_192_ofb128 };
static const MOC_EVP_CIPHER EVP_AES256OfbSuite     = { &CRYPTO_AESOfbSuite, 32, NID_aes_256_ofb128 };
static const MOC_EVP_CIPHER EVP_AES128CfbSuite     = { &CRYPTO_AESCfbSuite, 16, NID_aes_128_cfb128 };
static const MOC_EVP_CIPHER EVP_AES192CfbSuite     = { &CRYPTO_AESCfbSuite, 24, NID_aes_192_cfb128 };
static const MOC_EVP_CIPHER EVP_AES256CfbSuite     = { &CRYPTO_AESCfbSuite, 32, NID_aes_256_cfb128 };
#ifndef __DISABLE_AES_CTR_CIPHER__
static const MOC_EVP_CIPHER EVP_AES128CtrSuite     = { &CRYPTO_AESCtrSuite, 32, NID_aes_128_ctr };
static const MOC_EVP_CIPHER EVP_AES192CtrSuite     = { &CRYPTO_AESCtrSuite, 40, NID_aes_192_ctr };
static const MOC_EVP_CIPHER EVP_AES256CtrSuite     = { &CRYPTO_AESCtrSuite, 48, NID_aes_256_ctr };
#endif

#if !defined(__DISABLE_DIGICERT_SUITE_B__)
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#ifdef __ENABLE_DIGICERT_GCM_256B__
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, NULL, CRYPTO_INTERFACE_GCM_clone_256b };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, NULL, CRYPTO_INTERFACE_GCM_clone_256b };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, NULL, CRYPTO_INTERFACE_GCM_clone_256b };
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, NULL, CRYPTO_INTERFACE_GCM_clone_4k };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, NULL, CRYPTO_INTERFACE_GCM_clone_4k };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, NULL, CRYPTO_INTERFACE_GCM_clone_4k };
#elif defined(__ENABLE_DIGICERT_GCM_64K__)
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, NULL, CRYPTO_INTERFACE_GCM_clone_64k };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, NULL, CRYPTO_INTERFACE_GCM_clone_64k };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = {
            AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, NULL, CRYPTO_INTERFACE_GCM_clone_64k };
#endif
#else
#ifdef __ENABLE_DIGICERT_GCM_256B__
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = { AES_BLOCK_SIZE, GCM_createCtx_256b, GCM_deleteCtx_256b, NULL, GCM_clone_256b };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = { AES_BLOCK_SIZE, GCM_createCtx_256b, GCM_deleteCtx_256b, NULL, GCM_clone_256b };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = { AES_BLOCK_SIZE, GCM_createCtx_256b, GCM_deleteCtx_256b, NULL, GCM_clone_256b };
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = { AES_BLOCK_SIZE, GCM_createCtx_4k, GCM_deleteCtx_4k, NULL, GCM_clone_4k };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = { AES_BLOCK_SIZE, GCM_createCtx_4k, GCM_deleteCtx_4k, NULL, GCM_clone_4k };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = { AES_BLOCK_SIZE, GCM_createCtx_4k, GCM_deleteCtx_4k, NULL, GCM_clone_4k };
#elif defined(__ENABLE_DIGICERT_GCM_64K__)
static const BulkEncryptionAlgo CRYPTO_AESGcm128Suite = { AES_BLOCK_SIZE, GCM_createCtx_64k, GCM_deleteCtx_64k, NULL, GCM_clone_64k };
static const BulkEncryptionAlgo CRYPTO_AESGcm192Suite = { AES_BLOCK_SIZE, GCM_createCtx_64k, GCM_deleteCtx_64k, NULL, GCM_clone_64k };
static const BulkEncryptionAlgo CRYPTO_AESGcm256Suite = { AES_BLOCK_SIZE, GCM_createCtx_64k, GCM_deleteCtx_64k, NULL, GCM_clone_64k };
#endif
#endif
static const MOC_EVP_CIPHER EVP_AES128GcmSuite  = { &CRYPTO_AESGcm128Suite, 16, NID_aes_128_gcm };
static const MOC_EVP_CIPHER EVP_AES192GcmSuite  = { &CRYPTO_AESGcm192Suite, 24, NID_aes_192_gcm };
static const MOC_EVP_CIPHER EVP_AES256GcmSuite  = { &CRYPTO_AESGcm256Suite, 32, NID_aes_256_gcm };
#endif
#ifndef __DISABLE_AES_CCM__

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static const BulkEncryptionAlgo CRYPTO_AESCcmSuite = { AES_BLOCK_SIZE, CRYPTO_INTERFACE_AES_CCM_createCtx, CRYPTO_INTERFACE_AES_CCM_deleteCtx, 
                                                       DIGI_EVP_doAESCCM, CRYPTO_INTERFACE_AES_CCM_clone};
#else
static const BulkEncryptionAlgo CRYPTO_AESCcmSuite = { AES_BLOCK_SIZE, AESCCM_createCtx, AESCCM_deleteCtx, DIGI_EVP_doAESCCM, AESCCM_clone };
#endif
static const MOC_EVP_CIPHER EVP_AES256CcmSuite  = { &CRYPTO_AESCcmSuite, 32, NID_aes_256_ccm };
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
static const MOC_EVP_CIPHER EVP_AES192CcmSuite  = { &CRYPTO_AESCcmSuite, 24, NID_aes_192_ccm };
static const MOC_EVP_CIPHER EVP_AES128CcmSuite  = { &CRYPTO_AESCcmSuite, 16, NID_aes_128_ccm };
#endif
#endif /* __DISABLE_AES_CCM__ */
#ifndef __DISABLE_AES_XTS__
/* 128 and 256 key length can be handled by single CRYPTO_AESXtsSuite. */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static const BulkEncryptionAlgo CRYPTO_AESXtsSuite = { AES_BLOCK_SIZE, (CreateBulkCtxFunc)CRYPTO_INTERFACE_CreateAESXTSCtx, (DeleteBulkCtxFunc)CRYPTO_INTERFACE_DeleteAESXTSCtx, 
                                                      (CipherFunc)CRYPTO_INTERFACE_DoAESXTS, CRYPTO_INTERFACE_CloneAESXTSCtx };
#else
static const BulkEncryptionAlgo CRYPTO_AESXtsSuite = { AES_BLOCK_SIZE, (CreateBulkCtxFunc)CreateAESXTSCtx, (DeleteBulkCtxFunc)DeleteAESXTSCtx, (CipherFunc)DoAESXTS, CloneAESXTSCtx };
#endif
static const MOC_EVP_CIPHER EVP_AES128XTSSuite  = { &CRYPTO_AESXtsSuite, 32, NID_aes_128_xts };
static const MOC_EVP_CIPHER EVP_AES256XTSSuite  = { &CRYPTO_AESXtsSuite, 64, NID_aes_256_xts };
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static const BulkEncryptionAlgo CRYPTO_ChaChaSuite = { 64, (CreateBulkCtxFunc) CRYPTO_INTERFACE_CreateChaCha20Ctx,
                                                           (DeleteBulkCtxFunc) CRYPTO_INTERFACE_DeleteChaCha20Ctx,
                                                           (CipherFunc) CRYPTO_INTERFACE_DoChaCha20 };
#else
static const BulkEncryptionAlgo CRYPTO_ChaChaSuite = { 64, (CreateBulkCtxFunc) CreateChaCha20Ctx, (DeleteBulkCtxFunc) DeleteChaCha20Ctx, (CipherFunc) DoChaCha20, CloneChaCha20Ctx };
#endif
static const MOC_EVP_CIPHER EVP_ChaCha20Suite = { &CRYPTO_ChaChaSuite, 48, NID_chacha20 };
#endif /* defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER) */

void
DIGI_EVP_setEncrAlgo(MOC_EVP_CIPHER_CTX *ctx, int ciphertype)
{
    switch(ciphertype)
	{
		case NID_aes_128_ecb:
		  ctx->pEncrAlgo = &EVP_AES128EcbSuite;
		  break;
		case NID_aes_128_cbc:
		  ctx->pEncrAlgo = &EVP_AES128CbcSuite;
		  break;
		case NID_aes_128_ofb128:
		  ctx->pEncrAlgo = &EVP_AES128OfbSuite;
		  break;
		case NID_aes_128_cfb128:
		  ctx->pEncrAlgo = &EVP_AES128CfbSuite;
		  break;
#ifndef __DISABLE_AES_CTR_CIPHER__
		case NID_aes_128_ctr:
		  ctx->pEncrAlgo = &EVP_AES128CtrSuite;
		  break;
		case NID_aes_192_ctr:
		  ctx->pEncrAlgo = &EVP_AES192CtrSuite;
		  break;
		case NID_aes_256_ctr:
		  ctx->pEncrAlgo = &EVP_AES256CtrSuite;
		  break;
#endif
		case NID_aes_192_ecb:
		  ctx->pEncrAlgo = &EVP_AES192EcbSuite;
		  break;
		case NID_aes_192_cbc:
		  ctx->pEncrAlgo = &EVP_AES192CbcSuite;
		  break;
		case NID_aes_192_ofb128:
		  ctx->pEncrAlgo = &EVP_AES192OfbSuite;
		  break;
		case NID_aes_192_cfb128:
		  ctx->pEncrAlgo = &EVP_AES192CfbSuite;
		  break;
		case NID_aes_256_ecb:
		  ctx->pEncrAlgo = &EVP_AES256EcbSuite;
		  break;
		case NID_aes_256_cbc:
		  ctx->pEncrAlgo = &EVP_AES256CbcSuite;
		  break;
		case NID_aes_256_ofb128:
		  ctx->pEncrAlgo = &EVP_AES256OfbSuite;
		  break;
		case NID_aes_256_cfb128:
		  ctx->pEncrAlgo = &EVP_AES256CfbSuite;
		  break;
#ifndef __DISABLE_3DES_CIPHERS__
		case NID_des_ede3_cbc:
		  ctx->pEncrAlgo = &EVP_TripleDESCBCSuite;
		  break;
		case NID_des_ede3_ecb:
		  ctx->pEncrAlgo = &EVP_TripleDESECBSuite;
		  break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && !defined(__DISABLE_3DES_TWO_KEY_CIPHER__)
		case NID_des_ede_cbc:
		  ctx->pEncrAlgo = &EVP_DESEDECBCSuite;
		  break;
		case NID_des_ede_ecb:
		  ctx->pEncrAlgo = &EVP_DESEDEECBSuite;
		  break;
#endif
#endif
#ifdef __ENABLE_DES_CIPHER__
		case NID_des_cbc:
		  ctx->pEncrAlgo = &EVP_DESSuite;
		  break;
		case NID_des_ecb:
		  ctx->pEncrAlgo = &EVP_DESEcbSuite;
		  break;
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
		case NID_rc4:
          ctx->pEncrAlgo = &EVP_RC4Suite;
          break;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
        case NID_rc4_40:
		  ctx->pEncrAlgo = &EVP_RC440Suite;
		  break;
#endif
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
        case NID_rc2_ecb:
            ctx->pEncrAlgo = &EVP_RC2EcbSuite;
            break;
        case NID_rc2_cbc:
            ctx->pEncrAlgo = &EVP_RC2CbcSuite;
            break;
        case NID_rc2_40_cbc:
            ctx->pEncrAlgo = &EVP_RC2Cbc40Suite;
            break;
#endif /* __ENABLE_ARC2_CIPHERS__ */
#if !defined(__DISABLE_DIGICERT_SUITE_B__)
		case NID_aes_128_gcm:
		  ctx->pEncrAlgo = &EVP_AES128GcmSuite;
		  break;
		case NID_aes_192_gcm:
		  ctx->pEncrAlgo = &EVP_AES192GcmSuite;
		  break;
		case NID_aes_256_gcm:
		  ctx->pEncrAlgo = &EVP_AES256GcmSuite;
		  break;
#endif
#ifndef __DISABLE_AES_CCM__
		case NID_aes_256_ccm:
		  ctx->pEncrAlgo = &EVP_AES256CcmSuite;
		  break;
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_3_0__
		case NID_aes_192_ccm:
		  ctx->pEncrAlgo = &EVP_AES192CcmSuite;
		  break;
		case NID_aes_128_ccm:
		  ctx->pEncrAlgo = &EVP_AES128CcmSuite;
		  break;
#endif
#endif
#ifndef __DISABLE_AES_XTS__
		case NID_aes_128_xts:
		  ctx->pEncrAlgo = &EVP_AES128XTSSuite;
		  break;
		case NID_aes_256_xts:
		  ctx->pEncrAlgo = &EVP_AES256XTSSuite;
		  break;
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__DISABLE_DIGICERT_CHACHA20_MALLOC__) && (0x10100000L <= OPENSSL_VERSION_NUMBER)
        case NID_chacha20:
          ctx->pEncrAlgo = &EVP_ChaCha20Suite;
          break;
#endif
#if defined(__ENABLE_BLOWFISH_CIPHERS__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case NID_bf_cbc:
          ctx->pEncrAlgo = &EVP_BlowfishCBCSuite;
          break;
#endif
		default:
		  break;
    }
}

void
DIGI_EVP_CIPHER_CTX_init(MOC_EVP_CIPHER_CTX *ctx)
{
    ctx->pEncrAlgo = NULL;
    ctx->pEncrData = NULL;
    ctx->aad       = NULL;
    ctx->key       = NULL;
    ctx->pad       = 0;
    ctx->ivLen     = 0;
    ctx->aadLen    = 0;
    ctx->dataLen   = 0;
    ctx->tagLen    = 0;
}

int
DIGI_EVP_CIPHER_CTX_cleanup(MOC_SYM(hwAccelDescr hwAccelCtx) MOC_EVP_CIPHER_CTX *ctx)
{
    if (ctx->pEncrData && ctx->pEncrAlgo)
    {
        ctx->pEncrAlgo->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &ctx->pEncrData);
        ctx->pEncrData = 0;
    }
    ctx->pEncrAlgo = 0;
    if(ctx->aad)
	{
        OPENSSL_free(ctx->aad);
        ctx->aad = NULL;
    }
    ctx->aadLen = 0;

    if(ctx->key)
	{
        OPENSSL_free(ctx->key);
        ctx->key = NULL;
    }

    DIGI_MEMSET((ubyte*)ctx, 0x00, sizeof(MOC_EVP_CIPHER_CTX));

    return 1;
}
