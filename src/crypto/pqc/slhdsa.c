/*
 * slhdsa.c
 *
 * SLH-DSA methods.
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

/* Comments based on FIPS-205
   https://doi.org/10.6028/NIST.FIPS.205 */

#include "../../common/moptions.h"

#if defined(__ENABLE_DIGICERT_PQC_SIG__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__)

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/random.h"
#include "../../common/debug_console.h"

#include "../../crypto/hw_accel.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/sha3.h"
#include "../../crypto/hmac.h"
#include "../../crypto/pqc/slhdsa.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#include "../../crypto/crypto_hash_fips.h"
#endif

#define SLHDSA_TAG               0x534c4844   /* "SLHD" */

#define SLHDSA_MODE_SHAKE      0
#define SLHDSA_MODE_SHA2       1

#define SLHDSA_ADRS_WOTS_HASH  0
#define SLHDSA_ADRS_WOTS_PK    1
#define SLHDSA_ADRS_TREE       2
#define SLHDSA_ADRS_FORS_TREE  3
#define SLHDSA_ADRS_FORS_ROOTS 4
#define SLHDSA_ADRS_WOTS_PRF   5
#define SLHDSA_ADRS_FORS_PRF   6

#define SLHDSA_ADRS_LEN       32
#define SLHDSA_ADRS_CMPR_LEN  22

#define SLHDSA_W              16
#define SLHDSA_LOG_W           4  /* log base 2 of 16 */
#define SLHDSA_W_MASK       0x0f

#define SLHDSA_MIN_N          16
#define SLHDSA_MAX_N          32
#define SLHDSA_MAX_K          35
#define SLHDSA_MAX_LEN        67 /* max of len1 + len2 which is 64 + 3 */
#define SLHDSA_LEN2            3 /* [log(len1 * (w-1)) / log(w)] + 1, same value for len1 = 32,48,64 */
#define SLHDSA_LEN2_BYTES      2 /* (SLHDSA_LEN2 * SLHDSA_LOG_W + 7) / 8; ie 12/8 rounded up */
#define SLHDSA_MAX_M          49 /* 256f, (9*35+7)/8 + (68- 68/17 + 7)/8 + (68/17 + 7)/8 */

#define SLHDSA_MAX_HASH_RESULT_SIZE  SHA512_RESULT_SIZE
#define SLHDSA_MAX_HASH_BLOCK_SIZE   SHA512_BLOCK_SIZE
#define SLHDSA_MGF_MAX_HASH_INLEN    (2*SLHDSA_MAX_N + SLHDSA_MAX_HASH_BLOCK_SIZE)

#define SLHDSA_MAX_HASH_BLOCK_SIZE SHA512_BLOCK_SIZE
#define SLHDSA_MAX_HT_HEIGHT     9 /* max h/d which is 63/7 */
#define SLHDSA_MAX_FORS_HEIGHT  14 /* max a = log(t) */

#if __DIGICERT_MAX_INT__ == 64
#define SLHDSA_FULL_MASK 0xffffffffffffffffull
#else
#define SLHDSA_FULL_MASK 0xffffffff
#endif

#define SLHDSA_OID_LEN          11
#define SLHDSA_MAX_CONTEXT_LEN 255

/* If all sha2 modes are disable, we don't need the sha2 function pointer defns, likewise for shake */
#if defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_128S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_128F__)\
 && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_192S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_192F__)\
 && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_256S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHA2_256F__)
#define __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__
#endif

#if defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_128S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_128F__)\
 && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_192S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_192F__)\
 && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_256S__) && defined(__DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_256F__)
#define __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__
#endif

/* forward decl for function pointer types */
typedef struct _SlhdsaHashCtx SlhdsaHashCtx;

/* Function pointer types */
typedef MSTATUS (*BulkCtxHmsgFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) struct _SlhdsaHashCtx *pHashCtx, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut, ubyte4 m);
typedef MSTATUS (*BulkCtxPRFmsgFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) struct _SlhdsaHashCtx *pHashCtx, ubyte *pSkPrf, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut);
typedef MSTATUS (*BulkCtxCloneFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pDest, BulkCtx pSrc);
typedef void (*BulkCtxTHashFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) struct _SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut);

/* ------------------------------------------------------------------- */

/* compile time context */
typedef struct _SlhdsaCtx
{
    ubyte4 n;
    ubyte4 h;
    ubyte4 d;
    ubyte4 k;
    ubyte4 a;
    ubyte4 m;
    ubyte4 sigLen;
    ubyte4 len;
    ubyte4 len1;
    ubyte4 adrsLen;

    BulkCtxHmsgFunc H_MSG;
    BulkCtxPRFmsgFunc PRF_MSG;
    BulkCtxTHashFunc PRF;
    BulkCtxTHashFunc TL;

} SlhdsaCtx;

/* ------------------------------------------------------------------- */

/* runtime hash context */
typedef struct _SlhdsaHashCtx
{
    /* only used for sha2 modes */
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__
    BulkHashAlgo *pTLAlgo;
    BulkCtxCloneFunc TL_CLONE;

    BulkCtx pTLCtxSeeded;
    BulkCtx pPRFHashCtx;
    BulkCtx pPRFCtxSeeded;
#endif

    /* used for sha2 or shake modes */
    BulkCtx pTLHashCtx;
    ubyte4 n; /* copy for convenience */

    /* copy for pk seed for shake modes */
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__
    ubyte *pPkSeed;
#endif

} SlhdsaHashCtx;

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int slhdsa_fail = 0;

FIPS_TESTLOG_IMPORT;

/*------------------------------------------------------------------*/

/* prototype */
MOC_EXTERN MSTATUS
SLHDSA_generateKey_FIPS_consistency_test(SLHDSACtx* pCtx, RNGFun rng, void *rngArg);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

/* Implementations for the function pointers */
static MSTATUS SLHDSA_hMsgShaX(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut, ubyte4 m);
static MSTATUS SLHDSA_prfMsgShaX(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pSkPrf, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut);
static void SLHDSA_prfSha2(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut);
static void SLHDSA_tlSha2(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut);
static MSTATUS SLHDSA_hMsgShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut, ubyte4 m);
static MSTATUS SLHDSA_prfMsgShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pSkPrf, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut);
static void SLHDSA_tlPrfShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut);

/* ------------------------------------------------------------------- */

/* The 12 predefined security strengths */
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_128S__
static const SlhdsaCtx gSlhdsaSha128s =
{
    .n = 16,
    .h = 63,
    .d = 7,
    .k = 14,
    .a = 12,
    .m = 30,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 7856,   /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 35,        /* len = len1 + len2 */
    .len1 = 32,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_128F__
static const SlhdsaCtx gSlhdsaSha128f =
{
    .n = 16,
    .h = 66,
    .d = 22,
    .k = 33,
    .a = 6,
    .m = 34,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 17088,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 35,        /* len = len1 + len2 */
    .len1 = 32,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_192S__
static const SlhdsaCtx gSlhdsaSha192s =
{
    .n = 24,
    .h = 63,
    .d = 7,
    .k = 17,
    .a = 14,
    .m = 39,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 16224,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 51,        /* len = len1 + len2 */
    .len1 = 48,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_192F__
static const SlhdsaCtx gSlhdsaSha192f =
{
    .n = 24,
    .h = 66,
    .d = 22,
    .k = 33,
    .a = 8,
    .m = 42,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 35664,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 51,        /* len = len1 + len2 */
    .len1 = 48,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_256S__
static const SlhdsaCtx gSlhdsaSha256s =
{
    .n = 32,
    .h = 64,
    .d = 8,
    .k = 22,
    .a = 14,
    .m = 47,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 29792,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 67,        /* len = len1 + len2 */
    .len1 = 64,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2_256F__
static const SlhdsaCtx gSlhdsaSha256f =
{
    .n = 32,
    .h = 68,
    .d = 17,
    .k = 35,
    .a = 9,
    .m = 49,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 49856,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 67,        /* len = len1 + len2 */
    .len1 = 64,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_CMPR_LEN,

    .H_MSG = SLHDSA_hMsgShaX,
    .PRF_MSG = SLHDSA_prfMsgShaX,
    .PRF = SLHDSA_prfSha2,
    .TL = SLHDSA_tlSha2
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_128S__
static const SlhdsaCtx gSlhdsaShake128s =
{
    .n = 16,
    .h = 63,
    .d = 7,
    .k = 14,
    .a = 12,
    .m = 30,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 7856,   /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 35,        /* len = len1 + len2 */
    .len1 = 32,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_128F__
static const SlhdsaCtx gSlhdsaShake128f =
{
    .n = 16,
    .h = 66,
    .d = 22,
    .k = 33,
    .a = 6,
    .m = 34,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 17088,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 35,        /* len = len1 + len2 */
    .len1 = 32,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_192S__
static const SlhdsaCtx gSlhdsaShake192s =
{
    .n = 24,
    .h = 63,
    .d = 7,
    .k = 17,
    .a = 14,
    .m = 39,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 16224,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 51,        /* len = len1 + len2 */
    .len1 = 48,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_192F__
static const SlhdsaCtx gSlhdsaShake192f =
{
    .n = 24,
    .h = 66,
    .d = 22,
    .k = 33,
    .a = 8,
    .m = 42,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 35664,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 51,        /* len = len1 + len2 */
    .len1 = 48,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_256S__
static const SlhdsaCtx gSlhdsaShake256s =
{
    .n = 32,
    .h = 64,
    .d = 8,
    .k = 22,
    .a = 14,
    .m = 47,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 29792,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 67,        /* len = len1 + len2 */
    .len1 = 64,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE_256F__
static const SlhdsaCtx gSlhdsaShake256f =
{
    .n = 32,
    .h = 68,
    .d = 17,
    .k = 35,
    .a = 9,
    .m = 49,          /* (k*a + 7)/8 + (h - h/d + 7)/8 + (h/d + 7)/8 */
    .sigLen = 49856,  /* n * (1 + k * (a + 1) + (d * len + h) )*/
    .len = 67,        /* len = len1 + len2 */
    .len1 = 64,       /* n * (SLHDSA_LOG_W / 2) */
    .adrsLen = SLHDSA_ADRS_LEN,

    .H_MSG = SLHDSA_hMsgShake256,
    .PRF_MSG = SLHDSA_prfMsgShake256,
    .PRF = SLHDSA_tlPrfShake256,
    .TL = SLHDSA_tlPrfShake256
};
#endif

/* ------------------------------------------------------------------- */

/* OID's for pre-hash modes */

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_CTX_PREHASH_MODE__
static const ubyte gpSha256Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}; /* 2 16 840 1 101 3 4 2 1 */
static const ubyte gpSha512Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}; /* 2 16 840 1 101 3 4 2 3 */
static const ubyte gpShake128Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b}; /* 2 16 840 1 101 3 4 2 11 */
/* shake256Oid if ever needed: 2 16 840 1 101 3 4 2 12 */
#endif

/* ------------------------------------------------------------------- */

/* ADRS format is Section 4.2. it's 32 bytes or 8 four byte words.
   Roughly speaking something like...

   [layer] [tree1] [tree2] [tree3] [type] [keypair] [chain or height] [hash or index]

   with big endien byte representations of each

   The 22 byte compressed version has only one byte for layer and type, and 8 bytes
   for tree. offset is therefore 3, 7, or 10 bytes less for the compressed version.
   */
#define SLHDSA_LAYER_OFFSET 3
#define SLHDSA_TREE_OFFSET 7
#define SLHDSA_MAX_OFFSET 10

#define SLHDSA_GET_LAYER_OFFSET( pCtx) (SLHDSA_ADRS_CMPR_LEN == pCtx->adrsLen ? SLHDSA_LAYER_OFFSET : 0)
#define SLHDSA_GET_TREE_OFFSET( pCtx) (SLHDSA_ADRS_CMPR_LEN == pCtx->adrsLen ? SLHDSA_TREE_OFFSET : 0)
#define SLHDSA_GET_MAX_OFFSET( pCtx) (SLHDSA_ADRS_CMPR_LEN == pCtx->adrsLen ? SLHDSA_MAX_OFFSET : 0)

/* Values are never more than 1 byte for these ones, store in least signifiant byte of proper word  */
#define SLHDSA_ADRS_SET_LAYER( pADRS, layer, offset) pADRS[3 - offset] = (ubyte) layer
#define SLHDSA_ADRS_SET_TYPE( pADRS, type, offset) pADRS[19 - offset] = (ubyte) type
#define SLHDSA_ADRS_SET_CHAIN_ADRS( pADRS, chain, offset) pADRS[27 - offset] = (ubyte) chain
#define SLHDSA_ADRS_SET_HASH_ADRS( pADRS, hash, offset) pADRS[31 - offset] = (ubyte) hash
#define SLHDSA_ADRS_SET_TREE_HEIGHT( pADRS, height, offset) pADRS[27 - offset] = (ubyte) height
#define SLHDSA_ADRS_GET_TREE_HEIGHT( pADRS, offset ) pADRS[27 - offset]

/* Sizes from Table 2. */
static size_t getPrivKeyLen(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 2*32;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 2*48;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 2*64;
        default:
            return 0;
    }
}

/* Sizes from Table 2. */
static size_t getPubKeyLen(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 32;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 48;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 64;
        default:
            return 0;
    }
}

/* Sizes from Table 2. */
static size_t getSigLen(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S:
            return 7856;
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 17088;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S:
            return 16224;
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 35664;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S:
            return 29792;
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 49856;
        default:
            return 0;
    }
}

static MSTATUS validateParams(SLHDSAType type, SLHDSAParams *params)
{
    /* TODO fill in */
    MOC_UNUSED(type);
    MOC_UNUSED(params);
    return OK;
}

static MSTATUS validateCtx(SLHDSACtx *ctx)
{
    if (ctx == NULL) {
        return ERR_NULL_POINTER;
    }

    if (ctx->tag != SLHDSA_TAG) {
        return ERR_WRONG_CTX_TYPE;
    }

    if (ctx->type <= SLHDSA_TYPE_ERR || ctx->type > SLHDSA_TYPE_SHAKE_256F) {
        return ERR_INVALID_INPUT;
    }

    if ((ctx->pubKey == NULL && ctx->pubKeyLen != 0) || (ctx->privKey == NULL && ctx->privKeyLen != 0)) {
        return ERR_INVALID_INPUT;
    }
    if (ctx->context == NULL && ctx->contextLen != 0) {
        return ERR_INVALID_INPUT;
    }
    size_t neededPubKeyLen = getPubKeyLen(ctx->type);
    size_t neededPrivKeyLen = getPrivKeyLen(ctx->type);
    if ((ctx->pubKey != NULL && ctx->pubKeyLen != neededPubKeyLen) ||
        (ctx->privKey != NULL && ctx->privKeyLen != neededPrivKeyLen)) {
        return ERR_INVALID_INPUT;
    }

    return validateParams(ctx->type, &ctx->params);
}

static const SlhdsaCtx* SLHDSA_getOldCtx(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S:
            return &gSlhdsaSha128s;
        case SLHDSA_TYPE_SHA2_128F:
            return &gSlhdsaSha128f;
        case SLHDSA_TYPE_SHA2_192S:
            return &gSlhdsaSha192s;
        case SLHDSA_TYPE_SHA2_192F:
            return &gSlhdsaSha192f;
        case SLHDSA_TYPE_SHA2_256S:
            return &gSlhdsaSha256s;
        case SLHDSA_TYPE_SHA2_256F:
            return &gSlhdsaSha256f;
        case SLHDSA_TYPE_SHAKE_128S:
            return &gSlhdsaShake128s;
        case SLHDSA_TYPE_SHAKE_128F:
            return &gSlhdsaShake128f;
        case SLHDSA_TYPE_SHAKE_192S:
            return &gSlhdsaShake192s;
        case SLHDSA_TYPE_SHAKE_192F:
            return &gSlhdsaShake192f;
        case SLHDSA_TYPE_SHAKE_256S:
            return &gSlhdsaShake256s;
        case SLHDSA_TYPE_SHAKE_256F:
            return &gSlhdsaShake256f;
        default:
            return NULL;
    }
}

static bool isSecureDigestType(SLHDSACtx *ctx, SLHDSADigestType digestType)
{
    if (digestType == SLHDSA_DIGEST_TYPE_SHA256) {
        if (ctx->params.n != SLHDSA_MIN_N) {
            return false;
        }
    }

    return true;
}

/* ------------------------------------------------------------------- */

static inline void SLHDSA_ADRS_SET_TREE(ubyte *pADRS, ubyte8 tree, ubyte4 offset)
{
#if __DIGICERT_MAX_INT__ == 64
    pADRS[8 - offset] = (ubyte) (tree >> 56) & 0xff;
    pADRS[9 - offset] = (ubyte) (tree >> 48) & 0xff;
    pADRS[10 - offset] = (ubyte) (tree >> 40) & 0xff;
    pADRS[11 - offset] = (ubyte) (tree >> 32) & 0xff;
    pADRS[12 - offset] = (ubyte) (tree >> 24) & 0xff;
    pADRS[13 - offset] = (ubyte) (tree >> 16) & 0xff;
    pADRS[14 - offset] = (ubyte) (tree >> 8) & 0xff;
    pADRS[15 - offset] = (ubyte) tree & 0xff;
#else
    pADRS[8 - offset] = (ubyte) (tree.upper32 >> 24) & 0xff;
    pADRS[9 - offset] = (ubyte) (tree.upper32 >> 16) & 0xff;
    pADRS[10 - offset] = (ubyte) (tree.upper32 >> 8) & 0xff;
    pADRS[11 - offset] = (ubyte) tree.upper32 & 0xff;
    pADRS[12 - offset] = (ubyte) (tree.lower32 >> 24) & 0xff;
    pADRS[13 - offset] = (ubyte) (tree.lower32 >> 16) & 0xff;
    pADRS[14 - offset] = (ubyte) (tree.lower32 >> 8) & 0xff;
    pADRS[15 - offset] = (ubyte) tree.lower32 & 0xff;
#endif
}

static inline void SLHDSA_ADRS_SET_KEYPAIR(ubyte *pADRS, ubyte4 keypair, ubyte4 offset)
{
    /* keypair is never more than 2 bytes */
    pADRS[22 - offset] = (ubyte) (keypair >> 8) & 0xff;
    pADRS[23 - offset] = (ubyte) keypair & 0xff;
}

static inline ubyte4 SLHDSA_ADRS_GET_KEYPAIR(ubyte *pADRS, ubyte4 offset)
{
    /* keypair is never more than 2 bytes */
    return ((ubyte4) pADRS[22 - offset]) << 8 | ((ubyte4) pADRS[23 - offset]);
}

static inline void SLHDSA_ADRS_SET_TREE_INDEX(ubyte *pADRS, ubyte4 index, ubyte4 offset)
{
    pADRS[28 - offset] = (ubyte) (index >> 24) & 0xff;
    pADRS[29 - offset] = (ubyte) (index >> 16) & 0xff;
    pADRS[30 - offset] = (ubyte) (index >> 8) & 0xff;
    pADRS[31 - offset] = (ubyte) index & 0xff;
}

static inline ubyte4 SLHDSA_ADRS_GET_TREE_INDEX(ubyte *pADRS, ubyte4 offset)
{
    return ((ubyte4) pADRS[28 - offset]) << 24 | ((ubyte4) pADRS[29 - offset]) << 16 |
           ((ubyte4) pADRS[30 - offset]) << 8 | ((ubyte4) pADRS[31 - offset]);
}

/* ------------------------------------------------------------------- */

#ifndef  __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__
/* Same mgf as RSA. loop only iterates once for sha512 and up to twice for sha256
   no need to check return codes for the hash and copy calls */
static MSTATUS SLHDSA_mgf1(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pMgfSeed, ubyte4 mgfSeedLen, ubyte4 maskLen, ubyte *pOut)
{
    ubyte pC[4] = {0};
    ubyte4 tLen;
    ubyte pTempOut[SLHDSA_MAX_HASH_RESULT_SIZE]; /* big enough for one iteration of sha512 or two of sha256 */

    /* sanity checks */
    if (maskLen > SLHDSA_MAX_M)
    {
        return ERR_INVALID_INPUT;
    }

    if (mgfSeedLen > SLHDSA_MGF_MAX_HASH_INLEN)
    {
        return ERR_INVALID_INPUT;
    }

    /* we use the TL algo which is the same sha */
    for (tLen = 0; tLen < maskLen; tLen += pHashCtx->pTLAlgo->digestSize)
    {
        /* T = T || Hash(mgfSeed || C)    OK to not check return status since no allocations are done */
        (void) pHashCtx->pTLAlgo->initFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx);
        (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pMgfSeed, mgfSeedLen);
        (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pC, 4);
        (void) pHashCtx->pTLAlgo->finalFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pTempOut + tLen);
        /* increment string counter, won't ever get to index 2 */
        pC[3]++;
    }

    (void) DIGI_MEMCPY(pOut, pTempOut, maskLen);
    (void) DIGI_MEMSET(pTempOut, 0x00, SLHDSA_MAX_HASH_RESULT_SIZE);

    return OK;
}

/* ------------------------------------------------------------------- */

/* BulkCtxHmsgFunc instance for sha256 or sha512
   MGF1-SHA-X(R||PK.seed||SHA-X(R||PK.seed||PK.root||M),m)
   pOut must have room for 64 bytes */
static MSTATUS SLHDSA_hMsgShaX(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut, ubyte4 m)
{
    MSTATUS status;
    BulkCtx pShaCtx = pHashCtx->pTLHashCtx;
    ubyte pFirstOut[SLHDSA_MGF_MAX_HASH_INLEN]; /* big enough for 2 blocks and sha256 or sha512 */

    (void) pHashCtx->pTLAlgo->initFunc(MOC_HASH(hwAccelCtx) pShaCtx);
    (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pPrefix, prefixLen);
    (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pShaCtx, pMsg, msgLen);

    /* R and pk.seed (ie first two blocks of prefix), then hash result */
    (void) DIGI_MEMCPY(pFirstOut, pPrefix, 2 * pHashCtx->n);
    (void) pHashCtx->pTLAlgo->finalFunc(MOC_HASH(hwAccelCtx) pShaCtx, pFirstOut + pHashCtx->n * 2);

    status = SLHDSA_mgf1(MOC_HASH(hwAccelCtx) pHashCtx, pFirstOut, 2 * pHashCtx->n + pHashCtx->pTLAlgo->digestSize, m, pOut);
    (void) DIGI_MEMSET(pFirstOut, 0x00, 2 * pHashCtx->n + pHashCtx->pTLAlgo->digestSize);

    return status;
}

/* ------------------------------------------------------------------- */

/* BulkCtxPRFmsgFunc implementation for sha256 or sha512
   HMAC-SHA-X(SK.prf,OptRand||M)  Here optRand is part of pMsgPrefix */
static MSTATUS SLHDSA_prfMsgShaX(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx,
                                 ubyte *pSkPrf, ubyte *pPrefix, ubyte4 prefixLen,
                                 ubyte *pMsg, ubyte4 msgLen, ubyte *pOut)
{
    MSTATUS status = OK;
    HMAC_CTX *pHmacCtx = NULL;
    ubyte pTempOut[SLHDSA_MAX_HASH_RESULT_SIZE]; /* big enough for either sha */

    status = HmacCreate(MOC_HASH(hwAccelCtx) &pHmacCtx, pHashCtx->pTLAlgo);
    if (OK != status)
        goto exit;

    status = HmacKey(MOC_HASH(hwAccelCtx) pHmacCtx, pSkPrf, pHashCtx->n);
    if (OK != status)
        goto exit;

    status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pPrefix, prefixLen);
    if (OK != status)
        goto exit;

    status = HmacUpdate(MOC_HASH(hwAccelCtx) pHmacCtx, pMsg, msgLen);
    if (OK != status)
        goto exit;

    status = HmacFinal(MOC_HASH(hwAccelCtx) pHmacCtx, pTempOut);
    if (OK != status)
        goto exit;

    (void) DIGI_MEMCPY(pOut, pTempOut, pHashCtx->n);

exit:

    (void) HmacDelete(MOC_HASH(hwAccelCtx) &pHmacCtx);
    (void) DIGI_MEMSET(pTempOut, 0x00, SLHDSA_MAX_HASH_RESULT_SIZE);

    return status;
}
/* ------------------------------------------------------------------- */

static void SLHDSA_prfSha2(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut)
{
    ubyte pTempOut[SHA256_RESULT_SIZE];

    /* methods don't allocate memory (at least on non-operator flows), no need to check return codes */
    (void) SHA256_cloneCtx(MOC_HASH(hwAccelCtx) pHashCtx->pPRFHashCtx, pHashCtx->pPRFCtxSeeded);
    (void) SHA256_updateDigest (MOC_HASH(hwAccelCtx) pHashCtx->pPRFHashCtx, (ubyte *) pADRS, SLHDSA_ADRS_CMPR_LEN);
    (void) SHA256_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pPRFHashCtx, (ubyte *) pM, mLen);
    (void) SHA256_finalDigest(MOC_HASH(hwAccelCtx) pHashCtx->pPRFHashCtx, pTempOut);
    (void) DIGI_MEMCPY(pOut, pTempOut, pHashCtx->n);
}

/* ------------------------------------------------------------------- */

static void SLHDSA_tlSha2(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut)
{
    ubyte pTempOut[SLHDSA_MAX_HASH_RESULT_SIZE]; /* big enough for sha256 or sha512 */

    /* methods don't allocate memory (at least on non-operator flows), no need to check return codes */
    (void) pHashCtx->TL_CLONE(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pHashCtx->pTLCtxSeeded);
    (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, (ubyte *) pADRS, SLHDSA_ADRS_CMPR_LEN);
    (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, (ubyte *) pM, mLen);
    (void) pHashCtx->pTLAlgo->finalFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pTempOut);
    (void) DIGI_MEMCPY(pOut, pTempOut, pHashCtx->n);
}

/* ------------------------------------------------------------------- */

static MSTATUS SLHDSA_getSha2TLHashes(SlhdsaHashCtx *pHashCtx, ubyte tlAlgo)
{
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    status = CRYPTO_FIPS_getRSAHashAlgo(tlAlgo, (const BulkHashAlgo **) &pHashCtx->pTLAlgo);
#else
    status = CRYPTO_getRSAHashAlgo(tlAlgo, (const BulkHashAlgo **) &pHashCtx->pTLAlgo);
#endif
    if (OK != status)
        goto exit;

    /* also set the clone pointers  */
    if (ht_sha256 == tlAlgo)
    {
        pHashCtx->TL_CLONE = (BulkCtxCloneFunc) SHA256_cloneCtx;
    }
    else /* ht_sha512 == tlAlgo */
    {
        pHashCtx->TL_CLONE = (BulkCtxCloneFunc) SHA512_cloneCtx;
    }

exit:

    return status;
}
#endif /* #ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__ */

/* ------------------------------------------------------------------- */

#ifndef  __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__
/* BulkCtxHmsgFunc instance for shake256
   SHAKE256(R||PK.seed||PK.root||M,8m) */
static MSTATUS SLHDSA_hMsgShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pPrefix, ubyte4 prefixLen, ubyte *pMsg, ubyte4 msgLen, ubyte *pOut, ubyte4 m)
{
    (void) SHA3_initDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, MOCANA_SHA3_MODE_SHAKE256);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pPrefix, prefixLen);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pMsg, msgLen);
    return SHA3_finalDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pOut, m);
}

/* ------------------------------------------------------------------- */

/* BulkCtxPRFmsgFunc implementation for shake256
   SHAKE256(SK.prf||OptRand||M,n), we return a status to match the sha2 version,
   OptRand is part of the message prefix */
static MSTATUS SLHDSA_prfMsgShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx,
                                     ubyte *pSkPrf, ubyte *pPrefix, ubyte4 prefixLen,
                                     ubyte *pMsg, ubyte4 msgLen, ubyte *pOut)
{
    (void) SHA3_initDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, MOCANA_SHA3_MODE_SHAKE256);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pSkPrf, pHashCtx->n);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pPrefix, prefixLen);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pMsg, msgLen);
    (void) SHA3_finalDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pOut, pHashCtx->n);
    return OK;
}

/* ------------------------------------------------------------------- */

/* for shake one function can be both PRF and TL */
static void SLHDSA_tlPrfShake256(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte *pADRS, ubyte *pM, ubyte4 mLen, ubyte *pOut)
{
    /* methods don't allocate memory (at least on non-operator flows), no need to check return codes */
    (void) SHA3_initDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, MOCANA_SHA3_MODE_SHAKE256);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, (ubyte *) pHashCtx->pPkSeed, pHashCtx->n);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, (ubyte *) pADRS, SLHDSA_ADRS_LEN);
    (void) SHA3_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, (ubyte *) pM, mLen);
    (void) SHA3_finalDigest(MOC_HASH(hwAccelCtx) pHashCtx->pTLHashCtx, pOut, pHashCtx->n);
}
#endif /* #ifndef  __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__ */

/* ------------------------------------------------------------------- */

static void SLHDSA_freeHashes(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte hashMode)
{
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__
    if (SLHDSA_MODE_SHAKE == hashMode)
    {
        if (NULL != pHashCtx->pTLHashCtx)
        {
            (void) SHA3_freeDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pTLHashCtx);
        }

        if (NULL != pHashCtx->pPkSeed)
        {
            (void) DIGI_MEMSET_FREE(&pHashCtx->pPkSeed, pHashCtx->n);
        }
    }
#endif
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__
    if (SLHDSA_MODE_SHA2 == hashMode)
    {
        /* ok if BulkCtx's are NULL, we'll just ignore null pointer error code */
        if (NULL != pHashCtx->pTLAlgo)
        {
            (void) pHashCtx->pTLAlgo->freeFunc(MOC_HASH(hwAccelCtx) &pHashCtx->pTLCtxSeeded);
            (void) pHashCtx->pTLAlgo->freeFunc(MOC_HASH(hwAccelCtx) &pHashCtx->pTLHashCtx);
        }

        /* only sha256 used for PRFCtx */
        (void) SHA256_freeDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pPRFCtxSeeded);
        (void) SHA256_freeDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pPRFHashCtx);
    }
#endif

    (void) DIGI_MEMSET((ubyte *) pHashCtx, 0x00, sizeof(SlhdsaHashCtx));
}

/* ------------------------------------------------------------------- */

/* pkSeed should be pCtx->n bytes zero padded to the larger block size of pTLAlgo and pPRFAlgo */
static MSTATUS SLHDSA_initHashes(MOC_HASH(hwAccelDescr hwAccelCtx) SlhdsaHashCtx *pHashCtx, ubyte hashMode, ubyte *pPkSeed, ubyte4 n)
{
    MSTATUS status = OK;
    
    /* internal method, no need for null checks */

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHAKE__
    if (SLHDSA_MODE_SHAKE == hashMode)
    {
        /* we're using shake, make a copy or the public key seed */
        status = DIGI_MALLOC_MEMCPY((void **) &pHashCtx->pPkSeed, n, (void *) pPkSeed, n);
        if (OK != status)
            goto exit;

        /* TL */
        /* we init the TL context but don't update with the seed here */
        status = SHA3_allocDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pTLHashCtx);
        if (OK != status)
            goto exit;

        /* PRF uses same function as TL, no PRF context needed */
    }
#endif
#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_SHA2__
    if (SLHDSA_MODE_SHA2 == hashMode)
    {
        /* first set up which sha2 to use, sha256 for smallest n (16), sha512 otherwise */
        status = SLHDSA_getSha2TLHashes(pHashCtx, SLHDSA_MIN_N == n ? ht_sha256 : ht_sha512);
        if (OK != status)
            goto exit;

        /* we're using sha2, alloc and update with the public key seed */

        /* TL */
        status = pHashCtx->pTLAlgo->allocFunc(MOC_HASH(hwAccelCtx) &pHashCtx->pTLHashCtx);
        if (OK != status)
            goto exit;

        status = pHashCtx->pTLAlgo->allocFunc(MOC_HASH(hwAccelCtx) &pHashCtx->pTLCtxSeeded);
        if (OK != status)
            goto exit;

        (void) pHashCtx->pTLAlgo->initFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLCtxSeeded);
        (void) pHashCtx->pTLAlgo->updateFunc(MOC_HASH(hwAccelCtx) pHashCtx->pTLCtxSeeded, pPkSeed, pHashCtx->pTLAlgo->blockSize);

        /* PRF, always sha256 */
        status = SHA256_allocDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pPRFHashCtx);
        if (OK != status)
            goto exit;

        status = SHA256_allocDigest(MOC_HASH(hwAccelCtx) &pHashCtx->pPRFCtxSeeded);
        if (OK != status)
            goto exit;

        (void) SHA256_initDigest(MOC_HASH(hwAccelCtx) pHashCtx->pPRFCtxSeeded);
        (void) SHA256_updateDigest(MOC_HASH(hwAccelCtx) pHashCtx->pPRFCtxSeeded, pPkSeed, SHA256_BLOCK_SIZE);
    }
#endif

    /* also store a copy of n in pHashCtx for convenience */
    pHashCtx->n = n;

exit:

    if (OK != status)
    {
        SLHDSA_freeHashes(MOC_HASH(hwAccelCtx) pHashCtx, hashMode);
    }

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 4, base_2^b(X, b, outLen)
   For WOTS signing the output buffer pBaseB is a ubyte array
   For fors index generation its a ubyte4 array. We use SLHDSA_LOG_W == b
   as a flag for it to be WOTS signing. */
static void SLHDSA_base2totheb(ubyte *pX, ubyte4 b, ubyte4 outLen, void *pBaseB)
{
    ubyte4 in = 0;
    ubyte4 bits = 0;
    ubyte4 total = 0;
    ubyte4 out = 0;

    for (; out < outLen; out++)
    {
        while( bits < b )
        {
            total = (total << 8) + pX[in];
            in++;
            bits += 8;
        }

        bits -= b;

        if (SLHDSA_LOG_W == b)
        {
            ((ubyte *) pBaseB)[out] = (ubyte) ((total >> bits) & 0x0f); /* using, we know b is 4 */
        }
        else
        {
            ((ubyte4 *) pBaseB)[out] = (total >> bits) & (0xffff >> (16-b)); /* using, we know b is at most 14 */
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 5, chain(X, i, s, PK.seed, ADRS) */
static void SLHDSA_wotsChain(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pX, ubyte i, ubyte s, ubyte *pADRS, ubyte *pOut)
{
    ubyte j;

    /* pOut can be used as the buffer tmp */
    (void) DIGI_MEMCPY(pOut, pX, pCtx->n);

    for (j = i; j < (ubyte) (i + s); j++)
    {
        /* ADRS.setHashAddress(j) */
        SLHDSA_ADRS_SET_HASH_ADRS(pADRS, j, SLHDSA_GET_MAX_OFFSET(pCtx));
        /* tmp = F(PK.seed, ADRS, tmp); F is same as PRF here in all modes */
        pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pOut, pCtx->n, pOut);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 6, wots_pkGen(SK.seed, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx */
static MSTATUS SLHDSA_wotsPkGen(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSkSeed, ubyte *pADRS, ubyte *pPk)
{
    MSTATUS status = OK;
    ubyte pSkAdrs[SLHDSA_ADRS_LEN];
    ubyte pWotsPkAdrs[SLHDSA_ADRS_LEN];
    ubyte *pTmp = NULL;
    ubyte pSk[SLHDSA_MAX_N];
    ubyte4 i;

    status = DIGI_MALLOC((void **) &pTmp, pCtx->n * pCtx->len);
    if (OK != status)
        goto exit;

    (void) DIGI_MEMCPY(pSkAdrs, pADRS, SLHDSA_ADRS_LEN);
    (void) DIGI_MEMCPY(pWotsPkAdrs, pADRS, SLHDSA_ADRS_LEN);

    /* skADRS.setTypeAndClear(WOTS_PRF) */
    SLHDSA_ADRS_SET_TYPE(pSkAdrs, SLHDSA_ADRS_WOTS_PRF, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* and clear, zero hash adrs, and chain adrs will be set in loop */
    SLHDSA_ADRS_SET_HASH_ADRS(pSkAdrs, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

    for (i = 0; i < pCtx->len; i++)
    {
        /* skADRS.setChainAddress(i); */
        SLHDSA_ADRS_SET_CHAIN_ADRS(pSkAdrs, i, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* sk[i] = PRF(SK.seed, skADRS); */
        pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pSkAdrs, pSkSeed, pCtx->n, pSk);

        /* ADRS.setChainAddress(i); */
        SLHDSA_ADRS_SET_CHAIN_ADRS(pADRS, i, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* tmp[i] = chain(sk[i], 0, w- 1, PK.seed, ADRS); */
        SLHDSA_wotsChain(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSk, 0, SLHDSA_W - 1, pADRS, pTmp + i * pCtx->n);
    }

    /* wotspkADRS.setTypeAndClear(WOTS_PK); */
    SLHDSA_ADRS_SET_TYPE(pWotsPkAdrs, SLHDSA_ADRS_WOTS_PK, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress());  */
    /* already copied but do zero pad the last two words */
    (void) DIGI_MEMSET(pWotsPkAdrs + SLHDSA_ADRS_LEN - SLHDSA_GET_MAX_OFFSET(pCtx) - 8, 0x00, 8);

    /* pk = T_len(PK.seed, wotspkADRS, tmp);  */
    pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pWotsPkAdrs, pTmp, pCtx->n * pCtx->len, pPk);

exit:

    if (NULL != pTmp)
    {
        (void) DIGI_MEMSET_FREE(&pTmp, pCtx->n * pCtx->len);
    }

    (void) DIGI_MEMSET(pSk, 0x00, pCtx->n);

    return status;
}

/* ------------------------------------------------------------------- */

/* helper method to convert the msg to base 16 and append the checksum */
static void SLHDSA_msgToBase16withCsum(ubyte *pMsg, ubyte4 len1, ubyte *pBuffer)
{
    ubyte4 csum = 0; /* check sum */
    ubyte pLenBytes[SLHDSA_LEN2_BYTES]; /* 2 */
    ubyte4 i;

    SLHDSA_base2totheb(pMsg, SLHDSA_LOG_W, len1, (void *) pBuffer);

    for (i = 0; i < len1; i++)
    {
        csum += (ubyte4) ((ubyte) SLHDSA_W_MASK - pBuffer[i]);
    }

    /* csum is no more than 12 bits, align left so highest 3 nibbles are taken as its base 16 format */
    csum <<= 4; /* csum = csum << ((8 - ((SLHDSA_LEN2 * SLHDSA_LOG_W) % 8)) % 8); ie (3 * 4) mod 8 */
    pLenBytes[1] = csum & 0xff;
    pLenBytes[0] = (csum >> 8) & 0xff;

    SLHDSA_base2totheb(pLenBytes, SLHDSA_LOG_W, SLHDSA_LEN2, (void *) (pBuffer + len1));
}

/* ------------------------------------------------------------------- */

/* Algorithm 7, wots_sign(M, SK.seed, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx */
static void SLHDSA_wotsSign(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pM, ubyte *pSkSeed, ubyte *pADRS, ubyte *pSig)
{
    ubyte pSkAdrs[SLHDSA_ADRS_LEN];
    ubyte pMsg[SLHDSA_MAX_LEN]; /* 67, max of len1 + len2 */
    ubyte pSk[SLHDSA_MAX_N]; /* 32 */
    ubyte4 i;

    SLHDSA_msgToBase16withCsum(pM, pCtx->len1, pMsg);

    (void) DIGI_MEMCPY(pSkAdrs, pADRS, SLHDSA_ADRS_LEN);

    /* skADRS.setTypeAndClear(WOTS_PRF); */
    SLHDSA_ADRS_SET_TYPE( pSkAdrs, SLHDSA_ADRS_WOTS_PRF, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* and clear, zero hash adrs */
    SLHDSA_ADRS_SET_HASH_ADRS(pSkAdrs, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

    for ( i = 0; i < pCtx->len; i++ )
    {
        /* skADRS.setChainAddress(i); */
        SLHDSA_ADRS_SET_CHAIN_ADRS(pSkAdrs, i, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* sk = PRF(SK.seed, skADRS); */
        pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pSkAdrs, pSkSeed, pCtx->n, pSk);

        /* ADRS.setChainAddress(i); */
        SLHDSA_ADRS_SET_CHAIN_ADRS(pADRS, i, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* sig[i] = chain(sk, 0, msg[i], PK.seed, ADRS);  */
        SLHDSA_wotsChain(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSk, 0, pMsg[i], pADRS, pSig + i * pCtx->n);
    }

    (void) DIGI_MEMSET(pMsg, 0x00, pCtx->len);
    (void) DIGI_MEMSET(pSk, 0x00, pCtx->n);
}

/* ------------------------------------------------------------------- */

/* Algorithm 8, wots_pkFromSig(sig, M, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx */
static MSTATUS SLHDSA_wotsPkFromSig(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSig, ubyte *pM, ubyte *pADRS, ubyte *pPk)
{
    MSTATUS status = OK;
    ubyte pPkAdrs[SLHDSA_ADRS_LEN];
    ubyte pMsg[SLHDSA_MAX_LEN]; /* 67, max of len1 + len2 */
    ubyte *pTmp = NULL;
    ubyte4 i;

    status = DIGI_MALLOC((void **) &pTmp, pCtx->n * pCtx->len);
    if (OK != status)
        goto exit;

    SLHDSA_msgToBase16withCsum(pM, pCtx->len1, pMsg);

    (void) DIGI_MEMCPY(pPkAdrs, pADRS, SLHDSA_ADRS_LEN);

    for ( i = 0; i < pCtx->len; i++ )
    {
        /* ADRS.setChainAddress(i); */
        SLHDSA_ADRS_SET_CHAIN_ADRS( pADRS, i, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* tmp[i] = chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS); */
        SLHDSA_wotsChain(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSig + i * pCtx->n, pMsg[i], (ubyte) SLHDSA_W_MASK - pMsg[i], pADRS, pTmp + i * pCtx->n);
    }

    /* wotspkADRS.setTypeAndClear(WOTS_PK); the clear will be below */
    SLHDSA_ADRS_SET_TYPE(pPkAdrs, SLHDSA_ADRS_WOTS_PK, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress()); */
    SLHDSA_ADRS_SET_KEYPAIR(pPkAdrs, SLHDSA_ADRS_GET_KEYPAIR(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)), SLHDSA_GET_MAX_OFFSET(pCtx));

    /* zero the rest, bytes 24-31 for non-compressed 14-21 for compressed */
    (void) DIGI_MEMSET(pPkAdrs + SLHDSA_ADRS_LEN - SLHDSA_GET_MAX_OFFSET(pCtx) - 8, 0x00, 8);

    /* T_len(PK.seed, wotspkADRS, tmp); */
    pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pPkAdrs, pTmp, pCtx->n * pCtx->len, pPk);

exit:

    if (NULL != pTmp)
    {
        (void) DIGI_MEMSET_FREE(&pTmp, pCtx->n * pCtx->len);
    }

    (void) DIGI_MEMSET(pMsg, 0x00, pCtx->len);

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 9, xmss_node(SK.seed, i, z, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx */
static MSTATUS SLHDSA_xmssNode(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSkSeed, ubyte4 i, ubyte4 z, ubyte *pADRS, ubyte *pNode)
{
    MSTATUS status = OK;
    ubyte4 j;
    ubyte4 leafIdx = (0x01 << z) * i;
    ubyte *pStack = NULL;
    ubyte pHeights[SLHDSA_MAX_HT_HEIGHT + 1]; /* height of each node on the stack, one extra needed */
    ubyte stackPos = 0;

    /* internal method, NULL checks not necc */

    /* We do an iterative version using a stack to traverse the tree rather than the recursive version.
       The stack's maximum will be a leafnode from every level, plus the one additional one that will
       get added and then processed and popped, so allocate space for z + 1 nodes */
    status = DIGI_MALLOC((void **) &pStack, (z + 1) * pCtx->n);
    if (OK != status)
        goto exit;

    /* each iteration creates a new leaf, 2^z leaves total */
    for (j = 0; j < (ubyte4) (0x01 << z); j++)
    {
        /* ADRS.setTypeAndClear(WOTS_HASH); no need to clear, all bits set in the next calls */
        SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_WOTS_HASH, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* ADRS.setKeyPairAddress(i)
           but when we recursively get to the left most root node,
           i is multiplied by 2^z. Node index increments from there by j */
        SLHDSA_ADRS_SET_KEYPAIR(pADRS, (leafIdx + j), SLHDSA_GET_MAX_OFFSET(pCtx));
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));
        SLHDSA_ADRS_SET_TREE_INDEX(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* Generate a leaf node, put directly on stack, it's height is 1 */
        status = SLHDSA_wotsPkGen(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, pADRS, pStack + stackPos * pCtx->n);
        if (OK != status)
            goto exit;

        pHeights[stackPos] = 1;
        stackPos++;

        /* ADRS.setTypeAndClear(TREE); clear keypair. height and index will be set */
        SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_TREE, SLHDSA_GET_MAX_OFFSET(pCtx));
        SLHDSA_ADRS_SET_KEYPAIR(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* ADRS.setTreeHeight(z);
           But the while loop below always processes two leaf nodes first to get
           the level 1 node, so we first start out with a height of 1 */
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, 1, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* ADRS.setTreeIndex(i); same comment as above, i is shifted */
        SLHDSA_ADRS_SET_TREE_INDEX(pADRS, (leafIdx + j), SLHDSA_GET_MAX_OFFSET(pCtx));

        /* For ease in comparison all leafs get added to the stack, then
           we can compare the top two on stack, and the while loop statement becomes  */
        /* while ( Top two nodes on Stack have same height )*/
        while (stackPos > 1 && pHeights[stackPos - 1] == pHeights[stackPos - 2])
        {
            /* ADRS.setTreeIndex((ADRS.getTreeIndex()- 1) / 2); */
            SLHDSA_ADRS_SET_TREE_INDEX(pADRS, (SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) - 1) / 2, SLHDSA_GET_MAX_OFFSET(pCtx));

            /* node = H(PK.seed, ADRS, lnode || rnode) So we pop 2 elements
               and add one new one at height one greater, H is just TL with two nodes input */
            pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pStack + (stackPos - 2) * pCtx->n, 2 * pCtx->n, pStack + (stackPos - 2) * pCtx->n);
            pHeights[stackPos - 2]++;
            stackPos--;

            /* increment the height if we have more on the stack to pop */
            SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, SLHDSA_ADRS_GET_TREE_HEIGHT(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) + 1, SLHDSA_GET_MAX_OFFSET(pCtx));
        }
    }

    /* all that's left is the root, copy it */
    status = DIGI_MEMCPY(pNode, pStack, pCtx->n);

exit:

    if (NULL != pStack)
    {
        (void) DIGI_MEMSET_FREE(&pStack, (z + 1) * pCtx->n);
    }

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 10, xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx
   writes n * (len + h/d) bytes to pSig */
static MSTATUS SLHDSA_xmssSign(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSkSeed, ubyte *pM, ubyte4 idx, ubyte *pADRS, ubyte *pSigXmss)
{
    MSTATUS status = OK;
    ubyte4 j,k;

    for (j = 0; j < (pCtx->h / pCtx->d); j++) /* h' = h/d */
    {
        /* k = floor(idx / (2^j)) XOR 1; */
        k = (idx / (0x01 << j)) ^ 0x01;

        /* AUTH[j] = xmss_node(SK.seed, k, j, PK.seed, ADRS);
           First len * n bytes of sig will come from wots, store in jth index after that */
        status = SLHDSA_xmssNode(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, k, j, pADRS, pSigXmss + (j + pCtx->len) * pCtx->n);
        if (OK != status)
            goto exit;
    }

    /* ADRS.setTypeAndClear(WOTS_HASH); clear will happen after */
    SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_WOTS_HASH, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* ADRS.setKeyPairAddress(idx); */
    SLHDSA_ADRS_SET_KEYPAIR(pADRS, idx, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* zero the rest, bytes 24-31 for non-compressed, 14-21 for compressed */
    (void) DIGI_MEMSET(pADRS + SLHDSA_ADRS_LEN - SLHDSA_GET_MAX_OFFSET(pCtx) - 8, 0x00, 8);

    /* now write the first n * len bytes of the signature */
    SLHDSA_wotsSign(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pM, pSkSeed, pADRS, pSigXmss);

exit:

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 11, xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx */
static MSTATUS SLHDSA_xmssPkFromSig(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte4 idx, ubyte *pSigXmss, ubyte *pM, ubyte *pADRS, ubyte *pPkXmss)
{
    MSTATUS status = OK;

    /* big enough for 3 nodes of any size n,
       we put node[0] in the middle element so we can prepend or append */
    ubyte pNode[SLHDSA_MAX_N * 3];
    ubyte4 k = 0;

    /* ADRS.setTypeAndClear(WOTS_HASH); */
    SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_WOTS_HASH, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* ADRS.setKeyPairAddress(idx); */
    SLHDSA_ADRS_SET_KEYPAIR(pADRS, idx, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* zero the rest, bytes 24-31 for non-compressed, 14-21 for compressed */
    (void) DIGI_MEMSET(pADRS + SLHDSA_ADRS_LEN - SLHDSA_GET_MAX_OFFSET(pCtx) - 8, 0x00, 8);

    /* put node[0] in the middle element of pNode */
    status = SLHDSA_wotsPkFromSig(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSigXmss, pM, pADRS, pNode + pCtx->n);
    if (OK != status)
        goto exit;

    /* ADRS.setTypeAndClear(TREE); */
    SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_TREE, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* and clear keypair, we'll set index and heigt both below */
    SLHDSA_ADRS_SET_KEYPAIR(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* ADRS.setTreeIndex(idx); */
    SLHDSA_ADRS_SET_TREE_INDEX(pADRS, idx, SLHDSA_GET_MAX_OFFSET(pCtx));

    for (k = 0; k < (pCtx->h / pCtx->d); k++)
    {
        /* ADRS.setTreeHeight(k+1); */
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, k + 1, SLHDSA_GET_MAX_OFFSET(pCtx));

        if ( !((idx / (0x01 << k)) & 0x01) )
        {
            /* ADRS.setTreeIndex(ADRS.getTreeIndex() / 2); */
            SLHDSA_ADRS_SET_TREE_INDEX( pADRS, (SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) / 2), SLHDSA_GET_MAX_OFFSET(pCtx));

            /* node[1] = H(PK.seed, ADRS, (node[0] || AUTH[k])); */
            /* copy AUTH[k] after node[0], ie into the 3rd element, hash last 2 elements */
            (void) DIGI_MEMCPY(pNode + 2 * pCtx->n, pSigXmss + (k + pCtx->len) * pCtx->n, pCtx->n);
            pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pNode + pCtx->n, 2 * pCtx->n, pNode + pCtx->n);
        }
        else
        {
            /* ADRS.setTreeIndex((ADRS.getTreeIndex()- 1) / 2); */
            SLHDSA_ADRS_SET_TREE_INDEX( pADRS, ((SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) - 1) / 2), SLHDSA_GET_MAX_OFFSET(pCtx));

            /* node[1] = H(PK.seed, ADRS, (AUTH[k] || node[0])); */
            /* copy AUTH[k] before node[0], ie into the 1st element, hash first two elements */
            (void) DIGI_MEMCPY(pNode, pSigXmss + (k + pCtx->len) * pCtx->n, pCtx->n);
            pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pNode, 2 * pCtx->n, pNode + pCtx->n);
        }

        /* node[0] = node[1]; */
        /* already done, we stored hash result in middle element again */
    }

    /* result is in middle element of pNode */
    (void) DIGI_MEMCPY(pPkXmss, pNode + pCtx->n, pCtx->n);

exit:

    (void) DIGI_MEMSET(pNode, 0x00, 3 * pCtx->n);

    return status;
}

/* ------------------------------------------------------------------- */

/*  Algorithm 12, ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
    PK.seed already consumed in the SlhdsaHashCtx.
    writes (d * len + h) * n bytes to pSig */
static MSTATUS SLHDSA_htSign(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pM, ubyte *pSkSeed, ubyte8 treeIndex, ubyte4 leafIndex, ubyte *pSigHT)
{
    MSTATUS status = OK;
    ubyte pADRS[SLHDSA_ADRS_LEN] = {0};
    ubyte pRoot[SLHDSA_MAX_N];
    ubyte4 j;
    ubyte4 xmssSigLen;

    /* ADRS.setLayerAddress(0); */
    /* already set to 0 */

    /* ADRS.setTreeAddress(idx_tree); */
    SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

    /* writes n * (len + h/d) bytes to pSigHT */
    xmssSigLen = pCtx->n * (pCtx->len + (pCtx->h / pCtx->d));
    status = SLHDSA_xmssSign(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, pM, leafIndex, pADRS, pSigHT);
    if (OK != status)
        goto exit;

    status = SLHDSA_xmssPkFromSig(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, leafIndex, pSigHT, pM, pADRS, pRoot);
    if (OK != status)
        goto exit;

    for ( j = 1; j < pCtx->d; j++ )
    {
#if __DIGICERT_MAX_INT__ == 64
        /* h' least significant bits of idx_tree; */
        leafIndex = (ubyte4) (treeIndex & (SLHDSA_FULL_MASK >> (64 - pCtx->h / pCtx->d)));

        /* remove h' least sig bits of idx_tree; It's just a bit shift */
        treeIndex >>= (pCtx->h / pCtx->d);
#else
        /* we take advantage that we know h/d is no more than 9, low bits all get shifted away  */
        leafIndex = treeIndex.lower32 & (SLHDSA_FULL_MASK >> (32 - pCtx->h / pCtx->d));
        treeIndex.lower32 = (treeIndex.upper32 << (32 - (pCtx->h / pCtx->d))) | (treeIndex.lower32 >> (pCtx->h / pCtx->d));
        treeIndex.upper32 >>= (pCtx->h / pCtx->d);
#endif
        /* ADRS.setLayerAddress(j); */
        SLHDSA_ADRS_SET_LAYER(pADRS, j, SLHDSA_GET_LAYER_OFFSET(pCtx));

        /* ADRS.setTreeAddress(idx_tree); */
        SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

        status = SLHDSA_xmssSign(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, pRoot, leafIndex, pADRS, pSigHT + j * xmssSigLen);
        if (OK != status)
            goto exit;

        if (j < pCtx->d - 1)
        {
            status = SLHDSA_xmssPkFromSig(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, leafIndex, pSigHT + j * xmssSigLen, pRoot, pADRS, pRoot);
            if (OK != status)
                goto exit;
        }
    }

exit:

    (void) DIGI_MEMSET(pRoot, 0x00, pCtx->n);

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 13, ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root) */
static MSTATUS SLHDSA_htVerify(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pM, ubyte *pSigHT, ubyte8 treeIndex, ubyte4 leafIndex, ubyte *pPkHt, intBoolean *pMatchRes)
{
    MSTATUS status;
    ubyte pADRS[SLHDSA_ADRS_LEN] = {0};
    ubyte pNode[SLHDSA_MAX_N];
    ubyte4 j;
    ubyte4 xmssSigLen;

    /* ADRS.setLayerAddress(0); */
    /* already set to 0 */

    /* ADRS.setTreeAddress(idx_tree); */
    SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

    /* each xmss signature is xmssSigLen bytes */
    xmssSigLen = pCtx->n * (pCtx->len + (pCtx->h / pCtx->d));
    status = SLHDSA_xmssPkFromSig(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, leafIndex, pSigHT, pM, pADRS, pNode);
    if (OK != status)
        goto exit;

    for ( j = 1; j < pCtx->d; j++ )
    {
#if __DIGICERT_MAX_INT__ == 64
        /* h' least significant bits of idx_tree; */
        leafIndex = (ubyte4) (treeIndex & (SLHDSA_FULL_MASK >> (64 - pCtx->h / pCtx->d)));

        /* remove h' least sig bits of idx_tree; It's just a bit shift */
        treeIndex >>= (pCtx->h / pCtx->d);
#else
        /* we take advantage that we know h/d is no more than 9, low bits all get shifted away  */
        leafIndex = treeIndex.lower32 & (SLHDSA_FULL_MASK >> (32 - pCtx->h / pCtx->d));
        treeIndex.lower32 = (treeIndex.upper32 << (32 - (pCtx->h / pCtx->d))) | (treeIndex.lower32 >> (pCtx->h / pCtx->d));
        treeIndex.upper32 >>= (pCtx->h / pCtx->d);
#endif
        /* ADRS.setLayerAddress(j); */
        SLHDSA_ADRS_SET_LAYER(pADRS, j, SLHDSA_GET_LAYER_OFFSET(pCtx));

        /* ADRS.setTreeAddress(idx_tree); */
        SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

        status = SLHDSA_xmssPkFromSig(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, leafIndex, pSigHT + j * xmssSigLen, pNode, pADRS, pNode);
        if (OK != status)
            goto exit;
    }

    (void) DIGI_CTIME_MATCH(pNode, pPkHt, pCtx->n, pMatchRes);

exit:

    (void) DIGI_MEMSET(pNode, 0x00, pCtx->n);

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 14, fors_skGen(SK.seed, PK.seed, ADRS, idx)
   PK.seed already consumed in the SlhdsaHashCtx. */
static void SLHDSA_forsSkGen(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSkSeed, ubyte *pADRS, ubyte4 idx, ubyte *pSk)
{
    ubyte pSkAdrs[SLHDSA_ADRS_LEN];

    (void) DIGI_MEMCPY(pSkAdrs, pADRS, SLHDSA_ADRS_LEN);

    /* skADRS.setTypeAndClear(FORS_PRF); */
    SLHDSA_ADRS_SET_TYPE(pSkAdrs, SLHDSA_ADRS_FORS_PRF, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* and clear height */
    SLHDSA_ADRS_SET_TREE_HEIGHT(pSkAdrs, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* skADRS.setKeyPairAddress(ADRS.getKeyPairAddress()) */
    /* already done in the copy */

    /* skADRS.setTreeIndex(idx); */
    SLHDSA_ADRS_SET_TREE_INDEX(pSkAdrs, idx, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* sk = PRF(PK.seed, SK.seed, skADRS); */
    pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pSkAdrs, pSkSeed, pCtx->n, pSk);
}

/* ------------------------------------------------------------------- */

/* Algorithm 15, fors_node(SK.seed, i, z, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx. */
static MSTATUS SLHDSA_forsNode(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSkSeed, ubyte4 i, ubyte4 z, ubyte *pADRS, ubyte *pNode)
{
    MSTATUS status = OK;
    ubyte4 j;
    ubyte4 leafIdx = (0x01 << z) * i;

    ubyte pTemp[SLHDSA_MAX_N];
    ubyte *pStack = NULL;
    ubyte pHeights[SLHDSA_MAX_FORS_HEIGHT + 1]; /* height of each node on the stack, one extra needed */
    ubyte stackPos = 0;

    /* internal method, NULL checks not necc */

    /* We do an iterative version using a stack to traverse the tree rather than the recursive version.
       The stack's maximum will be a leafnode from every level, plus the one additional one that will
       get added and then processed and popped, so allocate space for z + 1 nodes */
    status = DIGI_MALLOC((void **) &pStack, (z + 1) * pCtx->n);
    if (OK != status)
        goto exit;

    /* each iteration creates a new leaf, 2^z leaves */
    for (j = 0; j < (ubyte4) (0x01 << z); j++)
    {
        /* Generate a leaf node, put directly on stack, it's height is 1 */

        /* sk = fors_SKgen(SK.seed, ADRS, i) but when we recursively get
           to the left most root node i is multiplied by 2^z.
           Node index increments from there by j */
        SLHDSA_forsSkGen(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, pADRS, leafIdx + j, pTemp);

        /* ADRS.setTreeIndex(i); same comment as above about i */
        SLHDSA_ADRS_SET_TREE_INDEX(pADRS, leafIdx + j, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* ADRS.setTreeHeight(0)*/
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* node = F(PK.seed, ADRS, sk); F is same as PRF here, type is still FORS_TREE */
        pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pTemp, pCtx->n, pStack + stackPos * pCtx->n);
        pHeights[stackPos] = 1;
        stackPos++;

        /* ADRS.setTreeHeight(1); */
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, 1, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* For ease in comparison all leafs get added to the stack, then
           we can compare the top two on stack, and the while loop statement becomes  */
        /* while ( Top two nodes on Stack have same height )*/
        while (stackPos > 1 && pHeights[stackPos - 1] == pHeights[stackPos - 2])
        {
            /* ADRS.setTreeIndex((ADRS.getTreeIndex()- 1) / 2); */
            SLHDSA_ADRS_SET_TREE_INDEX(pADRS, (SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) - 1) / 2, SLHDSA_GET_MAX_OFFSET(pCtx));

            /* node = H(PK.seed, ADRS, lnode || rnode); So we pop 2 elements
               and add one new one at height one greater, H is just TL with two nodes input */
            pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pStack + (stackPos - 2) * pCtx->n, 2 * pCtx->n, pStack + (stackPos - 2) * pCtx->n);
            pHeights[stackPos - 2]++;
            stackPos--;

            /* increment the height if we have more on the stack to pop */
            SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, SLHDSA_ADRS_GET_TREE_HEIGHT(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) + 1, SLHDSA_GET_MAX_OFFSET(pCtx));
        }
    }

    /* all that's left is the root, copy it */
    status = DIGI_MEMCPY(pNode, pStack, pCtx->n);

exit:

    if (NULL != pStack)
    {
        (void) DIGI_MEMSET_FREE(&pStack, (z + 1) * pCtx->n);
    }

    (void) DIGI_MEMSET(pTemp, 0x00, pCtx->n);

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 16, fors_sign(md, SK.seed, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx.
   writes k * (a + 1) * n bytes for the signature */
static MSTATUS SLHDSA_forsSign(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pMd, ubyte *pSkSeed, ubyte *pADRS, ubyte *pSigFors)
{
    MSTATUS status = OK;
    ubyte4 i,j;
    ubyte4 s;
    ubyte4 sigLen = 0;
    ubyte4 pIndices[SLHDSA_MAX_K];

    SLHDSA_base2totheb(pMd, pCtx->a, pCtx->k, (void *) pIndices);

    for (i = 0; i < pCtx->k; i++)
    {
        /* fors_SKgen(SK.seed, ADRS, i * 2^a + indices[i]) */
        SLHDSA_forsSkGen(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, pADRS, i * (0x01 << pCtx->a) + pIndices[i], pSigFors + sigLen);
        sigLen += pCtx->n;

        for (j = 0; j < pCtx->a; j++)
        {
            /* s = floor(idx / (2^j)) XOR 1; */
            s = (pIndices[i] / (0x01 << j) ) ^ 0x01;

            /* AUTH[j] = fors_node(SK.seed, i * 2^(a - j) + s, j, PK.seed, ADRS) */
            status = SLHDSA_forsNode(MOC_HASH(hwAccelCtx) pCtx, pHashCtx, pSkSeed, i * (0x01 << (pCtx->a - j)) + s, j, pADRS, pSigFors + sigLen);
            if (OK != status)
                goto exit;

            sigLen += pCtx->n;
        }
    }

exit:

    (void) DIGI_MEMSET((ubyte *) pIndices, 0x00, pCtx->k * sizeof(ubyte4));
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 17, fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
   PK.seed already consumed in the SlhdsaHashCtx. */
static MSTATUS SLHDSA_forsPkFromSig(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, SlhdsaHashCtx *pHashCtx, ubyte *pSigFors, ubyte *pMd, ubyte *pADRS, ubyte *pPkFors)
{
    MSTATUS status = OK;

    /* big enough for 3 nodes of any size n,
       we put node[0] in the middle element so we can prepend or append */
    ubyte pNode[3 * SLHDSA_MAX_N];
    ubyte *pRoots = NULL;
    ubyte4 i,j;
    ubyte pForsPkAdrs[SLHDSA_ADRS_LEN];
    ubyte4 pIndices[SLHDSA_MAX_K];

    status = DIGI_MALLOC((void **) &pRoots, pCtx->k * pCtx->n);
    if (OK != status)
        goto exit;

    SLHDSA_base2totheb(pMd, pCtx->a, pCtx->k, (void *) pIndices);

    for (i = 0; i < pCtx->k; i++)
    {
        /* ADRS.setTreeHeight(0); */
        SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, 0, SLHDSA_GET_MAX_OFFSET(pCtx));

        /* ADRS.setTreeIndex(i * 2^a + indices[i]); */
        SLHDSA_ADRS_SET_TREE_INDEX(pADRS, i * (0x01 << pCtx->a) + pIndices[i], SLHDSA_GET_MAX_OFFSET(pCtx));

        /* node[0] = F(PK.seed, ADRS, sk); F is same as PRF here */
        pCtx->PRF(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pSigFors, pCtx->n, pNode + pCtx->n);
        pSigFors += pCtx->n; /* ok to move passed by value ptr */

        for (j = 0; j < pCtx->a; j++)
        {
            /* ADRS.setTreeHeight(j+1); */
            SLHDSA_ADRS_SET_TREE_HEIGHT(pADRS, j + 1, SLHDSA_GET_MAX_OFFSET(pCtx));

            /* if ( (floor(idx / (2^j)) % 2) == 0 ) */
            if ( !((pIndices[i] / (0x01 << j)) & 0x01 ))
            {
                /* ADRS.setTreeIndex(ADRS.getTreeIndex() / 2); */
                SLHDSA_ADRS_SET_TREE_INDEX(pADRS, (SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) / 2), SLHDSA_GET_MAX_OFFSET(pCtx));

                /* node[1] = H(PK.seed, ADRS, node[0] || auth[j]); */
                /* copy auth[j] into last of three elements in pNode */
                (void) DIGI_MEMCPY(pNode + 2 * pCtx->n, pSigFors, pCtx->n);
                pSigFors += pCtx->n;
                pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pNode + pCtx->n, 2 * pCtx->n, pNode + pCtx->n);
            }
            else
            {
                /* ADRS.setTreeIndex((ADRS.getTreeIndex()- 1) / 2); */
                SLHDSA_ADRS_SET_TREE_INDEX(pADRS, ((SLHDSA_ADRS_GET_TREE_INDEX(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)) - 1) / 2), SLHDSA_GET_MAX_OFFSET(pCtx));

                /* node[1] = H(PK.seed, ADRS, auth[j] || node[0]); */
                /* copy auth[j] into first of three elements in pNode */
                (void) DIGI_MEMCPY(pNode, pSigFors, pCtx->n);
                pSigFors += pCtx->n;
                pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pADRS, pNode, 2 * pCtx->n, pNode + pCtx->n);
            }

            /* node[0] = node[1]; already all set, answer placed in middle of pNode */
        }

        /* root[i] = node[0]; */
        (void) DIGI_MEMCPY(pRoots + i * pCtx->n, pNode + pCtx->n, pCtx->n);
    }

    (void) DIGI_MEMCPY( pForsPkAdrs, pADRS, SLHDSA_ADRS_LEN);

    /* forspkADRS.setTypeAndClear(FORS_ROOTS); */
    SLHDSA_ADRS_SET_TYPE(pForsPkAdrs, SLHDSA_ADRS_FORS_ROOTS, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress()); */
    SLHDSA_ADRS_SET_KEYPAIR( pForsPkAdrs, SLHDSA_ADRS_GET_KEYPAIR(pADRS, SLHDSA_GET_MAX_OFFSET(pCtx)), SLHDSA_GET_MAX_OFFSET(pCtx));

    /* zero the rest, bytes 24-31 for non-compressed, 14-21 for compressed  */
    (void) DIGI_MEMSET(pForsPkAdrs + SLHDSA_ADRS_LEN - SLHDSA_GET_MAX_OFFSET(pCtx) - 8, 0x00, 8);

    /* pk = T_k(PK.seed, forspkADRS, root); */
    pCtx->TL(MOC_HASH(hwAccelCtx) pHashCtx, pForsPkAdrs, pRoots, pCtx->k * pCtx->n, pPkFors);

exit:

    if (NULL != pRoots)
    {
        (void) DIGI_MEMSET_FREE(&pRoots, pCtx->k * pCtx->n);
    }

    (void) DIGI_MEMSET(pNode, 0x00, 3 * pCtx->n);
    (void) DIGI_MEMSET((ubyte *) pIndices, 0x00, pCtx->k * sizeof(ubyte4));

    return status;
}

/* ------------------------------------------------------------------- */

/* Helper method to get the leaf index and tree index from the applicable bytes in pBuffer */
static void SLHDSA_getIndices(const SlhdsaCtx *pCtx, ubyte *pBuffer, ubyte8 *pTreeIndex, ubyte4 *pLeafIndex)
{
    ubyte4 indexBits = 0;
    ubyte4 indexBytes = 0;

#if __DIGICERT_MAX_INT__ == 64
    ubyte8 treeIndex = 0ULL;
#else
    ubyte8 treeIndex = {0};
#endif
    ubyte4 leafIndex = 0;
    ubyte4 i;

    /* internal method, NULL checks not necc */

    /* tmp_idx_tree = next floor((h- h/d +7)/ 8) bytes of digest;  */
    /* idx_tree = first h- h/d bits of tmp_idx_tree; */
    indexBits = pCtx->h - (pCtx->h / pCtx->d); /* d always divides h */
    indexBytes = (indexBits + 7) / 8;

#if __DIGICERT_MAX_INT__ == 64
    for (i = 0; i < indexBytes; i++)
    {
        treeIndex <<= 8;
        treeIndex |= (ubyte8) pBuffer[i];
    }

    /* mod 2^(h - h/d) */
    treeIndex &= (SLHDSA_FULL_MASK >> (64 - indexBits));
#else
    /* we know indexBytes is at least 7, do first 4 and then the rest */
    for (i = 0; i < 4; i++)
    {
        treeIndex.lower32 |= (ubyte4) (pBuffer[indexBytes - 1 - i] << (8 * i));
    }
    for (; i < indexBytes; i++)
    {
        treeIndex.upper32 |= (ubyte4) (pBuffer[indexBytes - 1 - i] << (8 * (i - 4)));
    }
    /* only upper32 may need to be masked, we know indexBits >= 54 */
    treeIndex.upper32 &= (SLHDSA_FULL_MASK >> (64 - indexBits));
#endif

    /* ok to move passed by value pointer, now get leaf index */
    pBuffer += indexBytes;

    /* tmp_idx_leaf = next floor((h/d +7)/ 8) bytes of digest; */
    /* idx_leaf = first h/d bits of tmp_idx_leaf; */
    indexBits = (pCtx->h / pCtx->d); /* d always divides h */
    indexBytes = (indexBits + 7) / 8;

    for (i = 0; i < indexBytes; i++)
    {
        leafIndex <<= 8;
        leafIndex |= (ubyte4) pBuffer[i];
    }

    /* mod 2^(h/d) */
    leafIndex &= ((~(ubyte4) 0) >> (32 - indexBits));

#if __DIGICERT_MAX_INT__ == 64
    *pTreeIndex = treeIndex;
#else
    pTreeIndex->upper32 = treeIndex.upper32;
    pTreeIndex->lower32 = treeIndex.lower32;
#endif
    *pLeafIndex = leafIndex;
}

/* ------------------------------------------------------------------- */

/* Algorithm 18, slh_keygen_internal(SK.seed, SK.prf, PK.seed)
   pBuf contains those 3 input params in that order. The output
   pk.root will be placed after them. */
static MSTATUS SLHDSA_keygen_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pBuf)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte pPkSeed[SLHDSA_MAX_HASH_BLOCK_SIZE] = {0}; /* 128 */
    ubyte pADRS[SLHDSA_ADRS_LEN] = {0};
    ubyte4 n = 0;
    SlhdsaHashCtx hashCtx = {0};
    ubyte hashMode = (SLHDSA_ADRS_LEN == pCtx->adrsLen ? SLHDSA_MODE_SHAKE : SLHDSA_MODE_SHA2);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);

    /* internal method, null checks not necc */
    n = pCtx->n;

    /* copy the pk seed, ie 3rd input seed, into a buffer with enough padding */
    (void) DIGI_MEMCPY(pPkSeed, pBuf + 2 * n, n);

    /* Init the hash suites with PK.seed padded with 0x00 to a block len */
    status = SLHDSA_initHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode, pPkSeed, n);
    if (OK != status)
        goto exit;

    /* ADRS.setLayerAddress(d-1); */
    SLHDSA_ADRS_SET_LAYER(pADRS, pCtx->d - 1, SLHDSA_GET_LAYER_OFFSET(pCtx));

    /* ADRS.setTreeAddress(0); */
    /* already done */

    /* create PK.root, place it after the other 3 seeds */
    status = SLHDSA_xmssNode(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pBuf, 0, pCtx->h / pCtx->d, pADRS, pBuf + 3 * n);

exit:

    (void) DIGI_MEMSET(pPkSeed, 0x00, n);
    (void) DIGI_MEMSET(pADRS, 0x00, SLHDSA_ADRS_LEN);

    SLHDSA_freeHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode);

    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 19, slh_sign_internal(M, SK, addrnd).
   It's required pDataPrefix have space for 2 seeds of length n,
   then be addr_rnd also length n, and then be the message rep prefix */
static MSTATUS SLHDSA_sign_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pSk,
                                    ubyte *pDataPrefix, ubyte4 dataPrefixLen,
                                    ubyte *pMsgRep, ubyte4 msgRepLen, ubyte *pSig)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte pADRS[SLHDSA_ADRS_LEN] = {0};
    ubyte pPkSeed[SLHDSA_MAX_HASH_BLOCK_SIZE] = {0}; /* 128 */
    ubyte pDigest[SLHDSA_MAX_M];
    ubyte pPkFors[SLHDSA_MAX_N];
    SlhdsaHashCtx hashCtx = {0};
    ubyte hashMode = (SLHDSA_ADRS_LEN == pCtx->adrsLen ? SLHDSA_MODE_SHAKE : SLHDSA_MODE_SHA2);
    ubyte4 n = 0;

    ubyte4 leafIndex = 0;
#if __DIGICERT_MAX_INT__ == 64
    ubyte8 treeIndex = 0ULL;
#else
    ubyte8 treeIndex = {0};
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);

    /* internal method, null checks not necc */
    n = pCtx->n;

    /* Seed the hash ctx with pkSeed, 3rd element in pSk, need to pad to hash block len */
    (void) DIGI_MEMCPY(pPkSeed, pSk + 2 * n, n);
    status = SLHDSA_initHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode, pPkSeed, n);
    if (OK != status)
        goto exit;

    /* R = PRF_msg(SK.prf, opt, M); but place as first n bytes of pSignature */

    /* SK.prf is 2nd element in pSk, and opt_rand = addrnd is 2 seeds from the start of pDataPrefix */
    status = pCtx->PRF_MSG(MOC_HASH(hwAccelCtx) &hashCtx, pSk + n, pDataPrefix + 2 * n, dataPrefixLen - 2 * n, pMsgRep, msgRepLen, pDataPrefix);
    if (OK != status)
        goto exit;

    (void) DIGI_MEMCPY(pSig, pDataPrefix, n);
    pSig += n;

    /* digest = H_msg(R, PK.seed, PK.root, M); */

    /* R is already at the start of pDataPrefix, copy in PK.seed and pK.root after it */
    (void) DIGI_MEMCPY(pDataPrefix + n, pSk + 2 * n, 2 * n);
    status = pCtx->H_MSG(MOC_HASH(hwAccelCtx) &hashCtx, pDataPrefix, dataPrefixLen, pMsgRep, msgRepLen, pDigest, pCtx->m);
    if (OK != status)
        goto exit;

    /* indices are after the md */
    SLHDSA_getIndices(pCtx, pDigest + (pCtx->k * pCtx->a + 7) / 8, &treeIndex, &leafIndex);

    /* ADRS.setTreeAddress(treeIndex); */
    SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

    /* ADRS.setTypeAndClear(FORS_TREE); */
    SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_FORS_TREE, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* ADRS.setKeyPairAddress(leafIndex); */
    SLHDSA_ADRS_SET_KEYPAIR(pADRS, leafIndex, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* SIG_FORS = fors_sign(md, SK.seed, PK.seed, ADRS); place after R, md is start of pDigest */
    status = SLHDSA_forsSign(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pDigest, pSk, pADRS, pSig);
    if (OK != status)
        goto exit;

    /* PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS); */
    status = SLHDSA_forsPkFromSig(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pSig, pDigest, pADRS, pPkFors);
    if (OK != status)
        goto exit;

    pSig += n * pCtx->k * (pCtx->a + 1);

    /* SIG_HT = ht_sign(PK_FORS, SK.seed, PK.seed, idx_tree, idx_leaf); place after SIG_FORS */
    status = SLHDSA_htSign(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pPkFors, pSk, treeIndex, leafIndex, pSig);

exit:

    (void) DIGI_MEMSET(pADRS, 0x00, SLHDSA_ADRS_LEN);
    (void) DIGI_MEMSET(pPkFors, 0x00, n);
    (void) DIGI_MEMSET(pDigest, 0x00, SLHDSA_MAX_M);
    (void) DIGI_MEMSET(pPkSeed, 0x00, n); /* only first n bytes were modified */

    SLHDSA_freeHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode);

    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 20, slh_verify_internal(M, SIG, PK)
   It's required pDataPrefix have space for 3 seeds of length n,
   and then be the message rep prefix */
static MSTATUS SLHDSA_verify_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pPk,
                                      ubyte *pDataPrefix, ubyte4 dataPrefixLen, ubyte *pMsgRep,
                                      ubyte4 msgRepLen, ubyte *pSig, sbyte4 sigLen, ubyte4 *pVerifyStatus)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte pADRS[SLHDSA_ADRS_LEN] = {0};
    ubyte pPkSeed[SLHDSA_MAX_HASH_BLOCK_SIZE] = {0}; /* 128 */
    ubyte pDigest[SLHDSA_MAX_M];
    ubyte pPkFors[SLHDSA_MAX_N];
    intBoolean isMatch = FALSE;
    ubyte4 leafIndex = 0;
    SlhdsaHashCtx hashCtx = {0};
    ubyte hashMode = (SLHDSA_ADRS_LEN == pCtx->adrsLen ? SLHDSA_MODE_SHAKE : SLHDSA_MODE_SHA2);
    ubyte4 n = 0;

#if __DIGICERT_MAX_INT__ == 64
    ubyte8 treeIndex = 0ULL;
#else
    ubyte8 treeIndex = {0};
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);

    /* Special case when called with a signature length that needs checking */
    if ((sigLen >= 0)&&(pCtx->sigLen != (ubyte4) sigLen))
    {
        /* Failed check */
        *pVerifyStatus = 1;
        goto exit;
    }

    /* internal method, null checks not necc */
    n = pCtx->n;

    /* Seed the hash ctx with pkSeed, need to pad to hash block len */
    (void) DIGI_MEMCPY(pPkSeed, pPk, n);

    status = SLHDSA_initHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode, pPkSeed, n);
    if (OK != status)
        goto exit;

    /* digest = H_msg(R, PK.seed, PK.root, M); R is first n bytes of the signature */
    (void) DIGI_MEMCPY(pDataPrefix, pSig, n);
    (void) DIGI_MEMCPY(pDataPrefix + n, pPk, 2 * n);
    status = pCtx->H_MSG(MOC_HASH(hwAccelCtx) &hashCtx, pDataPrefix, dataPrefixLen, pMsgRep, msgRepLen, pDigest, pCtx->m);
    if (OK != status)
        goto exit;

    pSig += n;

    /* indices are after the md */
    SLHDSA_getIndices(pCtx, pDigest + (pCtx->k * pCtx->a + 7) / 8, &treeIndex, &leafIndex);

    /* ADRS.setTreeAddress(treeIndex); */
    SLHDSA_ADRS_SET_TREE(pADRS, treeIndex, SLHDSA_GET_TREE_OFFSET(pCtx));

    /* ADRS.setTypeAndClear(FORS_TREE); */
    SLHDSA_ADRS_SET_TYPE(pADRS, SLHDSA_ADRS_FORS_TREE, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* ADRS.setKeyPairAddress(leafIndex); */
    SLHDSA_ADRS_SET_KEYPAIR(pADRS, leafIndex, SLHDSA_GET_MAX_OFFSET(pCtx));

    /* PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS); */
    status = SLHDSA_forsPkFromSig(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pSig, pDigest, pADRS, pPkFors);
    if (OK != status)
        goto exit;

    pSig += n * pCtx->k * (pCtx->a + 1);

    /* ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root); SIG_HT is after SIG_FORS */
    status = SLHDSA_htVerify(MOC_HASH(hwAccelCtx) pCtx, &hashCtx, pPkFors, pSig, treeIndex, leafIndex, pPk + n, &isMatch);
    if (OK != status)
        goto exit;

    *pVerifyStatus = !(!isMatch); /* convert to 0 for success, 1 for failure */

exit:

    (void) DIGI_MEMSET(pADRS, 0x00, SLHDSA_ADRS_LEN);
    (void) DIGI_MEMSET(pPkFors, 0x00, n);
    (void) DIGI_MEMSET(pDigest, 0x00, SLHDSA_MAX_M);
    (void) DIGI_MEMSET(pPkSeed, 0x00, n); /* only first n bytes were modified */

    SLHDSA_freeHashes(MOC_HASH(hwAccelCtx) &hashCtx, hashMode);

    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,pCtx->sigLen);
    return status;
}

/* Helper method that computes the prefix for the message or message digest.
   this method also leaves 3n bytes in front of *ppDataPrefix so that up to 3 seeds can be copied in */
//static MSTATUS SLHDSA_getDataPrefix(SlhdsaKey *pKey, ubyte **ppDataPrefix, ubyte4 *pDataPrefixLen)
static MSTATUS SLHDSA_getDataPrefix(SLHDSADigestType digestType, uint8_t n, uint8_t *contextStr, size_t contextStrLen, uint8_t **ppDataPrefix, size_t *pDataPrefixLen)
{
    MSTATUS status = OK;
    ubyte *pDataPrefix = NULL;
    ubyte *pDataPrefixPtr;
    ubyte4 dataPrefixLen = 3 * n + 2; /* space for 3 seeds and at least the intial mode and ctxLen bytes */

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_CTX_PREHASH_MODE__

    dataPrefixLen += contextStrLen;

    if (digestType != SLHDSA_DIGEST_TYPE_ERR) {
        dataPrefixLen += SLHDSA_OID_LEN;
    }
#endif

    status = DIGI_MALLOC((void **) &pDataPrefix, dataPrefixLen);
    if (OK != status)
        goto exit;

    pDataPrefixPtr = pDataPrefix + 3 * n;

#ifndef __DISABLE_DIGICERT_PQC_SLHDSA_CTX_PREHASH_MODE__
    pDataPrefixPtr[0] = (digestType == SLHDSA_DIGEST_TYPE_ERR ? 0 : 1);
    pDataPrefixPtr[1] = (ubyte) contextStrLen;

    pDataPrefixPtr += 2;

    if (contextStrLen > 0)
    {
        (void) DIGI_MEMCPY(pDataPrefixPtr, contextStr, contextStrLen);
        pDataPrefixPtr += contextStrLen;
    }

    switch(digestType)
    {
        case SLHDSA_DIGEST_TYPE_ERR:
            break;

        case SLHDSA_DIGEST_TYPE_SHA256:

            (void) DIGI_MEMCPY(pDataPrefixPtr, gpSha256Oid, SLHDSA_OID_LEN);
            break;

        case SLHDSA_DIGEST_TYPE_SHA512:

            (void) DIGI_MEMCPY(pDataPrefixPtr, gpSha512Oid, SLHDSA_OID_LEN);
            break;

        case SLHDSA_DIGEST_TYPE_SHAKE128:

            (void) DIGI_MEMCPY(pDataPrefixPtr, gpShake128Oid, SLHDSA_OID_LEN);
            break;

        default:
            /* shouldn't happen but sanity check */
            status = ERR_INVALID_INPUT;
            goto exit;
    }

#else

    pDataPrefixPtr[0] = 0;
    pDataPrefixPtr[1] = 0;

#endif /* __DISABLE_DIGICERT_PQC_SLHDSA_CTX_PREHASH_MODE__ */

    *ppDataPrefix = pDataPrefix; pDataPrefix = NULL;
    *pDataPrefixLen = dataPrefixLen;

exit:

    if (NULL != pDataPrefix)
    {
        (void) DIGI_MEMSET_FREE(&pDataPrefix, dataPrefixLen);
    }

    return status;
}

static MSTATUS sign(SLHDSACtx *ctx, uint8_t *msg, size_t msgLen, RNGFun rng, void *rngArg,
        uint8_t *contextString, size_t contextStringLen, uint8_t *sig, SLHDSADigestType digestType)
{
    MSTATUS status = OK;
    ubyte *pDataPrefix = NULL;
    size_t dataPrefixLen = 0;
    const SlhdsaCtx *pCtx = SLHDSA_getOldCtx(ctx->type);
    uint8_t n = ctx->params.n;

    status = SLHDSA_getDataPrefix(digestType, n, contextString, contextStringLen, &pDataPrefix, &dataPrefixLen);
    if (OK != status)
        goto exit;

    if (NULL != rng)
    {    
        status = (MSTATUS) rng(rngArg, n, pDataPrefix + 2 * n);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* we know that addrnd will instead be pk.seed, 3rd element of pSk (privKey) */
        (void) DIGI_MEMCPY(pDataPrefix + 2 * n, ctx->privKey + 2 * n, n);
    }

    /* pDataPrefix has 64 bytes of space for the TR to be pre-pended also */
    status = SLHDSA_sign_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->privKey, pDataPrefix, dataPrefixLen, msg, msgLen, sig);

exit:
    moc_memset_free(&pDataPrefix, dataPrefixLen);

    return status;
}

static MSTATUS verify(SLHDSACtx *ctx, uint8_t *msg, size_t msgLen, uint8_t *contextString, size_t contextStringLen, uint8_t *sig,
        SLHDSADigestType digestType)
{
    MSTATUS status = OK;
    ubyte *pDataPrefix = NULL;
    size_t dataPrefixLen = 0;
    const SlhdsaCtx *pCtx = SLHDSA_getOldCtx(ctx->type);

    status = SLHDSA_getDataPrefix(digestType, ctx->params.n, contextString, contextStringLen, &pDataPrefix, &dataPrefixLen);
    if (OK != status)
        goto exit;

    /* Call internal function, signalling the signature length has been checked already */
    uint32_t verifyStatus = 0;
    status = SLHDSA_verify_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->pubKey, pDataPrefix, dataPrefixLen, msg, msgLen, sig, -1, &verifyStatus);
    if (verifyStatus != 0) {
        status = ERR_CRYPTO_FAILURE;
    }

exit:
    moc_memset_free(&pDataPrefix, dataPrefixLen);

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_createCtx(SLHDSAType type, hwAccelDescr hwAccelCtx, SLHDSACtx *ctx)
{
    MSTATUS status = ERR_INVALID_INPUT;
    const SlhdsaCtx *pCtx;

    if (type <= SLHDSA_TYPE_ERR || type > SLHDSA_TYPE_SHAKE_256F)
	goto exit;

    status = ERR_NULL_POINTER;
    if (ctx == NULL)
	goto exit;

    status = OK;

    ctx->tag = SLHDSA_TAG;
    ctx->type = type;
    ctx->pubKey = NULL;
    ctx->pubKeyLen = 0;
    ctx->privKey = NULL;
    ctx->privKeyLen = 0;
    ctx->hwAccelCtx = hwAccelCtx;
    ctx->context = NULL;
    ctx->contextLen = 0;

    pCtx = SLHDSA_getOldCtx(ctx->type);

    ctx->params.n = pCtx->n;
    ctx->params.h = pCtx->h;
    ctx->params.d = pCtx->d;
    ctx->params.k = pCtx->k;
    ctx->params.a = pCtx->a;
    ctx->params.m = pCtx->m;

exit:
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 21, slh_keygen() */
static MSTATUS generateKeyPair(RNGFun rng, void *rngArg, SLHDSACtx *ctx)
{
    MSTATUS status = OK;
    uint8_t *pBuf = NULL;
    uint8_t n = 0;
    const SlhdsaCtx *pCtx = SLHDSA_getOldCtx(ctx->type);

    /* Algorithm 1 Step 1, create the seee xi */
    n = ctx->params.n;

    /* allocate space for a full private key, 4 seeds of length n */
    status = DIGI_MALLOC((void **) &ctx->privKey, 4 * n);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &ctx->pubKey, getPubKeyLen(ctx->type));
    if (OK != status)
        goto exit;
    pBuf = ctx->privKey;

    /* create SK.seed, SK.prf, and PK.seed directly into pBuf */
    status = (MSTATUS) rng(rngArg, 3 * n, pBuf);
    if (OK != status)
        goto exit;

    /* SLHDSA_keygen_internal(SK.seed, SK.prf, PK.seed), input params are all in pBuf in
       proper order, output pk.root will go after them into pBuf */
    status = SLHDSA_keygen_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->privKey);
    if (OK != status)
        goto exit;

    ctx->pubKeyLen = getPubKeyLen(ctx->type);
    ctx->privKeyLen = getPrivKeyLen(ctx->type);
    moc_memcpy(ctx->pubKey, ctx->privKey + 2*n, 2*n);

exit:
    if (status != OK) {
        moc_memset_free(&ctx->pubKey, getPubKeyLen(ctx->type));
        moc_memset_free(&ctx->privKey, getPrivKeyLen(ctx->type));
    }

    return status;
}

MOC_EXTERN MSTATUS SLHDSA_generateKeyPair(RNGFun rng, void *rngArg, SLHDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (rng == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (ctx->pubKey != NULL || ctx->privKey != NULL)
        goto exit;

    status = generateKeyPair(rng, rngArg, ctx);
    if (status != OK)
        goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = SLHDSA_generateKey_FIPS_consistency_test(ctx, rng, rngArg)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
MOC_EXTERN MSTATUS
SLHDSA_generateKey_FIPS_consistency_test(SLHDSACtx* pCtx, RNGFun rng, void *rngArg)
{
    MSTATUS status = OK;

#if __ENABLE_DIGICERT_FIPS_SLHDSA_FULL_PCT__
    /* Run the full sign/verify cycle with the generated key. This MAY TAKE A VERY LONG TIME! */
    sbyte4 msgLen = 15;
    ubyte msg[] = {
        'C', 'L', 'E', 'A', 'R', '_', 'T', 'E', 'X', 'T', '_', 'L', 'I', 'N', 'E'
    };

    size_t sigLen = getSigLen(pCtx->type);
    ubyte  *pSig = NULL;

    /* Create buffer */
    status = DIGI_MALLOC((void**)&pSig, sigLen);
    if (OK != status)
        goto exit;

    /* Create signature */
    status = SLHDSA_signMessage(pCtx, msg, msgLen, rng, rngArg,
				pSig, sigLen);
    if (OK != status)
        goto exit;

    if ( 1 == slhdsa_fail )
    {
        pSig[0] ^= 0xA5;
    }
    slhdsa_fail = 0;

    /* Verify signature */
    status = SLHDSA_verifyMessage(pCtx, msg, msgLen, pSig, sigLen);
    if (OK != status)
    {
        status = ERR_FIPS_SLHDSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_SLHDSA,status);
        goto exit;
    }

    FIPS_TESTLOG(1050, "SLHDSA_generateKey_FIPS_consistency_test: GOOD Signature Verify!");

exit:
    DIGI_FREE((void**)&pSig);

#else /* __ENABLE_DIGICERT_FIPS_SLHDSA_FULL_PCT__ */

    /* Run the 'seed check' on the generated key pair. */
    /* Per FIPS 140-3/IG - 10.3.A - Additional Comment 1, this is allowed to save time. */
    ubyte  *pPKSeedPublic;
    ubyte  *pPKSeedPrivate;
    ubyte4 seedLen;
    sbyte4 cmpRes = 0;

    /* Length of seeds */
    seedLen = pCtx->params.n;

    /* Set pointers into key arrays */
    pPKSeedPublic  = pCtx->pubKey;
    pPKSeedPrivate = pCtx->privKey + 2*seedLen;

    if ( 1 == slhdsa_fail )
    {
        pPKSeedPrivate[0] ^= 0x01;
    }
    slhdsa_fail = 0;

    /* Compare the seed arrays */
    if (OK != DIGI_CTIME_MATCH(pPKSeedPublic, pPKSeedPrivate,
                              seedLen, &cmpRes))
    {
        status = ERR_FIPS_SLHDSA_FAIL;
        setFIPS_Status(FIPS_ALGO_SLHDSA,status);
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_SLHDSA_FAIL;
        setFIPS_Status(FIPS_ALGO_SLHDSA,status);
        goto exit;
    }

    FIPS_TESTLOG(1051, "SLHDSA_generateKey_FIPS_consistency_test: GOOD Seeds!");

exit:
#endif /* __ENABLE_DIGICERT_FIPS_SLHDSA_FULL_PCT__ */
    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_setContext(const uint8_t *context, size_t contextSize, SLHDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    if (ctx->context != NULL)
    {
        DIGI_FREE((void **)&ctx->context);
        ctx->contextLen = 0;
    }

    status = OK;
    if ((context != NULL) && (contextSize > 0))
    {
        status = DIGI_MALLOC_MEMCPY((void **)&ctx->context, contextSize, (void *)context, contextSize);
        if (OK != status)
            goto exit;

        ctx->contextLen = contextSize;
    }
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_getPublicKeyLen(SLHDSACtx *ctx, size_t *publicKeyLen)
{
    if (ctx == NULL || publicKeyLen == NULL)
        return ERR_NULL_POINTER;

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *publicKeyLen = getPubKeyLen(ctx->type);

    return OK;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_getPublicKey(SLHDSACtx *ctx, uint8_t *publicKey, size_t publicKeyLen)

{
    if (ctx == NULL || publicKey == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    if (ctx->pubKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    /* TODO make this != to have the user explicitly send the correct size. This way they don't get the wrong key by mistake. */
    if (publicKeyLen < ctx->pubKeyLen) {
        return ERR_BUFFER_TOO_SMALL;
    }

    return DIGI_MEMCPY(publicKey, ctx->pubKey, ctx->pubKeyLen);
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, SLHDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (publicKey == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_PREVIOUSLY_EXISTING_ITEM;
    if (ctx->pubKey != NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (publicKeyLen != getPubKeyLen(ctx->type))
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **)&ctx->pubKey, publicKeyLen, (void *)publicKey, publicKeyLen);
    if (OK != status)
        goto exit;

    ctx->pubKeyLen = publicKeyLen;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

MOC_EXTERN MSTATUS SLHDSA_getPrivateKeyLen(SLHDSACtx *ctx, size_t *privateKeyLen)
{
    if (ctx == NULL || privateKeyLen == NULL)
        return ERR_NULL_POINTER;

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *privateKeyLen = getPrivKeyLen(ctx->type);

    return OK;
}

MOC_EXTERN MSTATUS SLHDSA_getPrivateKey(SLHDSACtx *ctx, uint8_t *privateKey, size_t privateKeyLen)
{
    if (ctx == NULL || privateKey == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    if (ctx->privKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    if (privateKeyLen != ctx->privKeyLen) {
        return ERR_BUFFER_TOO_SMALL;
    }

    return DIGI_MEMCPY(privateKey, ctx->privKey, ctx->privKeyLen);
}

MOC_EXTERN MSTATUS SLHDSA_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, SLHDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (privateKey == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_PREVIOUSLY_EXISTING_ITEM;
    if (ctx->privKey != NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (privateKeyLen != getPrivKeyLen(ctx->type))
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **)&ctx->privKey, privateKeyLen, (void *)privateKey, privateKeyLen);
    if (OK != status)
        goto exit;

    ctx->privKeyLen = privateKeyLen;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}
/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_getSignatureLen(SLHDSACtx *ctx, size_t *signatureLen)
{
    if (ctx == NULL || signatureLen == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *signatureLen = getSigLen(ctx->type);

    return OK;
}

/* ------------------------------------------------------------------- */

/* Algorithm 22 and 23, slh_sign(M, ctx, sk) or hash_slh_sign(M, ctx, PH, sk)
   rng is optional and it will be deterministic mode if it is not given. */
MOC_EXTERN MSTATUS SLHDSA_signMessage(SLHDSACtx *ctx, uint8_t *message, size_t messageLen, RNGFun rng, void *rngArg,
                                     uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || message == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->privKey == NULL)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = sign(ctx, message, messageLen, rng, rngArg, ctx->context, ctx->contextLen, signature, SLHDSA_DIGEST_TYPE_ERR);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

MOC_EXTERN MSTATUS SLHDSA_signDigest(SLHDSACtx *ctx, uint8_t *digest, size_t digestLen, SLHDSADigestType digestType, RNGFun rng, void *rngArg,
                                    uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || digest == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->privKey == NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (digestType <= SLHDSA_DIGEST_TYPE_ERR || digestType > SLHDSA_DIGEST_TYPE_SHAKE128)
        goto exit;

    status = ERR_CRYPTO_BAD_HASH;
    if (isSecureDigestType(ctx, digestType) != true)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = sign(ctx, digest, digestLen, rng, rngArg, ctx->context, ctx->contextLen, signature, digestType);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 24 and 25, slh_verify(M, SIG, ctx, PK) or hash_slh_verify(M, SIG, ctx, PH, PK) */
MOC_EXTERN MSTATUS SLHDSA_verifyMessage(SLHDSACtx *ctx, uint8_t *message, size_t messageLen, uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || message == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->pubKey == NULL)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = verify(ctx, message, messageLen, ctx->context, ctx->contextLen, signature, SLHDSA_DIGEST_TYPE_ERR);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

MOC_EXTERN MSTATUS SLHDSA_verifyDigest(SLHDSACtx *ctx, uint8_t *digest, size_t digestLen, SLHDSADigestType digestType,
                                      uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || digest == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->pubKey == NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (digestType <= SLHDSA_DIGEST_TYPE_ERR || digestType > SLHDSA_DIGEST_TYPE_SHAKE128)
        goto exit;

    status = ERR_CRYPTO_BAD_HASH;
    if (isSecureDigestType(ctx, digestType) != true)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = verify(ctx, digest, digestLen, ctx->context, ctx->contextLen, signature, digestType);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_cloneCtx(SLHDSACtx *ctx, SLHDSACtx *newCtx)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (ctx == NULL || newCtx == NULL)
        goto exit;

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    moc_memcpy(newCtx, ctx, sizeof(SLHDSACtx));
    newCtx->privKey = NULL;
    newCtx->pubKey = NULL;
    newCtx->context = NULL;

    /* and copy key buffers if present */
    if (ctx->pubKey != NULL)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&newCtx->pubKey, ctx->pubKeyLen, (void *)ctx->pubKey, ctx->pubKeyLen);
        if (OK != status)
            goto exit;
        newCtx->pubKeyLen = ctx->pubKeyLen;
    }

    if (ctx->privKey != NULL)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&newCtx->privKey, ctx->privKeyLen, (void *)ctx->privKey, ctx->privKeyLen);
        if (OK != status)
            goto exit;
        newCtx->privKeyLen = ctx->privKeyLen;
    }
    /* copy context if present */
    if (ctx->context != NULL)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&newCtx->context, ctx->contextLen, (void *)ctx->context, ctx->contextLen);
        if (OK != status)
            goto exit;
        newCtx->contextLen = ctx->contextLen;
    }

exit:
    if (status != OK) {
        SLHDSA_destroyCtx(newCtx);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN bool SLHDSA_verifyKeyPair(SLHDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    uint8_t test_priv[4 * SLHDSA_MAX_N] = {0}; /* big enough for all sizes n */
    uint8_t n = 0;
    bool    valid = false;

    /* Special sanity check */
    /* we must have both keys */
    if (NULL == ctx || NULL == ctx->pubKey || NULL == ctx->privKey)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SLHDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SLHDSA,ctx->type);

    /* this call will validate the length of both keys among other things */
    status = validateCtx(ctx);
    if (OK != status) 
        goto exit;

    n = ctx->params.n;

    /* validate the pk root actually goes with the other seeds, copy first 3 seeds */
    moc_memcpy(test_priv, ctx->privKey, 3 * n);

    /* and create a new pk.root, placed after the other 3 seeds */
    status = SLHDSA_keygen_internal(MOC_HASH(ctx->hwAccelCtx) SLHDSA_getOldCtx(ctx->type), test_priv);
    if (OK != status)
        goto exit;

    /* validate the pk.root in the private key is correct, and validate the public key matches too */
    if (0 == (moc_memcmp(test_priv + 3 * n, ctx->privKey + 3 * n, n) | moc_memcmp(ctx->pubKey, ctx->privKey + 2 * n, 2 * n)))
        valid = true;

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SLHDSA,ctx->type);
    return valid;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_destroyCtx(SLHDSACtx *ctx)
{
    (void) validateCtx(ctx);

    moc_memset_free(&ctx->context, ctx->contextLen);
    moc_memset_free(&ctx->pubKey, ctx->pubKeyLen);
    moc_memset_free(&ctx->privKey, ctx->privKeyLen);

    moc_memset(ctx, 0, sizeof(*ctx));

    return OK;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/pqc/slhdsa_priv.h"

static ubyte4 SLHDSA_getN(const SlhdsaCtx *pCtx)
{
    return pCtx->n;
}

static void triggerSLHDSAFail()
{
    slhdsa_fail = 1;
}

static FIPS_entry_fct slhdsa_table[] = {
    { SLHDSA_KEYGEN_INTERNAL_F_ID, (s_fct*)SLHDSA_keygen_internal },
    { SLHDSA_SIGN_INTERNAL_F_ID,   (s_fct*)SLHDSA_sign_internal },
    { SLHDSA_VERIFY_INTERNAL_F_ID, (s_fct*)SLHDSA_verify_internal },
    { SLHDSA_GET_OLD_CTX_F_ID,     (s_fct*)SLHDSA_getOldCtx },
    { SLHDSA_GET_OLD_N_F_ID,       (s_fct*)SLHDSA_getN },
    { SLHDSA_TRIGGER_FAIL_F_ID,    (s_fct*)triggerSLHDSAFail },
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* SLHDSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return slhdsa_table;

    return NULL;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* defined(__ENABLE_DIGICERT_PQC_SIG__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__) */
