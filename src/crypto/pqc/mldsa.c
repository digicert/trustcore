/*
 * mldsa.c
 *
 * MLDSA SIG methods.
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

/* Comments based on FIPS-204
   https://doi.org/10.6028/NIST.FIPS.204  */

#include <assert.h>

#include "../../common/moptions.h"

#if defined(__ENABLE_DIGICERT_PQC_SIG__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__)

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../common/debug_console.h"

#include "../../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#endif
#include "../../crypto/sha3.h"
#include "../../crypto/pqc/mldsa.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#endif

#if (-1 & 3) != 3
#error MLDSA build must be for platforms supporting 2s compliment
#endif

#define MLDSA_TAG               0x4d4c4453   /* "MLDS" */

#define MLDSA_N                        256   /* rank of the polynomial ring */
#define MLDSA_Q                    8380417   /* prime field size, 2^23 - 2^13 + 1 */
#define MLDSA_Q_MINUS1_OVER2       4190208
#define MLDSA_D                         13   /* power of 2 dividing Q - 1, number of dropped bits from T */
#define MLDSA_T_KEPT_BITS               10   /* number of bits kept in T */

#define MLDSA_QINV                58728449   /*  Q^-1 mod 2^32 */
#define MLDSA_256_INV                41978   /*  Augmented inverse of 256 with R^2 factor, (256^-1) * (R^2) mod Q */

#define MLDSA_ETA_2                      2
#define MLDSA_ETA_4                      4
#define MLDSA_44_ALPHA              190464   /* 2 * gamma2, ie 2 * (Q-1)/88 */
#define MLDSA_65_OR_87_ALPHA        523776   /* 2 * (Q-1)/32 */
#define MLDSA_LAMBDA_CONV                8   /* lambda/4 is 8 * K for each mode, no need to store lambda */

/*      MLDSA_SEED_LEN                  32   in header for use by serilalization code */
#define MLDSA_RHO_LEN                   32
#define MLDSA_K_LEN                     32
#define MLDSA_RHOPRIME_LEN              64
#define MLDSA_TR_LEN                    64
#define MLDSA_MU_LEN                    64
#define MLDSA_RND_LEN                   32
#define MLDSA_MAX_CONTEXT_LEN          255
#define MLDSA_NONCE_SUFFIX_LEN           2
#define MLDSA_BITS_PER_BYTE              8
#define MLDSA_OID_LEN                   11
#define MLDSA_SIGN_LOOP_MAX          65529   /* 2 byte ctr has to be less than this, 2^16 - max(L), ie 2^16 - 7. */

#define MLDSA_SHAKE128_RATE            168   /* SHA3 shake 128 rate */
#define MLDSA_SHAKE256_RATE            136   /* SHA3 shake 256 rate */
#define MLDSA_MAX_W1PACKED_LEN        1024   /* N * K * mBitLen / MLDSA_BITS_PER_BYTE (so max is 256 * 8 * 4 / 8) */

#define MLDSA_SAMPLE_VEC_LEN_ETA2      136   /* 256 words needed, so 128 bytes with prob 15/16 of < 15, rounded to shake256 rate multiple */
#define MLDSA_SAMPLE_VEC_LEN_ETA4      272   /* 256 words needed, so 128 bytes with prob 9/16 of < 9, rounded to shake256 rate multiple */
#define MLDSA_SAMPLE_VEC_LEN_GAMMA_17  576   /* 256 words needed, 9 bytes per 4 words, so 9 * 64 */
#define MLDSA_SAMPLE_VEC_LEN_GAMMA_19  640   /* 256 words needed, 5 bytes per 2 words, so 5 * 128 */
#define MLDSA_SAMPLE_POLY_LEN          840   /* 256 words needed, so 768 bytes with (negligible) probability q/2^23 of < q,
                                                rounded up to the nearest multiple of the shake128 rate, ie 168*5 = 840 */

#define MLDSA_H_SHA3_MODE   MOCANA_SHA3_MODE_SHAKE256

#define MLDSA_MASK              0xffffffff

/* ------------------------------------------------------------------- */

typedef struct MLDSAPoly8 {
    int8_t data[MLDSA_N];
} MLDSAPoly8;

typedef struct MLDSAVector8 {
    uint8_t numPolys;
    MLDSAPoly8 *polys;
} MLDSAVector8;

typedef struct MLDSAPoly32 {
    int32_t data[MLDSA_N];
} MLDSAPoly32;

typedef struct MLDSAVector32 {
    uint8_t numPolys;
    MLDSAPoly32 *polys;
} MLDSAVector32;

typedef struct MLDSAMatrix32 {
    uint8_t rows;
    uint8_t cols;
    /* Polynomials are stored in row-major order */
    MLDSAPoly32 *polys;
} MLDSAMatrix32;

typedef struct MLDSAsk {
    uint8_t *rho;
    uint8_t *K;
    uint8_t *tr;
    MLDSAVector32 *s1;
    MLDSAVector32 *s2;
    MLDSAVector32 *t0;
} MLDSAsk;

static const MLDSAParams mldsa44Params =
{
    .k = 4,
    .l = 4,
    .beta = 78,
    .gamma1 = (1 << 17),
    .gamma2 = 95232,    /* (Q-1)/88 */
    .eta = 2,
    .tau = 39,
    .omega = 80,
};

static const MLDSAParams mldsa65Params =
{
    .k = 6,
    .l = 5,
    .beta = 196,
    .gamma1 = (1 <<19),
    .gamma2 = 261888,
    .eta = 4,
    .tau = 49,
    .omega = 55,
};

static const MLDSAParams mldsa87Params =
{
    .k = 8,
    .l = 7,
    .beta = 120,
    .gamma1 = (1 << 19),
    .gamma2 = 261888,
    .eta = 2,
    .tau = 60,
    .omega = 75,
};

/* ------------------------------------------------------------------- */

/* OID's for pre-hash modes */
#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
static const ubyte gpSha256Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}; /* 2 16 840 1 101 3 4 2 1 */
static const ubyte gpSha512Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}; /* 2 16 840 1 101 3 4 2 3 */
static const ubyte gpShake128Oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b}; /* 2 16 840 1 101 3 4 2 11 */
#endif

/* ------------------------------------------------------------------- */

/*
   Appendix B, zetas array, except we also Mongtomery augment them.
   gZeta[i] = (zeta ^ brv[i]) * R mod Q
   where zeta = 1753 is a primitive 512-th root of 1.
   brv[i] is the 8 bit reveral of i,
   R is the montgomery constant 2^32 mod Q
   and Q is the MLDSA prime 8380417.
   Remember values are stored signed between -(Q-1)/2 and (Q+1)/2. */
static const sbyte4 gZeta[256] =
{
    -4186625,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
     1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
     2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
     2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
      811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
     3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
     -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
    -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
      189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
     1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
     2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
      266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
      900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
     -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
      342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
     2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
     -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
     -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
    -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
     -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int mldsa_fail = 0;

FIPS_TESTLOG_IMPORT;

/*------------------------------------------------------------------*/

/* prototype */
MOC_EXTERN MSTATUS
MLDSA_generateKey_FIPS_consistency_test(MLDSACtx* pCtx, RNGFun rng, void *rngArg);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

static size_t getGammaBitLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 18;
        case MLDSA_TYPE_65:
            return 20;
        case MLDSA_TYPE_87:
            return 20;
        default:
            return 0;
    }
}

static size_t getGammaSampleLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return MLDSA_SAMPLE_VEC_LEN_GAMMA_17;
        case MLDSA_TYPE_65:
            return MLDSA_SAMPLE_VEC_LEN_GAMMA_19;
        case MLDSA_TYPE_87:
            return MLDSA_SAMPLE_VEC_LEN_GAMMA_19;
        default:
            return 0;
    }
}

/* Sizes from Table 2. */
static size_t getPrivKeyLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 2560;
        case MLDSA_TYPE_65:
            return 4032;
        case MLDSA_TYPE_87:
            return 4896;
        default:
            return 0;
    }
}

/* Sizes from Table 2. */
static size_t getPubKeyLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 1312;
        case MLDSA_TYPE_65:
            return 1952;
        case MLDSA_TYPE_87:
            return 2592;
        default:
            return 0;
    }
}

/* Sizes from Table 2. */
static size_t getSigLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 2420;
        case MLDSA_TYPE_65:
            return 3309;
        case MLDSA_TYPE_87:
            return 4627;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */
static void hInit(MLDSACtx *ctx, SHA3_CTX *sha3Ctx)
{
    (void) SHA3_initDigest(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, MOCANA_SHA3_MODE_SHAKE256);
}

static void hUpdate(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *msg, size_t len)
{
    (void) SHA3_updateDigest(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, msg, len);
}

static void hFinal(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *digest, size_t len)
{
    (void) SHA3_finalDigest(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, digest, len);
}

static void freeMLDSAVector8(MLDSAVector8 *vec)
{
    moc_memset_free((ubyte**)&vec->polys, vec->numPolys * sizeof(MLDSAPoly8));
    moc_free((void**)&vec);
}

static void freeMLDSAVector32(MLDSAVector32 *vec)
{
    moc_memset_free((ubyte**)&vec->polys, vec->numPolys * sizeof(MLDSAPoly32));
    moc_free((void**)&vec);
}

static void freeMLDSAMatrix32(MLDSAMatrix32 *mat)
{
    moc_memset_free((ubyte**)&mat->polys, mat->rows * mat->cols * sizeof(MLDSAPoly32));
    moc_free((void**)&mat);
}

static void freeMLDSAsk(MLDSAsk *sk)
{
    freeMLDSAVector32(sk->t0);
    freeMLDSAVector32(sk->s2);
    freeMLDSAVector32(sk->s1);
    moc_free((void**)&sk);
}

static MSTATUS allocMLDSAVector8(uint8_t numPolys, MLDSAVector8 **vec)
{
    MSTATUS status = DIGI_MALLOC((void**)vec, sizeof(MLDSAVector8));
    if (status != OK) {
        goto exit;
    }

    (*vec)->numPolys = numPolys;
    status = DIGI_MALLOC((void**)&(*vec)->polys, numPolys * sizeof(MLDSAPoly8));
exit:
    return status;
}

static MSTATUS allocMLDSAVector32(uint8_t numPolys, MLDSAVector32 **vec)
{
    MSTATUS status = DIGI_MALLOC((void**)vec, sizeof(MLDSAVector32));
    if (status != OK) {
        goto exit;
    }

    (*vec)->numPolys = numPolys;
    status = DIGI_MALLOC((void**)&(*vec)->polys, numPolys*sizeof(MLDSAPoly32));
exit:
    return status;
}

static MSTATUS allocMLDSAMatrix32(uint8_t rows, uint8_t cols, MLDSAMatrix32 **mat)
{
    MSTATUS status = DIGI_MALLOC((void**)mat, sizeof(MLDSAMatrix32));
    if (status != OK) {
        goto exit;
    }

    status = DIGI_MALLOC((void**)&(*mat)->polys,  rows * cols * sizeof(MLDSAPoly32));
    if (status != OK) {
        goto exit;
    }

    (*mat)->rows = rows;
    (*mat)->cols = cols;

exit:
    return status;
}

static MSTATUS allocMLDSAsk(MLDSAParams *params, MLDSAsk **sk)
{
    MSTATUS status = DIGI_MALLOC((void**)sk, sizeof(MLDSAsk));
    if (status != OK) {
        goto exit;
    }

    status = allocMLDSAVector32(params->l, &(*sk)->s1 );
    if (status != OK) {
        goto exit;
    }

    status = allocMLDSAVector32(params->k, &(*sk)->s2);
    if (status != OK) {
        goto exit;
    }

    status = allocMLDSAVector32(params->k, &(*sk)->t0);

exit:
    if (status != OK) {
        freeMLDSAsk(*sk);
    }

    return status;
}

static void freeKeyGenMemory(MLDSAsk *sk, MLDSAMatrix32 *aHat, MLDSAVector32 *t)
{
    freeMLDSAVector32(t);
    freeMLDSAMatrix32(aHat);
    freeMLDSAsk(sk);
}

static MSTATUS allocKeyGenMemory(MLDSAParams *params, MLDSAsk **sk, MLDSAMatrix32 **aHat, MLDSAVector32 **t)
{
    MSTATUS status = allocMLDSAsk(params, sk);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAMatrix32(params->k, params->l, aHat);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->k, t);
    if (status != OK) {
        return status;
    }

    return OK;
}

static void freeSignMemory(MLDSAsk **sk, MLDSAMatrix32 **aHat, MLDSAVector32 **y, MLDSAVector32 **yHat, MLDSAVector32 **w,
                               MLDSAVector32 **w1, MLDSAVector8 **h, MLDSAPoly32 **cHat)
{
    moc_memset_free((ubyte**)cHat, sizeof(MLDSAPoly32));
    freeMLDSAVector8(*h);
    freeMLDSAVector32(*w1);
    freeMLDSAVector32(*w);
    freeMLDSAVector32(*yHat);
    freeMLDSAVector32(*y);
    freeMLDSAMatrix32(*aHat);
    freeMLDSAsk(*sk);
}

static MSTATUS allocSignMemory(MLDSAParams *params, MLDSAsk **sk, MLDSAMatrix32 **aHat, MLDSAVector32 **y, MLDSAVector32 **yHat, MLDSAVector32 **w,
                               MLDSAVector32 **w1, MLDSAVector8 **h, MLDSAPoly32 **cHat)
{
    MSTATUS status = allocMLDSAsk(params, sk);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAMatrix32(params->k, params->l, aHat);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->l, y);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->l, yHat);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->k, w);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->k, w1);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector8(params->k, h);
    if (status != OK) {
        return status;
    }

    status = DIGI_MALLOC((void**)cHat, sizeof(MLDSAPoly32));
    if (OK != status)
        return status;

    return OK;
}

static void freeVerifyMemory(MLDSAMatrix32 *aHat, MLDSAVector32 *z, MLDSAVector32 *w, MLDSAVector32 *t1, MLDSAVector8 *h)
{
    freeMLDSAVector8(h);
    freeMLDSAVector32(t1);
    freeMLDSAVector32(w);
    freeMLDSAVector32(z);
    freeMLDSAMatrix32(aHat);
}

static MSTATUS allocVerifyMemory(MLDSAParams *params, MLDSAMatrix32 **aHat, MLDSAVector32 **z, MLDSAVector32 **w, MLDSAVector32 **t1, MLDSAVector8 **h)
{
    MSTATUS status = allocMLDSAMatrix32(params->k, params->l, aHat);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->l, z);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->k, w);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector32(params->k, t1);
    if (status != OK) {
        return status;
    }

    status = allocMLDSAVector8(params->k, h);
    if (status != OK) {
        return status;
    }

    return OK;
}

/* ------------------------------------------------------------------- */

/* Algorithm by number are generally from 49 to 1 but not ordered
   precisely so static methods can be given before they are used */

/* Appendix A, Algorithm 49, together with the initial multiplication step.
   factor of R = 2^32 will be divided out  */
static inline int32_t montMultiply(int32_t x, int32_t y)
{
#if __DIGICERT_MAX_INT__ == 64
    int64_t coeff = ((int64_t) x) * ((int64_t) y);
    /* Montgomery reduction, mod 2^32 and multiply by Q^-1 */
    int32_t temp = (int32_t) (((int64_t) ((int32_t) coeff)) * MLDSA_QINV);
    /* Get the remainder, divide by 2^32 */
    return (int32_t) ((coeff - ((int64_t) temp) * MLDSA_Q) >> 32);
#else
    ubyte4 xlo;
    ubyte4 xhi;
    ubyte4 ylo;
    ubyte4 yhi;
    ubyte4 inner;
    ubyte4 prodhi;
    ubyte4 prodlo;

    sbyte4 sign;
    sbyte4 mask;

    sbyte4 hisub;
    sbyte4 losub;

    /* first make x and y positive, store for now in xlo and ylo */

    mask = (x >> 31); /* mask is 0 or all f's, must be on 2s compliment system */
    xlo = (ubyte4) ((mask ^ x) + (mask & 0x01)); /* either no op or sign change */
    sign = (mask ^ 0x01) + (mask & 0x01); /* keep track of sign */

    mask = (y >> 31);
    ylo = (ubyte4) ((mask ^ y) + (mask & 0x01));
    sign *= ((mask ^ 0x01) + (mask & 0x01));

    /* now get the low 16 bits and high 16 bits */
    xhi = xlo >> 16;
    yhi = ylo >> 16;
    xlo = xlo & 0xffff;
    ylo = ylo & 0xffff;

    /* take the product */
    inner = xlo * yhi + xhi * ylo;
    prodhi = (inner >> 16) + xhi * yhi;
    inner = (inner & 0xffff) << 16;

    prodlo = inner + xlo * ylo;

    /* was there a carry?
       constant time compare prodlo and inner */
    mask = (((prodlo >> 16) ^ (inner >> 16)) - 1) >> 16; /* mask is f's if high 16 bits are equal, 0 otherwise  */
    hisub = (sbyte4) (prodlo >> 16) - (sbyte4) (inner >> 16);
    losub = (sbyte4) (prodlo & 0xffff) - (sbyte4) (inner & 0xffff);

    mask = (hisub >> 31) | (mask & (losub >> 31)); /* mask is f's if highsub is neg, or high bits eq and low sub is neg*/
    prodhi += (ubyte4) (mask & 0x01);

    /* Montgomery reduction, mod 2^32, ie just take prodlo, and multiply by Q^-1 */

    /* re-use x for the inputs to prodLo * Q^-1, we only need lo byte */
    xhi = prodlo >> 16;
    xlo = prodlo & 0xffff;

    /* reuse y for the result */
    ylo = (((xlo * ((ubyte4) MLDSA_QINV >> 16) + xhi * ((ubyte4) MLDSA_QINV & 0xffff)) & 0xffff) << 16) + xlo * ((ubyte4) MLDSA_QINV & 0xffff);

    /* now multiply by Q, need both bytes, reuse x for the above result, re-use y for new result */
    xhi = ylo >> 16;
    xlo = ylo & 0xffff;

    inner = xlo * ((ubyte4) MLDSA_Q >> 16) + xhi * ((ubyte4) MLDSA_Q & 0xffff);
    yhi = (inner >> 16) + (xhi * ((ubyte4) MLDSA_Q >> 16));
    inner = (inner & 0xffff) << 16;

    ylo = inner + xlo * ((ubyte4) MLDSA_Q & 0xffff);

    /* overflow? same constant time compare as above */
    mask = (((ylo >> 16) ^ (inner >> 16)) - 1) >> 16; /* f's if equal, 0 otherwise  */
    hisub = (sbyte4) (ylo >> 16) - (sbyte4) (inner >> 16);
    losub = (sbyte4) (ylo & 0xffff) - (sbyte4) (inner & 0xffff);

    mask = (hisub >> 31) | (mask & (losub >> 31));
    yhi += (ubyte4) (mask & 0x01);

    /* subtract prod - y, just need high byte, but was there a borrow? */
    mask = (((prodlo >> 16) ^ (ylo >> 16)) - 1) >> 16; /* f's if equal, 0 otherwise  */
    hisub = (sbyte4) (prodlo >> 16) - (sbyte4) (ylo >> 16);
    losub = (sbyte4) (prodlo & 0xffff) - (sbyte4) (ylo & 0xffff);

    mask = (hisub >> 31) | (mask & (losub >> 31));
    yhi += (ubyte4) (mask & 0x01);

    /* high byte of prodhi and yhi. We know they are at most 16 bits so now no worry
       about overflow when casting to a sbyte4. No constant time compare needed */
    return sign * ((sbyte4) prodhi - (sbyte4) yhi);
#endif
}

/* ------------------------------------------------------------------- */

/* Algorithm 41, NTT(w), w converted to w^hat in place

We compute the Cooley-Tukey Bufferfly (CT)
CT_i: (a, b) |-> (a + zeta^i b, a - zeta^i b)   modulo q
*/
static void ntt(MLDSAPoly32 *poly)
{
    uint32_t m = 1;
    int32_t *data = poly->data;

    for (uint32_t len = MLDSA_N/2; len >= 1; len /= 2)
    {
        for (uint32_t start = 0; start < MLDSA_N; start += (2 * len), m++)
        {
            for (uint32_t j = start; j < start + len; j++)
            {
                int32_t t = montMultiply(gZeta[m], data[j + len]);
                data[j + len] = data[j] - t;
                data[j] = data[j] + t;
            }
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 42, NTT^-1(w^hat), w^hat converted to w in place

We compute the Gentleman-Sande Butterfly (GS), inverse of the Cooley-Tukey
GS_i: (a, b) |-> ( (a+b)/2, zeta^-i (a-b)/2 )    modulo q

Note that we don't divide a+b and a-b by 2 each time. The result is therefore
2 times too much. We'll correct for this after all calls.*/
static void nttInv(MLDSAPoly32 *poly)
{
    ubyte4 m = 255; /* we don't do initial subtract by 1, so start at 255*/
    int32_t *data = poly->data;

    for (uint32_t len = 1; len < MLDSA_N; len *= 2)
    {
        for (uint32_t start = 0; start < MLDSA_N; start += (2 * len), m--)
        {
            for (uint32_t j = start; j < start + len; j++)
            {
                int32_t t = data[j];
                data[j] = t + data[j + len]; /* Add but no divide 2, account for the 2 factor later */
                data[j + len] = montMultiply(-1 * gZeta[m], t - data[j + len]);
            }
        }
    }

    /* Each level grouping added a factor of 2, 8 groups,
       so multiply by an augmented 256^-1 */
    for(m = 0; m < MLDSA_N; m++)
    {
        data[m] = montMultiply(data[m], MLDSA_256_INV);
    }
}

static void nttVec(MLDSAVector32 *vec)
{
    for (int i = 0; i < vec->numPolys; i++) {
        ntt(&vec->polys[i]);
    }
}

static void nttInvVec(MLDSAVector32 *vec)
{
    for (int i = 0; i < vec->numPolys; i++) {
        nttInv(&vec->polys[i]);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 45, Multiply NTT */
static void multiplyNTT(int32_t *a, int32_t *b, int32_t *r)
{
    for(int i = 0; i < MLDSA_N; i++)
    {
        r[i] = montMultiply(a[i], b[i]);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 46, add vector NTT, inplace pV += pU,
   this method can be used for non-NTT vectors too */
static void addVectors(MLDSAVector32 *a, MLDSAVector32 *r)
{
    for (int i = 0; i < a->numPolys; i++) {
        int32_t *aData = a->polys[i].data;
        int32_t *rData = r->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            rData[j] += aData[j];
        }
    }
}

/* Done in place. r -= a */
static void subVectors(MLDSAVector32 *a, MLDSAVector32 *r)
{
    for (int i = 0; i < a->numPolys; i++) {
        int32_t *aData = a->polys[i].data;
        int32_t *rData = r->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            rData[j] -= aData[j];
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 47, Scalar vector multiplication in NTT domain,
   with conversion out of NTT domain added here for convenience.
   pC is a single ring element
   pV is a dimension l vector and so is the output pW
*/
static void mulPolyVec(MLDSAPoly32 *poly, MLDSAVector32 *vec, MLDSAVector32 *r)
{
    int32_t *a = poly->data;
    for (int i = 0; i < vec->numPolys; i++) {
        int32_t *b = vec->polys[i].data;
        int32_t *rData = r->polys[i].data;
        multiplyNTT(a, b, rData);
    }
}

/* ------------------------------------------------------------------- */

static void mulAccumNTT(int32_t *a, int32_t *b, int32_t *r)
{
    for(int i = 0; i < MLDSA_N; i++)
    {
        r[i] += montMultiply(a[i], b[i]);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 48, Matrix vector multiplication (in NTT domain).
   pScratch needs to be a single polynomial, 256 words
   pM is a k by l matrix, pV is l by 1 vector,
   so the result pW is a k by 1 vector */
static void matrixVectorNTT(MLDSAMatrix32 *mat, MLDSAVector32 *vec, MLDSAVector32 *res)
{
    int ind = 0;
    for (int i = 0; i < mat->rows; i++)
    {
        /* There's a way to get rid of this with an initial_mul_accum */
        moc_memset((ubyte *) &res->polys[i], 0x00, MLDSA_N * sizeof(int32_t));
        int32_t *r = res->polys[i].data;
        for (int j = 0; j < mat->cols; j++)
        {
            int32_t *a = mat->polys[ind + j].data;
            int32_t *b = vec->polys[j].data;
            mulAccumNTT(a, b, r);
        }

        ind += mat->cols;
    }
}

/* ------------------------------------------------------------------- */

/* Regular reduction, dividing by Q is approximated by dividing 2^23,
   add (2^23)/2 or 2^22 so result will be rounded to -Q/2 through Q/2,
   This can work on a single ring element by passing in a length of MLDSA_N
   or a vector of ring elements by passing in a multiple of that. */
static void vecReduce(MLDSAVector32 *vec)
{
    for (int i = 0; i < vec->numPolys; i++) {
        int32_t *data = vec->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            data[j] = (data[j] - ((data[j] + 0x400000) >> 23) * MLDSA_Q);
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 35, Power2Round(r) with d = 13.
   High word is returned, low word is set
   Decompose r into r1 * 2^13 + r0
   r1 = Round(r / 2^13) so add (2^13 - 1)/2, ie 0xfff,
   to r to get it rounded to nearest integer. The remainder
   r - (r1 * 2^13) will then be + or - in the correct range. */
static int32_t power2Round(int32_t r, int32_t *pR0)
{
    int32_t r1 = (r + 0xfff) >> MLDSA_D;
    *pR0 = r - (r1 << MLDSA_D);
    return r1;
}

static void power2RoundVec(MLDSAVector32 *t, MLDSAVector32 *t1, MLDSAVector32 *t0)
{
    for (int i = 0; i < t->numPolys; i++) {
        int32_t *tData = t->polys[i].data;
        int32_t *t1Data = t1->polys[i].data;
        int32_t *t0Data = t0->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            /* normalize coeffs of T for power2Round, even though we didn't reduce T,
               the coeffs of S2 are at most 4 bits and cannot additively shift those of
               pAS1 outside of [-Q/2, Q/2] by more than 4 bits, hence are still within
               [-Q-1,Q-1], hence the following line will properly normalize to [0,Q-1] */
            tData[j] += (tData[j] >> 31) & MLDSA_Q;
            t1Data[j] = power2Round(tData[j], &t0Data[j]);
        }
    }
}

/* ------------------------------------------------------------------- */

#ifndef __DISABLE_DIGICERT_PQC_MLDSA_44__

/* Algorithm 36, Decompose(r) for gamma2 = (Q-1)/88 (ie for ML-DSA-44).
   We return the high word and set the low word in pR0.

   Note 2 * gamma2 = 2 * (Q-1)/88 = (2^21 - 2^11)/11 but instead of dividing all
   at once by (2^21 - 2^11) we want to divide by
   as close to a power of 2 as possible. Factor out 2^11 and multiply
   numerator and denominator by 2^10 + 1 = 1025. Then numerator becomes
   1025 * 11 * r (ie 11275 * r) and our denominator is 2^11 * (2^20 - 1). Now division can become
   31 total bit shifts done first in a step of 7 and then 24.
 */
static int32_t MLDSA_decomposeV44(int32_t r, int32_t *pR0)
{
    int32_t r0;
    int32_t r1;

    /* make a positive rep, input r must be in range [-Q-1, Q-1] */
    r += (r >> 31) & MLDSA_Q;

    r1 = (r + 0x7f) >> 7;               /* round up */
    r1 = (r1 * 11275 + 0x800000) >> 24; /* round middle */
    r1 ^= ((43 - r1) >> 31) & r1;       /* biggest possible r1 is 43, make 0 otherwise with no branching,
                                           must be using 2s compliment */
    r0 = r - r1 * MLDSA_44_ALPHA;
    /* make a negative representative if that is closer to 0, must be using 2s compliment */
    r0 -= ((MLDSA_Q_MINUS1_OVER2 - r0) >> 31) & MLDSA_Q;
    *pR0 = r0;

    return r1;
}
#endif

/* ------------------------------------------------------------------- */

#if !defined(__DISABLE_DIGICERT_PQC_MLDSA_65__) || !defined(__DISABLE_DIGICERT_PQC_MLDSA_87__)

/* Algorithm 36, Decompose(r) for gamma2 = (Q-1)/32 (ie for ML-DSA-65 or ML-DSA-87).
   We return the high word and set the low word in pR0.

   Note 2 * gamma2 = 2 * (Q-1)/32 = 2^19 - 2^9 but instead of dividing all at
   once by (2^19 - 2^9) we want to divide by as close to a power of 2 as possible.
   Factor out 2^9 and multiply numerator and denominator by 2^10 + 1 = 1025.
   Then numerator becomes 1025 * r and our denominator is 2^9 * (2^20 - 1).
   Now division can become 29 total bit shifts done first in a step of 7 and then 22.
 */
static int32_t MLDSA_decomposeV65or87(int32_t r, int32_t *pR0)
{
    int32_t r0;
    int32_t r1;

    /* make a positive rep, input r must be in range [-Q-1, Q-1] */
    r += (r >> 31) & MLDSA_Q;

    r1 = (r + 0x7f) >> 7;              /* round up */
    r1 = (r1 * 1025 + 0x200000) >> 22; /* round middle */
    r1 &= 0x0f;  /* biggest possible r1 is 15, make 0 otherwise */

    r0 = r - r1 * MLDSA_65_OR_87_ALPHA;
    /* make a negative representative if that is closer to 0, must be using 2s compliment */
    r0 -= ((MLDSA_Q_MINUS1_OVER2 - r0) >> 31) & MLDSA_Q;
    *pR0 = r0;

    return r1;
}
#endif

/* ------------------------------------------------------------------- */

/* ALgorithm 37, HighBits(r), r must be in range [-Q-1, Q-1] for the decompose call */
static inline int32_t highbits(MLDSACtx *ctx, int32_t r)
{
    int32_t r0;
    return ctx->decompose(r, &r0);
}

static void highBitsVec(MLDSACtx *ctx, MLDSAVector32 *r, MLDSAVector32 *r1)
{
    for (int i = 0; i < r->numPolys; i++) {
        int32_t *rData = r->polys[i].data;
        int32_t *r1Data = r1->polys[i].data;

        /* This can't really be optimized because of the obfuscated function. The function pointer should really be to highBitsVec
         * instead. */
        for (int j = 0; j < MLDSA_N; j++) {
            int32_t r0;
            r1Data[j] = ctx->decompose(rData[j], &r0);
        }
    }
}
/* ------------------------------------------------------------------- */

/* Algorithm 38, LowBits(r), r must be in range [-Q-1, Q-1] for the decompose call */
static void lowBits(MLDSACtx *ctx, MLDSAVector32 *r, MLDSAVector32 *r0)
{
    for (int i = 0; i < r->numPolys; i++) {
        int32_t *rData = r->polys[i].data;
        int32_t *r0Data = r0->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            (void) ctx->decompose(rData[j], r0Data);
            r0Data++;
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 39, MakeHint(z, r) */
static int8_t makeHint(MLDSACtx *ctx, int32_t z, int32_t r)
{
    /* method is only used for a reduced r, and z with a bitlength <= 18.
       even if r + z is not reduced, it will be in the range [-Q/2, Q/2] additively shifted
       by at most 18 bits, so still fits within the [-Q-1, Q-1] range */
    int32_t r1 = highbits(ctx, r);
    int32_t v1 = highbits(ctx, r + z);

    return (int8_t) (r1 != v1);
}

/* ------------------------------------------------------------------- */

/* Algorithm 40, UseHint(h, r), r must be in range [-Q-1, Q-1] for the decompose call */
static inline int32_t useHint(MLDSACtx *ctx, int8_t m, int8_t h, int32_t r)
{
    int32_t r0;
    int32_t r1;

    r1 = ctx->decompose(r, &r0);

    if (h == 1) {
        /* m = (q-1)/2gamma2, ie 44 or 16,  */
        if (r0 > 0) {
            /* (r1 + 1) mod m */
            r1++;
            r1 -= (((int32_t) m - 1 - r1) >> 31) & ((int32_t) m); /* if r1 went to m then subtract m */
        } else {
            /* (r1 - 1) mod m */
            r1--;
            r1 += (r1 >> 31) & ((int32_t) m); /* if r1 went negarive then add m */
        }
    }

    return r1;
}

static void useHintVec(MLDSACtx *ctx, MLDSAVector8 *h, MLDSAVector32 *w)
{
    uint8_t m = 16;
    if (ctx->type == MLDSA_TYPE_44) {
        m = 44;
    }
    for (int i = 0; i < h->numPolys; i++) {
        int32_t *wData = w->polys[i].data;
        int8_t *hData = h->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            wData[j] = useHint(ctx, m, hData[j], wData[j]);
        }
    }
}

/* ------------------------------------------------------------------- */

#if !defined(__DISABLE_DIGICERT_PQC_MLDSA_44__) || !defined(__DISABLE_DIGICERT_PQC_MLDSA_87__)

/* Algorithm 15, modified version for eta = 2 and working on an entire buffer
   rather than one half byte at a time. We need uniformly random values from the
   set of 5 elements {-2, -1, 0, 1, 2}. We sample 4 bits at a time to get 15
   values 0 to 14 (we throw away 15). Then we mod by 5.  Instead of dividing by 5
   when we want to mod, we multiply by 205/1024 which is close enough
   to 1/5. Then the divide can just be a bit shift.
*/
static void coeffsFromHalfBytesEta2(uint8_t *in, uint32_t inLen, int32_t *out, uint32_t *count)
{
    uint32_t outCtr = *count;
    uint32_t temp1;
    uint32_t temp2;

    while (outCtr < MLDSA_N && inLen > 0) /* stop when we get to N or run out of input */
    {
        temp1 = (uint32_t) (*in & 0x0f);
        temp2 = (uint32_t) (*in >> 4);

        if (temp1 < 15) {
            temp1 = temp1 - ((205 * temp1) >> 10) * 5; /* temp1 mod 5 */
            out[outCtr] = MLDSA_ETA_2 - (int32_t) temp1; /* now make it from {-2 to 2} */
            outCtr++;
        }
        if (temp2 < 15 && outCtr < MLDSA_N)
        {
            temp2 = temp2 - ((205 * temp2) >> 10) * 5;
            out[outCtr] = MLDSA_ETA_2 - (int32_t) temp2;
            outCtr++;
        }
        in++;
        inLen--;
    }

    *count = outCtr;
}
#endif

/* ------------------------------------------------------------------- */

#if !defined(__DISABLE_DIGICERT_PQC_MLDSA_65__)

/* Algorithm 15, modified version for eta = 4 and working on an entire buffer
   rather than one half byte at a time. We need uniformly random values from
   the set of 9 elements {-4, ..., 4} We sample 4 bits at a time to get 9
   values 0 to 8 (throwing away 9 to 15).
*/
static void coeffsFromHalfBytesEta4(uint8_t *in, uint32_t inLen, int32_t *out, uint32_t *count)
{
    uint32_t outCtr = *count;
    uint32_t temp1;
    uint32_t temp2;

    while (outCtr < MLDSA_N && inLen > 0) /* stop when we get to N or run out of input */
    {
        temp1 = (uint32_t) (*in & 0x0f);
        temp2 = (uint32_t) (*in >> 4);

        if (temp1 < 9)
        {
            out[outCtr] = MLDSA_ETA_4 - (int32_t) temp1; /* now make it from {-4 to 4} */
            outCtr++;
        }
        if (temp2 < 9 && outCtr < MLDSA_N)
        {
            out[outCtr] = MLDSA_ETA_4 - (int32_t) temp2;
            outCtr++;
        }
        in++;
        inLen--;
    }

    *count = outCtr;
}
#endif

/* TODO might not matter but this is much slower than it needs to be, we can hardcode all the packing functions.*/
static void simpleBitPackVecShort(MLDSAVector32 *vec, uint8_t bitLen, uint8_t *out)
{
    assert(bitLen <= 8);

    size_t outInd = 0;
    uint8_t bits = bitLen;
    const size_t maxOut = vec->numPolys * MLDSA_N * bitLen / 8;

    for (int i = 0; i < vec->numPolys; i++) {
        uint32_t *data = (uint32_t*)vec->polys[i].data;
        int j = 0;
        while (j < MLDSA_N && outInd < maxOut) {
            out[outInd] = data[j] >> (bitLen - bits);
            while (bits < 8) {
                j++;
                out[outInd] |= (uint8_t) (data[j] << bits);
                bits += bitLen;
            }

            bits -= 8;
            if (0 == bits) {
                bits = bitLen;
                j++;
            }
            outInd++;
        }
    }
}


static void simpleBitPackVecLong(MLDSAVector32 *vec, uint8_t bitLen, uint8_t *out)
{
    assert(bitLen > 8);

    size_t outInd = 0;
    uint8_t bits = 0;
    const size_t maxOut = vec->numPolys * MLDSA_N * bitLen / 8;

    for (int i = 0; i < vec->numPolys; i++) {
        uint32_t *data = (uint32_t*)vec->polys[i].data;
        int j = 0;
        while (j < MLDSA_N && outInd < maxOut) {
            out[outInd] = (uint8_t)(data[j] >> bits);
            if ((bitLen - bits) < 8) {
                j++;
                out[outInd] |= (uint8_t) (data[j] << (bitLen - bits));
                bits = 8 - (bitLen - bits);
            } else {
                bits += 8;
            }
            outInd++;
        }
    }
}

static void simpleBitPackVec(MLDSAVector32 *vec, uint8_t bitLen, uint8_t *out)
{
    if (bitLen <= 8) {
        simpleBitPackVecShort(vec, bitLen, out);
    } else {
        simpleBitPackVecLong(vec, bitLen, out);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 17, BitPack(w, a, b)
   For convenience we pass in the bitLen of b too. In practice a is not needed.
   wLen should be a multiple of MLDSA_N.
   The output byte array pV must have the proper length.
   This is wLen * bitLen / 8 bytes (ie dimension * 32 * bitLen bytes).
*/
static void bitPack(MLDSAVector32 *vec, sbyte4 b, ubyte bitLen, uint8_t *buf)
{
    for (int i = 0; i < vec->numPolys; i++) {
        int32_t *data = vec->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            data[j] = b - data[j];
        }
    }

    simpleBitPackVec(vec, bitLen, buf);
}

/* ------------------------------------------------------------------- */

/* Algorithm 18, SimpleBitUnpack(v, b)
   Instead of passing in b we pass in the bitLen of b. We also pass in wLen
   so we can operate on an entire vector at once. Output words pW
   are in [0, 2^(bitLen) - 1]. The input byte array pV must have the proper
   length. This is wLwn * bitLen / 8 bytes (ie dimension * 32 * bitLen bytes). */
static size_t simpleBitUnpackPoly(const uint8_t *buf, ubyte bitLen, MLDSAPoly32 *poly)
{
    size_t in = 0;
    uint8_t bits = 0;
    uint32_t total = 0; /* we need room for up to 4 bytes for bitLen > 17 */

    uint32_t *data = (uint32_t*)poly->data;
    for (int i = 0; i < MLDSA_N; i++) {
        while( bits < bitLen ) {
            /* Ordering is little endian, so next byte is more significant,
               put it as the new highest order byte */
            total = (total >> 8) | (((uint32_t) buf[in]) << 24);
            in++;
            bits += 8;
        }

        bits -= bitLen;

        data[i] = (total >> (32 - bitLen - bits)) & (MLDSA_MASK >> (32 - bitLen));
    }

    return in;
}

static void simpleBitUnpack(const uint8_t *buf, ubyte bitLen, MLDSAVector32 *vec)
{
    int in = 0;
    uint8_t bits = 0;
    uint32_t total = 0; /* we need room for up to 4 bytes for bitLen > 17 */

    for (int i = 0; i < vec->numPolys; i++) {
        int32_t *data = vec->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            while( bits < bitLen ) {
                /* Ordering is little endian, so next byte is more significant,
                   put it as the new highest order byte */
                total = (total >> 8) | (((uint32_t) buf[in]) << 24);
                in++;
                bits += 8;
            }

            bits -= bitLen;

            data[j] = (total >> (32 - bitLen - bits)) & (MLDSA_MASK >> (32 - bitLen));
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 19, BitUnpack(v, a, b)
   For convenience we pass in the bitLen of b too. In practice a is not needed.
   Output words pW are in [-b-1, b]. The input byte array pV must have the proper
   length. This is wLwn * bitLen / 8 bytes (ie dimension * 32 * bitLen bytes).
*/
static size_t bitUnpackPoly(uint8_t *buf, uint32_t b, uint8_t bitLen, MLDSAPoly32 *poly)
{
    size_t offset = simpleBitUnpackPoly(buf, bitLen, poly);

    int32_t *data = poly->data;
    for (int i = 0; i < MLDSA_N; i++) {
        data[i] = b - data[i];
    }

    return offset;
}

static void bitUnpackVec(uint8_t *buf, uint32_t b, uint8_t bitLen, MLDSAVector32 *vec)
{
    for (int i = 0; i < vec->numPolys; i++) {
        buf += bitUnpackPoly(buf, b, bitLen, &vec->polys[i]);
    }
}


/* ------------------------------------------------------------------- */

/* Algorithm 20, HintBitPack(h) */
static void hintBitPack(MLDSAParams *params, MLDSAVector8 *h, uint8_t *buf)
{
    int index = 0;

    moc_memset(buf, 0x00, params->omega + params->k);

    for (int i = 0; i < h->numPolys; i++) {
        int8_t *data = h->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            if (data[j]) {
                buf[index] = (uint8_t) j;
                index++;
            }
        }

        /* and also store the total thus far after the omaga hints */
        buf[params->omega + i] = (uint8_t) index;
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 21, HintBitUnpack() */
static bool hintBitUnpack(uint8_t omega, uint8_t *y, MLDSAVector8 *h)
{
    bool status = false;
    uint8_t index = 0;
    uint8_t first;

    moc_memset(&h->polys[0], 0x00, h->numPolys * sizeof(MLDSAPoly8));

    for (int i = 0; i < h->numPolys; i++) {
        /* Step 4, validate the number of 1's is in the correct range*/
        if (y[omega + i] < index || y[omega + i] > omega) {
            goto exit;
        }

        first = index;

        while (index < y[omega + i]) {
            if (index > first && y[index - 1] >= y[index]) {
                goto exit;
            }

            h->polys[i].data[y[index]] = 1;
            index++;
        }
    }

    for (int i = index; i < omega; i++) {
        if (y[i] != 0) goto exit;
    }

    status = true;

exit:

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 14, modified version to handle a multiple sets of 3 bytes at once.
   inLen must be a multiple of 3. Each 3 bytes convert to one 23-bit word. */
static void coeffFromThreeBytes(uint8_t *pInBytes, uint32_t inLen, int32_t *pOutWords, uint32_t *pCount)
{
    uint32_t outCtr = *pCount;
    uint32_t coeff = 0;

    while (outCtr < MLDSA_N && inLen >= 3) /* stop when we get to N or run out of input */
    {
        coeff = (ubyte4) (pInBytes[0]) | (((ubyte4) (pInBytes[1])) << 8) | (((ubyte4) (pInBytes[2])) << 16);
        coeff &= 0x7fffff; /* same as subtracting 128 from high byte if it's > 127 */

        if (coeff < (ubyte4) MLDSA_Q)
        {
            pOutWords[outCtr++] = (sbyte4) coeff;
        }
        pInBytes += 3;
        inLen -= 3;
    }

    *pCount = outCtr;
}

/* ------------------------------------------------------------------- */

/* Algorithm 30, RejNTTPoly, we take rho and nonce separately rather
   than one combined 34 byte seed. pRho is 32 bytes, pNonce is 2 bytes (j and then i)
   pAhat needs space for 256 elements
   G is defined as SHAKE128*/
static void rejNTTPoly(MLDSACtx *ctx, SHA3_CTX *pSha3Ctx, uint8_t *rho, uint8_t scratch[MLDSA_SAMPLE_POLY_LEN], MLDSAPoly32 *poly)
{
    uint32_t count = 0;

    (void) SHA3_initDigest(MOC_HASH(ctx->hwAccelCtx) pSha3Ctx, MOCANA_SHA3_MODE_SHAKE128);
    (void) SHA3_updateDigest(MOC_HASH(ctx->hwAccelCtx) pSha3Ctx, rho, MLDSA_SEED_LEN + MLDSA_NONCE_SUFFIX_LEN);
    (void) SHA3_finalDigest(MOC_HASH(ctx->hwAccelCtx) pSha3Ctx, scratch, MLDSA_SAMPLE_POLY_LEN);

    coeffFromThreeBytes(scratch, MLDSA_SAMPLE_POLY_LEN, poly->data, &count);

    while (count < MLDSA_N) {
        (void) SHA3_additionalXOF(MOC_HASH(ctx->hwAccelCtx) pSha3Ctx, scratch, MLDSA_SHAKE128_RATE); /* divisible by 3  */
        coeffFromThreeBytes(scratch, MLDSA_SHAKE128_RATE, poly->data, &count);
    }
}

/* ------------------------------------------------------------------- */

//static void rejBoundedPoly(MOC_HASH(hwAccelDescr hwAccelCtx) const MldsaCtx *pCtx, SHA3_CTX *pSha3Ctx,
//                                 ubyte *pRho, ubyte *pNonceSuffix, sbyte4 *pA)
static void rejBoundedPolyEta2(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint8_t *nonce, uint8_t *scratch, MLDSAPoly32 *poly)
{
    uint32_t count = 0;
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, rho, MLDSA_RHOPRIME_LEN);
    hUpdate(ctx, sha3Ctx, nonce, MLDSA_NONCE_SUFFIX_LEN);
    hFinal(ctx, sha3Ctx, scratch, MLDSA_SAMPLE_VEC_LEN_ETA2);

    coeffsFromHalfBytesEta2(scratch, MLDSA_SAMPLE_VEC_LEN_ETA2, poly->data, &count);

    while (count < MLDSA_N)
    {
        (void) SHA3_additionalXOF(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, scratch, MLDSA_SHAKE256_RATE);
        coeffsFromHalfBytesEta2(scratch, MLDSA_SHAKE256_RATE, poly->data, &count);
    }
}

static void rejBoundedPolyEta4(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint8_t *nonce, uint8_t *scratch, MLDSAPoly32 *poly)
{
    uint32_t count = 0;
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, rho, MLDSA_RHOPRIME_LEN);
    hUpdate(ctx, sha3Ctx, nonce, MLDSA_NONCE_SUFFIX_LEN);
    hFinal(ctx, sha3Ctx, scratch, MLDSA_SAMPLE_VEC_LEN_ETA4);

    coeffsFromHalfBytesEta4(scratch, MLDSA_SAMPLE_VEC_LEN_ETA4, poly->data, &count);

    while (count < MLDSA_N)
    {
        (void) SHA3_additionalXOF(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, scratch, MLDSA_SHAKE256_RATE);
        coeffsFromHalfBytesEta4(scratch, MLDSA_SHAKE256_RATE, poly->data, &count);
    }
}

/* Algorithm 31 rejBoundedPoly(rho)
   pRho is a 64 byte seed, pNonceSuffix is a 2 byte counter
   pA needs space for 256 elements */
static void rejBoundedPoly(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint8_t *nonce, uint8_t *scratch, MLDSAPoly32 *poly)
{
    if (ctx->params.eta == 2) {
        rejBoundedPolyEta2(ctx, sha3Ctx, rho, nonce, scratch, poly);
    } else {
        rejBoundedPolyEta4(ctx, sha3Ctx, rho, nonce, scratch, poly);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 34 expandMask(rho, mu) except we don't loop over 0 to L-1 inside
   this method. This call handles just one ring element at a time so we
   can save both an NTT and non-NTT copy. The caller of this loops 0 to L-1
   and must increase mu + r each iteration. pY needs space for 256 elements
   Ensure that scratch has enough space.
   */
static void expandMask(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint16_t kappa, uint8_t *scratch, MLDSAVector32 *y, MLDSAVector32 *yHat)
{
    uint8_t bitLen = getGammaBitLen(ctx->type);
    size_t sampleLen = getGammaSampleLen(ctx->type);

    for (int i = 0; i < yHat->numPolys; i++)
    {
        MLDSAPoly32 *poly = &yHat->polys[i];

        hInit(ctx, sha3Ctx);
        hUpdate(ctx, sha3Ctx, rho, MLDSA_RHOPRIME_LEN);
        /* Only works little endian */
        hUpdate(ctx, sha3Ctx, (uint8_t*)&kappa, sizeof(kappa));
        hFinal(ctx, sha3Ctx, scratch, sampleLen);

        bitUnpackPoly(scratch, 0x01 << (bitLen - 1), bitLen, poly);

        kappa++;

        int32_t *copy = y->polys[i].data;
        moc_memcpy(copy, poly->data, sizeof(MLDSAPoly32));

        ntt(poly);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 32, ExpandA. pRho is 32 byte seed.
 * Ensure the scratch buffer is at least MLDSA_SAMPLE_POLY_LEN bytres.*/
static void expandA(MLDSACtx *ctx, SHA3_CTX *pSha3Ctx, uint8_t *rho, uint8_t *scratch, MLDSAMatrix32 *aHat)
{
    uint8_t rhoPrime[MLDSA_SEED_LEN + MLDSA_NONCE_SUFFIX_LEN];
    moc_memcpy(rhoPrime, rho, MLDSA_SEED_LEN);

    int ind = 0;
    for (int i = 0; i < aHat->rows; i++)
    {
        for (int j = 0; j < aHat->cols; j++)
        {
            rhoPrime[MLDSA_SEED_LEN] = j;
            rhoPrime[MLDSA_SEED_LEN + 1] = i;

            rejNTTPoly(ctx, pSha3Ctx, rhoPrime, scratch, &aHat->polys[ind]);
            ind++;
        }
    }
}

/* Algorithm 33, expandS, computes two vectors s1 and s2 using RejBoundedPoly.
   Since we use s1 and s2 at different times, and can re-use memory, we
   don't have a single expandS method and instead call RejBoundedPoly directly
   when s1 and then later when s2 is needed.
*/
static void expandS(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint8_t *scratch, MLDSAsk *sk)
{
    uint8_t nonce[2] = {0};

    MLDSAVector32 *s1 = sk->s1;
    for (int i = 0; i < s1->numPolys; i++) {
        rejBoundedPoly(ctx, sha3Ctx, rho, nonce, scratch, &s1->polys[i]);
        nonce[0]++;
    }

    MLDSAVector32 *s2 = sk->s2;
    for (int i = 0; i < s2->numPolys; i++) {
        rejBoundedPoly(ctx, sha3Ctx, rho, nonce, scratch, &s2->polys[i]);
        nonce[0]++;
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 29, SampleInBall(rho) */
static void sampleInBall(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *rho, uint32_t rhoLen, uint32_t tau, MLDSAPoly32 *c)
{
    uint8_t buf[MLDSA_SHAKE256_RATE];
    size_t bufPos = 0;
#if __DIGICERT_MAX_INT__ == 64
    uint64_t signs = 0ULL;
#else
    ubyte8 signs = {0};
#endif

    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, rho, rhoLen);
    hFinal(ctx, sha3Ctx, buf, sizeof(buf));

    /* Step 4, Use the first 8 bytes, 64 bits as entropy for the signs */
#if __DIGICERT_MAX_INT__ == 64
    for (int i = 0; i < 8; i++)
    {
        signs |= ((uint64_t) buf[i]) << (8*i);
    }
#else
    for (int i = 0; i < 4; i++)
    {
        signs.lower32 |= ((ubyte4) buf[i]) << (8*i);
    }
    for (int i = 0; i < 4; i++)
    {
        signs.upper32 |= ((ubyte4) buf[i+4]) << (8*i);
    }
#endif

    bufPos += 8;

    /* Initialize all coeffs to 0 */
    int32_t *data = c->data;
    moc_memset((ubyte *) data, 0x00, MLDSA_N * sizeof(int32_t));

    /* Step 6, each iteration will either set a new random index j
       to 1 or -1, or will copy a previously set index j to one
       of the last tau indices */
    int j = 0;
    for (int i = MLDSA_N - tau; i < MLDSA_N; i++) {
        /* Step 8 while j > i*/
        do {
            /* get a random index j <= i */

            /* first make sure we didn't run out of bytes */
            if (bufPos >= MLDSA_SHAKE256_RATE) {
                /* ok to not check return code, only sanity checks are done */
                (void) SHA3_additionalXOF(MOC_HASH(ctx->hwAccelCtx) sha3Ctx, buf, MLDSA_SHAKE256_RATE);
                bufPos = 0;
            }

            j = buf[bufPos];
            bufPos++;
        }
        while (j > i); /* keep looking until we get <= i */

        /* Step 11. ci = cj */
        data[i] = data[j];

        /* Step 12. cj = (-1) ^ h[i + tau - 256] */
#if __DIGICERT_MAX_INT__ == 64
        data[j] = 1 - 2 * (signs & 0x1);
        signs >>= 1;
#else
        if (i < MLDSA_N - tau + 32) /* first 32 signs are from signs.lower32 */ {
            data[j] = 1 - 2 * (signs.lower32 & 0x1);
            signs.lower32 >>= 1;
        } else /* signs.upper32 */ {
            data[j] = 1 - 2 * (signs.upper32 & 0x1);
            signs.upper32 >>= 1;
        }
#endif
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 22, pkEncode(rho, t1) */
static void pkEncode(uint8_t *rho, MLDSAVector32 *t1, uint8_t *pk)
{
    moc_memcpy(pk, rho, MLDSA_SEED_LEN);
    pk += MLDSA_SEED_LEN;
    simpleBitPackVec(t1, MLDSA_T_KEPT_BITS, pk);
}

/* ------------------------------------------------------------------- */

static void skEncodeS1S2(MLDSAParams *params, MLDSAVector32 *s1, MLDSAVector32 *s2, uint8_t *sk)
{
    sk += MLDSA_RHO_LEN + MLDSA_RHOPRIME_LEN + MLDSA_K_LEN;

    ubyte bitLen = (2 == params->eta ? 3 : 4); /* {-2,...2} packs as 3 bits, {-4,...,4} packs as 4 bits */

    bitPack(s1, params->eta, bitLen, sk);
    sk += MLDSA_N * s1->numPolys * bitLen / MLDSA_BITS_PER_BYTE;

    bitPack(s2, params->eta, bitLen, sk);

    /* TODO find out if a copy is faster, I think we can use t as a scratch */
    for (int i = 0; i < s1->numPolys; i++) {
        int32_t *data = s1->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            data[j] = params->eta - data[j];
        }
    }
    for (int i = 0; i < s2->numPolys; i++) {
        int32_t *data = s2->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            data[j] = params->eta - data[j];
        }
    }
}

/* Algorithm 24 but s1 and s2 are already encoded */
static void skEncode(MLDSAParams *params, uint8_t *rho, uint8_t *K, uint8_t *tr, MLDSAVector32 *t0, uint8_t *sk)
{
    uint8_t bitLen = (2 == params->eta ? 3 : 4); /* {-2,...2} packs as 3 bits, {-4,...,4} packs as 4 bits */

    moc_memcpy(sk, rho, MLDSA_SEED_LEN);
    sk += MLDSA_SEED_LEN;

    moc_memcpy(sk, K, MLDSA_SEED_LEN);
    sk += MLDSA_SEED_LEN;

    moc_memcpy(sk, tr, MLDSA_TR_LEN);
    sk += MLDSA_TR_LEN;

    /* skip s1 and s2 since they are already encoded. */
    /* packing, bitPack handles the whole vector, no looping needed here */
    sk += MLDSA_N * params->l * bitLen / MLDSA_BITS_PER_BYTE;
    sk += MLDSA_N * params->k * bitLen / MLDSA_BITS_PER_BYTE;

    bitPack(t0, 0x01 << (MLDSA_D - 1), MLDSA_D, sk);
}

/* ------------------------------------------------------------------- */

/* Algorithm 25, skDecode(sk), except we don't copy rho, tr, and K. They can
   be directly used from the key without the time and space of copying. */
static void skDecode(MLDSACtx *ctx, MLDSAsk *sk)
{
    uint8_t *privKey = ctx->privKey;
    sk->rho = privKey;
    privKey += MLDSA_RHO_LEN;
    sk->K = privKey;
    privKey += MLDSA_K_LEN;
    sk->tr = privKey;
    privKey += MLDSA_TR_LEN;

    uint8_t eta = ctx->params.eta;
    uint8_t l = ctx->params.l;
    uint8_t k = ctx->params.k;
    uint8_t bitLen = (2 == eta ? 3 : 4); /* {-2,...2} packs as 3 bits, {-4,...,4} packs as 4 bits */

    bitUnpackVec(privKey, eta, bitLen, sk->s1);
    privKey += MLDSA_N * l * bitLen / MLDSA_BITS_PER_BYTE;

    bitUnpackVec(privKey, eta, bitLen, sk->s2);
    privKey += MLDSA_N * k * bitLen / MLDSA_BITS_PER_BYTE;

    bitUnpackVec(privKey, 0x01 << (MLDSA_D - 1), MLDSA_D, sk->t0);
}

/* ------------------------------------------------------------------- */

/* Algorithm 26, sigEncode(c~, z, h) except c~ is already set, we just do z and h */
//static void sigEncode(const MldsaCtx *pCtx, sbyte4 *pZ, sbyte4 *pH, ubyte *pSigma)
static void sigEncode(MLDSAParams *params, MLDSAVector32 *z, MLDSAVector8 *h, uint8_t *sigma)
{
    /* no looping needed for z, bitPack handles the whole vector */
    uint8_t bitLen = 20;
    if (params->gamma1 == (1 << 17)) {
        bitLen = 18;
    }

    bitPack(z, params->gamma1, bitLen, sigma);
    sigma += MLDSA_N * bitLen * params->l / MLDSA_BITS_PER_BYTE;

    hintBitPack(params, h, sigma);
}

/* ------------------------------------------------------------------- */

/* Algorithm 27, sigDecode(sigma), we don't unpack c~ or h, just z. We can easily
   access c~ when we need it and we want to unpack h later in order to re-use memory.
   But for convenience we do move the pointer of the signature to where h is. */
static bool sigDecode(MLDSAParams *params, uint8_t *sigZ, MLDSAVector32 *z, MLDSAVector8 *h)
{

    uint8_t bitLen = 20;
    if (params->gamma1 == (1 << 17)) {
        bitLen = 18;
    }
    bitUnpackVec(sigZ, params->gamma1, bitLen, z);
    sigZ += MLDSA_N * bitLen * z->numPolys / MLDSA_BITS_PER_BYTE;

    return hintBitUnpack(params->omega, sigZ, h);
}

static void decodeT1(uint8_t *pk, MLDSAVector32 *t1)
{
    simpleBitUnpack(pk + MLDSA_SEED_LEN, MLDSA_T_KEPT_BITS, t1);

    for (int i = 0; i < t1->numPolys; i++) {
        int32_t *data = t1->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            data[j] <<= MLDSA_D;
        }
    }
}

/* ------------------------------------------------------------------- */

/* checks the norm of the polynomial vector input, ie whether
   the absolute value of the coefficients are not < bound
   As usual polyVecLen should be a multiple of 256 */
static bool hasInvalidNorm(MLDSAVector32 *vec, uint32_t bound)
{
    for (int i = 0; i < vec->numPolys; i++) {
        int32_t *data = vec->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            /* take absolute value */
            uint32_t temp = data[j] >> 31; /* shifts sign bit to all 1's or all 0's */
            temp = data[j] - ((temp & 0x2) * data[j]);
            if (temp >= bound) {
                return true; /* OK to short circuit */
            }
        }
    }

    return false;
}

/* ------------------------------------------------------------------- */

static void calcSeeds(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *xi, uint8_t *seeds)
{
    MLDSAParams *params = &ctx->params;
    uint8_t nonce[2] = {params->k, params->l};
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, xi, MLDSA_SEED_LEN);
    hUpdate(ctx, sha3Ctx, nonce, sizeof(nonce));
    hFinal(ctx, sha3Ctx, seeds, 4*MLDSA_SEED_LEN);
}


static void calcTr(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *pk, uint8_t *tr)
{
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, pk, getPubKeyLen(ctx->type));
    hFinal(ctx, sha3Ctx, tr, MLDSA_TR_LEN);
}

static void skToNTT(MLDSAsk *sk)
{
    for (int i = 0; i < sk->s1->numPolys; i++)
    {
        ntt(&sk->s1->polys[i]);
    }
    for (int i = 0; i < sk->s2->numPolys; i++)
    {
        ntt(&sk->s2->polys[i]);
        ntt(&sk->t0->polys[i]);
    }
}

/* This is only needed for testing. */
static void calcMu(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *tr, uint8_t *msg, size_t msgLen, uint8_t *mu)
{
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, tr, MLDSA_TR_LEN);
    hUpdate(ctx, sha3Ctx, msg, msgLen);
    hFinal(ctx, sha3Ctx, mu, MLDSA_MU_LEN);
}

static void calcRhoPrime(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, uint8_t *K, uint8_t *rnd, uint8_t *mu, uint8_t *rhoPrime)
{
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, K, MLDSA_K_LEN);
    hUpdate(ctx, sha3Ctx, rnd, MLDSA_RND_LEN);
    hUpdate(ctx, sha3Ctx, mu, MLDSA_MU_LEN);
    hFinal(ctx, sha3Ctx, rhoPrime, MLDSA_RHOPRIME_LEN);
}

static void calcW(MLDSAMatrix32 *aHat, MLDSAVector32 *yHat, MLDSAVector32 *w)
{
    matrixVectorNTT(aHat, yHat, w);
    vecReduce(w);
    nttInvVec(w);
}

static void calcCTilde(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, MLDSAVector32 *w1, uint8_t *mu,uint8_t *cTilde)
{
    MLDSAParams *params = &ctx->params;

    uint8_t bitLen = 4;
    if (ctx->type == MLDSA_TYPE_44) {
        bitLen = 6;
    }
    simpleBitPackVec(w1, bitLen, cTilde);

    /* TODO should probably be returned by simpleBitPackVec */
    uint32_t w1PackedLen = params->k * MLDSA_N * bitLen / MLDSA_BITS_PER_BYTE;
    hInit(ctx, sha3Ctx);
    hUpdate(ctx, sha3Ctx, mu, MLDSA_MU_LEN);
    hUpdate(ctx, sha3Ctx, cTilde, w1PackedLen);
    uint32_t lambdaOver4 = (uint32_t) params->k * MLDSA_LAMBDA_CONV;
    hFinal(ctx, sha3Ctx, cTilde, lambdaOver4);
}

static void calcCHat(MLDSACtx *ctx, SHA3_CTX *sha3Ctx, MLDSAVector32 *w, MLDSAVector32 *w1, uint8_t *mu, uint8_t *scratch, MLDSAPoly32 *cHat)
{
    MLDSAParams *params = &ctx->params;
    highBitsVec(ctx, w, w1);
    calcCTilde(ctx, sha3Ctx, w1, mu, scratch);
    uint32_t lambdaOver4 = (uint32_t) params->k * MLDSA_LAMBDA_CONV;
    sampleInBall(ctx, sha3Ctx, scratch, lambdaOver4, params->tau, cHat);
    ntt(cHat);
}

/* yHat is stored in z
 * Corresponds to 13 - 23 of Algorithm 7*/
static MSTATUS calcZ(MLDSAParams *params, MLDSAPoly32 *cHat, MLDSAVector32 *s1, MLDSAVector32 *cS1, MLDSAVector32 *z)
{
    /* z is an alias for yHat so this step computes z = yHat + cHat * s1Hat */
    mulPolyVec(cHat, s1, cS1);
    nttInvVec(cS1);
    addVectors(cS1, z);
    vecReduce(z);
    if (hasInvalidNorm(z, params->gamma1 - params->beta)) {
        return ERR_INTERNAL_ERROR;
    }

    return OK;
}

static bool isR0Small(MLDSACtx *ctx, MLDSAPoly32 *cHat, MLDSAVector32 *s2, MLDSAVector32 *w, MLDSAVector32 *cS2)
{
    mulPolyVec(cHat, s2, cS2);
    nttInvVec(cS2);
    subVectors(cS2, w);
    vecReduce(w);
    MLDSAVector32 *r0 = cS2;
    lowBits(ctx, w, r0);

    return !hasInvalidNorm(r0, ctx->params.gamma2 - ctx->params.beta);
}

static MSTATUS makeValidHint(MLDSACtx *ctx, MLDSAVector32 *cT0, MLDSAVector32 *wMinusCS2, MLDSAVector8 *h)
{
    /* Step 26, h = MakeHint( -c * t0  , w - c * s2 + c * t0  )

       MakeHint will have z = - c * t0 and r = w - c * s2 + c * t0;
       what gets compared is highbits of r and z + r, but z + r is
       w - c * s2.

       Note that MakeHint ( c * t0, w - c * s2 ) will compare
       w - c * s2 with w - c * s2 + c * t0, the same thing.
     */
    uint32_t hintCount = 0;

    for (int i = 0; i < h->numPolys; i++) {
        int8_t *hData = h->polys[i].data;
        int32_t *cT0Data = cT0->polys[i].data;
        int32_t *wData = wMinusCS2->polys[i].data;
        for (int j = 0; j < MLDSA_N; j++) {
            hData[j] = makeHint(ctx, cT0Data[j], wData[j]);
            hintCount += hData[j];
        }
    }

    if (hintCount > ctx->params.omega) {
        return ERR_INTERNAL_ERROR;
    }

    return OK;
}

/* Algorithm 6. ML-DSA.KeyGen_internal(). */
static
MSTATUS MLDSA_keyGen_internal(MLDSACtx *ctx, uint8_t *xi, uint8_t *sk, uint8_t *pk)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    SHA3_CTX *sha3Ctx = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = SHA3_allocDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    if (OK != status)
        goto exit;

    uint8_t seeds[4*MLDSA_SEED_LEN];
    calcSeeds(ctx, sha3Ctx, xi, seeds);
    uint8_t *rho = seeds;
    uint8_t *rhoPrime = seeds + MLDSA_RHO_LEN;
    uint8_t *K = &seeds[MLDSA_RHO_LEN + MLDSA_RHOPRIME_LEN];

    MLDSAParams *params = &ctx->params;
    MLDSAsk *mldsaSk;
    MLDSAMatrix32 *aHat;
    MLDSAVector32 *t;
    status = allocKeyGenMemory(params, &mldsaSk, &aHat, &t);
    if (status != OK) {
        goto exit;
    }

    uint8_t *scratch = (uint8_t*)t->polys;
    expandA(ctx, sha3Ctx, rho, scratch, aHat);
    expandS(ctx, sha3Ctx, rhoPrime, scratch, mldsaSk);
    skEncodeS1S2(params, mldsaSk->s1, mldsaSk->s2, sk);
    nttVec(mldsaSk->s1);

    matrixVectorNTT(aHat, mldsaSk->s1, t);
    vecReduce(t);
    nttInvVec(t);
    addVectors(mldsaSk->s2, t);

    MLDSAVector32 *t0 = mldsaSk->t0;
    MLDSAVector32 *t1 = mldsaSk->s2;
    power2RoundVec(t, t1, t0);

    pkEncode(rho, t1, pk);

    uint8_t *tr = rhoPrime;
    calcTr(ctx, sha3Ctx, pk, tr);

    skEncode(params, rho, K, tr, t0, sk);

exit:

    if (OK != status) {
        moc_memset(sk, 0x00, getPrivKeyLen(ctx->type));
    }

    if (NULL != sha3Ctx) {
        (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    }

    freeKeyGenMemory(mldsaSk, aHat, t);
    moc_memset(seeds, 0x00, sizeof(seeds));

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 7, ML-DSA.Sign_internal, except this version can take 
   an exterally computed mu or the msg. It should not take both.
   In fact it takes the externally computed mu in all cases except for testing. */
static
MSTATUS MLDSA_sign_internal(MLDSACtx *ctx, ubyte *pMu, uint8_t *msg, size_t msgLen,
			    uint8_t *rnd, uint8_t *sig)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    MLDSAParams *params = &ctx->params;
    uint32_t lambdaOver4 = (uint32_t) params->k * MLDSA_LAMBDA_CONV;
    SHA3_CTX *sha3Ctx = NULL;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = SHA3_allocDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    if (OK != status)
        goto exit;

    MLDSAsk *sk;
    MLDSAMatrix32 *aHat;
    MLDSAVector32 *y;
    MLDSAVector32 *yHat;
    MLDSAVector32 *w1;
    MLDSAVector32 *w;
    MLDSAVector8 *h;
    MLDSAPoly32 *cHat;
    status = allocSignMemory(params, &sk, &aHat, &y, &yHat, &w, &w1, &h, &cHat);
    if (status != OK) {
        goto exit;
    }

    uint8_t *scratch = (uint8_t*)yHat->polys;
    uint8_t mu[MLDSA_MU_LEN];
    uint8_t rhoPrime[MLDSA_RHOPRIME_LEN];
    uint16_t kappa = 0;

    skDecode(ctx, sk);
    skToNTT(sk);
    expandA(ctx, sha3Ctx, sk->rho, scratch, aHat);
    if (NULL == pMu)
    {
        calcMu(ctx, sha3Ctx, sk->tr, msg, msgLen, mu);
    }
    else
    {
        (void) DIGI_MEMCPY(mu, pMu, MLDSA_MU_LEN);
    }
    calcRhoPrime(ctx, sha3Ctx, sk->K, rnd, mu, rhoPrime);

    while (kappa  < MLDSA_SIGN_LOOP_MAX)
    {
        scratch = (uint8_t*)w1->polys;
        expandMask(ctx, sha3Ctx, rhoPrime, kappa, scratch, y, yHat);
        kappa += params->l;

        calcW(aHat, yHat, w);

        /* Use the signature as a scratch buffer */
        calcCHat(ctx, sha3Ctx, w, w1, mu, sig, cHat);

        MLDSAVector32 *z = y;
        MLDSAVector32 *cS1 = yHat;
        if (calcZ(params, cHat, sk->s1, cS1, z) != OK) {
            continue;
        }
        MLDSAVector32 *tmp = w1;
        if (!isR0Small(ctx, cHat, sk->s2, w, tmp)) {
            continue;
        }

        MLDSAVector32 *cT0 = w1;
        mulPolyVec(cHat, sk->t0, cT0);
        nttInvVec(cT0);
        if (hasInvalidNorm(cT0, params->gamma2)) {
            continue;
        }

        if (makeValidHint(ctx, cT0, w, h) != OK) {
            continue;
        }

        /* we found a valid signature, first lambda/4 bytes are set */
        sig += lambdaOver4;
        sigEncode(params, z, h, sig);

        goto exit;
    }
    status = ERR_INTERNAL_ERROR;

exit:

    if (OK != status) {
        moc_memset(sig, 0x00, MLDSA_MAX_W1PACKED_LEN);
    }
    if (NULL != sha3Ctx) {
        (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    }

    freeSignMemory(&sk, &aHat, &y, &yHat, &w, &w1, &h, &cHat);
    moc_memset(rhoPrime, 0x00, MLDSA_RHOPRIME_LEN);
    moc_memset(mu, 0x00, MLDSA_MU_LEN);

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 8, ML-DSA.Verify_internal, except this version can take 
   an exterally computed mu or the msg. It should not take both.
   In fact it takes the externally computed mu in all cases except for testing. */
static
MSTATUS MLDSA_verify_internal(MLDSACtx *ctx, ubyte *pMu, uint8_t *msg, size_t msgLen,
			      uint8_t *sig, uint32_t *verifyStatus)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    MLDSAParams *params = &ctx->params;
    uint8_t *pk = ctx->pubKey;
    SHA3_CTX *sha3Ctx = NULL;
    uint32_t vStatus = 0;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    /* allocate one SHA3_CTX that will be re-used each time one is needed */
    status = SHA3_allocDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    if (OK != status)
        goto exit;

    MLDSAMatrix32 *aHat;
    MLDSAVector32 *z;
    MLDSAVector32 *w;
    MLDSAVector32 *t1;
    MLDSAVector8 *h;
    status = allocVerifyMemory(params, &aHat, &z, &w, &t1, &h);
    if (status != OK) {
        goto exit;
    }

    uint32_t cTildeLen = (uint32_t) params->k * MLDSA_LAMBDA_CONV;
    uint8_t *cTilde = sig;
    vStatus |= !sigDecode(params, sig + cTildeLen, z, h);
    /* We do part of Step 13, validate Z, now before Z goes to NTT domain */
    vStatus |= (ubyte4) hasInvalidNorm(z, params->gamma1 - params->beta);
    nttVec(z);

    uint8_t *rho = pk;
    uint8_t *scratch = (uint8_t*)w->polys;
    expandA(ctx, sha3Ctx, rho, scratch, aHat);

    uint8_t tr[MLDSA_TR_LEN];
    uint8_t *mu = tr;
    calcTr(ctx, sha3Ctx, pk, tr);

    if (NULL == pMu)
    {
        calcMu(ctx, sha3Ctx, tr, msg, msgLen, mu);
    }
    else
    {
        (void) DIGI_MEMCPY(mu, pMu, MLDSA_MU_LEN);
    }

    matrixVectorNTT(aHat, z, w);

    MLDSAPoly32 *c = z->polys;
    sampleInBall(ctx, sha3Ctx, sig, cTildeLen, params->tau, c);
    ntt(c);

    decodeT1(pk, t1);
    nttVec(t1);
    mulPolyVec(c, t1, t1);

    subVectors(t1, w);
    vecReduce(w);
    nttInvVec(w);

    useHintVec(ctx, h, w);

    uint8_t *cTildePrime = (uint8_t*)h->polys;
    calcCTilde(ctx, sha3Ctx, w, mu, cTildePrime);

    int differ = 0;
    status = DIGI_CTIME_MATCH(cTilde, cTildePrime, cTildeLen, &differ);
    if (OK != status)
        goto exit;

    vStatus |= (uint32_t) differ;

    *verifyStatus = (!(!vStatus));

exit:

    if (NULL != sha3Ctx) {
        (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    }

    freeVerifyMemory(aHat, z, w, t1, h);
    moc_memset(mu, 0x00, MLDSA_MU_LEN);

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS validateParams(MLDSAType type, MLDSAParams *params)
{
    const MLDSAParams *knownParams = &mldsa44Params;
    if (type == MLDSA_TYPE_65) {
        knownParams = &mldsa65Params;
    } else if (type == MLDSA_TYPE_87){
        knownParams = &mldsa87Params;
    }

    if (moc_memcmp(params, knownParams, sizeof(MLDSAParams)) != OK) {
        return ERR_INVALID_INPUT;
    }

    return OK;
}

static MSTATUS validateCtx(MLDSACtx *ctx)
{
    if (ctx == NULL) {
        return ERR_NULL_POINTER;
    }

    if (ctx->tag != MLDSA_TAG) {
        return ERR_WRONG_CTX_TYPE;
    }

    if (ctx->type <= MLDSA_TYPE_ERR || ctx->type > MLDSA_TYPE_87) {
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

    if (ctx->decompose == NULL) {
        return ERR_INVALID_INPUT;
    }

    return validateParams(ctx->type, &ctx->params);
}

/* ------------------------------------------------------------------- */

/* expands key from the seed to the long form. 
   Make sure ctx->privKeySeed has been set before calling this method */
static MSTATUS expandKey(MLDSACtx *ctx)
{
    /* Ok to be uninitailized data at this point */
    ubyte *sk = NULL;
    size_t privKeyLen = getPrivKeyLen(ctx->type);
    MSTATUS status = DIGI_MALLOC((void **) &sk, privKeyLen);
    if (OK != status)
        goto exit;

    ubyte *pk = NULL;
    size_t pubKeyLen = getPubKeyLen(ctx->type);
    status = DIGI_MALLOC((void **) &pk, pubKeyLen);
    if (OK != status)
        goto exit;

    status = MLDSA_keyGen_internal(ctx, ctx->privKeySeed, sk, pk);
    if (OK != status)
        goto exit;

    /* free any previously existing public key. 
       A previously existing private key can't happen since
       this is only called from generate or setPrivateKey which
       already had checks */
    if (NULL != ctx->pubKey)
    {
        status = DIGI_MEMSET_FREE(&ctx->pubKey, ctx->pubKeyLen);
        if (OK != status)
            goto exit;
    }
    ctx->pubKey = pk;
    ctx->pubKeyLen = pubKeyLen;
    ctx->privKey = sk;
    ctx->privKeyLen = privKeyLen;

exit:
    if (status != OK) {
        moc_memset_free(&pk, pubKeyLen);
        moc_memset_free(&sk, privKeyLen);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_createCtx(MLDSAType type, hwAccelDescr hwAccelCtx, MLDSACtx *ctx)
{
    if (type <= MLDSA_TYPE_ERR || type > MLDSA_TYPE_87) {
        return ERR_INVALID_INPUT;
    }

    if (ctx == NULL) {
        return ERR_NULL_POINTER;
    }

    ctx->tag = MLDSA_TAG;
    ctx->type = type;
    ctx->pubKey = NULL;
    ctx->pubKeyLen = 0;
    ctx->privKey = NULL;
    ctx->privKeyLen = 0;
    ctx->hwAccelCtx = hwAccelCtx;
    ctx->context = NULL;
    ctx->contextLen = 0;

    switch (type) {
        case MLDSA_TYPE_44:
            ctx->params = mldsa44Params;
            ctx->decompose = MLDSA_decomposeV44;
            break;
        case MLDSA_TYPE_65:
            ctx->params = mldsa65Params;
            ctx->decompose = MLDSA_decomposeV65or87;
            break;
        case MLDSA_TYPE_87:
            ctx->params = mldsa87Params;
            ctx->decompose = MLDSA_decomposeV65or87;
            break;
        case MLDSA_TYPE_ERR:
            return ERR_FALSE;
    }

    return OK;
}

/* ------------------------------------------------------------------- */

/* Algorithm 1 ML-DSA,KeyGen() */
MOC_EXTERN MSTATUS MLDSA_generateKeyPair(RNGFun rng, void *rngArg, MLDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (rng == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = validateCtx(ctx);
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (ctx->pubKey != NULL || ctx->privKey != NULL)
        goto exit;

    /* Algorithm 1 Step 1, create the seed xi */
    status = (MSTATUS) rng(rngArg, MLDSA_SEED_LEN, ctx->privKeySeed);
    if (OK != status)
        goto exit;

    status = expandKey(ctx);
    if (OK != status)
    {
        (void) DIGI_MEMSET(ctx->privKeySeed, 0x00, MLDSA_SEED_LEN);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = MLDSA_generateKey_FIPS_consistency_test(ctx, rng, rngArg)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
MOC_EXTERN MSTATUS
MLDSA_generateKey_FIPS_consistency_test(MLDSACtx* pCtx, RNGFun rng, void *rngArg)
{
    MSTATUS status = OK;

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

    /* Create signature (deterministic) */
    status = MLDSA_signMessage(pCtx, msg, msgLen, NULL, rngArg,
			       pSig, sigLen);
    if (OK != status)
	goto exit;

    if ( 1 == mldsa_fail )
    {
        pSig[0] ^= 0xA5;
    }
    mldsa_fail = 0;

    /* Verify signature */
    status = MLDSA_verifyMessage(pCtx, msg, msgLen, pSig, sigLen);
    if (OK != status)
    {
        status = ERR_FIPS_MLDSA_SIGN_VERIFY_FAIL;
        setFIPS_Status(FIPS_ALGO_MLDSA,status);
	goto exit;
    }

    FIPS_TESTLOG(1040, "MLDSA_generateKey_FIPS_consistency_test: GOOD Signature Verify!");

exit:
    DIGI_FREE((void**)&pSig);
    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_setContext(const uint8_t *context, size_t contextSize, MLDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    if (ctx->context != NULL)
    {
        DIGI_FREE((void **)&ctx->context);
        ctx->contextLen = 0;
    }

    if ((context != NULL) && (contextSize > 0))
    {
        status = DIGI_MALLOC_MEMCPY((void **)&ctx->context, contextSize, (void *)context, contextSize);
        if (OK != status)
            goto exit;

        ctx->contextLen = contextSize;
    }
exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_getPublicKeyLen(MLDSACtx *ctx, size_t *publicKeyLen)
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

MOC_EXTERN MSTATUS MLDSA_getPublicKey(MLDSACtx *ctx, uint8_t *publicKey, size_t publicKeyLen)

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

MOC_EXTERN MSTATUS MLDSA_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, MLDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (publicKey == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

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

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_getPrivateKeyLen(MLDSACtx *ctx, size_t *privateKeyLen)
{
    if (ctx == NULL || privateKeyLen == NULL)
        return ERR_NULL_POINTER;

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *privateKeyLen = MLDSA_SEED_LEN;

    return OK;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_getPrivateKey(MLDSACtx *ctx, uint8_t *privateKey, size_t privateKeyLen)
{
    if (ctx == NULL || privateKey == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    /* TODO make this != to have the user explicitly send the correct size. This way they don't get the wrong key by mistake. */
    if (privateKeyLen < MLDSA_SEED_LEN) {
        return ERR_BUFFER_TOO_SMALL;
    }

    return DIGI_MEMCPY(privateKey, ctx->privKeySeed, MLDSA_SEED_LEN);
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, MLDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (privateKey == NULL || ctx == NULL)
	return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_PREVIOUSLY_EXISTING_ITEM;
    if (ctx->privKey != NULL)
        goto exit;

    /* handles both a full expanded key and a seed */
    if (privateKeyLen == getPrivKeyLen(ctx->type))
    {
        status = DIGI_MALLOC_MEMCPY((void **) &ctx->privKey, privateKeyLen, (void *) privateKey, privateKeyLen);
        if (OK != status)
            goto exit;
        
        ctx->privKeyLen = privateKeyLen;
        
        /* we're unable to get the seed */
        (void) DIGI_MEMSET(ctx->privKeySeed, 0x00, MLDSA_SEED_LEN);
    }
    else if (privateKeyLen == MLDSA_SEED_LEN)
    {
        status = DIGI_MEMCPY(ctx->privKeySeed, privateKey, MLDSA_SEED_LEN);
        if (OK != status)
            goto exit;
    
        status = expandKey(ctx);
        if (OK != status)
        {
            (void) DIGI_MEMSET(ctx->privKeySeed, 0x00, MLDSA_SEED_LEN);
        }
    }
    else
    {
        status = ERR_INVALID_INPUT;
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_getSignatureLen(MLDSACtx *ctx, size_t *signatureLen)
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

/* Algorithm 2, ML-DSA.Sign, and Algorithm 4, HashML-DSA.Sign
   with a randomizer. */
MOC_EXTERN MSTATUS MLDSA_signMessage(MLDSACtx *ctx, uint8_t *message, size_t messageLen, RNGFun rng, void *rngArg,
                                     uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4 actSigLen;
    MSTATUS status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    /* input validity checks performed by these calls */
    status = MLDSA_streamingInit(ctx, TRUE, 0, ctx->context, ctx->contextLen);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingUpdate(ctx, message, messageLen);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingSignFinal(ctx, rng, rngArg, signature, signatureLen, &actSigLen);

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__

/* This performs the same steps as MLDSA_streamingInit and MLDSA_streamingUpdate
   except it does not pre-hash the message and instead takes in the digest directly */
static MSTATUS MLDSA_prepareDigest(MLDSACtx *pCtx, ubyte *pDigest, ubyte4 digestLen, MLDSADigestType digestType)
{
    MSTATUS status;
    SHA3_CTX *pSha3Ctx = NULL;
    ubyte *pDataPrefix = NULL;
    ubyte4 dataPrefixLen = 2;

    if (pCtx->context != NULL)
        dataPrefixLen += pCtx->contextLen;

    status = DIGI_MALLOC((void**)&pDataPrefix, dataPrefixLen);
    if (OK != status)
        goto exit;

    /* Prepare '1 || ctxLen || ctx' */
    pDataPrefix[0] = 1;
    pDataPrefix[1] = pCtx->contextLen;
    if (pCtx->context != NULL)
        DIGI_MEMCPY(pDataPrefix+2, pCtx->context, pCtx->contextLen);

    status = SHA3_allocDigest(MOC_HASH(pCtx->hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    if (OK != status)
        goto exit;

    /* H ( tr || M' )
        tr = H(pk, 64)
        M' = 1 || ctxLen || ctx || digest */

    /* get or compute tr */
    if (NULL != pCtx->privKey)
    {
        /* tr is after rho and K in the private key */
        hInit(pCtx, pSha3Ctx);
        hUpdate(pCtx, pSha3Ctx, pCtx->privKey + MLDSA_RHO_LEN + MLDSA_K_LEN, MLDSA_TR_LEN);
    }
    else /* must actually hash the public key, use the sha3Ctx for that first  */
    {
        ubyte pTr[MLDSA_TR_LEN];
        calcTr(pCtx, pSha3Ctx, pCtx->pubKey, pTr);
        hInit(pCtx, pSha3Ctx); /* re-init the allocated sha3 context to start computing outer H */
        hUpdate(pCtx, pSha3Ctx, pTr, MLDSA_TR_LEN);
        (void) DIGI_MEMSET(pTr, 0x00, MLDSA_TR_LEN);
    }

    hUpdate(pCtx, pSha3Ctx, pDataPrefix, dataPrefixLen);

    switch (digestType)
    {
        case MLDSA_DIGEST_TYPE_SHA256:

            hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpSha256Oid, MLDSA_OID_LEN);
            break;

        case MLDSA_DIGEST_TYPE_SHA512:

            hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpSha512Oid, MLDSA_OID_LEN);
            break;

        case MLDSA_DIGEST_TYPE_SHAKE128:

            hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpShake128Oid, MLDSA_OID_LEN);
            break;
        
        default:
            
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    hUpdate(pCtx, pSha3Ctx, pDigest, digestLen);

    /* next is message or hash of message, transfer pointer */
    pCtx->pHCtx = (BulkCtx) pSha3Ctx; pSha3Ctx = NULL;
    pCtx->isExternalMu = TRUE;
    pCtx->initialized = TRUE;

exit:
    if (NULL != pDataPrefix)
    {
        DIGI_FREE((void**)&pDataPrefix);
    }
    if (NULL != pSha3Ctx)
    {
        (void) SHA3_freeDigest(MOC_HASH(pCtx->hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_signDigest(MLDSACtx *ctx, uint8_t *digest, size_t digestLen, MLDSADigestType digestType, RNGFun rng, void *rngArg,
                                    uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 actSigLen = 0;

    /* Special sanity check */
    if (ctx == NULL || digest == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->privKey == NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (digestType <= MLDSA_DIGEST_TYPE_ERR || digestType > MLDSA_DIGEST_TYPE_SHAKE128)
        goto exit;

    /* XXX do we want to add this check to verify? Do we want to verify a mistake that could have been made with a different
     * library?
     */
    status = ERR_CRYPTO_BAD_HASH;
    if (ctx->type >= MLDSA_TYPE_65 && digestType == MLDSA_DIGEST_TYPE_SHA256)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = MLDSA_prepareDigest(ctx, digest, digestLen, digestType);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingSignFinal(ctx, rng, rngArg, signature, signatureLen, &actSigLen);

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}
#endif /* __ENABLE_DIGICERT_PQC_SIG_STREAMING__ */

/* ------------------------------------------------------------------- */

/* Algorithm 3, ML-DSA.Verify, and Algorithm 5, HashML-DSA.Verify */
MOC_EXTERN MSTATUS MLDSA_verifyMessage(MLDSACtx *ctx, uint8_t *message, size_t messageLen, uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4 valid = 1;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    /* input validity checks performed by these calls */
    status = MLDSA_streamingInit(ctx, TRUE, 0, ctx->context, ctx->contextLen);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingUpdate(ctx, message, messageLen);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingVerifyFinal(ctx, signature, signatureLen, &valid);
    if (OK == status && valid)
    {
        status = ERR_CRYPTO_FAILURE;
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
MOC_EXTERN MSTATUS MLDSA_verifyDigest(MLDSACtx *ctx, uint8_t *digest, size_t digestLen, MLDSADigestType digestType,
                                      uint8_t *signature, size_t signatureLen)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4 valid = 1;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || digest == NULL || signature == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->pubKey == NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (digestType <= MLDSA_DIGEST_TYPE_ERR || digestType > MLDSA_DIGEST_TYPE_SHAKE128)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (signatureLen != getSigLen(ctx->type))
        goto exit;

    status = MLDSA_prepareDigest(ctx, digest, digestLen, digestType);
    if (OK != status)
        goto exit;

    status = MLDSA_streamingVerifyFinal(ctx, signature, signatureLen, &valid);
    if (OK == status && valid)
    {
        status = ERR_CRYPTO_FAILURE;
    }   
    
exit:
    
    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return status;
}
#endif

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_streamingInit(MLDSACtx *pCtx, byteBoolean isExternalMu, ubyte digestId, ubyte *pContextStr, ubyte4 ctxStrLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    SHA3_CTX *pSha3Ctx = NULL;
    ubyte pDataPrefix[2] = {0};

    /* Special sanity check */
    if (NULL == pCtx || (NULL == pContextStr && ctxStrLen > 0))
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,pCtx->type);
    
    /* if streaming is disabled, this is just called by one shot API, ie we only allow external MU calculation */
#ifndef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    status = ERR_INVALID_INPUT;
    if (!isExternalMu)
        goto exit;
#endif

    status = validateCtx(pCtx);
    if (OK != status)
        goto exit;
    
    /* sha256 not allowed for ML-DSA-65 or 87 */
    status = ERR_CRYPTO_BAD_HASH;
    if (pCtx->type >= MLDSA_TYPE_65 && ht_sha256 == digestId)
        goto exit;

    /* must have at least one key established */
    status = ERR_KEY;
    if (pCtx->pubKey == NULL && pCtx->privKey == NULL )
        goto exit;

    status = ERR_INVALID_INPUT;
    if (ctxStrLen > MLDSA_MAX_CONTEXT_LEN)
        goto exit;

    status = SHA3_allocDigest(MOC_HASH(pCtx->hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    if (OK != status)
        goto exit;

    /* H ( tr || M' )
       tr = H(pk, 64)
       M' = 0 or 1 || ctxLen || ctx || M or pre-Hash M */

    /* get or compute tr */
    if (NULL != pCtx->privKey)
    {   
        /* tr is after rho and K in the private key */
        hInit(pCtx, pSha3Ctx);
        hUpdate(pCtx, pSha3Ctx, pCtx->privKey + MLDSA_RHO_LEN + MLDSA_K_LEN, MLDSA_TR_LEN);
    }
    else /* must actually hash the public key, use the sha3Ctx for that first  */
    {
        ubyte pTr[MLDSA_TR_LEN];
        calcTr(pCtx, pSha3Ctx, pCtx->pubKey, pTr);
        hInit(pCtx, pSha3Ctx); /* re-init the allocated sha3 context to start computing outer H */
        hUpdate(pCtx, pSha3Ctx, pTr, MLDSA_TR_LEN);
        (void) DIGI_MEMSET(pTr, 0x00, MLDSA_TR_LEN);
    }

    pDataPrefix[0] = (isExternalMu ? 0 : 1);
    pDataPrefix[1] = (ubyte) ctxStrLen;
    hUpdate(pCtx, pSha3Ctx, pDataPrefix, sizeof(pDataPrefix));
    if (ctxStrLen > 0)
    {
        hUpdate(pCtx, pSha3Ctx, pContextStr, ctxStrLen);
    }

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    /* for not external mu, We are doing pre-hash as per FIPS-204, next is the oid, and also create a preHashCtx */
    if (!isExternalMu)
    {
        pCtx->digestId = digestId;
        switch (digestId)
        {
            case ht_sha256:

                hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpSha256Oid, MLDSA_OID_LEN);
                status = SHA256_allocDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit;

                (void) SHA256_initDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA256_CTX *) pCtx->pPreHashCtx);
                break;

            case ht_sha512:

                hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpSha512Oid, MLDSA_OID_LEN);
                status = SHA512_allocDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit;

                (void) SHA512_initDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA512_CTX *) pCtx->pPreHashCtx);
                break;

            case ht_shake128:

                hUpdate(pCtx, pSha3Ctx, (uint8_t *) gpShake128Oid, MLDSA_OID_LEN);
                status = SHA3_allocDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit; 

                (void) SHA3_initDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA3_CTX *) pCtx->pPreHashCtx, MOCANA_SHA3_MODE_SHAKE128);
                break;
            
            default:
                
                status = ERR_INVALID_INPUT;
                goto exit;
        }
    }
#endif

    /* next is message or hash of message, transfer pointer */
    pCtx->pHCtx = (BulkCtx) pSha3Ctx; pSha3Ctx = NULL;
    pCtx->isExternalMu = isExternalMu;
    pCtx->initialized = TRUE;

exit:

    /* pCtx->pPreHashCtx final thing to allocate, no need to clean it up on error */
    if (NULL != pSha3Ctx)
    { 
       (void) SHA3_freeDigest(MOC_HASH(pCtx->hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    }
    pDataPrefix[0] = 0;
    pDataPrefix[1] = 0;

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,pCtx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_streamingUpdate(MLDSACtx *pCtx, ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (NULL == pCtx || (NULL == pData && dataLen))
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,pCtx->type);

    status = ERR_UNINITIALIZED_CONTEXT;
    if (!pCtx->initialized)
        goto exit;

    status = OK;
    if (dataLen > 0)
    {
#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
        if (!pCtx->isExternalMu)   /* update our pre-hash */
        {
            switch(pCtx->digestId)
            {
                case ht_sha256:
                    status = SHA256_updateDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA256_CTX *) pCtx->pPreHashCtx, pData, dataLen);
                    break;
                case ht_sha512:
                    status = SHA512_updateDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA512_CTX *) pCtx->pPreHashCtx, pData, dataLen);
                    break; 
                case ht_shake128:
                    status = SHA3_updateDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA3_CTX *) pCtx->pPreHashCtx, pData, dataLen);
                    break;
                default: /* should not happen if initialized */
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
            }
        }
        else
#endif
        {
            /* For externamMu update our outer H hash directly with the message */
            hUpdate(pCtx, (SHA3_CTX *) pCtx->pHCtx, pData, dataLen);
        }
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,pCtx->type);
    return status;
}

/* ------------------------------------------------------------------- */

/* pResult must have at least 64 bytes of space (SHA512_RESULT_SIZE) */
static MSTATUS MLDSA_finalizeMu(MLDSACtx *pCtx, ubyte *pMu)
{
    MSTATUS status = OK;
    /* iternal method, NULL checks not necc */

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__

    ubyte pPreHash[SHA512_RESULT_SIZE]; /* big enough for all results */
    
    if (!pCtx->isExternalMu) /* finish the pre-hash */
    {
        switch(pCtx->digestId)
        {
            case ht_sha256:

                status = SHA256_finalDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA256_CTX *) pCtx->pPreHashCtx, pPreHash);
                if (OK != status)
                    goto exit;

                /* done with pPreHashCtx, can't be re-used, free now */
                status = SHA256_freeDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit;

                hUpdate(pCtx, (SHA3_CTX *) pCtx->pHCtx, pPreHash, SHA256_RESULT_SIZE);
                break;

            case ht_sha512:

                status = SHA512_finalDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA512_CTX *) pCtx->pPreHashCtx, pPreHash);
                if (OK != status)
                    goto exit;
                
                /* done with pPreHashCtx, can't be re-used, free now */
                status = SHA512_freeDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit;

                hUpdate(pCtx, (SHA3_CTX *) pCtx->pHCtx, pPreHash, SHA512_RESULT_SIZE);
                break;

            case ht_shake128:

                status = SHA3_finalDigest(MOC_HASH(pCtx->hwAccelCtx) (SHA3_CTX *) pCtx->pPreHashCtx, pPreHash, SHAKE128_RESULT_SIZE);
                if (OK != status)
                    goto exit;

                /* done with pPreHashCtx, can't be re-used, free now */
                status = SHA3_freeDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pPreHashCtx);
                if (OK != status)
                    goto exit;

                hUpdate(pCtx, (SHA3_CTX *) pCtx->pHCtx, pPreHash, SHAKE128_RESULT_SIZE);
                break;

            default: /* should not happen if initialized */
                status = ERR_INTERNAL_ERROR;
                goto exit;
        }
    }
#endif

    /* Now we are ready to compute mu */
    hFinal(pCtx, (SHA3_CTX *) pCtx->pHCtx, pMu, MLDSA_MU_LEN);

    /* Done with pCtx->pHCtx, can't be re-done, so free it now */
    status = SHA3_freeDigest(MOC_HASH(pCtx->hwAccelCtx) &pCtx->pHCtx);

exit:

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    (void) DIGI_MEMSET(pPreHash, 0x00, SHA512_RESULT_SIZE);
#endif

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_streamingSignFinal(MLDSACtx *pCtx, RNGFun rngFun, void *pRngFunArg,
                                            ubyte *pSignature, ubyte4 sigBufferLen, ubyte4 *pActualSigLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pRnd[MLDSA_RND_LEN];
    ubyte pMu[MLDSA_MU_LEN];

    /* Special sanity check */
    if (NULL == pCtx || NULL == pActualSigLen)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,pCtx->type);

    status = ERR_UNINITIALIZED_CONTEXT;
    if (!pCtx->initialized || pCtx->privKey == NULL)
        goto exit;

    *pActualSigLen = (ubyte4) getSigLen(pCtx->type);
    
    status = ERR_BUFFER_TOO_SMALL;
    if (NULL == pSignature || sigBufferLen < *pActualSigLen)
        goto exit;

    /* Before further processing make sure we can compute a seed */
    if (NULL != rngFun)
    {    
        status = (MSTATUS) rngFun(pRngFunArg, MLDSA_RND_LEN, pRnd);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* optional deterministic version set rnd to all 0x00 */
        (void) DIGI_MEMSET(pRnd, 0x00, MLDSA_RND_LEN);
    }

    status = MLDSA_finalizeMu(pCtx, pMu);
    if (OK != status)
        goto exit;

    status = MLDSA_sign_internal(pCtx, pMu, NULL, 0, pRnd, pSignature);

exit:

    (void) DIGI_MEMSET(pRnd, 0x00, MLDSA_RND_LEN);
    (void) DIGI_MEMSET(pMu, 0x00, MLDSA_MU_LEN);
    
    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,pCtx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_streamingVerifyFinal(MLDSACtx *pCtx, ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyStatus)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    ubyte pMu[MLDSA_MU_LEN];

    /* Special sanity check */
    if (NULL == pCtx || NULL == pVerifyStatus || NULL == pSignature)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,pCtx->type);

    status = ERR_UNINITIALIZED_CONTEXT;
    if (!pCtx->initialized || pCtx->pubKey == NULL)
        goto exit;

    status = ERR_FALSE;
    if (signatureLen != getSigLen(pCtx->type))
    {
        *pVerifyStatus = 1;
        goto exit;
    }

    status = MLDSA_finalizeMu(pCtx, pMu);
    if (OK != status)
        goto exit;

    status = MLDSA_verify_internal(pCtx, pMu, NULL, 0, pSignature, pVerifyStatus);

exit:

    (void) DIGI_MEMSET(pMu, 0x00, MLDSA_MU_LEN);
    
    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,pCtx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_cloneCtx(MLDSACtx *ctx, MLDSACtx *newCtx)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (ctx == NULL || newCtx == NULL)
        goto exit;

    status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    moc_memcpy(newCtx, ctx, sizeof(MLDSACtx));
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
        MLDSA_destroyCtx(newCtx);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN bool MLDSA_verifyKeyPair(MLDSACtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    bool ret = false;
    SHA3_CTX *sha3Ctx = NULL;
    uint8_t *sk_check = NULL;
    uint8_t *pk_check = NULL;
    uint8_t tr[MLDSA_TR_LEN];

    /* Special sanity check */
    /* we must have both keys */
    if (NULL == ctx || NULL == ctx->pubKey || NULL == ctx->privKey)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLDSA); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLDSA,ctx->type);

    /* this call will validate the length of both keys among other things */
    status = validateCtx(ctx);
    if (OK != status) 
        goto exit;

    /* allocate space for the key we'll check against */
    status = DIGI_MALLOC((void **) &sk_check, ctx->privKeyLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pk_check, ctx->pubKeyLen);
    if (OK != status)
        goto exit;

    status = SHA3_allocDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    if (OK != status)
        goto exit;

    MLDSAParams *params = &ctx->params;
    MLDSAsk *sk;
    MLDSAMatrix32 *aHat;
    MLDSAVector32 *t_check;
    MLDSAVector32 *t0_check;
    MLDSAVector32 *t1_check;

    status = allocKeyGenMemory(params, &sk, &aHat, &t_check);
    if (OK != status)
        goto exit;

    status = allocMLDSAVector32(params->k, &t0_check);
    if (OK != status)
        goto exit;

    status = allocMLDSAVector32(params->k, &t1_check);
    if (OK != status)
        goto exit;

    uint8_t *scratch = (uint8_t*)t_check->polys;

    skDecode(ctx, sk);
    skEncodeS1S2(params, sk->s1, sk->s2, sk_check);
    nttVec(sk->s1);
    expandA(ctx, sha3Ctx, sk->rho, scratch, aHat);
    matrixVectorNTT(aHat, sk->s1, t_check);
    vecReduce(t_check);
    nttInvVec(t_check);
    addVectors(sk->s2, t_check);
    power2RoundVec(t_check, t1_check, t0_check);

    /* repack so we can compare with the original key */
    pkEncode(sk->rho, t1_check, pk_check);
    calcTr(ctx, sha3Ctx, pk_check, tr);
    skEncode(params, sk->rho, sk->K, tr, t0_check, sk_check);

    /* we or the moc_memcmp results as to not leak which key is in invalid */
    if (0 == (moc_memcmp(sk_check, ctx->privKey, ctx->privKeyLen) | moc_memcmp(pk_check, ctx->pubKey, ctx->pubKeyLen)))
    {
        ret = true;
    }

exit:

    if (NULL != sk_check)
    {
        moc_memset_free(&sk_check, ctx->privKeyLen);
    }
    if (NULL != pk_check)
    {
        moc_memset_free(&pk_check, ctx->pubKeyLen);
    }
    freeKeyGenMemory(sk, aHat, t_check);
    freeMLDSAVector32(t0_check);
    freeMLDSAVector32(t1_check);

    if (NULL != sha3Ctx) 
    {
        (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) (BulkCtx *) &sha3Ctx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_MLDSA,ctx->type);
    return ret;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_destroyCtx(MLDSACtx *ctx)
{
    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        goto exit;
    }

    moc_memset_free(&ctx->context, ctx->contextLen);
    moc_memset_free(&ctx->pubKey, ctx->pubKeyLen);
    moc_memset_free(&ctx->privKey, ctx->privKeyLen);

    if (NULL != ctx->pHCtx)
    {
        (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) &ctx->pHCtx);
    }

#ifdef __ENABLE_DIGICERT_PQC_SIG_STREAMING__
    if (NULL != ctx->pPreHashCtx)
    {
        switch(ctx->digestId)
        {
            case ht_sha256:
                (void) SHA256_freeDigest(MOC_HASH(ctx->hwAccelCtx) &ctx->pPreHashCtx);
                break;

            case ht_sha512:
                (void) SHA512_freeDigest(MOC_HASH(ctx->hwAccelCtx) &ctx->pPreHashCtx);
                 break;

            case ht_shake128:
                (void) SHA3_freeDigest(MOC_HASH(ctx->hwAccelCtx) &ctx->pPreHashCtx);
                break;

            default:
                status = ERR_INTERNAL_ERROR;
                goto exit;
        }
    }
#endif

    moc_memset(ctx, 0, sizeof(*ctx));

exit:

    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/pqc/mldsa_priv.h"

static void MLDSA_triggerFail()
{
    mldsa_fail = 1;
}

static FIPS_entry_fct mldsa_table[] = {
    { MLDSA_KEYGEN_INTERNAL_F_ID,  (s_fct*)MLDSA_keyGen_internal },
    { MLDSA_SIGN_INTERNAL_F_ID,    (s_fct*)MLDSA_sign_internal },
    { MLDSA_VERIFY_INTERNAL_F_ID,  (s_fct*)MLDSA_verify_internal },
    { MLDSA_TRIGGER_FAIL_F_ID,     (s_fct*)MLDSA_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* MLDSA_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return mldsa_table;

    return NULL;
}
#endif

#endif /* defined(__ENABLE_DIGICERT_PQC_SIG__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__) */
