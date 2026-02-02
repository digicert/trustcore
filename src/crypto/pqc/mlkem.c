/*
 * mlkem.c
 *
 * ML-KEM methods.
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

/* Comments based on FIPS-203
   https://doi.org/10.6028/NIST.FIPS.203  */

#include "../../common/moptions.h"

#if defined(__ENABLE_DIGICERT_PQC_KEM__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__)

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/random.h"
#include "../../common/debug_console.h"

#include "../../crypto/hw_accel.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/sha3.h"
#include "../../crypto/pqc/mlkem.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#endif

#if (-1 & 3) != 3
#error MLKEM build must be for platforms supporting 2s compliment
#endif

#define MLKEM_TAG               0x4d4c4b45   /* "MLKE" */

#define MLKEM_N                256   /* rank of the polynomial ring */
#define MLKEM_N_BYTES          384   /* 256 12 bit words compresses to 384 bytes */
#define MLKEM_Q               3329   /* prime field size */
#define MLKEM_Q_OVER2         1664
#define MLKEM_RSQ             1353   /*  Montgomery R^2, 2^32 mod Q */
#define MLKEM_QINV          (-3327)  /*  Q^-1 mod 2^16 */
#define MLKEM_BARRET_M       20159   /*  2^26/Q rounded up */
#define MLKEM_128_INV         1441   /*  Augmented inverse of 128 with R^2 factor, (128^-1) * (R^2) mod Q */
#define MLKEM_SEED_LEN          32
#define MLKEM_PREKEY_LEN        64
#define MLKEM_ETA2               2   /* 2 for all modes */
#define MLKEM_SS_LEN            32   /* Shared secret len for all modes */
#define MLKEM_SHAKE128_RATE    168   /* SHA3 shake 128 rate */
#define MLKEM_SAMPLE_POLY_LEN  504   /* 256 words needed, so 384 bytes with probability q/2^12 of < q,
                                        rounded up to the nearest multiple of the shake128 rate, ie 168*3 */
#define MLKEM_MASK          0xffff
#define MLKEM_MASK_24     0xffffff
#define MLKEM_BITS_PER_BYTE      8

/* ------------------------------------------------------------------- */

typedef struct _MlkemCtx {
    ubyte k;           /* dimension */
    ubyte eta1;        /* 3 for ML-KEM-512, 2 otherwise */
    ubyte du;          /* 11 for ML-KEM-1024, 10 otherwise */
    ubyte dv;          /* 5 for ML-KEM-1024, 4 otherwise */
    ubyte4 dkPkeLen;   /* decryption key for pubkey enc scheme, 384 * k bytes */
    ubyte4 ekPkeLen;   /* encryption key for pubkey enc scheme, 384 * k + 32 bytes, also this is total pubLen */
    ubyte4 privLen;    /* dkPkeLen + ekPkeLen + 2 more 32 byte seeds */
    ubyte4 cipherLen;
} MlkemCtx;

typedef struct _MlkemKey {
    ubyte *pKeyBuf;
    MlkemCtx *pCtx;
    byteBoolean isPrivate;

} MlkemKey;

/* The 3 predefined security strengths */
#ifndef __DISABLE_DIGICERT_PQC_MLKEM_512__
static const MlkemCtx gMlkem512 =
{
    .k = 2,
    .eta1 = 3,
    .du = 10,
    .dv = 4,
    .dkPkeLen = 384 * 2,
    .ekPkeLen = 384 * 2 + MLKEM_SEED_LEN,
    .privLen = 384 * 4 + 3 * MLKEM_SEED_LEN,
    .cipherLen = 768
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_MLKEM_768__
static const MlkemCtx gMlkem768 =
{
    .k = 3,
    .eta1 = 2,
    .du = 10,
    .dv = 4,
    .dkPkeLen = 384 * 3,
    .ekPkeLen = 384 * 3 + MLKEM_SEED_LEN,
    .privLen = 384 * 6 + 3 * MLKEM_SEED_LEN,
    .cipherLen = 1088
};
#endif

#ifndef __DISABLE_DIGICERT_PQC_MLKEM_1024__
static const MlkemCtx gMlkem1024 =
{
    .k = 4,
    .eta1 = 2,
    .du = 11,
    .dv = 5,
    .dkPkeLen = 384 * 4,
    .ekPkeLen = 384 * 4 + MLKEM_SEED_LEN,
    .privLen = 384 * 8 + 3 * MLKEM_SEED_LEN,
    .cipherLen = 1568
};
#endif

static const MLKEMParams mlkem512Params =
{
    .k = 2,
    .eta1 = 3,
    .eta2 = 2,
    .du = 10,
    .dv = 4
};

static const MLKEMParams mlkem768Params =
{
    .k = 3,
    .eta1 = 2,
    .eta2 = 2,
    .du = 10,
    .dv = 4
};

static const MLKEMParams mlkem1024Params =
{
    .k = 4,
    .eta1 = 2,
    .eta2 = 2,
    .du = 11,
    .dv = 5
};

/* ------------------------------------------------------------------- */

/* Appendix A, precomputed values,
   except we also Montgomery augment them with a factor or R,
   gZeta[i] = (zeta ^ brv[i]) * R mod Q
   where zeta = 17 is a primitive 256th root of 1.
   brv[i] is the 7 bit reveral of i,
   R is the montgomery constant 2^16 mod Q
   and Q is the MLKEM prime 3329.
   Remember values are stored signed between -(Q-1)/2 and (Q+1)/2.
 */
static const sbyte2 gZeta[128] =
{
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,  -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,  -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,   516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,  -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,   422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119, -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384, -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,  -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int mlkem_fail = 0;

FIPS_TESTLOG_IMPORT;

/*------------------------------------------------------------------*/

/* prototype */
MOC_EXTERN MSTATUS
MLKEM_generateKey_FIPS_consistency_test(MLKEMCtx* pCtx, RNGFun rng, void *rngArg);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*------------------------------------------------------------------*/

/* Takes in 2 buffers, first is always 32 bytes, second buffers length is variable, desiredOutLen also can be given */
static MSTATUS MLKEM_shake256complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pSeed, ubyte *pIn, ubyte4 inLen, ubyte *pOut, ubyte4 desiredOutLen)
{
    MSTATUS status = OK;
    SHA3_CTX *pCtx = NULL;

    status = SHA3_allocDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;

    status = SHA3_initDigest(MOC_HASH(hwAccelCtx) pCtx, MOCANA_SHA3_MODE_SHAKE256);
    if (OK != status)
        goto exit;

    status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) pCtx, pSeed, MLKEM_SEED_LEN);
    if (OK != status)
        goto exit;

    status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) pCtx, pIn, inLen);
    if (OK != status)
        goto exit;

    status = SHA3_finalDigest(MOC_HASH(hwAccelCtx) pCtx, pOut, desiredOutLen);

exit:

    (void) SHA3_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx);

    return status;
}

static MSTATUS mlkem_h(MOC_HASH(hwAccelDescr hwAccelCtx) uint8_t *msg, size_t msgLen, uint8_t *res)
{
    return SHA3_completeDigest(MOC_HASH(hwAccelCtx) MOCANA_SHA3_MODE_SHA3_256, msg, msgLen, res, 32);
}

static MSTATUS mlkem_g(MOC_HASH(hwAccelDescr hwAccelCtx) uint8_t *msg, size_t msgLen, uint8_t *res)
{
    return SHA3_completeDigest(MOC_HASH(hwAccelCtx) MOCANA_SHA3_MODE_SHA3_512, msg, msgLen, res, 32);
}

static MSTATUS mlkem_j(MOC_HASH(hwAccelDescr hwAccelCtx) uint8_t *seed, uint8_t *cipher, size_t cipherLen, uint8_t *res)
{
    return MLKEM_shake256complete(MOC_HASH(hwAccelCtx) seed, cipher, cipherLen, res, MLKEM_SS_LEN);
}
/* ------------------------------------------------------------------- */

/* 32 byte seed, desiredOutLen byte output */
static MSTATUS MLKEM_prf(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pSeed, ubyte counter, ubyte *pOut, ubyte4 desiredOutLen)
{
    ubyte pCounter[1];

    pCounter[0] = counter;
    return MLKEM_shake256complete(MOC_HASH(hwAccelCtx) pSeed, pCounter, 1, pOut, desiredOutLen);
}

/* ------------------------------------------------------------------- */

/* To remain constant time we use Barret reduction, rather than if statement based reduction */
static inline sbyte2 MLKEM_reduceCoeff(sbyte2 coeff)
{
    /* (x * M) / 2^26 rounded up */
    sbyte2 temp = (sbyte2) (((sbyte4) coeff * MLKEM_BARRET_M + (1<<25)) >> 26);
    temp *= MLKEM_Q;
    return (coeff - temp);
}

/* ------------------------------------------------------------------- */

static sbyte2 MLKEM_montMultiply(sbyte2 x, sbyte2 y)
{
    sbyte4 prod = (sbyte4) x * (sbyte4) y;

    /* Montgomery Multiplication, truncate to last 16 bits */
    sbyte2 division = (sbyte2) (prod * MLKEM_QINV);

    /* compute remainder and shift away extra factor of 2^16 */
    return (sbyte2) ((prod - ((sbyte4) division) * MLKEM_Q) >> 16);
}

/* ------------------------------------------------------------------- */

/*
  The following polyVec methods provided for operations on a flat sbyte2 array.
  These can work on a single polynomial ring element by passing in polyVecLen
  of MLKEM_N, or on a vector of ring elements by passing in k * MLKEM_N */
static void MLKEM_polyVecReduce(sbyte2 *pPolyVec, ubyte4 polyVecLen)
{
    ubyte4 i;

    for (i = 0; i < polyVecLen; i++)
    {
        pPolyVec[i] = MLKEM_reduceCoeff(pPolyVec[i]);
    }
}

/* ------------------------------------------------------------------- */

/* Augmentation is multiplication by R^2 and then a reduction */
static void MLKEM_polyVecMontAug(sbyte2 *pPolyVec, ubyte4 polyVecLen)
{
    ubyte4 i;

    for (i = 0; i < polyVecLen; i++)
    {
        pPolyVec[i] = MLKEM_montMultiply(pPolyVec[i], (sbyte2) MLKEM_RSQ);
    }
}

/* ------------------------------------------------------------------- */

/* converts to positive reps in-place */
static void MLKEM_polyVecNormalize(sbyte2 *pPolyVec, ubyte4 polyVecLen)
{
    ubyte4 i;

    for (i = 0; i < polyVecLen; i++)
    {
        /* convert to positive representatives,
            (pPolyVec[i] >> 15) will be 0 or 0xffff based on sign,
            in which case for a negative rep, Q gets added  */
        pPolyVec[i] += (pPolyVec[i] >> 15) & MLKEM_Q;
    }
}

/* ------------------------------------------------------------------- */

/* pResult += pPolyVec */
static void MLKEM_polyVecAdd(sbyte2 *pPolyVec, ubyte4 polyVecLen, sbyte2 *pResult)
{
    ubyte4 i;

    for (i = 0; i < polyVecLen; i++)
    {
        pResult[i] += pPolyVec[i];
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 5, ByteEncode_d(F), for bitlen values of d <= 8
   Packs fLen ubyte2 words to a fLen * d / 8 length byte array.
   In practice fLen is a multiple of MLKEM_N (256) so this
   length is an integer. */
static void MLKEM_byteEncodeS(ubyte d, ubyte2 *pF, ubyte4 fLen, ubyte *pB)
{
    ubyte4 in = 0;
    ubyte bits = d; /* keeps track of bits "to get", start with d */
    ubyte4 out = 0;

    for (; out < fLen * d / 8; out++) /* fLen is divisible by 8 */
    {
        pB[out] = (ubyte) (pF[in] >> (d - bits));
        while (bits < 8)
        {
            in++;
            pB[out] |= (ubyte) (pF[in] << bits);
            bits += d;
        }

        bits -= 8;
        if (0 == bits)
        {
            bits = d;
            in++;
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 5, ByteEncode_d(F), for bitlen values of d > 8.
   Packs fLen ubyte2 words to a fLen * d / 8 length byte array.
   In practice fLen is a multiple of MLKEM_N (256) so this
   length is an integer. */
static void MLKEM_byteEncodeL(ubyte d, ubyte2 *pF, ubyte4 fLen, ubyte *pB)
{
    ubyte4 in = 0;
    ubyte bits = 0; /* keeps track of bits "already got" so far */
    ubyte4 out = 0;

    for (; out < fLen * d / 8; out++) /* fLen is divisible by 8 */
    {
        pB[out] = (ubyte) (pF[in] >> bits);
        if ((d - bits) < 8)
        {
            in++;
            pB[out] |= (ubyte) (pF[in] << (d - bits));
            bits = 8 - (d - bits);
        }
        else
        {
            bits += 8;
        }
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 6 ByteDecode_d(B) except we do not reduce mod q in the case
   d = 12. Reduction is only needed for key validation and a separate
   auxiliary MLKEM_keyValidityCheck is provided for that. This way we can
   also avoid the extra copying in an decode(encode()) round trip.
   This is the inverse to Algorithm 5. Here pB is the input but we implicitly
   assume its length is fLen * d / 8 bytes, where we pass in the resulting
   length of the ubyte2 array pF (ie fLen). */
static void MLKEM_byteDecode(ubyte d, ubyte *pB, ubyte2 *pF, ubyte4 fLen)
{
    ubyte4 in = 0;
    ubyte bits = 0;
    ubyte4 total = 0; /* we need room for up to 3 bytes for d > 9 */
    ubyte4 out = 0;

    for (; out < fLen; out++)
    {
        while( bits < d )
        {
            /* we use 3 bytes of total (ignore the highest byte).
               Ordering is little endian, so next byte is more significant,
               put it in the next highest spot after the ignored one */
            total = (total >> 8) | (((ubyte4) pB[in]) << 16);
            in++;
            bits += 8;
        }

        bits -= d;

        pF[out] = (ubyte2) ((total >> (24 - d - bits)) & (MLKEM_MASK_24 >> (24 - d)));
    }
}

/* ------------------------------------------------------------------- */

/* d_1 + d_2 2^12 = b_0 + b_1 2^8 + b_2 2^16  where b0, b1, b2 are
   the next 3 bytes in the input stream, inLen MUST be multiple of 3 */
static void MLKEM_sampleUniform(ubyte *pInBytes, ubyte4 inLen, sbyte2 *pOutWords, ubyte4 *pCount)
{
    ubyte4 outCtr = *pCount;
    ubyte2 d1 = 0;
    ubyte2 d2 = 0;

    while (outCtr < (MLKEM_N - 1) && inLen >= 3) /* stop when we need 0 or 1 more coeff */
    {
        /* Get 3 bytes at a time converted to up to 2 coefficients */
        d1 = (ubyte2) pInBytes[0] | (((ubyte2) (pInBytes[1] & 0x0f)) << 8);
        d2 = (ubyte2) (pInBytes[1] >> 4) | (((ubyte2) (pInBytes[2])) << 4);

        if (d1 < (ubyte2) MLKEM_Q)
        {
            pOutWords[outCtr++] = (sbyte2) d1;
        }
        if (d2 < (ubyte2) MLKEM_Q)
        {
            pOutWords[outCtr++] = (sbyte2) d2;
        }

        pInBytes += 3;
        inLen -= 3;
    }

    /* do we need one more? */
    while (outCtr != MLKEM_N && inLen >= 3)
    {
        /* Get 3 bytes at a time converted to up to 2 coefficients */
        d1 = (ubyte2) pInBytes[0] | (((ubyte2) (pInBytes[1] & 0x0f)) << 8);
        d2 = (ubyte2) (pInBytes[1] >> 4) | (((ubyte2) (pInBytes[2])) << 4);

        /* only check the second if the first fails */
        if (d1 < (ubyte2) MLKEM_Q)
        {
            pOutWords[outCtr++] = (sbyte2) d1;
        }
        else if (d2 < (ubyte2) MLKEM_Q)
        {
            pOutWords[outCtr++] = (sbyte2) d2;
        }

        pInBytes += 3;
        inLen -= 3;
    }

    *pCount = outCtr;
}

/* ------------------------------------------------------------------- */

/* Algorithm 7 sampleNTT, we pass in i and j rather than appending
   them to pB. This avoids an extra copy */
static MSTATUS MLKEM_sampleNTT(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pB, ubyte i, ubyte j, sbyte2 *pA)
{
    MSTATUS status = OK;
    ubyte pIndices[2];
    ubyte *pBuffer = NULL;
    SHA3_CTX *pCtx = NULL;
    ubyte4 count = 0;

    /* j goes first, then i */
    pIndices[0] = j;
    pIndices[1] = i;

    status = DIGI_MALLOC((void **) &pBuffer, MLKEM_SAMPLE_POLY_LEN); /* 504, divisible by 3 */
    if (OK != status)
        goto exit;

    status = SHA3_allocDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;

    status = SHA3_initDigest(MOC_HASH(hwAccelCtx) pCtx, MOCANA_SHA3_MODE_SHAKE128);
    if (OK != status)
        goto exit;

    status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) pCtx, pB, MLKEM_SEED_LEN);
    if (OK != status)
        goto exit;

    status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) pCtx, pIndices, 2);
    if (OK != status)
        goto exit;

    /* Our SHA3 version does not support sampling 3 bytes at a tinm,
       we therefore get MLKEM_SAMPLE_POLY_LEN bytes at a time and use
       MLKEM_sampleUniform to choose the ones less than q. This value
       will yield the needed 256 bytes most of the time */
    status = SHA3_finalDigest(MOC_HASH(hwAccelCtx) pCtx, pBuffer, MLKEM_SAMPLE_POLY_LEN);
    if (OK != status)
        goto exit;

    MLKEM_sampleUniform(pBuffer, MLKEM_SAMPLE_POLY_LEN, pA, &count);

    /* In case we did not get all 256 bytes then we need an additional block of output */
    while (count < MLKEM_N)
    {
        status = SHA3_additionalXOF(MOC_HASH(hwAccelCtx) pCtx, pBuffer, MLKEM_SHAKE128_RATE); /* 168, divisible by 3*/
        if (OK != status)
            goto exit;

        MLKEM_sampleUniform(pBuffer, MLKEM_SHAKE128_RATE, pA, &count);
    }

exit:

    if (NULL != pCtx)
    {
        (void) SHA3_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx);
    }

    if (NULL != pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pBuffer, MLKEM_SAMPLE_POLY_LEN);
    }

    return status;
}

/* ------------------------------------------------------------------- */

/* CBD(a, eta)_i = b_{2i eta} + b_{2i eta + 1} + ... + b_{2i eta + eta-1}
                - b_{2i eta + eta} - ... - b_{2i eta + 2eta - 1},

where b = OctetsToBits(a) (a serialized in Little Endian)

eta = 2 for this one and 3 for the one below that.

A 128-byte string input pA has each byte serialized in Little Endian
to a bit string b (b_{i} is the ith bit), so the formula above (for eta=2) is just
adding the first two bits and subtracting the next two
*/
static void MLKEM_CBD2(ubyte *pInput, sbyte2 *pPoly)
{
    ubyte4 i, j;
    ubyte4 in;
    ubyte4 temp;
    ubyte4 ctr = 0;

    /* We process 4 bytes at a time */
    for (i = 0; i < 32; i++)
    {
        in  = (ubyte4) pInput[0] | (((ubyte4) pInput[1]) << 8) | (((ubyte4) pInput[2]) << 16) | (((ubyte4) pInput[3]) << 24);

        /* get the 2nd and 4th bits of each nibble */
        temp = in & 0x55555555;

        /* put the 1st and 3rd bits of each nibble in the same postion and add,
           so each pair is a sum, 1st + second and then third + fourth and so forth */
        temp += (in >> 1) & 0x55555555;

        for(j = 0; j < 8; j++)
        {
            /* subtract the next pair from the first pair */
            pPoly[ctr++] = ((sbyte2) (temp >> (4 * j)) & 0x3) - ((sbyte2) (temp >> (4 * j + 2)) & 0x3);
        }

        pInput += 4;
    }
}

/* ------------------------------------------------------------------- */

#ifndef __DISABLE_DIGICERT_PQC_MLKEM_512__
/*
A 192-byte string input pInput has each byte serialized in Little Endian
to a bit string b (b_{i} is the ith bit), so the formula above (for eta=3) is just
adding the first three bits and subtracting the next three
*/
static void MLKEM_CBD3(ubyte *pInput, sbyte2 *pPoly)
{
    ubyte4 i, j;
    ubyte4 in;
    ubyte4 temp;
    ubyte4 ctr = 0;

    /* We process 3 bytes at a time */
    for (i = 0; i < 64; i++)
    {
        in = (ubyte4) pInput[0] | (((ubyte4) pInput[1]) << 8) | (((ubyte4) pInput[2]) << 16);

        /* get the 3rd,6th,9th,12th,15th,18th,21st,24th bits */
        temp = in & 0x00249249;
        /* line them up with the previous sets of bits in the same position and add */
        temp += (in >> 1) & 0x00249249;
        temp += (in >> 2) & 0x00249249;

        for(j = 0; j < 4; j++)
        {
            /* subtract the next trio from the trio pair */
            pPoly[ctr++] = ((sbyte2) (temp >> (6 * j)) & 0x7) - ((sbyte2) (temp >> (6 * j + 3)) & 0x7);
        }

        pInput += 3;
    }
}
#endif /* __DISABLE_DIGICERT_PQC_MLKEM_512__ */

/* ------------------------------------------------------------------- */

/* Algorithm 8 composed with PRF_eta, samplePolyCBD_eta(PRF_eta(sigma, N)) */
static MSTATUS MLKEM_samplePolyCBDPrfEta(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pB, ubyte eta, ubyte N, sbyte2 *pF)
{
    MSTATUS status;
    ubyte pPrfResult[MLKEM_PREKEY_LEN * 3]; /* 192, big enough for eta = 2 or 3 */

    status = MLKEM_prf(MOC_HASH(hwAccelCtx) pB, N, pPrfResult, MLKEM_PREKEY_LEN * (ubyte4) eta);
    if (OK != status)
        goto exit;

    /* only 512 uses eta = 3 (remmeber 512 uses both eta = 2 and eta = 3) */
#ifndef __DISABLE_DIGICERT_PQC_MLKEM_512__
    if ((ubyte) 2 == eta)
    {
        MLKEM_CBD2(pPrfResult, pF);
    }
    else if ((ubyte) 3 == eta)
    {
        MLKEM_CBD3(pPrfResult, pF);
    }
#else
    MLKEM_CBD2(pPrfResult, pF);
#endif

exit:

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 9 NTT(f), f converted to f^hat in place

We compute the Cooley-Tukey Bufferfly (CT)
CT_i: (a, b) |-> (a + zeta^i b, a - zeta^i b)   modulo q
we apply CT_64 128 times, CT_32 64 times etc.
*/
static void MLKEM_ntt(sbyte2 *pPoly)
{
    ubyte4 i = 1;
    ubyte4 j;
    ubyte4 len;
    ubyte4 start;
    sbyte2 t;

    for (len = MLKEM_N/2; len >= 2; len /= 2)
    {
        for (start = 0; start < MLKEM_N; start += (2 * len), i++)
        {
            for (j = start; j < start + len; j++)
            {
                t = MLKEM_montMultiply(gZeta[i], pPoly[j + len]);
                pPoly[j + len] = pPoly[j] - t;
                pPoly[j] = pPoly[j] + t;
            }
        }
    }
    MLKEM_polyVecReduce(pPoly, MLKEM_N);
}

/* ------------------------------------------------------------------- */

/* Algorithm 10 NTT^-1(f^hat), f^hat converted to f in place

We compute the Gentleman-Sande Butterfly (GS), inverse of the Cooley-Tukey
GS_i: (a, b) |-> ( (a+b)/2, zeta^-i (a-b)/2 )    modulo q
we apply GS_64 128 times, GS_32 64 times, etc...

Note that we don't divide a+b and a-b by 2 each time. The result is therefore
2 times too much. We'll correct for this after all calls.*/
static void MLKEM_nttInv(sbyte2 *pPoly)
{
    ubyte4 i = 127;
    ubyte4 j;
    ubyte4 len;
    ubyte4 start;
    sbyte2 t;

    for (len = 2; len <= MLKEM_N/2; len *= 2)
    {
        for (start = 0; start < MLKEM_N; start += (2 * len), i--)
        {
            for (j = start; j < start + len; j++)
            {
                t = pPoly[j];
                pPoly[j] = MLKEM_reduceCoeff(t + pPoly[j + len]);
                pPoly[j + len] = MLKEM_montMultiply(gZeta[i], pPoly[j + len] - t);
            }
        }
    }

    /* f * 3303 mod 𝑞, but we use an augmented 3303, ie augmented 128^-1.
       This is because each outer loop on len, 7 loops, added a factor of 2 */
    for (i = 0; i < MLKEM_N; i++)
    {
        pPoly[i] = MLKEM_montMultiply(pPoly[i], MLKEM_128_INV);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 12 */
static inline void MLKEM_baseCaseMultiply(sbyte2 a0, sbyte2 a1, sbyte2 b0, sbyte2 b1, sbyte2 gamma,
                                          sbyte2 *pC0, sbyte2 *pC1)
{
    /* c0 = a0 b0 + a1 b1 gamma */
    *pC0 = MLKEM_montMultiply(a0, b0);
    *pC0 += MLKEM_montMultiply(MLKEM_montMultiply(a1, b1), gamma);

    /* c1 = a0 b1 + a1 b0 */
    *pC1 = MLKEM_montMultiply(a0, b1);
    *pC1 += MLKEM_montMultiply(a1, b0);
}

/* ------------------------------------------------------------------- */

/* Algorithm 11, polynomial multiplication. If f has coeffs a and g has coeffs
   b the product h will have coeffs...

             [ a_i b_i + zeta^{2 brv(i >> 1) + 1} * a_{i+1} b_{i+1}  if i even
 (a o b)_i = [
             [ a_{i-1} b_i + a_i b_{i-1}                   otherwise

 Note 2 brv(i >> 1) + 1 = brv(64 + (i>>2)) for i == 0 mod 4
 and zeta^-i can be computed as -zeta^(128-i)
*/
static void MLKEM_multiplyNTTs(sbyte2 *pF, sbyte2 *pG, sbyte2 *pH)
{
    ubyte4 i;

    /* instead of looping over 128 coeffs we handle i = 0 mod 4 and i = 2 mod 4
       cases in one loop, that way we can re-use the gZeta table as is */
    for (i = 0; i < MLKEM_N; i += 4)
    {
        MLKEM_baseCaseMultiply(pF[i], pF[i + 1], pG[i], pG[i + 1], gZeta[64 + (i>>2)],
                               &pH[i], &pH[i + 1]);
        MLKEM_baseCaseMultiply(pF[i + 2], pF[i + 3], pG[i + 2], pG[i + 3], -1 * gZeta[64 + (i>>2)],
                               &pH[i + 2], &pH[i + 3]);
    }
}

/* ------------------------------------------------------------------- */

/* pScratch needs to be a single polynomial, 256 words */
static void MLKEM_matrixMul(ubyte4 k, sbyte2 *pMatrix, sbyte2 *pVector, sbyte2 *pScratch, sbyte2 *pResult)
{
    ubyte4 i,j;
    ubyte4 nk = MLKEM_N * k;

    /* initialize result to all 0s */
    (void) DIGI_MEMSET((ubyte *) pResult, 0x00, nk * sizeof(sbyte2));

    for (i = 0; i < k; i++)
    {
        /* dot product row of matrix with input vector */
        for (j = 0; j < k; j++)
        {
            MLKEM_multiplyNTTs(pMatrix + MLKEM_N * j, pVector + MLKEM_N * j, pScratch);
            MLKEM_polyVecAdd(pScratch, MLKEM_N, pResult);
        }

        /* reduce each element in the new polynomial */
        MLKEM_polyVecReduce(pResult, MLKEM_N);

        /* move pMatrix to next row vector, pResult to next element */
        pMatrix += nk;
        pResult += MLKEM_N;
    }
}

/* ------------------------------------------------------------------- */

static MSTATUS MLKEM_matrixGen(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pRho, ubyte4 k, byteBoolean transpose, sbyte2 *pA)
{
    MSTATUS status = OK;
    ubyte4 i,j;

    for (i = 0; i < k; i++)
    {
        for (j = 0; j < k; j++)
        {
            /* transpose is same entries just stored transposed */
            status = MLKEM_sampleNTT(MOC_HASH(hwAccelCtx) pRho, i, j, pA + MLKEM_N *
                                     (transpose ? ((j * k) + i) : (i * k) + j));

            if (OK != status)
                goto exit;
        }
    }

exit:

    return status;
}

/* ------------------------------------------------------------------- */

/* also puts the vector in the ntt domain if toNTT is TRUE */
static MSTATUS MLKEM_vectorGen(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pSigma, ubyte eta, ubyte4 k, ubyte4 offset,
                               byteBoolean toNTT, sbyte2 *pVector)
{
    MSTATUS status = OK;
    ubyte4 i;

    for (i = 0; i < k; i++)
    {
        /* Both Prf_eta step and CBD steps done by this call */
        status = MLKEM_samplePolyCBDPrfEta(MOC_HASH(hwAccelCtx) pSigma, eta, (ubyte) (i + offset), pVector + MLKEM_N * i);
        if (OK != status)
            goto exit;

        if (toNTT)
        {
            MLKEM_ntt(pVector + MLKEM_N * i);
        }
    }

exit:

    return status;
}

/* ------------------------------------------------------------------- */

/* Section 7.2, equivalent to checking x = Encode_12(Decode_12(x)),
   We perform the decode_12 operation and check
   that each value is actually less than q. */
static MSTATUS MLKEM_keyValidityCheck(ubyte *pIn, ubyte4 inLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_INTERNAL_ERROR;
    sbyte2 check;
    ubyte4 i = 0;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,inLen);

    /* sanity check on the length, should be 384 * k bytes
       Note that is divisible by 3 */
    if (0 != inLen % MLKEM_N_BYTES)
        goto exit;

    status = OK;
    for (i = 0; i < inLen; i += 3)
    {
        check = (sbyte2) pIn[i] | (((sbyte2) pIn[i+1] & 0x0f) << 8);
        if (check >= (sbyte2) MLKEM_Q) {
            status = ERR_BAD_KEY;
            goto exit;
        }

        check = ((sbyte2) pIn[i+1] >> 4) | ((sbyte2) pIn[i+2] << 4);
        if (check >= (sbyte2) MLKEM_Q) {
            status = ERR_BAD_KEY;
            goto exit;
        }
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,inLen);
    return status;
}

/* Section 7.3 Decapsulation input checks.
   Validate the hash of the ek. Use pMprimeAndH as temp space for now */
static
MSTATUS MLKEM_keyHashCheck(MLKEMCtx *ctx, const MlkemCtx *pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    sbyte4 differ = 0;
    ubyte pTest[MLKEM_SEED_LEN]; /* for validating the hash, H(ek) */

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);

    status = mlkem_h(MOC_HASH(ctx->hwAccelCtx) ctx->decKey + pCtx->dkPkeLen, pCtx->ekPkeLen, pTest);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pTest, ctx->decKey + pCtx->dkPkeLen + pCtx->ekPkeLen, MLKEM_SEED_LEN, &differ);
    if (OK != status)
        goto exit;

    if (differ)
        status = ERR_BAD_KEY;

exit:
    (void) DIGI_MEMSET(pTest, 0x00, MLKEM_SEED_LEN);
    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);
    return status;
}

/* ------------------------------------------------------------------- */

/* Copys pNew to pResult for mask = 0xff, and a no-op if mask = 0x00 */
static void MLKEM_ctimeCopy(ubyte *pResult, ubyte *pNew, ubyte mask)
{
    ubyte4 i;

    for (i = 0; i < MLKEM_SS_LEN; i++)
    {
        pResult[i] ^= mask & (pResult[i] ^ pNew[i]);
    }
}

/* ------------------------------------------------------------------- */

/* Compress_d(x), x -> Round((2^d/q) * x) mod 2^d
   Operation is in-place, output is positive so can be treated
   as a ubyte2 array for ByteEncode */
static void MLKEM_compress(ubyte d, sbyte2 *pX, ubyte4 xLen)
{
    ubyte4 i;

    for (i = 0; i < xLen; i++)
    {
        /* if negative, add Q to make positive */
        pX[i] += (pX[i] >> 15) & MLKEM_Q;

        /* add Q/2 so the division by Q will round to nearest integer */
        pX[i] = ((((ubyte4) pX[i] << d) + MLKEM_Q_OVER2)/MLKEM_Q) & (MLKEM_MASK >> (16 - d));
    }
}

/* ------------------------------------------------------------------- */

/* Decompress_d(y), y -> Round ((q/2^d) * y)
   Operation is in-place, output can be considered as a sbyte2 * array */
static void MLKEM_decompress(ubyte d, ubyte2 *pY, ubyte4 yLen)
{
    ubyte4 i;

    for (i = 0; i < yLen; i++)
    {
        /* Add 2^(d-1) so that we round to the nearest integer when dividing by 2^d */
        pY[i] = (ubyte2) ((((ubyte4) (pY[i] & (MLKEM_MASK >> (16 - d)))) * MLKEM_Q + (1 << (d-1))) >> d);
    }
}

/* ------------------------------------------------------------------- */

/* Algorithm 13 K-PKE.KeyGen, we copy both ek_pke and dk_pke to their place
   in pKeyBuf so that more copying is not needed later, pD has an extra byte of space
   in order to append k */
static MSTATUS MLKEM_kPkeKeyGen(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pD, ubyte *pKeyBuf)
{
    MSTATUS status = OK;
    ubyte pRhoSigma[MLKEM_SEED_LEN*2];

    /* element */
    sbyte2 *pTemp;

    /* vectors */
    sbyte2 *pS_hat;
    sbyte2 *pT_hat;
    sbyte2 *pE_hat; /* will come out of re-used space, don't count in malloc */

    /* matrix */
    sbyte2 *pA_hat;

    /* space for all polynomials in a single shot */
    ubyte *pScratch = NULL;
    ubyte4 scratchLen;

    /* make a ubyte4 copy of k since it's used so much */
    ubyte4 k = (ubyte4) pCtx->k;
    ubyte4 nk = MLKEM_N * (ubyte4) pCtx->k;

    /* one k * k matrix and two vectors of length k, and one element */
    scratchLen = (k * k + 2 * k + 1) * MLKEM_N * sizeof(sbyte2);

    status = DIGI_MALLOC((void **) &pScratch, scratchLen);
    if (OK != status)
        goto exit;

    /* start with the temp, the two vectors and then the matrix */
    pTemp = (sbyte2 *) pScratch;

    pS_hat = pTemp + MLKEM_N;
    pT_hat = pS_hat + nk;

    pA_hat = pT_hat + nk;

    /* re-use space */
    pE_hat = pA_hat;

    /* Step 1 */
    pD[MLKEM_SEED_LEN] = pCtx->k;   /* pD came in with the extra byte of space */
    status = mlkem_g(MOC_HASH(hwAccelCtx) pD, MLKEM_SEED_LEN + 1, pRhoSigma);
    if (OK != status)
        goto exit;

    /* Steps 3-7, A^ is taken to be augmented in NTT domain */
    status = MLKEM_matrixGen(MOC_HASH(hwAccelCtx) pRhoSigma, k, FALSE, pA_hat);
    if (OK != status)
        goto exit;

    /* Steps 8-10 and 16, pS_hat comes out of this call already in NTT domain */
    status = MLKEM_vectorGen(MOC_HASH(hwAccelCtx) pRhoSigma + MLKEM_SEED_LEN, pCtx->eta1, k, 0, TRUE, pS_hat);
    if (OK != status)
        goto exit;

    /* We peform the matrix multiplication in step 18 first
       so that we can then re-use space to generate e (steps 12-14 and 17) */

    /* t^ = A^ * s^ + e^ */
    /* first A^ * s^, store in pT_hat */
    MLKEM_matrixMul(k, pA_hat, pS_hat, pTemp, pT_hat); /* Use pE_hat as scratch for now */

    /* put back in mont domain */
    MLKEM_polyVecMontAug(pT_hat, nk);

    /* Steps 12-14 and 17, get e and reduce, we are done with A, re-use the memory */
    status = MLKEM_vectorGen(MOC_HASH(hwAccelCtx) pRhoSigma + MLKEM_SEED_LEN, pCtx->eta1, k, k, TRUE, pE_hat);
    if (OK != status)
        goto exit;

    /* Now finish step 18, add e^ to get t^ */
    MLKEM_polyVecAdd(pE_hat, nk, pT_hat);
    MLKEM_polyVecReduce(pT_hat, nk);

    /* Steps 19 and 20, we copy directly to proper place in pKeyBuf */
    MLKEM_polyVecNormalize(pS_hat, nk);
    MLKEM_byteEncodeL(12, (ubyte2 *) pS_hat, nk, pKeyBuf);

    /* remember packed vector is 384 bytes per element */
    MLKEM_polyVecNormalize(pT_hat, nk);
    MLKEM_byteEncodeL(12, (ubyte2 *) pT_hat, nk, pKeyBuf + MLKEM_N_BYTES * k);

    /* copy in rho */
    (void) DIGI_MEMCPY(pKeyBuf + (2 * MLKEM_N_BYTES * k), pRhoSigma, MLKEM_SEED_LEN);

exit:

    /* sensative data, zero too */
    if (NULL != pScratch)
    {
        (void) DIGI_MEMSET_FREE(&pScratch, scratchLen);
    }

    (void) DIGI_MEMSET(pRhoSigma, 0x00, MLKEM_SEED_LEN*2);

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 14 K-PKE.Encrypt(ek_PKE, m, r) */
static MSTATUS MLKEM_kPkeEncrypt(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pEkPke, ubyte *pM, ubyte *pR, ubyte *pCipher)
{
    MSTATUS status = OK;
    ubyte4 i;

    /* matrix */
    sbyte2 *pA_hatT; /* A^ transpose */

    /* vectors */
    sbyte2 *pY_hat;
    sbyte2 *pU;
    sbyte2 *pE1;    /* will come out of re-used space, don't count in malloc */
    sbyte2 *pT_hat; /* will come out of re-used space, don't count in malloc */

    /* elements */
    sbyte2 *pTemp;
    sbyte2 *pV;   /* will come out of re-used space, don't count in malloc */
    sbyte2 *pE2;  /* will come out of re-used space, don't count in malloc */

    /* space for all polynomials in a single shot */
    ubyte *pScratch = NULL;
    ubyte4 scratchLen;

    /* make a ubyte4 copy of k since it's used so much */
    ubyte4 k = (ubyte4) pCtx->k;
    ubyte4 nk = MLKEM_N * (ubyte4) pCtx->k;

    /* one k * k matrix and two vectors of length k and 1 element */
    scratchLen = (k * k + 2 * k + 1) * MLKEM_N * sizeof(sbyte2);
    status = DIGI_MALLOC((void **) &pScratch, scratchLen);
    if (OK != status)
        goto exit;

    /* start with single elems, then the vectors, and then the matrix */
    pTemp = (sbyte2 *) pScratch;

    pY_hat = pTemp + MLKEM_N;
    pU =  pY_hat + nk;

    pA_hatT = pU + nk;

    /* re-use memory in pA_hatT */
    pT_hat = pA_hatT;
    pE1 = pA_hatT;
    pE2 = pA_hatT;
    pV = pA_hatT + nk;  /* re-use the second column */

    /* We do steps out of order to save on memory usage */

    /* Steps 4-8. rho is after the ek_pke vector in the public key */
    status = MLKEM_matrixGen(MOC_HASH(hwAccelCtx) pEkPke + MLKEM_N_BYTES * k, k, TRUE, pA_hatT);
    if (OK != status)
        goto exit;

    /* Steps 9-12, y^ already in NTT domain comes out of this call */
    status = MLKEM_vectorGen(MOC_HASH(hwAccelCtx) pR, pCtx->eta1, k, 0, TRUE, pY_hat);
    if (OK != status)
        goto exit;

    /* Partial Step 19, (A^)^T * y^, store in pU as a temp var for now */
    MLKEM_matrixMul(k, pA_hatT, pY_hat, pTemp, pU);

    /* Go out of NTT for each elem of pU */
    for (i = 0; i < k; i++)
    {
        MLKEM_nttInv(pU + MLKEM_N * i);
    }

    /* Steps 13-16. Get e1, done with A^, ok to use pE1 */
    status = MLKEM_vectorGen(MOC_HASH(hwAccelCtx) pR, MLKEM_ETA2, k, k, FALSE, pE1);
    if (OK != status)
        goto exit;

    /* rest of step 19, add e1 to our temp value in pU */
    MLKEM_polyVecAdd(pE1, nk, pU);
    MLKEM_polyVecReduce(pU, nk);

    /* Step 2, get t^, done with pE1, ok to use pT_hat */
    MLKEM_byteDecode(12, pEkPke, (ubyte2 *) pT_hat, nk);

    /* Step 21, Dot product t^ with y^, initialize pV to zero, pV will be a running tally */
    (void) DIGI_MEMSET((ubyte *) pV, 0x00, MLKEM_N * sizeof(sbyte2));
    for (i = 0; i < k; i++)
    {
        MLKEM_multiplyNTTs(pT_hat + MLKEM_N * i, pY_hat + MLKEM_N * i, pTemp);
        MLKEM_polyVecAdd(pTemp, MLKEM_N, pV);
    }

    /* reduce each element in the new polynomial and take out of NTT domain */
    MLKEM_polyVecReduce(pV, MLKEM_N);
    MLKEM_nttInv(pV);

    /* get e_2, done with pT_hat, ok to re-use space again for pE2 */
    status = MLKEM_samplePolyCBDPrfEta(MOC_HASH(hwAccelCtx) pR, MLKEM_ETA2, (ubyte) (2 * k), pE2);
    if (OK != status)
        goto exit;

    /* now add e2 */
    MLKEM_polyVecAdd(pE2, MLKEM_N, pV);

    /* Step 20, get mu, Decompress_1(ByteDecode_1 (m))  */
    MLKEM_byteDecode(1, pM, (ubyte2 *) pTemp, MLKEM_N);
    MLKEM_decompress(1, (ubyte2 *) pTemp, MLKEM_N);

    /* add to running total pV to finish step 21 */
    MLKEM_polyVecAdd(pTemp, MLKEM_N, pV);
    MLKEM_polyVecReduce(pV, MLKEM_N);

    /* Must initialize to all zeros first for final 2 steps */
    (void) DIGI_MEMSET(pCipher, 0x00, pCtx->cipherLen);

    /* Step 22 */
    MLKEM_compress(pCtx->du, pU, nk);
    MLKEM_byteEncodeL(pCtx->du, (ubyte2 *) pU, nk, pCipher);

    /* Step 23 */
    pCipher += (nk / MLKEM_BITS_PER_BYTE * pCtx->du);
    MLKEM_compress(pCtx->dv, pV, MLKEM_N);
    MLKEM_byteEncodeS(pCtx->dv, (ubyte2 *) pV, MLKEM_N, pCipher);

exit:

    /* sensative data, zero too */
    if (NULL != pScratch)
    {
        (void) DIGI_MEMSET_FREE(&pScratch, scratchLen);
    }

    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 15 K-PKE.Decrypt(dk_PKE, c) */
static MSTATUS MLKEM_kPkeDecrypt(const MlkemCtx *pCtx, ubyte *pCipher, ubyte *pDkPke, ubyte *pM)
{
    MSTATUS status = OK;
    ubyte4 i;

    /* vectors */
    sbyte2 *pS_hat;
    sbyte2 *pUprime;

    /* elements */
    sbyte2 *pVprime;
    sbyte2 *pW;

    /* space for all polynomials in a single shot */
    ubyte *pScratch = NULL;
    ubyte4 scratchLen;

    /* make a ubyte4 copy of k since it's used so much */
    ubyte4 k = (ubyte4) pCtx->k;
    ubyte4 nk = MLKEM_N * (ubyte4) pCtx->k;

    /* two vectors of length k and 2 elements */
    scratchLen = (2 * k + 2) * MLKEM_N * sizeof(sbyte2);
    status = DIGI_MALLOC((void **) &pScratch, scratchLen);
    if (OK != status)
        goto exit;

    /* start with single elems, then the vectors */
    pVprime = (sbyte2 *) pScratch;
    pW = pVprime + MLKEM_N;

    pS_hat = pW + MLKEM_N;
    pUprime = pS_hat + nk;

    /* Step 3, get u' */
    MLKEM_byteDecode(pCtx->du, pCipher, (ubyte2 *) pUprime, nk);
    MLKEM_decompress(pCtx->du, (ubyte2 *) pUprime, nk);

    /* We delay step 4, getting v', until later so we can re-use space, move to its
       position however in pCipher */
    pCipher += (nk / MLKEM_BITS_PER_BYTE * pCtx->du);

    /* Step 5, get s^ */
    MLKEM_byteDecode(12, pDkPke, (ubyte2 *) pS_hat, nk);

    /* Step 6, compute w = v' - InvNtt((s^)^T * Ntt(u')) */

    /* Ntt(u') */
    for (i = 0; i < k; i++)
    {
        MLKEM_ntt(pUprime + MLKEM_N * i);
    }

    /* (s^)^T * Ntt(u), store into pW, start with pW zero */
    (void) DIGI_MEMSET((ubyte *) pW, 0x00, MLKEM_N * sizeof(sbyte2));
    for (i = 0; i < k; i++)
    {
        MLKEM_multiplyNTTs(pUprime + MLKEM_N * i, pS_hat + MLKEM_N * i, pVprime); /* Use pVprime as a temp var */
        MLKEM_polyVecAdd(pVprime, MLKEM_N, pW);
    }

    /* - InvNtt((s^)^T * Ntt(u')) */
    MLKEM_polyVecReduce(pW, MLKEM_N);
    MLKEM_nttInv(pW);

    for (i = 0; i < MLKEM_N; i++)
    {
        pW[i] *= -1;
    }

    /* Step 4, now we need v' */
    MLKEM_byteDecode(pCtx->dv, pCipher, (ubyte2 *) pVprime, MLKEM_N);
    MLKEM_decompress(pCtx->dv, (ubyte2 *) pVprime, MLKEM_N);

    /* w = v' - InvNtt((s^)^T * Ntt(u')), pW reps the dot product, negate it and add v */
    MLKEM_polyVecAdd(pVprime, MLKEM_N, pW);
    MLKEM_polyVecReduce(pW, MLKEM_N);

    /* Step 7 */
    MLKEM_compress(1, pW, MLKEM_N);
    MLKEM_byteEncodeS(1, (ubyte2 *) pW, MLKEM_N, pM);

exit:

    /* sensative data, zero too */
    if (NULL != pScratch)
    {
        (void) DIGI_MEMSET_FREE(&pScratch, scratchLen);
    }

    return status;
}

/* ------------------------------------------------------------------- */

/*  Algorithm 16, ML-KEM.KeyGen_internal. We require an extra byte after
    the 32-byte seed pD to suffix with the domain param k.
    pZ is a 32 byte seed too, and output params pDk must be the proper length
    We do not output pEk since it is already inside pDk */
static MSTATUS MLKEM_keyGen_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pD,
                                     ubyte *pZ, ubyte *pDk)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);

    /* internal method, checks already done */

    /* Step 1, compute ek_pke and dk_pke, both will be in pDk, pD has extra byte of space */
    status = MLKEM_kPkeKeyGen(MOC_HASH(hwAccelCtx) pCtx, pD, pDk);
    if (OK != status)
        goto exit;

    /* ek = ek_pke */

    /* Step 3, first H(ek). hashing starts after dk_pke and is pKey->ekPkeLen bytes */
    status = mlkem_h(MOC_HASH(hwAccelCtx) pDk + pCtx->dkPkeLen, pCtx->ekPkeLen,
                     pDk + pCtx->dkPkeLen + pCtx->ekPkeLen);
    if (OK != status)
        goto exit;

    /* copy in z to the last 32 bytes */
    (void) DIGI_MEMCPY(pDk + pCtx->privLen - MLKEM_SEED_LEN, pZ, MLKEM_SEED_LEN);

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 17, ML-KEM.Encaps_internal(ek,m), pM has to have
   32 bytes of extra space that will be used to append H(ek) */
static MSTATUS MLKEM_encaps_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pEk,
                                     ubyte *pM, ubyte *pC, ubyte *pK)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte pKandR[MLKEM_PREKEY_LEN];

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);

    /* internal method, checks already done */

    /* Step 1, (K, r) = G(m || H(ek)) */

    /* H(ek) */
    status = mlkem_h(MOC_HASH(hwAccelCtx) pEk, pCtx->ekPkeLen, pM + MLKEM_SEED_LEN); /* pM has extra space */
    if (OK != status)
        goto exit;

    /* G(m || H(ek)) */
    status = mlkem_g(MOC_HASH(hwAccelCtx) pM, MLKEM_PREKEY_LEN, pKandR);
    if (OK != status)
        goto exit;

    /* Step 2, c = K-PKE.Encrypt(ek, m, r) */
    status = MLKEM_kPkeEncrypt(MOC_HASH(hwAccelCtx) pCtx, pEk, pM, pKandR + MLKEM_SEED_LEN, pC);
    if (OK != status)
        goto exit;

    /* Step 3 */
    status = DIGI_MEMCPY(pK, pKandR, MLKEM_SS_LEN);

exit:

    (void) DIGI_MEMSET(pKandR, 0x00, MLKEM_PREKEY_LEN);
    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 18, ML-KEM.Decaps_internal(dk, c) */
static MSTATUS MLKEM_decaps_internal(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pDk, ubyte *pC, ubyte *pK)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte pMprimeAndH[MLKEM_PREKEY_LEN];
    ubyte pKprimeAndRprime[MLKEM_PREKEY_LEN];
    ubyte *pCprime = NULL;
    sbyte4 differ = 0;
    ubyte mask = 0;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);

    /* internal method, checks already done */

    /* Steps 1-4 we'll access the appropriate places in the key directly */

    /* need space for the cipherText compare c' */
    status = DIGI_MALLOC((void **) &pCprime, pCtx->cipherLen);
    if (OK != status)
        goto exit;

    /* Step 5, m' = K-PKE.Decrypt(dkPKE ,c) */
    status = MLKEM_kPkeDecrypt(pCtx, pC, pDk, pMprimeAndH);
    if (OK != status)
        goto exit;

    /* copy h after the plaintext m', h is second to last 32 byte group in key */
    status = DIGI_MEMCPY(pMprimeAndH + MLKEM_SEED_LEN, pDk + pCtx->privLen - MLKEM_PREKEY_LEN, MLKEM_SEED_LEN);
    if (OK != status)
        goto exit;

    /* Step 6, (K', r') = G(m' || h) */
    status = mlkem_g(MOC_HASH(hwAccelCtx) pMprimeAndH, MLKEM_PREKEY_LEN, pKprimeAndRprime);
    if (OK != status)
        goto exit;

    /* Step 7, Kbar = J(z || c), z is last seed in the decryption key, we use the space in pK for Kbar */
    status = mlkem_j(MOC_HASH(hwAccelCtx) pDk + pCtx->privLen - MLKEM_SEED_LEN, pC, pCtx->cipherLen, pK);
    if (OK != status)
        goto exit;

    /* Step 8, c' = K-PKE.Encrypt(ekPKE, m′,r′) */
    status = MLKEM_kPkeEncrypt(MOC_HASH(hwAccelCtx) pCtx, pDk + pCtx->dkPkeLen, pMprimeAndH, pKprimeAndRprime + MLKEM_SEED_LEN, pCprime);
    if (OK != status)
        goto exit;

    /* Step 9, is c = c'? */
    status = DIGI_CTIME_MATCH(pC, pCprime, pCtx->cipherLen, (intBoolean *) &differ);
    if (OK != status)
        goto exit;

    /* Step 10, in constant time we get either our real secret K' or our error fill in Kbar
       we take advantage that we know differ is only one byte if non-zero.
       if differ = 0 then our subtract gives all f's, otherwise it gives
       a single byte value that gets shifted to 0. */
    mask = (ubyte) (((ubyte4) differ - 1) >> 8);
    MLKEM_ctimeCopy(pK, pKprimeAndRprime, mask);

exit:

    /* destroy the mask and differ flags too */
    mask = 0;
    differ = 0;

    (void) DIGI_MEMSET(pMprimeAndH, 0x00, MLKEM_PREKEY_LEN);
    (void) DIGI_MEMSET(pKprimeAndRprime, 0x00, MLKEM_PREKEY_LEN);

    if (NULL != pCprime)
    {
        (void) DIGI_MEMSET_FREE(&pCprime, pCtx->cipherLen);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,pCtx->cipherLen);
    return status;
}

/* Sizes from Table 3. */
static size_t getCipherLen(MLKEMType type)
{
    switch (type) {
        case MLKEM_TYPE_512:
            return 768;
        case MLKEM_TYPE_768:
            return 1088;
        case MLKEM_TYPE_1024:
            return 1568;
        default:
            return 0;
    }
}

/* Sizes from Table 3. */
static size_t getPrivKeyLen(MLKEMType type)
{
    switch (type) {
        case MLKEM_TYPE_512:
            return 1632;
        case MLKEM_TYPE_768:
            return 2400;
        case MLKEM_TYPE_1024:
            return 3168;
        default:
            return 0;
    }
}

/* Sizes from Table 3. */
static size_t getPubKeyLen(MLKEMType type)
{
    switch (type) {
        case MLKEM_TYPE_512:
            return 800;
        case MLKEM_TYPE_768:
            return 1184;
        case MLKEM_TYPE_1024:
            return 1568;
        default:
            return 0;
    }
}
static MSTATUS validateParams(MLKEMType type, MLKEMParams *params)
{
    const MLKEMParams *knownParams = &mlkem512Params;
    if (type == MLKEM_TYPE_768) {
        knownParams = &mlkem768Params;
    } else if (type == MLKEM_TYPE_1024){
        knownParams = &mlkem1024Params;
    }

    if (moc_memcmp(params, knownParams, sizeof(MLKEMParams)) != OK) {
        return ERR_INVALID_INPUT;
    }

    return OK;
}

static MSTATUS validateCtx(MLKEMCtx *ctx)
{
    if (ctx == NULL) {
        return ERR_NULL_POINTER;
    }

    if (ctx->tag != MLKEM_TAG) {
        return ERR_WRONG_CTX_TYPE;
    }

    if (ctx->type <= MLKEM_TYPE_ERR || ctx->type > MLKEM_TYPE_1024) {
        return ERR_INVALID_INPUT;
    }

    if ((ctx->encKey == NULL && ctx->encKeyLen != 0) || (ctx->decKey == NULL && ctx->decKeyLen != 0)) {
        return ERR_INVALID_INPUT;
    }
    size_t neededPubKeyLen = getPubKeyLen(ctx->type);
    size_t neededPrivKeyLen = getPrivKeyLen(ctx->type);
    if ((ctx->encKey != NULL && ctx->encKeyLen != neededPubKeyLen) ||
        (ctx->decKey != NULL && ctx->decKeyLen != neededPrivKeyLen)) {
        return ERR_INVALID_INPUT;
    }

    return validateParams(ctx->type, &ctx->params);
}

static const MlkemCtx* MLKEM_getOldCtx(MLKEMType type)
{
    if (type == MLKEM_TYPE_512) {
        return &gMlkem512;
    } else if (type == MLKEM_TYPE_768) {
        return &gMlkem768;
    }

    return &gMlkem1024;
}

static MSTATUS encapsulate(MLKEMCtx *ctx, RNGFun rngFun, void *rngFunArg, uint8_t *cipherText, uint8_t *sharedSecret)
{
    MSTATUS status = OK;
    ubyte pMandH[MLKEM_PREKEY_LEN]; /* extra 32 bytes space to apppend H(ek) after M */
    const MlkemCtx *pCtx = MLKEM_getOldCtx(ctx->type);

    /* Section 7.2 Key Encapsulation check, length check already done when setting the key,
       check that the byte reps for cpaPub are valid integers mod q */
    status = MLKEM_keyValidityCheck(ctx->encKey, ctx->encKeyLen - MLKEM_SEED_LEN);
    if (OK != status)
        goto exit;

    /* Step 1, create m directly */
    status = (MSTATUS) rngFun(rngFunArg, MLKEM_SEED_LEN, pMandH);
    if (OK != status)
        goto exit;

    /* Step 5 */
    status = MLKEM_encaps_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->encKey, pMandH, cipherText, sharedSecret);

exit:

    (void) DIGI_MEMSET(pMandH, 0x00, MLKEM_PREKEY_LEN);

    return status;
}

static MSTATUS decapsulate(MLKEMCtx *ctx, uint8_t *cipherText, uint8_t *sharedSecret)
{
    MSTATUS status = OK;
    const MlkemCtx *pCtx = MLKEM_getOldCtx(ctx->type);

    /* Section 7.3 Decapsulation input checks.
       Length of ciphertext already validated above
       Length of private key is validated when deserialized and/or generated.
    */
    status = MLKEM_keyHashCheck(ctx, pCtx);
    if (OK != status)
        goto exit;

    status = MLKEM_decaps_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->decKey, cipherText, sharedSecret);

exit:
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_createCtx(MLKEMType type, hwAccelDescr hwAccelCtx, MLKEMCtx *ctx)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (type <= MLKEM_TYPE_ERR || type > MLKEM_TYPE_1024)
        goto exit;

    status = ERR_NULL_POINTER;
    if (ctx == NULL)
        goto exit;

    ctx->tag = MLKEM_TAG;
    ctx->type = type;
    ctx->encKey = NULL;
    ctx->encKeyLen = 0;
    ctx->decKey = NULL;
    ctx->decKeyLen = 0;
    ctx->hwAccelCtx = hwAccelCtx;

    status = ERR_FALSE;
    switch (type) {
        case MLKEM_TYPE_512:
            ctx->params = mlkem512Params;
            break;
        case MLKEM_TYPE_768:
            ctx->params = mlkem768Params;
            break;
        case MLKEM_TYPE_1024:
            ctx->params = mlkem1024Params;
            break;
        default:
            /* Can't happen */
            goto exit;
    }
    status = OK;

exit:
    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS generateKeyPair(RNGFun rng, void *rngArg, MLKEMCtx *ctx)
{
    MSTATUS status = OK;
    const MlkemCtx *pCtx = MLKEM_getOldCtx(ctx->type);
    ubyte pD[MLKEM_SEED_LEN + 1]; /* extra byte for appending the dimension k */
    ubyte pZ[MLKEM_SEED_LEN];

    /* Step 1, create d */
    status = (MSTATUS) rng(rngArg, MLKEM_SEED_LEN, pD);
    if (OK != status)
        goto exit;

    /* Step 2, create z */
    status = (MSTATUS) rng(rngArg, MLKEM_SEED_LEN, pZ);
    if (OK != status)
        goto exit;

    /* allocate spave for the full private key dk, ok to be uninitialized at this point */
    status = DIGI_MALLOC((void **) &ctx->decKey, pCtx->privLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &ctx->encKey, pCtx->ekPkeLen);
    if (OK != status)
        goto exit;

    /* Step 6 */
    status = MLKEM_keyGen_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, pD, pZ, ctx->decKey);
    if (OK != status)
        goto exit;

    /* Copy out the public key */
    moc_memcpy(ctx->encKey, ctx->decKey + pCtx->dkPkeLen, pCtx->ekPkeLen);
    ctx->encKeyLen = getPubKeyLen(ctx->type);
    ctx->decKeyLen = getPrivKeyLen(ctx->type);

exit:

    if (status != OK) {
        moc_memset_free(&ctx->decKey, pCtx->privLen);
        moc_memset_free(&ctx->encKey, pCtx->ekPkeLen);
    }

    moc_memset(pD, 0x00, MLKEM_SEED_LEN + 1);
    moc_memset(pZ, 0x00, MLKEM_SEED_LEN);

    return status;
}

MOC_EXTERN MSTATUS MLKEM_generateKeyPair(RNGFun rng, void *rngArg, MLKEMCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (rng == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (ctx->encKey != NULL || ctx->decKey != NULL)
        goto exit;

    status = generateKeyPair(rng, rngArg, ctx);
    if (status != OK)
        goto exit;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = MLKEM_generateKey_FIPS_consistency_test(ctx, rng, rngArg)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
MOC_EXTERN MSTATUS
MLKEM_generateKey_FIPS_consistency_test(MLKEMCtx* pCtx, RNGFun rng, void *rngArg)
{
    MSTATUS status = OK;
    sbyte4  cmpRes = 0;

    /* Test 'random' data */
    static const ubyte test[] = {
        0x59, 0xe0, 0x86, 0x9e, 0x3d, 0xd7, 0xec, 0x7f, 0x32, 0xa7, 0xba, 0xcc,
        0x64, 0x5a, 0xde, 0x5c, 0x1a, 0xb1, 0x97, 0xe2, 0xde, 0xa0, 0xd0, 0x4e,
        0xad, 0x1b, 0x76, 0x38, 0x5d, 0xbc, 0xb7, 0x19
    };
    ubyte  *pTest = NULL;

    ubyte  *pK = NULL;
    ubyte  *pKprime = NULL;
    size_t sharedLen = MLKEM_SS_LEN;

    /* Created cipher */
    ubyte  *pCipher = NULL;
    ubyte4 cipherLen = getCipherLen(pCtx->type);

    const MlkemCtx *pOldCtx = MLKEM_getOldCtx(pCtx->type);

    status = DIGI_MALLOC((void**)&pTest, sizeof(test)+MLKEM_PREKEY_LEN);
    if (OK != status)
        goto exit;
    DIGI_MEMCPY(pTest, test, sizeof(test));

    status = DIGI_MALLOC((void**)&pK, sharedLen);
    if (OK != status)
        goto exit;
    status = DIGI_MALLOC((void**)&pKprime, sharedLen);
    if (OK != status)
        goto exit;
    status = DIGI_MALLOC((void**)&pCipher, cipherLen);
    if (OK != status)
        goto exit;

    /* Encapsulate (derived) shared data into cipher and return both */
    status = MLKEM_encaps_internal(MOC_HASH(ctx->hwAccelCtx) pOldCtx, pCtx->encKey, pTest, pCipher, pK);
    if (OK != status)
        goto exit;

    if ( 1 == mlkem_fail )
    {
        pCipher[0] ^= 0xA5;
    }
    mlkem_fail = 0;

    /* Decapsulate cipher and recover shared byte array */
    status = MLKEM_decaps_internal(MOC_HASH(ctx->hwAccelCtx) pOldCtx, pCtx->decKey, pCipher, pKprime);
    if (OK != status)
    {
        status = ERR_FIPS_MLKEM_ENCAPS_DECAPS_FAIL;
        setFIPS_Status(FIPS_ALGO_MLKEM,status);
        goto exit;
    }
    /* Compare both 'versions' of shared data */
    status = DIGI_CTIME_MATCH(pK, pKprime, sharedLen, &cmpRes);
    if (OK != status)
    {
        status = ERR_FIPS_MLKEM_ENCAPS_DECAPS_FAIL;
        setFIPS_Status(FIPS_ALGO_MLKEM,status);
        goto exit;
    }
    if (0 != cmpRes)
    {
        status = ERR_FIPS_MLKEM_ENCAPS_DECAPS_FAIL;
        setFIPS_Status(FIPS_ALGO_MLKEM,status);
        goto exit;
    }

    FIPS_TESTLOG(1030, "MLKEM_generateKey_FIPS_consistency_test: GOOD decapsulated data!");

exit:
    DIGI_FREE((void**)&pCipher);
    DIGI_FREE((void**)&pKprime);
    DIGI_FREE((void**)&pK);
    DIGI_FREE((void**)&pTest);
    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_getPublicKeyLen(MLKEMCtx *ctx, size_t *publicKeyLen)
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

MOC_EXTERN MSTATUS MLKEM_getPublicKey(MLKEMCtx *ctx, uint8_t *publicKey, size_t publicKeyLen)

{
    if (ctx == NULL || publicKey == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    if (ctx->encKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    if (publicKeyLen != ctx->encKeyLen) {
        return ERR_BUFFER_TOO_SMALL;
    }

    return DIGI_MEMCPY(publicKey, ctx->encKey, ctx->encKeyLen);
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_setPublicKey(uint8_t *publicKey, size_t publicKeyLen, MLKEMCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (publicKey == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_PREVIOUSLY_EXISTING_ITEM;
    if (ctx->encKey != NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (publicKeyLen != getPubKeyLen(ctx->type))
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **)&ctx->encKey, publicKeyLen, (void *)publicKey, publicKeyLen);
    if (OK != status)
        goto exit;

    ctx->encKeyLen = publicKeyLen;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return status;
}

MOC_EXTERN MSTATUS MLKEM_getPrivateKeyLen(MLKEMCtx *ctx, size_t *privateKeyLen)
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

MOC_EXTERN MSTATUS MLKEM_getPrivateKey(MLKEMCtx *ctx, uint8_t *privateKey, size_t privateKeyLen)
{
    if (ctx == NULL || privateKey == NULL) {
        return ERR_NULL_POINTER;
    }

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    if (ctx->decKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    if (privateKeyLen != ctx->decKeyLen) {
        return ERR_BUFFER_TOO_SMALL;
    }

    return DIGI_MEMCPY(privateKey, ctx->decKey, ctx->decKeyLen);
}

MOC_EXTERN MSTATUS MLKEM_setPrivateKey(uint8_t *privateKey, size_t privateKeyLen, MLKEMCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (privateKey == NULL || ctx == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_PREVIOUSLY_EXISTING_ITEM;
    if (ctx->decKey != NULL)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (privateKeyLen != getPrivKeyLen(ctx->type))
        goto exit;

    status = DIGI_MALLOC_MEMCPY((void **)&ctx->decKey, privateKeyLen, (void *)privateKey, privateKeyLen);
    if (OK != status)
        goto exit;

    ctx->decKeyLen = privateKeyLen;

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_getCipherTextLen(MLKEMCtx *ctx, size_t *cipherTextLen)
{
    if (ctx == NULL || cipherTextLen == NULL)
        return ERR_NULL_POINTER;

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *cipherTextLen = getCipherLen(ctx->type);

    return OK;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_getSharedSecretLen(MLKEMCtx *ctx, size_t *sharedSecretLen)
{
    if (ctx == NULL || sharedSecretLen == NULL)
        return ERR_NULL_POINTER;

    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    *sharedSecretLen = MLKEM_SS_LEN;

    return OK;
}

/* ------------------------------------------------------------------- */

/* Algorithm 20, ML-KEM.Encaps(ek) */
MOC_EXTERN MSTATUS MLKEM_encapsulate(MLKEMCtx *ctx, RNGFun rngFun, void *rngFunArg, uint8_t *cipherText, size_t cipherTextLen,
                                     uint8_t *sharedSecret, size_t sharedSecretLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || rngFun == NULL || cipherText == NULL || sharedSecret == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->encKey == NULL)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (cipherTextLen != getCipherLen(ctx->type))
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (sharedSecretLen != MLKEM_SS_LEN)
        goto exit;

    status =  encapsulate(ctx, rngFun, rngFunArg, cipherText, sharedSecret);

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

/* Algorithm 21 ML-KEM.Decaps(dk, c) */
MOC_EXTERN MSTATUS MLKEM_decapsulate(MLKEMCtx *ctx, uint8_t *cipherText, size_t cipherTextLen, uint8_t *sharedSecret,
                                     size_t sharedSecretLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;

    /* Special sanity check */
    if (ctx == NULL || cipherText == NULL ||  sharedSecret == NULL)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    status = validateCtx(ctx);
    if (status != OK)
        goto exit;

    status = ERR_UNINITIALIZED_CONTEXT;
    if (ctx->decKey == NULL)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (cipherTextLen != getCipherLen(ctx->type))
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (sharedSecretLen != MLKEM_SS_LEN)
        goto exit;

    status = decapsulate(ctx, cipherText, sharedSecret);

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_cloneCtx(MLKEMCtx *ctx, MLKEMCtx *newCtx)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (ctx == NULL || newCtx == NULL)
        goto exit;

    status = validateCtx(ctx);
    if (status != OK) {
        return status;
    }

    moc_memcpy(newCtx, ctx, sizeof(MLKEMCtx));
    newCtx->decKey = NULL;
    newCtx->encKey = NULL;

    if (ctx->encKey != NULL)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&newCtx->encKey, ctx->encKeyLen, (void *)ctx->encKey, ctx->encKeyLen);
        if (OK != status)
            goto exit;
        newCtx->encKeyLen = ctx->encKeyLen;
    }

    if (ctx->decKey != NULL)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&newCtx->decKey, ctx->decKeyLen, (void *)ctx->decKey, ctx->decKeyLen);
        if (OK != status)
            goto exit;
        newCtx->decKeyLen = ctx->decKeyLen;
    }

exit:
    if (status != OK) {
        MLKEM_destroyCtx(newCtx);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN bool MLKEM_verifyKeyPair(MLKEMCtx *ctx, RNGFun rngFun, void *pRngFunArg)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = ERR_NULL_POINTER;
    MlkemCtx *pCtx;
    ubyte test[MLKEM_SEED_LEN];
    ubyte *pCipher = NULL;
    ubyte k[MLKEM_SS_LEN] = {0};
    ubyte k_prime[MLKEM_SS_LEN] = {0}; 
    bool ret = false;

    /* Special sanity check */
    /* we must have both keys */
    if (NULL == ctx || NULL == ctx->encKey || NULL == ctx->decKey)
        return status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_MLKEM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_MLKEM,ctx->type);

    /* We cannot fully mathematically validate that the public key,
       goes with the private key, ie that t = As + e, 
       since the sigma seed for the error term e was not saved.
       We instead do the keypair check spelled out in Section 7.1. */

    pCtx = (MlkemCtx *) MLKEM_getOldCtx(ctx->type);

    /* this call will validate the length of both keys among other things */
    status = validateCtx(ctx);
    if (OK != status) 
        goto exit;

    /* 1) seed consistency, we no longer have a seed, skip */
    /* 2) check ek as in section 7.2, type (length) already checked */
    status = MLKEM_keyValidityCheck(ctx->encKey, ctx->encKeyLen - MLKEM_SEED_LEN);
    if (OK != status)
        goto exit;

    /* 3) check dk as in Section 7.3, type (length) already checked,
       Validate the hash of the ek */
    status = mlkem_h(MOC_HASH(ctx->hwAccelCtx) ctx->decKey + pCtx->dkPkeLen, pCtx->ekPkeLen, (uint8_t *) test);
    if (OK != status)
        goto exit;
    
    if (0 != moc_memcmp(test, ctx->decKey + pCtx->dkPkeLen + pCtx->ekPkeLen, MLKEM_SEED_LEN))
        goto exit;

    /* validate ekPke is the same in both priv and pub */
    if (0 != moc_memcmp(ctx->encKey, ctx->decKey + pCtx->dkPkeLen, pCtx->ekPkeLen))
        goto exit;

    /* 4) Pairwise consistency, take a random 32 byte seed and rountrip enc/dec creating 2 secrets K and K' */
    if (NULL != rngFun)
    {
        status = (MSTATUS) rngFun(pRngFunArg, MLKEM_SEED_LEN, test);
        if (OK != status)
            goto exit;

        status = DIGI_MALLOC((void **) &pCipher, getCipherLen(ctx->type));
        if (OK != status)
            goto exit;

        status = MLKEM_encaps_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->encKey, test, pCipher, k);
        if (OK != status)
           goto exit;

        status = MLKEM_decaps_internal(MOC_HASH(ctx->hwAccelCtx) pCtx, ctx->decKey, pCipher, k_prime);
        if (OK != status)
            goto exit;

        if (0 != moc_memcmp(k, k_prime, MLKEM_SS_LEN))
            goto exit;
    }

    ret = true;

exit:

    if (NULL != pCipher)
    {
        moc_memset_free(&pCipher, getCipherLen(ctx->type));
    }

    moc_memset(k, 0x00, MLKEM_SS_LEN);
    moc_memset(k_prime, 0x00, MLKEM_SS_LEN);
    moc_memset(test, 0x00, MLKEM_SEED_LEN);

    FIPS_LOG_END_ALG(FIPS_ALGO_MLKEM,ctx->type);
    return ret;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_destroyCtx(MLKEMCtx *ctx)
{
    MSTATUS status = validateCtx(ctx);
    if (status != OK) {
        goto exit;
    }

    moc_memset_free(&ctx->encKey, ctx->encKeyLen);
    moc_memset_free(&ctx->decKey, ctx->decKeyLen);

    moc_memset(ctx, 0, sizeof(*ctx));

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../../crypto/pqc/mlkem_priv.h"

static ubyte4 MLKEM_getCipherLen(const MlkemCtx *pCtx)
{
    return pCtx->cipherLen;
}

static ubyte4 MLKEM_getDKPubLen(const MlkemCtx *pCtx)
{
    return pCtx->dkPkeLen;
}

static ubyte4 MLKEM_getEKPubLen(const MlkemCtx *pCtx)
{
    return pCtx->ekPkeLen;
}

static ubyte4 MLKEM_getPrivLen(const MlkemCtx *pCtx)
{
    return pCtx->privLen;
}

static void MLKEM_triggerFail(void)
{
    mlkem_fail = 1;
}

/* ------------------------------------------------------------------- */

static FIPS_entry_fct mlkem_table[] = {
    { MLKEM_KEY_VALIDITY_CHECK_F_ID, (s_fct*)MLKEM_keyValidityCheck },
    { MLKEM_KEY_HASH_CHECK_F_ID,     (s_fct*)MLKEM_keyHashCheck },
    { MLKEM_KEYGEN_INTERNAL_F_ID,    (s_fct*)MLKEM_keyGen_internal },
    { MLKEM_ENCAPS_INTERNAL_F_ID,    (s_fct*)MLKEM_encaps_internal },
    { MLKEM_DECAPS_INTERNAL_F_ID,    (s_fct*)MLKEM_decaps_internal },
    { MLKEM_GET_OLD_CTX_F_ID,        (s_fct*)MLKEM_getOldCtx },
    { MLKEM_GET_OLD_CIPHER_LEN_F_ID, (s_fct*)MLKEM_getCipherLen},
    { MLKEM_GET_OLD_DK_PUB_LEN_F_ID, (s_fct*)MLKEM_getDKPubLen},
    { MLKEM_GET_OLD_EK_PUB_LEN_F_ID, (s_fct*)MLKEM_getEKPubLen},
    { MLKEM_GET_OLD_PRIV_LEN_F_ID,   (s_fct*)MLKEM_getPrivLen},
    { MLKEM_TRIGGER_FAIL_F_ID,       (s_fct*)MLKEM_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* MLKEM_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return mlkem_table;

    return NULL;
}
#endif  /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#endif /* defined(__ENABLE_DIGICERT_PQC_KEM__) || defined(__ENABLE_DIGICERT_PQC_CAVP_TEST__) */
