/*
 * md4.c
 *
 * Message Digest 4(MD4)
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
#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4_INTERNAL__

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_MD4__) && !defined(__MD4_HARDWARE_HASH__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/md45.h"
#include "../crypto/md4.h"
#include "../harness/harness.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/* Constants for MD4Transform routine.
 */
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

static void MD4Transform(ubyte4 a[4], const ubyte b[64]);

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + (ubyte4)0x5a827999; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + (ubyte4)0x6ed9eba1; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MD4Alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(MD4_CTX), TRUE, pp_context);
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MD4Free(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}


/*---------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MD4Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */

    pCtx->count[0] = pCtx->count[1] = 0;

    /* Load magic initialization constants.
    */
    pCtx->state[0] = 0x67452301;
    pCtx->state[1] = 0xefcdab89;
    pCtx->state[2] = 0x98badcfe;
    pCtx->state[3] = 0x10325476;

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */
    return status;
}


/*---------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MD4Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pContext, const ubyte* input, ubyte4 inputLen)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4 i, index, partLen;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */

    /* Compute number of bytes mod 64 */
    index = (ubyte4)((pContext->count[0] >> 3) & 0x3F);
    /* Update number of bits */
    if ((pContext->count[0] += ((ubyte4)inputLen << 3)) < ((ubyte4)inputLen << 3))
        pContext->count[1]++;
    pContext->count[1] += ((ubyte4)inputLen >> 29);

    partLen = 64 - index;

    /* Transform as many times as possible */
    if (inputLen >= partLen)
    {
        DIGI_MEMCPY(&pContext->buffer[index], input, partLen);
        MD4Transform(pContext->state, pContext->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
        {
            MD4Transform(pContext->state, input+i);
        }
        index = 0;
    }
    else
    {
        i = 0;
    }
    /* Buffer remaining input */
    DIGI_MEMCPY(&pContext->buffer[index], input+i, inputLen-i);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */
    return OK;
}


/*---------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MD4Final (MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX* pCtx, ubyte digest[MD4_DIGESTSIZE])
{
    FIPS_LOG_DECL_SESSION;
    ubyte bits[8];
    ubyte4 index, padLen;

    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */

    /* Save number of bits */
    MD45_encode(bits, pCtx->count, 8);

    /* Pad out to 56 mod 64.
    */
    index = (ubyte4)((pCtx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD4Update(MOC_HASH(hwAccelCtx) pCtx, MD45_PADDING, padLen);

    /* Append length (before padding) */
    MD4Update(MOC_HASH(hwAccelCtx) pCtx, bits, 8);
    /* Store state in digest */
    MD45_encode(digest, pCtx->state, 16);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */
    return status;
}


/*---------------------------------------------------------------------*/

static void MD4Transform (ubyte4 state[4], const ubyte block[64])
{
    ubyte4  a = state[0],
            b = state[1],
            c = state[2],
            d = state[3],
            x[16];

  /* put the block into equivalent ubyte4 */
  MD45_decode(x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11); /* 1 */
  FF (d, a, b, c, x[ 1], S12); /* 2 */
  FF (c, d, a, b, x[ 2], S13); /* 3 */
  FF (b, c, d, a, x[ 3], S14); /* 4 */
  FF (a, b, c, d, x[ 4], S11); /* 5 */
  FF (d, a, b, c, x[ 5], S12); /* 6 */
  FF (c, d, a, b, x[ 6], S13); /* 7 */
  FF (b, c, d, a, x[ 7], S14); /* 8 */
  FF (a, b, c, d, x[ 8], S11); /* 9 */
  FF (d, a, b, c, x[ 9], S12); /* 10 */
  FF (c, d, a, b, x[10], S13); /* 11 */
  FF (b, c, d, a, x[11], S14); /* 12 */
  FF (a, b, c, d, x[12], S11); /* 13 */
  FF (d, a, b, c, x[13], S12); /* 14 */
  FF (c, d, a, b, x[14], S13); /* 15 */
  FF (b, c, d, a, x[15], S14); /* 16 */

  /* Round 2 */
  GG (a, b, c, d, x[ 0], S21); /* 17 */
  GG (d, a, b, c, x[ 4], S22); /* 18 */
  GG (c, d, a, b, x[ 8], S23); /* 19 */
  GG (b, c, d, a, x[12], S24); /* 20 */
  GG (a, b, c, d, x[ 1], S21); /* 21 */
  GG (d, a, b, c, x[ 5], S22); /* 22 */
  GG (c, d, a, b, x[ 9], S23); /* 23 */
  GG (b, c, d, a, x[13], S24); /* 24 */
  GG (a, b, c, d, x[ 2], S21); /* 25 */
  GG (d, a, b, c, x[ 6], S22); /* 26 */
  GG (c, d, a, b, x[10], S23); /* 27 */
  GG (b, c, d, a, x[14], S24); /* 28 */
  GG (a, b, c, d, x[ 3], S21); /* 29 */
  GG (d, a, b, c, x[ 7], S22); /* 30 */
  GG (c, d, a, b, x[11], S23); /* 31 */
  GG (b, c, d, a, x[15], S24); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 0], S31); /* 33 */
  HH (d, a, b, c, x[ 8], S32); /* 34 */
  HH (c, d, a, b, x[ 4], S33); /* 35 */
  HH (b, c, d, a, x[12], S34); /* 36 */
  HH (a, b, c, d, x[ 2], S31); /* 37 */
  HH (d, a, b, c, x[10], S32); /* 38 */
  HH (c, d, a, b, x[ 6], S33); /* 39 */
  HH (b, c, d, a, x[14], S34); /* 40 */
  HH (a, b, c, d, x[ 1], S31); /* 41 */
  HH (d, a, b, c, x[ 9], S32); /* 42 */
  HH (c, d, a, b, x[ 5], S33); /* 43 */
  HH (b, c, d, a, x[13], S34); /* 44 */
  HH (a, b, c, d, x[ 3], S31); /* 45 */
  HH (d, a, b, c, x[11], S32); /* 46 */
  HH (c, d, a, b, x[ 7], S33); /* 47 */
  HH (b, c, d, a, x[15], S34); /* 48 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
MD4_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
                   ubyte4 dataLen, ubyte *pOutput)
{
    FIPS_LOG_DECL_SESSION;
    MD4_CTX mdContext;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD4,0); /* See code below */

    if (OK > (status = MD4Init(MOC_HASH(hwAccelCtx) &mdContext)))
        goto exit;

    if (OK > (status = MD4Update(MOC_HASH(hwAccelCtx) &mdContext, pData, dataLen)))
        goto exit;

    status = MD4Final(MOC_HASH(hwAccelCtx) &mdContext, pOutput);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD4,0);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS 
MD4_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pDest, MD4_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(MD4_CTX));
}
#endif /* defined(__ENABLE_DIGICERT_MD4__) && !defined(__MD4_HARDWARE_HASH__) */
