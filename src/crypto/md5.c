/*
 * md5.c
 *
 * MD5 Message Digest Algorithm
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __MD5_HARDWARE_HASH__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/int64.h"
#include "../crypto/md5.h"
#include "../crypto/md45.h"
#include "../harness/harness.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/* MD5 non-linear functions */
#define F(X,Y,Z)                ((X & Y) | ((~X) & Z))
#define G(X,Y,Z)                ((X & Z) | ((Y)&(~Z)))
#define H(X,Y,Z)                (X ^ Y ^ Z)
#define I(X,Y,Z)                (Y ^ (X | (~Z)))

/* the four MD5 operations */
#define FF(a,b,c,d,Mj,s,Ti)     a = b + ROTATE_LEFT((a + F(b,c,d) + (Mj) + (ubyte4)(Ti)), (s));
#define GG(a,b,c,d,Mj,s,Ti)     a = b + ROTATE_LEFT((a + G(b,c,d) + (Mj) + (ubyte4)(Ti)), (s));
#define HH(a,b,c,d,Mj,s,Ti)     a = b + ROTATE_LEFT((a + H(b,c,d) + (Mj) + (ubyte4)(Ti)), (s));
#define II(a,b,c,d,Mj,s,Ti)     a = b + ROTATE_LEFT((a + I(b,c,d) + (Mj) + (ubyte4)(Ti)), (s));


/*------------------------------------------------------------------*/

extern MSTATUS
MD5Alloc_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(MD5_CTX), TRUE, pp_context);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD5Free_m(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD5Init_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        pContext->hashBlocks[0] = 0x67452301L;
        pContext->hashBlocks[1] = 0xefcdab89L;
        pContext->hashBlocks[2] = 0x98badcfeL;
        pContext->hashBlocks[3] = 0x10325476L;

        ZERO_U8(pContext->mesgLength);

        pContext->hashBufferIndex = 0;

        status = OK;
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */
    return status;
}


/*------------------------------------------------------------------*/

/* MD5 basic transformation. Transforms state based on block. */
static void
MD5_transform(MD5_CTX *pContext, const ubyte *pData)
{
    ubyte4 a = pContext->hashBlocks[0];
    ubyte4 b = pContext->hashBlocks[1];
    ubyte4 c = pContext->hashBlocks[2];
    ubyte4 d = pContext->hashBlocks[3];
#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte4 *M = pContext->M;
#else
    ubyte4 M[16];
#endif

    MD45_decode(M, pData, 64);

    /* Round 1 */
    FF(a, b, c, d, M[0],   7, 0xd76aa478L);
    FF(d, a, b, c, M[1],  12, 0xe8c7b756L);
    FF(c, d, a, b, M[2],  17, 0x242070dbL);
    FF(b, c, d, a, M[3],  22, 0xc1bdceeeL);
    FF(a, b, c, d, M[4],   7, 0xf57c0fafL);
    FF(d, a, b, c, M[5],  12, 0x4787c62aL);
    FF(c, d, a, b, M[6],  17, 0xa8304613L);
    FF(b, c, d, a, M[7],  22, 0xfd469501L);
    FF(a, b, c, d, M[8],   7, 0x698098d8L);
    FF(d, a, b, c, M[9],  12, 0x8b44f7afL);
    FF(c, d, a, b, M[10], 17, 0xffff5bb1L);
    FF(b, c, d, a, M[11], 22, 0x895cd7beL);
    FF(a, b, c, d, M[12],  7, 0x6b901122L);
    FF(d, a, b, c, M[13], 12, 0xfd987193L);
    FF(c, d, a, b, M[14], 17, 0xa679438eL);
    FF(b, c, d, a, M[15], 22, 0x49b40821L);

    /* Round 2 */
    GG(a, b, c, d, M[1],   5, 0xf61e2562L);
    GG(d, a, b, c, M[6],   9, 0xc040b340L);
    GG(c, d, a, b, M[11], 14, 0x265e5a51L);
    GG(b, c, d, a, M[0],  20, 0xe9b6c7aaL);
    GG(a, b, c, d, M[5],   5, 0xd62f105dL);
    GG(d, a, b, c, M[10],  9, 0x02441453L);
    GG(c, d, a, b, M[15], 14, 0xd8a1e681L);
    GG(b, c, d, a, M[4],  20, 0xe7d3fbc8L);
    GG(a, b, c, d, M[9],   5, 0x21e1cde6L);
    GG(d, a, b, c, M[14],  9, 0xc33707d6L);
    GG(c, d, a, b, M[3],  14, 0xf4d50d87L);
    GG(b, c, d, a, M[8],  20, 0x455a14edL);
    GG(a, b, c, d, M[13],  5, 0xa9e3e905L);
    GG(d, a, b, c, M[2],   9, 0xfcefa3f8L);
    GG(c, d, a, b, M[7],  14, 0x676f02d9L);
    GG(b, c, d, a, M[12], 20, 0x8d2a4c8aL);

    /* Round 3 */
    HH(a, b, c, d, M[5],   4, 0xfffa3942L);
    HH(d, a, b, c, M[8],  11, 0x8771f681L);
    HH(c, d, a, b, M[11], 16, 0x6d9d6122L);
    HH(b, c, d, a, M[14], 23, 0xfde5380cL);
    HH(a, b, c, d, M[1],   4, 0xa4beea44L);
    HH(d, a, b, c, M[4],  11, 0x4bdecfa9L);
    HH(c, d, a, b, M[7],  16, 0xf6bb4b60L);
    HH(b, c, d, a, M[10], 23, 0xbebfbc70L);
    HH(a, b, c, d, M[13],  4, 0x289b7ec6L);
    HH(d, a, b, c, M[0],  11, 0xeaa127faL);
    HH(c, d, a, b, M[3],  16, 0xd4ef3085L);
    HH(b, c, d, a, M[6],  23, 0x04881d05L);
    HH(a, b, c, d, M[9],   4, 0xd9d4d039L);
    HH(d, a, b, c, M[12], 11, 0xe6db99e5L);
    HH(c, d, a, b, M[15], 16, 0x1fa27cf8L);
    HH(b, c, d, a, M[2],  23, 0xc4ac5665L);

    /* Round 4 */
    II(a, b, c, d, M[0],   6, 0xf4292244L);
    II(d, a, b, c, M[7],  10, 0x432aff97L);
    II(c, d, a, b, M[14], 15, 0xab9423a7L);
    II(b, c, d, a, M[5],  21, 0xfc93a039L);
    II(a, b, c, d, M[12],  6, 0x655b59c3L);
    II(d, a, b, c, M[3],  10, 0x8f0ccc92L);
    II(c, d, a, b, M[10], 15, 0xffeff47dL);
    II(b, c, d, a, M[1],  21, 0x85845dd1L);
    II(a, b, c, d, M[8],   6, 0x6fa87e4fL);
    II(d, a, b, c, M[15], 10, 0xfe2ce6e0L);
    II(c, d, a, b, M[6],  15, 0xa3014314L);
    II(b, c, d, a, M[13], 21, 0x4e0811a1L);
    II(a, b, c, d, M[4],   6, 0xf7537e82L);
    II(d, a, b, c, M[11], 10, 0xbd3af235L);
    II(c, d, a, b, M[2],  15, 0x2ad7d2bbL);
    II(b, c, d, a, M[9],  21, 0xeb86d391L);

    pContext->hashBlocks[0] += a;
    pContext->hashBlocks[1] += b;
    pContext->hashBlocks[2] += c;
    pContext->hashBlocks[3] += d;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD5Update_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext, const ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */

    if ((NULL == pContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    u8_Incr32(&pContext->mesgLength, 8 * dataLen);

    /* some remaining from last time ?*/
    if (0 < pContext->hashBufferIndex)
    {
        ubyte4 numToCopy = MD5_BLOCK_SIZE - pContext->hashBufferIndex;

        if (numToCopy > dataLen)
            numToCopy = dataLen;

        DIGI_MEMCPY(pContext->hashBuffer + pContext->hashBufferIndex, pData, numToCopy);

        pData += numToCopy;
        dataLen -= numToCopy;
        pContext->hashBufferIndex += numToCopy;

        if (MD5_BLOCK_SIZE == pContext->hashBufferIndex)
        {
            MD5_transform(pContext, pContext->hashBuffer);
            pContext->hashBufferIndex = 0;
        }
    }

    /* process as much as possible right now */
    while (MD5_BLOCK_SIZE <= dataLen)
    {
        MD5_transform(pContext, pData);

        dataLen -= MD5_BLOCK_SIZE;
        pData   += MD5_BLOCK_SIZE;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(pContext->hashBuffer + pContext->hashBufferIndex, pData, dataLen);
        pContext->hashBufferIndex += dataLen;
    }

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MD5Final_m(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext, ubyte pMd5Output[MD5_DIGESTSIZE])
{
    FIPS_LOG_DECL_SESSION;
    ubyte4  bitCount[2];
    ubyte   bits[8];
    ubyte4  count;
    ubyte4  padLen;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */

    if ((NULL == pContext) || (NULL == pMd5Output))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* make bit count */
    bitCount[0] = LOW_U8(pContext->mesgLength);
    bitCount[1] = HI_U8(pContext->mesgLength);   /* will likely always be zero... */

    MD45_encode(bits, bitCount, 8);

    /* calc pad length */
    count = (ubyte4)((bitCount[0] >> 3) & 0x3f);

    padLen = ((MD5_BLOCK_SIZE - 8) <= count) ?
        ((MD5_BLOCK_SIZE + (MD5_BLOCK_SIZE - 8)) - count) : ((MD5_BLOCK_SIZE - 8) - count);
    /* hash pad */
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, MD45_PADDING, padLen)))
        goto exit;

    /* hash bit length */
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, bits, 8)))
        goto exit;

    /* output final hash */
    MD45_encode((ubyte *) pMd5Output, pContext->hashBlocks, MD5_DIGESTSIZE);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS 
MD5_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pDest, MD5_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(MD5_CTX));
}

/*------------------------------------------------------------------*/

#ifndef __MD5_ONE_STEP_HARDWARE_HASH__

extern MSTATUS
MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    FIPS_LOG_DECL_SESSION;
    MD5_CTX mdContext;
    MSTATUS status = OK;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */

    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) &mdContext)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) &mdContext, pData, dataLen)))
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCtx) &mdContext, pMdOutput);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_MD5,0); /* See code below */
    return status;
}

#endif /* __MD5_ONE_STEP_HARDWARE_HASH__ */

#endif /* __MD5_HARDWARE_HASH__ */
