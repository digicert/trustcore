/*
 * sha1.c
 *
 * SHA - Secure Hash Algorithm
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
@file       sha1.c

@brief      Documentation file for the NanoCrypto SHA1 API.

@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto SHA1 API.

@flags
There are no flag dependencies to enable the functions in the NanoCrypto SHA1 API.

@filedoc    sha1.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"


#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/int64.h"
#include "../crypto/sha1.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../harness/harness.h"


/*------------------------------------------------------------------*/

/* SHA1 functions */
#define K0                      0x5a827999L
#define K1                      0x6ed9eba1L
#define K2                      0x8f1bbcdcL
#define K3                      0xca62c1d6L

#define F1(A, B, C, D, E, msg)   { \
                                  E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + ROTATE_LEFT(A, 5);  \
                                  B  = ROTATE_LEFT(B, 30); \
                                 }

/*
* SHA-1 F2 Function
*/
#define F2(A, B, C, D, E, msg)   { \
                                   E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + ROTATE_LEFT(A, 5);   \
                                   B  = ROTATE_LEFT(B, 30);  \
                                 }

/*
* SHA-1 F3 Function
*/
#define F3(A, B, C, D, E, msg)   {  \
                                   E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + ROTATE_LEFT(A, 5);  \
                                   B  = ROTATE_LEFT(B, 30); \
                                 }

/*
* SHA-1 F4 Function
*/
#define F4(A, B, C, D, E, msg)   {  \
                                   E += (B ^ C ^ D) + msg + 0xCA62C1D6 + ROTATE_LEFT(A, 5);  \
                                   B  = ROTATE_LEFT(B, 30);  \
                                 }
#ifdef __ASM_386_GCC__
#define HOST_c2l(c,l)	{ ubyte4 r=*((ubyte4 *)(c));	\
                          __asm ("bswapl %0":"=r"(r):"0"(r));	\
                          (l)=r; }
#endif
#ifndef __SHA1_HARDWARE_HASH__

/*------------------------------------------------------------------*/

/* local prototypes */
static void sha1_transform(shaDescr *p_shaContext, const ubyte* M);

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_CALLOC((void**)pp_context, 1, sizeof(shaDescr));
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA1 - Before Zeroization\n");
        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pp_context+counter));
        }
        FIPS_PRINT("\n");
#endif

    /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*) *pp_context,0x00,sizeof(shaDescr));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA1 - After Zeroization\n");
        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pp_context+counter));
        }
        FIPS_PRINT("\n");
#endif

    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA1); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA1,0);

    if (NULL == p_shaContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        p_shaContext->hashBlocks[0] = 0x67452301L;
        p_shaContext->hashBlocks[1] = 0xefcdab89L;
        p_shaContext->hashBlocks[2] = 0x98badcfeL;
        p_shaContext->hashBlocks[3] = 0x10325476L;
        p_shaContext->hashBlocks[4] = 0xc3d2e1f0L;

#if __DIGICERT_MAX_INT__ == 64
        p_shaContext->mesgLength = 0;
#else
        p_shaContext->mesgLength.upper32 = 0;
        p_shaContext->mesgLength.lower32 = 0;
#endif

        p_shaContext->hashBufferIndex = 0;

        status = OK;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_SHA1,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, const ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA1); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA1,0);

    if ((NULL == p_shaContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    u8_Incr32( &p_shaContext->mesgLength, dataLen);

    /* some remaining from last time ?*/
    if (p_shaContext->hashBufferIndex > 0)
    {
        sbyte4 numToCopy = SHA1_BLOCK_SIZE - p_shaContext->hashBufferIndex;
        if ( (sbyte4)dataLen < numToCopy)
        {
            numToCopy = dataLen;
        }

        DIGI_MEMCPY( p_shaContext->hashBuffer + p_shaContext->hashBufferIndex, pData, numToCopy);
        pData += numToCopy;
        dataLen -= numToCopy;
        p_shaContext->hashBufferIndex += numToCopy;
        if (SHA1_BLOCK_SIZE == p_shaContext->hashBufferIndex)
        {
            sha1_transform( p_shaContext, p_shaContext->hashBuffer);
            p_shaContext->hashBufferIndex = 0;
        }
    }

    /* process as much as possible right now */
    while ( SHA1_BLOCK_SIZE <= dataLen)
    {
        sha1_transform( p_shaContext, pData);

        dataLen -= SHA1_BLOCK_SIZE;
        pData += SHA1_BLOCK_SIZE;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(p_shaContext->hashBuffer + p_shaContext->hashBufferIndex, pData, dataLen);
        p_shaContext->hashBufferIndex += dataLen;
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SHA1,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *pContext, ubyte *pOutput)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    sbyte4 i;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA1); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA1,0);

    if ((NULL == pContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* we should have room to append one byte onto the message */
    pContext->hashBuffer[pContext->hashBufferIndex] = 0x80;
    pContext->hashBufferIndex++;

    /* less than 8 bytes available -> extra round */
    if ( pContext->hashBufferIndex > SHA1_BLOCK_SIZE - 8)
    {
        while ( pContext->hashBufferIndex < SHA1_BLOCK_SIZE)
        {
            pContext->hashBuffer[pContext->hashBufferIndex++] = 0x00;
        }
        sha1_transform( pContext, pContext->hashBuffer);
        pContext->hashBufferIndex = 0;
    }

    /*last round */
    while ( pContext->hashBufferIndex < SHA1_BLOCK_SIZE - 8)
        {
        pContext->hashBuffer[pContext->hashBufferIndex++] = 0x00;
    }

    /* fill in message bit length */
    /* bytes to bits */
    pContext->mesgLength = u8_Shl( pContext->mesgLength, 3);

    BIGEND32(pContext->hashBuffer+SHA1_BLOCK_SIZE-8, HI_U8(pContext->mesgLength));
    BIGEND32(pContext->hashBuffer+SHA1_BLOCK_SIZE-4, LOW_U8(pContext->mesgLength));


    sha1_transform( pContext, pContext->hashBuffer);

    /* return the output */
    for (i = 0; i < SHA1_RESULT_SIZE/4; ++i)
    {
        BIGEND32( pOutput, pContext->hashBlocks[i]);
        pOutput += 4;
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SHA1,0);
    return status;

} /* SHA1_finalDigest */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SHA1_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *pDest, shaDescr *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(shaDescr));
}

/*------------------------------------------------------------------*/

#ifndef __SHA1_ONE_STEP_HARDWARE_HASH__


extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    FIPS_LOG_DECL_SESSION;
    shaDescr shaContext;
    MSTATUS  status = OK;
#ifdef __ZEROIZE_TEST__
    int counter;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA1); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA1,0);

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext, pData, dataLen)))
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pShaOutput);

exit:
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA1 - Before Zeroization\n");
        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)&shaContext+counter));
        }
        FIPS_PRINT("\n");
#endif
    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((unsigned char *)&shaContext,0x00,sizeof(shaDescr));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA1 - After Zeroization\n");
        for( counter = 0; counter < sizeof(shaDescr); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)&shaContext+counter));
        }
        FIPS_PRINT("\n");
#endif

    FIPS_LOG_END_ALG(FIPS_ALGO_SHA1,0);
    return status;
}

#endif /* __SHA1_ONE_STEP_HARDWARE_HASH__ */

#endif /* __SHA1_HARDWARE_HASH__ */




/*------------------------------------------------------------------*/

#if ((!(defined(__SHA1_HARDWARE_HASH__))) || (!(defined(__DISABLE_DIGICERT_RNG__))))
static void
sha1_transform(SW_SHA1_CTX *p_shaContext, const ubyte* M)
{
#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte4 *W = p_shaContext->W;
#else
    ubyte4 W[80];
#endif
    ubyte4  A, B, C, D, E;
    sbyte4  t;

    /* Wt = Mt for t = 0 to 15 */
    for (t = 0; t < 16; t+=4)
    {
#ifdef __ASM_386_GCC__
        HOST_c2l((M),W[t]);
        M+=4;
        HOST_c2l((M),W[t+1]);
        M+=4;
        HOST_c2l((M),W[t+2]);
        M+=4;
        HOST_c2l((M),W[t+3]);
        M+=4;
#else
        W[t] =  ((ubyte4)(*M++) << 24);
        W[t] |= ((ubyte4)(*M++) << 16);
        W[t] |= ((ubyte4)(*M++) << 8);
        W[t] |=  (ubyte4)(*M++);
        W[t+1] =  ((ubyte4)(*M++) << 24);
        W[t+1] |= ((ubyte4)(*M++) << 16);
        W[t+1] |= ((ubyte4)(*M++) << 8);
        W[t+1] |=  (ubyte4)(*M++);
        W[t+2] =  ((ubyte4)(*M++) << 24);
        W[t+2] |= ((ubyte4)(*M++) << 16);
        W[t+2] |= ((ubyte4)(*M++) << 8);
        W[t+2] |=  (ubyte4)(*M++);
        W[t+3] =  ((ubyte4)(*M++) << 24);
        W[t+3] |= ((ubyte4)(*M++) << 16);
        W[t+3] |= ((ubyte4)(*M++) << 8);
        W[t+3] |=  (ubyte4)(*M++);
#endif
    }

    /* Wt = (Wt-3 XOR Wt-8 XOR Wt-14 XOR Wt-16) <<< 1, for t = 16 to 79 */
    for (; t < 80; t += 8)
    {
         W[t  ] = ROTATE_LEFT((W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]), 1);
         W[t+1] = ROTATE_LEFT((W[t-2] ^ W[t-7] ^ W[t-13] ^ W[t-15]), 1);
         W[t+2] = ROTATE_LEFT((W[t-1] ^ W[t-6] ^ W[t-12] ^ W[t-14]), 1);
         W[t+3] = ROTATE_LEFT((W[t  ] ^ W[t-5] ^ W[t-11] ^ W[t-13]), 1);
         W[t+4] = ROTATE_LEFT((W[t+1] ^ W[t-4] ^ W[t-10] ^ W[t-12]), 1);
         W[t+5] = ROTATE_LEFT((W[t+2] ^ W[t-3] ^ W[t- 9] ^ W[t-11]), 1);
         W[t+6] = ROTATE_LEFT((W[t+3] ^ W[t-2] ^ W[t- 8] ^ W[t-10]), 1);
         W[t+7] = ROTATE_LEFT((W[t+4] ^ W[t-1] ^ W[t- 7] ^ W[t- 9]), 1);
    }

    A = p_shaContext->hashBlocks[0];
    B = p_shaContext->hashBlocks[1];
    C = p_shaContext->hashBlocks[2];
    D = p_shaContext->hashBlocks[3];
    E = p_shaContext->hashBlocks[4];

    F1(A, B, C, D, E, W[ 0]);   F1(E, A, B, C, D, W[ 1]);
    F1(D, E, A, B, C, W[ 2]);   F1(C, D, E, A, B, W[ 3]);
    F1(B, C, D, E, A, W[ 4]);   F1(A, B, C, D, E, W[ 5]);
    F1(E, A, B, C, D, W[ 6]);   F1(D, E, A, B, C, W[ 7]);
    F1(C, D, E, A, B, W[ 8]);   F1(B, C, D, E, A, W[ 9]);
    F1(A, B, C, D, E, W[10]);   F1(E, A, B, C, D, W[11]);
    F1(D, E, A, B, C, W[12]);   F1(C, D, E, A, B, W[13]);
    F1(B, C, D, E, A, W[14]);   F1(A, B, C, D, E, W[15]);
    F1(E, A, B, C, D, W[16]);   F1(D, E, A, B, C, W[17]);
    F1(C, D, E, A, B, W[18]);   F1(B, C, D, E, A, W[19]);

    F2(A, B, C, D, E, W[20]);   F2(E, A, B, C, D, W[21]);
    F2(D, E, A, B, C, W[22]);   F2(C, D, E, A, B, W[23]);
    F2(B, C, D, E, A, W[24]);   F2(A, B, C, D, E, W[25]);
    F2(E, A, B, C, D, W[26]);   F2(D, E, A, B, C, W[27]);
    F2(C, D, E, A, B, W[28]);   F2(B, C, D, E, A, W[29]);
    F2(A, B, C, D, E, W[30]);   F2(E, A, B, C, D, W[31]);
    F2(D, E, A, B, C, W[32]);   F2(C, D, E, A, B, W[33]);
    F2(B, C, D, E, A, W[34]);   F2(A, B, C, D, E, W[35]);
    F2(E, A, B, C, D, W[36]);   F2(D, E, A, B, C, W[37]);
    F2(C, D, E, A, B, W[38]);   F2(B, C, D, E, A, W[39]);

    F3(A, B, C, D, E, W[40]);   F3(E, A, B, C, D, W[41]);
    F3(D, E, A, B, C, W[42]);   F3(C, D, E, A, B, W[43]);
    F3(B, C, D, E, A, W[44]);   F3(A, B, C, D, E, W[45]);
    F3(E, A, B, C, D, W[46]);   F3(D, E, A, B, C, W[47]);
    F3(C, D, E, A, B, W[48]);   F3(B, C, D, E, A, W[49]);
    F3(A, B, C, D, E, W[50]);   F3(E, A, B, C, D, W[51]);
    F3(D, E, A, B, C, W[52]);   F3(C, D, E, A, B, W[53]);
    F3(B, C, D, E, A, W[54]);   F3(A, B, C, D, E, W[55]);
    F3(E, A, B, C, D, W[56]);   F3(D, E, A, B, C, W[57]);
    F3(C, D, E, A, B, W[58]);   F3(B, C, D, E, A, W[59]);

    F4(A, B, C, D, E, W[60]);   F4(E, A, B, C, D, W[61]);
    F4(D, E, A, B, C, W[62]);   F4(C, D, E, A, B, W[63]);
    F4(B, C, D, E, A, W[64]);   F4(A, B, C, D, E, W[65]);
    F4(E, A, B, C, D, W[66]);   F4(D, E, A, B, C, W[67]);
    F4(C, D, E, A, B, W[68]);   F4(B, C, D, E, A, W[69]);
    F4(A, B, C, D, E, W[70]);   F4(E, A, B, C, D, W[71]);
    F4(D, E, A, B, C, W[72]);   F4(C, D, E, A, B, W[73]);
    F4(B, C, D, E, A, W[74]);   F4(A, B, C, D, E, W[75]);
    F4(E, A, B, C, D, W[76]);   F4(D, E, A, B, C, W[77]);
    F4(C, D, E, A, B, W[78]);   F4(B, C, D, E, A, W[79]);

    p_shaContext->hashBlocks[0] += A;
    p_shaContext->hashBlocks[1] += B;
    p_shaContext->hashBlocks[2] += C;
    p_shaContext->hashBlocks[3] += D;
    p_shaContext->hashBlocks[4] += E;
}

/*------------------------------------------------------------------*/


#ifndef __DISABLE_DIGICERT_RNG__
extern MSTATUS
SHA1_G(ubyte *pData, ubyte *pShaOutput)
{
    SW_SHA1_CTX ctx;
    sbyte4      i;

    ctx.hashBlocks[0] = 0x67452301L;
    ctx.hashBlocks[1] = 0xefcdab89L;
    ctx.hashBlocks[2] = 0x98badcfeL;
    ctx.hashBlocks[3] = 0x10325476L;
    ctx.hashBlocks[4] = 0xc3d2e1f0L;

    sha1_transform( &ctx, pData);

    for (i = 0; i < SHA1_RESULT_SIZE/4; ++i)
    {
        BIGEND32( pShaOutput, ctx.hashBlocks[i]);
        pShaOutput += 4;
    }

    return OK;
}
#endif

/*------------------------------------------------------------------*/

#if (!(defined(__DISABLE_DIGICERT_RNG__)))
extern MSTATUS
SHA1_GK(ubyte *pData, ubyte *pShaOutput)
{
    SW_SHA1_CTX ctx;
    sbyte4      i;

    /* cyclic shift of the hash blocks */
    ctx.hashBlocks[4] = 0x67452301L;
    ctx.hashBlocks[0] = 0xefcdab89L;
    ctx.hashBlocks[1] = 0x98badcfeL;
    ctx.hashBlocks[2] = 0x10325476L;
    ctx.hashBlocks[3] = 0xc3d2e1f0L;

    sha1_transform(&ctx, pData);

    for (i = 0; i < SHA1_RESULT_SIZE/4; ++i)
    {
        BIGEND32( pShaOutput, ctx.hashBlocks[i]);
        pShaOutput += 4;
    }

    return OK;
}
#endif


#endif /* ((!(defined(__SHA1_HARDWARE_HASH__))) || (!(defined(__DISABLE_DIGICERT_RNG__)))) */
