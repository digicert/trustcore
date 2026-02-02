/*
 * sha3.c
 *
 * Methods for sha3 operations.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SHA3__

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/int64.h"
#include "../common/mocana.h"

#include "../crypto/hw_accel.h"
#ifndef __SHA3_HARDWARE_HASH__

#include "../crypto/sha3.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

/*---------------------------------------------------------------------------*/

#define SHA3_NUM_ROUNDS 24
#define SHA3_MAX_RATE 200

#if __DIGICERT_MAX_INT__ == 64

#define GET_LOW_BYTE( a) ((ubyte) (a & 0xffULL))
#define SET_LOW_BYTE( a) (ubyte8) a

#else

#define GET_LOW_BYTE( a) ((ubyte) (a.lower32 & 0xff))

static MOC_INLINE ubyte8 SET_LOW_BYTE(ubyte a)
{
    ubyte8 temp = {0,0};
    temp.lower32 = (ubyte4) a;

    return temp;
}

#endif /* __DIGICERT_MAX_INT__ == 64 */

#define ROTATE_LEFT_64( a, bits) u8_Or( u8_Shl(a,bits), u8_Shr(a,64-bits) )

/* The (maximum) output length in bytes of each of the first 4 Sha3 modes */
static const ubyte4 gpSha3OutLenTable[4] = {28, 32, 48, 64};

/* The rate in bytes (ie block size) of the Sha3 modes */
static const ubyte4 gpSha3RateTable[6] = {144, 136, 104, 72, 168, 136};

/* The padding byte (or domain byte) per sha mode */
static const ubyte gpSha3paddingByte[6] = {0x06, 0x06, 0x06, 0x06, 0x1f, 0x1f};

static const ubyte gpRhotates[5][5] =
{
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};


static const ubyte8 gpIotas[SHA3_NUM_ROUNDS] =
{
#if __DIGICERT_MAX_INT__ == 64
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
#else
    {0x00000000,0x00000001},
    {0x00000000,0x00008082},
    {0x80000000,0x0000808a},
    {0x80000000,0x80008000},
    {0x00000000,0x0000808b},
    {0x00000000,0x80000001},
    {0x80000000,0x80008081},
    {0x80000000,0x00008009},
    {0x00000000,0x0000008a},
    {0x00000000,0x00000088},
    {0x00000000,0x80008009},
    {0x00000000,0x8000000a},
    {0x00000000,0x8000808b},
    {0x80000000,0x0000008b},
    {0x80000000,0x00008089},
    {0x80000000,0x00008003},
    {0x80000000,0x00008002},
    {0x80000000,0x00000080},
    {0x00000000,0x0000800a},
    {0x80000000,0x8000000a},
    {0x80000000,0x80008081},
    {0x80000000,0x00008080},
    {0x00000000,0x80000001},
    {0x80000000,0x80008008}
#endif /* __DIGICERT_MAX_INT__ == 64 */
};

/*
 We perform a single round in one method. See Section 2.4
 of "Keccak implementation overview" for this plane-per-plane
 processing approach and section 2.2 for the lane complementing
 transform.
 */
static void SHA3_performRound(ubyte8 pOutState[5][5], ubyte8 pInState[5][5], ubyte4 roundNum)
{
    ubyte8 pC[5];
    ubyte8 pD[5];

    pC[0] = pInState[0][0] ^ pInState[1][0] ^ pInState[2][0] ^ pInState[3][0] ^ pInState[4][0];
    pC[1] = pInState[0][1] ^ pInState[1][1] ^ pInState[2][1] ^ pInState[3][1] ^ pInState[4][1];
    pC[2] = pInState[0][2] ^ pInState[1][2] ^ pInState[2][2] ^ pInState[3][2] ^ pInState[4][2];
    pC[3] = pInState[0][3] ^ pInState[1][3] ^ pInState[2][3] ^ pInState[3][3] ^ pInState[4][3];
    pC[4] = pInState[0][4] ^ pInState[1][4] ^ pInState[2][4] ^ pInState[3][4] ^ pInState[4][4];

    pD[0] = ROTATE_LEFT_64(pC[1], 1) ^ pC[4];
    pD[1] = ROTATE_LEFT_64(pC[2], 1) ^ pC[0];
    pD[2] = ROTATE_LEFT_64(pC[3], 1) ^ pC[1];
    pD[3] = ROTATE_LEFT_64(pC[4], 1) ^ pC[2];
    pD[4] = ROTATE_LEFT_64(pC[0], 1) ^ pC[3];

    pC[0] = pInState[0][0] ^ pD[0];
    pC[1] = ROTATE_LEFT_64(pInState[1][1] ^ pD[1], gpRhotates[1][1]);
    pC[2] = ROTATE_LEFT_64(pInState[2][2] ^ pD[2], gpRhotates[2][2]);
    pC[3] = ROTATE_LEFT_64(pInState[3][3] ^ pD[3], gpRhotates[3][3]);
    pC[4] = ROTATE_LEFT_64(pInState[4][4] ^ pD[4], gpRhotates[4][4]);

    pOutState[0][0] = pC[0] ^ ( pC[1] | pC[2]) ^ gpIotas[roundNum];
    pOutState[0][1] = pC[1] ^ (~pC[2] | pC[3]);
    pOutState[0][2] = pC[2] ^ ( pC[3] & pC[4]);
    pOutState[0][3] = pC[3] ^ ( pC[4] | pC[0]);
    pOutState[0][4] = pC[4] ^ ( pC[0] & pC[1]);

    pC[0] = ROTATE_LEFT_64(pInState[0][3] ^ pD[3], gpRhotates[0][3]);
    pC[1] = ROTATE_LEFT_64(pInState[1][4] ^ pD[4], gpRhotates[1][4]);
    pC[2] = ROTATE_LEFT_64(pInState[2][0] ^ pD[0], gpRhotates[2][0]);
    pC[3] = ROTATE_LEFT_64(pInState[3][1] ^ pD[1], gpRhotates[3][1]);
    pC[4] = ROTATE_LEFT_64(pInState[4][2] ^ pD[2], gpRhotates[4][2]);

    pOutState[1][0] = pC[0] ^ (pC[1] |  pC[2]);
    pOutState[1][1] = pC[1] ^ (pC[2] &  pC[3]);
    pOutState[1][2] = pC[2] ^ (pC[3] | ~pC[4]);
    pOutState[1][3] = pC[3] ^ (pC[4] |  pC[0]);
    pOutState[1][4] = pC[4] ^ (pC[0] &  pC[1]);

    pC[0] = ROTATE_LEFT_64(pInState[0][1] ^ pD[1], gpRhotates[0][1]);
    pC[1] = ROTATE_LEFT_64(pInState[1][2] ^ pD[2], gpRhotates[1][2]);
    pC[2] = ROTATE_LEFT_64(pInState[2][3] ^ pD[3], gpRhotates[2][3]);
    pC[3] = ROTATE_LEFT_64(pInState[3][4] ^ pD[4], gpRhotates[3][4]);
    pC[4] = ROTATE_LEFT_64(pInState[4][0] ^ pD[0], gpRhotates[4][0]);

    pOutState[2][0] =  pC[0] ^ ( pC[1] | pC[2]);
    pOutState[2][1] =  pC[1] ^ ( pC[2] & pC[3]);
    pOutState[2][2] =  pC[2] ^ (~pC[3] & pC[4]);
    pOutState[2][3] = ~pC[3] ^ ( pC[4] | pC[0]);
    pOutState[2][4] =  pC[4] ^ ( pC[0] & pC[1]);

    pC[0] = ROTATE_LEFT_64(pInState[0][4] ^ pD[4], gpRhotates[0][4]);
    pC[1] = ROTATE_LEFT_64(pInState[1][0] ^ pD[0], gpRhotates[1][0]);
    pC[2] = ROTATE_LEFT_64(pInState[2][1] ^ pD[1], gpRhotates[2][1]);
    pC[3] = ROTATE_LEFT_64(pInState[3][2] ^ pD[2], gpRhotates[3][2]);
    pC[4] = ROTATE_LEFT_64(pInState[4][3] ^ pD[3], gpRhotates[4][3]);

    pOutState[3][0] =  pC[0] ^ ( pC[1] & pC[2]);
    pOutState[3][1] =  pC[1] ^ ( pC[2] | pC[3]);
    pOutState[3][2] =  pC[2] ^ (~pC[3] | pC[4]);
    pOutState[3][3] = ~pC[3] ^ ( pC[4] & pC[0]);
    pOutState[3][4] =  pC[4] ^ ( pC[0] | pC[1]);

    pC[0] = ROTATE_LEFT_64(pInState[0][2] ^ pD[2], gpRhotates[0][2]);
    pC[1] = ROTATE_LEFT_64(pInState[1][3] ^ pD[3], gpRhotates[1][3]);
    pC[2] = ROTATE_LEFT_64(pInState[2][4] ^ pD[4], gpRhotates[2][4]);
    pC[3] = ROTATE_LEFT_64(pInState[3][0] ^ pD[0], gpRhotates[3][0]);
    pC[4] = ROTATE_LEFT_64(pInState[4][1] ^ pD[1], gpRhotates[4][1]);

    pOutState[4][0] =  pC[0] ^ (~pC[1] & pC[2]);
    pOutState[4][1] = ~pC[1] ^ ( pC[2] | pC[3]);
    pOutState[4][2] =  pC[2] ^ ( pC[3] & pC[4]);
    pOutState[4][3] =  pC[3] ^ ( pC[4] | pC[0]);
    pOutState[4][4] =  pC[4] ^ ( pC[0] & pC[1]);
}

static void SHA3_keccak(ubyte8 pState[5][5])
{
    ubyte8 pTempState[5][5];

    /* Complements needed for the lane complementing transform */
    pState[0][1] = ~pState[0][1];
    pState[0][2] = ~pState[0][2];
    pState[1][3] = ~pState[1][3];
    pState[2][2] = ~pState[2][2];
    pState[3][2] = ~pState[3][2];
    pState[4][0] = ~pState[4][0];

    SHA3_performRound(pTempState, pState, 0);
    SHA3_performRound(pState, pTempState, 1);
    SHA3_performRound(pTempState, pState, 2);
    SHA3_performRound(pState, pTempState, 3);
    SHA3_performRound(pTempState, pState, 4);
    SHA3_performRound(pState, pTempState, 5);
    SHA3_performRound(pTempState, pState, 6);
    SHA3_performRound(pState, pTempState, 7);
    SHA3_performRound(pTempState, pState, 8);
    SHA3_performRound(pState, pTempState, 9);
    SHA3_performRound(pTempState, pState, 10);
    SHA3_performRound(pState, pTempState, 11);
    SHA3_performRound(pTempState, pState, 12);
    SHA3_performRound(pState, pTempState, 13);
    SHA3_performRound(pTempState, pState, 14);
    SHA3_performRound(pState, pTempState, 15);
    SHA3_performRound(pTempState, pState, 16);
    SHA3_performRound(pState, pTempState, 17);
    SHA3_performRound(pTempState, pState, 18);
    SHA3_performRound(pState, pTempState, 19);
    SHA3_performRound(pTempState, pState, 20);
    SHA3_performRound(pState, pTempState, 21);
    SHA3_performRound(pTempState, pState, 22);
    SHA3_performRound(pState, pTempState, 23);

    /* un-complement */
    pState[0][1] = ~pState[0][1];
    pState[0][2] = ~pState[0][2];
    pState[1][3] = ~pState[1][3];
    pState[2][2] = ~pState[2][2];
    pState[3][2] = ~pState[3][2];
    pState[4][0] = ~pState[4][0];
}


/*
 Method to absorb numBlocks, each block having a byte length of rate. pMessage must be
 precisely numBlocks * rate bytes.
 */
static MSTATUS SHA3_absorb_blocks(ubyte8 pState[5][5], ubyte *pMessage, ubyte4 numBlocks, ubyte4 rate)
{
    ubyte *pMsgPtr = pMessage;
    ubyte8 temp;
    ubyte4 w = rate/8;
    ubyte4 i,j;

    /* internal method, skip null check, but do perform sanity check on the rate */
    if (rate > SHA3_MAX_RATE || ( (rate & 0x07) != 0x00 ) ) /* rate mod 8 */
        return ERR_SHA3;

    for (i = 0; i < numBlocks; ++i)
    {
        for (j = 0; j < w; ++j)
        {
            temp = u8_Or(u8_Or( u8_Or(        SET_LOW_BYTE(pMsgPtr[0]),      u8_Shl(SET_LOW_BYTE(pMsgPtr[1]),  8)),
                                u8_Or( u8_Shl(SET_LOW_BYTE(pMsgPtr[2]), 16), u8_Shl(SET_LOW_BYTE(pMsgPtr[3]), 24))),
                         u8_Or( u8_Or( u8_Shl(SET_LOW_BYTE(pMsgPtr[4]), 32), u8_Shl(SET_LOW_BYTE(pMsgPtr[5]), 40)),
                                u8_Or( u8_Shl(SET_LOW_BYTE(pMsgPtr[6]), 48), u8_Shl(SET_LOW_BYTE(pMsgPtr[7]), 56))));

            ((ubyte8 *)pState)[j] = u8_Xor(((ubyte8 *)pState)[j], temp);
            pMsgPtr += 8;
        }

        SHA3_keccak(pState);
    }

    return OK;
}


/*
 Method to squeeze desiredResultLen bytes out of the state. pResult must be big enough to hold
 that many bytes. rate must be a multiple of 8 and no bigger than 200.
 */
static MSTATUS SHA3_squeeze(ubyte8 pState[5][5], ubyte *pResult, ubyte4 desiredResultLen, ubyte4 rate)
{
    ubyte *pResPtr = pResult;
    ubyte8 temp;
    ubyte4 w = rate/8;
    ubyte4  i,j;

    /* internal method, skip null check, but do perform sanity check on the rate */
    if (rate > SHA3_MAX_RATE || ( (rate & 0x07) != 0x00 ) ) /* rate mod 8 */
        return ERR_SHA3;

    while (desiredResultLen != 0)
    {
        for (i = 0; ( (i < w) && (desiredResultLen != 0) ); ++i)
        {
            temp = ((ubyte8 *)pState)[i];

            if (desiredResultLen < 8)
            {
                for (j = 0; j < desiredResultLen; ++j)
                {
                    *pResPtr++ = GET_LOW_BYTE(temp);
                    temp = u8_Shr(temp, 8);
                }
                goto exit;
            }

            pResPtr[0] = GET_LOW_BYTE(temp);
            pResPtr[1] = GET_LOW_BYTE(u8_Shr(temp, 8));
            pResPtr[2] = GET_LOW_BYTE(u8_Shr(temp, 16));
            pResPtr[3] = GET_LOW_BYTE(u8_Shr(temp, 24));
            pResPtr[4] = GET_LOW_BYTE(u8_Shr(temp, 32));
            pResPtr[5] = GET_LOW_BYTE(u8_Shr(temp, 40));
            pResPtr[6] = GET_LOW_BYTE(u8_Shr(temp, 48));
            pResPtr[7] = GET_LOW_BYTE(u8_Shr(temp, 56));

            pResPtr += 8;
            desiredResultLen -= 8;
        }
        if (desiredResultLen)
        {
            SHA3_keccak(pState);
        }
    }

exit:

    return OK;
}


/* Allocates an empty ctx */
MOC_EXTERN MSTATUS SHA3_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx)
{
    if (NULL == pSha3_ctx)
        return ERR_NULL_POINTER;

    return DIGI_CALLOC((void**)pSha3_ctx, 1, sizeof(SHA3_CTX));
}


/*
 Initializes a sha3 ctx. mode must be one of the SHA3_MODE_...
 macros defined in sha3.h
 */
MOC_EXTERN MSTATUS SHA3_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte4 mode)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;

    MSTATUS status = OK;

    if (NULL == pSha3_ctx)
        return ERR_NULL_POINTER;
    /* an already initialized ctx had no dynamic memory allocation so no need to worry about it */

    if (mode > MOCANA_SHA3_MODE_SHAKE256)
        return ERR_SHA3_INVALID_MODE;

    FIPS_GET_SHA3_FALGO(FAlgoId,mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    pSha3_ctx->position = 0;
    pSha3_ctx->mode = mode;

    status = DIGI_MEMSET((ubyte *) pSha3_ctx->pState, 0x00, sizeof(pSha3_ctx->pState));
    if (OK == status)
        pSha3_ctx->initialized = TRUE;

    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;
}


/*
 Updates the sha3 ctx with the data in pMessage. pMessage is allowed to be NULL if
 messageLen is zero.
 */
MOC_EXTERN MSTATUS SHA3_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pMessage, ubyte4 messageLen)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;

    MSTATUS status = OK;
    ubyte *pMsgPtr = pMessage;
    ubyte4 bytesNeeded;
    ubyte4 messageLeft = messageLen;
    ubyte4 rate;

    if (NULL == pSha3_ctx || (NULL == pMessage && messageLen) )
        return ERR_NULL_POINTER;

    if ( !(pSha3_ctx->initialized) )
        return ERR_SHA3_UNINITIALIZED_CTX;

    if (!messageLen)
        return OK;

    FIPS_GET_SHA3_FALGO(FAlgoId,pSha3_ctx->mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    rate = gpSha3RateTable[pSha3_ctx->mode];

    /* Process bytes leftover in pBuffer */
    bytesNeeded = rate - pSha3_ctx->position;

    if (messageLen < bytesNeeded)
    {

        status = DIGI_MEMCPY( &(pSha3_ctx->pBuffer[pSha3_ctx->position]), pMsgPtr, messageLen);
        if (OK != status)
            goto exit;

        pSha3_ctx->position += messageLen;
        goto exit;  /* no more message left anyway */

    }
    else
    {
        status = DIGI_MEMCPY( &(pSha3_ctx->pBuffer[pSha3_ctx->position]), pMsgPtr, bytesNeeded);
        if (OK != status)
            goto exit;

        /* just 1 block */
        status = SHA3_absorb_blocks(pSha3_ctx->pState, pSha3_ctx->pBuffer, 1, rate);
        if (OK != status)
            goto exit;

        pMsgPtr += bytesNeeded;
        messageLeft -= bytesNeeded;
        pSha3_ctx->position = 0;
    }

    /* Process as many blocks of the message as we can */
    if (messageLeft >= rate)
    {
        ubyte4 numBlocks = messageLeft/rate;
        status = SHA3_absorb_blocks(pSha3_ctx->pState, pMsgPtr, numBlocks, rate);
        if (OK != status)
            goto exit;

        pMsgPtr += numBlocks * rate;
        messageLeft -= numBlocks * rate;
    }

    /* Copy any leftovers to the buffer */
    if (messageLeft)
    {
        status = DIGI_MEMCPY( pSha3_ctx->pBuffer, pMsgPtr, messageLeft);
        if (OK != status)
            goto exit;

        pSha3_ctx->position = messageLeft;
    }

exit:

    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;
}


/*
 Finalizes the sha3 ctx (ie pads the message) and writes the output to pResult. For the non
 extendable output modes the standard number of bytes for each mode are written. For extendable
 output modes the desired number of bytes is passed in via the desiredResultLen parameter.
 In any case it is up to the caller to make sure pResult has enough space.
 */
MOC_EXTERN MSTATUS SHA3_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;

    MSTATUS status = OK;
    ubyte4 rate;

    if (NULL == pSha3_ctx || NULL == pResult)
        return ERR_NULL_POINTER;

    if ( !(pSha3_ctx->initialized) )
        return ERR_SHA3_UNINITIALIZED_CTX;

    FIPS_GET_SHA3_FALGO(FAlgoId,pSha3_ctx->mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    /* Ignore desiredResultLen if not an XOF mode, get the fixed desiredResultLen */
    if (pSha3_ctx->mode < MOCANA_SHA3_MODE_SHAKE128)
        desiredResultLen = gpSha3OutLenTable[pSha3_ctx->mode];

    rate = gpSha3RateTable[pSha3_ctx->mode];

    /* handle padding, we always pad at leest one byte, even in the case the data was a full block length */
    pSha3_ctx->pBuffer[pSha3_ctx->position] = gpSha3paddingByte[pSha3_ctx->mode];
    pSha3_ctx->position++;

    /* if we have room in the buffer, 0x00 pad */
    if (pSha3_ctx->position < rate)
    {
        status = DIGI_MEMSET(&(pSha3_ctx->pBuffer[pSha3_ctx->position]), 0x00, rate - pSha3_ctx->position );
        if (OK != status)
            goto exit;

        /* essentially done, no need to increment pSha3_ctx->position */
    }

    /* last byte in buffer (whether the leading padding byte or a 0x00), always has its first bit set */
    pSha3_ctx->pBuffer[rate - 1] |= 0x80;

    /* final block */
    status = SHA3_absorb_blocks(pSha3_ctx->pState, pSha3_ctx->pBuffer, 1, rate);
    if (OK != status)
        goto exit;

    /* ready to squeeze out some results */
    status = SHA3_squeeze(pSha3_ctx->pState, pResult, desiredResultLen, rate);

exit:

    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;
}

/* desiredResultLen must be a multiple of the rate and same with previous calls to SHA3_finalDigest */
MOC_EXTERN MSTATUS SHA3_additionalXOF(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pSha3_ctx, ubyte *pResult, ubyte4 desiredResultLen)
{
    ubyte4 rate;

    if (NULL == pSha3_ctx || NULL == pResult)
        return ERR_NULL_POINTER;

    if ( !(pSha3_ctx->initialized) )
        return ERR_SHA3_UNINITIALIZED_CTX;

    if (pSha3_ctx->mode < MOCANA_SHA3_MODE_SHAKE128)
        return ERR_SHA3_INVALID_MODE;

    rate = gpSha3RateTable[pSha3_ctx->mode];

    /* we only allow this API to output full blocks at a time, ie blocks of rate bytes */
    if (0 == desiredResultLen || 0 != (desiredResultLen % rate))
        return ERR_INVALID_INPUT;

    /* the full block in the call to SHA3_finalDigest did not call SHA3_keccak after it, so call now */
    SHA3_keccak(pSha3_ctx->pState);
    return SHA3_squeeze(pSha3_ctx->pState, pResult, desiredResultLen, rate);
}


/* A one shot ctx free API that just uses the above APIs for simplicity */
MOC_EXTERN MSTATUS SHA3_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 mode, ubyte *pMessage, ubyte4 messageLen, ubyte *pResult, ubyte4 desiredResultLen)
{
    FIPS_LOG_DECL_SESSION;
    FIPS_LOG_DECL_FALGO;

    MSTATUS status = OK;
    SHA3_CTX *pSha3Ctx = NULL;

    FIPS_GET_SHA3_FALGO(FAlgoId,mode);
    FIPS_GET_STATUS_RETURN_IF_BAD(FAlgoId); /* may return here */
    FIPS_LOG_START_ALG(FAlgoId,0);

    /* Input param validation will be handled by the below called methods */

    status = SHA3_allocDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    if (OK != status)
        goto exit;

    status = SHA3_initDigest(MOC_HASH(hwAccelCtx) pSha3Ctx, mode);
    if (OK != status)
        goto exit;

    status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) pSha3Ctx, pMessage, messageLen);
    if (OK != status)
        goto exit;

    status = SHA3_finalDigest(MOC_HASH(hwAccelCtx) pSha3Ctx, pResult, desiredResultLen);

exit:
    if (NULL != pSha3Ctx)
    {
        /* ok to ignore return code, don't change status */
        SHA3_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx *) &pSha3Ctx);
    }

    FIPS_LOG_END_ALG(FAlgoId,0);
    return status;
}


/* zeros and frees a context */
MOC_EXTERN MSTATUS SHA3_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pSha3_ctx)
{
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    if (NULL == pSha3_ctx)
        return ERR_NULL_POINTER;

    if (NULL == *pSha3_ctx) /* no op, nothing to free */
        return OK;

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nSHA3 - Before Zeroization\n");
    for( counter = 0; counter < sizeof(SHA3_CTX); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*pSha3_ctx+counter));
    }
    FIPS_PRINT("\n");
#endif

    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((ubyte*) *pSha3_ctx, 0x00, sizeof(SHA3_CTX));

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nSHA3 - After Zeroization\n");
    for( counter = 0; counter < sizeof(SHA3_CTX); counter++)
    {
        FIPS_PRINT("%02x",*((ubyte*)*pSha3_ctx+counter));
    }
    FIPS_PRINT("\n");
#endif

    return DIGI_FREE((void**) pSha3_ctx);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SHA3_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pDest, SHA3_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(SHA3_CTX));
}
#endif /* __SHA3_HARDWARE_HASH__ */
#endif /* __ENABLE_DIGICERT_SHA3__ */
