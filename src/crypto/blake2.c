/*
 * blake2.c
 *
 * Blake2 hash or mac algorithms
 *
 * See RFC 7693 for more information.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2B_INTERNAL__
#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2S_INTERNAL__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/merrors.h"
#include "../crypto/hw_accel.h"

#ifndef __BLAKE2_HARDWARE_ACCELERATOR__

#include "../crypto/blake2.h"
#include "../common/mstdlib.h"

/* ----------------------------------- BLAKE 2B ----------------------------------- */

#if defined(__ENABLE_DIGICERT_BLAKE_2B__)

#if __DIGICERT_MAX_INT__ == 32
#error BLAKE_2B can only be enabled for 64 bit builds
#endif

#define ROTR64( word, bytes) (((word) >> bytes) | ((word) << ( 64 - bytes)))

#define GB(r,i,a,b,c,d)                        \
do {                                           \
a = a + b + pM[BLAKE2B_sigma[r][2*i+0]]; \
d = ROTR64(d ^ a, 32);                         \
c = c + d;                                     \
b = ROTR64(b ^ c, 24);                         \
a = a + b + pM[BLAKE2B_sigma[r][2*i+1]]; \
d = ROTR64(d ^ a, 16);                         \
c = c + d;                                     \
b = ROTR64(b ^ c, 63);                         \
} while(0)

#define ROUND_B(r)                   \
do {                                 \
GB(r,0,pV[ 0],pV[ 4],pV[ 8],pV[12]); \
GB(r,1,pV[ 1],pV[ 5],pV[ 9],pV[13]); \
GB(r,2,pV[ 2],pV[ 6],pV[10],pV[14]); \
GB(r,3,pV[ 3],pV[ 7],pV[11],pV[15]); \
GB(r,4,pV[ 0],pV[ 5],pV[10],pV[15]); \
GB(r,5,pV[ 1],pV[ 6],pV[11],pV[12]); \
GB(r,6,pV[ 2],pV[ 7],pV[ 8],pV[13]); \
GB(r,7,pV[ 3],pV[ 4],pV[ 9],pV[14]); \
} while(0)

static const ubyte8 BLAKE2B_IV[8] =
{
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const ubyte BLAKE2B_sigma[12][16] =
{
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#ifndef MOC_LITTLE_ENDIAN
static MOC_INLINE ubyte8 toUbyte8(ubyte *pSrc)
{
    return (( ubyte8 )( pSrc[0] ) <<  0) |
    (( ubyte8 )( pSrc[1] ) <<  8) |
    (( ubyte8 )( pSrc[2] ) << 16) |
    (( ubyte8 )( pSrc[3] ) << 24) |
    (( ubyte8 )( pSrc[4] ) << 32) |
    (( ubyte8 )( pSrc[5] ) << 40) |
    (( ubyte8 )( pSrc[6] ) << 48) |
    (( ubyte8 )( pSrc[7] ) << 56);
}

static MOC_INLINE void fromUbyte8(ubyte *pDest, ubyte8 src)
{
    pDest[0] = (ubyte)(src >>  0);
    pDest[1] = (ubyte)(src >>  8);
    pDest[2] = (ubyte)(src >> 16);
    pDest[3] = (ubyte)(src >> 24);
    pDest[4] = (ubyte)(src >> 32);
    pDest[5] = (ubyte)(src >> 40);
    pDest[6] = (ubyte)(src >> 48);
    pDest[7] = (ubyte)(src >> 56);
}
#endif


static MOC_INLINE void BLAKE2B_incCtr( BLAKE2B_CTX *pCtx, ubyte8 inc )
{
    pCtx->pT[0] += inc;
    pCtx->pT[1] += ( pCtx->pT[0] < inc );
}


static void BLAKE2B_compress( BLAKE2B_CTX *pCtx, ubyte pBlock[MOC_BLAKE2B_BLOCKLEN] )
{
    ubyte8 pM[16] = {0};
    ubyte8 pV[16] = {0};
    ubyte4 i = 0;

#ifdef MOC_LITTLE_ENDIAN
    /* ok to ignore DIGI_MEMCPY return code */
    DIGI_MEMCPY((ubyte *) pM, pBlock, MOC_BLAKE2B_BLOCKLEN);
#else
    for(; i < 16; ++i )
    {
        pM[i] = toUbyte8(pBlock + i * sizeof(ubyte8));
    }
#endif

    DIGI_MEMCPY(pV, pCtx->pH, 8 * sizeof(ubyte8));

    pV[ 8] = BLAKE2B_IV[0];
    pV[ 9] = BLAKE2B_IV[1];
    pV[10] = BLAKE2B_IV[2];
    pV[11] = BLAKE2B_IV[3];
    pV[12] = BLAKE2B_IV[4] ^ pCtx->pT[0];
    pV[13] = BLAKE2B_IV[5] ^ pCtx->pT[1];
    pV[14] = BLAKE2B_IV[6] ^ pCtx->f;
    pV[15] = BLAKE2B_IV[7];

    ROUND_B( 0 );
    ROUND_B( 1 );
    ROUND_B( 2 );
    ROUND_B( 3 );
    ROUND_B( 4 );
    ROUND_B( 5 );
    ROUND_B( 6 );
    ROUND_B( 7 );
    ROUND_B( 8 );
    ROUND_B( 9 );
    ROUND_B( 10 );
    ROUND_B( 11 );

    for( i = 0; i < 8; ++i )
    {
        pCtx->pH[i] = pCtx->pH[i] ^ pV[i] ^ pV[i + 8];
    }
}


MOC_EXTERN MSTATUS BLAKE2B_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    return DIGI_MALLOC(ppCtx, sizeof(BLAKE2B_CTX));
}


MOC_EXTERN MSTATUS BLAKE2B_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen)
{
    BLAKE2B_CTX *pBlakeCtx = (BLAKE2B_CTX *) pCtx;

    if (NULL == pBlakeCtx || (keyLen && NULL == pKey))
        return ERR_NULL_POINTER;

    if ( !outLen || outLen > MOC_BLAKE2B_MAX_OUTLEN )
        return ERR_BLAKE2_INVALID_OUTLEN;

    if ( NULL != pKey && ( !keyLen || keyLen > MOC_BLAKE2B_MAX_KEYLEN) )
        return ERR_BLAKE2_INVALID_KEYLEN;

    /* pCtx already checked for NULL, ok to ignore DIGI_MEMSET/DIGI_MEMCPY return code */
    DIGI_MEMSET((ubyte *) pBlakeCtx, 0x00, sizeof(BLAKE2B_CTX));
    DIGI_MEMCPY(pBlakeCtx->pH, BLAKE2B_IV, 8 * sizeof(ubyte8));

    /* IV XOR ParamBlock */
    pBlakeCtx->pH[0] ^= (0x01010000ULL ^ (((ubyte8) keyLen) << 8) ^ ((ubyte8) outLen));
    pBlakeCtx->outLen = outLen;

    if (keyLen)
    {
        /* buffer for a a padded key */
        ubyte pPaddedKey[MOC_BLAKE2B_BLOCKLEN] = {0};

        /* ok to ignore return codes */
        DIGI_MEMCPY(pPaddedKey, pKey, keyLen);
        BLAKE2B_update(MOC_HASH(hwAccelCtx) pCtx, pPaddedKey, MOC_BLAKE2B_BLOCKLEN);
        DIGI_MEMSET(pPaddedKey, 0x00, MOC_BLAKE2B_BLOCKLEN );
    }

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2B_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen )
{
    ubyte4 bytesNeeded = 0;
    BLAKE2B_CTX *pBlakeCtx = (BLAKE2B_CTX *) pCtx;

    if (NULL == pBlakeCtx || (dataLen && NULL == pData) )
        return ERR_NULL_POINTER;

    if (!dataLen)
        return OK; /* ok no-op */

    bytesNeeded = MOC_BLAKE2B_BLOCKLEN - pBlakeCtx->bufPos;

    /* only process a block if we have at least one more block coming */
    if( dataLen > bytesNeeded )
    {
        /* copy what we need to the buffer, ok to ignore return code */
        DIGI_MEMCPY( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, pData, bytesNeeded);
        pBlakeCtx->bufPos = 0;

        /* Process the block */
        BLAKE2B_incCtr( pBlakeCtx, MOC_BLAKE2B_BLOCKLEN );
        BLAKE2B_compress( pBlakeCtx, pBlakeCtx->pBuffer );

        pData += bytesNeeded;  /* ok to modify passed by value ptr */
        dataLen -= bytesNeeded;

        /* Process any additional blocks */
        while(dataLen > MOC_BLAKE2B_BLOCKLEN)
        {
            BLAKE2B_incCtr(pBlakeCtx, MOC_BLAKE2B_BLOCKLEN);
            BLAKE2B_compress( pBlakeCtx, pData );

            pData += MOC_BLAKE2B_BLOCKLEN;
            dataLen -= MOC_BLAKE2B_BLOCKLEN;
        }
    }

    /* copy any remaining bytes to the buffer, note dataLen can't be 0 here due to the above checks */
    DIGI_MEMCPY( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, pData, dataLen );
    pBlakeCtx->bufPos += dataLen;

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2B_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput)
{
#ifndef MOC_LITTLE_ENDIAN
    ubyte pTemp[MOC_BLAKE2B_MAX_OUTLEN] = {0};
    ubyte4 i = 0;
#endif
    BLAKE2B_CTX *pBlakeCtx = (BLAKE2B_CTX *) pCtx;

    if (NULL == pBlakeCtx || NULL == pOutput)
        return ERR_NULL_POINTER;

    if( 0x00ULL != pBlakeCtx->f)
        return ERR_BLAKE2_ALREADY_PROCESSED_LAST_BLOCK;

    pBlakeCtx->f = (ubyte8)-1;

    /* zero pad to a blockLen, ok to ignore DIGI_MEMSET/DIGI_MEMCPY return codes */
    DIGI_MEMSET( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, 0x00, MOC_BLAKE2B_BLOCKLEN - pBlakeCtx->bufPos );

    BLAKE2B_incCtr( pBlakeCtx, pBlakeCtx->bufPos );
    BLAKE2B_compress( pBlakeCtx, pBlakeCtx->pBuffer );

#ifdef MOC_LITTLE_ENDIAN
    DIGI_MEMCPY( pOutput, pBlakeCtx->pH, pBlakeCtx->outLen);
#else
    for(; i < 8; ++i) /* Output to temp buffer so we can take care of Endianness correctly */
        fromUbyte8( pTemp + i * sizeof( ubyte8 ), pBlakeCtx->pH[i] );

    DIGI_MEMCPY( pOutput, pTemp, pBlakeCtx->outLen );
    DIGI_MEMSET( pTemp, 0x00, MOC_BLAKE2B_MAX_OUTLEN);
#endif

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2B_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
    MSTATUS status = OK, fstatus = OK;
    BulkCtx pCtx = NULL;

    /* input validation handled by the below calls */
    status = BLAKE2B_alloc(MOC_HASH(hwAccelCtx) &pCtx);
    if (OK != status)
        goto exit;

    status = BLAKE2B_init(MOC_HASH(hwAccelCtx) pCtx, outLen, pKey, keyLen);
    if (OK != status)
        goto exit;

    status = BLAKE2B_update(MOC_HASH(hwAccelCtx) pCtx, pData, dataLen);
    if (OK != status)
        goto exit;

    status = BLAKE2B_final(MOC_HASH(hwAccelCtx) pCtx, pOutput);

exit:

    fstatus = BLAKE2B_delete(MOC_HASH(hwAccelCtx) &pCtx);
    if (OK == status)
        status = fstatus;

    return status;
}


MOC_EXTERN MSTATUS BLAKE2B_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    if (NULL == *ppCtx)
        return OK;

    DIGI_MEMSET((ubyte *) *ppCtx, 0x00, sizeof(BLAKE2B_CTX)); /* ok to ignore return code */
    return DIGI_FREE(ppCtx);
}

MOC_EXTERN MSTATUS BLAKE2B_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2B_CTX *pDest, BLAKE2B_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(BLAKE2B_CTX));
}
#endif /* defined(__ENABLE_DIGICERT_BLAKE_2B__) */


/* ----------------------------------- BLAKE 2S ----------------------------------- */


#if defined(__ENABLE_DIGICERT_BLAKE_2S__)

#define ROTR32( word, bytes) (((word) >> bytes) | ((word) << ( 32 - bytes)))

#define GS(r,i,a,b,c,d)                        \
do {                                           \
a = a + b + pM[BLAKE2S_sigma[r][2*i+0]]; \
d = ROTR32(d ^ a, 16);                         \
c = c + d;                                     \
b = ROTR32(b ^ c, 12);                         \
a = a + b + pM[BLAKE2S_sigma[r][2*i+1]]; \
d = ROTR32(d ^ a, 8);                          \
c = c + d;                                     \
b = ROTR32(b ^ c, 7);                          \
} while(0)

#define ROUND_S(r)                   \
do {                                 \
GS(r,0,pV[ 0],pV[ 4],pV[ 8],pV[12]); \
GS(r,1,pV[ 1],pV[ 5],pV[ 9],pV[13]); \
GS(r,2,pV[ 2],pV[ 6],pV[10],pV[14]); \
GS(r,3,pV[ 3],pV[ 7],pV[11],pV[15]); \
GS(r,4,pV[ 0],pV[ 5],pV[10],pV[15]); \
GS(r,5,pV[ 1],pV[ 6],pV[11],pV[12]); \
GS(r,6,pV[ 2],pV[ 7],pV[ 8],pV[13]); \
GS(r,7,pV[ 3],pV[ 4],pV[ 9],pV[14]); \
} while(0)

#ifndef MOC_LITTLE_ENDIAN
static MOC_INLINE ubyte4 toUbyte4(ubyte *pSrc)
{
    return (( ubyte4 )( pSrc[0] ) <<  0) |
    (( ubyte4 )( pSrc[1] ) <<  8) |
    (( ubyte4 )( pSrc[2] ) << 16) |
    (( ubyte4 )( pSrc[3] ) << 24);
}

static MOC_INLINE void fromUbyte4(ubyte *pDest, ubyte4 src)
{
    pDest[0] = (ubyte)(src >>  0);
    pDest[1] = (ubyte)(src >>  8);
    pDest[2] = (ubyte)(src >> 16);
    pDest[3] = (ubyte)(src >> 24);
}
#endif

static const ubyte4 BLAKE2S_IV[8] =
{
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const ubyte BLAKE2S_sigma[10][16] =
{
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }
};


static MOC_INLINE void BLAKE2S_incCtr( BLAKE2S_CTX *pCtx, ubyte4 inc )
{
    pCtx->pT[0] += inc;
    pCtx->pT[1] += ( pCtx->pT[0] < inc );
}


static void BLAKE2S_compress( BLAKE2S_CTX *pCtx, ubyte pBlock[MOC_BLAKE2S_BLOCKLEN] )
{
    ubyte4 pM[16] = {0};
    ubyte4 pV[16] = {0};
    ubyte4 i = 0;

#ifdef MOC_LITTLE_ENDIAN
    /* ok to ignore DIGI_MEMCPY return code */
    DIGI_MEMCPY((ubyte *) pM, pBlock, MOC_BLAKE2S_BLOCKLEN);
#else
    for(; i < 16; ++i )
    {
        pM[i] = toUbyte4(pBlock + i * sizeof(ubyte4));
    }
#endif

    DIGI_MEMCPY(pV, pCtx->pH, 8 * sizeof(ubyte4));

    pV[ 8] = BLAKE2S_IV[0];
    pV[ 9] = BLAKE2S_IV[1];
    pV[10] = BLAKE2S_IV[2];
    pV[11] = BLAKE2S_IV[3];
    pV[12] = BLAKE2S_IV[4] ^ pCtx->pT[0];
    pV[13] = BLAKE2S_IV[5] ^ pCtx->pT[1];
    pV[14] = BLAKE2S_IV[6] ^ pCtx->f;
    pV[15] = BLAKE2S_IV[7];

    ROUND_S( 0 );
    ROUND_S( 1 );
    ROUND_S( 2 );
    ROUND_S( 3 );
    ROUND_S( 4 );
    ROUND_S( 5 );
    ROUND_S( 6 );
    ROUND_S( 7 );
    ROUND_S( 8 );
    ROUND_S( 9 );

    for( i = 0; i < 8; ++i)
    {
        pCtx->pH[i] = pCtx->pH[i] ^ pV[i] ^ pV[i + 8];
    }
}


MOC_EXTERN MSTATUS BLAKE2S_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    return DIGI_MALLOC(ppCtx, sizeof(BLAKE2S_CTX));
}


MOC_EXTERN MSTATUS BLAKE2S_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen, ubyte *pKey, ubyte4 keyLen)
{
    BLAKE2S_CTX *pBlakeCtx = (BLAKE2S_CTX *) pCtx;

    if (NULL == pBlakeCtx || (keyLen && NULL == pKey))
        return ERR_NULL_POINTER;

    if ( !outLen || outLen > MOC_BLAKE2S_MAX_OUTLEN )
        return ERR_BLAKE2_INVALID_OUTLEN;

    if ( NULL != pKey && ( !keyLen || keyLen > MOC_BLAKE2S_MAX_KEYLEN) )
        return ERR_BLAKE2_INVALID_KEYLEN;

    /* pCtx already checked for NULL, ok to ignore DIGI_MEMSET/DIGI_MEMCPY return code */
    DIGI_MEMSET((ubyte *) pBlakeCtx, 0x00, sizeof(BLAKE2S_CTX));
    DIGI_MEMCPY(pBlakeCtx->pH, BLAKE2S_IV, 8 * sizeof(ubyte4));

    /* IV XOR ParamBlock */
    pBlakeCtx->pH[0] ^= (0x01010000UL ^ (keyLen << 8) ^ outLen);
    pBlakeCtx->outLen = outLen;

    if (keyLen)
    {
        /* buffer for a a padded key */
        ubyte pPaddedKey[MOC_BLAKE2S_BLOCKLEN] = {0};

        /* ok to ignore return codes */
        DIGI_MEMCPY(pPaddedKey, pKey, keyLen);
        BLAKE2S_update(MOC_HASH(hwAccelCtx) pCtx, pPaddedKey, MOC_BLAKE2S_BLOCKLEN);
        DIGI_MEMSET(pPaddedKey, 0x00, MOC_BLAKE2S_BLOCKLEN );
    }

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2S_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen )
{
    ubyte4 bytesNeeded = 0;
    BLAKE2S_CTX *pBlakeCtx = (BLAKE2S_CTX *) pCtx;

    if (NULL == pBlakeCtx || (dataLen && NULL == pData) )
        return ERR_NULL_POINTER;

    if (!dataLen)
        return OK; /* ok no-op */

    bytesNeeded = MOC_BLAKE2S_BLOCKLEN - pBlakeCtx->bufPos;

    /* only process a block if we have at least one more block coming */
    if( dataLen > bytesNeeded )
    {
        /* copy what we need to the buffer, ok to ignore return code */
        DIGI_MEMCPY( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, pData, bytesNeeded);
        pBlakeCtx->bufPos = 0;

        /* Process the block */
        BLAKE2S_incCtr( pBlakeCtx, MOC_BLAKE2S_BLOCKLEN );
        BLAKE2S_compress( pBlakeCtx, pBlakeCtx->pBuffer );

        pData += bytesNeeded;  /* ok to modify passed by value ptr */
        dataLen -= bytesNeeded;

        /* Process any additional blocks */
        while(dataLen > MOC_BLAKE2S_BLOCKLEN)
        {
            BLAKE2S_incCtr(pBlakeCtx, MOC_BLAKE2S_BLOCKLEN);
            BLAKE2S_compress( pBlakeCtx, pData );

            pData += MOC_BLAKE2S_BLOCKLEN;
            dataLen -= MOC_BLAKE2S_BLOCKLEN;
        }
    }

    /* copy any remaining bytes to the buffer, note dataLen can't be 0 here due to the above checks */
    DIGI_MEMCPY( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, pData, dataLen );
    pBlakeCtx->bufPos += dataLen;

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2S_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput)
{
#ifndef MOC_LITTLE_ENDIAN
    ubyte pTemp[MOC_BLAKE2S_MAX_OUTLEN] = {0};
    ubyte4 i = 0;
#endif
    BLAKE2S_CTX *pBlakeCtx = (BLAKE2S_CTX *) pCtx;

    if (NULL == pBlakeCtx || NULL == pOutput)
        return ERR_NULL_POINTER;

    if( 0x00UL != pBlakeCtx->f)
        return ERR_BLAKE2_ALREADY_PROCESSED_LAST_BLOCK;

    pBlakeCtx->f = (ubyte4)-1;

    /* zero pad to a blockLen, ok to ignore DIGI_MEMSET/DIGI_MEMCPY return codes */
    DIGI_MEMSET( pBlakeCtx->pBuffer + pBlakeCtx->bufPos, 0x00, MOC_BLAKE2S_BLOCKLEN - pBlakeCtx->bufPos );

    BLAKE2S_incCtr( pBlakeCtx, pBlakeCtx->bufPos );
    BLAKE2S_compress( pBlakeCtx, pBlakeCtx->pBuffer );

#ifdef MOC_LITTLE_ENDIAN
    DIGI_MEMCPY( pOutput, pBlakeCtx->pH, pBlakeCtx->outLen);
#else
    for(; i < 8; ++i) /* Output to temp buffer so we can take care of Endianness correctly */
        fromUbyte4( pTemp + i * sizeof( ubyte4 ), pBlakeCtx->pH[i] );

    DIGI_MEMCPY( pOutput, pTemp, pBlakeCtx->outLen );
    DIGI_MEMSET( pTemp, 0x00, MOC_BLAKE2S_MAX_OUTLEN);
#endif

    return OK;
}


MOC_EXTERN MSTATUS BLAKE2S_complete(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
    MSTATUS status = OK, fstatus = OK;
    BulkCtx pCtx = NULL;

    /* input validation handled by the below calls */
    status = BLAKE2S_alloc(MOC_HASH(hwAccelCtx) &pCtx);
    if (OK != status)
        goto exit;

    status = BLAKE2S_init(MOC_HASH(hwAccelCtx) pCtx, outLen, pKey, keyLen);
    if (OK != status)
        goto exit;

    status = BLAKE2S_update(MOC_HASH(hwAccelCtx) pCtx, pData, dataLen);
    if (OK != status)
        goto exit;

    status = BLAKE2S_final(MOC_HASH(hwAccelCtx) pCtx, pOutput);

exit:

    fstatus = BLAKE2S_delete(MOC_HASH(hwAccelCtx) &pCtx);
    if (OK == status)
        status = fstatus;

    return status;
}


MOC_EXTERN MSTATUS BLAKE2S_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    if (NULL == *ppCtx)
        return OK;

    DIGI_MEMSET((ubyte *) *ppCtx, 0x00, sizeof(BLAKE2S_CTX)); /* ok to ignore return code */
    return DIGI_FREE(ppCtx);
}

MOC_EXTERN MSTATUS BLAKE2S_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2S_CTX *pDest, BLAKE2S_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(BLAKE2S_CTX));
}
#endif /*  defined(__ENABLE_DIGICERT_BLAKE_2S__)       */
#endif /* !defined(__BLAKE2_HARDWARE_ACCELERATOR__) */
