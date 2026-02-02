/*
 * sha512.c
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
@file       sha512.c

@brief      C source file for the Nanocrypto SHA384 and SHA512 APIs.

@details    C source file for the Nanocrypto SHA384 and SHA512 APIs.

*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512_INTERNAL__
#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384_INTERNAL__

#include "../common/moptions.h"

#if !defined( __DISABLE_DIGICERT_SHA512__) || !defined(__DISABLE_DIGICERT_SHA384__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifndef __SHA512_HARDWARE_HASH__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/int64.h"
#include "../common/int128.h"
#include "../crypto/sha512.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../harness/harness.h"

#if defined(TEST) || defined(VERBOSE)
#include <stdio.h>
#endif

/*------------------------------------------------------------------*/

#if __DIGICERT_MAX_INT__ == 64

/* SHA512 constants */
static ubyte8 K[80] = {
0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

/* SHA512 functions */
#define CH(X,Y,Z)               (((X) & (Y)) ^ ((~X) & (Z)))
#define MAJ(X,Y,Z)              (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))

#define SHR(X, n)               ( ((ubyte8)(X)) >> (n))
#define SHL(X, n)               ( ((ubyte8)(X)) << (n))

/* implementing ROTR using the rot instructions on 64 bit CPU (PPC64, x86_64)
decreases the performance. */
#define ROTR(X, n)              (  (SHR(X,n)) | (SHL(X, (64-n))) )

#define BSIG0(X)                 ( (ROTR(X,28)) ^ (ROTR(X,34)) ^ (ROTR(X,39)) )
#define BSIG1(X)                 ( (ROTR(X,14)) ^ (ROTR(X,18)) ^ (ROTR(X,41)) )
#define LSIG0(X)                 ( (ROTR(X,1)) ^  (ROTR(X,8))  ^ (SHR(X,7))   )
#define LSIG1(X)                 ( (ROTR(X,19)) ^ (ROTR(X,61)) ^ (SHR(X,6)) )


#else

static ubyte8 K[80] = {
{ 0x428a2f98, 0xd728ae22}, { 0x71374491, 0x23ef65cd}, { 0xb5c0fbcf, 0xec4d3b2f}, { 0xe9b5dba5, 0x8189dbbc},
{ 0x3956c25b, 0xf348b538}, { 0x59f111f1, 0xb605d019}, { 0x923f82a4, 0xaf194f9b}, { 0xab1c5ed5, 0xda6d8118},
{ 0xd807aa98, 0xa3030242}, { 0x12835b01, 0x45706fbe}, { 0x243185be, 0x4ee4b28c}, { 0x550c7dc3, 0xd5ffb4e2},
{ 0x72be5d74, 0xf27b896f}, { 0x80deb1fe, 0x3b1696b1}, { 0x9bdc06a7, 0x25c71235}, { 0xc19bf174, 0xcf692694},
{ 0xe49b69c1, 0x9ef14ad2}, { 0xefbe4786, 0x384f25e3}, { 0x0fc19dc6, 0x8b8cd5b5}, { 0x240ca1cc, 0x77ac9c65},
{ 0x2de92c6f, 0x592b0275}, { 0x4a7484aa, 0x6ea6e483}, { 0x5cb0a9dc, 0xbd41fbd4}, { 0x76f988da, 0x831153b5},
{ 0x983e5152, 0xee66dfab}, { 0xa831c66d, 0x2db43210}, { 0xb00327c8, 0x98fb213f}, { 0xbf597fc7, 0xbeef0ee4},
{ 0xc6e00bf3, 0x3da88fc2}, { 0xd5a79147, 0x930aa725}, { 0x06ca6351, 0xe003826f}, { 0x14292967, 0x0a0e6e70},
{ 0x27b70a85, 0x46d22ffc}, { 0x2e1b2138, 0x5c26c926}, { 0x4d2c6dfc, 0x5ac42aed}, { 0x53380d13, 0x9d95b3df},
{ 0x650a7354, 0x8baf63de}, { 0x766a0abb, 0x3c77b2a8}, { 0x81c2c92e, 0x47edaee6}, { 0x92722c85, 0x1482353b},
{ 0xa2bfe8a1, 0x4cf10364}, { 0xa81a664b, 0xbc423001}, { 0xc24b8b70, 0xd0f89791}, { 0xc76c51a3, 0x0654be30},
{ 0xd192e819, 0xd6ef5218}, { 0xd6990624, 0x5565a910}, { 0xf40e3585, 0x5771202a}, { 0x106aa070, 0x32bbd1b8},
{ 0x19a4c116, 0xb8d2d0c8}, { 0x1e376c08, 0x5141ab53}, { 0x2748774c, 0xdf8eeb99}, { 0x34b0bcb5, 0xe19b48a8},
{ 0x391c0cb3, 0xc5c95a63}, { 0x4ed8aa4a, 0xe3418acb}, { 0x5b9cca4f, 0x7763e373}, { 0x682e6ff3, 0xd6b2b8a3},
{ 0x748f82ee, 0x5defb2fc}, { 0x78a5636f, 0x43172f60}, { 0x84c87814, 0xa1f0ab72}, { 0x8cc70208, 0x1a6439ec},
{ 0x90befffa, 0x23631e28}, { 0xa4506ceb, 0xde82bde9}, { 0xbef9a3f7, 0xb2c67915}, { 0xc67178f2, 0xe372532b},
{ 0xca273ece, 0xea26619c}, { 0xd186b8c7, 0x21c0c207}, { 0xeada7dd6, 0xcde0eb1e}, { 0xf57d4f7f, 0xee6ed178},
{ 0x06f067aa, 0x72176fba}, { 0x0a637dc5, 0xa2c898a6}, { 0x113f9804, 0xbef90dae}, { 0x1b710b35, 0x131c471b},
{ 0x28db77f5, 0x23047d84}, { 0x32caab7b, 0x40c72493}, { 0x3c9ebe0a, 0x15c9bebc}, { 0x431d67c4, 0x9c100d4c},
{ 0x4cc5d4be, 0xcb3e42b6}, { 0x597f299c, 0xfc657e2a}, { 0x5fcb6fab, 0x3ad6faec}, { 0x6c44198c, 0x4a475817}
};


/* SHA512 functions */
#define CH(X,Y,Z)               u8_Xor( u8_And((X),(Y)), u8_And( u8_Not(X),(Z)))
#define MAJ(X,Y,Z)              u8_Xor( u8_Xor( u8_And((X),(Y)), u8_And((X),(Z))), u8_And((Y),(Z)))

#define SHR(X, n)               u8_Shr((X),(n))
#define ROTR(X, n)              u8_Or( u8_Shr((X),(n)), u8_Shl((X),(64-n)) )

#define BSIG0(X)                u8_Xor( u8_Xor( ROTR(X,28), ROTR(X,34) ), ROTR(X,39) )
#define BSIG1(X)                u8_Xor( u8_Xor( ROTR(X,14), ROTR(X,18) ), ROTR(X,41) )
#define LSIG0(X)                u8_Xor( u8_Xor( ROTR(X,1),  ROTR(X,8)  ), SHR(X,7)   )
#define LSIG1(X)                u8_Xor( u8_Xor( ROTR(X,19), ROTR(X,61) ), SHR(X,6)  )

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SHA512_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_CALLOC((void**)pp_context, 1, sizeof(SHA512_CTX));
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA512_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA512 - Before Zeroization\n");
        for( counter = 0; counter < sizeof(SHA512_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pp_context+counter));
        }
        FIPS_PRINT("\n");
#endif

    /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*) *pp_context,0x00,sizeof(SHA512_CTX));
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nSHA512 - After Zeroization\n");
        for( counter = 0; counter < sizeof(SHA512_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pp_context+counter));
        }
        FIPS_PRINT("\n");
#endif
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA512__

extern MSTATUS
SHA512_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
#if __DIGICERT_MAX_INT__ == 64

        pContext->hashBlocks[0] = 0x6a09e667f3bcc908ULL;
        pContext->hashBlocks[1] = 0xbb67ae8584caa73bULL;
        pContext->hashBlocks[2] = 0x3c6ef372fe94f82bULL;
        pContext->hashBlocks[3] = 0xa54ff53a5f1d36f1ULL;
        pContext->hashBlocks[4] = 0x510e527fade682d1ULL;
        pContext->hashBlocks[5] = 0x9b05688c2b3e6c1fULL;
        pContext->hashBlocks[6] = 0x1f83d9abfb41bd6bULL;
        pContext->hashBlocks[7] = 0x5be0cd19137e2179ULL;

#else
        U8INIT(pContext->hashBlocks[0], 0x6a09e667, 0xf3bcc908);
        U8INIT(pContext->hashBlocks[1], 0xbb67ae85, 0x84caa73b);
        U8INIT(pContext->hashBlocks[2], 0x3c6ef372, 0xfe94f82b);
        U8INIT(pContext->hashBlocks[3], 0xa54ff53a, 0x5f1d36f1);
        U8INIT(pContext->hashBlocks[4], 0x510e527f, 0xade682d1);
        U8INIT(pContext->hashBlocks[5], 0x9b05688c, 0x2b3e6c1f);
        U8INIT(pContext->hashBlocks[6], 0x1f83d9ab, 0xfb41bd6b);
        U8INIT(pContext->hashBlocks[7], 0x5be0cd19, 0x137e2179);
#endif

        ZERO_U16( pContext->msgLength);

        pContext->hashBufferIndex = 0;

        status = OK;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;
}

#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA384__

extern MSTATUS
SHA384_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pContext)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
#if __DIGICERT_MAX_INT__ == 64
        pContext->hashBlocks[0] = 0xcbbb9d5dc1059ed8ULL;
        pContext->hashBlocks[1] = 0x629a292a367cd507ULL;
        pContext->hashBlocks[2] = 0x9159015a3070dd17ULL;
        pContext->hashBlocks[3] = 0x152fecd8f70e5939ULL;
        pContext->hashBlocks[4] = 0x67332667ffc00b31ULL;
        pContext->hashBlocks[5] = 0x8eb44a8768581511ULL;
        pContext->hashBlocks[6] = 0xdb0c2e0d64f98fa7ULL;
        pContext->hashBlocks[7] = 0x47b5481dbefa4fa4ULL;
#else
        U8INIT(pContext->hashBlocks[0], 0xcbbb9d5d, 0xc1059ed8);
        U8INIT(pContext->hashBlocks[1], 0x629a292a, 0x367cd507);
        U8INIT(pContext->hashBlocks[2], 0x9159015a, 0x3070dd17);
        U8INIT(pContext->hashBlocks[3], 0x152fecd8, 0xf70e5939);
        U8INIT(pContext->hashBlocks[4], 0x67332667, 0xffc00b31);
        U8INIT(pContext->hashBlocks[5], 0x8eb44a87, 0x68581511);
        U8INIT(pContext->hashBlocks[6], 0xdb0c2e0d, 0x64f98fa7);
        U8INIT(pContext->hashBlocks[7], 0x47b5481d, 0xbefa4fa4);
#endif

        ZERO_U16(pContext->msgLength);

        pContext->hashBufferIndex = 0;

        status = OK;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;
}

#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SHA2_FASTEST__
static void
sha512_transform(SHA512_CTX *pContext, const ubyte M[SHA512_BLOCK_SIZE])
{
#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte8 *W = pContext->W;
#else
    ubyte8 W[80];
#endif
    ubyte8 a,b,c,d,e,f,g,h;
    ubyte8 T1,T2;
    
    ubyte8 *pHashBlocks = (ubyte8 *) pContext->hashBlocks;
    
#ifdef MOC_LITTLE_ENDIAN
#if __DIGICERT_MAX_INT__ == 64
#define MOC_BYTETOWORD( t) \
    W[t]  = (((ubyte8)(*M++)) << 56); \
    W[t] |= (((ubyte8)(*M++)) << 48); \
    W[t] |= (((ubyte8)(*M++)) << 40); \
    W[t] |= (((ubyte8)(*M++)) << 32); \
    W[t] |= (((ubyte8)(*M++)) << 24); \
    W[t] |= (((ubyte8)(*M++)) << 16); \
    W[t] |= (((ubyte8)(*M++)) << 8);  \
    W[t] |=  (ubyte8)(*M++)
#else
#define MOC_BYTETOWORD( t) \
    W[t].upper32  = ((ubyte4)(*M++) << 24); \
    W[t].upper32 |= ((ubyte4)(*M++) << 16); \
    W[t].upper32 |= ((ubyte4)(*M++) << 8);  \
    W[t].upper32 |=  (ubyte4)(*M++);        \
    W[t].lower32  = ((ubyte4)(*M++) << 24); \
    W[t].lower32 |= ((ubyte4)(*M++) << 16); \
    W[t].lower32 |= ((ubyte4)(*M++) << 8);  \
    W[t].lower32 |=  (ubyte4)(*M++)
#endif /* __DIGICERT_MAX_INT__ == 64 */
    
    MOC_BYTETOWORD(0);
    MOC_BYTETOWORD(1);
    MOC_BYTETOWORD(2);
    MOC_BYTETOWORD(3);
    MOC_BYTETOWORD(4);
    MOC_BYTETOWORD(5);
    MOC_BYTETOWORD(6);
    MOC_BYTETOWORD(7);
    MOC_BYTETOWORD(8);
    MOC_BYTETOWORD(9);
    MOC_BYTETOWORD(10);
    MOC_BYTETOWORD(11);
    MOC_BYTETOWORD(12);
    MOC_BYTETOWORD(13);
    MOC_BYTETOWORD(14);
    MOC_BYTETOWORD(15);
#else
    DIGI_MEMCPY((ubyte *) W, M, SHA512_BLOCK_SIZE);
#endif /* MOC_LITTLE_ENDIAN */
    
#define MOC_W( t) \
    W[t] = u8_Add( u8_Add( u8_Add(LSIG1( W[t-2]), W[t-7]), LSIG0( W[t-15])), W[t-16]);
    
    MOC_W(16);
    MOC_W(17);
    MOC_W(18);
    MOC_W(19);
    MOC_W(20);
    MOC_W(21);
    MOC_W(22);
    MOC_W(23);
    MOC_W(24);
    MOC_W(25);
    MOC_W(26);
    MOC_W(27);
    MOC_W(28);
    MOC_W(29);
    MOC_W(30);
    MOC_W(31);
    MOC_W(32);
    MOC_W(33);
    MOC_W(34);
    MOC_W(35);
    MOC_W(36);
    MOC_W(37);
    MOC_W(38);
    MOC_W(39);
    MOC_W(40);
    MOC_W(41);
    MOC_W(42);
    MOC_W(43);
    MOC_W(44);
    MOC_W(45);
    MOC_W(46);
    MOC_W(47);
    MOC_W(48);
    MOC_W(49);
    MOC_W(50);
    MOC_W(51);
    MOC_W(52);
    MOC_W(53);
    MOC_W(54);
    MOC_W(55);
    MOC_W(56);
    MOC_W(57);
    MOC_W(58);
    MOC_W(59);
    MOC_W(60);
    MOC_W(61);
    MOC_W(62);
    MOC_W(63);
    MOC_W(64);
    MOC_W(65);
    MOC_W(66);
    MOC_W(67);
    MOC_W(68);
    MOC_W(69);
    MOC_W(70);
    MOC_W(71);
    MOC_W(72);
    MOC_W(73);
    MOC_W(74);
    MOC_W(75);
    MOC_W(76);
    MOC_W(77);
    MOC_W(78);
    MOC_W(79);
    
    a = pHashBlocks[0];
    b = pHashBlocks[1];
    c = pHashBlocks[2];
    d = pHashBlocks[3];
    e = pHashBlocks[4];
    f = pHashBlocks[5];
    g = pHashBlocks[6];
    h = pHashBlocks[7];
    
#define MOC_L( t) \
    T1 = u8_Add(u8_Add(u8_Add(u8_Add(h, BSIG1(e)), CH(e,f,g)), K[t]), W[t]); \
    T2 = u8_Add(BSIG0(a), MAJ(a,b,c)); \
    h = g; \
    g = f; \
    f = e; \
    e = u8_Add(d, T1); \
    d = c; \
    c = b; \
    b = a; \
    a = u8_Add(T1, T2); \

    MOC_L(0);
    MOC_L(1);
    MOC_L(2);
    MOC_L(3);
    MOC_L(4);
    MOC_L(5);
    MOC_L(6);
    MOC_L(7);
    MOC_L(8);
    MOC_L(9);
    MOC_L(10);
    MOC_L(11);
    MOC_L(12);
    MOC_L(13);
    MOC_L(14);
    MOC_L(15);
    MOC_L(16);
    MOC_L(17);
    MOC_L(18);
    MOC_L(19);
    MOC_L(20);
    MOC_L(21);
    MOC_L(22);
    MOC_L(23);
    MOC_L(24);
    MOC_L(25);
    MOC_L(26);
    MOC_L(27);
    MOC_L(28);
    MOC_L(29);
    MOC_L(30);
    MOC_L(31);
    MOC_L(32);
    MOC_L(33);
    MOC_L(34);
    MOC_L(35);
    MOC_L(36);
    MOC_L(37);
    MOC_L(38);
    MOC_L(39);
    MOC_L(40);
    MOC_L(41);
    MOC_L(42);
    MOC_L(43);
    MOC_L(44);
    MOC_L(45);
    MOC_L(46);
    MOC_L(47);
    MOC_L(48);
    MOC_L(49);
    MOC_L(50);
    MOC_L(51);
    MOC_L(52);
    MOC_L(53);
    MOC_L(54);
    MOC_L(55);
    MOC_L(56);
    MOC_L(57);
    MOC_L(58);
    MOC_L(59);
    MOC_L(60);
    MOC_L(61);
    MOC_L(62);
    MOC_L(63);
    MOC_L(64);
    MOC_L(65);
    MOC_L(66);
    MOC_L(67);
    MOC_L(68);
    MOC_L(69);
    MOC_L(70);
    MOC_L(71);
    MOC_L(72);
    MOC_L(73);
    MOC_L(74);
    MOC_L(75);
    MOC_L(76);
    MOC_L(77);
    MOC_L(78);
    MOC_L(79);
    
    u8_Incr( pHashBlocks, a);
    u8_Incr( pHashBlocks + 1, b);
    u8_Incr( pHashBlocks + 2, c);
    u8_Incr( pHashBlocks + 3, d);
    u8_Incr( pHashBlocks + 4, e);
    u8_Incr( pHashBlocks + 5, f);
    u8_Incr( pHashBlocks + 6, g);
    u8_Incr( pHashBlocks + 7, h);
}

#else

/*------------------------------------------------------------------*/

static void
sha512_transform(SHA512_CTX *pContext, const ubyte M[SHA512_BLOCK_SIZE])
{
#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte8 *W = pContext->W;
#else
    ubyte8 W[80];
#endif
    sbyte4 t;
    ubyte8 a,b,c,d,e,f,g,h;
    ubyte8 T1,T2;

    /* message schedule */
    for (t = 0; t < 16; ++t)
    {
#if __DIGICERT_MAX_INT__ == 64
        W[t]  = (((ubyte8)(*M++)) << 56);
        W[t] |= (((ubyte8)(*M++)) << 48);
        W[t] |= (((ubyte8)(*M++)) << 40);
        W[t] |= (((ubyte8)(*M++)) << 32);
        W[t] |= (((ubyte8)(*M++)) << 24);
        W[t] |= (((ubyte8)(*M++)) << 16);
        W[t] |= (((ubyte8)(*M++)) << 8);
        W[t] |=  (ubyte8)(*M++);

#else
        W[t].upper32  = ((ubyte4)(*M++) << 24);
        W[t].upper32 |= ((ubyte4)(*M++) << 16);
        W[t].upper32 |= ((ubyte4)(*M++) << 8);
        W[t].upper32 |=  (ubyte4)(*M++);
        W[t].lower32  = ((ubyte4)(*M++) << 24);
        W[t].lower32 |= ((ubyte4)(*M++) << 16);
        W[t].lower32 |= ((ubyte4)(*M++) << 8);
        W[t].lower32 |=  (ubyte4)(*M++);
#endif

#ifdef VERBOSE
#if __DIGICERT_MAX_INT__ == 64
        printf("%016lx", W[t]);
#else
        printf("%08x%08x ", W[t].upper32, W[t].lower32);
#endif
#endif

    }

    for (; t < 80; ++t)
    {
        W[t] = u8_Add( u8_Add( u8_Add(LSIG1( W[t-2]), W[t-7]), LSIG0( W[t-15])), W[t-16]);
    }

    a = pContext->hashBlocks[0];
    b = pContext->hashBlocks[1];
    c = pContext->hashBlocks[2];
    d = pContext->hashBlocks[3];
    e = pContext->hashBlocks[4];
    f = pContext->hashBlocks[5];
    g = pContext->hashBlocks[6];
    h = pContext->hashBlocks[7];

    for (t = 0; t < 80; ++t)
    {
        T1 = u8_Add(u8_Add(u8_Add(u8_Add(h, BSIG1(e)), CH(e,f,g)), K[t]), W[t]);
        T2 = u8_Add(BSIG0(a), MAJ(a,b,c));
        h = g;
        g = f;
        f = e;
        e = u8_Add(d, T1);
        d = c;
        c = b;
        b = a;
        a = u8_Add(T1, T2);

#ifdef VERBOSE
#if __DIGICERT_MAX_INT__ == 64
        printf("\n%d\t%016lx %016lx %016lx %016lx\n\t%016lxx %016lx %016lx %016lx\n",
               t, a, b, c, d, e, f, g, h);
#else
        printf("\n%d\t%08x%08x %08x%08x %08x%08x %08x%08x\n\t%08x%08x %08x%08x %08x%08x %08x%08x\n",
            t, a.upper32, a.lower32,
            b.upper32, b.lower32,
            c.upper32, c.lower32,
            d.upper32, d.lower32,
            e.upper32, e.lower32,
            f.upper32, f.lower32,
            g.upper32, g.lower32,
            h.upper32, h.lower32);
#endif
#endif
    }

    u8_Incr( &pContext->hashBlocks[0], a);
    u8_Incr( &pContext->hashBlocks[1], b);
    u8_Incr( &pContext->hashBlocks[2], c);
    u8_Incr( &pContext->hashBlocks[3], d);
    u8_Incr( &pContext->hashBlocks[4], e);
    u8_Incr( &pContext->hashBlocks[5], f);
    u8_Incr( &pContext->hashBlocks[6], g);
    u8_Incr( &pContext->hashBlocks[7], h);

#ifdef VERBOSE
#if __DIGICERT_MAX_INT__ == 64
    printf("\n%016lx %016lx %016lx %016lx\n%016lx %016lx %016lx %016lx\n",
            pContext->hashBlocks[0],
            pContext->hashBlocks[1],
            pContext->hashBlocks[2],
            pContext->hashBlocks[3],
            pContext->hashBlocks[4],
            pContext->hashBlocks[5],
            pContext->hashBlocks[6],
           pContext->hashBlocks[7]);
#else
    printf("\n%08x%08x %08x%08x %08x%08x %08x%08x\n%08x%08x %08x%08x %08x%08x %08x%08x\n",
            pContext->hashBlocks[0].upper32, pContext->hashBlocks[0].lower32,
            pContext->hashBlocks[1].upper32, pContext->hashBlocks[1].lower32,
            pContext->hashBlocks[2].upper32, pContext->hashBlocks[2].lower32,
            pContext->hashBlocks[3].upper32, pContext->hashBlocks[3].lower32,
            pContext->hashBlocks[4].upper32, pContext->hashBlocks[4].lower32,
            pContext->hashBlocks[5].upper32, pContext->hashBlocks[5].lower32,
            pContext->hashBlocks[6].upper32, pContext->hashBlocks[6].lower32,
            pContext->hashBlocks[7].upper32, pContext->hashBlocks[7].lower32 );
#endif
#endif

}
#endif /* __ENABLE_DIGICERT_SHA2_FASTEST__ */

/*------------------------------------------------------------------*/

extern MSTATUS
SHA512_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext,
                    const ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if ((NULL == pContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* increment the 128 bit counter */
    u16_Incr32(&pContext->msgLength, dataLen);

    /* some remaining from last time ?*/
    if (pContext->hashBufferIndex > 0)
    {
        sbyte4 numToCopy = SHA512_BLOCK_SIZE - pContext->hashBufferIndex;
        if ( (sbyte4)dataLen < numToCopy)
        {
            numToCopy = dataLen;
        }

        DIGI_MEMCPY( pContext->hashBuffer + pContext->hashBufferIndex, pData, numToCopy);
        pData += numToCopy;
        dataLen -= numToCopy;
        pContext->hashBufferIndex += numToCopy;
        if (SHA512_BLOCK_SIZE == pContext->hashBufferIndex)
        {
            sha512_transform( pContext, pContext->hashBuffer);
            pContext->hashBufferIndex = 0;
        }
    }

    /* process as much as possible right now */
    while ( SHA512_BLOCK_SIZE <= dataLen)
    {
        sha512_transform( pContext, pData);

        dataLen -= SHA512_BLOCK_SIZE;
        pData += SHA512_BLOCK_SIZE;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(pContext->hashBuffer + pContext->hashBufferIndex, pData, dataLen);
        pContext->hashBufferIndex += dataLen;
    }

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SHA512_finalDigestAux(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext,
                      ubyte *pOutput, sbyte4 outputSize)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    sbyte4 i;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if ((NULL == pContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* we should have room to append one byte onto the message */
    pContext->hashBuffer[pContext->hashBufferIndex++] = 0x80;

    /* less than 16 bytes available -> extra round */
   if ( pContext->hashBufferIndex > SHA512_BLOCK_SIZE - 16)
    {
        while ( pContext->hashBufferIndex < SHA512_BLOCK_SIZE)
        {
            pContext->hashBuffer[pContext->hashBufferIndex++] = 0x00;
        }
        sha512_transform( pContext, pContext->hashBuffer);
        pContext->hashBufferIndex = 0;
    }

    /*last round */
    /* NOTE: should be SHA512_BLOCK_SIZE - 16 to put a 16 bytes length */
    while ( pContext->hashBufferIndex < SHA512_BLOCK_SIZE - 16)
    {
        pContext->hashBuffer[pContext->hashBufferIndex++] = 0x00;
    }

    /* fill in message bit length */
    /* bytes to bits */
    pContext->msgLength = u16_Shl( pContext->msgLength, 3);
    /* fill with 0 always but replace when we support bigger msg length! */
    BIGEND32(pContext->hashBuffer+SHA512_BLOCK_SIZE-16, W1_U16(pContext->msgLength));
    BIGEND32(pContext->hashBuffer+SHA512_BLOCK_SIZE-12, W2_U16(pContext->msgLength));
    BIGEND32(pContext->hashBuffer+SHA512_BLOCK_SIZE-8, W3_U16(pContext->msgLength));
    BIGEND32(pContext->hashBuffer+SHA512_BLOCK_SIZE-4, W4_U16(pContext->msgLength));

    sha512_transform( pContext, pContext->hashBuffer);

    /* return the output */
    for (i = 0; i < outputSize/8; ++i)
    {
        BIGEND32( pOutput, HI_U8(pContext->hashBlocks[i]));
        BIGEND32( pOutput + 4, LOW_U8(pContext->hashBlocks[i]));
        pOutput += 8;
    }

exit:
#ifdef __ZEROIZE_TEST__
    {
        int counter;

        FIPS_PRINT("\nSHA512_finalDigestAux - Before Zeroization\n");
        for (counter = 0; counter < sizeof(SHA512_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)pContext + counter));
        }
        FIPS_PRINT("\n");
    }
#endif
    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((ubyte *)pContext, 0x00, sizeof(SHA512_CTX));

#ifdef __ZEROIZE_TEST__
    {
        int counter;

        FIPS_PRINT("\nSHA512_finalDigestAux - After Zeroization\n");
        for (counter = 0; counter < sizeof(SHA512_CTX); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)pContext + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;

} /* SHA512_finalDigestAux */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA512__

extern MSTATUS
SHA512_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext, ubyte *pOutput)
{
    return SHA512_finalDigestAux( MOC_HASH(hwAccelCtx) pContext, pOutput,
                                    SHA512_RESULT_SIZE);
} /* SHA512_finalDigest */

/*------------------------------------------------------------------*/

extern MSTATUS 
SHA512_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pDest, SHA512_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(SHA512_CTX));
}
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SHA384__
extern MSTATUS
SHA384_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pContext, ubyte *pOutput)
{
    return SHA512_finalDigestAux( MOC_HASH(hwAccelCtx) pContext, pOutput,
                                    SHA384_RESULT_SIZE);
} /* SHA384_finalDigest */

/*------------------------------------------------------------------*/

extern MSTATUS 
SHA384_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pDest, SHA384_CTX *pSrc)
{
    return DIGI_MEMCPY((ubyte *) pDest, (ubyte *) pSrc, sizeof(SHA384_CTX));
}
#endif

/*------------------------------------------------------------------*/

#if !defined( __SHA512_ONE_STEP_HARDWARE_HASH__) && !defined(__DISABLE_DIGICERT_SHA512__)

extern MSTATUS
SHA512_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    FIPS_LOG_DECL_SESSION;
    SHA512_CTX context;
    MSTATUS  status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if (OK > (status = SHA512_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;

    if (OK > (status = SHA512_updateDigest(MOC_HASH(hwAccelCtx) &context, pData, dataLen)))
        goto exit;

    status = SHA512_finalDigest(MOC_HASH(hwAccelCtx) &context, pShaOutput);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;
}

#endif /* __SHA512_ONE_STEP_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#if !defined( __SHA384_ONE_STEP_HARDWARE_HASH__) && !defined(__DISABLE_DIGICERT_SHA384__)

extern MSTATUS
SHA384_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    FIPS_LOG_DECL_SESSION;
    SHA384_CTX context;
    MSTATUS  status = OK;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_SHA512); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_SHA512,0);

    if (OK > (status = SHA384_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;

    if (OK > (status = SHA384_updateDigest(MOC_HASH(hwAccelCtx) &context, pData, dataLen)))
        goto exit;

    status = SHA384_finalDigest(MOC_HASH(hwAccelCtx) &context, pShaOutput);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_SHA512,0);
    return status;
}

#endif /* __SHA384_ONE_STEP_HARDWARE_HASH__ */

#endif /* __SHA512_HARDWARE_HASH__ */

#ifdef TEST

#include <stdlib.h>
#include <stdio.h>

/*
 * those are the standard FIPS-180-2 test vectors
 */

static char *msg[] =
{
    "abc",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"\
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    NULL
};

static char *val512[] =
{
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"\
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"\
    "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"\
    "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
};

static char *val384[] =
{
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"\
    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"\
    "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"\
    "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
};

#include <string.h>

static int Compare( ubyte* res, int resSize, char* expectedVal)
{
    int i;
    char output[129];

    for( i = 0; i < resSize; i++ )
    {
        sprintf( output + i * 2, "%02x", res[i] );
    }

    return  strcmp(expectedVal, output) ? 1 : 0;
}

int TestSHA384()
{
    SHA384_CTX ctx;
    int i, retVal = 0;
    ubyte result[SHA384_RESULT_SIZE];
    char buf[1000];

    for (i = 0; i < 2; ++i)
    {
         SHA384_completeDigest( msg[i], DIGI_STRLEN( msg[i]), result);
         retVal += Compare(result, sizeof(result), val384[i]);
    }

    SHA384_initDigest( &ctx);
    memset( buf, 'a', 1000 );

    for( i = 0; i < 1000; i++ )
    {
        SHA384_updateDigest( &ctx, buf, 1000 );
    }
    SHA384_finalDigest( &ctx, result);

    retVal += Compare(result, sizeof(result), val384[2]);

    return( retVal );
}


int TestSHA512()
{
    SHA512_CTX ctx;
    int i, retVal = 0;
    ubyte result[SHA512_RESULT_SIZE];
    char buf[1000];

    for (i = 0; i < 2; ++i)
    {
         SHA512_completeDigest( msg[i], DIGI_STRLEN( msg[i]), result);
         retVal += Compare(result, sizeof(result), val512[i]);
    }

    SHA512_initDigest( &ctx);
    memset( buf, 'a', 1000 );

    for( i = 0; i < 1000; i++ )
    {
        SHA512_updateDigest( &ctx, buf, 1000 );
    }
    SHA512_finalDigest( &ctx, result);

    retVal += Compare(result, sizeof(result), val512[2]);
    return( retVal );
}

#endif

#endif /* __DISABLE_DIGICERT_SHA512__ */
