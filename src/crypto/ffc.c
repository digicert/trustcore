/*
 * ffc.c
 *
 * Finite Field Cryptography Domain Parameter Validation.
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
@file       ffc.c

@brief      Documentation file for the NanoCrypto FFC Domain Validation APIs.

@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto FFC Domain Validation APIs.

@filedoc    ffc.c
*/

#include "../common/moptions.h"

#if !defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__) || defined(__ENABLE_DIGICERT_DSA__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"

#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"

#include "../crypto/ffc.h"

/*------------------------------------------------------------------*/

extern MSTATUS FFC_verifyG(MOC_FFC(hwAccelDescr hwAccelCtx) vlong *pP, vlong *pQ, vlong *pG, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    vlong*  p_1       = NULL;
    vlong*  tmp       = NULL;
    MSTATUS status = OK;
    
    if (NULL == pP || NULL == pQ || NULL == pG || NULL == pIsValid)
        return ERR_NULL_POINTER;
    
    *pIsValid = FALSE;
    
    /* verify g as per Appendix A.2.2 of NIST FIPS186-4 */
    if (OK > (status = VLONG_makeVlongFromVlong(pP, &p_1, ppVlongQueue)))
        goto exit;
    
    /* p_1 = p-1 */
    if (OK > (status = VLONG_decrement(p_1, ppVlongQueue)))
        goto exit;
    
    /* g must be less than (p-1) */
    if (VLONG_compareSignedVlongs(p_1, pG) <= 0)
        goto exit;
    
    /* g must be greater than 1 */
    if (1 >= VLONG_bitLength(pG))
        goto exit;
    
    /* if g^q = 1 mod p, then return PARTIALLY VALID */
    if(OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) pG, pQ, pP, &tmp, ppVlongQueue)))
        goto exit;
    
    if( (TRUE == VLONG_isVlongBitSet(tmp, 0)) && (1 == VLONG_bitLength(tmp)))
        *pIsValid = TRUE;
    
exit:
    
    VLONG_freeVlong(&p_1, ppVlongQueue);
    VLONG_freeVlong(&tmp, ppVlongQueue);
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS FFC_getHashValue(MOC_FFC(hwAccelDescr hwAccelCtx) FFCHashType hashType,
                                ubyte *pSrc, ubyte4 length, ubyte *pHashVal)
{
    MSTATUS status = OK;
    
    if (NULL == pSrc || NULL == pHashVal)
        return ERR_NULL_POINTER;
    
    switch (hashType)
    {
        case FFC_sha1:
        {
            status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pSrc, length, pHashVal);
            break;
        }
#ifndef __DISABLE_DIGICERT_SHA224__
        case FFC_sha224:
        {
            status = SHA224_completeDigest(MOC_HASH(hwAccelCtx) pSrc, length, pHashVal);
            break;
        }
#endif
            
#ifndef __DISABLE_DIGICERT_SHA256__
        case FFC_sha256:
        {
            status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pSrc, length, pHashVal);
            break;
        }
#endif
            
#ifndef __DISABLE_DIGICERT_SHA384__
        case FFC_sha384:
        {
            status = SHA384_completeDigest(MOC_HASH(hwAccelCtx) pSrc, length, pHashVal);
            break;
        }
#endif
            
#ifndef __DISABLE_DIGICERT_SHA512__
        case FFC_sha512:
        {
            SHA512_completeDigest(MOC_HASH(hwAccelCtx) pSrc, length, pHashVal);
            break;
        }
#endif
        default:
        {
            /* The needed SHA-2 algorithm was not built in */
            status = ERR_CRYPTO_SHA_ALGORITHM_DISABLED;
        }
    }
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS FFC_getHashLen(FFCHashType hashType, ubyte4 *pHashLen)
{
    MSTATUS status = OK;
    
    if (NULL == pHashLen)
        return ERR_NULL_POINTER;
    
    switch(hashType)
    {
        case FFC_sha1:
        {
            *pHashLen = 160;
            break;
        }
#ifndef __DISABLE_DIGICERT_SHA224__
        case FFC_sha224:
        {
            *pHashLen = 224;
            break;
        }
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
        case FFC_sha256:
        {
            *pHashLen = 256;
            break;
        }
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
        case FFC_sha384:
        {
            *pHashLen = 384;
            break;
        }
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
        case FFC_sha512:
        {
            *pHashLen = 512;
            break;
        }
#endif
        default:
        {
            /* The needed SHA-2 algorithm was not built in */
            status = ERR_CRYPTO_SHA_ALGORITHM_DISABLED;
        }
    }
    
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS FFC_computePQ_FIPS_1864(MOC_FFC(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                      vlong **ppNewP, vlong **ppNewQ, ubyte4 L, ubyte4 Nin, FFCHashType hashType, ubyte4 *pRetC,
                                      ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    ubyte*          S     = NULL;
    ubyte*          U     = NULL;
    ubyte*          U_tmp = NULL;
    ubyte*          U_hash  = NULL;
    vlong*          U_vlong = NULL;
    vlong*          U_vlongtmp = NULL;
    vlong*          bBit  = NULL;
    vlong*          q     = NULL;
    vlong*          W     = NULL;
    vlong*          Vk    = NULL;
    vlong*          X     = NULL;
    vlong*          p     = NULL;
    vlong*          swap; /* place holder for swap */
    ubyte4          n, k, C, N, carry, b;
    sbyte4          index;
    intBoolean      isPrimeQ, isPrimeP;
    MSTATUS         status = OK;
    ubyte4          shaSize;
    ubyte4          shaBytes;
    ubyte4          iterations = (4 * L) - 1;
#ifdef __ENABLE_DIGICERT_64_BIT__
    ubyte4          unitSize = 64;
#else
    ubyte4          unitSize = 32;
#endif

    if (NULL == ppNewP || NULL == ppNewQ || NULL == pSeed || NULL == pIsPrimePQ)
        return ERR_NULL_POINTER;
    
    isPrimeP = FALSE;
    *pIsPrimePQ = FALSE;

    if( OK > (status = FFC_getHashLen(hashType, &shaSize)))
        goto exit;

    shaBytes = shaSize / 8;

    /* L and Nin should have already been validated by the calling method */

    /* The shaSize must be greater than N. The only allowed SHA algorithms are SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 */
    if(shaSize < Nin)
    {
        status = ERR_DSA_HASH_TOO_SMALL; /* OK, ERR_DH_HASH_TOO_SMALL has same value so no confusion if this method is called by DH */
        goto exit;
    }

    /* allocate buffers */
    if (NULL == (S = MALLOC(seedSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (U = MALLOC(shaBytes)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (U_tmp = MALLOC(seedSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (U_hash = MALLOC(shaBytes)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = VLONG_allocVlong(&W, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&X, ppVlongQueue)))
        goto exit;

    n = (L-1) / shaSize;
    b = (L-1) - (n*shaSize);

    isPrimeQ = FALSE;

    /* use the provided seed as S */
    if (OK > (status = DIGI_MEMCPY(S, pSeed, seedSize)))
        goto exit;

    /* U = HASH(S) mod 2^(N-1) */
    if (OK > (status = FFC_getHashValue(MOC_FFC(hwAccelCtx) hashType, S, seedSize, U)))
        goto exit;

    VLONG_freeVlong(&U_vlong, ppVlongQueue);
    if (OK > (status = VLONG_vlongFromByteString(U, shaBytes, &U_vlong, ppVlongQueue)))
        goto exit;

    VLONG_freeVlong(&U_vlongtmp, ppVlongQueue);
    if (OK > (status = VLONG_allocVlong(&U_vlongtmp, ppVlongQueue)))
        goto exit;

    if (OK > (status = VLONG_setVlongBit(U_vlongtmp, Nin - 1)))
        goto exit;

    if(OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) U_vlong, U_vlongtmp, &swap, ppVlongQueue)))
        goto exit;

    VLONG_freeVlong(&U_vlong, ppVlongQueue);
    U_vlong = swap; swap = 0;


    /* q = 2^(N-1) + U + 1 - (U mod 2) */
    VLONG_freeVlong(&q, ppVlongQueue);
    if (OK > (status = VLONG_allocVlong(&q, ppVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_setVlongBit(q, Nin - 1)))
        goto exit;

    /* if U is odd then U + 1 - (U mod 2) = U  */
    /* if U is even then U + 1 - (U mod 2) = U + 1 */
    if(!(U[shaBytes-1] & 0x01))
    {
        if (OK > (status = VLONG_increment(U_vlong, ppVlongQueue)))
            goto exit;
    }

    if (OK > (status = VLONG_addSignedVlongs(q, U_vlong, ppVlongQueue)))
        goto exit;

    if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, q, prime_DSA, &isPrimeQ, ppVlongQueue)))
        goto exit;

    /* Q should have been prime with the provided seed */
    if (FALSE == isPrimeQ)
        goto exit;

    /* Let C = 0 and N = 1 */
    C = 0;
    N = 1;

    do
    {
        /* Vk = HASH((S + N + k) mod 2^g) */
        VLONG_clearVlong(W);    /* W = 0 */

        for (k = 0; k <= n; k++)
        {

            DIGI_MEMCPY(U_tmp, S, seedSize);

            carry = N + k;

            for (index = seedSize-1; 0 <= index; index--)
            {
                carry += U_tmp[index];

                U_tmp[index] = (ubyte)(carry & 0xff);

                carry >>= 8;

                if (0 == carry)
                    break;
            }

            /* Vk = HASH[(Seed + offset + k)] */
            if (OK > (status = FFC_getHashValue(MOC_FFC(hwAccelCtx) hashType, U_tmp, seedSize, U_hash)))
                goto exit;

            /* W += Vk; W = V0 + (V1 << shaSize) + ... + (Vk << (k * shaSize) */
            VLONG_freeVlong(&Vk, ppVlongQueue);

            if (OK > (status = VLONG_vlongFromByteString(U_hash, shaBytes, &Vk, ppVlongQueue)))
                goto exit;

            if (k == n)
            {
                ubyte4 i = (b + 1) / unitSize;
                vlong* tmp;
                for (i = shaSize/unitSize; i > (b / unitSize); i--)
                    if (OK > (status = VLONG_setVlongUnit(Vk, i, 0)))
                        goto exit;

                /* clear highest bit */
                VLONG_freeVlong(&bBit, ppVlongQueue);
                if (OK > (status = VLONG_allocVlong(&bBit, ppVlongQueue)))
                    goto exit;

                if (OK > (status = VLONG_setVlongBit(bBit, b)))
                    goto exit;

                if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) Vk, bBit, &tmp, ppVlongQueue)))
                    goto exit;

                VLONG_freeVlong(&Vk, ppVlongQueue);
                Vk = tmp; tmp = 0;

            }

            if (OK > (status = VLONG_shlXvlong(Vk, k * shaSize)))
                goto exit;

            if (OK > (status = VLONG_addSignedVlongs(W, Vk, ppVlongQueue)))
                goto exit;
        }

        /* X = W + (2^(L-1)) */
        VLONG_clearVlong(X);

        if (OK > (status = VLONG_setVlongBit(X, L - 1)))
            goto exit;

        if (OK > (status = VLONG_addSignedVlongs(X, W, ppVlongQueue)))
            goto exit;

        /* p = X - ((X mod 2q) - 1) */
        if (OK > (status = VLONG_shlVlong(q)))
            goto exit;

        VLONG_freeVlong(&p, ppVlongQueue);
        if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) X, q, &p, ppVlongQueue)))
            goto exit;


        if (OK > (status = VLONG_shrVlong(q)))
            goto exit;

        if (OK > (status = VLONG_decrement(p, ppVlongQueue)))
            goto exit;

        /* negate it */
        p->negative ^= TRUE;

        if (OK > (status = VLONG_addSignedVlongs(p, X, ppVlongQueue)))
            goto exit;

        /* if p < (2^(L-1)), we need to try p again */
        if ((0 != (p->pUnits[0] & 1)) && (!p->negative) && (VLONG_bitLength(p) >= L))
        {
            if (OK > (status = PRIME_doPrimeTestsEx(MOC_MOD(hwAccelCtx) pFipsRngCtx, p, prime_DSA, &isPrimeP, ppVlongQueue)))
                goto exit;

            /* if p is prime, we got our prime pair */
            if (isPrimeP)
                break;
        }

        /* C = C + 1 and N = N + n + 1 */
        C++;
        N += n + 1;
    }
    while ((iterations > C) && (FALSE == isPrimeP));

    /* p should have been prime from q, based on the seed */
    if (FALSE == isPrimeP)
        goto exit;

    /* PQ are both prime */
    *pIsPrimePQ = TRUE;

    /* set the output pointers */
    
    *ppNewP = p; p = NULL;
    *ppNewQ = q; q = NULL;
    
    if (NULL != pRetC)
        *pRetC = C;

exit:
    
    FREE(S);
    FREE(U);
    FREE(U_tmp);
    FREE(U_hash);
    VLONG_freeVlong(&q, ppVlongQueue);
    VLONG_freeVlong(&W, ppVlongQueue);
    VLONG_freeVlong(&Vk, ppVlongQueue);
    VLONG_freeVlong(&X, ppVlongQueue);
    VLONG_freeVlong(&p, ppVlongQueue);
    VLONG_freeVlong(&bBit, ppVlongQueue);
    VLONG_freeVlong(&U_vlong, ppVlongQueue);
    VLONG_freeVlong(&U_vlongtmp, ppVlongQueue);

    return status;

} /* computePQ_FIPS_1864 */
#endif
