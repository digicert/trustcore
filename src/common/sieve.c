/*
 * sieve.c
 *
 * Prime Sieve Factory
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_PRIME_SIEVE__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/prime.h"
#include "../common/sieve.h"


/*------------------------------------------------------------------*/

#define PRIME_SIEVE_PRODUCT         (3 * 5 * 7 * 11 * 13)


/*------------------------------------------------------------------*/

/* Lookup table: */
/* 1) Build look up table for p, where base_p is a big prime multiplied by (8 * PRIME_SIEVE_PRODUCT) */
/* 2) find p prime candidates that are p mod 24 == 11; and not multiples of 3,5,7,11,13 */
/* 3) find q prime candidates that are not multiples of 3,5,7,11,13 */
/* 4) merge these two tables together, so that we only search prime candidates that are potentials from p and q tables */
/* 5) output data: least significant bit corresponds to smallest prime candidate for fast lookups */

/* Revenge of the Sieve: */
/* 1) Pick a random index % table size */
/* 2) Pick a random big prime (base_p) */
/* 3) multiple base_p by (8 * PRIME_SIEVE_PRODUCT) */
/* 4) search for primes p & q, where RFC-4119 2q+1 = p, or how our code is written (p-1)/2 = q */


/*------------------------------------------------------------------*/

static ubyte4 qpPrimeCandidates[] = {
    0xfe77bd63UL, 0x738d7bdeUL, 0xdd6b79e7UL, 0xe75ae7bbUL, 0x1ef6fddeUL,
    0xdef1cfe7UL, 0xb5aef77eUL, 0xbd77bbc6UL, 0x63ddcf3dUL, 0xbcfff7bdUL,
    0xeff38d7bUL, 0x7bde6b59UL, 0xfde75ae7UL, 0xe71ef73dUL, 0xbadef3ceUL,
    0xc6bdae77UL, 0x3dfd7bb9UL, 0xbdf3ddceUL, 0x6b3ceff7UL, 0x5aeff38dUL,
    0xd77b9e7fUL, 0x39fde77aUL, 0xfee71edfUL, 0x77bed6b3UL, 0xf9cebd9eUL,
    0xcf35ee7bUL, 0xf7adf7bdUL, 0x8f6b1cefUL, 0x7fdaf773UL, 0x7fd73b9dUL,
    0xde39ddebUL, 0xbdfee71aUL, 0x9e77bdf6UL, 0x73fbcef5UL, 0xbdcf37aeUL,
    0xeff9ad6fUL, 0xf39f6f1cUL, 0xdd6bdcf7UL, 0xeb5fcf3bUL, 0x9ad639feUL,
    0xf7bdfee7UL, 0xf78e7779UL, 0xac73bbd7UL, 0x6bbdceb7UL, 0x1cee79efUL,
    0xf7f79defUL, 0x7bdceb5cUL, 0xfef35acfUL, 0xe7bbd639UL, 0x78d7bdffUL,
    0xd7b79e77UL, 0xb5ac7bbdUL, 0xef6fddeeUL, 0xef1cfe71UL, 0x5cef77edUL,
    0xd77bbcebUL, 0x39dcf3daUL, 0xcfef7bd6UL, 0xf738d7bdUL, 0xbde6b79eUL,
    0xee75ae7bUL, 0x71af77dfUL, 0xedef3cfeUL, 0x6b5aef7bUL, 0xdfd7bbbcUL,
    0xde3ddce3UL, 0xb3ceff5bUL, 0xaeff38d7UL, 0x77b9e7b5UL, 0x9fde77aeUL,
    0xee71ed73UL, 0x7bedeb3dUL, 0x9cebdae7UL, 0xe35fe7bfUL, 0x7adf7ddcUL,
    0xd6b3cef7UL, 0xfdaf7f38UL, 0xbd77b9e7UL, 0xe39ddeb7UL, 0x5fee71edUL,
    0xe77bef6bUL, 0x3fbcefd9UL, 0xdcf35ae7UL, 0xffbad77bUL, 0x39f6b1ceUL,
    0xd6fdcf7fUL, 0xb5fdf3b9UL, 0xade39deeUL, 0x7bdeee71UL, 0x79e77b9fUL,
    0xc73fbd6fUL, 0xbbdcf37aUL, 0xceef9ed6UL, 0x7f79fef1UL, 0xbdd6b5cfUL,
    0xef35ecf7UL, 0x7bad639fUL, 0x9d7b9ffeUL, 0x7b79e777UL, 0x7ac73bddUL,
    0xf6bddcebUL, 0xf1cee71eUL, 0xcf777adeUL, 0xf7bdceb5UL, 0x9fcf3dadUL,
    0xfefbbd63UL, 0x778d6bddUL, 0xde7b79efUL, 0xef5ac7bbUL, 0x1af77dfeUL,
    0xd6f3cfe7UL, 0xb5cef7beUL, 0xed7bbbceUL, 0xe39dce3dUL, 0x5ceef5bdUL,
    0xef738d7bUL, 0xbb9e7b7aUL, 0xffe77ae7UL, 0xe71ad779UL, 0xbcdeb3dfUL,
    0xceb5aef7UL, 0x3dfe7bfbUL, 0xade7ddceUL, 0x7b3cef75UL, 0xdaf7f38dUL,
    0xe77b9e7bUL, 0x39ddef7bUL, 0xdee71ed6UL, 0x773efeb5UL, 0xfbcefdaeUL,
    0xce35be73UL, 0x7bad77fdUL, 0x9d6b3cefUL, 0x6fdcf7f3UL, 0x5bdf7b9eUL,
    0xde39dfebUL, 0xb5eee71eUL, 0x9e77baf7UL, 0x73fbd6ffUL, 0xbdcf35acUL,
    0xeefbed7bUL, 0xf79feb1cUL, 0x9d6f5ce7UL, 0xf35edf7bUL, 0x3ade39deUL,
    0xd7b9efe7UL, 0xb79e77b9UL, 0xac73fdd6UL, 0x6bfdcf37UL, 0x1ceef1efUL,
    0xf777afefUL, 0x7bdd6b58UL, 0xfcf3dedfUL, 0xefbbd639UL, 0x79d6b9dfUL,
    0xe7b59ef7UL, 0xf7ac73bdUL
};

#define SIZEOF_QP_PRIME_CANDIDATE_TABLE     (sizeof(qpPrimeCandidates) / sizeof(ubyte4))


/*------------------------------------------------------------------*/

static MSTATUS
SIEVE_findStartingBase(MOC_PRIME(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                       vlong *pPrimeFactor, ubyte4 primeBitLength, vlong **ppRetBaseP, vlong **ppVlongQueue)
{
    vlong*  pBigRngPrime = NULL;
    vlong*  pBaseP = NULL;
    ubyte4  primeFactorBitLen;
    MSTATUS status;

    if (OK > (status = VLONG_allocVlong(&pBaseP, ppVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pBaseP);

    primeFactorBitLen = VLONG_bitLength(pPrimeFactor) + 3;        /* + shl 3 */

    do
    {
        /* to prevent leaks, if we need to loop */
        VLONG_freeVlong(&pBigRngPrime, ppVlongQueue);

        /* find a big prime */
        if (OK > (status = PRIME_generateSizedPrime(MOC_PRIME(hwAccelCtx) pRandomContext, &pBigRngPrime, (1 | primeBitLength) - primeFactorBitLen, ppVlongQueue)))
            goto exit;

        /* multiply prime against our factors (i.e. 3*5*7*11*13), which allows us to use our bit map to mask out multiples of 3,5,7,11,13 */
        if (OK > (status = VLONG_vlongSignedMultiply(pBaseP, pPrimeFactor, pBigRngPrime)))
            goto exit;

        /* multiple of 24, so we can do quick 11 == p mod 24 table lookups */
        if (OK > (status = VLONG_shlXvlong(pBaseP, 3)))
            goto exit;

        /* add 11 for generator 2, 11 == p mod 24 */
        if (OK > (status = VLONG_addImmediate(pBaseP, 11, ppVlongQueue)))
            goto exit;
    }
    while (primeBitLength != VLONG_bitLength(pBaseP));

    *ppRetBaseP = pBaseP;
    pBaseP = NULL;

exit:
    VLONG_freeVlong(&pBigRngPrime, ppVlongQueue);
    VLONG_freeVlong(&pBaseP, ppVlongQueue);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SIEVE_startingIndex(randomContext *pRandomContext, ubyte4 *pRetIndex)
{
    ubyte4  index;
    MSTATUS status;

    if (OK > (status = RANDOM_numberGenerator(pRandomContext, (ubyte *)&index, sizeof(ubyte4))))
        goto exit;

    index = index % ((8 * PRIME_SIEVE_PRODUCT) / 24);

    *pRetIndex = index;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SIEVE_findDiffieHellmanEphemeralP(MOC_PRIME(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, vlong **ppRetPrimeP, ubyte4 primeBitLength, vlong **ppVlongQueue)
{
    intBoolean  isPrime      = FALSE;
    vlong*      pPrimeFactor = NULL;
    vlong*      pBaseP       = NULL;
    vlong*      pQ           = NULL;
    ubyte4      index;
    MSTATUS     status;

    /* set prime sieve factor */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(PRIME_SIEVE_PRODUCT, &pPrimeFactor, ppVlongQueue)))
        goto exit;

    DEBUG_PRINT(0, "SIEVE_findDiffieHellmanEphemeralP: start = ");
    DEBUG_UPTIME(0);
    DEBUG_PRINTNL(0, "");

    /* chose a random big prime */
    if (OK > (status = SIEVE_findStartingBase(MOC_PRIME(hwAccelCtx) pRandomContext, pPrimeFactor, primeBitLength, &pBaseP, ppVlongQueue)))
        goto exit;

    /* chose a random starting index */
    if (OK > (status = SIEVE_startingIndex(pRandomContext, &index)))
        goto exit;

    /* fast forward to appropriate offset (0, 24, 48, ... */
    if (OK > (status = VLONG_addImmediate(pBaseP, 24 * index, ppVlongQueue)))
        goto exit;

    while (FALSE == isPrime)
    {
        /* the precomputed sieve skips all bad p||q candidates (i.e. multiples of 3, 5, 7, 11 and 13) */
        if (0 == (qpPrimeCandidates[index / 32] & (1 << (index % 32))))
        {
            /* clear bits are prime candidates */
            /* test p */
            if (OK > (status = VLONG_makeVlongFromVlong(pBaseP, &pQ, ppVlongQueue)))
                goto exit;

            /* test (p-1)/2 == p/2 */
            if (OK > (status = VLONG_shrVlong(pQ)))
                goto exit;

            /* test p & q simultaneously */
            if (OK > (status = PRIME_doDualPrimeTests(MOC_MOD(hwAccelCtx) pRandomContext, 5, pQ, pBaseP, &isPrime, ppVlongQueue)))
                goto exit;

            VLONG_freeVlong(&pQ, ppVlongQueue);

            if (TRUE == isPrime)
                break;
        }

        /* move to next bit */
        index = ((index + 1) % ((8 * PRIME_SIEVE_PRODUCT) / 24));

        if (0 == index)
        {
            DEBUG_PRINT(0, ".");
        }

        if (OK > (status = VLONG_addImmediate(pBaseP, 24, ppVlongQueue)))
            goto exit;
    }

    DEBUG_PRINTNL(0, "");
    DEBUG_PRINT(0, "SIEVE_findDiffieHellmanEphemeralP: end = ");
    DEBUG_UPTIME(0);
    DEBUG_PRINTNL(0, "");

    *ppRetPrimeP = pBaseP;
    pBaseP = NULL;

exit:
    VLONG_freeVlong(&pQ, ppVlongQueue);
    VLONG_freeVlong(&pPrimeFactor, ppVlongQueue);
    VLONG_freeVlong(&pBaseP, ppVlongQueue);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_PRIME_SIEVE__)) */
