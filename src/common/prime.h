/*
 * prime.h
 *
 * Prime Factory Header
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


/*------------------------------------------------------------------*/

#ifndef __PRIME_HEADER__
#define __PRIME_HEADER__

typedef enum
{
    prime_DSA,
    prime_RSA,
    prime_Legacy
} PrimeTestType;

MOC_EXTERN MSTATUS PRIME_simpleSmallPrimeTest(ubyte4 primeCandidate, intBoolean *pRetIsPrime);
MOC_EXTERN MSTATUS PRIME_doPrimeTestsEx(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, vlong *pPrime, PrimeTestType type, intBoolean *pIsPrime, vlong **ppVlongQueue);
MOC_EXTERN MSTATUS PRIME_doPrimeTests(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, vlong *pPrime, intBoolean *pIsPrime, vlong **ppVlongQueue);
MOC_EXTERN MSTATUS PRIME_doDualPrimeTests(MOC_MOD(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, sbyte4 startingIndex, vlong *pPrimeA, vlong *pPrimeB, intBoolean *pIsBothPrime, vlong **ppVlongQueue);
MOC_EXTERN MSTATUS PRIME_simplePrimeTest(MOC_MOD(hwAccelDescr hwAccelCtx) vlong *pPrime, ubyte4 startingIndex, ubyte4 endingIndex, intBoolean *pRetIsPrime, vlong **ppVlongQueue);
MOC_EXTERN MSTATUS PRIME_generateSizedPrime(MOC_PRIME(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, vlong **ppRetPrime, ubyte4 numBitsLong, vlong **ppVlongQueue);

#endif /* __PRIME_HEADER__ */
