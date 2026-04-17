/*
 * prime.h
 *
 * Prime Factory Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
