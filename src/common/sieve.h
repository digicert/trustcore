/*
 * sieve.h
 *
 * Prime Sieve Factory Header
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

#ifndef __SIEVE_HEADER__
#define __SIEVE_HEADER__

MOC_EXTERN MSTATUS SIEVE_findDiffieHellmanEphemeralP(MOC_PRIME(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, vlong **ppRetPrimeP, ubyte4 primeBitLength, vlong **ppVlongQueue);

#endif /* __SIEVE_HEADER__ */
