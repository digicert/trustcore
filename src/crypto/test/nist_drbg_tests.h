/*
 * nist_drbg_tests.h
 *
 * DRBG test vectors from NIST
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
#ifndef __NIST_DRBG_TESTS_HEADER__
#define __NIST_DRBG_TESTS_HEADER__

typedef struct 
{
    const char* entropyInput;
    const char* nonce;
    const char* personalizationString;
    const char* additionalInput1;
    const char* entropyInputPR1;
    const char* additionalInput2;
    const char* entropyInputPR2;
    const char* result;
} NIST_DRBG_TestVectorPR;

typedef struct 
{
    const char* entropyInput;
    const char* nonce;
    const char* personalizationString;
    const char* additionalInput1;
    const char* entropyInputReseed;
    const char* additionalInputReseed;
    const char* additionalInput2;    
    const char* result;
} NIST_DRBG_TestVectorNoPR;

#endif /* __NIST_DRBG_TESTS_HEADER__ */