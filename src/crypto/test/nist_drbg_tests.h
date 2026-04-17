/*
 * nist_drbg_tests.h
 *
 * DRBG test vectors from NIST
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