/*
 * prime_test.c
 *
 * unit test for prime.c
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

#include "../prime.c"

#include "../../../unit_tests/unittest.h"

#include "print_vlong.c"

/* in vlong_test.c */
extern void MakeVlongFromString(const sbyte* s, vlong** newVlong, vlong** ppQueue);

const sbyte* tests[] =
{
  "809314ECDE98D5A3E1D7BFB23EE3AE85423E97173BF8A689F34CC2250E06AB416810FC"
  "1282A89D91C81FD8B4463A27C9FDBA7DE6645FA2EB6E3CE30D58C8DBE7",
  "8020864FC66280B7D217FECB1A86D944DB3DA2B5660E7E47D9F196467437D1C94F5A8F"
  "18F6F91FABEE207FA7FED5E54E811B904EE46B0FA4CCC9E4AAF7872557"
};

int prime_test_1()
{
    int retVal = 0;
    vlong* pTest = 0;
    int i;
    intBoolean isPrime;
    randomContext* pRandomContext;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    RANDOM_acquireContext( &pRandomContext);

    for (i = 0; i < COUNTOF(tests); ++i)
    {
        MakeVlongFromString( tests[i], &pTest, NULL);
        retVal += UNITTEST_STATUS( i, PRIME_doPrimeTests(MOC_MOD(hwAccelCtx) pRandomContext, 
                                                         pTest,
                                                         &isPrime, 
                                                         NULL));
        retVal += UNITTEST_TRUE(i, isPrime);
        VLONG_freeVlong(&pTest, NULL);
    } 

    RANDOM_releaseContext( &pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

