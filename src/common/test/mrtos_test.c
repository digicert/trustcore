/*
 * mrtos_test.c
 *
 * unit test for RTOS
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

#include "../../common/moptions.h"

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"


#include "../../../unit_tests/unittest.h"

int mrtos_test_time()
{
    int retVal = 0;
    ubyte4 diff1, diff2;
    moctime_t t1, t2, t3;

    RTOS_deltaMS( NULL, &t1);

    RTOS_sleepMS( 100);

    diff1 = RTOS_deltaMS( &t1, &t2);

    retVal += UNITTEST_TRUE(diff1, diff1 >= 100);
    retVal += UNITTEST_TRUE(diff1, diff1 <= 500);

    RTOS_sleepMS(100);

    diff2 = RTOS_deltaMS( &t1, &t3);

    retVal += UNITTEST_TRUE(diff2, diff2 >= 200);
    retVal += UNITTEST_TRUE(diff1, diff2 <= 1000);

    retVal += UNITTEST_TRUE(0, diff1 <= diff2);

    return retVal;
}