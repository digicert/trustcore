/*
 * mrtos_test.c
 *
 * unit test for RTOS
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
