/*
 * mbitmap_test.c
 *
 * Mocana Bit Map Test
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
#include "../../common/mstdlib.h"
#include "../../common/mlimits.h"
#include "../../common/mbitmap.h"

/* #include "../mbitmap.c"  */

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__)
#include <stdio.h>
#include <string.h>
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++;
static int error_line;

/*------------------------------------------------------------------*/

int mbitmap_test_all()
{
    ubyte4          index, loop;
    intBoolean      isSet;
    bitmapDescr*    pBitMapDescr = NULL;
    ubyte4          numTests = 0;
    MSTATUS         status = OK;

    TEST_IT(OK > (status = MBITMAP_createMap(&pBitMapDescr, 1024, 2049)))

    for (loop = 1024; loop <= 2049; loop++)
    {
        TEST_IT(OK > (status = MBITMAP_findVacantIndex(pBitMapDescr, &index)))

        TEST_IT(OK > (status = MBITMAP_isIndexSet(pBitMapDescr, index, &isSet)))

        TEST_IT(FALSE == isSet)
    }

    /* negative test */
    TEST_IT(OK <= (status = MBITMAP_findVacantIndex(pBitMapDescr, &index)))

    for (loop = 1023; loop < 2051; loop++)
    {
        /* negative test */
        TEST_IT(OK <= (status = MBITMAP_testAndSetIndex(pBitMapDescr, loop)))
    }

    for (loop = 1023; loop < 2051; loop++)
    {
        status = MBITMAP_clearIndex(pBitMapDescr, loop);

        if (1024 > loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else if (2049 < loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else TEST_IT(OK > status)    /* if we're in range the code should always succeed */
    }

    for (loop = 0; loop <= (2049 - 1024); loop++)
    {
        TEST_IT(OK > (status = MBITMAP_findVacantIndex(pBitMapDescr, &index)))

        TEST_IT(OK > (status = MBITMAP_isIndexSet(pBitMapDescr, index, &isSet)))

        TEST_IT(FALSE == isSet)
    }

    for (loop = 1023; loop < 2051; loop++)
    {
        status = MBITMAP_clearIndex(pBitMapDescr, loop);

        if (1024 > loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else if (2049 < loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else TEST_IT(OK > status)    /* if we're in range the code should always succeed */
    }

    for (loop = 0; loop <= (2049 - 1024); loop++)
    {
        TEST_IT(OK > (status = MBITMAP_findVacantIndex(pBitMapDescr, &index)))

        TEST_IT(1024 != index)

        TEST_IT(OK > (status = MBITMAP_isIndexSet(pBitMapDescr, index, &isSet)))

        TEST_IT(FALSE == isSet)

        TEST_IT(OK > (status = MBITMAP_clearIndex(pBitMapDescr, index)))

        TEST_IT(OK > (status = MBITMAP_isIndexSet(pBitMapDescr, index, &isSet)))

        TEST_IT(TRUE == isSet)
    }

    for (loop = 1023; loop < 2051; loop++)
    {
        status = MBITMAP_clearIndex(pBitMapDescr, loop);

        if (1024 > loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else if (2049 < loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else TEST_IT(OK > status)    /* if we're in range the code should always succeed */
    }

    for (loop = 1023; loop < 2051; loop++)
    {
        status = MBITMAP_testAndSetIndex(pBitMapDescr, loop);

        if (1024 > loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else if (2049 < loop)
        {
            /* out of range should always fail */
            TEST_IT(OK <= status)
        }
        else TEST_IT(OK > status)    /* if we're in range the code should always succeed */
    }

    status = MBITMAP_releaseMap(&pBitMapDescr);

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\nmstdlib_test_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}
