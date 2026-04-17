/*
 * merrors_test.c
 *
 * Mocana Error Test
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

/*! Mocana error look up.
This file contains functions enabling Mocana error code look up.

! External Functions
This file contains the following public ($extern$) functions:
- $MERROR_lookUpErrorCode$

*/

#define __INTERNAL_MERRORS__

#include "../moptions.h"

#ifndef __ENABLE_LOOKUP_TABLE__
#define __ENABLE_LOOKUP_TABLE__
#endif

#include "../mdefs.h"
#include "../mtypes.h"

/* setup for enum list */
#ifdef   __ERROR_LOOKUP_TABLE__
#undef   __ERROR_LOOKUP_TABLE__
#endif
#include "../merrors.h"

/* setup for lookup table */
#define  __ERROR_LOOKUP_TABLE__
#undef   __MERRORS_HEADER__
#undef   ERROR_DEF
#undef   ERROR_DEF_LAST

#include "../merrors.h"
#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#define PRINTF1      printf
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF1(R)
#define PRINTF2(R,S)
#define PRINTF3(R,S,T)
#endif


/*------------------------------------------------------------------*/

#define NUM_ERROR_CODES     (sizeof(m_ErrorLookupTable) / sizeof(errDescr))


/*---------------------------------------------------------------------------*/

static int
MERRORS_TEST_verifyErrorCodesAreSorted(void)
{
    int     testResult = 0;
    int     index;
    MSTATUS errorCode = m_ErrorLookupTable[0].errorCode;

    for (index = 1; index < NUM_ERROR_CODES; index++)
    {
        if (errorCode < m_ErrorLookupTable[index].errorCode)
        {
            PRINTF1("MERRORS_TEST_verifyErrorCodesAreSorted: list is not sorted!\n");
            PRINTF3("errorMesg = %s, errorCode = %d\n", m_ErrorLookupTable[index].pErrorMesg, m_ErrorLookupTable[index].errorCode);
            testResult++;
        }
        else if (errorCode == m_ErrorLookupTable[index].errorCode)
        {
            PRINTF1("MERRORS_TEST_verifyErrorCodesAreSorted: list contains duplicate!\n");
            PRINTF3("errorMesg = %s, errorCode = %d\n", m_ErrorLookupTable[index].pErrorMesg, m_ErrorLookupTable[index].errorCode);
            testResult++;
        }

        errorCode = m_ErrorLookupTable[index].errorCode;
    }

    return testResult;
}


/*---------------------------------------------------------------------------*/

int merrors_test_all()
{
    int     testResult = 0;

    /* Remove the tests at the request of Atul and Sumit
    testResult += MERRORS_TEST_verifyErrorCodesAreSorted();
    */

    return testResult;
}


//int main(int argc, char* argv[])
//{
//    return merrors_test_all();
//}
