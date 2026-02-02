/*
 * sort_test.c
 *
 * Mocana Sort Test
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
#include "../../common/mstdlib.h"
#include "../../common/sort.h"

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined( __RTOS_OSX__)
#include <stdio.h>
#define PRINTF1      printf
#define PRINTF2      printf
#define PRINTF3      printf
#define PRINTF4      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF1(R)
#define PRINTF2(R,S)
#define PRINTF3(R,S,T)
#define PRINTF4(R,S,T,U)
#endif


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4  order;
    ubyte   hexOrder[9];

} testStruct;

testStruct testArray[128];


/*------------------------------------------------------------------*/

static void
initArray(void)
{
    sbyte4 i, j = (sizeof(testArray) / sizeof(testStruct));

    for (i = 0; i < (sizeof(testArray) / sizeof(testStruct)); i++, j--)
    {
        testArray[i].order = j;
        /* FIXME:  stdio.h required */
        sprintf((char *)testArray[i].hexOrder, "%08x", j);
    }
}


/*------------------------------------------------------------------*/

static void
dumpArray(void)
{
    sbyte4 i;

    for (i = 0; i < (sizeof(testArray) / sizeof(testStruct)); i++)
    {
        PRINTF4("%3d:   %3d, %s\n", i, testArray[i].order, testArray[i].hexOrder);
    }
}


/*------------------------------------------------------------------*/

static intBoolean
testSortResults(sbyte4 lowerRange, sbyte4 upperRange, intBoolean doOutput)
{
    sbyte4      i;
    intBoolean  didTestFail = FALSE;

    for (i = lowerRange + 1; i <= upperRange; i++)
    {
        if (testArray[i - 1].order > testArray[i].order)
        {
            if (doOutput)
            {
                PRINTF1("testArray: array not properly sorted!\n");
                dumpArray();
            }

            didTestFail = TRUE;
            break;
        }
    }

    return didTestFail;
}


/*------------------------------------------------------------------*/

static MSTATUS
testValue(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess)
{
    testStruct* pFirstValue  = (testStruct *)pFirstItem;
    testStruct* pSecondValue = (testStruct *)pSecondItem;

    *pRetIsLess = (pFirstValue->order < pSecondValue->order) ? TRUE : FALSE;

    return OK;
}


/*------------------------------------------------------------------*/

int sort_test(void)
{
    intBoolean  notSorted;
    int         numTestFail = 0;
    MSTATUS     status;

    initArray();

    notSorted = testSortResults(0, 127, FALSE);     /* negative test */
    if (FALSE == notSorted)
        numTestFail++;

    status = SORT_shellSort(testArray, sizeof(testStruct), 0, 127, testValue);

    notSorted = testSortResults(0, 127, TRUE);
    if (TRUE == notSorted)
        numTestFail++;

    status = SORT_shellSort(testArray, sizeof(testStruct), 0, 127, testValue);

    notSorted = testSortResults(0, 127, TRUE);
    if (TRUE == notSorted)
        numTestFail++;

    initArray();

    notSorted = testSortResults(0, 127, FALSE);     /* negative test */
    if (FALSE == notSorted)
        numTestFail++;

    status = SORT_shellSort(testArray, sizeof(testStruct), 1, 126, testValue);

    notSorted = testSortResults(0, 127, FALSE);     /* negative test */
    if (FALSE == notSorted)
        numTestFail++;

    notSorted = testSortResults(1, 126, TRUE);
    if (TRUE == notSorted)
        numTestFail++;

exit:
    return numTestFail;
}


/*------------------------------------------------------------------*/

//int main()
//{
//    return sort_test();
//}
