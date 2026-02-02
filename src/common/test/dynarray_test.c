/*
 * dynarray_test.c
 *
 * unit test for dynarray.c
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

#include "../dynarray.c"

#include "../../../unit_tests/unittest.h"


#define NUMELEMEMTS (331)

int dynarray_test_1()
{
    DynArray dynArr;
    MSTATUS status;
    sbyte4 elementCount;
    int retVal = 0;
    long i;
    long* testArray = 0;
    long element;

    if  (OK > (status = DYNARR_Init( sizeof(long), &dynArr)))
    {
        return UNITTEST_STATUS(0, status);
    }

    for (i = 0; i < NUMELEMEMTS; i++)
    {
        retVal += UNITTEST_STATUS(i, DYNARR_Append( &dynArr, &i));
    }

    retVal += UNITTEST_STATUS( 0, DYNARR_GetElementCount( &dynArr, &elementCount));

    retVal += UNITTEST_INT(0, NUMELEMEMTS, elementCount);

    for (i = 0; i < elementCount; ++i)
    {
        retVal += UNITTEST_STATUS(i, DYNARR_Get( &dynArr, i, &element));
        retVal += UNITTEST_INT(i, element, i);
    }

    retVal += UNITTEST_STATUS(0, DYNARR_DetachArray( &dynArr, (void**) &testArray));

    for (i = 0; i < NUMELEMEMTS; i++)
    {
        retVal += UNITTEST_INT(i, testArray[i], i);
    }


    retVal += UNITTEST_STATUS(0, DYNARR_Uninit( &dynArr));

    if (testArray)
    {
        FREE(testArray);
    }

    return retVal;
}

