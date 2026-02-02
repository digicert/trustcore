/*
 * base64m_test.c
 *
 * Base64 Encoder & Decoder Test
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
#include "../../common/mrtos.h"
#define __IN_DIGICERT_C__     /* FOR TESTING PURPOSES --- ENABLES BASE64 init/free */
#include "../../common/base64.h"

/* #include "../base64m.c"  */

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <string.h>
#define PRINTF1      printf
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF1(X)
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++
static int error_line = 0;
static int numTests = 0;


/*------------------------------------------------------------------*/

#define MAX_BUF_SIZE        4096

static ubyte *p_testInput[] =
{
    (ubyte *)"abc",
    (ubyte *)"abcd",
    (ubyte *)"abcde",
    (ubyte *)"abcdef",
    (ubyte *)"abcdefg",
    (ubyte *)"abcdefgh"
};

static ubyte *p_testResult[] =
{
    (ubyte *)"YWJj",
    (ubyte *)"YWJjZA==",
    (ubyte *)"YWJjZGU=",
    (ubyte *)"YWJjZGVm",
    (ubyte *)"YWJjZGVmZw==",
    (ubyte *)"YWJjZGVmZ2g=",
};

static ubyte *p_testInputUrl[] =
{
    (ubyte *)"",
    (ubyte *)"f",
    (ubyte *)"fo",
    (ubyte *)"foo",
    (ubyte *)"foob",
    (ubyte *)"fooba",
    (ubyte *)"foobar",
};

static ubyte *p_testResultUrl[] =
{
    (ubyte *)"",
    (ubyte *)"Zg",
    (ubyte *)"Zm8",
    (ubyte *)"Zm9v",
    (ubyte *)"Zm9vYg",
    (ubyte *)"Zm9vYmE",
    (ubyte *)"Zm9vYmFy",
};

static ubyte bigTest[MAX_BUF_SIZE];


/*------------------------------------------------------------------*/

int base64m_test_all()
{
    ubyte*  pRetBuffer1 = NULL;
    ubyte*  pRetBuffer2 = NULL;
    ubyte4  origLength1;
    ubyte4  origLength2;
    ubyte4  retLength1;
    ubyte4  retLength2;
    sbyte4  result;
    sbyte4  i;
    MSTATUS status;

    TEST_IT(OK > (status = BASE64_initializeContext()));

    /* simple tests */
    for (i = 0; i < 6; i++)
    {
        origLength1 = DIGI_STRLEN((const sbyte *)(p_testInput[i]));
        origLength2 = DIGI_STRLEN((const sbyte *)(p_testResult[i]));

        TEST_IT(OK > (status = BASE64_encodeMessage(p_testInput[i], origLength1, &pRetBuffer1, &retLength1)));

        TEST_IT(retLength1 != origLength2);

        TEST_IT(OK > (status = DIGI_MEMCMP(pRetBuffer1, p_testResult[i], retLength1, &result)));

        TEST_IT(0 != result);

        TEST_IT(OK > (status = BASE64_decodeMessage(pRetBuffer1, retLength1, &pRetBuffer2, &retLength2)));

        TEST_IT(retLength2 != origLength1);

        TEST_IT(OK > (status = DIGI_MEMCMP(pRetBuffer2, p_testInput[i], retLength2, &result)));

        TEST_IT(0 != result);

        BASE64_freeMessage(&pRetBuffer1);
        BASE64_freeMessage(&pRetBuffer2);
    }

    /* exhaustive test */
    for (i = 0; i < MAX_BUF_SIZE; i++)
        bigTest[i] = 0xab + (i % 0x7f);

    for (i = 1; i < MAX_BUF_SIZE - 1; i++)
    {
        /* encode - decode */
        TEST_IT(OK > (status = BASE64_encodeMessage(bigTest, i, &pRetBuffer1, &retLength1)));
        TEST_IT(OK > (status = BASE64_decodeMessage(pRetBuffer1, retLength1, &pRetBuffer2, &retLength2)));

        /* compare before and after */
        TEST_IT(OK > (status = DIGI_MEMCMP(bigTest, pRetBuffer2, retLength2, &result)));
        TEST_IT(0 != result);

        BASE64_freeMessage(&pRetBuffer1);
        BASE64_freeMessage(&pRetBuffer2);
    }

    TEST_IT(OK > (status = BASE64_freeContext()));

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\nbase64m_test_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}

int base64m_test_url_all()
{
    ubyte*  pRetBuffer1 = NULL;
    ubyte*  pRetBuffer2 = NULL;
    ubyte4  origLength1;
    ubyte4  origLength2;
    ubyte4  retLength1;
    ubyte4  retLength2;
    sbyte4  result;
    volatile sbyte4  i;
    MSTATUS status;

    TEST_IT(OK > (status = BASE64_initializeContext()));

    /* simple tests */
    for (i = 0; i < 6; i++)
    {
        origLength1 = DIGI_STRLEN((const sbyte *)(p_testInputUrl[i]));
        origLength2 = DIGI_STRLEN((const sbyte *)(p_testResultUrl[i]));

        TEST_IT(OK > (status = BASE64_urlEncodeMessage(p_testInputUrl[i], origLength1, &pRetBuffer1, &retLength1)));

        TEST_IT(retLength1 != origLength2);

        TEST_IT(OK > (status = DIGI_MEMCMP(pRetBuffer1, p_testResultUrl[i], retLength1, &result)));

        TEST_IT(0 != result);

        TEST_IT(OK > (status = BASE64_urlDecodeMessage(pRetBuffer1, retLength1, &pRetBuffer2, &retLength2)));

        TEST_IT(retLength2 != origLength1);

        TEST_IT(OK > (status = DIGI_MEMCMP(pRetBuffer2, p_testInputUrl[i], retLength2, &result)));

        TEST_IT(0 != result);

        BASE64_freeMessage(&pRetBuffer1);
        BASE64_freeMessage(&pRetBuffer2);
    }

    /* exhaustive test */
    for (i = 0; i < MAX_BUF_SIZE; i++)
        bigTest[i] = 0xab + (i % 0x7f);

    for (i = 21; i < MAX_BUF_SIZE - 1; i++)
    {
        /* encode - decode */
        TEST_IT(OK > (status = BASE64_urlEncodeMessage(bigTest, i, &pRetBuffer1, &retLength1)));
        TEST_IT(OK > (status = BASE64_urlDecodeMessage(pRetBuffer1, retLength1, &pRetBuffer2, &retLength2)));

        /* compare before and after */
        TEST_IT(OK > (status = DIGI_MEMCMP(bigTest, pRetBuffer2, retLength2, &result)));
        if (0 != result)
        {
            printf("it failed on test i: %d\n", i);
        }
        TEST_IT(0 != result);

        BASE64_freeMessage(&pRetBuffer1);
        BASE64_freeMessage(&pRetBuffer2);
    }

    TEST_IT(OK > (status = BASE64_freeContext()));

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\nbase64m_test_url_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}


//int main(int argc, char* argv[])
//{
//    return mstdlib_test_all();
//}
