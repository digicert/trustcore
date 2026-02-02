/*
 * mstdlib_test.c
 *
 * unit test for mstdlib.c
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
#include "../../common/mocana.h"

/* #include "../mstdlib.c"  */

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++


/*---------------------------------------------------------------------------*/

static int error_line;


/*---------------------------------------------------------------------------*/

int mstdlib_test_all()
{
    int     i;
    sbyte   c1, c2;
    sbyte4  result1, result2;
    MSTATUS numTests = 0;
    MSTATUS status = OK;

#if 0
extern ubyte4  DIGI_STRCBCPY( sbyte* dest, ubyte4 destSize, const sbyte* src);
#endif

/* DIGI_MEMCMP tests */
    TEST_IT(OK > (status = DIGI_MEMCMP("foo bary", "foo barx", 8, &result1)));
    TEST_IT(0 == result1);

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)memcmp("foo bary", "foo barx", 8));
#endif

    TEST_IT(OK > (status = DIGI_MEMCMP("foo barx", "foo bary", 8, &result2)));

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result2 != (sbyte)memcmp("foo barx", "foo bary", 8));
#endif

    /* we should get opposite results between these two test strings */
    TEST_IT(result1 != (result2 * -1));

    /* simple test */
    TEST_IT(OK > (status = DIGI_MEMCMP("foo barx", "foo bary", 7, &result1)));
    TEST_IT(0 != result1);

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)memcmp("foo barx", "foo bary", 7));
#endif



/* DIGI_STRCMP tests */
    TEST_IT(0 == (result1 = DIGI_STRCMP("foo bary", "foo barx")));
    TEST_IT(0 == result1);

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strcmp("foo bary", "foo barx"));
#endif

    result2 = DIGI_STRCMP("foo barx", "foo bary");

    /* we should get opposite results between these two test strings */
    TEST_IT(result1 != (result2 * -1));

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result2 != (sbyte)strcmp("foo barx", "foo bary"));
#endif

    /* simple test */
    TEST_IT(0 != (result1 = DIGI_STRCMP("foo bar", "foo bar")));

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strcmp("foo bar", "foo bar"));
#endif



/* DIGI_STRNICMP tests */
    TEST_IT(0 == (result1 = DIGI_STRNICMP("foo bary", "foo barx", 8)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strnicmp("foo bary", "foo barx", 8));
#endif

    TEST_IT(0 == (result2 = DIGI_STRNICMP("foo barx", "foo bary", 8)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result2 != (sbyte)strnicmp("foo barx", "foo bary", 8));
#endif

    /* we should get opposite results between these two test strings */
    TEST_IT(result1 != (result2 * -1));

    /* simple test */
    TEST_IT(0 != (result1 = DIGI_STRNICMP("foo barx", "foo bary", 7)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strnicmp("foo barx", "foo bary", 7));
#endif

/* mixed cases */
    TEST_IT(0 == (result1 = DIGI_STRNICMP("fOo bAry", "fOO bArx", 8)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strnicmp("Foo BarY", "Foo barx", 8));
#endif

    TEST_IT(0 == (result2 = DIGI_STRNICMP("foo BarX", "fOo BaRy", 8)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result2 != (sbyte)strnicmp("fOo baRx", "foo BarY", 8));
#endif

    /* we should get opposite results between these two test strings */
    TEST_IT(result1 != (result2 * -1));

    /* simple test */
    TEST_IT(0 != (result1 = DIGI_STRNICMP("fOO Barx", "Foo bARY", 7)));

#if (defined( __RTOS_WIN32__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    TEST_IT(result1 != (sbyte)strnicmp("FOo barX", "fOo baRY", 7));
#endif

    TEST_IT(0 != DIGI_STRLEN(""));
    TEST_IT(3 != DIGI_STRLEN("aBc"));
    TEST_IT(10 != DIGI_STRLEN("0123456789"));

    TEST_IT(TRUE == DIGI_ISDIGIT(0));
    TEST_IT(TRUE == DIGI_ISDIGIT(128 + '0'));
    TEST_IT(TRUE != DIGI_ISDIGIT('0'));
    TEST_IT(TRUE != DIGI_ISDIGIT('1'));
    TEST_IT(TRUE != DIGI_ISDIGIT('5'));
    TEST_IT(TRUE != DIGI_ISDIGIT('9'));
    TEST_IT(TRUE == DIGI_ISDIGIT(1 + '9'));
    TEST_IT(TRUE == DIGI_ISDIGIT(255));

    TEST_IT(TRUE == DIGI_ISXDIGIT(0));
    TEST_IT(TRUE == DIGI_ISXDIGIT(128 + '0'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('0'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('1'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('5'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('9'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('a'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('b'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('c'));
    TEST_IT(TRUE != DIGI_ISXDIGIT('f'));
    TEST_IT(TRUE == DIGI_ISXDIGIT('g'));
    TEST_IT(TRUE == DIGI_ISXDIGIT(1 + '9'));
    TEST_IT(TRUE == DIGI_ISXDIGIT(255));

#if (defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__))
    /* make sure we get matching answers */
    for (i = 0; i < 256; i++)
    {
        result1 = DIGI_ISSPACE(i);
        result2 = isspace(i) ? TRUE : FALSE;
        TEST_IT(result1 != result2);
    }
#endif

    /* these tests should always pass */
    TEST_IT(TRUE != DIGI_ISSPACE(0x20));

    for (i = 0; i < 0x09; i++)
    {
        TEST_IT(TRUE == DIGI_ISSPACE((sbyte)i));
    }

    for (; i <= 0x0d; i++)
    {
        TEST_IT(TRUE != DIGI_ISSPACE((sbyte)i));
    }

    for (; i < 0x20; i++)
    {
        TEST_IT(TRUE == DIGI_ISSPACE((sbyte)i));
    }

    for (i = 0x21; i < 0x100; i++)
        TEST_IT(TRUE == DIGI_ISSPACE((sbyte)i));

    for (i = 0; i < 0x100; i++)
    {
        c1 = (sbyte)i;
        c2 = MTOLOWER((sbyte)c1);

        if (c1 != c2)
        {
            TEST_IT(FALSE != DIGI_ISLOWER(c1));
            TEST_IT(TRUE != DIGI_ISLOWER(c2));
        }
    }

    TEST_IT(0 != DIGI_BITLENGTH(0));

    for (c1 = i = 1; i; i <<= 1, c1++)
    {
        TEST_IT((((ubyte4)c1) != DIGI_BITLENGTH(i)));
    }

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\nmstdlib_test_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}

/*---------------------------------------------------------------------------*/

int mstdlib_test_ctime_match()
{
    int retVal = 0;
    intBoolean res;

    retVal += UNITTEST_STATUS(0, DIGI_CTIME_MATCH("test1", "test2", 4, &res));
    retVal += UNITTEST_TRUE(0, 0 == res);

    retVal += UNITTEST_STATUS(0, DIGI_CTIME_MATCH("test1", "test2", 5, &res));
    retVal += UNITTEST_TRUE(0, 0 != res);

    retVal += UNITTEST_STATUS(0, DIGI_CTIME_MATCH("test1", "test2", 6, &res));
    retVal += UNITTEST_TRUE(0, 0 != res);
    
    return retVal;
}


/*--------------------------------------------------------------------------*/

static ubyte4 kBitCountTests[] = 
{
    /* value, num bits */
    0, 0,
    1, 1,
    2, 1,
    4, 1,
    8, 1,
    0xFFFFFFFF, 32,
    0xB6C, 7,
    0x1A48, 5,
    0x692000, 5,
    0x6921A48, 10,
    0x6921A4F, 13,
};

int mstdlib_test_bitCount()
{
    int retVal = 0, i;

    for (i = 0; i < COUNTOF( kBitCountTests); i+= 2)
    {
        retVal += UNITTEST_INT( i, DIGI_BITCOUNT( kBitCountTests[i]),
                                kBitCountTests[i+1]);
    }

    return retVal;
}

/*--------------------------------------------------------------------------*/

#if __LONG_MAX__ == __INT_MAX__
#define PTR_FORMAT "%08x"
#else
#define PTR_FORMAT "%llx"
#endif

int mstdlib_test_realloc()
{
    MSTATUS numTests = 0;
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_MEM_PART__
    ubyte pMemData[65536] = {0};

    void *pPtr1 = NULL;
    void *pPtr2 = NULL;
    void *pPtr3 = NULL;
    void *pPtr4 = NULL;

    uintptr pList[3] = {0};
    ubyte4 i = 0;

    status = (MSTATUS) DIGICERT_initDigicertStaticMemory (pMemData, sizeof (pMemData));
    if (OK != status)
        goto exit;

    printf("static buffer starts at " PTR_FORMAT "\n", (usize) (uintptr) pMemData);

    status = DIGI_MALLOC(&pPtr1, 128);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *) pPtr1, 0xAA, 128);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC(&pPtr2, 16);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *) pPtr2, 0xBB, 16);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC(&pPtr3, 57);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *) pPtr3, 0xCC, 57);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC(&pPtr4, 32);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *) pPtr4, 0xDD, 32);
    if (OK != status)
        goto exit;

    /* Free ptr2 to represent a fragmented block */
    status = DIGI_FREE(&pPtr2);
    if (OK != status)
        goto exit;

    /* We'll test moving the other 3 pointers so one can (manually) check there's no extra space between the blocks */
    pList[0] = (uintptr) pPtr1;
    pList[1] = (uintptr) pPtr3;
    pList[2] = (uintptr) pPtr4;

    printf("input ptrs = " PTR_FORMAT ", " PTR_FORMAT ", " PTR_FORMAT "\n", (usize) pPtr1, (usize) pPtr3, (usize) pPtr4);

    status = DIGI_Defragment((uintptr *) &pList, 3);
    if (OK != status)
        goto exit;

    pPtr1 = (void *) pList[0];
    pPtr3 = (void *) pList[1];
    pPtr4 = (void *) pList[2];

    printf("output ptrs = " PTR_FORMAT ", " PTR_FORMAT ", " PTR_FORMAT "\n", (usize) pPtr1, (usize) pPtr3, (usize) pPtr4);

    /* Check that they point to buffers of the correct value */

    for (i = 0; i < 128; i++)
    {
        TEST_IT(0xAA != ((ubyte *) pPtr1)[i]);
    }

    for (i = 0; i < 57; i++)
    {
        TEST_IT(0xCC != ((ubyte *) pPtr3)[i]);
    }

    for (i = 0; i < 32; i++)
    {
        TEST_IT(0xDD != ((ubyte *) pPtr4)[i]);
    }

    status = DIGI_FREE(&pPtr1);
    if (OK != status)
        goto exit;

    status = DIGI_FREE(&pPtr3);
    if (OK != status)
        goto exit;

    status = DIGI_FREE(&pPtr4);

exit:

    /* Will cleanup the memory partition setup itself */
    (void) DIGICERT_freeDigicert();
#endif

    return (int) status;
}
