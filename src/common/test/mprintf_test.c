/*
 * mprintf_test.c
 *
 * Mocana printf Test
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

#ifdef __ENABLE_DIGICERT_PRINTF__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/moc_segment.h"
#include "../../common/mprintf.h"

#include "../../../unit_tests/unittest.h"

#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 1024

#ifndef LONG_MAX
#define LONG_MAX 0xffffffff
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

typedef struct printfTest
{
    ubyte*  format;
    void*   arg;
} printfTest;

#ifdef __ENABLE_MPRINTF_FLOAT__
typedef struct printfTestFloat
{
    ubyte*  format;
    double  arg;
} printfTestFloat;
#endif

static printfTest testCases[] =
{
    {(ubyte*) "%d", (void*)  0},
    {(ubyte*) "%d", (void*)  2222},
    {(ubyte*) "%d", (void*)  -1},
    {(ubyte*) "%d", (void*)  0xffffffffL},
    {(ubyte*) "%d", (void*)  0x7fffffffL},
    {(ubyte*) "%d", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%d", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%d", (void*)  0x0000ffffL},
    {(ubyte*) "%d", (void*)  0xffff0000L},

    {(ubyte*) "%u", (void*)  0},
    {(ubyte*) "%u", (void*)  1},
    {(ubyte*) "%u", (void*)  -1},
    {(ubyte*) "%u", (void*)  0xffffffffL},
    {(ubyte*) "%u", (void*)  0x7fffffffL},
    {(ubyte*) "%u", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%u", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%u", (void*)  0x0000ffffL},
    {(ubyte*) "%u", (void*)  0xffff0000L},

    {(ubyte*) "%i", (void*)  0},
    {(ubyte*) "%i", (void*)  1},
    {(ubyte*) "%i", (void*)  -1},
    {(ubyte*) "%i", (void*)  0xffffffffL},
    {(ubyte*) "%i", (void*)  0x7fffffffL},
    {(ubyte*) "%u", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%u", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%u", (void*)  0x0000ffffL},
    {(ubyte*) "%u", (void*)  0xffff0000L},

    {(ubyte*) "%x", (void*)  0},
    {(ubyte*) "%x", (void*)  1},
    {(ubyte*) "%x", (void*)  -1},
    {(ubyte*) "%x", (void*)  0xffffffffL},
    {(ubyte*) "%x", (void*)  0x7fffffffL},
    {(ubyte*) "%x", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%x", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%x", (void*)  0x0000ffffL},
    {(ubyte*) "%x", (void*)  0xffff0000L},

    {(ubyte*) "%X", (void*)  0},
    {(ubyte*) "%X", (void*)  1},
    {(ubyte*) "%X", (void*)  -1},
    {(ubyte*) "%X", (void*)  0xffffffffL},
    {(ubyte*) "%X", (void*)  0x7fffffffL},
    {(ubyte*) "%X", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%X", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%X", (void*)  0x0000ffffL},
    {(ubyte*) "%X", (void*)  0xffff0000L},

    {(ubyte*) "%o", (void*)  0},
    {(ubyte*) "%o", (void*)  1},
    {(ubyte*) "%o", (void*)  -1},
    {(ubyte*) "%o", (void*)  0xffffffffL},
    {(ubyte*) "%o", (void*)  0x7fffffffL},
    {(ubyte*) "%o", (void*)  0xf0f0f0f0L},
    {(ubyte*) "%o", (void*)  0x0f0f0f0fL},
    {(ubyte*) "%o", (void*)  0x0000ffffL},
    {(ubyte*) "%o", (void*)  0xffff0000L},

    {(ubyte*) "%c", (void*)  'a'},
    {(ubyte*) "%c", (void*)  '\n'},
    {(ubyte*) "%c", (void*)  '\0'},
    {(ubyte*) "%c", (void*)  '\t'},

    {(ubyte*) "%s", (void*)  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~`!@#$^&*()_-+=/?>.<,|'{} []"}
};

#ifdef __ENABLE_MPRINTF_FLOAT__
static printfTestFloat testCasesFloat[] =
{
    {(ubyte*) "%f", 0.0},
    {(ubyte*) "%f", 1.0},
    {(ubyte*) "%f", -1.0},
    {(ubyte*) "%f", 3.14e-10},
    {(ubyte*) "%f", 3.14e+10},
    {(ubyte*) "%f", -3.14e-10},
    {(ubyte*) "%f", 0.1e400},
    {(ubyte*) "%f", 0.1e-400},
    {(ubyte*) "%f", 0.666666},
    {(ubyte*) "%f", 3.12345678901234567890},
    {(ubyte*) "%f", 0xf0f0f0f0f0f0f0f0ULL},
    {(ubyte*) "%f", 0x0f0f0f0f0f0f0f0fULL},
    {(ubyte*) "%f", 0xffffffffffffffffULL},
    {(ubyte*) "%f", 1234567901234567890},

};
#endif

static ubyte* testStrings[] =
{
    (ubyte*) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~`!@#$^&*()_-+=/?>.<,|'{} []",
    (ubyte*) "%%\\\"\n\t\r\\",
    (ubyte*) "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%",
    NULL
};


char* s1[] =
{"", "+", "-", "0", " ", "#", "+-", "+0", "+ ", "+#", "- ", "-0", "-#", " 0", " #", "+-0", "+-#", "+- 0#", 0};

char* s2[] =
{"", "0", "0.0", "9", ".9", "9.9", "9.0", "57", ".57", "57.57", "57.0", "9.57", "57.9", "100", "0.100", "100.100", "100.0", 0};

char* s3[] =
{
    "", "h", "l", "hh", 
#ifdef __ENABLE_MPRINTF_LONG_LONG__
    "ll", 
#endif
    0
};

char* s4[] =
{"d", "i", "o", "u", "x", "X", "p", "c", "s", "%", 0};

int argNum[] =
{
    0, 1, -1, -11, 11, 0xffffffff, 0x7fffffff, 0xf0f0f0f0, 0x0f0f0f0f, 0xffff0000, 0x0000ffff, 0x00ff00ff,
    0xff00ff00, 0x77777777, 0xcccccccc, 0xc0c0c0c0, 0x0c0c0c0c
};

char* argStr[] =
{"", "hello", "world", "hello, world", 0};


/*------------------------------------------------------------------*/

int compareResults(ubyte *formatString, sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 caseNumber, sbyte4 printResult)
{
    int result;

    if (0 != (result = strcmp((char*)buf1, (char*)buf2)))
        result = -1;

    if ((-1 == result) && (printResult))
    {
        printf("\n/-------------------------------\\\n");
        printf("Case #%3d: <%s>", caseNumber, formatString);
        printf("\n--------------------------\n");
        printf("snprintf: <%s>", buf1);
        printf("\n--------------------------\n");
        printf("mprintf : <%s>", buf2);
        printf("\n\\-------------------------------/\n");
        
        /* stop program when any mismatch is found */
        if (2 == printResult)
            exit(0);
    }

    return result;
}


/*------------------------------------------------------------------*/

int no_arg_test(sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 printResult)
{
    int result = 0;
    int retVal = 0;
    int i;
    ubyte* stringN;

    for (i = 0; NULL != (stringN = testStrings[i]); i++)
    {
        snprintf((char*)buf1, bufSize, (char*)stringN);
        
        if (0 > (result = DIGI_SNPRINTF(buf2, bufSize, stringN)))
            goto exit;

        retVal += compareResults(stringN, buf1, buf2, bufSize, i+1, printResult);
    }

    result = retVal;

exit:
    return result;
}


/*------------------------------------------------------------------*/

int single_arg_test(sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 printResult)
{
    int result = 0;
    int retVal = 0;
    int i;
    printfTest testCaseN;

    for (i = 0; i<sizeof(testCases)/sizeof(printfTest); i++)
    {
        testCaseN = testCases[i];

        snprintf((char*)buf1, bufSize, (char*)testCaseN.format, testCaseN.arg);

        if (0 > (result = DIGI_SNPRINTF(buf2, bufSize, testCaseN.format, testCaseN.arg)))
            goto exit;
        
        retVal += compareResults(testCaseN.format, buf1, buf2, bufSize, i+1, printResult);
    }

    result = retVal;

exit:
    return result;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MPRINTF_FLOAT__
int floating_point_test(sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 printResult)
{
    int result = 0;
    int retVal = 0;
    int i;
    printfTestFloat testCaseN;

    for (i = 0; i<sizeof(testCasesFloat)/sizeof(printfTestFloat); i++)
    {
        testCaseN = testCasesFloat[i];

        snprintf((char*)buf1, bufSize, testCaseN.format, testCaseN.arg);

        if (0 > (result = DIGI_SNPRINTF(buf2, bufSize, testCaseN.format, testCaseN.arg)))
            goto exit;

        retVal += compareResults(testCaseN.format, buf1, buf2, bufSize, i+1, printResult);
    }

    result = retVal;

exit:
    return result;
}
#endif


/*------------------------------------------------------------------*/

int chain_buf_overflow_test(mocSegDescr *pBufSeg)
{
    int result = -1;

    DIGI_clearTestSeg(pBufSeg);
    result = MPRINTF(pBufSeg, NULL, (const ubyte*)"%*d", MAX_BUFFER_SIZE + 1, 0);

    if (ERR_MPRINTF_BUFFER_FULL == result)
        result = 0;

    return result;
}


/*------------------------------------------------------------------*/

int getSize(char **a)
{
    int i;

    for (i=0; 0 != a[i]; i++)
        ;

    return i;
}


/*------------------------------------------------------------------*/

int auto_generated_test(sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 printResult)
{
    int i, j, k, x, y;
    int size1, size2, size3, size4;
    int argNumSize, argStrSize;
    int totalCases = 0;
    int result = 0;
    int retVal = 0;
    char formatString[MAX_BUFFER_SIZE];
    char output[MAX_BUFFER_SIZE];

    memset(formatString, 0x00, MAX_BUFFER_SIZE);

    size1 = getSize(s1);
    size2 = getSize(s2);
    size3 = getSize(s3);
    size4 = getSize(s4);

    argNumSize = sizeof(argNum)/sizeof(int);
    argStrSize = getSize(argStr);

    for (i=0; i<size4; i++)
    {
        for (j=0; j<size3; j++)
        {
            for (k=0; k<size2; k++)
            {
                for (x=0; x<size1; x++)
                {
                    snprintf(formatString, MAX_BUFFER_SIZE, "%%%s%s%s%s", s1[x], s2[k], s3[j], s4[i]);

                    if ('s' != *s4[i])
                    {
                        for (y=0; y<argNumSize; y++)
                        {
                            snprintf(output, MAX_BUFFER_SIZE, formatString, argNum[y]);
                            totalCases++;
                            //printf("case#%5d: %s\n", totalCases, formatString);
                            //printf("case#%5d: %d\n", totalCases, argNum[y]);

                            snprintf((char*)buf1, bufSize, formatString, argNum[y]);

                            if (0 > (result = DIGI_SNPRINTF(buf2, bufSize, (const ubyte*)formatString, argNum[y])))
                                goto exit;

                            retVal += compareResults((ubyte*)formatString, buf1, buf2, bufSize, totalCases, printResult);
                        }
                    }
                    else if ('\0' == *s3[j]) /* skip string test with length modifier, wchar_t in not implemented */
                    {
                        for (y=0; y<argStrSize; y++)
                        {
                            snprintf(output, MAX_BUFFER_SIZE, formatString, argStr[y]);
                            totalCases++;
                            //printf("case#%5d: %s\n", total, output);

                            snprintf((char*)buf1, bufSize, formatString, argStr[y]);

                            if (0 > (result = DIGI_SNPRINTF(buf2, bufSize, (const ubyte*)formatString, argStr[y])))
                                goto exit;

                            retVal += compareResults((ubyte*)formatString, buf1, buf2, bufSize, totalCases, printResult);
                        }
                    }
                }
            }
        }
    }

    result = retVal;
    //printf("\nTotoal number of cases tested: %d\n", totalCases);

exit:
    return result;
}


/*------------------------------------------------------------------*/

int integer_test(sbyte *buf1, sbyte *buf2, ubyte4 bufSize, sbyte4 printResult)
{
    int result = 0;

    signed long     i;
    unsigned long   j;

    for (i = 0x80000000L; ; i++)
    {
        snprintf((char*)buf1, bufSize, "Test signed long: %ld", i);
        DIGI_SNPRINTF(buf2, bufSize, (const ubyte*)"Test signed long: %ld", i);
        result += compareResults((ubyte*)"Test signed long: %d", buf1, buf2, bufSize, 0, printResult);

        if (0x7fffffffL == i)
            break;
    }

    for (j = 0; ; j++)
    {
        snprintf((char*)buf1, bufSize, "Test unsigned long: %lu", j);
        DIGI_SNPRINTF(buf2, bufSize, (const ubyte*)"Test unsigned long: %lu", j);
        result += compareResults((ubyte*)"Test unsigned long: %u", buf1, buf2, bufSize, 0, printResult);

        if (0xffffffffL == j)
            break;
    }

    return result;
}

#endif /* __ENABLE_DIGICERT_PRINTF__*/


/*------------------------------------------------------------------*/

int mprintf_test_all()
{
    int result = 0;

#ifdef __ENABLE_DIGICERT_PRINTF__

    int printResult = 1;
    mocSegDescr* pBufSeg = NULL;

    sbyte buf1[MAX_BUFFER_SIZE];
    sbyte buf2[MAX_BUFFER_SIZE];

    if (0 > (result = DIGI_createTestSeg(&pBufSeg, 2, MAX_BUFFER_SIZE >> 1)))
    {
        printf("Error: DIGI_createTestSeg failed.\n");
        goto exit;
    }

    result += UNITTEST_STATUS(1, no_arg_test(buf1, buf2, MAX_BUFFER_SIZE, printResult));
    
    result += UNITTEST_STATUS(2, single_arg_test(buf1, buf2, MAX_BUFFER_SIZE, printResult));
    
    result += UNITTEST_STATUS(3, chain_buf_overflow_test(pBufSeg));
    
#ifdef __ENABLE_MPRINTF_FLOAT__
    result += UNITTEST_STATUS(4, floating_point_test(buf1, buf2, MAX_BUFFER_SIZE, printResult));
#endif
    
    //result += UNITTEST_STATUS(5, auto_generated_test(buf1, buf2, MAX_BUFFER_SIZE, printResult));
    
    //result += UNITTEST_STATUS(6, integer_test(buf1, buf2, MAX_BUFFER_SIZE, printResult));

exit:
    DIGI_freeTestSeg(&pBufSeg);

#endif

    return result;
}

