/*
 * property_test.c
 *
 * Property Management
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
#include "../../common/hash_value.h"
#include "../../common/hash_table.h"
#include "../../common/property.h"

#if 1
#include <stdio.h>
#define PROPERTY_TEST_PRINT(X)      printf X
#else
#define PROPERTY_TEST_PRINT(X)
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
extern void dbg_dump(void);
#endif


/*------------------------------------------------------------------*/

typedef struct propertyResults
{
    sbyte*                  pName;
    sbyte*                  pValue;
    intBoolean              isFound;
    MSTATUS                 expectedStatus;

} propertyResults;


/*------------------------------------------------------------------*/

static propertyResults answers1[] =
{
    {   "system.date.month", "march", TRUE, OK  },
    {   "system.date.year",  "2010",  TRUE, OK  },
    {   "system.date.day",   "23",    TRUE, OK  },
    {   "system.date.hour",  "twelve o'clock",  TRUE, OK  }
};

static propertyResults answers2[] =
{
    {   "system.date.month", "exist1",     TRUE, OK  },
    {   "system.date.year",  "exist2",     TRUE, OK  },
    {   "system.date.day",   "exist3",     TRUE, OK  },
    {   "system.date.hour",  "exist four", TRUE, OK  }
};

static propertyResults answers3[] =
{
    {   "sxstem.date.month", "exist1",     FALSE, OK  },
    {   "sxstem.date.year",  "exist2",     FALSE, OK  },
    {   "sxstem.date.day",   "exist3",     FALSE, OK  },
    {   "sxstem.date.hour",  "exist four", FALSE, OK  }
};

static propertyResults answers4[] =
{
    {   "system.date.month", "exist1",     TRUE, OK  },
    {   "system.date.year",  "exist2",     TRUE, OK  },
    {   "system.date.day",   "exist3",     TRUE, OK  },
    {   "system.date.hour",  "exist four", TRUE, OK  }
};

static propertyResults answers5[] =
{
    {   "system.date.month", "exist4",     TRUE, OK  },
    {   "system.date.year",  "exist5",     TRUE, OK  },
    {   "system.date.day",   "exist6",     TRUE, OK  },
    {   "system.date.hour",  "exist five", TRUE, OK  }
};

static propertyResults answers6[] =
{
    {   "system.date.month", "exist4",     TRUE, OK  },
    {   "system.date.year",  "exist5",     TRUE, OK  },
    {   "system.date.day",   "exist6",     TRUE, OK  },
    {   "system.date.hour",  "exist six",  TRUE, OK  },
    {   "sxstem.date.month", "exist1",     FALSE, OK  },
    {   "sxstem.date.year",  "exist2",     FALSE, OK  },
    {   "sxstem.date.day",   "exist3",     FALSE, OK  },
    {   "sxstem.date.hour",  "exist four", FALSE, OK  }
};

static propertyResults answers7[] =
{
    {   "system.date.month", "exist4",     TRUE, OK  },
    {   "system.date.year",  "exist5",     TRUE, OK  },
    {   "system.date.day",   "exist6",     TRUE, OK  },
    {   "system.date.hour",  "exist seven",TRUE, OK  },
    {   "sxstem.date.month", "exist1",     FALSE, OK  },
    {   "sxstem.date.year",  "exist2",     FALSE, OK  },
    {   "sxstem.date.day",   "exist3",     FALSE, OK  },
    {   "sxstem.date.hour",  "exist four", FALSE, OK  }
};


/*------------------------------------------------------------------*/

typedef struct propertyTest
{
    intBoolean              cleanSlate;
    ubyte4                  priority;
    MSTATUS                 expectedStatus;
    enum propertyPolicies   propertyAddPolicy;
    sbyte*                  pPropertiesList;
    propertyResults*        results;
    sbyte4                  numResults;

} propertyTest;


/*------------------------------------------------------------------*/

static propertyTest tests[] =
{
    {
        FALSE, 0, OK, policyOverwriteAlways,
        "system.date.month = march\n"
        "system.date.year   =    2010\n"
        "system.date.day = 23   \n    \n"
        "\t  system.date.hour  = twelve o'clock \t",
        answers1,
        sizeof(answers1) / sizeof(propertyResults)
    },
    {
        FALSE, 0, OK, policyOverwriteIfExists,
        "system.date.month = exist1\n"
        "system.date.year   =    exist2\n"
        "system.date.day = exist3   \n    \n"
        "\t  system.date.hour  = exist four \t\n# comment line\n\n   ",
        answers2,
        sizeof(answers2) / sizeof(propertyResults)
    },
    {
        FALSE, 0, OK, policyOverwriteIfExists,
        "sxstem.date.month = exist1\n"
        "sxstem.date.year   =    exist2\n"
        "sxstem.date.day = exist3   \n    \n"
        "\t  sxstem.date.hour  = exist four \t\n# comment line\n\n   ",
        answers3,
        sizeof(answers3) / sizeof(propertyResults)
    },
    {
        FALSE, 0, OK, policyOverwriteGreaterPriority,
        "system.date.month = exist4\n"
        "system.date.year   =    exist5\n"
        "system.date.day = exist6   \n    \n"
        "\t  system.date.hour  = exist five \t\n# comment line\n\n   ",
        answers4,
        sizeof(answers4) / sizeof(propertyResults)
    },
    {
        FALSE, 1, OK, policyOverwriteGreaterPriority,
        "system.date.month = exist4\n"
        "system.date.year   =    exist5\n"
        "system.date.day = exist6   \n    \n"
        "\t  system.date.hour  = exist five \t\n# comment line\n\n   ",
        answers5,
        sizeof(answers5) / sizeof(propertyResults)
    },
    {
        FALSE, 10, OK, policyOverwriteGreaterPriorityAndExists,
        "sxstem.date.month = exist1\n"
        "sxstem.date.year   =    exist2\n"
        "sxstem.date.day = exist3   \n    \n"
        "\t  sxstem.date.hour  = exist four \t\n# comment line\n system.date.hour=exist six\nsystem.date.hour=exist seven  ",
        answers6,
        sizeof(answers6) / sizeof(propertyResults)
    },
    {
        FALSE, 10, OK, policyOverwriteGreaterEqualPriorityAndExists,
        "sxstem.date.month = exist1\n"
        "sxstem.date.year   =    exist2\n"
        "sxstem.date.day = exist3   \n    \n"
        "\t  sxstem.date.hour  = exist four \t\n# comment line\n system.date.hour=exist six\nsystem.date.hour=exist seven  ",
        answers7,
        sizeof(answers7) / sizeof(propertyResults)
    }
};

#define NUM_TESTS   (sizeof(tests) / sizeof(propertyTest))


/*------------------------------------------------------------------*/

static MSTATUS
callbackMalformedLine(void *pCookie, const sbyte *pMalformedLine, ubyte4 lineNum)
{
    PROPERTY_TEST_PRINT(("Line %d: [[%s]]\n", lineNum, pMalformedLine));

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
PROPERTY_TEST_outputProperty(void *pCookie, const ubyte *pPropertyName, const ubyte *pPropertyValue)
{
    if (0 == DIGI_STRCMP(pPropertyName, "system.date.year"))
    {
        PROPERTY_TEST_PRINT(("\n# an example of inserting data during the output"));
        PROPERTY_TEST_PRINT(("\n# this could have been easily fwrite(), etc"));
        PROPERTY_TEST_PRINT(("\n# another trick would be to use hidden properties"));
        PROPERTY_TEST_PRINT(("\n# to signal section breaks for sorted output\n"));
    }

    PROPERTY_TEST_PRINT(("%s=%s\n", pPropertyName, pPropertyValue));

    return OK;
}


/*------------------------------------------------------------------*/

int property_test(void)
{
    propertyTable*  pPropertyTable = NULL;
    sbyte4          i, j;
    int             testFails = 0;
    MSTATUS         status;

    if (OK > (status = PROPERTY_newInstance(&pPropertyTable)))
    {
        PROPERTY_TEST_PRINT(("property_test: PROPERTY_newInstance() failed with status = %d\n", status));
        testFails++;
        goto exit;
    }

    for (i = 0; i < NUM_TESTS; i++)
    {
        if (TRUE == tests[i].cleanSlate)
        {
            if (OK > (status = PROPERTY_deleteInstance(&pPropertyTable)))
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_deleteInstance() failed with status = %d\n", status));
                testFails++;
                goto exit;
            }

            if (NULL != pPropertyTable)
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_deleteInstance() failed, pPropertyTable is not null\n"));
                testFails++;
                goto exit;
            }

            if (OK > (status = PROPERTY_newInstance(&pPropertyTable)))
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_newInstance() failed with status = %d\n", status));
                testFails++;
                goto exit;
            }
        }

        status = PROPERTY_parseLines(pPropertyTable,
                                     tests[i].pPropertiesList, DIGI_STRLEN(tests[i].pPropertiesList),
                                     tests[i].priority, tests[i].propertyAddPolicy,
                                     NULL, callbackMalformedLine);

        if (status != tests[i].expectedStatus)
        {
            PROPERTY_TEST_PRINT(("property_test: PROPERTY_parseLines() status %d, not equal to expected status %d\n", status, tests[i].expectedStatus));
            testFails++;
            continue;
        }

        for (j = 0; j < tests[i].numResults; j++)
        {
            sbyte*              pPropertyValue;
            propertyResults*    pAnswers;
            intBoolean          foundProperty;
            intBoolean          testFailed;

            pAnswers = &tests[i].results[j];
            pPropertyValue = NULL;

            status = PROPERTY_findPropertyValue(pPropertyTable,
                                                pAnswers->pName, &pPropertyValue,
                                                &foundProperty);

            if (status != pAnswers->expectedStatus)
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_findPropertyValue() status %d, not equal to expected status %d\n", status, pAnswers->expectedStatus));
                testFails++;
                continue;
            }

            testFailed = FALSE;

            if ((foundProperty == pAnswers->isFound) && (FALSE == foundProperty))
            {
                /* nothing to check lookup failed as expected */
            }
            else if (foundProperty != pAnswers->isFound)
            {
                testFailed = TRUE;
            }
            else if (DIGI_STRLEN(pAnswers->pValue) != ((NULL != pPropertyValue) ? DIGI_STRLEN(pPropertyValue) : 0))
            {
                testFailed = TRUE;
            }
            else
            {
                sbyte4 result;

                DIGI_MEMCMP(pAnswers->pValue, pPropertyValue, DIGI_STRLEN(pAnswers->pValue), &result);

                if (0 != result)
                    testFailed = TRUE;
            }

            if (TRUE == testFailed)
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_findPropertyValue() [%s] not equal to expected [%s]\n", pPropertyValue, pAnswers->pValue));
                testFails++;
                continue;
            }

            if ((TRUE == foundProperty) && (OK > (status = PROPERTY_releaseClonedPropertyValue(&pPropertyValue))))
            {
                PROPERTY_TEST_PRINT(("property_test: PROPERTY_releaseClonedPropertyValue() failed, status = %d\n", status));
                testFails++;
                continue;
            }
        }
    }

    PROPERTY_TEST_PRINT(("================== WHATEVER ORDER ====================\n"));

    if (OK > (status = PROPERTY_outputPropertyList(pPropertyTable, NULL, PROPERTY_TEST_outputProperty)))
        goto exit;

    PROPERTY_TEST_PRINT(("=================== SORTED ORDER =====================\n"));

    if (OK > (status = PROPERTY_outputSortedPropertyList(pPropertyTable, NULL, PROPERTY_TEST_outputProperty)))
        goto exit;

    PROPERTY_TEST_PRINT(("======================================================\n"));

    if (OK > (status = PROPERTY_deleteInstance(&pPropertyTable)))
    {
        PROPERTY_TEST_PRINT(("property_test: PROPERTY_deleteInstance() failed with status = %d\n", status));
        testFails++;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif

exit:
    return testFails;
}
