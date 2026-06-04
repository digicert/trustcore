/*
 * datetime_test.c
 *
 * unit test for datetime.c
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

#include "../datetime.c"

#include "../../../unit_tests/unittest.h"

typedef struct DateTimeTest
{
    const char* s;          /* input */
    const char* encs;       /* encoded */
    TimeDate    dt;
} DateTimeTest;


static DateTimeTest gDateTimeTests[] =
{
    {
        "19961115220345Z",
        "961115220345Z",
        { 26, 11, 15, 22, 03, 45 }
    },

    {
        "21000101000000Z",
        "21000101000000Z",
        { 130, 1, 1, 0, 0, 0 }
    },
};

int datetime_test_1()
{
    int i, retVal = 0;
    TimeDate res;
    sbyte sres[20];

    for (i=0; i<COUNTOF(gDateTimeTests); ++i)
    {
        retVal += UNITTEST_STATUS(i,
                                  DATETIME_convertFromValidityString((const sbyte*) gDateTimeTests[i].s,
                                                                     &res));

        retVal += UNITTEST_TRUE(i, res.m_year == gDateTimeTests[i].dt.m_year);
        retVal += UNITTEST_TRUE(i, res.m_month == gDateTimeTests[i].dt.m_month);
        retVal += UNITTEST_TRUE(i, res.m_day == gDateTimeTests[i].dt.m_day);
        retVal += UNITTEST_TRUE(i, res.m_hour == gDateTimeTests[i].dt.m_hour);
        retVal += UNITTEST_TRUE(i, res.m_minute == gDateTimeTests[i].dt.m_minute);
        retVal += UNITTEST_TRUE(i, res.m_second == gDateTimeTests[i].dt.m_second);

        retVal += UNITTEST_STATUS(i,
                                  DATETIME_convertFromValidityString((const sbyte*) gDateTimeTests[i].encs,
                                                                     &res));

        retVal += UNITTEST_TRUE(i, res.m_year == gDateTimeTests[i].dt.m_year);
        retVal += UNITTEST_TRUE(i, res.m_month == gDateTimeTests[i].dt.m_month);
        retVal += UNITTEST_TRUE(i, res.m_day == gDateTimeTests[i].dt.m_day);
        retVal += UNITTEST_TRUE(i, res.m_hour == gDateTimeTests[i].dt.m_hour);
        retVal += UNITTEST_TRUE(i, res.m_minute == gDateTimeTests[i].dt.m_minute);
        retVal += UNITTEST_TRUE(i, res.m_second == gDateTimeTests[i].dt.m_second);

        retVal += UNITTEST_STATUS(i, DATETIME_convertToValidityString( &gDateTimeTests[i].dt,
                                                                      sres));

        retVal += UNITTEST_TRUE(i, 0 == DIGI_STRCMP(sres, (const sbyte*) gDateTimeTests[i].encs));

    }

    return retVal;
}

/*-------------------------------------------------------------------------*/
/* Test DATETIME_diffTime - Feb/March boundary and leap year handling      */
/*-------------------------------------------------------------------------*/

typedef struct DiffTimeTest
{
    TimeDate dt1;           /* later date */
    TimeDate dt2;           /* earlier date */
    sbyte4   expectedDays;  /* expected difference in days */
    const char* desc;       /* test description */
} DiffTimeTest;

static DiffTimeTest gDiffTimeTests[] =
{
    /* Feb/March boundary - non-leap years (should be 1 day) */
    { { 56, 3, 1, 12, 0, 0 }, { 56, 2, 28, 12, 0, 0 }, 1, "Mar 1 2026 - Feb 28 2026 (non-leap)" },
    { { 55, 3, 1, 12, 0, 0 }, { 55, 2, 28, 12, 0, 0 }, 1, "Mar 1 2025 - Feb 28 2025 (non-leap)" },
    { { 51, 3, 1, 12, 0, 0 }, { 51, 2, 28, 12, 0, 0 }, 1, "Mar 1 2021 - Feb 28 2021 (non-leap)" },

    /* Feb/March boundary - leap years (should be 2 days: Feb 28 -> Feb 29 -> Mar 1) */
    { { 54, 3, 1, 12, 0, 0 }, { 54, 2, 28, 12, 0, 0 }, 2, "Mar 1 2024 - Feb 28 2024 (leap year)" },
    { { 50, 3, 1, 12, 0, 0 }, { 50, 2, 28, 12, 0, 0 }, 2, "Mar 1 2020 - Feb 28 2020 (leap year)" },
    { { 30, 3, 1, 12, 0, 0 }, { 30, 2, 28, 12, 0, 0 }, 2, "Mar 1 2000 - Feb 28 2000 (leap, div 400)" },

    /* Cross-year spans */
    { { 56, 3, 1, 12, 0, 0 }, { 55, 2, 28, 12, 0, 0 }, 366, "Mar 1 2026 - Feb 28 2025 (1 yr span)" },

    /* Year boundaries */
    { { 56, 1, 1, 12, 0, 0 }, { 55, 12, 31, 12, 0, 0 }, 1, "Jan 1 2026 - Dec 31 2025" },
    { { 30, 1, 1, 12, 0, 0 }, { 29, 12, 31, 12, 0, 0 }, 1, "Jan 1 2000 - Dec 31 1999" },

    /* Regular leap years (divisible by 4) */
    { { 34, 3, 1, 12, 0, 0 }, { 34, 2, 28, 12, 0, 0 }, 2, "Mar 1 2004 - Feb 28 2004 (leap)" },
    { { 58, 3, 1, 12, 0, 0 }, { 58, 2, 28, 12, 0, 0 }, 2, "Mar 1 2028 - Feb 28 2028 (leap)" },

    /* Multi-decade span */
    { { 60, 1, 1, 12, 0, 0 }, { 50, 1, 1, 12, 0, 0 }, 3653, "Jan 1 2030 - Jan 1 2020 (10 yr)" },
};

int datetime_test_diffTime()
{
    int i, retVal = 0;
    sbyte4 secDiff;

    for (i = 0; i < COUNTOF(gDiffTimeTests); ++i)
    {
        retVal += UNITTEST_STATUS(i,
                    DATETIME_diffTime(&gDiffTimeTests[i].dt1,
                                      &gDiffTimeTests[i].dt2,
                                      &secDiff));

        retVal += UNITTEST_TRUE(i, secDiff == (gDiffTimeTests[i].expectedDays * 86400));
    }

    return retVal;
}

/*-------------------------------------------------------------------------*/
/* Test DATETIME_getNewTime - adding time and leap year transitions        */
/*-------------------------------------------------------------------------*/

typedef struct GetNewTimeTest
{
    TimeDate input;         /* starting date */
    sbyte4   addSeconds;    /* seconds to add */
    TimeDate expected;      /* expected result (year, month, day, hour, minute, second) */
    const char* desc;       /* test description */
} GetNewTimeTest;

static GetNewTimeTest gGetNewTimeTests[] =
{
    /* Non-leap year: Feb 28 + 1 day = Mar 1 */
    { { 56, 2, 28, 12, 0, 0 }, 86400, { 56, 3, 1, 12, 0, 0 }, "Feb 28 2026 + 1 day = Mar 1" },
    { { 55, 2, 28, 12, 0, 0 }, 86400, { 55, 3, 1, 12, 0, 0 }, "Feb 28 2025 + 1 day = Mar 1" },

    /* Leap year: Feb 28 + 1 day = Feb 29 */
    { { 54, 2, 28, 12, 0, 0 }, 86400, { 54, 2, 29, 12, 0, 0 }, "Feb 28 2024 + 1 day = Feb 29" },
    { { 50, 2, 28, 12, 0, 0 }, 86400, { 50, 2, 29, 12, 0, 0 }, "Feb 28 2020 + 1 day = Feb 29" },
    { { 30, 2, 28, 12, 0, 0 }, 86400, { 30, 2, 29, 12, 0, 0 }, "Feb 28 2000 + 1 day = Feb 29" },

    /* Leap year: Feb 29 + 1 day = Mar 1 */
    { { 54, 2, 29, 12, 0, 0 }, 86400, { 54, 3, 1, 12, 0, 0 }, "Feb 29 2024 + 1 day = Mar 1" },
    { { 50, 2, 29, 12, 0, 0 }, 86400, { 50, 3, 1, 12, 0, 0 }, "Feb 29 2020 + 1 day = Mar 1" },

    /* Non-leap: Feb 27 + 2 days = Mar 1 (skips Feb 29) */
    { { 56, 2, 27, 12, 0, 0 }, 2*86400, { 56, 3, 1, 12, 0, 0 }, "Feb 27 2026 + 2 days = Mar 1" },

    /* Hour rollover: 23:00 + 2 hours = next day 01:00 */
    { { 56, 2, 28, 23, 0, 0 }, 7200, { 56, 3, 1, 1, 0, 0 }, "Feb 28 2026 23:00 + 2hrs = Mar 1" },

    /* Year boundary: Dec 31 + 1 day = Jan 1 next year */
    { { 55, 12, 31, 12, 0, 0 }, 86400, { 56, 1, 1, 12, 0, 0 }, "Dec 31 2025 + 1 day = Jan 1 2026" },
    { { 29, 12, 31, 12, 0, 0 }, 86400, { 30, 1, 1, 12, 0, 0 }, "Dec 31 1999 + 1 day = Jan 1 2000" },

    /* Adding 365 days across years */
    { { 50, 2, 28, 12, 0, 0 }, 365*86400, { 51, 2, 27, 12, 0, 0 }, "Feb 28 2020 + 365 days" },
    { { 55, 2, 28, 12, 0, 0 }, 365*86400, { 56, 2, 28, 12, 0, 0 }, "Feb 28 2025 + 365 days" },
};

int datetime_test_getNewTime()
{
    int i, retVal = 0;
    TimeDate result;

    for (i = 0; i < COUNTOF(gGetNewTimeTests); ++i)
    {
        retVal += UNITTEST_STATUS(i,
                    DATETIME_getNewTime(&gGetNewTimeTests[i].input,
                                        gGetNewTimeTests[i].addSeconds,
                                        &result));

        retVal += UNITTEST_TRUE(i, result.m_year == gGetNewTimeTests[i].expected.m_year);
        retVal += UNITTEST_TRUE(i, result.m_month == gGetNewTimeTests[i].expected.m_month);
        retVal += UNITTEST_TRUE(i, result.m_day == gGetNewTimeTests[i].expected.m_day);
        retVal += UNITTEST_TRUE(i, result.m_hour == gGetNewTimeTests[i].expected.m_hour);
        retVal += UNITTEST_TRUE(i, result.m_minute == gGetNewTimeTests[i].expected.m_minute);
        retVal += UNITTEST_TRUE(i, result.m_second == gGetNewTimeTests[i].expected.m_second);
    }

    return retVal;
}

/*-------------------------------------------------------------------------*/
/* Test certificate renewal scenario - time until expiry                   */
/*-------------------------------------------------------------------------*/

int datetime_test_certRenewal()
{
    int retVal = 0;
    TimeDate currentTime = { 56, 2, 28, 12, 0, 0 };  /* Feb 28, 2026 noon */
    TimeDate certExpiry = { 56, 3, 1, 12, 0, 0 };    /* Mar 1, 2026 noon */
    sbyte4 secDiff;

    retVal += UNITTEST_STATUS(0, DATETIME_diffTime(&certExpiry, &currentTime, &secDiff));

    /* Should be exactly 24 hours (1 day) until expiry */
    retVal += UNITTEST_TRUE(0, secDiff == 86400);

    return retVal;
}

/*-------------------------------------------------------------------------*/
/* Test cumulative day additions (regression test for accumulating errors) */
/*-------------------------------------------------------------------------*/

int datetime_test_cumulativeDays()
{
    int retVal = 0;
    TimeDate start = { 56, 2, 25, 12, 0, 0 };  /* Feb 25, 2026 */
    TimeDate result;
    int i;

    /* Expected dates after adding 1-10 days from Feb 25, 2026 */
    static const struct { ubyte2 y; ubyte m; ubyte d; } expected[] = {
        { 56, 2, 26 }, { 56, 2, 27 }, { 56, 2, 28 }, { 56, 3, 1 },  /* days 1-4 */
        { 56, 3, 2 },  { 56, 3, 3 },  { 56, 3, 4 },  { 56, 3, 5 },  /* days 5-8 */
        { 56, 3, 6 },  { 56, 3, 7 }                                 /* days 9-10 */
    };

    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_STATUS(i,
                    DATETIME_getNewTime(&start, (i + 1) * 86400, &result));

        retVal += UNITTEST_TRUE(i, result.m_year == expected[i].y);
        retVal += UNITTEST_TRUE(i, result.m_month == expected[i].m);
        retVal += UNITTEST_TRUE(i, result.m_day == expected[i].d);
    }

    return retVal;
}

