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

