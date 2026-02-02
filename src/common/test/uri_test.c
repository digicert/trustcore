/*
 * uri_test.c
 *
 * unit test for uri.c
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
#include "../../common/uri.h"

// #include "../uri.c"

#include "../../../unit_tests/unittest.h"

typedef struct
{
    char* scheme;
    char* userInfo;
    char* host;
    int port;
    char* path;
    char* query;
    char* fragment;
    char* result;
} TESTCASE2;

typedef struct
{
    char* scheme;
    char* authority;
    char* path;
    char* query;
    char* fragment;
    char* result;
} TESTCASE4;

TESTCASE2 testcases2[] = {
    {"http", ";/?:@&=+,$", "host", 80, "/index.html", "", "", "http://%3B%2F%3F%3A%40&=+,$@host:80/index.html"},
    {"http", "user info", "host", 80, "/path name.html", "", "", "http://user%20info@host:80/path%20name.html"},
};

TESTCASE4 testcases4[] = {
    {"http", "host:80", "/abc/def", "query", "", "http://host:80/abc/def?query"},
    {"http", "host:80", "/index.html", "", "", "http://host:80/index.html"},
    {"http", "host:80", "/index.html", "", "fragment", "http://host:80/index.html#fragment"},
    {"http", "host:80", "/index.html", ";/?:@&=+,$", "", "http://host:80/index.html?%3B%2F%3F%3A%40%26%3D%2B%2C%24"},
    {"http", "host:80", "/path with spaces.html", "query value", "", "http://host:80/path%20with%20spaces.html?query%20value"}
};
/*---------------------------------------------------------------------------*/

int uri_creation2_test(ubyte4 whichcase, TESTCASE2 testcase)
{
    sbyte4 result;
    URI *uri;

    URI_CreateURI2(testcase.scheme,
        testcase.userInfo,
        testcase.host,
        testcase.port,
        testcase.path,
        testcase.query,
        testcase.fragment,
        &uri);

    DIGI_MEMCMP(testcase.result, uri->uriBuf, DIGI_STRLEN(testcase.result), &result);
    URI_DELETE(uri);
    return UNITTEST_TRUE(whichcase, result == 0);

}

int uri_creation4_test(ubyte4 whichcase, TESTCASE4 testcase)
{
    sbyte4 result;
    URI *uri;

    URI_CreateURI4(testcase.scheme,
        testcase.authority,
        testcase.path,
        testcase.query,
        testcase.fragment,
        &uri);
    DIGI_MEMCMP(testcase.result, uri->uriBuf, DIGI_STRLEN(testcase.result), &result);
    URI_DELETE(uri);
    return UNITTEST_TRUE(whichcase, result == 0);

}

int uri_creation_tests()
{
    int retVal = 0;
    ubyte4 i;
    ubyte4 numCases = sizeof(testcases2) / sizeof(TESTCASE2);

    for (i = 0; i < numCases; i++)
    {
        retVal += uri_creation2_test(i, testcases2[i]);
    }

    numCases = sizeof(testcases4) / sizeof(TESTCASE4);
     for (i = 0; i < numCases; i++)
    {
        retVal += uri_creation4_test(i, testcases4[i]);
    }

    return retVal;
}

int uri_parsing4_test(ubyte4 whichcase, TESTCASE4 testcase)
{
    int retVal = 0;
    sbyte4 result;
    URI *uri;
    sbyte* component;
    sbyte* unescaped;

    URI_ParseURI(testcase.result, &uri);
    URI_GetScheme(uri, &component);
    result = DIGI_STRCMP(testcase.scheme, component);
    if (component)
		FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetAuthority(uri, &component);
    result = DIGI_STRCMP(testcase.authority, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetPath(uri, &component);
    result = DIGI_STRCMP(testcase.path, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetQuery(uri, &component);
    URI_Unescape(component, DIGI_STRLEN(component), &unescaped);
    result = DIGI_STRCMP(testcase.query, unescaped);
    if (component)
        FREE(component);
    if (unescaped)
        FREE(unescaped);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetFragment(uri, &component);
    result = DIGI_STRCMP(testcase.fragment, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }

exit:
    URI_DELETE(uri);

    return retVal;

}

int uri_parsing2_test(ubyte4 whichcase, TESTCASE2 testcase)
{
    int retVal = 0;
    sbyte4 result;
    URI *uri;
    sbyte* component;
    ubyte2 port;

    URI_ParseURI(testcase.result, &uri);
    URI_GetScheme(uri, &component);
    result = DIGI_STRCMP(testcase.scheme, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetUserinfo(uri, &component);
    result = DIGI_STRCMP(testcase.userInfo, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetHost(uri, &component);
    result = DIGI_STRCMP(testcase.host, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetPort(uri, &port);

    if (testcase.port != port)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }

    URI_GetPath(uri, &component);
    result = DIGI_STRCMP(testcase.path, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetQuery(uri, &component);
    result = DIGI_STRCMP(testcase.query, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }
    URI_GetFragment(uri, &component);
    result = DIGI_STRCMP(testcase.fragment, component);
    if (component)
        FREE(component);
    if (result != 0)
    {
        retVal += UNITTEST_TRUE(whichcase, FALSE);
        goto exit;
    }

exit:
    URI_DELETE(uri);

    return retVal;
}


int uri_parsing_tests()
{
    int retVal = 0;
    ubyte4 i;
    ubyte4 numCases = sizeof(testcases4) / sizeof(TESTCASE4);

    for (i = 0; i < numCases; i++)
    {
        retVal += uri_parsing4_test(i, testcases4[i]);
    }

    numCases = sizeof(testcases2) / sizeof(TESTCASE2);

    for (i = 0; i < numCases; i++)
    {
        retVal += uri_parsing2_test(i, testcases2[i]);
    }
    return retVal;
}

int uri_illegal_format_tests()
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte *uri1 = "certificate$evocti=ce%%_+rtificate\2a\2a\2a\2a\2a\5c\5c\5c///@$@$@$@$@$@$@$@$@RevocationList?";
    sbyte *unescaped = NULL;

    status = URI_Unescape(uri1, DIGI_STRLEN(uri1), &unescaped);
    retVal = UNITTEST_TRUE(0, ERR_URI_INVALID_FORMAT == status);
exit:
    if (unescaped)
        FREE(unescaped);
    return retVal;
}

int uri_space_encoding_test()
{
    int retVal = 0;
    ubyte escaped[256];
    ubyte4 escapedLen;
    sbyte4 result;

    sbyte* testQuery = "CA Name With Spaces";
    ubyte4 expectedLen = 25; /* "CA%20Name%20With%20Spaces" */

    if (OK > URI_Escape(QUERY, testQuery, DIGI_STRLEN(testQuery), escaped, &escapedLen))
    {
        retVal += UNITTEST_TRUE(0, FALSE);
        goto exit;
    }

    DIGI_MEMCMP("CA%20Name%20With%20Spaces", escaped, expectedLen, &result);
    retVal += UNITTEST_TRUE(1, result == 0);
    retVal += UNITTEST_TRUE(2, escapedLen == expectedLen);

    sbyte* testPath = "/path with spaces/file.txt";
    if (OK > URI_Escape(PATH, testPath, DIGI_STRLEN(testPath), escaped, &escapedLen))
    {
        retVal += UNITTEST_TRUE(3, FALSE);
        goto exit;
    }

    DIGI_MEMCMP("%2Fpath%20with%20spaces%2Ffile.txt", escaped, 34, &result);
    retVal += UNITTEST_TRUE(4, result == 0);

    sbyte* testAuth = "user name@host";
    if (OK > URI_Escape(AUTHORITY, testAuth, DIGI_STRLEN(testAuth), escaped, &escapedLen))
    {
        retVal += UNITTEST_TRUE(5, FALSE);
        goto exit;
    }

    DIGI_MEMCMP("user%20name%40host", escaped, 18, &result);
    retVal += UNITTEST_TRUE(6, result == 0);

exit:
    return retVal;
}

int uri_test_all()
{
	int retVal = 0;
    retVal = uri_creation_tests();
    retVal += uri_parsing_tests();
    retVal += uri_illegal_format_tests();
    retVal += uri_space_encoding_test();
	return retVal;
}

//int main(int argc, char* argv[])
//{
//    return uri_test_all();
//}
