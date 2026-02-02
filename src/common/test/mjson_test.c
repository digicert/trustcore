/*
 * mjson_test.c
 *
 * unit test for mjson.c
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

#include "../mjson.c"

#include "../../common/mstdlib.h"
#include "../../common/mocana.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

/*
 * NOTE: Invalid JSON strings were tested using 'https://jsonformatter.curiousconcept.com/'
 *       to ensure they do not conform to the JSON standard.
 */

int mjson_test_acquireRelease()
{
    MSTATUS status;
    int retval = 0;
    JSON_ContextType *ctx = NULL;

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_TRUE(0, NULL != ctx);

    status = JSON_releaseContext(&ctx);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_TRUE(1, NULL == ctx);

    /* Test error cases */
    status = JSON_acquireContext(NULL);
    retval += UNITTEST_TRUE(10, OK != status);

    status = JSON_releaseContext(NULL);
    retval += UNITTEST_TRUE(11, OK != status);

exit:
    return retval;
}

int mjson_test_parsePrimitives()
{
    MSTATUS status;
    int retval = 0;
    JSON_ContextType *ctx = NULL;
    JSON_TokenType   tok;

    const sbyte n1[] = "null";
    const sbyte t1[] = "true";
    const sbyte f1[] = "false";

    const sbyte i1[] = "0";
    const sbyte i2[] = "4711";
    const sbyte i3[] = "-666";

    const sbyte u1[] = "0.0";
    const sbyte u2[] = "47.11";
    const sbyte u3[] = "-6.66";

    const sbyte e1[] = "-";
    const sbyte e2[] = ".0";
    const sbyte e3[] = "-1.";

    const sbyte x1[] = "1E10";
    const sbyte x2[] = "1E-10";
    const sbyte x3[] = "1.0E10";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Booleans */
    status = fillPrimitiveToken(&tok,
                                t1, 0, sizeof(t1)-1);
    retval += UNITTEST_STATUS(1, status);
    status = fillPrimitiveToken(&tok,
                                f1, 0, sizeof(f1)-1);
    retval += UNITTEST_STATUS(1, status);

    /* Null */
    status = fillPrimitiveToken(&tok,
                                n1, 0, sizeof(n1)-1);
    retval += UNITTEST_STATUS(2, status);

    /* Integers */
    status = fillPrimitiveToken(&tok,
                                i1, 0, sizeof(i1)-1);
    retval += UNITTEST_STATUS(3, status);
    status = fillPrimitiveToken(&tok,
                                i2, 0, sizeof(i2)-1);
    retval += UNITTEST_STATUS(3, status);
    status = fillPrimitiveToken(&tok,
                                i3, 0, sizeof(i3)-1);
    retval += UNITTEST_STATUS(3, status);

    /* Numbers */
    status = fillPrimitiveToken(&tok,
                                u1, 0, sizeof(u1)-1);
    retval += UNITTEST_STATUS(4, status);
    status = fillPrimitiveToken(&tok,
                                u2, 0, sizeof(u2)-1);
    retval += UNITTEST_STATUS(4, status);
    status = fillPrimitiveToken(&tok,
                                u3, 0, sizeof(u3)-1);
    retval += UNITTEST_STATUS(4, status);

    /* Edge cases */
    status = fillPrimitiveToken(&tok,
                                t1, 1, sizeof(t1)-1);
    retval += UNITTEST_TRUE(10, OK != status);
    status = fillPrimitiveToken(&tok,
                                f1, 1, sizeof(f1)-1);
    retval += UNITTEST_TRUE(10, OK != status);
    status = fillPrimitiveToken(&tok,
                                t1, 0, sizeof(t1)-2);
    retval += UNITTEST_TRUE(10, OK != status);
    status = fillPrimitiveToken(&tok,
                                f1, 0, sizeof(f1)-2);
    retval += UNITTEST_TRUE(10, OK != status);

    status = fillPrimitiveToken(&tok,
                                n1, 1, sizeof(n1)-1);
    retval += UNITTEST_TRUE(20, OK != status);
    status = fillPrimitiveToken(&tok,
                                n1, 0, sizeof(n1)-2);
    retval += UNITTEST_TRUE(20, OK != status);

    /* Illegal formats */
    status = fillPrimitiveToken(&tok,
                                e1, 0, sizeof(e1)-1);
    retval += UNITTEST_TRUE(30, OK != status);
    status = fillPrimitiveToken(&tok,
                                e2, 0, sizeof(e2)-1);
    retval += UNITTEST_TRUE(30, OK != status);
    status = fillPrimitiveToken(&tok,
                                e3, 0, sizeof(e3)-1);
    retval += UNITTEST_TRUE(30, OK != status);

#if 0
    /* Exponent Format */
    status = fillPrimitiveToken(&tok,
                                x1, 0, sizeof(x1)-1);
    retval += UNITTEST_STATUS(40, status);
    status = fillPrimitiveToken(&tok,
                                x2, 0, sizeof(x2)-1);
    retval += UNITTEST_STATUS(40, status);
    status = fillPrimitiveToken(&tok,
                                x3, 0, sizeof(x3)-1);
    retval += UNITTEST_STATUS(40, status);
#else
    printf("WARNING: Exponent format not supported! Tests were skipped...\n");
#endif

    /* Bad input */
    status = fillPrimitiveToken(&tok,
                                i1, sizeof(i1)-1, 0);
    retval += UNITTEST_TRUE(50, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseBoundary()
{
    MSTATUS status;
    int retval = 0;
    JSON_ContextType *ctx = NULL;
    ubyte4 tokens;

    const sbyte str0[] = "{}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Simplest objects possible, setting one parameter to NULL */
    status = JSON_parse(NULL, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_TRUE(1, OK != status);

    status = JSON_parse(ctx, NULL, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        NULL);
    retval += UNITTEST_TRUE(3, OK != status);

    /* Invalid parameters */
    status = JSON_parse(ctx, str0, 0,
                        &tokens);
    retval += UNITTEST_TRUE(10, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseSimple()
{
    MSTATUS status;
    int retval = 0;
    JSON_ContextType *ctx = NULL;
    ubyte4 tokens;

    const sbyte str0[] = "{}";
    const sbyte str1[] = "[]";
    const sbyte str2[] = "{\"name\":\"value\"}";
    const sbyte str3[] = "[false]";
    const sbyte str4[] = "[1]";
    const sbyte str5[] = "[\"on\"]";
    const sbyte str6[] = "{\"object\":null}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Simplest objects possible */
    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    retval += UNITTEST_INT(1, tokens, 1);

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    retval += UNITTEST_INT(2, tokens, 1);

    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_STATUS(3, status);
    retval += UNITTEST_INT(3, tokens, 3);

    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_STATUS(4, status);
    retval += UNITTEST_INT(4, tokens, 2);

    status = JSON_parse(ctx, str4, sizeof(str4)-1,
                        &tokens);
    retval += UNITTEST_STATUS(5, status);
    retval += UNITTEST_INT(5, tokens, 2);

    status = JSON_parse(ctx, str5, sizeof(str5)-1,
                        &tokens);
    retval += UNITTEST_STATUS(6, status);
    retval += UNITTEST_INT(6, tokens, 2);

    status = JSON_parse(ctx, str6, sizeof(str6)-1,
                        &tokens);
    retval += UNITTEST_STATUS(7, status);
    retval += UNITTEST_INT(7, tokens, 3);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseSimpleBadInput()
{
    MSTATUS status;
    int retval = 0;
    JSON_ContextType *ctx = NULL;
    ubyte4 tokens;

    const sbyte str0[] = "{name}";
    const sbyte str1[] = "{\"name\":}";
    const sbyte str2[] = "{\"name\" \"value\"}";
    const sbyte str3[] = "{\"name\":\"valu}";
    const sbyte str4[] = "{\"nam}";
    const sbyte str5[] = "{]";
    const sbyte str6[] = "[}";
    const sbyte str7[] = "[name]";
    const sbyte str8[] = "[\"nam]";
    const sbyte str9[] = "[\"s1\" \"s2\"]";
    const sbyte str10[] = "\"\"";
    const sbyte str11[] = "{\"{\"}";
    const sbyte str12[] = "-";
    const sbyte str13[] = "{#}";
    const sbyte str14[] = "{\"v\":@}";
    const sbyte str15[] = "{false}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Simplest invalid strings possible */
    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_TRUE(1, OK != status);

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_TRUE(3, OK != status);

    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_TRUE(4, OK != status);

    status = JSON_parse(ctx, str4, sizeof(str4)-1,
                        &tokens);
    retval += UNITTEST_TRUE(5, OK != status);

    status = JSON_parse(ctx, str5, sizeof(str5)-1,
                        &tokens);
    retval += UNITTEST_TRUE(6, OK != status);

    status = JSON_parse(ctx, str6, sizeof(str6)-1,
                        &tokens);
    retval += UNITTEST_TRUE(7, OK != status);

    status = JSON_parse(ctx, str7, sizeof(str7)-1,
                        &tokens);
    retval += UNITTEST_TRUE(8, OK != status);

    status = JSON_parse(ctx, str8, sizeof(str8)-1,
                        &tokens);
    retval += UNITTEST_TRUE(9, OK != status);

    status = JSON_parse(ctx, str9, sizeof(str9)-1,
                        &tokens);
    retval += UNITTEST_TRUE(10, OK != status);

    status = JSON_parse(ctx, str10, sizeof(str10)-1,
                        &tokens);
    retval += UNITTEST_TRUE(11, OK != status);

    status = JSON_parse(ctx, str11, sizeof(str11)-1,
                        &tokens);
    retval += UNITTEST_TRUE(12, OK != status);

    status = JSON_parse(ctx, str12, sizeof(str12)-1,
                        &tokens);
    retval += UNITTEST_TRUE(13, OK != status);

    status = JSON_parse(ctx, str13, sizeof(str13)-1,
                        &tokens);
    retval += UNITTEST_TRUE(14, OK != status);

    status = JSON_parse(ctx, str14, sizeof(str14)-1,
                        &tokens);
    retval += UNITTEST_TRUE(15, OK != status);

    status = JSON_parse(ctx, str15, sizeof(str15)-1,
                        &tokens);
    retval += UNITTEST_TRUE(16, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseSimpleBoolean()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type;
    ubyte4           tokens;

    const sbyte str0[] = "{\"v\":false}";
    const sbyte str1[] = "{\"v\":true}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 3);
    if (0 < retval)
        goto exit;

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(10, type.type, JSON_False);
    retval += UNITTEST_INT(10, type.elemCnt, 0);
    retval += UNITTEST_INT(10, type.len, 5);
    if (0 < retval)
        goto exit;

    /***/
    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, tokens, 3);
    if (0 < retval)
        goto exit;

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(20, type.type, JSON_True);
    retval += UNITTEST_INT(20, type.elemCnt, 0);
    retval += UNITTEST_INT(20, type.len, 4);
    if (0 < retval)
        goto exit;

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseSimpleNull()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"v\":null}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 3);
    if (0 < retval)
        goto exit;

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(10, type.type, JSON_Null);
    retval += UNITTEST_INT(10, type.elemCnt, 0);
    retval += UNITTEST_INT(10, type.len, 4);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseSimpleStrings()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;
    sbyte4           cmp;

    const sbyte str0[] = "{\"v\":\"}\"}";
    const sbyte str1[] = "{\"[\":1}";
    const sbyte str2[] = "[\"{\"]";

    /* List taken from 'https://www.json.org/' */
    const sbyte str3[] = "[\"\\n\"]";
    const sbyte str4[] = "[\"\\t\"]";
    const sbyte str5[] = "[\"\\r\"]";
    const sbyte str6[] = "[\"\\f\"]";
    const sbyte str7[] = "[\"\\b\"]";
    const sbyte str8[] = "[\"\\\"\"]";
    const sbyte str9[] = "[\"\\/\"]";

    const sbyte ustr0[] = "[\"\\u0020\"]";

    const sbyte s0[] = "[\"test\"]";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Simplest 'confusion' strings possible */
    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);

    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_STATUS(3, status);

    /* Special characters */
    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_STATUS(4, status);
    retval += UNITTEST_INT(14, tokens, 2);

    status = JSON_parse(ctx, str4, sizeof(str4)-1,
                        &tokens);
    retval += UNITTEST_STATUS(5, status);
    retval += UNITTEST_INT(15, tokens, 2);

    status = JSON_parse(ctx, str5, sizeof(str5)-1,
                        &tokens);
    retval += UNITTEST_STATUS(6, status);
    retval += UNITTEST_INT(16, tokens, 2);

    status = JSON_parse(ctx, str6, sizeof(str6)-1,
                        &tokens);
    retval += UNITTEST_STATUS(7, status);
    retval += UNITTEST_INT(17, tokens, 2);

    status = JSON_parse(ctx, str7, sizeof(str7)-1,
                        &tokens);
    retval += UNITTEST_STATUS(8, status);
    retval += UNITTEST_INT(18, tokens, 2);

    status = JSON_parse(ctx, str8, sizeof(str8)-1,
                        &tokens);
    retval += UNITTEST_STATUS(9, status);
    retval += UNITTEST_INT(19, tokens, 2);

    status = JSON_parse(ctx, str9, sizeof(str9)-1,
                        &tokens);
    retval += UNITTEST_STATUS(110, status);
    retval += UNITTEST_INT(120, tokens, 2);

    /* Unicode strings */
    status = JSON_parse(ctx, ustr0, sizeof(ustr0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(200, status);
    retval += UNITTEST_INT(210, tokens, 2);

    /* Test value in token */
    status = JSON_parse(ctx, s0, sizeof(s0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(300, status);
    retval += UNITTEST_INT(300, tokens, 2);

    status = JSON_getToken(ctx, 1, &type);
    retval += UNITTEST_STATUS(300, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(301, type.type, JSON_String);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(301, type.len, 4);
    DIGI_MEMCMP((const ubyte*)&(s0[2]),
               (const ubyte*)type.pStart, 4, &cmp);
    retval += UNITTEST_INT(302, cmp, 0);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getTokenBoundary()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"name\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(0, tokens, 3);

    /* Invalid 'JSON_getNumTokens' parameters */
    status = JSON_getNumTokens(NULL, &tokens);
    retval += UNITTEST_TRUE(1, OK != status);

    status = JSON_getNumTokens(ctx, NULL);
    retval += UNITTEST_TRUE(1, OK != status);

    /* Invalid 'JSON_getToken' access */
    status = JSON_getToken(ctx, 10, &type);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_getToken(NULL, 1, &type);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_getToken(ctx, 1, NULL);
    retval += UNITTEST_TRUE(2, OK != status);

exit:
   JSON_releaseContext(&ctx);
   return retval;
}

int mjson_test_getTokenEmpty()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 1);

    status = JSON_getNumTokens(ctx, &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 1);

    status = JSON_getToken(ctx, 0, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(10, type.type, JSON_Object);
    retval += UNITTEST_INT(10, type.elemCnt, 0);
    retval += UNITTEST_INT(10, type.len, sizeof(str0)-1);
    retval += UNITTEST_TRUE(10, str0 == type.pStart);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getTokenSimple()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;
    sbyte4           cmp;

    const sbyte str0[] = "{\"name\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 3);

    status = JSON_getNumTokens(ctx, &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 3);

    /***/
    status = JSON_getToken(ctx, 0, &type);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, type.type, JSON_Object);
    retval += UNITTEST_INT(2, type.elemCnt, 1);

    /***/
    status = JSON_getToken(ctx, 1, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(10, type.type, JSON_String);
    retval += UNITTEST_INT(10, type.elemCnt, 1);
    retval += UNITTEST_INT(10, type.len, 4);
    DIGI_MEMCMP((const ubyte*)&(str0[2]),
               (const ubyte*)type.pStart, 4, &cmp);
    retval += UNITTEST_INT(10, cmp, 0);

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(20, type.type, JSON_String);
    retval += UNITTEST_INT(20, type.elemCnt, 0);
    retval += UNITTEST_INT(20, type.len, 5);
    DIGI_MEMCMP((const ubyte*)&(str0[9]),
               (const ubyte*)type.pStart, 5, &cmp);
    retval += UNITTEST_INT(10, cmp, 0);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseArray()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;
    sbyte4           cmp;

    const sbyte str0[] = "{\"v\":[]}";
    const sbyte str1[] = "{\"v\":[1,2,3]}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    /* Simplest arrays possible */
    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_STATUS(1, status);
    retval += UNITTEST_INT(1, tokens, 3);

    /***/
    status = JSON_getToken(ctx, 0, &type);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, type.type, JSON_Object);
    retval += UNITTEST_INT(2, type.elemCnt, 1);

    /***/
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(3, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(3, type.type, JSON_Array);
    retval += UNITTEST_INT(3, type.elemCnt, 0);
    retval += UNITTEST_INT(3, type.len, 2);
    if (0 < retval)
        goto exit;

    DIGI_MEMCMP((const ubyte*)&(str0[5]),
               (const ubyte*)type.pStart, 2, &cmp);
    retval += UNITTEST_INT(3, cmp, 0);

    /* Test intermediate release/acquire */
    JSON_releaseContext(&ctx);
    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(10, tokens, 6);

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(11, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(11, type.type, JSON_Array);
    retval += UNITTEST_INT(11, type.elemCnt, 3);
    retval += UNITTEST_INT(11, type.len, 7);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseNumbers()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"v\":0}";
    const sbyte str1[] = "{\"v\":123}";
    const sbyte str2[] = "{\"v\":-1001}";
    const sbyte str3[] = "{\"v\":1.0}";
    const sbyte str4[] = "{\"v\":-42.11}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(1, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(10, type.type, JSON_Integer);
    retval += UNITTEST_INT(10, type.elemCnt, 0);
    retval += UNITTEST_INT(10, type.len, 1);
    retval += UNITTEST_INT(10, type.num.intVal, 0);

    /***/
    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(2, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(20, type.type, JSON_Integer);
    retval += UNITTEST_INT(20, type.elemCnt, 0);
    retval += UNITTEST_INT(20, type.len, 3);
    retval += UNITTEST_INT(20, type.num.intVal, 123);

    /***/
    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_STATUS(3, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(3, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(30, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(30, type.type, JSON_Integer);
    retval += UNITTEST_INT(30, type.elemCnt, 0);
    retval += UNITTEST_INT(30, type.len, 5);
    retval += UNITTEST_INT(30, type.num.intVal, -1001);

    /***/
    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_STATUS(4, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(4, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(40, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(40, type.type, JSON_Float);
    retval += UNITTEST_INT(40, type.elemCnt, 0);
    retval += UNITTEST_INT(40, type.len, 3);
    retval += UNITTEST_INT(40, type.num.floatVal, 1.0);

    /***/
    status = JSON_parse(ctx, str4, sizeof(str4)-1,
                        &tokens);
    retval += UNITTEST_STATUS(5, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(5, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(50, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(50, type.type, JSON_Float);
    retval += UNITTEST_INT(50, type.elemCnt, 0);
    retval += UNITTEST_INT(50, type.len, 6);
    retval += UNITTEST_INT(50, type.num.floatVal, -42.11);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseNumbersBadInput()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens;

    const sbyte str0[] = "{\"v\":-}";
    const sbyte str1[] = "{\"v\":.0}";
    const sbyte str2[] = "{\"v\":0.}";
    const sbyte str3[] = "{\"v\":0..6}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_TRUE(1, OK != status);

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_TRUE(3, OK != status);

    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_TRUE(4, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseObjectElements()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"e1\":1,\"e2\":-3.5,\"e3\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 7);

    status = JSON_getToken(ctx, 0, &type);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, type.type, JSON_Object);
    retval += UNITTEST_INT(2, type.elemCnt, 3);
    retval += UNITTEST_INT(2, type.len, sizeof(str0)-1);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseNestedObjects()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"o\":{}}";
    const sbyte str1[] = "{\"o\":{\"o1\":1,\"o2\":2}}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(1, tokens, 3);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(10, type.type, JSON_Object);
    retval += UNITTEST_INT(10, type.elemCnt, 0);
    retval += UNITTEST_INT(10, type.len, 2);

    /***/
    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT(2, tokens, 7);
    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(20, type.type, JSON_Object);
    retval += UNITTEST_INT(20, type.elemCnt, 2);
    retval += UNITTEST_INT(20, type.len, 15);

    status = JSON_getToken(ctx, 3, &type);
    retval += UNITTEST_STATUS(21, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(21, type.type, JSON_String);
    retval += UNITTEST_INT(21, type.len, 2);

    status = JSON_getToken(ctx, 4, &type);
    retval += UNITTEST_STATUS(22, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(22, type.type, JSON_Integer);
    retval += UNITTEST_INT(22, type.len, 1);
    retval += UNITTEST_INT(22, type.num.intVal, 1);

    status = JSON_getToken(ctx, 5, &type);
    retval += UNITTEST_STATUS(23, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(23, type.type, JSON_String);
    retval += UNITTEST_INT(23, type.len, 2);

    status = JSON_getToken(ctx, 6, &type);
    retval += UNITTEST_STATUS(24, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(24, type.type, JSON_Integer);
    retval += UNITTEST_INT(24, type.len, 1);
    retval += UNITTEST_INT(24, type.num.intVal, 2);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseNestedObjectsBadInput()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    ubyte4           tokens;

    const sbyte str0[] = "{\"o\":{}";
    const sbyte str1[] = "{\"o\":{\"o1\":1 \"o2\":2}}";
    const sbyte str2[] = "{\"o\":{,}}";
    const sbyte str3[] = "{{}}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

#if 0
    /* For later improvements of the parser JSON state logic */
    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_TRUE(1, OK != status);
#else
    printf("WARNING: Parser syntax check incomplete! Tests were skipped...\n");
#endif

    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_TRUE(2, OK != status);

    status = JSON_parse(ctx, str2, sizeof(str2)-1,
                        &tokens);
    retval += UNITTEST_TRUE(3, OK != status);

    status = JSON_parse(ctx, str3, sizeof(str3)-1,
                        &tokens);
    retval += UNITTEST_TRUE(4, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getObjectIndexBoundary()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens, place;

    const sbyte str0[] = "{\"name\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;

    /* NULL parameters */
    status = JSON_getObjectIndex(NULL, (sbyte*)"name", 0,
                                 &place, FALSE);
    retval += UNITTEST_TRUE(2, OK != status);
    status = JSON_getObjectIndex(ctx, NULL, 0,
                                 &place, FALSE);
    retval += UNITTEST_TRUE(2, OK != status);
    status = JSON_getObjectIndex(ctx, (sbyte*)"name", 0,
                                 NULL, FALSE);
    retval += UNITTEST_TRUE(2, OK != status);

    /* Bad values */
    status = JSON_getObjectIndex(ctx, (sbyte*)"name", 999,
                                 &place, FALSE);
    retval += UNITTEST_TRUE(3, OK != status);
    status = JSON_getObjectIndex(ctx, (sbyte*)"", 0,
                                 &place, FALSE);
    retval += UNITTEST_TRUE(3, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getObjectIndexSimple()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens, place;

    const sbyte str0[] = "{\"e1\":1,\"e2\":-3.5,\"e3\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 7);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e1", 0,
                                 &place, FALSE);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, place, 1);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e2", 0,
                                 &place, FALSE);
    retval += UNITTEST_STATUS(3, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(3, place, 3);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e3", 0,
                                 &place, FALSE);
    retval += UNITTEST_STATUS(4, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(4, place, 5);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getObjectIndexBoundedSimple()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens, place;

    const sbyte str0[] = "{\"e1\":1,\"e2\":-3.5,\"e3\":\"value\"}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 7);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e1", 0,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, place, 1);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e2", 0,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(3, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(3, place, 3);

    status = JSON_getObjectIndex(ctx, (sbyte*)"e3", 0,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(4, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(4, place, 5);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getObjectIndexBounded()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens, place, place1, place2, place3, placea;

    const sbyte str0[] = "{\"o1\":{\"v\":1},\"o2\":{\"v\":2,\"a\":false},\"o3\":{\"v\":3}}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 15);

    status = JSON_getObjectIndex(ctx, (sbyte*)"o1", 0,
                                 &place1, TRUE);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, place1, 1);

    status = JSON_getObjectIndex(ctx, (sbyte*)"o2", 0,
                                 &place2, TRUE);
    retval += UNITTEST_STATUS(3, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(3, place2, 5);

    status = JSON_getObjectIndex(ctx, (sbyte*)"o3", 0,
                                 &place3, TRUE);
    retval += UNITTEST_STATUS(4, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(4, place3, 11);

    status = JSON_getObjectIndex(ctx, (sbyte*)"v", place1+1,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;

    status = JSON_getObjectIndex(ctx, (sbyte*)"v", place2+1,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(11, status);
    if (0 < retval)
        goto exit;

    status = JSON_getObjectIndex(ctx, (sbyte*)"v", place3+1,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(12, status);
    if (0 < retval)
        goto exit;

    status = JSON_getObjectIndex(ctx, (sbyte*)"a", 0,
                                 &placea, TRUE);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;

    status = JSON_getObjectIndex(ctx, (sbyte*)"a", place2+1,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(21, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_TRUE(21, placea == place);

    status = JSON_getObjectIndex(ctx, (sbyte*)"a", place1+1,
                                 &place, TRUE);
    retval += UNITTEST_TRUE(22, OK != status);

    status = JSON_getObjectIndex(ctx, (sbyte*)"a", place3+1,
                                 &place, TRUE);
    retval += UNITTEST_TRUE(23, OK != status);

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseObjectsInArray()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens;

    const sbyte str0[] = "{\"a\":[{}]}";
    const sbyte str1[] = "{\"a\":[{\"o1\":1,\"o2\":2},{\"o1\":10,\"o2\":11}]}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 4);

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(10, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(10, type.type, JSON_Array);
    retval += UNITTEST_INT(10, type.elemCnt, 1);
    retval += UNITTEST_INT(10, type.len, 4);

    status = JSON_getToken(ctx, 3, &type);
    retval += UNITTEST_STATUS(11, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(11, type.type, JSON_Object);
    retval += UNITTEST_INT(11, type.elemCnt, 0);
    retval += UNITTEST_INT(11, type.len, 2);

    /*****/
    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, tokens, 13);

    status = JSON_getToken(ctx, 2, &type);
    retval += UNITTEST_STATUS(20, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(20, type.type, JSON_Array);
    retval += UNITTEST_INT(20, type.elemCnt, 2);
    retval += UNITTEST_INT(20, type.len, 35);

    status = JSON_getToken(ctx, 3, &type);
    retval += UNITTEST_STATUS(21, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(21, type.type, JSON_Object);
    retval += UNITTEST_INT(21, type.elemCnt, 2);
    retval += UNITTEST_INT(21, type.len, 15);

exit:
   JSON_releaseContext(&ctx);
   return retval;
}

int mjson_test_getObjectIndexArray()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens, place = 0, arrayCount;
    ubyte4           i;

    const sbyte str0[] = "{\"a\":[{\"o1\":1,\"o2\":2},{\"o1\":10,\"o2\":11}]}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 13);
    if (0 < retval)
        goto exit;

    /* Locate array 'a' */
    status = JSON_getObjectIndex(ctx, (sbyte*)"a", 0,
                                 &place, FALSE);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, place, 1);

    /* Locate Token for 'a' value */
    ++place;
    status = JSON_getToken(ctx, place, &type);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;

    /* Find array count */
    retval += UNITTEST_INT(3, type.type, JSON_Array);
    if (0 < retval)
        goto exit;

    arrayCount = type.elemCnt;
    ++place;

    for (i = 0; i < arrayCount; ++i)
    {
        JSON_TokenType entry, nvpair;
        ubyte4         subPlace;

        /* Get entry in array */
        status = JSON_getToken(ctx, place, &entry);
        retval += UNITTEST_STATUS(20+i, status);
        if (0 < retval)
            goto exit;

        /* Ensure expected type */
        retval += UNITTEST_INT(30+i, entry.type, JSON_Object);
        if (0 < retval)
            goto exit;

        /* Locate 'o1' */
        status = JSON_getObjectIndex(ctx, (sbyte*)"o1", place,
                                     &subPlace, FALSE);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_TRUE(40+i, 0 != subPlace);
        status = JSON_getToken(ctx, subPlace, &nvpair);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(40+i, nvpair.type, JSON_String);
        status = JSON_getToken(ctx, subPlace+1, &nvpair);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(40+i, nvpair.type, JSON_Integer);

        switch (i)
        {
        case 0:
            retval += UNITTEST_INT(40+i, nvpair.num.intVal, 1);
            break;
        case 1:
            retval += UNITTEST_INT(40+i, nvpair.num.intVal, 10);
            break;
        }

        /* Locate 'o2' */
        status = JSON_getObjectIndex(ctx, (sbyte*)"o2", place,
                                     &subPlace, FALSE);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_TRUE(50+i, 0 != subPlace);
        status = JSON_getToken(ctx, subPlace, &nvpair);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(50+i, nvpair.type, JSON_String);
        status = JSON_getToken(ctx, subPlace+1, &nvpair);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(50+i, nvpair.type, JSON_Integer);

        switch (i)
        {
        case 0:
            retval += UNITTEST_INT(50+i, nvpair.num.intVal, 2);
            break;
        case 1:
            retval += UNITTEST_INT(50+i, nvpair.num.intVal, 11);
            break;
        }

        /* Step to next entry */
        place = subPlace + 2;
    }

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_getObjectIndexBoundedArray()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    JSON_TokenType   type = { 0 };
    ubyte4           tokens, place = 0, arrayCount;
    ubyte4           i;

    const sbyte str0[] = "{\"a\":[{\"o1\":1,\"o2\":2},{\"o1\":10,\"o2\":11}]}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 13);
    if (0 < retval)
        goto exit;

    /* Locate array 'a' */
    status = JSON_getObjectIndex(ctx, (sbyte*)"a", 0,
                                 &place, TRUE);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, place, 1);

    /* Locate Token for 'a' value */
    ++place;
    status = JSON_getToken(ctx, place, &type);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;

    /* Find array count */
    retval += UNITTEST_INT(3, type.type, JSON_Array);
    if (0 < retval)
        goto exit;

    arrayCount = type.elemCnt;
    ++place;

    for (i = 0; i < arrayCount; ++i)
    {
        JSON_TokenType entry, nvpair;
        ubyte4         subPlace;

        /* Get entry in array */
        status = JSON_getToken(ctx, place, &entry);
        retval += UNITTEST_STATUS(20+i, status);
        if (0 < retval)
            goto exit;

        /* Ensure expected type */
        retval += UNITTEST_INT(30+i, entry.type, JSON_Object);
        if (0 < retval)
            goto exit;

        /* Locate 'o1' */
        status = JSON_getObjectIndex(ctx, (sbyte*)"o1", place,
                                     &subPlace, TRUE);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_TRUE(40+i, 0 != subPlace);
        status = JSON_getToken(ctx, subPlace, &nvpair);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(40+i, nvpair.type, JSON_String);
        status = JSON_getToken(ctx, subPlace+1, &nvpair);
        retval += UNITTEST_STATUS(40+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(40+i, nvpair.type, JSON_Integer);

        switch (i)
        {
        case 0:
            retval += UNITTEST_INT(40+i, nvpair.num.intVal, 1);
            break;
        case 1:
            retval += UNITTEST_INT(40+i, nvpair.num.intVal, 10);
            break;
        }

        /* Locate 'o2' */
        status = JSON_getObjectIndex(ctx, (sbyte*)"o2", place,
                                     &subPlace, TRUE);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_TRUE(50+i, 0 != subPlace);
        status = JSON_getToken(ctx, subPlace, &nvpair);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(50+i, nvpair.type, JSON_String);
        status = JSON_getToken(ctx, subPlace+1, &nvpair);
        retval += UNITTEST_STATUS(50+i, status);
        if (0 < retval)
            goto exit;
        retval += UNITTEST_INT(50+i, nvpair.type, JSON_Integer);

        switch (i)
        {
        case 0:
            retval += UNITTEST_INT(50+i, nvpair.num.intVal, 2);
            break;
        case 1:
            retval += UNITTEST_INT(50+i, nvpair.num.intVal, 11);
            break;
        }

        /* Step to next entry */
        place = subPlace + 2;
    }

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseNestedArrays()
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    //JSON_TokenType   type;
    ubyte4           tokens;

    const sbyte str0[] = "{\"a\":[[]]}";
    const sbyte str1[] = "{\"a\":[[1,2],[3,4],[5,6]]}";

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, str0, sizeof(str0)-1,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(1, tokens, 4);
    if (0 < retval)
        goto exit;

    /***/
    status = JSON_parse(ctx, str1, sizeof(str1)-1,
                        &tokens);
    retval += UNITTEST_STATUS(2, status);
    if (0 < retval)
        goto exit;
    retval += UNITTEST_INT(2, tokens, 12);
    if (0 < retval)
        goto exit;

exit:
    JSON_releaseContext(&ctx);
    return retval;
}

static int
run_json_fromFile(const char* path)
{
    MSTATUS status;
    int retval = 0;

    JSON_ContextType *ctx = NULL;
    ubyte4           tokens;

    sbyte* pContent = NULL;
    ubyte4 contentLen;

    status = DIGICERT_readFile(path,
                             (ubyte**)&pContent,
                             &contentLen);
    if (OK != status)
    {
        printf("WARNING: Could not read test file '%s'. Test was skipped!\n", path);
        goto exit;
    }

    status = JSON_acquireContext(&ctx);
    retval += UNITTEST_STATUS(0, status);
    if (0 < retval)
        goto exit;

    status = JSON_parse(ctx, pContent, contentLen,
                        &tokens);
    retval += UNITTEST_STATUS(1, status);
    if (0 < retval)
        goto exit;

    printf("Found %u tokens in '%s'\n", tokens, path);
    retval += UNITTEST_TRUE(2, 0 < tokens);

exit:
    if (NULL != pContent)
    {
        DIGI_FREE((void**)&pContent);
    }
    JSON_releaseContext(&ctx);
    return retval;
}

int mjson_test_parseJSONExamples()
{
    int retval = 0;
    int i;

    /* NOTE: File content copied from 'http://www.json.org/example.html' */
    const char* files[] = {
            "JSON_example1.txt",
            "JSON_example2.txt",
            "JSON_example3.txt",
            "JSON_example4.txt",
            "JSON_example5.txt",
            NULL,
    };

    /* Run all listed files */
    for (i = 0; i < 999; ++i)
    {
        if (NULL == files[i])
            break;

        retval += run_json_fromFile(files[i]);
    }

    return retval;
}
