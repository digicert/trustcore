/*
 * test_mqtt_utils.c
 *
 * MQTT Utils Unit Test
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include "cmocka.h"

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"

#include "../../mqtt/mqtt_util.h"


static void mqtt_test_valid_utf8(void **ppState)
{
    ubyte *pValid1 = "abc";
    ubyte4 valid1Len = 3;
    ubyte pValid2[] = {0xED, 0x95, 0x9C, 0xEA, 0xB5, 0xAD, 0xEC, 0x96, 0xB4};
    ubyte4 valid2Len = 9;

    assert_int_equal(TRUE, isValidUtf8(pValid1, valid1Len));
    assert_int_equal(TRUE, isValidUtf8(pValid2, valid2Len));
    assert_int_equal(FALSE, isValidUtf8(NULL, 0));

    return;
}

static void mqtt_test_varint_encode(void **ppState)
{
    MSTATUS status;
    ubyte res[4];
    ubyte bytesWritten = 0;
    ubyte4 val1 = 1;
    ubyte res1[4] = {0x01};
    ubyte4 res1NumBytes = 1;
    ubyte4 val2 = 129;
    ubyte res2[4] = {0x81, 0x01};
    ubyte4 res2NumBytes = 2;
    ubyte4 val3 = 16385;
    ubyte res3[4] = {0x81, 0x80, 0x01};
    ubyte4 res3NumBytes = 3;
    ubyte4 val4 = 2097153;
    ubyte res4[4] = {0x81, 0x80, 0x80, 0x01};
    ubyte4 res4NumBytes = 4;

    status = MQTT_encodeVariableByteInt(val1, (ubyte *)res, &bytesWritten);
    assert_int_equal(OK, status);
    assert_int_equal(bytesWritten, res1NumBytes);
    assert_memory_equal(res, res1, bytesWritten);

    status = MQTT_encodeVariableByteInt(val2, (ubyte *)res, &bytesWritten);
    assert_int_equal(OK, status);
    assert_int_equal(bytesWritten, res2NumBytes);
    assert_memory_equal(res, res2, bytesWritten);
    
    status = MQTT_encodeVariableByteInt(val3, (ubyte *)res, &bytesWritten);
    assert_int_equal(OK, status);
    assert_int_equal(bytesWritten, res3NumBytes);
    assert_memory_equal(res, res3, bytesWritten);
    
    status = MQTT_encodeVariableByteInt(val4, (ubyte *)res, &bytesWritten);
    assert_int_equal(OK, status);
    assert_int_equal(bytesWritten, res4NumBytes);
    assert_memory_equal(res, res4, bytesWritten);

    /* Length only */
    assert_int_equal(OK, MQTT_encodeVariableByteInt(val1, NULL, &bytesWritten));
    assert_int_equal(bytesWritten, res1NumBytes);

    assert_int_equal(OK, MQTT_encodeVariableByteInt(val2, NULL, &bytesWritten));
    assert_int_equal(bytesWritten, res2NumBytes);

    assert_int_equal(OK, MQTT_encodeVariableByteInt(val3, NULL, &bytesWritten));
    assert_int_equal(bytesWritten, res3NumBytes);

    assert_int_equal(OK, MQTT_encodeVariableByteInt(val4, NULL, &bytesWritten));
    assert_int_equal(bytesWritten, res4NumBytes);

    /* Error */
    assert_int_not_equal(OK, MQTT_encodeVariableByteInt(268435457, (ubyte *)res, &bytesWritten));

    return;
}

static void mqtt_test_varint_decode(void **ppState)
{
    MSTATUS status;
    ubyte4 val = 0;
    ubyte res[4];
    ubyte bytesUsed = 0;
    ubyte4 val1 = 1;
    ubyte res1[4] = {0x01};
    ubyte4 res1NumBytes = 1;
    ubyte4 val2 = 129;
    ubyte res2[4] = {0x81, 0x01};
    ubyte4 res2NumBytes = 2;
    ubyte4 val3 = 16385;
    ubyte res3[4] = {0x81, 0x80, 0x01};
    ubyte4 res3NumBytes = 3;
    ubyte4 val4 = 2097153;
    ubyte res4[4] = {0x81, 0x80, 0x80, 0x01};
    ubyte4 res4NumBytes = 4;
    ubyte res6[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    status = MQTT_decodeVariableByteInt((ubyte *)res1, res1NumBytes, &val, &bytesUsed);
    assert_int_equal(OK, status);
    assert_int_equal(val, val1);
    assert_int_equal(bytesUsed, res1NumBytes);

    status = MQTT_decodeVariableByteInt((ubyte *)res2, res2NumBytes, &val, &bytesUsed);
    assert_int_equal(OK, status);
    assert_int_equal(val, val2);
    assert_int_equal(bytesUsed, res2NumBytes);

    status = MQTT_decodeVariableByteInt((ubyte *)res3, res3NumBytes, &val, &bytesUsed);
    assert_int_equal(OK, status);
    assert_int_equal(val, val3);
    assert_int_equal(bytesUsed, res3NumBytes);

    status = MQTT_decodeVariableByteInt((ubyte *)res4, res4NumBytes, &val, &bytesUsed);
    assert_int_equal(OK, status);
    assert_int_equal(val, val4);
    assert_int_equal(bytesUsed, res4NumBytes);

    /* Error cases */
    status = MQTT_decodeVariableByteInt(NULL, 0, &val, NULL);
    assert_int_not_equal(OK, status);

    status = MQTT_decodeVariableByteInt((ubyte *)res1, 1, NULL, NULL);
    assert_int_not_equal(OK, status);

    status = MQTT_decodeVariableByteInt((ubyte *)res1, 0, &val, NULL);
    assert_int_not_equal(OK, status);

    status = MQTT_decodeVariableByteInt((ubyte *)res6, 6, &val, NULL);
    assert_int_not_equal(OK, status);

    return;
}

static int testSetup(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = MOCANA_initMocana();
    if (OK == status)
        ret = 0;

    return ret;
}

static int testTeardown(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = MOCANA_freeMocana();
    if (OK == status)
        ret = 0;

    return ret;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(mqtt_test_varint_encode),
        cmocka_unit_test(mqtt_test_varint_decode),
        cmocka_unit_test(mqtt_test_valid_utf8)

    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}