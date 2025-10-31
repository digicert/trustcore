/*
 * test_mqtt_core.c
 *
 * MQTT Core Unit Test
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

#include "cmocka.h"

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"
#include "common/mocana.h"

#include "../../mqtt/mqtt_client.h" 
#include "mqtt/mqtt_client_priv.h"
#include "mqtt/mqtt_core.h"


typedef struct
{
    ubyte4 numElements;
    MqttPacketList *pHead;
    MqttPacketList *pTail;
} MqttPacketListWrapper;

static void mqtt_test_MQTT_initCoreandUninitcore(void **ppState)
{
    MSTATUS status;
    sbyte4 mqttMaxClientConnections = 1;

    status = MQTT_initCore(0);
    assert_int_equal(ERR_MQTT_INVALID_MAX_CLIENT_CONN, status);

    status = MQTT_uninitCore();
    assert_int_equal(OK, status);

    status = MQTT_initCore(mqttMaxClientConnections);
    assert_int_equal(OK, status);

    status = MQTT_uninitCore();
    assert_int_equal(OK, status);
}

static void mqtt_test_MQTT_createConnectInstanceAndRelease(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    MqttCtx *pCtx = NULL;

    MQTT_initCore(2);

    status = MQTT_createConnectInstanceFromId(5, "testClient1", 11, &connInst, 0);
    assert_int_equal(OK, status);
    assert_int_equal(0, connInst);

    status = MQTT_createConnectInstanceFromId(4, "testClient2", 11, &connInst, 0);
    assert_int_equal(OK, status);
    assert_int_equal(1, connInst);

    status = MQTT_getCtxFromConnInst(0, &pCtx);
    assert_int_equal(OK, status);

    status = MQTT_releaseClientCtx(&pCtx);
    assert_int_equal(OK, status);

    status = MQTT_getCtxFromConnInst(1, &pCtx);
    assert_int_equal(OK, status);

    status = MQTT_releaseClientCtx(&pCtx);
    assert_int_equal(OK, status);

    MQTT_uninitCore();
}

static void mqtt_test_MQTT_hasUnackedPackets(void **ppState)
{
    MqttCtx *pCtx = NULL;
    byteBoolean result = 0;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->pPacketIdList = NULL;
    result = MQTT_hasUnackedPackets(pCtx);
    assert_int_equal(0, result);
    
    MqttPacketListWrapper *pWrapper = NULL;
    MOC_MALLOC((void **)&pWrapper, sizeof(MqttPacketListWrapper));
    assert_non_null(pWrapper);

    pWrapper->numElements = 0;
    pCtx->pPacketIdList = (void *)pWrapper;

    result = MQTT_hasUnackedPackets(pCtx);
    assert_int_equal(0, result);

    pWrapper->numElements = 1;
    result = MQTT_hasUnackedPackets(pCtx);
    assert_int_equal(1, result);

    pWrapper->numElements = 2;
    result = MQTT_hasUnackedPackets(pCtx);
    assert_int_equal(1, result);

    MOC_FREE((void **)&pWrapper);
    MOC_FREE((void **)&pCtx);
   
}

static void mqtt_test_MQTT_addPacketIdToList(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->pPacketIdList = NULL;
    status = MQTT_addPacketIdToList(pCtx, 1);
    assert_int_equal(OK, status);
    
    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    assert_non_null(pWrapper);
    assert_int_equal(1, pWrapper->numElements);
    assert_int_equal(1, pWrapper->pHead->packetId);
    assert_int_equal(1, pWrapper->pTail->packetId);

    status = MQTT_addPacketIdToList(pCtx, 2);
    assert_int_equal(OK, status);
    assert_int_equal(2, pWrapper->numElements);
    assert_int_equal(1, pWrapper->pHead->packetId);
    assert_int_equal(2, pWrapper->pTail->packetId);


    pCtx->pPacketIdList = (void *)pWrapper;
    status = MQTT_addPacketIdToList(pCtx, 3);
    assert_int_equal(OK, status);
    assert_int_equal(3, pWrapper->numElements);
    assert_int_equal(1, pWrapper->pHead->packetId);
    assert_int_equal(3, pWrapper->pTail->packetId);

    MQTT_freePacketIdList(pCtx);
    MOC_FREE((void **)&pCtx);
    
}

static void mqtt_test_MQTT_removePacketIdFromList(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->pPacketIdList = NULL;

    status = MQTT_addPacketIdToList(pCtx, 1);
    assert_int_equal(OK, status);
    status = MQTT_addPacketIdToList(pCtx, 2);
    assert_int_equal(OK, status);
    status = MQTT_addPacketIdToList(pCtx, 3);
    assert_int_equal(OK, status);

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    assert_non_null(pWrapper);
    assert_int_equal(3, pWrapper->numElements);
    assert_int_equal(1, pWrapper->pHead->packetId);
    assert_int_equal(3, pWrapper->pTail->packetId);

    status = MQTT_removePacketIdFromList(pCtx, 1);
    assert_int_equal(OK, status);
    assert_int_equal(2, pWrapper->numElements);
    assert_int_equal(2, pWrapper->pHead->packetId);
    assert_int_equal(3, pWrapper->pTail->packetId);

    status = MQTT_removePacketIdFromList(pCtx, 3); 
    assert_int_equal(OK, status);
    assert_int_equal(1, pWrapper->numElements);
    assert_int_equal(2, pWrapper->pHead->packetId);
    assert_int_equal(2, pWrapper->pTail->packetId);

    status = MQTT_removePacketIdFromList(pCtx, 22);
    assert_int_equal(OK, status);
    assert_int_equal(1, pWrapper->numElements);
    assert_int_equal(2, pWrapper->pHead->packetId);
    assert_int_equal(2, pWrapper->pTail->packetId);    

    MQTT_freePacketIdList(pCtx);
    MOC_FREE((void **)&pCtx);

}

static void mqtt_test_MQTT_checkPublishDeliveryAllowed(void **ppState)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    byteBoolean allowed = 0;

    MQTT_initCore(1);
    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));

    status = MQTT_checkPublishDeliveryAllowed(pCtx, 1, &allowed);
    assert_int_equal(OK, status);
    assert_int_equal(1, allowed);

    status = MQTT_checkPublishDeliveryAllowed(pCtx, 1, &allowed);
    assert_int_equal(OK, status);
    assert_int_equal(0, allowed);

    MQTT_uninitCore();
    MOC_FREE((void **)&pCtx);
    
}

static void mqtt_test_MQTT_closeConnectionInternal(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    MqttCtx *pCtx = NULL;

    MQTT_initCore(1);
    status = MQTT_createConnectInstanceFromId(5, "testClient1", 11, &connInst, 0);
    assert_int_equal(OK, status);
    assert_int_equal(0, connInst);

    status = MQTT_closeConnectionInternal(0);
    assert_int_equal(OK, status);

    MQTT_uninitCore();
}

static void mqtt_test_MQTT_packetIdExists(void **ppState)
{
    MSTATUS status;
    byteBoolean exists = 0;
    MqttCtx *pCtx = NULL;

    MQTT_initCore(1);

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));

    exists = MQTT_packetIdExists(pCtx, 1);
    assert_int_equal(FALSE, exists);

    MOC_FREE((void **)&pCtx);
    MQTT_uninitCore();
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
        cmocka_unit_test(mqtt_test_MQTT_initCoreandUninitcore),
        cmocka_unit_test(mqtt_test_MQTT_createConnectInstanceAndRelease),
        cmocka_unit_test(mqtt_test_MQTT_hasUnackedPackets),
        cmocka_unit_test(mqtt_test_MQTT_addPacketIdToList),
        cmocka_unit_test(mqtt_test_MQTT_removePacketIdFromList),
        cmocka_unit_test(mqtt_test_MQTT_checkPublishDeliveryAllowed),
        cmocka_unit_test(mqtt_test_MQTT_packetIdExists),
        cmocka_unit_test(mqtt_test_MQTT_closeConnectionInternal)
    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}