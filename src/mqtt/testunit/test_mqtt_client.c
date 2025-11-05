/*
 * test_mqtt_client.c
 *
 * MQTT Client Unit Test
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
#include "common/mtcp.h"
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
#include "../../ssl/ssl.h"
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
#include "../../mqtt/mqtt_client.h"
#include "../../mqtt/mqtt_client_priv.h"
#include "../../mqtt/mqtt_core.h"

static void mqtt_test_MQTT_init(void **ppState)
{
    MSTATUS status;

    status = MQTT_init(1);
    assert_int_equal(OK, status);

    status = MQTT_init(0);
    assert_int_equal(OK, status);

    status = MQTT_init(-1);
    assert_int_equal(ERR_MQTT_INVALID_MAX_CLIENT_CONN, status);

    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_shutdownStack(void **ppState)
{
    MSTATUS status;

    status = MQTT_shutdownStack();
    assert_int_equal(OK, status);

    MQTT_init(1);
    status = MQTT_shutdownStack();
    assert_int_equal(OK, status);
}

static void mqtt_test_MQTT_connect(void **ppState)
{
    sbyte4 connInst;
    MqttVersion version;

    version = 4;
    MQTT_init(2);
    connInst = MQTT_connect(version, "testClient", 10);
    assert_int_equal(0, connInst);

    version = 5;
    connInst = MQTT_connect(version, "testClient", 10);
    assert_int_equal(1, connInst);

    MQTT_closeConnection(0);
    MQTT_closeConnection(1);
    MQTT_shutdownStack(); 

}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
static void mqtt_test_MQTT_asyncConnect(void **ppState)
{
    sbyte4 connInst;
    MqttVersion version;

    version = 4;
    MQTT_init(2);
    connInst = MQTT_asyncConnect(version, "testClient", 10);
    assert_int_equal(0, connInst);

    version = 5;
    connInst = MQTT_asyncConnect(version, "testClient", 10);
    assert_int_equal(1, connInst);

    MQTT_closeConnection(0);
    MQTT_closeConnection(1);
    MQTT_shutdownStack(); 
}
#endif

static void mqtt_test_MQTT_setTransportTCP(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    TCP_SOCKET socket = 0;
    
    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setTransportTCP(0, socket);
    assert_int_equal(OK, status);

    socket = -1;
    status = MQTT_setTransportTCP(0, socket);
    assert_int_equal(ERR_MQTT_INVALID_TCP_SOCKET, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_setCookie(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    void *pCookie = NULL;
    
    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setCookie(0, pCookie);
    assert_int_equal(OK, status);

    pCookie = (void *)0x1;
    status = MQTT_setCookie(0, pCookie);
    assert_int_equal(OK, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_getCookie(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    void *pCookie = NULL;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setCookie(0, pCookie);
    assert_int_equal(OK, status);

    void *pGetCookie = NULL;
    status = MQTT_getCookie(0, &pGetCookie);
    assert_int_equal(OK, status);

    assert_int_equal(pCookie, pGetCookie);

    pCookie = (void *)0x1;
    status = MQTT_setCookie(0, pCookie);
    assert_int_equal(OK, status);

    status = MQTT_getCookie(0, &pGetCookie);
    assert_int_equal(OK, status);

    assert_int_equal(pCookie, pGetCookie);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_closeConnection(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_closeConnection(0);
    assert_int_equal(OK, status);

    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_setControlPacketHandlers(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    MqttPacketHandlers handlers = {0};

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setControlPacketHandlers(0, &handlers);
    assert_int_equal(OK, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_isConnectionEstablished(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    sbyte4 isConn;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    isConn = MQTT_isConnectionEstablished(0);
    assert_int_equal(0, isConn); 

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
static void mqtt_test_MQTT_getSendBuffer(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;

    MQTT_init(1);
    connInst = MQTT_asyncConnect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_getSendBuffer(0, pData, &dataLen);
    assert_int_equal(OK, status);

    pData = (ubyte *)0x1;
    status = MQTT_getSendBuffer(0, pData, &dataLen);
    assert_int_equal(OK, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_recvMessage(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    MqttCtx *pCtx = NULL;

    MQTT_init(1);
    connInst = MQTT_asyncConnect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    MQTT_getCtxFromConnInst(0, &pCtx);
    pCtx->maxPacketSize = 1024;

    status = MQTT_recvMessage(0, pData, dataLen);
    assert_int_equal(ERR_NULL_POINTER, status);

    ubyte buffer[11] = {0x20, 0x09, 0x00, 0x00, 0x06, 0x22, 0x00, 0x0a, 0x21, 0x00, 0x0a};
    pData = buffer;
    dataLen = 11;
    status = MQTT_recvMessage(0, pData, dataLen);
    assert_int_equal(OK, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}
#endif

static void mqtt_test_MQTT_transactionPending(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    sbyte4 isPending;

    MQTT_init(2);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    isPending = MQTT_transactionPending(0);
    assert_int_equal(0, isPending);
    
    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_readTimeout(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte4 timeout = 0;
    MqttCtx *pCtx = NULL;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    MQTT_getCtxFromConnInst(0, &pCtx);
    pCtx->connectionState = CONNECT_OPEN;
    pCtx->keepAliveMS = 1000;

    status = MQTT_readTimeout(0, &timeout);
    assert_int_equal(OK, status);

    timeout = 10;
    status = MQTT_readTimeout(0, &timeout);
    assert_int_equal(OK, status);
    assert_int_equal(pCtx->keepAliveMS, timeout);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_resetConnectionState(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    MqttCtx *pCtx = NULL;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_resetConnectionState(0);
    assert_int_equal(OK, status);

    MQTT_getCtxFromConnInst(0, &pCtx);
    assert_int_equal(CONNECT_NEGOTIATE, pCtx->connectionState);

  
    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_getClientIdFromConnInst(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte *pClientId = NULL;
    ubyte4 clientIdLen = 0;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_getClientIdFromConnInst(0, &pClientId, &clientIdLen);
    assert_int_equal(OK, status);

    assert_memory_equal("testClient", pClientId, clientIdLen);
    assert_int_equal(10, clientIdLen);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

#if defined( __MQTT_ENABLE_FILE_PERSIST__)
static void mqtt_test_MQTT_MQTT_setPersistMode(void **ppState)
{
    MSTATUS status;
    FilePersistArgs args = {0};
    sbyte4 connInst;
    MqttCtx *pCtx = NULL;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    args.mode = 1;
    args.pDir = "testDir";
    status = MQTT_setPersistMode(0, &args);
    assert_int_equal(OK, status);

    MQTT_getCtxFromConnInst(0, &pCtx);
    assert_int_equal(MQTT_PERSIST_MODE_FILE, pCtx->persistMode);
    assert_memory_equal("testDir", pCtx->pDir, 7);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}
#endif

static void mqtt_test_MQTT_setPublishTimeout(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte4 publishTimeout = 0;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setPublishTimeout(0, publishTimeout);
    assert_int_equal(OK, status);

    publishTimeout = 10;
    status = MQTT_setPublishTimeout(0, publishTimeout);
    assert_int_equal(OK, status);


    publishTimeout = 4294967;
    status = MQTT_setPublishTimeout(0, publishTimeout);
    assert_int_equal(OK, status);

    publishTimeout = 4294968;
    status = MQTT_setPublishTimeout(0, publishTimeout);
    assert_int_equal(ERR_INVALID_INPUT, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_setProtocolBufferSize(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    ubyte4 bufferSize = 0;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    status = MQTT_setProtocolBufferSize(0, bufferSize);
    assert_int_equal(OK, status);

    bufferSize = 10;
    status = MQTT_setProtocolBufferSize(0, bufferSize);
    assert_int_equal(OK, status);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_getConnackReasonString(void **ppState)
{
    MSTATUS status;
    sbyte4 connInst;
    sbyte *pReasonStr = NULL;
    MqttCtx *pCtx = NULL;

    MQTT_init(1);
    connInst = MQTT_connect(5, "testClient", 10);
    assert_int_equal(0, connInst);

    MQTT_getCtxFromConnInst(0, &pCtx);
    pCtx->version = 5;

    status = MQTT_getConnackReasonString(0, MQTT_CONNECT_UNSUPPORTED_PROTOCOL_VERSION_V5, &pReasonStr);
    assert_int_equal(OK, status);
    assert_memory_equal("Unsupported Protocol Version", pReasonStr, 26);

    status = MQTT_getConnackReasonString(0, -1, &pReasonStr);
    assert_int_equal(OK, status);
    assert_memory_equal("Unknown reason code", pReasonStr, 18);

    pCtx->version = 4;

    status = MQTT_getConnackReasonString(0, MQTT_CONNECT_SERVER_UNAVAILABLE_V3, &pReasonStr);
    assert_int_equal(OK, status);
    assert_memory_equal("Connection Refused, Server unavailable", pReasonStr, 36);

    status = MQTT_getConnackReasonString(0, 25, &pReasonStr);
    assert_int_equal(OK, status);
    assert_memory_equal("Unknown reason code", pReasonStr, 18);

    MQTT_closeConnection(0);
    MQTT_shutdownStack();

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
        cmocka_unit_test(mqtt_test_MQTT_init),
        cmocka_unit_test(mqtt_test_MQTT_shutdownStack),
        cmocka_unit_test(mqtt_test_MQTT_connect),
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        cmocka_unit_test(mqtt_test_MQTT_asyncConnect),
#endif
        cmocka_unit_test(mqtt_test_MQTT_setTransportTCP),
        cmocka_unit_test(mqtt_test_MQTT_setCookie),
        cmocka_unit_test(mqtt_test_MQTT_getCookie),
        cmocka_unit_test(mqtt_test_MQTT_closeConnection),
        cmocka_unit_test(mqtt_test_MQTT_setControlPacketHandlers),
        cmocka_unit_test(mqtt_test_MQTT_isConnectionEstablished),
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        cmocka_unit_test(mqtt_test_MQTT_getSendBuffer),
        cmocka_unit_test(mqtt_test_MQTT_recvMessage),
#endif
        cmocka_unit_test(mqtt_test_MQTT_transactionPending),
#if defined( __MQTT_ENABLE_FILE_PERSIST__)
        cmocka_unit_test(mqtt_test_MQTT_MQTT_setPersistMode),
#endif
        cmocka_unit_test(mqtt_test_MQTT_readTimeout),
        cmocka_unit_test(mqtt_test_MQTT_resetConnectionState),
        cmocka_unit_test(mqtt_test_MQTT_getClientIdFromConnInst),
        cmocka_unit_test(mqtt_test_MQTT_setPublishTimeout),
        cmocka_unit_test(mqtt_test_MQTT_setProtocolBufferSize),
        cmocka_unit_test(mqtt_test_MQTT_getConnackReasonString)
    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}