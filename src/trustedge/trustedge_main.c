/*
 * trustedge_main.c
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
 *
 */

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mfmgmt.h"
#include "../common/mjson.h"
#include "../common/debug_console.h"
#include "../common/build_info.h"
#include "../common/msg_logger.h"
#include "../common/arg_parser.h"
#include "../common/mtcp.h"
#include "../common/mtcp_async.h"
#include "../mqtt/mqtt_client.h"
#include "../http/http_context.h"
#include "../http/http.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix
 *
 * Issue: The header file mqtt_client.h includes merrors.h and redefines OK to
 * MOC_OK for ESP32 builds. The ssl.h header below includes a ESP32 toolchain
 * header file which also defines OK which then gets redefined to MOC_OK causing
 * compilation errors.
 *
 * Fix: Undefine OK before including ssl.h, then redefine it back to MOC_OK
 */
#undef OK
#endif
#include "../ssl/ssl.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#include "utils/trustedge_utils.h"
#include "utils/trustedge_tap.h"
#include "../common/common_utils.h"
#ifndef __DISABLE_TRUSTEDGE_REST_API__
#include <string.h>
#include "../common/hash_value.h"
#include "../trustedge/agent/trustedge_agent_priv.h"
#include "../trustedge/agent/trustedge_agent_protobuf.h"
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
#include "../est/est_cert_utils.h"
#include "../trustedge/est/trustedge_est_include.h"
#include "../http/http_common.h"
#include "../ssl/ssl.h"
#endif
#endif
#include "../trustedge/trustedge_main.h"
#include "../est/est_client_api.h"
#include "../common/msignal.h"

#ifdef __RTOS_ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(trustedge, LOG_LEVEL_DBG);
#endif

#ifdef __RTOS_LINUX__
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#endif

#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
#include <pthread.h>
#endif

/*----------------------------------------------------------------------------*/

#define TRUSTEDGE_PROG_NAME                     "trustedge"
#define RUN_DIR                                 "/run"
#define TRUSTEDGE_PID_FILE                      "/run/trustedge.pid"
#define TRUSTEDGE_LEGACY_PID_FILE               "/var/run/trustedge.pid"
#ifndef __DISABLE_TRUSTEDGE_REST_API__
#define ENROLL_API_ENDPOINT                     "/v1/certificate/enroll"
#define KEYGEN_API_ENDPOINT                     "/v1/key/asymmetric"
#define SERVICE_API_ENDPOINT                    "/v1/service"
#define REPORTED_ATTR_API_ENDPOINT              "/v1/agent/attributes/reported"
#define DESIRED_ATTR_API_ENDPOINT               "/v1/agent/attributes/desired"
#define NOTIFICATION_SUBSCRIBE_API_ENDPOINT     "/v1/resources/subscribe"
#define NOTIFICATION_UNSUBSCRIBE_API_ENDPOINT   "/v1/resources/unsubscribe"
#define LIST_RESOURCES_API_ENDPOINT             "/v1/resources/list?pid="
#define LIST_UPDATED_RESOURCES_API_ENDPOINT     "/v1/resources/list_updated?pid="
#define ACK_RESOURCES_API_ENDPOINT              "/v1/resources/ack?pid="
#define MAX_HTTP_CLIENT_SESSIONS                (10)
#endif

#define MAX_MQTT_CLIENT_CONNECTIONS             (1)
#define MAX_SSL_SERVER_CONNECTIONS              (1)
#define MAX_SSL_CLIENT_CONNECTIONS              (10)

static sbyte *enrollMode = NULL;
RTOS_MUTEX gCertMutex = NULL;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
TrustEdgeRestApiCtx gRestApiCtx = {0};
static certStorePtr pCertStore = NULL;
static const ubyte* http_protocol[] = { "trustedge_secret", "http/1.1" };
#endif

/*----------------------------------------------------------------------------*/

typedef enum ServiceType {
    TRUSTEDGE_AGENT,
    TRUSTEDGE_CERTIFICATE
} ServiceType;

/*----------------------------------------------------------------------------*/

int MQTT_EXAMPLE_main(int argc, char *ppArgv[], TrustEdgeConfig **ppConfig);
int TRUSTEDGE_agentMain(int argc, char *ppArgv[], int isService, TrustEdgeConfig **ppConfig);
MSTATUS TRUSTEDGE_agentMainReset(void);
int TRUSTEDGE_certificateMain(int argc, char *ppArgv[], sbyte *pEnrollMode, E_TEAgentMode operatingMode, TrustEdgeConfig **ppConfig);

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
static void TRUSTEDGE_displayHelp(
    char *pProg)
{
    DB_PRINT("Usage: %s <command> [<args>]\n", pProg);
    DB_PRINT("\n");
    DB_PRINT("TrustEdge command line tool\n");
    DB_PRINT("\n");
    DB_PRINT("Options:\n");
    DB_PRINT("  --help          Display global usage information\n");
    DB_PRINT("  --version       Display TrustEdge version\n");
    DB_PRINT("  --daemon        Run TrustEdge agent in daemon mode\n");
    DB_PRINT("                  Arguments are read from trustedge configuration file\n");
    DB_PRINT("\n");
    DB_PRINT("Commands:\n");
    DB_PRINT("  agent             Agent mode - connected to Device Trust Manager\n");
    DB_PRINT("  mqtt              MQTT client for pub/sub\n");
    DB_PRINT("  certificate       Certificate mode\n");
    DB_PRINT("  certificate scep  SCEP mode\n");
    DB_PRINT("  certificate est   EST mode\n");
    DB_PRINT("\n");
    DB_PRINT("For more information on a specific command, use:\n");
    DB_PRINT("  %s <command> --help\n", pProg);
}

/*----------------------------------------------------------------------------*/

static void TRUSTEDGE_displayVersion(void)
{
    BUILD_INFO_print();
}
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ */

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_TRUSTEDGE_REST_API__
typedef enum
{
    HTTP_INVALID,
    HTTP_GET,
    HTTP_POST
} E_HttpMethod;

typedef enum
{
    INVALID_REQUEST,
    KEYGEN_REQUEST,
    ENROLL_REQUEST,
    SUBSCRIBE_REQUEST,
    UNSUBSCRIBE_REQUEST,
    LIST_RESOURCES_REQUEST,
    LIST_UPDATED_RESOURCES_REQUEST,
    ACK_RESOURCES_REQUEST,
    REPORTED_ATTR_REQUEST,
    DESIRED_ATTR_REQUEST,
    SERVICE_CONF_REQUEST
} E_HttpRequest;

typedef enum
{
    CONTENT_TYPE_INVALID,
    CONTENT_TYPE_JSON
} E_HttpContentType;

typedef struct _HttpHeaderInfo
{
    E_HttpMethod method;
    E_HttpRequest request;
    byteBoolean contentData;
    E_HttpContentType contentType;
    ubyte4 contentLen;
    sbyte *pUnprocessedContent;
    sbyte4 unprocessedContentLen;
} HttpHeaderInfo;

intBoolean gNeedToDie = FALSE;
#endif /* !defined(__DISABLE_TRUSTEDGE_REST_API__) */

volatile int gShutdownClient = 0;
volatile int gIsProcessInterrupted = 0;

void TRUSTEDGE_signalHandler(int dummy) {
    MOC_UNUSED(dummy);
    gShutdownClient = 1;
    gIsProcessInterrupted = 1;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    gNeedToDie = TRUE;
#endif
}

byteBoolean TRUSTEDGE_isServiceRunning()
{
    if (TRUE == FMGMT_pathExists((const sbyte *) TRUSTEDGE_PID_FILE, NULL))
    {
        return TRUE;
    }

    if (TRUE == FMGMT_pathExists((const sbyte *) TRUSTEDGE_LEGACY_PID_FILE, NULL))
    {
        return TRUE;
    }
    return FALSE;
}

typedef struct TrustEdgeThreadArgs {
    enum ServiceType type;
    int argc;
    char **ppArgv;
    ubyte4 threadType;
    TrustEdgeConfig *pConfig;
} TrustEdgeThreadArgs;

/*----------------------------------------------------------------------------*/

void TRUSTEDGE_threadStart(void *pArg)
{
    TrustEdgeThreadArgs *pStruct = (TrustEdgeThreadArgs *)pArg;

    switch(pStruct->type)
    {
        case TRUSTEDGE_AGENT:
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Launching agent thread\n");
            (void) TRUSTEDGE_agentMain(pStruct->argc - 1, (&pStruct->ppArgv[1]), 1, &(pStruct->pConfig));
            break;
        case TRUSTEDGE_CERTIFICATE:
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Launching certificate thread\n");
            (void) TRUSTEDGE_certificateMain(pStruct->argc - 1, (&pStruct->ppArgv[1]), enrollMode, TE_AGENT_DAEMON_MODE, &(pStruct->pConfig));
            break;
    };
}

#ifndef __DISABLE_TRUSTEDGE_REST_API__
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
static sbyte4 TRUSTEDGE_setALPNCallback(sbyte4 connectionInstance,
                                    ubyte** out[],
                                    sbyte4* outlen,
                                    ubyte* in,
                                    sbyte4 inlen)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(in);
    MOC_UNUSED(inlen);

    MSTATUS status = OK;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s::%s\n", "TRUSTEDGE_setALPNCallback", http_protocol[1]);

    *outlen = 2;
    *out = (ubyte **)http_protocol;

    return status;
}

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
/* This function can be extended to do additional
 * certificate handling by the application */
static MSTATUS TRUSTEDGE_getCertAndStatusCallback(sbyte4 connectionInstance,
                                                    struct certChain* pCertChain,
                                                    MSTATUS validationstatus)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pCertChain);

    return validationstatus;
}

#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */

#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
static MSTATUS TRUSTEDGE_invalidCertCallback(sbyte4 connectionInstance, MSTATUS status)
{
    MOC_UNUSED(connectionInstance);
    MSTATUS newStatus = OK;

    MSG_LOG_print(MSG_LOG_INFO, "TRUSTEDGE_invalidCertCallback; status = %d\n", status);
    MSG_LOG_print(MSG_LOG_INFO, "TRUSTEDGE_invalidCertCallback; resetting status to %d\n", newStatus);

    return newStatus;
}
#endif /* __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__ */

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
static sbyte4
TRUSTEDGE_rehandshakeAlert(sbyte4 connectionInstance)
{
    SSL_initiateRehandshake(connectionInstance);
    return 0;
}
#endif

static sbyte4 TRUSTEDGE_httpSslSend(httpContext *pHttpContext, sbyte4 socket,
    ubyte *pDataToSend, ubyte4 numBytesToSend,
    ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);

    MSG_LOG_print(MSG_LOG_VERBOSE, "TRUSTEDGE_httpSslSend::pDataToSend: %p\n", pDataToSend);
    MSG_LOG_print(MSG_LOG_VERBOSE, "TRUSTEDGE_httpSslSend::numBytesToSend: %d\n", numBytesToSend);

    sbyte4 sslConnectionInst = SSL_getInstanceFromSocket(socket);
    *pRetNumBytesSent = SSL_send(sslConnectionInst, (sbyte  *)pDataToSend, numBytesToSend);
    return OK;
}

static sbyte4 TRUSTEDGE_httpResponseBodyCallback(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, sbyte4 isContinueFromBlock)
{
    MSTATUS status = OK;
    sbyte *pContentLengthStr = NULL;
	MOC_UNUSED(isContinueFromBlock);

    /* the index for ContentLength */
    ubyte4 index = NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS + ContentLength;

    /* if contentlength known, allocate memory only once */
    if (pHttpContext->receivedPendingDataLength <= 0 &&
            pHttpContext->responseBitmask[index/8] & (1<<(index & 7)))
    {
        sbyte *pStop;
        sbyte4 contentLength;
        HTTP_stringDescr *pStrDescr = &(pHttpContext->responses[index]);


        if (NULL == (pContentLengthStr = MALLOC(pStrDescr->httpStringLength+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        status = DIGI_MEMCPY(pContentLengthStr, pStrDescr->pHttpString, pStrDescr->httpStringLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        (pContentLengthStr)[pStrDescr->httpStringLength] = '\0';
        contentLength = DIGI_ATOL((sbyte*)pContentLengthStr, (const sbyte**)&pStop);
        FREE(pContentLengthStr);
        pContentLengthStr = NULL;
        if (pHttpContext->pReceivedPendingDataFree)
        {
            FREE(pHttpContext->pReceivedPendingDataFree);
        }
        pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = (ubyte*) MALLOC(contentLength);
    }

    /* accumulate response body in httpContext pReceivedDataPending */
    if (!(pHttpContext->responseBitmask[index/8] & (1<<(index & 7))))
    {
        ubyte *pNewBuffer = (ubyte*)MALLOC(pHttpContext->receivedPendingDataLength+dataLength);
        if (pHttpContext->receivedPendingDataLength > 0)
        {
            /* copy existing data */
            status = DIGI_MEMCPY(pNewBuffer, pHttpContext->pReceivedPendingDataFree, pHttpContext->receivedPendingDataLength);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "DIGI_MEMCPY failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        status = DIGI_MEMCPY(pNewBuffer+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        if (pHttpContext->pReceivedPendingDataFree)
        {
            FREE(pHttpContext->pReceivedPendingDataFree);
        }
        pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = pNewBuffer;
    } else
    {
        status = DIGI_MEMCPY(pHttpContext->pReceivedPendingDataFree+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
    pHttpContext->receivedPendingDataLength += dataLength;

exit:
    if (NULL != pContentLengthStr)
    {
        FREE(pContentLengthStr);
    }
    return status;
}

static sbyte4 TRUSTEDGE_httpResponseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);
    return OK;
}
#endif /* !__DISABLE_TRUSTEDGE_HTTPS_REST_API__ */

static MSTATUS
TRUSTEDGE_restApiResourceAlloc(
    void *pHashCookie,
    hashTablePtrElement **ppNewElement)
{
    MSTATUS status;
    MOC_UNUSED(pHashCookie);

    status = DIGI_CALLOC((void **)ppNewElement, 1, sizeof(hashTablePtrElement));

    DEBUG_RELABEL_MEMORY(*ppNewElement);

    return status;
}

static MSTATUS
TRUSTEDGE_restApiPidFree(
    void *pHashCookie,
    hashTablePtrElement *pDeleteElement)
{
    ubyte2 i;
    TrustEdgePidCtx *pPidCtx = (TrustEdgePidCtx *)pDeleteElement->pAppData;
    MOC_UNUSED(pHashCookie);

    for (i = 0; i < pPidCtx->numPids; i++)
    {
        DIGI_FREE((void **) &pPidCtx->pPidVal[i]);
    }

    DIGI_FREE((void **) &pPidCtx->pPidVal);
    DIGI_FREE((void **) &pPidCtx);
    return DIGI_FREE((void **)(&pDeleteElement));
}

static MSTATUS
TRUSTEDGE_restApiResourceFree(
    void *pHashCookie,
    hashTablePtrElement *pDeleteElement)
{
    ubyte2 i;
    TrustEdgeResourceCtx *pResCtx = (TrustEdgeResourceCtx *)pDeleteElement->pAppData;
    MOC_UNUSED(pHashCookie);

    for (i = 0; i < pResCtx->numResources; i++)
    {
        DIGI_FREE((void **) &pResCtx->resourceCtx[i].pResourcePath);
    }

    DIGI_FREE((void **) &pResCtx->resourceCtx);
    DIGI_FREE((void **) &pResCtx);
    return DIGI_FREE((void **)(&pDeleteElement));
}

static MSTATUS
TRUSTEDGE_hashTableInsert(hashTableOfPtrs *pHashTable, void *pKey, ubyte4 keyLen, void *pAppData)
{
    MSTATUS status = OK;
    ubyte4 hashValue;

    if ((NULL == pHashTable) || (NULL == pKey) || (NULL == pAppData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    HASH_VALUE_hashGen(pKey, keyLen, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

    status = HASH_TABLE_addPtr(pHashTable, hashValue, pAppData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "HASH_TABLE_addPtr failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS
TRUSTEDGE_restApiProcessSubscribeRequest(TrustEdgeRestApiCtx *pResCtx, JSON_ContextType *pJCtx, ubyte2 maxProcess, ubyte2 maxResourcePerProcess)
{
    MSTATUS status = OK;
    sbyte *pPid = NULL;
    ubyte4 ndx, i;
    ubyte2 j;
    JSON_TokenType token = {0}, objToken = {0};
    ubyte4 hashValue;
    intBoolean foundPidKey = FALSE, foundResKey = FALSE;
    intBoolean createdResCtx = FALSE;
    TrustEdgeResourceCtx *pFoundResCtx;
    TrustEdgePidCtx *pFoundPidCtx;
    ubyte *pResPath = NULL;
    byteBoolean duplicateResource, duplicatePid;
    TrustEdgeResourceCtx *pTmpResCtx = NULL;
    TrustEdgePidCtx *pTmpPidCtx = NULL;

    if ((NULL == pJCtx) || (NULL == pResCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "pid", &pPid, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "pid field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    HASH_VALUE_hashGen(pPid, DIGI_STRLEN(pPid) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

    status = HASH_TABLE_findPtr(pResCtx->pHashTablePidKey, hashValue, NULL, NULL, (void **)&pFoundResCtx, &foundPidKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "HASH_TABLE_findPtr failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (FALSE == foundPidKey)
    {
        if (maxProcess == pResCtx->numProcesses)
        {
            status = ERR_TRUSTEDGE_AGENT_TOPIC_SUBSCRIBE;
            MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "TRUSTEDGE_restApiProcessSubscribeRequest::process max limit exceeded, ignoring the request.");
            goto exit;
        }
    }
    else
    {
        pTmpResCtx = pFoundResCtx;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "resources", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "resources field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        duplicatePid = FALSE;
        duplicateResource = FALSE;
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &objToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (NULL != pResPath)
        {
            (void) DIGI_FREE((void **) &pResPath);
            pResPath = NULL;
        }

        status = DIGI_MALLOC_MEMCPY((void **)&pResPath, objToken.len + 1, (void *)objToken.pStart, objToken.len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pResPath[objToken.len] = '\0';

        if (TRUE == foundPidKey || TRUE == createdResCtx)
        {
            for (j = 0; j < pTmpResCtx->numResources; j++)
            {
                if (0 == DIGI_STRCMP((const sbyte *)pTmpResCtx->resourceCtx[j].pResourcePath, pResPath))
                {
                    duplicateResource = TRUE;
                    continue;
                }
            }
        }
        else
        {
            status = DIGI_CALLOC((void **)&pTmpResCtx, 1, sizeof(TrustEdgeResourceCtx));
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "DIGI_CALLOC failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pResCtx->numProcesses += 1;
            createdResCtx = TRUE;
        }

        if (FALSE == duplicateResource)
        {
            if (maxResourcePerProcess == pTmpResCtx->numResources)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "%s\n", "TRUSTEDGE_restApiProcessSubscribeRequest::resources list exceeds maximum allowed resources, some resources are ignored.");
                break;
            }

            if (0 == pTmpResCtx->numResources)
            {
                status = DIGI_CALLOC((void **)&pTmpResCtx->resourceCtx, maxResourcePerProcess, sizeof(TrustEdgeResource));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_CALLOC failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }

            status = DIGI_MALLOC_MEMCPY((void **)&pTmpResCtx->resourceCtx[pTmpResCtx->numResources].pResourcePath, objToken.len + 1, (void *)objToken.pStart, objToken.len);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pTmpResCtx->resourceCtx[pTmpResCtx->numResources].pResourcePath[objToken.len] = '\0';
            pTmpResCtx->numResources += 1;

            HASH_VALUE_hashGen(pResPath, DIGI_STRLEN(pResPath) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

            status = HASH_TABLE_findPtr(pResCtx->pHashTableResourceKey, hashValue, NULL, NULL, (void **)&pFoundPidCtx, &foundResKey);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "HASH_TABLE_findPtr failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (TRUE == foundResKey)
            {
                pTmpPidCtx = pFoundPidCtx;
                for (j = 0; j < pTmpPidCtx->numPids; j++)
                {
                    if (0 == DIGI_STRCMP((const sbyte *)pTmpPidCtx->pPidVal[j], pPid))
                    {
                        duplicatePid = TRUE;
                        continue;
                    }
                }
            }
            else
            {
                status = DIGI_CALLOC((void **)&pTmpPidCtx, 1, sizeof(TrustEdgePidCtx));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MALLOC failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }

            if (FALSE == duplicatePid)
            {
                if (0 == pTmpPidCtx->numPids)
                {
                    status = DIGI_CALLOC((void **)&pTmpPidCtx->pPidVal, maxProcess, sizeof(ubyte*));
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_CALLOC failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }

                status = DIGI_MALLOC_MEMCPY((void **)&pTmpPidCtx->pPidVal[pTmpPidCtx->numPids], DIGI_STRLEN(pPid) + 1, pPid, DIGI_STRLEN(pPid));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                pTmpPidCtx->pPidVal[pTmpPidCtx->numPids][DIGI_STRLEN(pPid)] = '\0';
                pTmpPidCtx->numPids += 1;

                if (FALSE == foundResKey)
                {
                    status = TRUSTEDGE_hashTableInsert(pResCtx->pHashTableResourceKey, pResPath, objToken.len + 1, pTmpPidCtx);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "TRUSTEDGE_hashTableInsert failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_WARNING, "TRUSTEDGE_restApiProcessSubscribeRequest::ignoring duplicate resource: %s, with pid: %s\n", pResPath, pPid);
        }
    }

    if (FALSE == foundPidKey)
    {
        status = TRUSTEDGE_hashTableInsert(pResCtx->pHashTablePidKey, pPid, DIGI_STRLEN(pPid) + 1, pTmpResCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "TRUSTEDGE_hashTableInsert failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

exit:
    if (NULL != pPid)
    {
        (void) DIGI_FREE((void **) &pPid);
        pPid = NULL;
    }
    if (NULL != pResPath)
    {
        (void) DIGI_FREE((void **) &pResPath);
        pResPath = NULL;
    }

    return status;
}

static MSTATUS
TRUSTEDGE_restApiProcessAckUnsubscribeRequest(TrustEdgeRestApiCtx *pResCtx, JSON_ContextType *pJCtx, E_HttpRequest requestType)
{
    MSTATUS status = OK;
    sbyte *pPid = NULL, *pResPath = NULL;
    ubyte4 hashValuePid, hashValueRes;
    TrustEdgeResourceCtx *pFoundResCtx, *pTmpResCtx;
    TrustEdgePidCtx *pFoundPidCtx, *pTmpPidCtx;
    intBoolean foundPidKey = FALSE, foundResKey;
    byteBoolean foundRes;
    ubyte4 ndx, i;
    ubyte2 j, k;
    JSON_TokenType token = {0}, objToken = {0};

    if ((NULL == pJCtx) || (NULL == pResCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (UNSUBSCRIBE_REQUEST == requestType)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "pid", &pPid, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "pid field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (ACK_RESOURCES_REQUEST == requestType)
    {
        status = DIGI_MALLOC_MEMCPY((void **)&pPid, DIGI_STRLEN(pResCtx->pPid) + 1, pResCtx->pPid, DIGI_STRLEN(pResCtx->pPid));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pPid[DIGI_STRLEN(pResCtx->pPid)] = '\0';
    }

    HASH_VALUE_hashGen(pPid, DIGI_STRLEN(pPid) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValuePid);

    status = HASH_TABLE_findPtr(pResCtx->pHashTablePidKey, hashValuePid, NULL, NULL, (void **)&pFoundResCtx, &foundPidKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "HASH_TABLE_findPtr failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (FALSE == foundPidKey)
    {
        status = ERR_NOT_FOUND;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Requetsed pid needs to subscribe first, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "resources", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "resources field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        foundRes = FALSE;
        foundResKey = FALSE;
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &objToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (NULL != pResPath)
        {
            (void) DIGI_FREE((void **) &pResPath);
            pResPath = NULL;
        }

        status = DIGI_MALLOC_MEMCPY((void **)&pResPath, objToken.len + 1, (void *)objToken.pStart, objToken.len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pResPath[objToken.len] = '\0';

        for (j = 0; j < pFoundResCtx->numResources; j++)
        {
            if (0 == DIGI_STRCMP((const sbyte *)pFoundResCtx->resourceCtx[j].pResourcePath, pResPath))
            {
                if (UNSUBSCRIBE_REQUEST == requestType)
                {
                    (void) DIGI_FREE((void **)&pFoundResCtx->resourceCtx[j].pResourcePath);
                    for (k = j; k < pFoundResCtx->numResources - 1; k++)
                    {
                        pFoundResCtx->resourceCtx[k] = pFoundResCtx->resourceCtx[k + 1];
                    }

                    pFoundResCtx->numResources -= 1;
                    foundRes = TRUE;
                }
                else if (ACK_RESOURCES_REQUEST == requestType)
                {
                    pFoundResCtx->resourceCtx[j].isUpdated = FALSE;
                    pFoundResCtx->numUpdatedResources -= 1;
                }

                break;
            }
        }

        if (TRUE == foundRes)
        {
            HASH_VALUE_hashGen(pResPath, DIGI_STRLEN(pResPath) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValueRes);

            status = HASH_TABLE_findPtr(pResCtx->pHashTableResourceKey, hashValueRes, NULL, NULL, (void **)&pFoundPidCtx, &foundResKey);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "HASH_TABLE_findPtr failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            for (j = 0; j < pFoundPidCtx->numPids; j++)
            {
                if (0 == DIGI_STRCMP((const sbyte *)pFoundPidCtx->pPidVal[j], pPid))
                {
                    (void) DIGI_FREE((void **)&pFoundPidCtx->pPidVal[j]);
                    for (k = j; k < pFoundPidCtx->numPids - 1; k++)
                    {
                        pFoundPidCtx->pPidVal[k] = pFoundPidCtx->pPidVal[k + 1];
                    }

                    pFoundPidCtx->numPids -= 1;
                    break;
                }
            }

            if (0 == pFoundPidCtx->numPids)
            {
                (void) DIGI_FREE((void **)&pFoundPidCtx->pPidVal);
                pFoundPidCtx->pPidVal = NULL;

                status = HASH_TABLE_deletePtr(pResCtx->pHashTableResourceKey, hashValueRes, NULL, NULL, (void **)&pTmpPidCtx, &foundResKey);
                if ((OK != status) || (FALSE == foundResKey))
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "HASH_TABLE_deletePtr failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
        }
        else
        {
            status = ERR_NOT_FOUND;
            MSG_LOG_print(MSG_LOG_WARNING, "TRUSTEDGE_restApiProcessAckUnsubscribeRequest::resource not found in subscribe list: %s\n", pResPath);
        }
    }

    if ((UNSUBSCRIBE_REQUEST == requestType) && (0 == pFoundResCtx->numResources))
    {
        (void) DIGI_FREE((void **)&pFoundResCtx->resourceCtx);
        pFoundResCtx->resourceCtx = NULL;

        status = HASH_TABLE_deletePtr(pResCtx->pHashTablePidKey, hashValuePid, NULL, NULL, (void **)&pTmpResCtx, &foundPidKey);
        if ((OK != status) || (FALSE == foundPidKey))
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "HASH_TABLE_deletePtr failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pResCtx->numProcesses -= 1;
    }

exit:
    if (NULL != pPid)
    {
        (void) DIGI_FREE((void **) &pPid);
        pPid = NULL;
    }
    if (NULL != pResPath)
    {
        (void) DIGI_FREE((void **) &pResPath);
        pResPath = NULL;
    }

    return status;
}

static MSTATUS
TRUSTEDGE_restApiFetchDesiredAttributes(TrustEdgeConfig *pConfig)
{
    MSTATUS status = OK;
    TrustEdgeAgentCtx *pAgentCtx = NULL;

    if (NULL == pConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pAgentCtx, 1, sizeof(TrustEdgeAgentCtx));
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_DESIRED_ATTRIBUTE_FILE,
        &pAgentCtx->pDesiredAttributeFile);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pAgentCtx->pDesiredAttributeFile, NULL))
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "Reading desired attributes from %s\n", pAgentCtx->pDesiredAttributeFile);

        status = HASH_TABLE_createPtrsTable(
            &pAgentCtx->pDesiredAttributes, METRIC_HASH_TABLE_SIZE, NULL,
            TRUSTEDGE_agentMetricAlloc, TRUSTEDGE_agentMetricFree);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "HASH_TABLE_createPtrsTable failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        /* Add desired attributes from file */
        status = TRUSTEDGE_agentProtobufLoadMetricFile(
             pAgentCtx, TE_DESIRED_ATTRIBUTES_FILE);
        if (OK != status)
        {
            goto exit;
        }

        gRestApiCtx.pHashTableDesiredAttrs = pAgentCtx->pDesiredAttributes;
        pAgentCtx->pDesiredAttributes = NULL;
    }
    else
    {
        status = ERR_FILE_NOT_EXIST;
    }

exit:
    if (NULL != pAgentCtx)
    {
        TRUSTEDGE_agentContextRelease((TrustEdgeAgentContext **)&pAgentCtx);
    }
    return status;
}

static MSTATUS
TRUSTEDGE_processHttpHeader(TrustEdgeRestApiCtx *pResCtx, sbyte *pHttpHeader, sbyte4 httpHeaderLen, HttpHeaderInfo *pInfo, TrustEdgeThreadArgs *pStruct)
{
    MSTATUS status = OK;
    sbyte *pToken, *pReq, *pTmpToken;
    sbyte url[64] = {0};
    sbyte conType[64] = {0};
    sbyte conLen[8] = {0};
    ubyte i;
    sbyte *pLeft, *pRight;

    if ((NULL == pResCtx) || (NULL == pHttpHeader) || (NULL == pInfo) || (NULL == pStruct))
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "NULL pointer exception, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    pInfo->contentData = FALSE;

    if (NULL != (pToken = (sbyte *) strstr((const char *)pHttpHeader, (const char *)"GET")))
    {
        pInfo->method = HTTP_GET;
    }
    else if (NULL != (pToken = (sbyte *) strstr((const char *)pHttpHeader, (const char *)"POST")))
    {
        pInfo->method = HTTP_POST;
    }
    else
    {
        status = ERR_HTTP;
        pInfo->method = HTTP_INVALID;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Invalid HTTP method, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    /* Get the request type */
    pReq = DIGI_STRCHR((sbyte *)pToken, ' ', DIGI_STRLEN(pToken));
    if (pReq == NULL)
    {
        status = ERR_HTTP;
        goto exit;
    }
    while (DIGI_ISSPACE(*pReq)) pReq++;
    i = 0;
    while ((i < sizeof(url) - 1) && !DIGI_ISSPACE(pReq[i]))
    {
        url[i] = pReq[i];
        i++;
    }
    url[i] = '\0';

    if (0 == DIGI_STRCMP(KEYGEN_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = KEYGEN_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRCMP(ENROLL_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = ENROLL_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRCMP(NOTIFICATION_SUBSCRIBE_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = SUBSCRIBE_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRCMP(NOTIFICATION_UNSUBSCRIBE_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = UNSUBSCRIBE_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRNCMP(LIST_RESOURCES_API_ENDPOINT, (sbyte *)url, DIGI_STRLEN(LIST_RESOURCES_API_ENDPOINT)))
    {
        pInfo->request = LIST_RESOURCES_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRNCMP(LIST_UPDATED_RESOURCES_API_ENDPOINT, (sbyte *)url, DIGI_STRLEN(LIST_UPDATED_RESOURCES_API_ENDPOINT)))
    {
        pInfo->request = LIST_UPDATED_RESOURCES_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRNCMP(ACK_RESOURCES_API_ENDPOINT, (sbyte *)url, DIGI_STRLEN(ACK_RESOURCES_API_ENDPOINT)))
    {
        pInfo->request = ACK_RESOURCES_REQUEST;
        pStruct->type = TRUSTEDGE_CERTIFICATE;
    }
    else if (0 == DIGI_STRCMP(REPORTED_ATTR_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = REPORTED_ATTR_REQUEST;
        pStruct->type = TRUSTEDGE_AGENT;
    }
    else if (0 == DIGI_STRCMP(DESIRED_ATTR_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = DESIRED_ATTR_REQUEST;
        pStruct->type = TRUSTEDGE_AGENT;
    }
    else if (0 == DIGI_STRCMP(SERVICE_API_ENDPOINT, (sbyte *)url))
    {
        pInfo->request = SERVICE_CONF_REQUEST;
        pStruct->type = TRUSTEDGE_AGENT;
    }
    else
    {
        status = ERR_HTTP;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Invalid Rest API endpoint, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((ACK_RESOURCES_REQUEST == pInfo->request) || (LIST_RESOURCES_REQUEST == pInfo->request) || (LIST_UPDATED_RESOURCES_REQUEST == pInfo->request))
    {
        pLeft = DIGI_STRCHR(url, '{', DIGI_STRLEN(url));
        if (NULL == pLeft)
        {
            status = ERR_URI_INVALID_FORMAT;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Invalid rest api uri format, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pRight = DIGI_STRCHR(url, '}', DIGI_STRLEN(url));
        if (NULL == pRight)
        {
            status = ERR_URI_INVALID_FORMAT;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Invalid rest api uri format, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY((void **)&pResCtx->pPid, pRight - pLeft, pLeft + 1, pRight - pLeft - 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pResCtx->pPid[pRight - pLeft - 1] = '\0';
    }

    if ((HTTP_GET == pInfo->method) && (SERVICE_CONF_REQUEST != pInfo->request) && (DESIRED_ATTR_REQUEST != pInfo->request) &&
        (LIST_RESOURCES_REQUEST != pInfo->request) && (LIST_UPDATED_RESOURCES_REQUEST != pInfo->request))
    {
        status = ERR_HTTP;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Invalid http method provided with api endpoint, use POST. status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((HTTP_POST == pInfo->method) && (ENROLL_REQUEST != pInfo->request) && (KEYGEN_REQUEST != pInfo->request) &&
        (REPORTED_ATTR_REQUEST != pInfo->request) && (SUBSCRIBE_REQUEST != pInfo->request) && (UNSUBSCRIBE_REQUEST != pInfo->request) &&
        (ACK_RESOURCES_REQUEST != pInfo->request))
    {
        status = ERR_HTTP;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Invalid http method provided with api endpoint, use GET. status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((ENROLL_REQUEST == pInfo->request) || (KEYGEN_REQUEST == pInfo->request) || (SUBSCRIBE_REQUEST == pInfo->request) ||
        (UNSUBSCRIBE_REQUEST == pInfo->request) || (ACK_RESOURCES_REQUEST == pInfo->request) || (REPORTED_ATTR_REQUEST == pInfo->request))
    {
        pInfo->contentData = TRUE;
    }

    if (TRUE == pInfo->contentData)
    {
        if(NULL == (pToken = (sbyte *)strstr((const char *)pToken, (const char *)"Content-Type:")))
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Content-Type header missing in HTTP request, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        pToken += DIGI_STRLEN((sbyte *)"Content-Type:");
        while (DIGI_ISSPACE(*pToken)) pToken++;
        i = 0;
        while ((i < sizeof(conType) - 1) && (pToken[i] != '\r' && pToken[i] != '\n'))
        {
            conType[i] = pToken[i];
            i++;
        }
        conType[i] = '\0';

        if(0 == DIGI_STRCMP((const char *)conType, "application/json"))
        {
            pInfo->contentType = CONTENT_TYPE_JSON;
        }
        else
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            pInfo->contentType = CONTENT_TYPE_INVALID;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Invalid content type in HTTP request, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if( (NULL == (pTmpToken = (sbyte *)strstr((const char *)pToken, (const char *)"Content-Length:"))) &&
            (NULL == (pTmpToken = (sbyte *)strstr((const char *)pToken, (const char *)"content-length:"))) )
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Content-Length header missing in HTTP request, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        else
        {
            pToken = pTmpToken;
        }

        pToken += DIGI_STRLEN((sbyte *)"Content-Length:");
        while (DIGI_ISSPACE(*pToken)) pToken++;
        i=0;
        while ((i < sizeof(conLen) - 1) && (pToken[i] != '\r' && pToken[i] != '\n'))
        {
            conLen[i] = pToken[i];
            i++;
        }
        conLen[i] = '\0';
        pInfo->contentLen = (ubyte4)DIGI_ATOL((const sbyte *)conLen, NULL);

        if(!pInfo->contentLen)
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Invalid content length in HTTP request, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if(NULL == (pToken = (sbyte *)strstr((const char *)pToken, (const char *)"\r\n\r\n")))
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "Malformed HTTP request, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        pToken += 4;

        pInfo->pUnprocessedContent = pToken;
        pInfo->unprocessedContentLen = httpHeaderLen - (pToken - pHttpHeader);
    }

exit:
    return status;
}

#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
MSTATUS TRUSTEDGE_setupTLSConnection(TrustEdgeConfig *pConfig, void *pClientSocket, sbyte *pKeystorePath, sbyte *pServerKeyCert, sbyte4 *pConnectionInstance)
{
    MSTATUS  status = OK;
    TCP_SOCKET clientSocket;
    certDescriptor certDesc = {0};
    SizedBuffer certificate;
    sbyte *pFullPath = NULL;
    sbyte *pKeyCertPath = NULL;
    sbyte *pFile = NULL;
    ubyte4 length = 0;
    MOC_UNUSED(pConfig);

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
    SSL_sslSettings()->maxByteCount = 1024*1024*10;
    SSL_sslSettings()->maxTimerCountForRehandShake = 60*60*1000;
    SSL_sslSettings()->funcPtrClientRehandshakeRequest = TRUSTEDGE_rehandshakeAlert;
#endif

    if (OK > (status = HTTP_initClient(MAX_HTTP_CLIENT_SESSIONS)))
        goto exit;

    HTTP_httpSettings()->funcPtrHttpTcpSend = TRUSTEDGE_httpSslSend;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = TRUSTEDGE_httpResponseBodyCallback;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = TRUSTEDGE_httpResponseHeaderCallback;

    DIGI_MEMSET((ubyte *)&certDesc, 0x00, sizeof(SizedBuffer));

    status = DIGI_MALLOC_MEMCPY((void **)&pFile, DIGI_STRLEN(pServerKeyCert) + 5, pServerKeyCert, DIGI_STRLEN(pServerKeyCert));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = DIGI_MEMCPY(pFile + DIGI_STRLEN(pServerKeyCert), ESTC_EXT_PEM, 4);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "DIGI_MEMCPY failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    pFile[DIGI_STRLEN(pServerKeyCert) + 4] = '\0';

    pKeyCertPath = EST_CERT_UTIL_buildKeyStoreFullPath(pKeystorePath, CERTS_PKI_COMPONENT);
    status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath(pKeyCertPath, pFile, (char **)&pFullPath),
                    &certDesc.pCertificate, &certDesc.certLength);
    if (OK != status)
    {
        /* if signal interrupted read, exit without error */
        if (0 == gShutdownClient)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "Unable to read server certificate: %s, status = %s (%d)\n",
                pFullPath, MERROR_lookUpErrorCode(status), status);
        }
        else
        {
            status = OK;
        }

        goto exit;
    }

    if(NULL != pKeyCertPath)
    {
        DIGI_FREE((void **)&pKeyCertPath);
        pKeyCertPath = NULL;
    }
    if(NULL != pFullPath)
    {
        DIGI_FREE((void **)&pFullPath);
        pFullPath = NULL;
    }

    pKeyCertPath = EST_CERT_UTIL_buildKeyStoreFullPath(pKeystorePath, KEYS_PKI_COMPONENT);
    status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath(pKeyCertPath, pFile, (char **)&pFullPath),
                    &certDesc.pKeyBlob, &certDesc.keyBlobLength);
    if (OK != status)
    {
        /* if signal interrupted read, exit without error */
        if (0 == gShutdownClient)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "Unable to read server key: %s, status = %s (%d)\n",
                pFullPath, MERROR_lookUpErrorCode(status), status);
        }
        else
        {
            status = OK;
        }

        goto exit;
    }

    AsymmetricKey asymKey = {0};

    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Unable to initialize asymmetric key, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        certDesc.pKeyBlob, certDesc.keyBlobLength, NULL,
        &asymKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Unable to deserialize server key, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    DIGI_FREE((void**)&certDesc.pKeyBlob);
    status = KEYBLOB_makeKeyBlobEx(&asymKey, &certDesc.pKeyBlob, &certDesc.keyBlobLength);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Unable to make server key keyblob, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(certDesc.pCertificate, certDesc.certLength,
                            &certificate.data, &length);
    certificate.length = length;
    DIGI_FREE((void**)&certDesc.pCertificate);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Unable to decode server cert, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    certDesc.pCertificate = certificate.data;

    if (OK > (status = CERT_STORE_createStore(&pCertStore)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "CERT_STORE_createStore failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (NULL != certificate.data)
    {
        if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(
            pCertStore, &certificate, 1, certDesc.pKeyBlob, certDesc.keyBlobLength)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "CERT_STORE_addIdentityWithCertificateChain failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    clientSocket = (TCP_SOCKET)((uintptr)pClientSocket);

    if (0 > (*pConnectionInstance = SSL_acceptConnection(clientSocket, pCertStore)))
    {
        /* if signal interrupted read, exit without error */
        if (0 == gShutdownClient)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "SSL_acceptConnection failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
        }
        else
        {
            status = OK;
        }

        goto exit;
    }

#ifndef __DISABLE_DIGICERT_ALPN_CALLBACK__
    if (OK > SSL_setAlpnCallback(*pConnectionInstance, TRUSTEDGE_setALPNCallback))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "SSL_setAlpnCallback failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        SSL_closeConnection(*pConnectionInstance);
        goto exit;
    }
#endif

#ifndef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (OK > SSL_setSessionFlags(*pConnectionInstance, SSL_FLAG_NO_MUTUAL_AUTH_REQUEST))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "SSL_setSessionFlags failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        SSL_closeConnection(*pConnectionInstance);
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
    if(OK > SSL_setCertAndStatusCallback(*pConnectionInstance,
            TRUSTEDGE_getCertAndStatusCallback))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "SSL_setCertAndStatusCallback failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    status = SSL_setSessionFlags(*pConnectionInstance, SSL_FLAG_REQUIRE_MUTUAL_AUTH);
#endif

#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
    if (OK > SSL_setInvalidCertCallback(*pConnectionInstance,
                TRUSTEDGE_invalidCertCallback))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "SSL_setInvalidCertCallback failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
    }
#endif

#if defined(__ENABLE_DIGICERT_PQC__)
    if (TRUE == pConfig->requirePQC)
    {
        status = SSL_enforcePQCAlgorithm(*pConnectionInstance);
        if (OK > status)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed to set PQC algorithms\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
#endif

    if (0 > (status = SSL_negotiateConnection(*pConnectionInstance)))
    {
        /* if signal interrupted read, exit without error */
        if (0 == gShutdownClient)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "SSL_negotiateConnection failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
        }
        else
        {
            status = OK;
        }

        (void) SSL_closeConnection(*pConnectionInstance);
        *pConnectionInstance = -1;
        goto exit;
    }

exit:
    CERT_STORE_releaseStore(&pCertStore);

    if(NULL != pKeyCertPath)
    {
        DIGI_FREE((void **)&pKeyCertPath);
        pKeyCertPath = NULL;
    }
    if(NULL != pFullPath)
    {
        DIGI_FREE((void **)&pFullPath);
        pFullPath = NULL;
    }
    if(NULL != pFile)
    {
        DIGI_FREE((void **)&pFile);
        pFullPath = NULL;
    }
    if (NULL != certDesc.pCertificate)
    {
        DIGI_FREE((void **)&certDesc.pCertificate);
        certDesc.pCertificate = 0;
    }
    if (NULL != certDesc.pKeyBlob)
    {
        DIGI_FREE((void **)&certDesc.pKeyBlob);
        certDesc.pKeyBlob = 0;
    }

    return status;
}
#endif /* !__DISABLE_TRUSTEDGE_HTTPS_REST_API__ */

static void TRUSTEDGE_threadStartRestAPI(void *pArg)
{
    MSTATUS status = OK, tmpStatus = OK;
    TCP_SOCKET listenSocket = -1;
    TCP_SOCKET clientSocket = -1;
    intBoolean listenSocketClose = FALSE;
    intBoolean clientSocketClose = FALSE;
    HttpHeaderInfo headerInfo;
    sbyte *pHttpPayload = NULL;
    ubyte4 received, nRet;
    sbyte4 found;
    TrustEdgeThreadArgs *pStruct = (TrustEdgeThreadArgs *)pArg;
    TrustEdgeConfig *pConfig = NULL;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pMode = NULL;
    sbyte *pSuccessMsg = "HTTP/1.1 200\r\nServer: TrustEdge Agent\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"status\":\"SUCCESS\"}\n";
    sbyte *pFailedMsg =  "HTTP/1.1 400\r\nServer: TrustEdge Agent\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"status\":\"FAILED\"}\n";
    sbyte *pFinalSuccessMsg = NULL;
    sbyte *pResList = NULL;
    TrustEdgeResourceCtx *pFoundResCtx = NULL;
    sbyte pIpAddr[40] = {0};
    sbyte *pServerFQDN = DEFAULT_SERVER_FQDN;
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
    sbyte *pKeystorePath = NULL;
    sbyte *pServerKeyCert = NULL;
    sbyte4 connectionInstance = 0;
    byteBoolean isHttps = FALSE;
    sbyte4 isPending = 0;
#endif

    MSG_LOG_print(MSG_LOG_INFO, "%s", "Launching agent rest api thread\n");
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
    if (0 == DIGI_STRNICMP("https", pStruct->pConfig->pRequestType, DIGI_STRLEN("https")))
    {
        isHttps = TRUE;
    }

    if (TRUE == isHttps)
    {
        pServerFQDN = pStruct->pConfig->pServerFQDN;
    }
#endif
    status = TRUSTEDGE_utilsGetHostByName(pServerFQDN, pIpAddr);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "TRUSTEDGE_utilsGetHostByName failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "If running locally, make sure dns mapping entry is present in /etc/hosts file.");
        goto outerExit;
    }

    status = TCP_LISTEN_SOCKET_ADDR(&listenSocket, pIpAddr, pStruct->pConfig->port);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "TCP_LISTEN_SOCKET_ADDR failed, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto outerExit;
    }

    listenSocketClose = TRUE;
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
    if (TRUE == isHttps)
    {
        MSG_LOG_print(MSG_LOG_INFO, "HTTPS server listening on [https://%s:%d]\n", pServerFQDN, pStruct->pConfig->port);
        MSG_LOG_print(MSG_LOG_INFO, "Certificate & Key alias for TLS auth: %s\n", pStruct->pConfig->pServerKeyCert);
    }
    else
#endif
    {
        MSG_LOG_print(MSG_LOG_INFO, "HTTP server listening on [http://localhost:%d]\n", pStruct->pConfig->port);
    }

    status = HASH_TABLE_createPtrsTable(
        &gRestApiCtx.pHashTablePidKey, TRUSTEDGE_REST_API_HASH_TABLE_SIZE(pStruct->pConfig->numProcess * pStruct->pConfig->numResource), NULL,
        TRUSTEDGE_restApiResourceAlloc, TRUSTEDGE_restApiResourceFree);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Hash table creation failed\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto outerExit;
    }

    status = HASH_TABLE_createPtrsTable(
        &gRestApiCtx.pHashTableResourceKey, TRUSTEDGE_REST_API_HASH_TABLE_SIZE(pStruct->pConfig->numProcess * pStruct->pConfig->numResource), NULL,
        TRUSTEDGE_restApiResourceAlloc, TRUSTEDGE_restApiPidFree);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Hash table creation failed\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto outerExit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "Max processes allowed to subscribe: %d\n", pStruct->pConfig->numProcess);
    MSG_LOG_print(MSG_LOG_VERBOSE, "Max resources allowed per process: %d\n", pStruct->pConfig->numResource);

    do
    {
        status = OK;
        found = FALSE;
        received = 0;
        nRet = 0;
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
        pKeystorePath = NULL;
        pServerKeyCert = NULL;
        isPending = 0;
        connectionInstance = 0;
#endif

        status = DIGI_MEMSET((void *)&headerInfo, 0, sizeof(headerInfo));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MEMSET failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = TCP_ACCEPT_SOCKET(&clientSocket, listenSocket, &gNeedToDie);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "TCP_ACCEPT_SOCKET failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        clientSocketClose = TRUE;

#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
        if (TRUE == isHttps)
        {
            status = DIGI_MALLOC_MEMCPY((void **)&pKeystorePath, DIGI_STRLEN(pStruct->pConfig->pKeystoreDir) + 1, pStruct->pConfig->pKeystoreDir, DIGI_STRLEN(pStruct->pConfig->pKeystoreDir));
            if (OK != status)
            {
                goto exit;
            }

            pKeystorePath[DIGI_STRLEN(pStruct->pConfig->pKeystoreDir)] = '\0';

            status = DIGI_MALLOC_MEMCPY((void **)&pServerKeyCert, DIGI_STRLEN(pStruct->pConfig->pServerKeyCert) + 1, pStruct->pConfig->pServerKeyCert, DIGI_STRLEN(pStruct->pConfig->pServerKeyCert));
            if (OK != status)
            {
                goto exit;
            }

            pServerKeyCert[DIGI_STRLEN(pStruct->pConfig->pServerKeyCert)] = '\0';

            status = TRUSTEDGE_setupTLSConnection(pConfig, (void *)((usize)clientSocket), pKeystorePath, pServerKeyCert, &connectionInstance);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "TRUSTEDGE_setupTLSConnection failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#endif

        status = DIGI_CALLOC((void **) &pHttpPayload, 8192 + 1, sizeof(sbyte));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_CALLOC failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        while (!found)
        {
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
            if (TRUE == isHttps)
            {
                status = SSL_recv(connectionInstance, pHttpPayload + received, 1024 - received, &nRet, 0);
            }
            else
#endif
            {
                status = TCP_READ_AVL(
                    clientSocket, pHttpPayload + received, 1024 - received, &nRet,
                    TCP_NO_TIMEOUT);
            }

            if (0 > status)
            {
                /* if signal interrupted read, exit without error */
                if (0 == gShutdownClient)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "TCP_READ_AVL failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                }
                else
                {
                    status = OK;
                }
                goto exit;
            }

            received += nRet;
            pHttpPayload[received] = 0;
            found = (NULL != strstr((const char *) pHttpPayload, "\r\n\r\n"));
        }

#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
        if (TRUE == isHttps)
        {
            (void) SSL_recvPending(connectionInstance, &isPending);
            MSG_LOG_print(MSG_LOG_VERBOSE, "SSL_recv::bytes pending=%s\n", isPending ? "TRUE" : "FALSE");
        }
#endif
        /* Parse the HTTP header to determine what the request is */
        status = TRUSTEDGE_processHttpHeader(&gRestApiCtx, pHttpPayload, received, &headerInfo, pStruct);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "TRUSTEDGE_processHttpHeader failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = DIGI_MALLOC((void **)&gRestApiCtx.pJsonBuf, headerInfo.contentLen + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MALLOC failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = DIGI_MEMSET((ubyte *)gRestApiCtx.pJsonBuf, 0x0, headerInfo.contentLen + 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "DIGI_MEMSET failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        received = 0;
        if (0 != headerInfo.unprocessedContentLen)
        {
            status = DIGI_MEMCPY(
                gRestApiCtx.pJsonBuf, headerInfo.pUnprocessedContent,
                headerInfo.unprocessedContentLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "DIGI_MEMCPY failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            received = headerInfo.unprocessedContentLen;
        }

        while (received < headerInfo.contentLen)
        {
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
            if (TRUE == isHttps)
            {
                status = SSL_recv(connectionInstance, gRestApiCtx.pJsonBuf + received, headerInfo.contentLen - received,
                    &nRet, 0);
            }
            else
#endif
            {
                status = TCP_READ_AVL(
                    clientSocket, gRestApiCtx.pJsonBuf + received, headerInfo.contentLen - received, &nRet,
                    TCP_NO_TIMEOUT);
            }
            if (0 > status)
            {
                /* if signal interrupted read, exit without error */
                if (0 == gShutdownClient)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "TCP_READ_AVL failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                }
                else
                {
                    status = OK;
                }
                goto exit;
            }
            received += nRet;
            gRestApiCtx.pJsonBuf[received] = 0;
        }

        switch(pStruct->type)
        {
            case TRUSTEDGE_CERTIFICATE:
                if ((LIST_RESOURCES_REQUEST == headerInfo.request) || (LIST_UPDATED_RESOURCES_REQUEST == headerInfo.request))
                {
                    break;
                }

                status = JSON_acquireContext(&pJCtx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "JSON_acquireContext failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = JSON_parse(pJCtx, gRestApiCtx.pJsonBuf, DIGI_STRLEN(gRestApiCtx.pJsonBuf), &numTokens);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "JSON_parse failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (SUBSCRIBE_REQUEST == headerInfo.request)
                {
                    status = TRUSTEDGE_restApiProcessSubscribeRequest(&gRestApiCtx, pJCtx, pStruct->pConfig->numProcess, pStruct->pConfig->numResource);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "TRUSTEDGE_restApiProcessSubscribeRequest failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    break;
                }
                else if ((UNSUBSCRIBE_REQUEST == headerInfo.request) || (ACK_RESOURCES_REQUEST == headerInfo.request))
                {
                    status = TRUSTEDGE_restApiProcessAckUnsubscribeRequest(&gRestApiCtx, pJCtx, headerInfo.request);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "TRUSTEDGE_restApiProcessAckUnsubscribeRequest failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    break;
                }
                else if (KEYGEN_REQUEST == headerInfo.request)
                {
                    enrollMode = NULL;
                    status = JSON_getJsonStringValue(
                        pJCtx, 0, "outputMode", &gRestApiCtx.pOutputMode, TRUE);
                    if (OK != status)
                    {
                        DIGI_MALLOC_MEMCPY((void **)&gRestApiCtx.pOutputMode, 9, "file", 8);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "DIGI_MALLOC_MEMCPY failed, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        gRestApiCtx.pOutputMode[8] = '\0';
                    }
                    else
                    {
                        if ((0 != DIGI_STRCMP(gRestApiCtx.pOutputMode, "file")) && (0 != DIGI_STRCMP(gRestApiCtx.pOutputMode, "FILE")) &&
                            (0 != DIGI_STRCMP(gRestApiCtx.pOutputMode, "buffered")) && (0 != DIGI_STRCMP(gRestApiCtx.pOutputMode, "BUFFERED")))
                            {
                                status = ERR_INVALID_INPUT;
                                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                                    "outputMode field invalid in request json: %s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                    }
                }
                else if (ENROLL_REQUEST == headerInfo.request)
                {
                    status = JSON_getJsonStringValue(
                        pJCtx, 0, "protocol", &pMode, TRUE);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "protocol field missing in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    if ((0 == DIGI_STRCMP(pMode, "EST")) || (0 == DIGI_STRCMP(pMode, "est")))
                    {
                        enrollMode = EST_JSTR;
                    }
                    else if ((0 == DIGI_STRCMP(pMode, "SCEP")) || (0 == DIGI_STRCMP(pMode, "scep")))
                    {
                        enrollMode = SCEP_JSTR;
                    }
                    else
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "Invalid protocol field in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = TRUSTEDGE_utilsCloneConfig(pStruct->pConfig, &pConfig);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "TRUSTEDGE_utilsCloneConfig failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = TRUSTEDGE_certificateMain(pStruct->argc - 1, (&pStruct->ppArgv[1]), enrollMode, TE_AGENT_REST_API_MODE, &(pStruct->pConfig));
                pStruct->pConfig = pConfig;
                pConfig = NULL;
                break;

            case TRUSTEDGE_AGENT:
                if (DESIRED_ATTR_REQUEST == headerInfo.request)
                {
                    status = TRUSTEDGE_restApiFetchDesiredAttributes(pStruct->pConfig);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "TRUSTEDGE_restApiFetchDesiredAttributes failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
                else if (REPORTED_ATTR_REQUEST == headerInfo.request)
                {
                    /* TODO */
                }

                break;

            default:
                status = ERR_INVALID_ARG;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Invalid failed, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
        }

        if (OK == status)
        {
            if ((KEYGEN_REQUEST == headerInfo.request) && ((0 == DIGI_STRCMP(gRestApiCtx.pOutputMode, "buffered")) || (0 == DIGI_STRCMP(gRestApiCtx.pOutputMode, "BUFFERED"))))
            {
                sbyte *pTmpSuccessMsg1 = "HTTP/1.1 200\r\nServer: TrustEdge Agent\r\nContent-Type: application/json\r\nContent-Length: ";
                sbyte *pTmpSuccessMsg2 = "\r\n\r\n";
                sbyte *pTmpSuccessMsg3 = "{\"status\":\"SUCCESS\",\n\"key\": \"\n";
                sbyte *pTmpSuccessMsg4 = "\"}\n";
                ubyte contentLenDigits = 0;
                ubyte4 contentLen = DIGI_STRLEN(pTmpSuccessMsg3) + gRestApiCtx.privLen + DIGI_STRLEN(pTmpSuccessMsg4);
                ubyte4 totalLen = DIGI_STRLEN(pTmpSuccessMsg1) + DIGI_STRLEN(pTmpSuccessMsg2) + contentLen;
                ubyte4 tmpLen = contentLen;

                while (0 != tmpLen)
                {
                    contentLenDigits++;
                    tmpLen /= 10;
                }

                totalLen += contentLenDigits;

                status = DIGI_MALLOC((void **) &pFinalSuccessMsg, totalLen + 1);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MALLOC failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg, pTmpSuccessMsg1, DIGI_STRLEN(pTmpSuccessMsg1));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (NULL == DIGI_LTOA(contentLen, pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1), contentLenDigits))
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "Error converting Content-Length to string, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits, pTmpSuccessMsg2, DIGI_STRLEN(pTmpSuccessMsg2));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2), pTmpSuccessMsg3, DIGI_STRLEN(pTmpSuccessMsg3));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3),
                                    gRestApiCtx.pKeyBuf, gRestApiCtx.privLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + gRestApiCtx.privLen,
                                    pTmpSuccessMsg4, DIGI_STRLEN(pTmpSuccessMsg4));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                pFinalSuccessMsg[DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + gRestApiCtx.privLen + DIGI_STRLEN(pTmpSuccessMsg4)] = '\0';
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
                if (TRUE == isHttps)
                {
                    SSL_send(connectionInstance, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg));
                }
                else
#endif
                {
                    TCP_WRITE(
                        clientSocket, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg), &nRet);
                }
            }
            else if ((LIST_RESOURCES_REQUEST == headerInfo.request) || (LIST_UPDATED_RESOURCES_REQUEST == headerInfo.request))
            {
                sbyte *pTmpSuccessMsg1 = "HTTP/1.1 200\r\nServer: TrustEdge Agent\r\nContent-Type: application/json\r\nContent-Length: ";
                sbyte *pTmpSuccessMsg2 = "\r\n\r\n";
                sbyte *pTmpSuccessMsg3 = "{\"status\":\"SUCCESS\",\n\"resources\": [\n";
                sbyte *pTmpSuccessMsg4 = "\n]\n}\n";
                ubyte contentLenDigits = 0;
                ubyte4 contentLen = DIGI_STRLEN(pTmpSuccessMsg3) + DIGI_STRLEN(pTmpSuccessMsg4);
                ubyte4 resLen = 0, totalLen = 0;
                ubyte4 tmpLen;
                intBoolean foundPidKey = FALSE;
                ubyte4 hashValue;
                sbyte *pRes;
                ubyte2 i, j;

                HASH_VALUE_hashGen(gRestApiCtx.pPid, DIGI_STRLEN(gRestApiCtx.pPid) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

                status = HASH_TABLE_findPtr(gRestApiCtx.pHashTablePidKey, hashValue, NULL, NULL, (void **)&pFoundResCtx, &foundPidKey);

                if (FALSE == foundPidKey)
                {
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
                    if (TRUE == isHttps)
                    {
                        SSL_send(connectionInstance, pFailedMsg, DIGI_STRLEN((sbyte *)pFailedMsg));
                    }
                    else
#endif
                    {
                        TCP_WRITE(
                            clientSocket, pFailedMsg, DIGI_STRLEN((sbyte *)pFailedMsg), &nRet);
                    }
                }
                else
                {
                    for (i = 0; i < pFoundResCtx->numResources; i++)
                    {
                        if (LIST_UPDATED_RESOURCES_REQUEST == headerInfo.request)
                        {
                            if (TRUE == pFoundResCtx->resourceCtx[i].isUpdated)
                            {
                                resLen += DIGI_STRLEN(pFoundResCtx->resourceCtx[i].pResourcePath) + 4;
                            }
                        }
                        else
                        {
                            resLen += DIGI_STRLEN(pFoundResCtx->resourceCtx[i].pResourcePath) + 4;
                        }
                    }

                    if (0 != resLen)
                    {
                        resLen -= 2;
                    }

                    contentLen += resLen;

                    if (0 != resLen)
                    {
                        status = DIGI_MALLOC((void **)&pResList, resLen + 1);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "DIGI_MALLOC failed, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        resLen = 0;
                        j = 0;
                        for (i = 0; i < pFoundResCtx->numResources; i++)
                        {
                            if (LIST_UPDATED_RESOURCES_REQUEST == headerInfo.request)
                            {
                                if (TRUE == pFoundResCtx->resourceCtx[i].isUpdated)
                                {
                                    j += 1;
                                    pRes = pFoundResCtx->resourceCtx[i].pResourcePath;
                                    pResList[resLen] = '"';
                                    resLen += 1;

                                    status = DIGI_MEMCPY(pResList + resLen, pRes, DIGI_STRLEN(pRes));
                                    if (OK != status)
                                    {
                                        MSG_LOG_print(MSG_LOG_ERROR,
                                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                                            MERROR_lookUpErrorCode(status), status);
                                        goto exit;
                                    }

                                    resLen += DIGI_STRLEN(pRes);
                                    pResList[resLen] = '"';
                                    resLen += 1;

                                    if ((pFoundResCtx->numUpdatedResources > 1) && (j != (pFoundResCtx->numUpdatedResources)))
                                    {
                                        status = DIGI_MEMCPY(pResList + resLen, ",\n", 2);
                                        if (OK != status)
                                        {
                                            MSG_LOG_print(MSG_LOG_ERROR,
                                                "DIGI_MEMCPY failed, status = %s (%d)\n",
                                                MERROR_lookUpErrorCode(status), status);
                                            goto exit;
                                        }

                                        resLen += 2;
                                    }
                                }
                            }
                            else
                            {
                                pRes = pFoundResCtx->resourceCtx[i].pResourcePath;
                                pResList[resLen] = '"';
                                resLen += 1;

                                status = DIGI_MEMCPY(pResList + resLen, pRes, DIGI_STRLEN(pRes));
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                                        MERROR_lookUpErrorCode(status), status);
                                    goto exit;
                                }

                                resLen += DIGI_STRLEN(pRes);
                                pResList[resLen] = '"';
                                resLen += 1;

                                if (i != pFoundResCtx->numResources - 1)
                                {
                                    status = DIGI_MEMCPY(pResList + resLen, ",\n", 2);
                                    if (OK != status)
                                    {
                                        MSG_LOG_print(MSG_LOG_ERROR,
                                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                                            MERROR_lookUpErrorCode(status), status);
                                        goto exit;
                                    }

                                    resLen += 2;
                                }
                            }
                        }

                        pResList[resLen] = '\0';
                    }

                    tmpLen = contentLen;
                    while (0 != tmpLen)
                    {
                        contentLenDigits++;
                        tmpLen /= 10;
                    }

                    totalLen = DIGI_STRLEN(pTmpSuccessMsg1) + DIGI_STRLEN(pTmpSuccessMsg2) + contentLen + contentLenDigits;

                    status = DIGI_MALLOC((void **) &pFinalSuccessMsg, totalLen + 1);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MALLOC failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGI_MEMCPY(pFinalSuccessMsg, pTmpSuccessMsg1, DIGI_STRLEN(pTmpSuccessMsg1));
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    if (NULL == DIGI_LTOA(contentLen, pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1), contentLenDigits))
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "Error converting Content-Length to string, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits, pTmpSuccessMsg2, DIGI_STRLEN(pTmpSuccessMsg2));
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2), pTmpSuccessMsg3, DIGI_STRLEN(pTmpSuccessMsg3));
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    if (0 != resLen)
                    {
                        status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3),
                                            pResList, resLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "DIGI_MEMCPY failed, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                    }

                    status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + resLen,
                                        pTmpSuccessMsg4, DIGI_STRLEN(pTmpSuccessMsg4));
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    pFinalSuccessMsg[DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + resLen + DIGI_STRLEN(pTmpSuccessMsg4)] = '\0';
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
                    if (TRUE == isHttps)
                    {
                        SSL_send(connectionInstance, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg));
                    }
                    else
#endif
                    {
                        TCP_WRITE(
                            clientSocket, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg), &nRet);
                    }
                }
            }
            else if (DESIRED_ATTR_REQUEST == headerInfo.request)
            {
                sbyte *pTmpSuccessMsg1 = "HTTP/1.1 200\r\nServer: TrustEdge Agent\r\nContent-Type: application/json\r\nContent-Length: ";
                sbyte *pTmpSuccessMsg2 = "\r\n\r\n";
                sbyte *pTmpSuccessMsg3 = "{\"status\":\"SUCCESS\",\n\"attributes\": {\n";
                sbyte *pTmpSuccessMsg4 = "\n}\n}\n";
                ubyte contentLenDigits = 0;
                ubyte4 contentLen = DIGI_STRLEN(pTmpSuccessMsg3) + DIGI_STRLEN(pTmpSuccessMsg4);
                ubyte4 attrsLen = 0, totalLen = 0;
                ubyte4 tmpLen, attrsCount = 0;
                TrustEdgeAgentMetric *pMetric;
                void *pBucketCookie = NULL;
                ubyte4 index = 0;

                while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(gRestApiCtx.pHashTableDesiredAttrs, &pBucketCookie, &index)))
                {
                    attrsLen += DIGI_STRLEN(pMetric->pName) + DIGI_STRLEN(pMetric->pValue) + 7;
                    attrsCount++;
                }

                if (0 != attrsCount)
                {
                    attrsLen -= 2;
                }

                contentLen += attrsLen;

                if (0 != attrsCount)
                {
                    status = DIGI_MALLOC((void **)&pResList, attrsLen + 1);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MALLOC failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    attrsLen = 0;
                    pBucketCookie = NULL;
                    index = 0;
                    while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(gRestApiCtx.pHashTableDesiredAttrs, &pBucketCookie, &index)))
                    {
                        attrsCount--;
                        pResList[attrsLen++] = '"';
                        status = DIGI_MEMCPY(pResList + attrsLen, pMetric->pName, DIGI_STRLEN(pMetric->pName));
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "DIGI_MEMCPY failed, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        attrsLen += DIGI_STRLEN(pMetric->pName);
                        pResList[attrsLen++] = '"';
                        pResList[attrsLen++] = ':';
                        pResList[attrsLen++] = '"';
                        status = DIGI_MEMCPY(pResList + attrsLen, pMetric->pValue, DIGI_STRLEN(pMetric->pValue));
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "DIGI_MEMCPY failed, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        attrsLen += DIGI_STRLEN(pMetric->pValue);
                        pResList[attrsLen++] = '"';

                        if (0 != attrsCount)
                        {
                            pResList[attrsLen++] = ',';
                            pResList[attrsLen++] = '\n';
                        }
                    }

                    pResList[attrsLen] = '\0';
                }

                tmpLen = contentLen;
                while (0 != tmpLen)
                {
                    contentLenDigits++;
                    tmpLen /= 10;
                }

                totalLen = DIGI_STRLEN(pTmpSuccessMsg1) + DIGI_STRLEN(pTmpSuccessMsg2) + contentLen + contentLenDigits;

                status = DIGI_MALLOC((void **) &pFinalSuccessMsg, totalLen + 1);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MALLOC failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg, pTmpSuccessMsg1, DIGI_STRLEN(pTmpSuccessMsg1));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (NULL == DIGI_LTOA(contentLen, pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1), contentLenDigits))
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "Error converting Content-Length to string, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits, pTmpSuccessMsg2, DIGI_STRLEN(pTmpSuccessMsg2));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2), pTmpSuccessMsg3, DIGI_STRLEN(pTmpSuccessMsg3));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (0 != attrsLen)
                {
                    status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3),
                                        pResList, attrsLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "DIGI_MEMCPY failed, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }

                status = DIGI_MEMCPY(pFinalSuccessMsg + DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + attrsLen,
                                    pTmpSuccessMsg4, DIGI_STRLEN(pTmpSuccessMsg4));
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "DIGI_MEMCPY failed, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                pFinalSuccessMsg[DIGI_STRLEN(pTmpSuccessMsg1) + contentLenDigits + DIGI_STRLEN(pTmpSuccessMsg2) + DIGI_STRLEN(pTmpSuccessMsg3) + attrsLen + DIGI_STRLEN(pTmpSuccessMsg4)] = '\0';
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
                if (TRUE == isHttps)
                {
                    SSL_send(connectionInstance, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg));
                }
                else
#endif
                {
                    TCP_WRITE(
                        clientSocket, pFinalSuccessMsg, DIGI_STRLEN((sbyte *)pFinalSuccessMsg), &nRet);
                }
            }
            else
            {
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
                if (TRUE == isHttps)
                {
                    SSL_send(connectionInstance, pSuccessMsg, DIGI_STRLEN((sbyte *)pSuccessMsg));
                }
                else
#endif
                {
                    TCP_WRITE(
                        clientSocket, pSuccessMsg, DIGI_STRLEN((sbyte *)pSuccessMsg), &nRet);
                }
            }
        }

    exit:
        if (OK != status)
        {
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
            if (TRUE == isHttps)
            {
                SSL_send(connectionInstance, pFailedMsg, DIGI_STRLEN((sbyte *)pFailedMsg));
            }
            else
#endif
            {
                TCP_WRITE(
                    clientSocket, pFailedMsg, DIGI_STRLEN((sbyte *)pFailedMsg), &nRet);
            }
        }
        if (NULL != pHttpPayload)
        {
            DIGI_FREE((void **) &pHttpPayload);
            pHttpPayload = NULL;
        }
        if (NULL != gRestApiCtx.pJsonBuf)
        {
            DIGI_FREE((void **) &gRestApiCtx.pJsonBuf);
            gRestApiCtx.pJsonBuf = NULL;
        }
        if (TRUE == clientSocketClose)
        {
            (void) TCP_CLOSE_SOCKET(clientSocket);
        }
        if (NULL != pJCtx)
        {
            JSON_releaseContext(&pJCtx);
            pJCtx = NULL;
        }
        if (NULL != pMode)
        {
            DIGI_FREE((void **) &pMode);
            pMode = NULL;
        }
        if (NULL != gRestApiCtx.pOutputMode)
        {
            DIGI_FREE((void **) &gRestApiCtx.pOutputMode);
            gRestApiCtx.pOutputMode = NULL;
        }
        if (NULL != gRestApiCtx.pKeyBuf)
        {
            DIGI_FREE((void **) &gRestApiCtx.pKeyBuf);
            gRestApiCtx.pKeyBuf = NULL;
        }
        if (NULL != gRestApiCtx.pPid)
        {
            DIGI_FREE((void **) &gRestApiCtx.pPid);
            gRestApiCtx.pPid = NULL;
        }
        if (NULL != gRestApiCtx.pHashTableDesiredAttrs)
        {
            HASH_TABLE_removePtrsTable(gRestApiCtx.pHashTableDesiredAttrs, NULL);
            gRestApiCtx.pHashTableDesiredAttrs = NULL;
        }
        if (NULL != pFinalSuccessMsg)
        {
            DIGI_FREE((void **) &pFinalSuccessMsg);
            pFinalSuccessMsg = NULL;
        }
        if (NULL != pResList)
        {
            DIGI_FREE((void **) &pResList);
            pResList = NULL;
        }
        if (NULL != pKeystorePath)
        {
            (void) DIGI_FREE((void **)&pKeystorePath);
            pKeystorePath = NULL;
        }
        if (NULL != pServerKeyCert)
        {
            (void) DIGI_FREE((void **)&pServerKeyCert);
            pServerKeyCert = NULL;
        }
        if (0 < connectionInstance)
        {
            (void) SSL_closeConnection(connectionInstance);
        }
    } while (0 == gIsProcessInterrupted);

outerExit:
    if (TRUE == listenSocketClose)
    {
        (void) TCP_CLOSE_SOCKET(listenSocket);
    }
    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
        pConfig = NULL;
    }
    if (NULL != pStruct->pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pStruct->pConfig);
        pStruct->pConfig = NULL;
    }

    tmpStatus = HASH_TABLE_removePtrsTable(gRestApiCtx.pHashTablePidKey, NULL);
    if (OK != tmpStatus)
    {
        MSG_LOG_print(MSG_LOG_INFO, "HASH_TABLE_removePtrsTable failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(tmpStatus), tmpStatus);
    }

    tmpStatus = HASH_TABLE_removePtrsTable(gRestApiCtx.pHashTableResourceKey, NULL);
    if (OK != tmpStatus)
    {
        MSG_LOG_print(MSG_LOG_INFO, "HASH_TABLE_removePtrsTable failed, status = %s (%d)\n",
                MERROR_lookUpErrorCode(tmpStatus), tmpStatus);
    }

    MSG_LOG_print(MSG_LOG_INFO, "Exiting TrustEdge Rest API Mode: status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
}

#endif /* !defined(__DISABLE_TRUSTEDGE_REST_API__) */

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__ENABLE_DIGICERT_TAP_REMOTE__)
static MSTATUS TRUSTEDGE_mainEstTapCallback(
    TAP_Context **ppTapContext,
    TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred,
    byteBoolean getContext)
{
    return TRUSTEDGE_TAP_getCtx(
        ppTapContext, ppTapEntityCred, ppTapKeyCred, NULL, 0, getContext);
}
#endif
#endif

/*----------------------------------------------------------------------------*/

extern int TRUSTEDGE_init(void)
{
    return (int) DIGICERT_initDigicert();
}

/*----------------------------------------------------------------------------*/

extern int TRUSTEDGE_reset(void)
{
    MSTATUS status = TRUSTEDGE_agentMainReset();
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "\nERROR: TRUSTEDGE_agentMainReset failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

extern int TRUSTEDGE_deinit(void)
{
    (void) DIGICERT_freeDigicert();
    return 0;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
extern int TRUSTEDGE_main(int argc, char *ppArgv[])
#else
int main(int argc, char *ppArgv[])
#endif
{
    MSTATUS status = OK;
    TrustEdgeConfig *pConfig = NULL;
    JSON_ContextType *pJCtx = NULL;
    sbyte *pLogLevel = NULL;
    MsgLogLevel logLevel;
    int i;
    struct TrustEdgeThreadArgs certMain = {0};
    struct TrustEdgeThreadArgs agentMain = {0};
    RTOS_THREAD certTid = RTOS_THREAD_INVALID;
    RTOS_THREAD agentTid = RTOS_THREAD_INVALID;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    struct TrustEdgeThreadArgs agentRestApi = {0};
    RTOS_THREAD agentRestApiTid = RTOS_THREAD_INVALID;
#endif
#ifdef __RTOS_LINUX__
#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
    byteBoolean isServiceMode = FALSE;
    FileDescriptorInfo fileDescr = {0};
    sbyte4 pidFd;
#endif
    /* disabled buffering stdout/stderr so logs
     * get written real time */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif

#if defined(__RTOS_WIN32__)
#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
    byteBoolean isServiceMode = FALSE;
#endif
#endif

#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: DIGICERT_initDigicert failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (0 == argc || 1 == argc)
    {
        status = ERR_TRUSTEDGE_NO_ARG;
        TRUSTEDGE_displayHelp(1 == argc ? ppArgv[0] : TRUSTEDGE_PROG_NAME);
        DB_PRINT(
            "\nERROR: No arguments provided, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "--daemon"))
    {
        isServiceMode = TRUE;
    }

#ifdef __RTOS_LINUX__
    if (TRUE == isServiceMode && TRUE == TRUSTEDGE_isServiceRunning())
    {
        DB_PRINT(
            "%s", "TrustEdge Agent is already running.. \n");
        status = OK;
        goto nocleanup;
    }

    if (TRUE == isServiceMode)
    {
        /* if /run exists, use that directory for PID file */
        if (TRUE == FMGMT_pathExists(RUN_DIR, &fileDescr) && FTDirectory == fileDescr.type)
        {
            pidFd = open(TRUSTEDGE_PID_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (0 > pidFd)
            {
                DB_PRINT(
                    "%s", "TrustEdge Agent failed to write PID file, exiting..\n");
                status = ERR_TRUSTEDGE;
                goto exit;
            }

            dprintf(pidFd, "%d\n", getpid());
            close(pidFd);
        }
        else
        {
            pidFd = open(TRUSTEDGE_LEGACY_PID_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (0 > pidFd)
            {
                DB_PRINT(
                    "%s", "TrustEdge Agent failed to write PID file, exiting..\n");
                status = ERR_TRUSTEDGE;
                goto exit;
            }

            dprintf(pidFd, "%d\n", getpid());
            close(pidFd);
        }
    }
#endif /* __RTOS_LINUX__ */
#endif

    status = MQTT_init(MAX_MQTT_CLIENT_CONNECTIONS);
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: MQTT_init failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = HTTP_init();
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: HTTP_init failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SSL_init(MAX_SSL_SERVER_CONNECTIONS, MAX_SSL_CLIENT_CONNECTIONS);
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: SSL_init failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    /* Initialize logging early so errors during config parsing are visible */
    status = MSG_LOG_init(MSG_LOG_INFO);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to initialize logger, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadConfig(&pConfig);
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: TRUSTEDGE_utilsReadConfig failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__ENABLE_DIGICERT_TAP_REMOTE__)
    if (OK == TRUSTEDGE_TAP_init(1, pConfig))
    {
        /* Register TAP callbacks */
        status = EST_CLIENT_registerTapCtxCallback(
            TRUSTEDGE_mainEstTapCallback);
        if (OK != status)
        {
            DB_PRINT(
                "\nWARNING: TAP EST callback failed to register, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
        }
    }
#endif
#endif

    if (NULL != pConfig->pProxyUrl)
    {
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
        status = HTTP_PROXY_setProxyUrlAndPort(pConfig->pProxyUrl);
#else
        status = ERR_HTTP_PROXY_NOT_ENABLED;
#endif
        if (OK != status)
        {
            DB_PRINT(
                "\nERROR: Failed to set proxy URL (%s), status = %s (%d)\n",
                pConfig->pProxyUrl, MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
    status = SIGNAL_registerHandler(MSIGTERM, TRUSTEDGE_signalHandler);
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: SIGNAL_registerHandler failed to set MSIGTERM handler with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SIGNAL_registerHandler(MSIGINT, TRUSTEDGE_signalHandler);
    if (OK != status)
    {
        DB_PRINT(
            "\nERROR: SIGNAL_registerHandler failed to set MSIGINT handler with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#endif

    /* Override logLevel if provided as command line argument */
    pConfig->exitClient = FALSE;
    for (i = 1; i < argc; i++)
    {
#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
        if (0 == DIGI_STRCMP((const sbyte *) "--log-level", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValueRef(
                (char **) ppArgv, argc, &i, &pLogLevel);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: Unable to process log level argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) ppArgv[i], (const sbyte *) "--version"))
        {
            /* Exit with OK status */
            TRUSTEDGE_displayVersion();
            goto exit;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--require-pqc", (const sbyte *) ppArgv[i]))
        {
            pConfig->requirePQC = TRUE;
        }
#endif

        if (0 == DIGI_STRCMP((const sbyte *) "--exit-on-complete", (const sbyte *) ppArgv[i]))
        {
            pConfig->exitClient = TRUE;
        }
    }

#if !defined(__ENABLE_DIGICERT_PQC__)
    if (TRUE == pConfig->requirePQC)
    {
        status = ERR_TRUSTEDGE_AGENT_FEATURE_NOT_AVAILABLE;
        DB_PRINT(
            "\nERROR: PQC is not enabled, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#endif

    if (NULL != pLogLevel)
    {
        status = MSG_LOG_convertStringLevel(pLogLevel, &logLevel);
        if (OK != status)
        {
            DB_PRINT(
                "\nERROR: Failed to convert log level string, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
    else
    {
        if (FALSE == TRUSTEDGE_utilsGetConfigLogLevel (&logLevel))
        {
            /* if no config or --log-level, set default */
            logLevel = MSG_LOG_INFO;
        }
    }

    /* Update log level based on config or command line argument */
    status = MSG_LOG_changeLevel(logLevel);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "ERROR: Failed to change log level, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
    if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "--help"))
    {
        /* Exit with OK status */
        TRUSTEDGE_displayHelp(ppArgv[0]);
        goto exit;
    }
#endif

    if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "--daemon"))
    {
        ubyte4 len;

        argc = 2;
        if (TRUE == pConfig->isCertFieldMissing)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "certificate field missing in trustedge json, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#ifndef __DISABLE_TRUSTEDGE_REST_API__
        agentRestApi.type = TRUSTEDGE_AGENT;
        agentRestApi.ppArgv = ppArgv;
        agentRestApi.argc = argc;

        status = TRUSTEDGE_utilsCloneConfig(pConfig, &(agentRestApi.pConfig));
        if (OK != status)
        {
            DB_PRINT(
                "\nERROR: TRUSTEDGE_utilsCloneConfig failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = RTOS_createThread(TRUSTEDGE_threadStartRestAPI, (void *)&agentRestApi, TRUSTEDGE_MAIN, &agentRestApiTid);
        if (OK != status)
        {
            DB_PRINT(
                "\nERROR: RTOS_createThread failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        RTOS_sleepMS(2000);
#endif
        len = DIGI_STRLEN(pConfig->pTrustEdgeMode);
        if (len == DIGI_STRLEN("certificate") && 0 == DIGI_STRNICMP (pConfig->pTrustEdgeMode, "certificate", len))
        {
            if ((NULL == pConfig->pCertificateMode) || (0 == DIGI_STRCMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) "")))
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Certificate mode missing in request json, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            else if (DIGI_STRLEN((const sbyte *) pConfig->pCertificateMode) == DIGI_STRLEN((const sbyte *) SCEP_JSTR) &&
                0 == DIGI_STRNICMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) SCEP_JSTR, DIGI_STRLEN((const sbyte *) SCEP_JSTR)))
            {
                enrollMode = SCEP_JSTR;
            }
            else if (DIGI_STRLEN((const sbyte *) pConfig->pCertificateMode) == DIGI_STRLEN((const sbyte *) EST_JSTR) &&
                0 == DIGI_STRNICMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) EST_JSTR, DIGI_STRLEN((const sbyte *) EST_JSTR)))
            {
                enrollMode = EST_JSTR;
            }
            else
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Invalid certificate mode, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            MSG_LOG_setLabel("TRUSTEDGE-CERTIFICATE");
#ifndef __DISABLE_TRUSTEDGE_REST_API__
            certMain.type = TRUSTEDGE_CERTIFICATE;
            certMain.ppArgv = ppArgv;
            certMain.argc = argc;
            certMain.pConfig = pConfig;
            pConfig = NULL;

            status = RTOS_createThread(TRUSTEDGE_threadStart, (void *)&certMain, TRUSTEDGE_MAIN, &certTid);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: RTOS_createThread failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
#else
            status = TRUSTEDGE_certificateMain(argc - 1, ppArgv + 1, enrollMode, TE_AGENT_DAEMON_MODE, &pConfig);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: TRUSTEDGE_certificateMain failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
#endif
        }
        else if (len == DIGI_STRLEN((const sbyte *) "agent") && 0 == DIGI_STRNICMP((const sbyte *) pConfig->pTrustEdgeMode, (const sbyte *) "agent", len))
        {
            MSG_LOG_setLabel("TRUSTEDGE-AGENT");
#ifndef __DISABLE_TRUSTEDGE_REST_API__
            agentMain.type = TRUSTEDGE_AGENT;
            agentMain.ppArgv = ppArgv;
            agentMain.argc = argc;
            agentMain.pConfig = pConfig;
            pConfig = NULL;

            status = RTOS_createThread(TRUSTEDGE_threadStart, (void *)&agentMain, TRUSTEDGE_MAIN, &agentTid);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: RTOS_createThread failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
#else
            status = TRUSTEDGE_agentMain(argc - 1, ppArgv + 1, 1, &pConfig);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: TRUSTEDGE_agentMain failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
#endif
        }
        else if (len == DIGI_STRLEN((const sbyte *) "agent,certificate") &&
            (0 == DIGI_STRNICMP((const sbyte *) pConfig->pTrustEdgeMode, (const sbyte *) "agent,certificate", len) ||
             0 == DIGI_STRNICMP((const sbyte *) pConfig->pTrustEdgeMode, (const sbyte *) "certificate,agent", len)))
        {
            if ((NULL == pConfig->pCertificateMode) || (0 == DIGI_STRCMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) "")))
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Certificate mode missing in request json, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            else if (DIGI_STRLEN((const sbyte *) pConfig->pCertificateMode) == DIGI_STRLEN((const sbyte *) SCEP_JSTR) &&
                0 == DIGI_STRNICMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) SCEP_JSTR, DIGI_STRLEN((const sbyte *) SCEP_JSTR)))
            {
                enrollMode = SCEP_JSTR;
            }
            else if (DIGI_STRLEN((const sbyte *) pConfig->pCertificateMode) == DIGI_STRLEN((const sbyte *) EST_JSTR) &&
                0 == DIGI_STRNICMP((const sbyte *) pConfig->pCertificateMode, (const sbyte *) EST_JSTR, DIGI_STRLEN((const sbyte *) EST_JSTR)))
            {
                enrollMode = EST_JSTR;
            }
            else
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Invalid certificate mode, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            MSG_LOG_setLabel((sbyte *) "TRUSTEDGE-AGENT");
            certMain.type = TRUSTEDGE_CERTIFICATE;
            certMain.ppArgv = ppArgv;
            certMain.argc = argc;
            certMain.pConfig = pConfig;
            pConfig = NULL;

            agentMain.type = TRUSTEDGE_AGENT;
            agentMain.ppArgv = ppArgv;
            agentMain.argc = argc;

            status = TRUSTEDGE_utilsCloneConfig(certMain.pConfig, &(agentMain.pConfig));
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: TRUSTEDGE_utilsCloneConfig failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            status = RTOS_createThread(TRUSTEDGE_threadStart, (void *)&certMain, TRUSTEDGE_MAIN, &certTid);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: RTOS_createThread failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            RTOS_sleepMS(2000);

            status = RTOS_createThread(TRUSTEDGE_threadStart, (void *)&agentMain, TRUSTEDGE_MAIN, &agentTid);
            if (OK != status)
            {
                DB_PRINT(
                    "\nERROR: RTOS_createThread failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else
        {
            status = ERR_TRUSTEDGE_UNKNOWN_ARG;
            DB_PRINT(
                "\nERROR: Argument \"%s\" not recognized, status = %s (%d)\n",
                pConfig->pTrustEdgeMode, MERROR_lookUpErrorCode(status), status);
        }

        goto exit;
    }
#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
    else if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "mqtt"))
    {
        status = MQTT_EXAMPLE_main(argc - 1, ppArgv + 1, &pConfig);
    }
    else if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "agent"))
    {
        status = TRUSTEDGE_agentMain(argc - 1, ppArgv + 1, 0, &pConfig);
    }
    else if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "certificate"))
    {
        if (TRUE == pConfig->isCertFieldMissing)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "certificate field missing in trustedge json, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        if (argc > 2 && 0 == DIGI_STRCMP((const sbyte *) ppArgv[2], (const sbyte *) SCEP_JSTR))
        {
            enrollMode = SCEP_JSTR;
            status = TRUSTEDGE_certificateMain(argc - 2, ppArgv + 2, enrollMode, TE_AGENT_CLI_MODE, &pConfig);
        }
        else
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
        if (argc > 2 && 0 == DIGI_STRCMP((const sbyte *) ppArgv[2], (const sbyte *) EST_JSTR))
        {
            enrollMode = EST_JSTR;
            status = TRUSTEDGE_certificateMain(argc - 2, ppArgv + 2, enrollMode, TE_AGENT_CLI_MODE, &pConfig);
        }
        else
#endif
        {
            status = TRUSTEDGE_certificateMain(argc - 1, ppArgv + 1, enrollMode, TE_AGENT_CLI_MODE, &pConfig);
        }
    }
    else
    {
        status = ERR_TRUSTEDGE_UNKNOWN_ARG;
        TRUSTEDGE_displayHelp(ppArgv[0]);
        DB_PRINT(
            "\nERROR: Argument \"%s\" not recognized, status = %s (%d)\n",
            ppArgv[1], MERROR_lookUpErrorCode(status), status);
    }
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ */

exit:

#ifdef __RTOS_LINUX__
    if (RTOS_THREAD_INVALID != agentTid)
    {
        pthread_join((uintptr) agentTid, NULL);
    }

    if (RTOS_THREAD_INVALID != certTid)
    {
        pthread_join((uintptr) certTid, NULL);
    }

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (RTOS_THREAD_INVALID != agentRestApiTid)
    {
        pthread_join((uintptr) agentRestApiTid, NULL);
    }
#endif
#endif

    JSON_releaseContext (&pJCtx);
    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
    }
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (NULL != certMain.pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&certMain.pConfig);
    }
    if (NULL != agentRestApi.pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&agentRestApi.pConfig);
    }
#endif

    MSG_LOG_uninit();

#if defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__ENABLE_DIGICERT_TAP_REMOTE__)
    TRUSTEDGE_TAP_clean();
#endif
#endif

    SSL_shutdownStack();
    HTTP_stop();
    MQTT_shutdownStack();

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
    TRUSTEDGE_deinit();

#ifdef __RTOS_LINUX__
    if (TRUE == isServiceMode)
    {
        (void) FMGMT_remove((const sbyte *) TRUSTEDGE_PID_FILE, FALSE);
        (void) FMGMT_remove((const sbyte *) TRUSTEDGE_LEGACY_PID_FILE, FALSE);
    }
#endif /* __RTOS_LINUX__ */
#endif

    RTOS_mutexFree(&gCertMutex);

#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
nocleanup:
#endif
    return (OK == status) ? 0 : -1;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
#if defined(__RTOS_ZEPHYR__)
atomic_t g_TrustEdgeState = ATOMIC_INIT((int) DISCONNECTED);
#endif

extern enum TrustedgeState TRUSTEDGE_getState()
{
#if defined(__RTOS_ZEPHYR__)
    return (enum TrustedgeState) atomic_get(&g_TrustEdgeState);
#else
    return UNKNOWN;
#endif
}

extern void TRUSTEDGE_setState(enum TrustedgeState state)
{
#if defined(__RTOS_ZEPHYR__)
    atomic_set(&g_TrustEdgeState, (int) state);
#else
    MOC_UNUSED(state);
#endif
}

extern enum TrustedgeStatus TRUSTEDGE_getStatus()
{
    MSTATUS status;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pPath = NULL;
    enum TrustedgeStatus trustedgeStatus = PREINSTALL;

    status = TRUSTEDGE_utilsGetConfigPath(&pPath);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pPath, NULL))
    {
        goto exit;
    }

    DIGI_FREE((void **) &pPath);
    trustedgeStatus = INSTALLED;

    status = TRUSTEDGE_utilsReadConfig(&pConfig);
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir,
        (sbyte *) TRUSTEDGE_BOOTSTRAP_FILE,
        &pPath);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pPath, NULL))
    {
        goto exit;
    }

    trustedgeStatus = PROVISIONED;

exit:

    DIGI_FREE((void **) &pPath);

    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
    }

    return trustedgeStatus;
}

#define TRUSTEDGE_TCP_SERVER_PORT   8080
#define BUFFER_SIZE                 1024

static MSTATUS TRUSTEDGE_tcpClient(TCP_SOCKET serverSocket, ubyte2 port, sbyte *pFilename)
{
#if defined(__RTOS_ZEPHYR__)
    MSTATUS status = ERR_GENERAL;
    sbyte pPayload[BUFFER_SIZE] = {0};
    sbyte pIpAddr[40] = {0};
    ubyte4 nRet = 0;
    sbyte4 bytesWritten = 0;
    sbyte4 numBytesSent = 0;
    k_timeout_t timeout = K_MSEC(2000);
    FileDescriptor pCtx = NULL;
    int totalBytes = 0;

    status = TRUSTEDGE_utilsGetHostByName("provision.digicert.com", pIpAddr);
    if (OK != status)
    {
        goto exit;
    }

    do
    {
        k_sleep(timeout);
        status = TCP_CONNECT(&serverSocket, pIpAddr, port);
    } while (OK != status);

    if (0 == DIGI_STRCMP(pFilename, "filesys"))
    {
        status = FMGMT_fopen("filesystem.zip", "wb", &pCtx);
        if (OK != status)
        {
            goto exit;
        }
    }
    else if (0 == DIGI_STRCMP(pFilename, "bootstrap"))
    {
        status = FMGMT_fopen("bootstrap.zip", "wb", &pCtx);
        if (OK != status)
            goto exit;
    }


    status = TCP_WRITE(serverSocket, pFilename, DIGI_STRLEN(pFilename), &numBytesSent);
    if (OK != status)
    {
        goto exit;
    }

    do {

        status = TCP_READ_AVL_EX(serverSocket, pPayload, BUFFER_SIZE, &nRet, TCP_NO_TIMEOUT);
        if (ERR_TCP_READ_TIMEOUT == status)
        {
            status = OK;
            break;
        }

        if (nRet > 0)
        {
            status = FMGMT_fwrite(pPayload, 1, nRet, pCtx, &bytesWritten);
            totalBytes += bytesWritten;
            if (OK != status)
            {
                break;
            }
        }
    } while (nRet > 0);

    FMGMT_fclose(&pCtx);
    status = OK;

exit:

    return status;
#else
    MOC_UNUSED(serverSocket);
    MOC_UNUSED(port);
    MOC_UNUSED(pFilename);
    return ERR_NOT_IMPLEMENTED;
#endif
}

extern void TRUSETDGE_clientStart(void *pArg)
{
    MSTATUS status;
    TCP_SOCKET serverSocket = -1;
    sbyte *pFileRequest = (sbyte *)pArg;

    status = TRUSTEDGE_tcpClient(serverSocket, TRUSTEDGE_TCP_SERVER_PORT, pFileRequest);
    if (OK != status)
    {
        goto exit;
    }

exit:
    (void) TCP_CLOSE_SOCKET(serverSocket);
}

extern int TRUSTEDGE_launch(enum TrustedgeMode mode)
{
    /* generate command line arguments here to allow processing
     * with API as written. */
    /* we want to generate "./trustedge --daemon" */
    MSTATUS status;
    int argc = 2;
    char **pArgs = NULL;
    enum TrustedgeStatus trustedgeStatus;
    RTOS_THREAD clientTid = RTOS_THREAD_INVALID;

    /* ok if DIGICERT_initDigicert called more than once, will be idempotent */
    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "\nERROR: DIGICERT_initDigicert failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    trustedgeStatus = TRUSTEDGE_getStatus();
    switch (trustedgeStatus) {
        case PREINSTALL:
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TrustEdge not installed. Downloading files..\n");
            status = RTOS_createThread(TRUSETDGE_clientStart, (void *)"filesys", TRUSTEDGE_MAIN, &clientTid);
            if (OK != status)
            {
                goto exit;
            }

            pthread_join((uintptr) clientTid, NULL);

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Files downloaded. Extracting..\n");
            status = TRUSTEDGE_install("filesystem.zip");
            if (OK != status)
            {
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TrustEdge installed. Downloading bootstrap configuration...\n");
            /* fallthrough */
        case INSTALLED:
            if (FALSE == FMGMT_pathExists("bootstrap.zip", NULL))
            {
                status = RTOS_createThread(TRUSETDGE_clientStart, (void *)"bootstrap", TRUSTEDGE_MAIN, &clientTid);
                if (OK != status)
                {
                    goto exit;
                }

                pthread_join((uintptr) clientTid, NULL);
            }

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Bootstrap configuration downloaded. Extracting...\n");
            status = TRUSTEDGE_extractBootStrap("bootstrap.zip");
            if (OK != status)
                goto exit;

            /* fallthrough */
        case PROVISIONED:
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TrustEdge is provisioned.\n");
            break;
    }

    if (PROVISION == mode)
    {
        status = OK;
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Launching..\n");
    if (LAUNCH_AND_EXIT == mode)
    {
        argc++; /* add --exit-on-complete */
    }
    status = DIGI_CALLOC((void **) &pArgs, argc, sizeof(char *));
    if (OK != status)
        goto exit;

    pArgs[0] = TRUSTEDGE_utilsCloneString("trustedge");
    pArgs[1] = TRUSTEDGE_utilsCloneString("--daemon");
    if (LAUNCH_AND_EXIT == mode)
    {
        pArgs[2] = TRUSTEDGE_utilsCloneString("--exit-on-complete");
    }

    status = TRUSTEDGE_main(argc, pArgs);

exit:

    if (NULL != pArgs)
    {
        int i;

        for (i = 0; i < argc; i++)
        {
            if (NULL != pArgs[i])
            {
                (void) DIGI_FREE((void **) &pArgs[i]);
            }
        }
        (void) DIGI_FREE((void **) &pArgs);
    }
    return status;
}

extern int TRUSTEDGE_installEx(char *pZipPath, char *pDst)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL == pZipPath) || (NULL == pDst))
    {
        goto exit;
    }

    status = TRUSTEDGE_utilsExtractZip(pZipPath, pDst);

exit:
    return status;
}

extern int TRUSTEDGE_install(char *pZipPath)
{
    return TRUSTEDGE_installEx(pZipPath, "/");
}

int TRUSTEDGE_setMountPoint(unsigned char *pNewMountPath)
{
    return FMGMT_setMountPoint(pNewMountPath);
}

#ifdef __ENABLE_DIGICERT_CUSTOM_MALLOC__
extern int TRUSTEDGE_initCustomHeap(void *pHeap, int heapSize)
{
    return DIGICERT_initCustomHeap(pHeap, (size_t)heapSize);
}
#endif
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ */
