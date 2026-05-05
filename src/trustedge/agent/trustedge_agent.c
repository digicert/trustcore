/*
 * trustedge_agent.c
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

#include <stdio.h>
#ifdef __RTOS_LINUX__
#include <time.h>
#include <unistd.h>
#endif

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/msg_logger.h"
#include "../../common/uri.h"
#include "../../common/mtcp.h"
#include "../../common/mtcp_async.h"
#include "../../common/base64.h"
#include "../../common/datetime.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/msg_logger.h"
#include "../../common/vlong.h"
#include "../../common/common_utils.h"
#include "../../common/mfmgmt.h"
#include "../../common/hash_value.h"
#include "../../common/mime_parser.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto/ecc.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/crypto_utils.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#include "../../trustedge/utils/trustedge_tap.h"
#endif
#include "../../crypto/tools/crypto_keygen.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto_interface/crypto_interface_sha512.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_sig.h"
#endif
#include "../../cert_enroll/cert_enroll.h"
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
#include "../../ssl/ssl.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#include "../../mqtt/mqtt_client.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_protobuf.h"
#include "../../trustedge/agent/trustedge_agent_persist.h"
#include "../../trustedge/agent/trustedge_agent_policy.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"
#include "../../trustedge/agent/trustedge_agent_attributes.h"
#include "../../trustedge/agent/trustedge_agent_certificate.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../est/est_cert_utils.h"
#include "../../est/est_client_api.h"
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
#include "../../trustedge/agent/trustedge_agent_debug.h"
#endif

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
#include "../../trustedge/agent/trustedge_state.h"
#endif

/*----------------------------------------------------------------------------*/

#define TRUSTEDGE_SOURCE                "TrustEdge v2.0"

/* TODO: Better name for label, possible alternatives
 *
 * "TEPA" - TrusEdge Protection Agent
 * "TA" - TrustEdge Agent
 */
#define TRUSTEDGE_AGENT_LOG_LABEL       "TRUSTEDGE-AGENT"

/* Default scheme we expect from the provided endpoints
 */
#define TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTT    "mqtt"
#define TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTTS   "mqtts"

/*----------------------------------------------------------------------------*/

static TrustedgeGlobalFuncTable gFuncPtrTable = {
    .pFuncOnSafeToExit = NULL,
    .pFuncDNSLookup = NULL,
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
    .pFuncActionHandler = NULL
#endif
};

extern TrustedgeGlobalFuncTable *TRUSTEDGE_getFunctionTable(void)
{
    return &gFuncPtrTable;
}

/*----------------------------------------------------------------------------*/

static intBoolean logPayload = FALSE;

extern intBoolean TRUSTEDGE_isLogPayloadEnabled(void)
{
    return logPayload;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParseConfig(
    TrustEdgeAgentCtx *pAgentCtx);

static MSTATUS TRUSTEDGE_agentInit(
    TrustEdgeAgentCtx *pAgentCtx);

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentMetricAlloc(
    void *pHashCookie,
    hashTablePtrElement **ppNewElement)
{
    MOC_UNUSED(pHashCookie);
    MSTATUS status;

    status = DIGI_MALLOC((void **)ppNewElement, sizeof(hashTablePtrElement));

    DEBUG_RELABEL_MEMORY(*ppNewElement);

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentMetricFree(
    void *pHashCookie,
    hashTablePtrElement *pDeleteElement)
{
    MOC_UNUSED(pHashCookie);
    TrustEdgeAgentMetric *pMetric = pDeleteElement->pAppData;
    DIGI_FREE((void **) &pMetric->pName);
    DIGI_FREE((void **) &pMetric->pValue);
    DIGI_FREE((void **) &pMetric);

    return DIGI_FREE((void **)(&pDeleteElement));
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentContextAcquire(
    TrustEdgeAgentContext **ppCtx,
    TrustEdgeConfig **ppConfig)
{
    MSTATUS status;
    TrustEdgeAgentCtx *pCtx = NULL;
    sbyte4 len;
    sbyte *pPath = NULL;
    ubyte *pPatDataBlob = NULL;
    ubyte4 patDataBlobLen;
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
    FileDescriptorInfo fdInfo = { 0 };
#endif

    if (NULL == ppCtx || NULL == ppConfig || NULL == *ppConfig)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Context and/or settings are NULL\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pCtx, 1, sizeof(TrustEdgeAgentCtx));
    if (OK != status)
    {
        goto exit;
    }

    pCtx->pConfig = *ppConfig;
    *ppConfig = NULL;

    status = TRUSTEDGE_utilsGetConfigPath(&pPath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "Failed to get configuration file. %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCtx->pConfig->pBootstrapConfig)
    {
        len = DIGI_STRLEN(pCtx->pConfig->pBootstrapConfig);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCtx->pBootstrapConfigFile, len + 1,
            pCtx->pConfig->pBootstrapConfig, len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->pBootstrapConfigFile[len] = '\0';
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_NO_BOOTSTRAP_CONFIG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Bootstrap configuration file required\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCtx->pConfig->pBootstrapSig)
    {
        len = DIGI_STRLEN(pCtx->pConfig->pBootstrapSig);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCtx->pBootstrapSigFile, len + 1,
            pCtx->pConfig->pBootstrapSig, len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->pBootstrapSigFile[len] = '\0';
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_NO_BOOTSTRAP_SIG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Bootstrap signature file required\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCtx->pConfig->pWorkspaceDir)
    {
        /* if no workspace passed as argument, use trustedge.json entry */
        len = DIGI_STRLEN(pCtx->pConfig->pWorkspaceDir);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCtx->pWorkspaceDir, len + 1,
            pCtx->pConfig->pWorkspaceDir, len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->pWorkspaceDir[len] = '\0';
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_NO_WORKSPACE_DIR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Workspace directory required\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HASH_TABLE_createPtrsTable(
        &pCtx->pMetrics, METRIC_HASH_TABLE_SIZE, NULL,
        TRUSTEDGE_agentMetricAlloc, TRUSTEDGE_agentMetricFree);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Hash table creation failed\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HASH_TABLE_createPtrsTable(
        &pCtx->pDesiredAttributes, METRIC_HASH_TABLE_SIZE, NULL,
        TRUSTEDGE_agentMetricAlloc, TRUSTEDGE_agentMetricFree);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Hash table creation failed\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCtx->pConfig->pDebugDir)
    {
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
        len = DIGI_STRLEN(pCtx->pConfig->pDebugDir);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCtx->pDebugDir, len + 1,
            pCtx->pConfig->pDebugDir, len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->pDebugDir[len] = '\0';

        if (FALSE == FMGMT_pathExists(pCtx->pDebugDir, &fdInfo))
        {
            status = FMGMT_mkdir(pCtx->pDebugDir, 0744);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else if (FTDirectory != fdInfo.type)
        {
            status = ERR_DIR_NOT_DIRECTORY;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#else
        status = ERR_TRUSTEDGE_AGENT_FEATURE_NOT_AVAILABLE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
#endif
    }

    MSG_LOG_print(MSG_LOG_INFO, "Parsing bootstrap configuration file: %s\n", pCtx->pBootstrapConfigFile);

    status = TRUSTEDGE_agentParseConfig(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentInit(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx->pPatFile)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Policy authorization token file path not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->pPatData = NULL;
    if (TRUE == FMGMT_pathExists(pCtx->pPatFile, NULL))
    {
        patDataBlobLen = 0;
        status = DIGICERT_readFile(pCtx->pPatFile, &pPatDataBlob, &patDataBlobLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Policy authorization token file failed to read\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY((void **) &pCtx->pPatData, patDataBlobLen + 1, pPatDataBlob, patDataBlobLen);
        if (OK != status)
        {
            DIGI_FREE((void **) &pPatDataBlob);
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pCtx->pPatData[patDataBlobLen] = '\0';
        DIGI_FREE((void **) &pPatDataBlob);
    }

    /* if setting interval values are negative, ignore them */
    pCtx->refreshToken = FALSE;
    pCtx->connectionUptimeInterval = pCtx->pConfig->connUptimeInterval;
    pCtx->keepAliveInterval = pCtx->pConfig->keepAliveInterval;
    pCtx->policyRequestTimeout = pCtx->pConfig->policyRequestTimeout;
    pCtx->sleepInterval = pCtx->pConfig->sleepInterval;
    pCtx->recvPollingInterval = pCtx->pConfig->recvPollingInterval;
    pCtx->refreshHours = pCtx->pConfig->refreshHours;
    pCtx->actionHandlerTimeout = pCtx->pConfig->actionHandlerTimeout;
    pCtx->maxRetryCount = pCtx->pConfig->maxRetryCount;
    pCtx->timeoutWindow = pCtx->pConfig->timestampWindow;
    pCtx->maxErrorResponses = pCtx->pConfig->maxErrorResponses;
    pCtx->enforceToken = (byteBoolean) pCtx->pConfig->enforceToken;
    pCtx->persistArtifact = (byteBoolean) pCtx->pConfig->persistArtifact;
    pCtx->protocolBufferSize = pCtx->pConfig->protocolBufferSize;

    logPayload = pCtx->pConfig->logPayload;

    pCtx->pTable = TRUSTEDGE_getFunctionTable();

    pCtx->service = FALSE;

    *ppCtx = pCtx; pCtx = NULL;

exit:

    if (NULL != pCtx)
    {
        TRUSTEDGE_agentContextRelease((TrustEdgeAgentContext **) &pCtx);
    }

    DIGI_FREE((void **) &pPath);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMetricMatch(
    void *pTmpProperty,
    void *pMetricMatch,
    intBoolean *pRetIsMatch)
{
    TrustEdgeAgentMetric *pMetric = (TrustEdgeAgentMetric *) pTmpProperty;
    TrustEdgeAgentMetric *pMatch = (TrustEdgeAgentMetric *) pMetricMatch;
    MSTATUS status = OK;
    sbyte4 result;

    *pRetIsMatch = FALSE;

    if (pMetric->nameLen == pMatch->nameLen)
    {
        status = DIGI_MEMCMP(
            (const ubyte*) pMetric->pName, (const ubyte*) pMatch->pName,
            pMetric->nameLen, &result);
        if (OK != status)
        {
            goto exit;
        }

        if (0 == result)
            *pRetIsMatch = TRUE;
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentGetMetric(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pName,
    ubyte4 nameLen,
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status;
    sbyte *pMetricName = NULL;
    TrustEdgeAgentMetric *pFoundMetric = NULL;
    TrustEdgeAgentMetric match;
    intBoolean doesMetricAlreadyExist;
    ubyte4 hashValue;

    *ppVal = NULL;
    *pValLen = 0;

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pMetricName, nameLen + 1, pName, nameLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pMetricName[nameLen] = '\0';

    HASH_VALUE_hashGen(pMetricName, nameLen + 1, METRIC_HASH_VALUE_BASE, &hashValue);

    match.pName = pMetricName;
    match.nameLen = nameLen + 1;
    status = HASH_TABLE_findPtr(
        pCtx->pMetrics, hashValue, &match, TRUSTEDGE_agentMetricMatch,
        (void **) &pFoundMetric, &doesMetricAlreadyExist);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == doesMetricAlreadyExist)
    {
        *ppVal = pFoundMetric->pValue;
        *pValLen = pFoundMetric->valueLen;
    }

exit:

    DIGI_FREE((void **) &pMetricName);

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentIsMetricPresent(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pName,
    ubyte4 nameLen,
    intBoolean *present)
{
    MSTATUS status;
    TrustEdgeAgentMetric *pFoundMetric = NULL;
    TrustEdgeAgentMetric match;
    intBoolean doesMetricAlreadyExist;
    ubyte4 hashValue;

    HASH_VALUE_hashGen(pName, nameLen + 1, METRIC_HASH_VALUE_BASE, &hashValue);

    match.pName = pName;
    match.nameLen = nameLen + 1;
    status = HASH_TABLE_findPtr(
        pCtx->pMetrics, hashValue, &match, TRUSTEDGE_agentMetricMatch,
        (void **)&pFoundMetric, &doesMetricAlreadyExist);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                      "%s line %d status: %d = %s\n",
                      __func__, __LINE__, status,
                      MERROR_lookUpErrorCode(status));
        goto exit;
    }
    *present = doesMetricAlreadyExist;

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_agentAddMetric(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice,
    ubyte *pName,
    ubyte4 nameLen,
    ubyte *pVal,
    ubyte4 valLen)
{
    MSTATUS status;
    sbyte *pMetricName = NULL;
    TrustEdgeAgentMetric *pNewMetric = NULL;
    TrustEdgeAgentMetric *pFoundMetric = NULL;
    TrustEdgeAgentMetric match;
    intBoolean doesMetricAlreadyExist;
    ubyte4 hashValue;
    hashTableOfPtrs *pTable = NULL;

    switch (fileChoice)
    {
        case TE_METRICS_FILE:
            pTable = pCtx->pMetrics;
            break;
        case TE_DESIRED_ATTRIBUTES_FILE:
            pTable = pCtx->pDesiredAttributes;
            break;
        default:
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
    }

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pMetricName, nameLen + 1, pName, nameLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pMetricName[nameLen] = '\0';

    HASH_VALUE_hashGen(pMetricName, nameLen + 1, METRIC_HASH_VALUE_BASE, &hashValue);

    match.pName = pMetricName;
    match.nameLen = nameLen + 1;
    status = HASH_TABLE_findPtr(
        pTable, hashValue, &match, TRUSTEDGE_agentMetricMatch,
        (void **) &pFoundMetric, &doesMetricAlreadyExist);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == doesMetricAlreadyExist)
    {
        status = DIGI_CALLOC((void **) &pNewMetric, 1, sizeof(TrustEdgeAgentMetric));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pNewMetric->pName = pMetricName;
        pNewMetric->nameLen = nameLen + 1;
        pMetricName = NULL;

        status = DIGI_MALLOC_MEMCPY(
            (void **) &(pNewMetric->pValue), valLen + 1, pVal, valLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        (pNewMetric->pValue)[valLen] = '\0';
        pNewMetric->valueLen = valLen + 1;

        status = HASH_TABLE_addPtr(pTable, hashValue, pNewMetric);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
    {
        /* Metric already exists, update the existing entry */
        DIGI_FREE((void **) &pFoundMetric->pValue);

        status = DIGI_MALLOC_MEMCPY(
            (void **) &(pFoundMetric->pValue), valLen + 1, pVal, valLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        (pFoundMetric->pValue)[valLen] = '\0';
        pFoundMetric->valueLen = valLen + 1;
    }

exit:

    DIGI_FREE((void **) &pMetricName);

    return status;
}

#if 0

extern MSTATUS TRUSTEDGE_agentGetAttribute(
    void *pArg,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen)
{
    MSTATUS status;
    ubyte4 i, j;
    TrustEdgeAgentCtx *pCtx = (TrustEdgeAgentCtx *) pArg;
    ubyte *pVal = NULL;
    ubyte4 valLen = 0;
    ubyte4 totalLen = 0;
    byteBoolean foundPlaceholder;
    sbyte *pIter = pOutput;

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < expressionLen; i++)
    {
        foundPlaceholder = FALSE;

        if (pExpression[i] == '#' && i < expressionLen - 1 && pExpression[i + 1] == '#')
        {
            for (j = i + 2; j < expressionLen; j++)
            {
                if (pExpression[j] == '#' && j < expressionLen - 1 && pExpression[j + 1] == '#')
                {
                    foundPlaceholder = TRUE;

                    status = TRUSTEDGE_agentGetMetric(
                        pCtx, (ubyte *) (pExpression + i + 2), j - i - 2,
                        &pVal, &valLen);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    break;
                }
            }
        }

        if (TRUE == foundPlaceholder && NULL == pVal)
        {
            totalLen = 0;
            break;
        }

        if (NULL != pVal)
        {
            i = j + 1;
            totalLen += valLen;
            if (NULL != pIter)
            {
                DIGI_MEMCPY(pIter, pVal, valLen);
                pIter += valLen;
            }
            pVal = NULL;
        }
        else
        {
            if (NULL != pIter)
            {
                *pIter = pExpression[i];
                pIter++;
            }
            totalLen += 1;
        }
    }

    *pOutputLen = totalLen;
    status = OK;

exit:

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentComputeInventoryAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    byteBoolean overwrite)
{
    MSTATUS status;

    status = TRUSTEDGE_agentInventoryAttributes(pAgentCtx, overwrite);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentWriteMetrics(pAgentCtx, TE_METRICS_FILE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentProcessDesiredAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    JSON_ContextType *pJCtx,
    ubyte4 startIdx,
    sbyte *pAttrJStr)
{
    MSTATUS status;
    ubyte4 ndx;
    JSON_TokenType attrToken = { 0 };
    ubyte4 i;
    sbyte *pName = NULL;
    ubyte4 nameLen;
    sbyte *pValue = NULL;
    intBoolean isPresent;

    status = JSON_getJsonArrayValue(
        pJCtx, startIdx, pAttrJStr, &ndx, &attrToken, TRUE);
    if (OK == status)
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "Reading %s attributes\n", pAttrJStr);

        ndx++;
        for (i = 0; i < attrToken.elemCnt; i++)
        {
            DIGI_FREE((void **) &pName);
            status = JSON_getJsonStringValue(pJCtx, ndx, KEY_JSTR, &pName, TRUE);
            if (OK == status)
            {
                nameLen = DIGI_STRLEN(pName);
                status = TRUSTEDGE_agentIsMetricPresent(pAgentCtx, pName, nameLen, &isPresent);
                if (OK != status)
                {
                    goto exit;
                }
                if (FALSE == isPresent)
                {
                    DIGI_FREE((void **) &pValue);
                    status = JSON_getJsonStringValue(pJCtx, ndx, VALUE_JSTR, &pValue, TRUE);
                    if (OK == status && 0 != DIGI_STRLEN(pValue))
                    {
                        MSG_LOG_print(MSG_LOG_VERBOSE, "Adding attribute with key %s and value %s\n", pName, pValue);
                        status = TRUSTEDGE_agentAddMetric(
                            pAgentCtx, TE_DESIRED_ATTRIBUTES_FILE,
                            pName, nameLen, pValue, DIGI_STRLEN(pValue));
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                    }
                }
            }
            else
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "No key found, Skipping attribute at index %d\n", i);
            }

            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            ndx++;
        }
    }
    else
    {
        /* not found */
        status = OK;
    }

exit:

    DIGI_FREE((void **) &pName);
    DIGI_FREE((void **) &pValue);

    return status;
}

static MSTATUS TRUSTEDGE_agentVerifyBootstrapSignature(
    sbyte *pJWS,
    sbyte4 jwsLen,
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pDeviceName,
    sbyte *pDeviceGroupId)
{
    MSTATUS status = OK;
    sbyte *pHeader = NULL;
    sbyte4 headerLen = 0;
    sbyte *pPayload = NULL;
    sbyte4 payloadLen = 0;
    sbyte *pSignature = NULL;
    sbyte4 signatureLen = 0;
    JWSAlg alg = JWS_ALG_NONE;
    certChainPtr pCertChain = NULL;

    MSG_LOG_print(MSG_LOG_INFO, "%s\n", "Verifying bootstrap config signature");

    if (NULL == pJWS || 0 == jwsLen
       || NULL == pAccountId || NULL == pDeviceId
       || NULL == pDivisionId || NULL == pDeviceName
       || NULL == pDeviceGroupId)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Input parameters NULL\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsParseJWT(pJWS, jwsLen, &pHeader, &headerLen, &pPayload, &payloadLen, &pSignature, &signatureLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to parse JWS token\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsParseJWTHeader(
        pHeader, headerLen, &alg, &pCertChain, NULL, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == TRUSTEDGE_utilsValidatePayload(NULL,
            pAccountId, pDeviceId,
            pDivisionId, pDeviceName,
            pDeviceGroupId, pPayload,
            payloadLen,TRUE))
    {
        status = ERR_TRUSTEDGE_AGENT_JWT_MALFORMED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsVerifyJWTSignature(alg, pHeader,
        headerLen + 1 + payloadLen, pCertChain,
        pSignature, signatureLen, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to verify JWS signature\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    if (NULL != pCertChain)
        CERTCHAIN_delete(&pCertChain);

    return status;
}

static MSTATUS TRUSTEDGE_agentParseConfig(
    TrustEdgeAgentCtx *pAgentCtx)
{
    MSTATUS status;
    ubyte *pConfig = NULL;
    ubyte *pSigToken = NULL;
    ubyte4 configLen = 0;
    ubyte4 sigTokenLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 tokensFound = 0, rendezvousNdx, mqttEndpointNdx;
    ubyte4 i, j, authNdx, primaryNdx, secondaryNdx;
    JSON_TokenType primaryToken = { 0 };
    JSON_TokenType secondaryToken = { 0 };
    JSON_TokenType secondaryEndpointToken = { 0 };
    JSON_TokenType authToken = { 0 };
    ubyte *pAttrVal = NULL;
    intBoolean persistConn = FALSE;
    sbyte *pEndpoint = NULL;
    sbyte *pMethod = NULL;
    sbyte *pAuthKey = NULL;
    sbyte4 authKeyLen = 0;
    sbyte *pAuthCert = NULL;
    sbyte4 authCertLen = 0;
    sbyte *pName = NULL;
    sbyte *pValue = NULL;
    URI *pCurUri = NULL;
    sbyte *pScheme = NULL;
    sbyte *pHandle = NULL;
    sbyte *pCertHandle = NULL;
    sbyte *pPath = NULL;
    byteBoolean foundDeviceName = FALSE;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    sbyte *pChoosenScheme = TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTT;
#endif
    sbyte *pAttributeFile = NULL;
    sbyte *pBootstrapKeyFile = NULL;

    /* Input validation not required */

    status = DIGICERT_readFile(
        pAgentCtx->pBootstrapConfigFile, &pConfig, &configLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to read %s bootstrap configuration file\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pAgentCtx->pBootstrapConfigFile);
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pConfig, configLen, &tokensFound);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, DEVICE_ID_JSTR, &pAgentCtx->configOptions.pDeviceId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), DEVICE_ID_JSTR);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO, "Device ID> %s\n", pAgentCtx->configOptions.pDeviceId);

    /*optional*/
    status = JSON_getJsonStringValue(
        pJCtx, 0, DEVICE_NAME_JSTR, &pAgentCtx->configOptions.pDeviceName, TRUE);
    if (OK == status)
    {
        MSG_LOG_print(MSG_LOG_INFO, "Device Name> %s\n", pAgentCtx->configOptions.pDeviceName);
        foundDeviceName = TRUE;
    }
    else if (ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), DEVICE_NAME_JSTR);
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, ACCOUNT_ID_JSTR, &pAgentCtx->configOptions.pAccountId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), ACCOUNT_ID_JSTR);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO, "Account ID> %s\n", pAgentCtx->configOptions.pAccountId);

    status = JSON_getJsonStringValue(
        pJCtx, 0, DIVISION_ID_JSTR, &pAgentCtx->configOptions.pDivisionId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), DIVISION_ID_JSTR);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO, "Division ID> %s\n", pAgentCtx->configOptions.pDivisionId);

    status = JSON_getJsonStringValue(
        pJCtx, 0, DEVICE_GROUP_ID_JSTR, &pAgentCtx->configOptions.pDeviceGroupId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), DEVICE_GROUP_ID_JSTR);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO, "Device Group ID> %s\n", pAgentCtx->configOptions.pDeviceGroupId);

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, RENDEZVOUS_CONFIGURATION_JSTR, &rendezvousNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), RENDEZVOUS_CONFIGURATION_JSTR);
        goto exit;
    }

    if (TRUE == pAgentCtx->pConfig->verifyBootstrapSig)
    {
        status = DIGICERT_readFile(
            pAgentCtx->pBootstrapSigFile, &pSigToken, &sigTokenLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to read %s bootstrap signature file\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pAgentCtx->pBootstrapSigFile);
            goto exit;
        }

        status = TRUSTEDGE_agentVerifyBootstrapSignature(pSigToken, sigTokenLen,
                    pAgentCtx->configOptions.pAccountId,
                    pAgentCtx->configOptions.pDeviceId,
                    pAgentCtx->configOptions.pDivisionId,
                    pAgentCtx->configOptions.pDeviceName,
                    pAgentCtx->configOptions.pDeviceGroupId
                    );
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. BOOTSTRAP CONFIG SIGNATURE VERIFICATION FAILED!!\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_INFO, "%s\n", "Bootstrap config signature verified successfully");
    }

    if (TRUE == foundDeviceName)
    {
        status = TRUSTEDGE_agentAddMetric(
            pAgentCtx, TE_METRICS_FILE,
            (ubyte *) DEVICE_NAME_JSTR, DIGI_STRLEN(DEVICE_NAME_JSTR),
            (ubyte *) pAgentCtx->configOptions.pDeviceName,
            DIGI_STRLEN(pAgentCtx->configOptions.pDeviceName));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Unable to add %s metric\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), DEVICE_NAME_JSTR);
            goto exit;
        }
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, rendezvousNdx, MQTT_ENDPOINT_JSTR, &mqttEndpointNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), MQTT_ENDPOINT_JSTR);
        goto exit;
    }

    status = JSON_getJsonArrayValue(
        pJCtx, mqttEndpointNdx, PRIMARY_JSTR,
        &primaryNdx, &primaryToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), PRIMARY_JSTR);
        goto exit;
    }

    status = JSON_getJsonArrayValue(
        pJCtx, mqttEndpointNdx, SECONDARY_JSTR,
        &secondaryNdx, &secondaryToken, TRUE);
    if (ERR_NOT_FOUND == status)
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "No %s endpoint attribute found\n", SECONDARY_JSTR);
        status = OK;
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), SECONDARY_JSTR);
        goto exit;
    }

    /* Allocate memory for all URI values which will be 1 for the primary plus
     * n URIs for the secondary */
    status = DIGI_CALLOC(
        (void **) &pAgentCtx->mqttConfig.ppEndpoints,
        1 + secondaryToken.elemCnt, sizeof(URI *));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pAgentCtx->mqttConfig.totalEndpoints = 1 + secondaryToken.elemCnt;

    primaryNdx++;
    for (i = 0; i < primaryToken.elemCnt; i++)
    {
        DIGI_FREE((void **) &pEndpoint);
        status = JSON_getJsonString(pJCtx, primaryNdx, &pEndpoint);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        URI_DELETE(pCurUri);
        pCurUri = NULL;
        status = URI_ParseURI(pEndpoint, &pCurUri);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to parse primary %s MQTT endpoint\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pEndpoint);
            goto exit;
        }

        DIGI_FREE((void **) &pScheme);
        status = URI_GetScheme(pCurUri, &pScheme);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to get endpoint scheme for %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pEndpoint);
            goto exit;
        }

        /* Accept mqtts:// if SSL is enabled otherwise allow for mqtt:// */
        if (0 == DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTT))
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            if (NULL == pAgentCtx->mqttConfig.ppEndpoints[0])
            {
                pAgentCtx->mqttConfig.ppEndpoints[0] = pCurUri;
                pCurUri = NULL;
            }
#else
            /* Scheme matches, set it as primary */
            /* Index 0 should always be the primary URI */
            pAgentCtx->mqttConfig.ppEndpoints[0] = pCurUri;
            pCurUri = NULL;
            break;
#endif
        }
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        else if (0 == DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTTS))
        {
            URI_DELETE(pAgentCtx->mqttConfig.ppEndpoints[0]);
            pChoosenScheme = TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTTS;
            /* Scheme matches, set it as primary */
            /* Index 0 should always be the primary URI */
            pAgentCtx->mqttConfig.ppEndpoints[0] = pCurUri;
            pCurUri = NULL;
            break;
        }
#endif

        primaryNdx++;
    }

    /* Parse the secondary URI's */
    for (i = 0; i < secondaryToken.elemCnt; i++)
    {
        secondaryNdx++;
        status = JSON_getToken(pJCtx, secondaryNdx, &secondaryEndpointToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_Array != secondaryEndpointToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        for (j = 0; j < secondaryEndpointToken.elemCnt; j++)
        {
            DIGI_FREE((void **) &pEndpoint);
            secondaryNdx++;
            status = JSON_getJsonString(pJCtx, secondaryNdx, &pEndpoint);
            if (OK != status)
            {
                goto exit;
            }

            URI_DELETE(pCurUri);
            pCurUri = NULL;
            status = URI_ParseURI(pEndpoint, &pCurUri);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Failed to parse secondary %s MQTT endpoint\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pEndpoint);
                goto exit;
            }

            DIGI_FREE((void **) &pScheme);
            status = URI_GetScheme(pCurUri, &pScheme);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Failed to get endpoint scheme for %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pEndpoint);
                goto exit;
            }
            DIGI_FREE((void **) &pEndpoint);

            /* Accept mqtts:// if SSL is enabled otherwise allow for mqtt:// */
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            if (0 == DIGI_STRCMP(pScheme, pChoosenScheme))
#else
            if (0 == DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTT))
#endif
            {
                /* Scheme matches, set it as secondary */
                pAgentCtx->mqttConfig.ppEndpoints[i + 1] = pCurUri;
                pCurUri = NULL;
                secondaryNdx += (secondaryEndpointToken.elemCnt - j - 1);
                break;
            }
            else
            {
                URI_DELETE(pCurUri);
                pCurUri = NULL;
            }
        }
    }

    status = JSON_getJsonBooleanValue(
        pJCtx, rendezvousNdx, PERSIST_CONNECTION_JSTR, &persistConn, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), PERSIST_CONNECTION_JSTR);
        goto exit;
    }

    pAgentCtx->mqttConfig.persistConnection = persistConn;

    status = COMMON_UTILS_addPathComponent(
        pAgentCtx->pConfig->pConfDir, TRUSTEDGE_POLICY_AUTH_FILE,
        &pAgentCtx->pPatFile);
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pAgentCtx->pConfig->pConfDir, TRUSTEDGE_METRICS_FILE,
        &pAgentCtx->pMetricFile);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pAgentCtx->pMetricFile, NULL))
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "Reading device metrics from %s\n", pAgentCtx->pMetricFile);

        /* Device metrics already exist, ignore the ones from the bootstrap
         * configuration and load in the ones from the metric file */
        status = TRUSTEDGE_agentProtobufLoadMetricFile(
            pAgentCtx, TE_METRICS_FILE);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        status = COMMON_UTILS_addPathComponent(
            pAgentCtx->pConfig->pConfDir, TRUSTEDGE_ATTRIBUTES_FILE,
            &pAttributeFile);
        if (OK != status)
        {
            goto exit;
        }

        /* Process customer provided attributes */
        if (TRUE == FMGMT_pathExists(pAttributeFile, NULL))
        {
            MSG_LOG_print(
                MSG_LOG_VERBOSE, "Reading attributes from %s\n", pAttributeFile);

            status = TRUSTEDGE_agentCustomerAttributes(
                pAgentCtx, pAttributeFile);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        DIGI_FREE((void **) &pAttributeFile);

        /* Load in default inventory attributes */
        status = TRUSTEDGE_agentComputeInventoryAttributes(pAgentCtx, FALSE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_agentProcessDesiredAttributes(
            pAgentCtx, pJCtx, 0, DEVICE_ATTRIBUTES_JSTR);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = COMMON_UTILS_addPathComponent(
        pAgentCtx->pConfig->pConfDir, TRUSTEDGE_DESIRED_ATTRIBUTE_FILE,
        &pAgentCtx->pDesiredAttributeFile);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pAgentCtx->pDesiredAttributeFile, NULL))
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE, "Reading desired attributes from %s\n", pAgentCtx->pDesiredAttributeFile);

        /* Add desired attributes from file */
        status = TRUSTEDGE_agentProtobufLoadMetricFile(
            pAgentCtx, TE_DESIRED_ATTRIBUTES_FILE);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = JSON_getJsonArrayValue(
        pJCtx, 0, AUTHENTICATION_JSTR, &authNdx, &authToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), AUTHENTICATION_JSTR);
        goto exit;
    }

    /* Loop through authentication methods */
    authNdx++;
    for (i = 0; i < authToken.elemCnt; i++)
    {
        status = JSON_getJsonStringValue(
            pJCtx, authNdx, METHOD_JSTR, &pMethod, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Unable to read %s attribute\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), METHOD_JSTR);
            goto exit;
        }

        if (0 == DIGI_STRCMP(pMethod, X509_JSTR))
        {
            status = JSON_getJsonStringValue(
                pJCtx, authNdx, CERT_ALIAS_JSTR, &pCertHandle, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Unable to read %s attribute\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), CERT_ALIAS_JSTR);
                goto exit;
            }

            status = COMMON_UTILS_addPathComponent(
                pAgentCtx->pConfig->pKeystoreCertsDir, pCertHandle, &pPath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = DIGICERT_readFile(pPath, (ubyte **) &pAuthCert, &authCertLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Could not read authentication certificate from %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pPath);
                goto exit;
            }
            DIGI_FREE((void **) &pPath);

            status = CA_MGMT_decodeCertificate(
                pAuthCert, authCertLen,
                &pAgentCtx->configOptions.pAuthCert,
                &pAgentCtx->configOptions.authCertLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_utilsValidateCert(
                pAgentCtx->pTrustedStore,
                pAgentCtx->configOptions.pAuthCert,
                pAgentCtx->configOptions.authCertLen, FALSE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Failed to validate certificate %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pHandle);
                goto exit;
            }

            status = JSON_getJsonStringValue(
                pJCtx, authNdx, KEY_ALIAS_JSTR, &pHandle, TRUE);
            if (OK == status)
            {
                status = COMMON_UTILS_addPathComponent(
                    pAgentCtx->pConfig->pKeystoreKeysDir, pHandle, &pPath);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = DIGICERT_readFile(pPath, (ubyte **) &pAuthKey, &authKeyLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s. Could not read authentication key from %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status), pPath);
                    goto exit;
                }

                /* Store key in memory as DER format, more efficient */
                status = CA_MGMT_decodeCertificate(
                    pAuthKey, authKeyLen,
                    &pAgentCtx->configOptions.pAuthKey,
                    &pAgentCtx->configOptions.authKeyLen);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
            else
            {
                MSG_LOG_print(MSG_LOG_INFO,
                    "Searching for private key for certificate %s\n", pCertHandle);

                status = TRUSTEDGE_utilsFindPrivateKey(
                    pAgentCtx->pConfig->pKeystoreKeysDir,
                    pAgentCtx->configOptions.pAuthCert,
                    pAgentCtx->configOptions.authCertLen,
                    &pAgentCtx->configOptions.pAuthKey,
                    &pAgentCtx->configOptions.authKeyLen,
                    &pBootstrapKeyFile);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s. Failed to find private key\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_AUTH_METHOD_UNKNOWN;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Authentication method %s not supported\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pMethod);
            goto exit;
        }

        /* Currently, only one authentication method is allowed. No need to
         * process the remaining elements in the authentication JSON array
         *
         * TODO: When allowing multiple authentication methods, need to
         * determine how behaviour works when connecting to MQTT endpoint.
         * Loop through endpoints with each authentication method or loop
         * through authentication methods with each endpoint? Assume the former,
         * need to confirm */
        break;
    }

    if (NULL != pBootstrapKeyFile)
    {
        /* Update alias in bootstrap configuration file */
        status = TRUSTEDGE_utilsUpdateBootstrapConfig(
            pAgentCtx->pBootstrapConfigFile,
            pBootstrapKeyFile,
            FALSE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to update bootstrap configuration file with key alias\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = OK;

exit:

    DIGI_FREE((void **) &pAttributeFile);
    DIGI_FREE((void **) &pScheme);
    DIGI_FREE((void **) &pPath);
    DIGI_FREE((void **) &pHandle);
    DIGI_FREE((void **) &pCertHandle);
    DIGI_FREE((void **) &pAuthCert);
    DIGI_FREE((void **) &pAuthKey);
    DIGI_FREE((void **) &pEndpoint);
    DIGI_FREE((void **) &pMethod);
    DIGI_FREE((void **) &pName);
    DIGI_FREE((void **) &pValue);
    DIGI_FREE((void **) &pAttrVal);
    JSON_releaseContext(&pJCtx);
    DIGI_FREE((void **) &pConfig);
    DIGI_FREE((void **) &pSigToken);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttConnAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttConnAckInfo *pInfo)
{
    MOC_UNUSED(pMsg);
    MSTATUS status;
    TrustEdgeAgentCtx *pAgentCtx = NULL;
    sbyte *pReasonString = NULL;

    status = MQTT_getCookie(connectionInstance, (void **) &pAgentCtx);
    if (OK != status)
    {
        goto exit;
    }

    if (0 == pInfo->reasonCode)
    {
        MSG_LOG_print(
            MSG_LOG_INFO, "%s", "Connection established to MQTT endpoint\n");
        status = OK;
    }
    else
    {
        if (OK != MQTT_getConnackReasonString(connectionInstance, pInfo->reasonCode, &pReasonString))
        {
            pReasonString = "UNKNOWN";
        }
        MSG_LOG_print(
            MSG_LOG_ERROR,
            "Connection to MQTT endpoint failed with reason code: %d (%s)\n",
            pInfo->reasonCode, pReasonString);
        if (NULL != pInfo->pReasonStr)
        {
            MSG_LOG_print(
                MSG_LOG_ERROR,
                "Reason string: %.*s\n", pInfo->reasonStrLen, pInfo->pReasonStr);
        }
        status = ERR_TRUSTEDGE_AGENT_MQTT_CONNECT_FAILED;
    }

    pAgentCtx->mqttConfig.status = status;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttSubAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttSubAckInfo *pInfo)
{
    MOC_UNUSED(pMsg);
    MSTATUS status;
    ubyte4 i;
    TrustEdgeAgentCtx *pAgentCtx = NULL;

    status = MQTT_getCookie(connectionInstance, (void **) &pAgentCtx);
    if (OK != status)
    {
        goto exit;
    }

    pAgentCtx->policyReqTimeoutExit = TRUE;

    for (i = 0; i < pInfo->QoSCount; i++)
    {
        if (0 != *(pInfo->pQoS + i) && 1 != *(pInfo->pQoS + i) && 2 != *(pInfo->pQoS + i))
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Failed to subscribe to topic with message ID %d\n", pInfo->msgId);
            if (NULL != pInfo->pReasonStr)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "Reason string: %.*s\n", pInfo->reasonStrLen, pInfo->pReasonStr);
            }
            pAgentCtx->mqttConfig.status = ERR_TRUSTEDGE_AGENT_TOPIC_SUBSCRIBE;
            goto exit;
        }
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#define JWS_AUTH_HEADER     "{\"alg\":\"%s\",\"typ\":\"JWT\",\"x5t#S256\":\"%s\",\"x5c\":[\"%s\"]}"
#define JWS_AUTH_PAYLOAD    "{\"device_id\":\"%s\",\"account_id\":\"%s\",\"division_id\":\"%s\",\"device_group_id\":\"%s\",\"exp\":\"%lu\",\"source\":\"%s\"}"

static MSTATUS TRUSTEDGE_agentCreateJWSAuthHeader(
    TrustEdgeAgentCtx *pCtx,
    JWSAlg alg,
    sbyte **ppHeader)
{
    MSTATUS status;
    ubyte pFingerprint[SHA256_RESULT_SIZE];
    ubyte *pEncodedFingerprint = NULL;
    ubyte4 encodedFingerprintLen = 0;
    ubyte *pBase64Cert = NULL;
    ubyte4 base64CertLen = 0;
    ubyte4 len;
    int ret;
    sbyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    sbyte *pAlg = NULL;

    /* Input validation not required */

    switch (alg)
    {
        case JWS_ALG_RS256:
            pAlg = JWS_AUTH_HEADER_ALG_RS256;
            break;
        case JWS_ALG_RS384:
            pAlg = JWS_AUTH_HEADER_ALG_RS384;
            break;
        case JWS_ALG_RS512:
            pAlg = JWS_AUTH_HEADER_ALG_RS512;
            break;
        case JWS_ALG_ES256:
            pAlg = JWS_AUTH_HEADER_ALG_ES256;
            break;
        case JWS_ALG_ES384:
            pAlg = JWS_AUTH_HEADER_ALG_ES384;
            break;
        case JWS_ALG_ES512:
            pAlg = JWS_AUTH_HEADER_ALG_ES512;
            break;
        case JWS_ALG_PS256:
            pAlg = JWS_AUTH_HEADER_ALG_PS256;
            break;
        case JWS_ALG_PS384:
            pAlg = JWS_AUTH_HEADER_ALG_PS384;
            break;
        case JWS_ALG_PS512:
            pAlg = JWS_AUTH_HEADER_ALG_PS512;
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
            pAlg = JWS_AUTH_HEADER_ALG_MLDSA44;
            break;
        case JWS_ALG_MLDSA65:
            pAlg = JWS_AUTH_HEADER_ALG_MLDSA65;
            break;
        case JWS_ALG_MLDSA87:
            pAlg = JWS_AUTH_HEADER_ALG_MLDSA87;
            break;
        case JWS_ALG_SLHDSA_SHA2_128F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128F;
            break;
        case JWS_ALG_SLHDSA_SHA2_128S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128S;
            break;
        case JWS_ALG_SLHDSA_SHA2_192F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192F;
            break;
        case JWS_ALG_SLHDSA_SHA2_192S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192S;
            break;
        case JWS_ALG_SLHDSA_SHA2_256F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256F;
            break;
        case JWS_ALG_SLHDSA_SHA2_256S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_128F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_128S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_192F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_192S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192S;
            break;
        case JWS_ALG_SLHDSA_SHAKE_256F:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256F;
            break;
        case JWS_ALG_SLHDSA_SHAKE_256S:
            pAlg = JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256S;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
    }

    status = CRYPTO_INTERFACE_SHA256_completeDigest(
        pCtx->configOptions.pAuthCert, pCtx->configOptions.authCertLen,
        pFingerprint);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_urlEncodeMessage(
        pFingerprint, sizeof(pFingerprint),
        &pEncodedFingerprint, &encodedFingerprintLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pEncodedFingerprint[encodedFingerprintLen] = '\0';

    status = BASE64_encodeMessage(
        pCtx->configOptions.pAuthCert, pCtx->configOptions.authCertLen,
        &pBase64Cert, &base64CertLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pBase64Cert[base64CertLen] = '\0';

    ret = snprintf(NULL, 0, JWS_AUTH_HEADER,
                        pAlg,
                        pEncodedFingerprint,
                        pBase64Cert);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to retreive message size\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    msgLen = ret;

    status = DIGI_MALLOC((void **) &pMsg, msgLen + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pMsg, msgLen + 1, JWS_AUTH_HEADER,
                        pAlg,
                        pEncodedFingerprint,
                        pBase64Cert);
    if ( (0 > ret) || ((sbyte4) msgLen != ret) )
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n. Failed to construct message",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_urlEncodeMessage(pMsg, msgLen, (ubyte **) ppHeader, &len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppHeader)[len] = '\0';

exit:

    DIGI_FREE((void **) &pEncodedFingerprint);
    DIGI_FREE((void **) &pBase64Cert);
    DIGI_FREE((void **) &pMsg);

    return status;
}

static MSTATUS TRUSTEDGE_agentCreateJWSAuthPayload(
    TrustEdgeAgentCtx *pCtx,
    sbyte **ppPayload)
{
    MSTATUS status;
    int ret;
    ubyte4 msgLen = 0;
    ubyte4 len;
    ubyte4 elapsedTime;
    sbyte *pMsg = NULL;

    /* Input validation not required */

    status = TRUSTEDGE_utilsGetElapsedTime(&elapsedTime);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* TODO: What is good expiration time to set in JWS? */
    elapsedTime += 300;

    ret = snprintf(NULL, 0, JWS_AUTH_PAYLOAD,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDivisionId,
                        pCtx->configOptions.pDeviceGroupId,
                        (unsigned long)elapsedTime,
                        TRUSTEDGE_SOURCE);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to retrieve message size\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    msgLen = ret;

    status = DIGI_MALLOC((void **) &pMsg, msgLen + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pMsg, msgLen + 1, JWS_AUTH_PAYLOAD,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDivisionId,
                        pCtx->configOptions.pDeviceGroupId,
                        (unsigned long)elapsedTime,
                        TRUSTEDGE_SOURCE);
    if ((0 > ret) || ((sbyte4) msgLen != ret))
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n. Failed to construct message",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_urlEncodeMessage(pMsg, msgLen, (ubyte **) ppPayload, &len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppPayload)[len] = '\0';

exit:

    DIGI_FREE((void **) &pMsg);
    return status;
}

static MSTATUS TRUSTEDGE_agentCreateJWSAuthSignature(
    TrustEdgeAgentCtx *pAgentCtx,
    AsymmetricKey *pAsymKey,
    JWSAlg alg,
    sbyte *pHeader,
    sbyte *pPayload,
    sbyte **ppSignature)
{
    MOC_UNUSED(pAgentCtx);
    MSTATUS status;
    BulkCtx pCtx = NULL;
    ubyte pDigest[SHA512_RESULT_SIZE];
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;
    sbyte4 sigLen = 0;
    ubyte *pSig = NULL;
    ubyte4 len;
    BulkHashAlgo *pBulkHashAlgo = NULL;
    ubyte4 hashId = 0;
    ubyte4 saltLen = 0;
    ubyte *pFullMsg = NULL;
    ubyte4 fullMsgLen = 0;
    sbyte4 headerLen, payloadLen;

    switch (alg)
    {
        case JWS_ALG_RS256:
            status = CRYPTO_getRSAHashAlgo(ht_sha256, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_RS384:
            status = CRYPTO_getRSAHashAlgo(ht_sha384, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_RS512:
            status = CRYPTO_getRSAHashAlgo(ht_sha512, (const BulkHashAlgo **) &pBulkHashAlgo);
            break;

        case JWS_ALG_ES256:
            status = CRYPTO_getECCHashAlgo(ht_sha256, &pBulkHashAlgo);
            break;

        case JWS_ALG_ES384:
            status = CRYPTO_getECCHashAlgo(ht_sha384, &pBulkHashAlgo);
            break;

        case JWS_ALG_ES512:
            status = CRYPTO_getECCHashAlgo(ht_sha512, &pBulkHashAlgo);
            break;

        case JWS_ALG_PS256:
            hashId = ht_sha256;
            saltLen = SHA256_RESULT_SIZE;
            status = OK;
            break;
        case JWS_ALG_PS384:
            hashId = ht_sha384;
            saltLen = SHA384_RESULT_SIZE;
            status = OK;
            break;
        case JWS_ALG_PS512:
            hashId = ht_sha512;
            saltLen = SHA512_RESULT_SIZE;
            status = OK;
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            hashId = ht_none;
            saltLen = 0;
            status = OK;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            break;
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pBulkHashAlgo)
    {
        status = pBulkHashAlgo->allocFunc(&pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->initFunc(pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->updateFunc(
            pCtx, pHeader, DIGI_STRLEN(pHeader));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->updateFunc(pCtx, ".", 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->updateFunc(
            pCtx, pPayload, DIGI_STRLEN(pPayload));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pBulkHashAlgo->finalFunc(pCtx, pDigest);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
    {
        headerLen = DIGI_STRLEN(pHeader);
        payloadLen = DIGI_STRLEN(pPayload);
        fullMsgLen = headerLen + 1 + payloadLen;

        status = DIGI_MALLOC((void **) &pFullMsg, fullMsgLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        DIGI_MEMCPY(pFullMsg, pHeader, headerLen);
        DIGI_MEMCPY(pFullMsg + headerLen, ".", 1);
        DIGI_MEMCPY(pFullMsg + headerLen + 1, pPayload, payloadLen);
    }

    switch (alg)
    {
        case JWS_ALG_RS256:
        case JWS_ALG_RS384:
        case JWS_ALG_RS512:
            status = ASN1_buildDigestInfoAlloc(
                pDigest, pBulkHashAlgo->digestSize, pBulkHashAlgo->hashId,
                &pDigestInfo, &digestInfoLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(
                pAsymKey->key.pRSA, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_ES256:
        case JWS_ALG_ES384:
        case JWS_ALG_ES512:
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
                pAsymKey->key.pECC, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            sigLen *= 2;
            break;

        case JWS_ALG_PS256:
        case JWS_ALG_PS384:
        case JWS_ALG_PS512:
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pAsymKey->pQsCtx, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;
#endif
        case JWS_ALG_NONE:
            status = ERR_TRUSTEDGE_AGENT;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
    }

    if (0 != sigLen)
    {
        status = DIGI_MALLOC((void **) &pSig, sigLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    switch (alg)
    {
        case JWS_ALG_RS256:
        case JWS_ALG_RS384:
        case JWS_ALG_RS512:
            status = CRYPTO_INTERFACE_RSA_signMessageAux(
                pAsymKey->key.pRSA, pDigestInfo, digestInfoLen, pSig, NULL);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_ES256:
        case JWS_ALG_ES384:
        case JWS_ALG_ES512:
            status = CRYPTO_INTERFACE_ECDSA_signDigestAux(
                pAsymKey->key.pECC, RANDOM_rngFun, g_pRandomContext, pDigest,
                pBulkHashAlgo->digestSize, pSig, sigLen, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case JWS_ALG_PS256:
        case JWS_ALG_PS384:
        case JWS_ALG_PS512:
            status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(
                g_pRandomContext, pAsymKey->key.pRSA, hashId,
                MOC_PKCS1_ALG_MGF1, hashId, pFullMsg, fullMsgLen, saltLen,
                &pSig, &sigLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

#ifdef __ENABLE_DIGICERT_PQC__
        case JWS_ALG_MLDSA44:
        case JWS_ALG_MLDSA65:
        case JWS_ALG_MLDSA87:
        case JWS_ALG_SLHDSA_SHA2_128F:
        case JWS_ALG_SLHDSA_SHA2_128S:
        case JWS_ALG_SLHDSA_SHA2_192F:
        case JWS_ALG_SLHDSA_SHA2_192S:
        case JWS_ALG_SLHDSA_SHA2_256F:
        case JWS_ALG_SLHDSA_SHA2_256S:
        case JWS_ALG_SLHDSA_SHAKE_128F:
        case JWS_ALG_SLHDSA_SHAKE_128S:
        case JWS_ALG_SLHDSA_SHAKE_192F:
        case JWS_ALG_SLHDSA_SHAKE_192S:
        case JWS_ALG_SLHDSA_SHAKE_256F:
        case JWS_ALG_SLHDSA_SHAKE_256S:
            status = CRYPTO_INTERFACE_QS_SIG_sign(pAsymKey->pQsCtx, RANDOM_rngFun, g_pRandomContext, pFullMsg, fullMsgLen,
                                                  pSig, sigLen, &sigLen);

            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;
#endif
        case JWS_ALG_NONE:
            status = ERR_TRUSTEDGE_AGENT;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
    }

    status = BASE64_urlEncodeMessage(
        pSig, sigLen, (ubyte **) ppSignature, &len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppSignature)[len] = '\0';

exit:

    DIGI_FREE((void **) &pFullMsg);
    DIGI_FREE((void **) &pDigestInfo);
    CRYPTO_INTERFACE_SHA256_freeDigest(&pCtx);
    DIGI_FREE((void **) &pSig);

    return status;
}

static MSTATUS TRUSTEDGE_agentGetJWSAlg(
    AsymmetricKey *pAsymKey,
    JWSAlg *pAlg)
{
    MSTATUS status;
    sbyte4 lenRsaN;
    ubyte4 curveId;

    switch (pAsymKey->type & 0xFF)
    {
        case akt_rsa:
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(pSSLSock->hwAccelCookie)
                pAsymKey->key.pRSA, &lenRsaN);
            if (OK != status)
            {
                goto exit;
            }

            if (NULL != pAsymKey->pAlgoId &&
                ALG_ID_RSA_SSA_PSS_OID == pAsymKey->pAlgoId->oidFlag)
            {
                if (256 == lenRsaN)
                    *pAlg = JWS_ALG_PS256;
                else if (384 == lenRsaN)
                    *pAlg = JWS_ALG_PS384;
                else if (512 == lenRsaN)
                    *pAlg = JWS_ALG_PS512;
                else
                {
                    status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
                    goto exit;
                }
            }
            else
            {
                if (256 == lenRsaN)
                    *pAlg = JWS_ALG_RS256;
                else if (384 == lenRsaN)
                    *pAlg = JWS_ALG_RS384;
                else if (512 == lenRsaN)
                    *pAlg = JWS_ALG_RS512;
                else
                {
                    status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
                    goto exit;
                }
            }
            break;

        case akt_ecc:
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
                pAsymKey->key.pECC, &curveId);
            if (OK != status)
            {
                goto exit;
            }

            if (cid_EC_P256 == curveId)
                *pAlg = JWS_ALG_ES256;
            else if (cid_EC_P384 == curveId)
                *pAlg = JWS_ALG_ES384;
            else if (cid_EC_P521 == curveId)
                *pAlg = JWS_ALG_ES512;
            else
            {
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
            }
            break;

#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
            status = CRYPTO_INTERFACE_QS_getAlg(pAsymKey->pQsCtx, &curveId); /* reuse curveId var for pqc alg */
            if (OK != status)
            {
                goto exit;
            }

            if (cid_PQC_MLDSA_44 == curveId)
                *pAlg = JWS_ALG_MLDSA44;
            else if (cid_PQC_MLDSA_65 == curveId)
                *pAlg = JWS_ALG_MLDSA65;
            else if (cid_PQC_MLDSA_87 == curveId)
                *pAlg = JWS_ALG_MLDSA87;
            else if (cid_PQC_SLHDSA_SHA2_128F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_128F;
            else if (cid_PQC_SLHDSA_SHA2_128S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_128S;
            else if (cid_PQC_SLHDSA_SHA2_192F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_192F;
            else if (cid_PQC_SLHDSA_SHA2_192S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_192S;
            else if (cid_PQC_SLHDSA_SHA2_256F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_256F;
            else if (cid_PQC_SLHDSA_SHA2_256S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHA2_256S;
            else if (cid_PQC_SLHDSA_SHAKE_128F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_128F;
            else if (cid_PQC_SLHDSA_SHAKE_128S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_128S;
            else if (cid_PQC_SLHDSA_SHAKE_192F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_192F;
            else if (cid_PQC_SLHDSA_SHAKE_192S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_192S;
            else if (cid_PQC_SLHDSA_SHAKE_256F == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_256F;
            else if (cid_PQC_SLHDSA_SHAKE_256S == curveId)
                *pAlg = JWS_ALG_SLHDSA_SHAKE_256S;
            else
            {
                status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
                goto exit;
            }
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
            break;
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentCreateJWSAuth(
    TrustEdgeAgentCtx *pCtx,
    sbyte **ppJWSAuth)
{
    MSTATUS status;
    sbyte *pHeader = NULL;
    sbyte *pPayload = NULL;
    sbyte *pSignature = NULL;
    sbyte *pIter;
    sbyte *pAuth = NULL;
    sbyte4 len;
    JWSAlg alg = JWS_ALG_NONE;

    AsymmetricKey asymKey = { 0 };

    CRYPTO_initAsymmetricKey(&asymKey);

    status = CRYPTO_deserializeAsymKey(
        pCtx->configOptions.pAuthKey, pCtx->configOptions.authKeyLen,
        NULL, &asymKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to deserialize authorization key\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentGetJWSAlg(&asymKey, &alg);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }


    status = TRUSTEDGE_agentCreateJWSAuthHeader(pCtx, alg, &pHeader);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentCreateJWSAuthPayload(pCtx, &pPayload);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentCreateJWSAuthSignature(
        pCtx, &asymKey, alg, pHeader, pPayload, &pSignature);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    len = DIGI_STRLEN(pHeader) + 1 + DIGI_STRLEN(pPayload) + 1 + DIGI_STRLEN(pSignature);
    status = DIGI_MALLOC((void **) &pAuth, len + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pIter = pAuth;

    DIGI_MEMCPY(pIter, pHeader, DIGI_STRLEN(pHeader));
    pIter += DIGI_STRLEN(pHeader);

    *pIter++ = '.';

    DIGI_MEMCPY(pIter, pPayload, DIGI_STRLEN(pPayload));
    pIter += DIGI_STRLEN(pPayload);

    *pIter++ = '.';

    DIGI_MEMCPY(pIter, pSignature, DIGI_STRLEN(pSignature));
    pIter += DIGI_STRLEN(pSignature);

    *pIter = '\0';

    *ppJWSAuth = pAuth;

exit:

    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pPayload);
    DIGI_FREE((void **) &pHeader);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParsePendingPolicies(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen)
{
    MSTATUS status;
    ubyte4 i, j, ndx, dependencyNdx;
    JSON_TokenType token = { 0 };
    JSON_TokenType policyToken = { 0 };
    JSON_TokenType dependencyToken = { 0 };
    sbyte *pDivisionId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pPolicyType = NULL;
    sbyte *pAuthorizationToken = NULL;
    TrustEdgeAgentPolicyType policyType;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte4 priority;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    TrustEdgeAgentPolicyNode *pFound = NULL;
    ubyte *pBase64DecodedAuthToken = NULL;
    ubyte4 base64DecodedAuthTokLen = 0;
    TrustEdgeAgentPolicyDependency *pDependentPolicy = NULL;
#ifdef __ENABLE_DIGICERT_TOKEN_MISSING_FALLBACK__
    pCtx->isPAT = TRUE;
#endif
    TrustEdgeAgentPolicyNode *pNewPendingPolicyList = NULL;

    /* Input validation not required */

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "divisionId", &pDivisionId, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == pCtx->configOptions.pDivisionId ||
     0 != DIGI_STRNCMP(pDivisionId, pCtx->configOptions.pDivisionId, DIGI_STRLEN(pDivisionId)))
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_WARNING,
            "Division ID %s does not match\n", pDivisionId);
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "accountId", &pAccountId, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == pCtx->configOptions.pAccountId ||
     0 != DIGI_STRNCMP(pAccountId, pCtx->configOptions.pAccountId, DIGI_STRLEN(pAccountId)))
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_WARNING,
            "Account ID %s does not match\n", pAccountId);
        goto exit;
    }

    if (TE_TOPIC_NCMD == pCtx->curTopic)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "deviceId", &pDeviceId, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        if (NULL == pCtx->configOptions.pDeviceId ||
            0 != DIGI_STRNCMP(pDeviceId, pCtx->configOptions.pDeviceId, DIGI_STRLEN(pDeviceId)))
        {
            status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
            MSG_LOG_print(MSG_LOG_WARNING,
                "Device ID %s does not match\n", pDeviceId);
            goto exit;
        }
    }
    else if (TE_TOPIC_GCMD == pCtx->curTopic)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "deviceGroupId", &pDeviceId, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        if (NULL == pCtx->configOptions.pDeviceGroupId ||
            0 != DIGI_STRNCMP(pDeviceId, pCtx->configOptions.pDeviceGroupId, DIGI_STRLEN(pDeviceId)))
        {
            status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
            MSG_LOG_print(MSG_LOG_WARNING,
                "Device Group ID %s does not match\n", pDeviceId);
            goto exit;
        }
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "pendingPolicies", &ndx, &token, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == pCtx->enforceToken)
    {
        if (token.elemCnt > 0)
        {
            status = JSON_getJsonStringValue(
                pJCtx, 0, "authorizationToken", &pAuthorizationToken, TRUE);
            if (OK != status)
            {
#ifdef __ENABLE_DIGICERT_TOKEN_MISSING_FALLBACK__
                pCtx->isPAT = FALSE;
#endif
                status = ERR_TRUSTEDGE_AGENT_NO_POLICY_AUTH_TOKEN;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s", "No policy authorization token found\n");

                goto exit;
            }
        }
        else
        {
            (void) JSON_getJsonStringValue(
                pJCtx, 0, "authorizationToken", &pAuthorizationToken, TRUE);
        }

        if (NULL != pAuthorizationToken)
        {
            status = BASE64_decodeMessage(
                pAuthorizationToken, DIGI_STRLEN(pAuthorizationToken),
                    &pBase64DecodedAuthToken, &base64DecodedAuthTokLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_utilsProcessJWT(
                pCtx->configOptions.pAccountId,
                pCtx->configOptions.pDeviceId,
                pCtx->configOptions.pDivisionId,
                pBase64DecodedAuthToken, base64DecodedAuthTokLen, pCtx->pTrustedStore);
            if (OK != status)
            {
                DIGI_FREE((void **) &pBase64DecodedAuthToken);
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            DIGI_FREE((void **) &(pCtx->pPatData));
            status = DIGI_MALLOC_MEMCPY((void **) &pCtx->pPatData, DIGI_STRLEN(pAuthorizationToken) + 1, pAuthorizationToken, DIGI_STRLEN(pAuthorizationToken));
            DIGI_FREE((void **) &pBase64DecodedAuthToken);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            pCtx->pPatData[DIGI_STRLEN(pAuthorizationToken)] = '\0';

            MSG_LOG_print(MSG_LOG_INFO, "Writing policy authorization to %s\n",
                pCtx->pPatFile);
            status = DIGICERT_writeFile(pCtx->pPatFile, pCtx->pPatData, DIGI_STRLEN(pAuthorizationToken));
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Unable to write policy authorization token to %s\n", pCtx->pPatFile);
                goto exit;
            }
        }

    }

    if (NULL != pCtx->curPolicy.pPolicy)
    {
        pNewPendingPolicyList = pCtx->curPolicy.pPolicy;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &policyToken);
        if (OK != status)
        {
            goto exit;
        }

        if (JSON_Object != policyToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        DIGI_FREE((void **) &pDeviceGroupId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK == status && (NULL != pCtx->configOptions.pDeviceGroupId) &&
            0 == DIGI_STRNCMP(pDeviceGroupId, pCtx->configOptions.pDeviceGroupId, DIGI_STRLEN(pDeviceGroupId)))
        {
            DIGI_FREE((void **) &pPolicyId);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "policyId", &pPolicyId, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Missing policyId, skipping policy at index %d\n", i);
                goto next;
            }

            DIGI_FREE((void **) &pPolicyType);
            status = JSON_getJsonStringValue(
                pJCtx, ndx, "policyType", &pPolicyType, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Missing policyType, skipping policy with ID %s\n", pPolicyId);
                goto next;
            }

            if (0 == DIGI_STRCMP(pPolicyType, "CERTIFICATE"))
            {
                policyType = TE_POLICY_TYPE_CERTIFICATE;
            }
            else if (0 == DIGI_STRCMP(pPolicyType, "UPDATE"))
            {
                policyType = TE_POLICY_TYPE_UPDATE;
            }
            else if (0 == DIGI_STRCMP(pPolicyType, "CLOUDPLATFORM"))
            {
                policyType = TE_POLICY_TYPE_CLOUDPLATFORM;
            }
            else
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Unknown policy type %s, skipping policy with ID %s\n", pPolicyType, pPolicyId);
                goto next;
            }

            status = JSON_getJsonIntegerValue(
                pJCtx, ndx, "priority", &priority, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Missing priority, skipping policy with ID %s\n", pPolicyId);
                goto next;
            }

            if (TE_POLICY_TYPE_UPDATE == policyType)
            {
                DIGI_FREE((void **) &pDeploymentId);
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "deploymentId", &pDeploymentId, TRUE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_WARNING,
                        "Missing deploymentId, skipping policy with ID %s\n", pPolicyId);
                    goto next;
                }
            }

            if (TE_POLICY_TYPE_CLOUDPLATFORM == policyType)
            {
                status = JSON_getJsonArrayValue(pJCtx, ndx, "policyDependency", &dependencyNdx, &dependencyToken, TRUE);
                if (OK != status)
                {
                    goto exit;
                }

                if (dependencyToken.elemCnt > 0)
                {
                    status = DIGI_CALLOC((void **) &pDependentPolicy, 1, sizeof(TrustEdgeAgentPolicyDependency));
                    if (OK != status)
                    {
                        goto exit;
                    }

                    pDependentPolicy->count = dependencyToken.elemCnt;

                    status = DIGI_CALLOC((void **) &pDependentPolicy->pPolicies, dependencyToken.elemCnt, sizeof(TrustEdgeAgentPolicyDependencyFields));
                    if (OK != status)
                    {
                        goto exit;
                    }
                }

                for (j = 0; j < dependencyToken.elemCnt; j++)
                {
                    dependencyNdx++;

                    status = JSON_getJsonStringValue(
                        pJCtx, dependencyNdx, "policyType", &pDependentPolicy->pPolicies[j].pPolicyType, TRUE);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_WARNING,
                            "Missing policyType, skipping policy with ID %s\n", pPolicyId);
                        goto next;
                    }

                    status = JSON_getJsonStringValue(
                        pJCtx, dependencyNdx, "policyId", &pDependentPolicy->pPolicies[j].pPolicyId, TRUE);

                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_WARNING,
                            "Missing policyId, skipping policy with ID %s\n", pPolicyId);
                        goto next;
                    }

                    status = JSON_getLastIndexInObject(pJCtx, dependencyNdx, &dependencyNdx);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }
            }

            status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
                pCtx->pAppliedPolicies, pPolicyId, policyType, &pFound);
            if (OK != status)
            {
                goto exit;
            }

            if (NULL == pFound)
            {
                /* Check if policy is in error policy list */
                status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
                    pCtx->pErrorPolicies, pPolicyId, policyType, &pFound);
                if (OK != status)
                {
                    goto exit;
                }

                if (NULL != pFound)
                {
                    status = TRUSTEDGE_agentPolicyUnlinkNode(
                        pFound, &pCtx->pErrorPolicies);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = TRUSTEDGE_agentPolicyDeleteNode(&pFound);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }

                /* Add policy to pending policy list */
                status = TRUSTEDGE_agentPolicyAddNode(
                    policyType, &pDeviceGroupId, &pPolicyId, &pDeploymentId,
                    priority, NULL, NULL, NULL, &pDependentPolicy, FALSE, 0, &pNewPendingPolicyList);
                if (OK != status)
                {
                    goto exit;
                }

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
                TRUSTEDGE_setState(PROCESSING_POLICY);
#endif
            }
            else
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Policy ID %s already exists in applied policies\n", pPolicyId);

                if (TE_POLICY_TYPE_UPDATE == policyType)
                {
                    /* this does not change state, so if this fails, just ignore */
                    (void) TRUSTEDGE_agentSendUpdatePolicyDeploymentStatus(pCtx,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pFound->pDeviceGroupId,
                        pFound->pId,
                        pFound->pDeploymentId,
                        pCtx->pPatData,
                        TRUE, NULL, NULL);
                }
                else if (TE_POLICY_TYPE_CERTIFICATE == policyType)
                {
                    (void) TRUSTEDGE_agentSendCertificateStatus(pCtx,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pFound->pDeviceGroupId,
                        pFound->pId,
                        pCtx->pPatData,
                        TRUE,
                        pCtx->curPolicy.stage,
                        OK);
                }
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "Device Group ID %s does not match\n", pDeviceGroupId);
        }

next:

        status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
        if (OK != status)
        {
            goto exit;
        }
    }

    pCtx->recievedPendingPolicies = TRUE;

    if (NULL != pCtx->pPendingPolicies)
    {
        if (NULL != pCtx->curPolicy.pPolicy)
        {
            status = TRUSTEDGE_agentPolicyUnlinkNode(
                pCtx->curPolicy.pPolicy, &pCtx->pPendingPolicies);
            if (OK != status)
            {
                goto exit;
            }
        }

        status = TRUSTEDGE_agentPolicyDeleteNodes(&pCtx->pPendingPolicies);
        if (OK != status)
        {
            goto exit;
        }
    }

    pCtx->pPendingPolicies = pNewPendingPolicyList;
    pNewPendingPolicyList = NULL;

    TRUSTEDGE_agentPolicyPrintNodes(pCtx->pPendingPolicies);

exit:

    TRUSTEDGE_agentPolicyDeleteNodes(&pNewPendingPolicyList);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pDivisionId);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pPolicyType);
    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pAuthorizationToken);
    TRUSTEDGE_freeDependentPolicies(pDependentPolicy);
    JSON_releaseContext(&pJCtx);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentCertSpecGenKey(
    CertEnrollAlg alg,
    TrustEdgeAgentKeySource keySrc,
    AsymmetricKey **ppNewKey
#if defined(__ENABLE_DIGICERT_TAP__)
    ,CertEnrollTAPAttributes *pAttributes
#endif
)
{
    MSTATUS status = OK;
    KeyGenArgs genArgs = { 0 };
#if defined(__ENABLE_DIGICERT_TAP__)
    KeyGenTapArgs tapArgs = { 0 };
#endif
    AsymmetricKey *pNewKey = NULL;

    switch (alg)
    {
        case rsa2048:
            genArgs.gKeyType = akt_rsa;
            genArgs.gKeySize = 2048;
            break;
        case rsa3072:
            genArgs.gKeyType = akt_rsa;
            genArgs.gKeySize = 3072;
            break;
        case rsa4096:
            genArgs.gKeyType = akt_rsa;
            genArgs.gKeySize = 4096;
            break;
        case ecdsaP256:
            genArgs.gKeyType = akt_ecc;
            genArgs.gKeySize = 256;
            genArgs.gCurve = cid_EC_P256;
            break;
        case ecdsaP384:
            genArgs.gKeyType = akt_ecc;
            genArgs.gKeySize = 384;
            genArgs.gCurve = cid_EC_P384;
            break;
        case ecdsaP521:
            genArgs.gKeyType = akt_ecc;
            genArgs.gKeySize = 521;
            genArgs.gCurve = cid_EC_P521;
            break;
        case eddsaEd25519:
            genArgs.gKeyType = akt_ecc;
            genArgs.gCurve = cid_EC_Ed25519;
            break;
        case eddsaEd448:
            genArgs.gKeyType = akt_ecc;
            genArgs.gCurve = cid_EC_Ed448;
            break;
#ifdef __ENABLE_DIGICERT_PQC__
        case mldsa44:
            genArgs.gKeyType = akt_qs;
            genArgs.gQsAlg = cid_PQC_MLDSA_44;
            break;
        case mldsa65:
            genArgs.gKeyType = akt_qs;
            genArgs.gQsAlg = cid_PQC_MLDSA_65;
            break;
        case mldsa87:
            genArgs.gKeyType = akt_qs;
            genArgs.gQsAlg = cid_PQC_MLDSA_87;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_ALGO;
            goto exit;
    }

    switch (keySrc)
    {
        case TRUSTEDGE_KEY_SOURCE_SW:
            break;

#if defined(__ENABLE_DIGICERT_TAP__)
        case TRUSTEDGE_KEY_SOURCE_TPM2:
        case TRUSTEDGE_KEY_SOURCE_PKCS11:
            status = TRUSTEDGE_TAP_getCtx(
                &tapArgs.gpTapCtx, &tapArgs.gpTapEntityCredList,
                &tapArgs.gpTapCredList, NULL, 0, 1);
            if (OK != status)
            {
                goto exit;
            }

            genArgs.gKeyType |= 0x00020000;
            genArgs.gModNum = pAttributes->moduleId;
            genArgs.gPrimary = pAttributes->primary;
            genArgs.gHierarchy = pAttributes->hierarchy;
            genArgs.gSigScheme = pAttributes->sigScheme;
            genArgs.gEncScheme = pAttributes->encScheme;
            genArgs.gKeyUsage = pAttributes->keyUsage;
            genArgs.gpKeyHandle = pAttributes->pKeyHandle;
            genArgs.gKeyNonceHandle = pAttributes->keyNonceHandle;
            break;

#if defined(__ENABLE_DIGICERT_TEE__)
        case TRUSTEDGE_KEY_SOURCE_TEE:
            /* generated key is actually a software key, TEE secure store applies to its serialization */
            break;
#endif
#endif /* __ENABLE_DIGICERT_TAP__ */

        default:
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_SOURCE;
            goto exit;
    }

    /* internal method, NULL checks not necc */
    status = DIGI_MALLOC((void **) &pNewKey, sizeof(AsymmetricKey));
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(pNewKey);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    status = KEYGEN_generateKey(&genArgs, &tapArgs, pNewKey, g_pRandomContext);
#else
    status = KEYGEN_generateKey(&genArgs, NULL, pNewKey, g_pRandomContext);
#endif
    if (OK != status)
    {
        goto exit;
    }

    *ppNewKey = pNewKey; pNewKey = NULL;

exit:

    if (NULL != pNewKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(pNewKey, NULL);
        (void) DIGI_FREE((void **) &pNewKey);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_validateCurrentPolicy(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pDeploymentId,
    TrustEdgeAgentPolicyType type)
{
    MSTATUS status;

    if (NULL == pCtx->curPolicy.pPolicy)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, no policy currently in progress, recieved message with policy ID %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pId);
        goto exit;
    }
    else if (0 != DIGI_STRCMP(pId, pCtx->curPolicy.pPolicy->pId))
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, currently processing policy ID %s, recieved message with policy ID %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pCtx->curPolicy.pPolicy->pId, pId);
        goto exit;
    }
    else if (type != pCtx->curPolicy.pPolicy->type)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, currently processing policy type %d, recieved message with policy type %d\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pCtx->curPolicy.pPolicy->type, type);
        goto exit;
    }
    else
    {
        if (NULL != pDeviceId)
        {
            if (0 != DIGI_STRCMP(pDeviceId, pCtx->configOptions.pDeviceId))
            {
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Unexpected message, current device ID %s, recieved message with device ID %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pCtx->configOptions.pDeviceId, pDeviceId);
                goto exit;
            }
        }

        if (NULL != pAccountId)
        {
            if (0 != DIGI_STRCMP(pAccountId, pCtx->configOptions.pAccountId))
            {
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Unexpected message, current account ID %s, recieved message with account ID %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pCtx->configOptions.pAccountId, pAccountId);
                goto exit;
            }
        }

        if (NULL != pDeviceGroupId)
        {
            if (0 != DIGI_STRCMP(pDeviceGroupId, pCtx->configOptions.pDeviceGroupId))
            {
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Unexpected message, current device group ID %s, recieved message with device group ID %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pCtx->configOptions.pDeviceGroupId, pDeviceGroupId);
                goto exit;
            }
        }

        if (TE_POLICY_TYPE_UPDATE == type)
        {
            if (0 != DIGI_STRCMP(pDeploymentId, pCtx->curPolicy.pPolicy->pDeploymentId))
            {
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Unexpected message, current deployment ID %s, recieved message with depolyment ID %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pCtx->curPolicy.pPolicy->pDeploymentId, pDeploymentId);
                goto exit;
            }
        }

        status = OK;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#if 0
#define MQTT_CERTIFICATE_REQUEST_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%s\",\n" \
    "    \"csrFormat\":\"pkcs10\"\n" \
    "}\n"

static MSTATUS TRUSTEDGE_agentCertSpecSendRequest(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pReq,
    ubyte4 reqLen)
{
    MSTATUS status;
    int ret;
    sbyte *pMsg = NULL;
    ubyte *pPem = NULL;
    ubyte4 pemLen = 0;

    status = BASE64_makePemMessageAlloc(
        MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE, pReq, reqLen, &pPem, &pemLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_MSG,
                    pCtx->configOptions.pDeviceId,
                    pCtx->configOptions.pAccountId,
                    pCtx->configOptions.pDeviceGroupId,
                    pCtx->curPolicy.pPolicy->pId,
                    pPem);
    DIGI_MALLOC((void **) &pMsg, ret + 1);
    ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_MSG,
                    pCtx->configOptions.pDeviceId,
                    pCtx->configOptions.pAccountId,
                    pCtx->configOptions.pDeviceGroupId,
                    pCtx->curPolicy.pPolicy->pId,
                    pPem);

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
    TRUSTEDGE_agentKeepMsg(pCtx, "certSpec", pMsg, DIGI_STRLEN(pMsg));
#endif

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pMsg, DIGI_STRLEN(pMsg));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pPem);
    DIGI_FREE((void **) &pMsg);

    return status;
}
#endif

static MSTATUS TRUSTEDGE_agentParseCertificateSpecification(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen)
{
    MSTATUS status;
    CertEnrollAlg keyGenAlg = certEnrollAlgUndefined;
    CertEnrollAlg existingKeyGenAlg = certEnrollAlgUndefined;
    AsymmetricKey *pNewKey = NULL;

    ubyte4 reqFormatNdx;
    sbyte *pFormat = NULL;
    CertEnrollFormat reqFormat = CE_FORMAT_UNDEFIND;
    sbyte *pSpec = NULL;
    CertEnrollMode reqSpec = CE_UNDEFINED;
    sbyte *pCopy = NULL;
    sbyte *pSigAlgStr = NULL;
    ubyte4 specNdx, ndx;
    sbyte *pValue = NULL;
    ubyte4 arrNdx, srcNdx;
    JSON_TokenType arrToken = { 0 }, token = { 0 };
    JSON_TokenType keySrcToken = { 0 };
    ubyte4 i;
    ubyte *pCSR = NULL;
    ubyte4 csrLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    sbyte *pId = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pOutFile = NULL;
    sbyte *pKeyAlias = NULL;
    sbyte4 strLen;
    ubyte *pKey = NULL;
    TrustEdgeAgentCertSpec certSpec = { 0 };
    TrustEdgeAgentKeySource keySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
    TrustEdgeAgentKeySource existingKeySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
    ubyte4 sigAlg = ht_none;
    ExtendedEnrollFlow extFlow = EXT_ENROLL_FLOW_NONE;
#if defined(__ENABLE_DIGICERT_TAP__)
    intBoolean foundProvider;
    CertEnrollTAPAttributes tapAttributes = { 0 };
#endif

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "certificatePolicyId", &pId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceId", &pDeviceId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "accountId", &pAccountId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceGroupId", &pDeviceGroupId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = TRUSTEDGE_validateCurrentPolicy(pCtx, pId, pDeviceId, pAccountId,
        pDeviceGroupId, NULL, TE_POLICY_TYPE_CERTIFICATE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_RSP_PARSE;

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, "certificateSpecification", &specNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "certificateRequestFormat", &reqFormatNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, reqFormatNdx, "format", &pFormat, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == DIGI_STRCMP(pFormat, "PKCS10"))
    {
        reqFormat = CE_FORMAT_PKCS10;
    }
    else if (0 == DIGI_STRCMP(pFormat, "CMC"))
    {
        reqFormat = CE_FORMAT_CMC;
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_FORMAT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, reqFormatNdx, "specification", &pSpec, TRUE);

    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pSpec, "TRUSTED_SIGNER"))
        {
            reqSpec = CE_TRUSTED_SIGNER;
        }
        else if (0 == DIGI_STRCMP(pSpec, "TPM2_ATTEST"))
        {
            reqSpec = CE_TPM2_ATTEST;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_SPEC;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (CE_FORMAT_PKCS10 == reqFormat && ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    else if (CE_FORMAT_CMC == reqFormat && ERR_NOT_FOUND == status)
    {
        reqSpec = CE_TRUSTED_SIGNER;
        status = OK;
    }
    else
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "keyCertAttributes", &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Intentionally ignore status */
    (void) JSON_getJsonStringValue(
        pJCtx, ndx, "keyAlias", &pKeyAlias, TRUE);

    /* Assign alias */
    if (NULL != pKeyAlias)
    {
        pCtx->curPolicy.pPolicy->pAlias = pKeyAlias;
        pKeyAlias = NULL;
    }
    else
    {
        strLen = DIGI_STRLEN(pCtx->curPolicy.pPolicy->pId);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCtx->curPolicy.pPolicy->pAlias, strLen + 1,
            pCtx->curPolicy.pPolicy->pId, strLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCtx->curPolicy.pPolicy->pAlias[strLen] = '\0';
    }

    status = COMMON_UTILS_addPathComponent(pCtx->pConfig->pKeystoreKeysDir, pCtx->curPolicy.pPolicy->pAlias, &pOutFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(pOutFile, ".pem", &pOutFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pOutFile, NULL))
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "Using existing key from %s\n", pOutFile);

        status = TRUSTEDGE_utilsLoadKey(pOutFile, &pNewKey);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_utilsDetermineKeyParams(
            pNewKey, &existingKeyGenAlg, &existingKeySrc);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = JSON_getJsonArrayValue(
        pJCtx, ndx, "keyAlgorithm", &arrNdx, &arrToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    arrNdx++;
    for (i = 0; i < arrToken.elemCnt; i++)
    {
        status = JSON_getToken(pJCtx, arrNdx + i, &token);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != token.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        keyGenAlg = certEnrollAlgUndefined;
        if (0 == DIGI_STRNCMP("RSA+2048", token.pStart, token.len))
        {
            keyGenAlg = rsa2048;
        }
        else if (0 == DIGI_STRNCMP("RSA+3072", token.pStart, token.len))
        {
            keyGenAlg = rsa3072;
        }
        else if (0 == DIGI_STRNCMP("RSA+4096", token.pStart, token.len))
        {
            keyGenAlg = rsa4096;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P256", token.pStart, token.len))
        {
            keyGenAlg = ecdsaP256;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P384", token.pStart, token.len))
        {
            keyGenAlg = ecdsaP384;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P521", token.pStart, token.len))
        {
            keyGenAlg = ecdsaP521;
        }
        else if (0 == DIGI_STRNCMP("EDDSA+Ed25519", token.pStart, token.len))
        {
            keyGenAlg = eddsaEd25519;
        }
        else if (0 == DIGI_STRNCMP("EDDSA+Ed448", token.pStart, token.len))
        {
            keyGenAlg = eddsaEd448;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (0 == DIGI_STRNCMP("MLDSA+44", token.pStart, token.len))
        {
            keyGenAlg = mldsa44;
        }
        else if (0 == DIGI_STRNCMP("MLDSA+65", token.pStart, token.len))
        {
            keyGenAlg = mldsa65;
        }
        else if (0 == DIGI_STRNCMP("MLDSA+87", token.pStart, token.len))
        {
            keyGenAlg = mldsa87;
        }
#endif

        if (certEnrollAlgUndefined != keyGenAlg)
        {
            if (certEnrollAlgUndefined != existingKeyGenAlg)
            {
                if (keyGenAlg == existingKeyGenAlg)
                {
                    /* Found algorithm and key size which matches existing key */
                    break;
                }
            }
            else
            {
                /* Found algorithm and key size to generate */
                break;
            }
        }
    }

    if (certEnrollAlgUndefined == keyGenAlg)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_ALGO;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentGetKeyHashAlgorithm(
        keyGenAlg, &sigAlg);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getObjectIndex(
        pJCtx, "source", ndx, &srcNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    srcNdx++;
    status = JSON_getToken(pJCtx, srcNdx, &token);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (JSON_String == token.type)
    {
        if (KEY_SOURCE_SW_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_SW;
        }
        else if (KEY_SOURCE_SW_SERVER_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW_SERVER, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_SW_SERVER;
        }
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TEE, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TEE_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TEE, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_TEE;
        }
#else
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TPM2, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TPM2_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TPM2, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_TPM2;
        }
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_PKCS11, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_PKCS11_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_PKCS11, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_PKCS11;
        }
#endif
#endif
        if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != keySrc)
        {
            if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != existingKeySrc)
            {
                if (keySrc != existingKeySrc)
                {
                    /* Key source provided in specification does not match
                     * existing key, error and exit */
                    status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_SOURCE;
                    goto exit;
                }
            }
        }

        keySrcToken = token;
    }
    else if (JSON_Array == token.type)
    {
        srcNdx++;
        for (i = 0; i < token.elemCnt; i++)
        {
            status = JSON_getToken(pJCtx, srcNdx + i, &keySrcToken);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (JSON_String != keySrcToken.type)
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            keySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
            if (KEY_SOURCE_SW_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_SW;
            }
            else if (KEY_SOURCE_SW_SERVER_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW_SERVER, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_SW_SERVER;
            }
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TEE, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TEE_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TEE, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_TEE;
            }
#else
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TPM2, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TPM2_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TPM2, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_TPM2;
            }
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_PKCS11, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_PKCS11_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_PKCS11, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_PKCS11;
            }
#endif
#endif
            if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != keySrc)
            {
                if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != existingKeySrc)
                {
                    if (keyGenAlg == existingKeyGenAlg)
                    {
                        /* Found algorithm and key size which matches existing key */
                        break;
                    }
                }
                else
                {
                    /* Found algorithm and key size to generate */
                    break;
                }
            }
        }
    }

    if (TRUSTEDGE_KEY_SOURCE_UNDEFINED == keySrc)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_SOURCE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_VERBOSE, "Selected key source %.*s (%d)\n",
        keySrcToken.len, keySrcToken.pStart, keySrc);

#if defined(__ENABLE_DIGICERT_TAP__)
    if (TRUSTEDGE_KEY_SOURCE_SW != keySrc && TRUSTEDGE_KEY_SOURCE_SW_SERVER != keySrc)
    {
        /* Initialize defaults */
        tapAttributes.moduleId = 1;
        tapAttributes.primary = FALSE;
        tapAttributes.hierarchy = TAP_HIERARCHY_NONE;
        tapAttributes.keyUsage = TAP_KEY_USAGE_GENERAL;
        tapAttributes.sigScheme = TAP_SIG_SCHEME_NONE;
        tapAttributes.encScheme = TAP_ENC_SCHEME_NONE;
        tapAttributes.pKeyHandle = NULL;
        tapAttributes.keyNonceHandle = 0;
        tapAttributes.certHandle = 0;

#if defined(__ENABLE_DIGICERT_TEE__)
        if (TRUSTEDGE_KEY_SOURCE_TEE == keySrc)
           tapAttributes.provider = TAP_PROVIDER_TEE;
        else
           tapAttributes.provider = 0; /* not needed */
#endif

        status = CERT_ENROLL_parseTAPAttributes(
            pJCtx, ndx, keyGenAlg, &tapAttributes);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to parse TAP attributes\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TEE__)
        if (TRUSTEDGE_KEY_SOURCE_TEE == keySrc)
        {
            if (NULL == tapAttributes.pKeyHandle)
            {
                /* TODO if No key handle, error and give proper message, for now set handle to 0x10000001 */
#if 0
                status = ERR_INVALID_INPUT;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. TAP key handle must be provided for TEE Key source.\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
#else
                status = DIGI_MALLOC((void **) &tapAttributes.pKeyHandle, sizeof(TAP_Buffer));
                if (OK != status)
                    goto exit;

                status = DIGI_MALLOC((void **) &tapAttributes.pKeyHandle->pBuffer, 4);
                if (OK != status)
                    goto exit;

                tapAttributes.pKeyHandle->pBuffer[0] = 0x10;
                tapAttributes.pKeyHandle->pBuffer[1] = 0x00;
                tapAttributes.pKeyHandle->pBuffer[2] = 0x00;
                tapAttributes.pKeyHandle->pBuffer[3] = 0x01;
                tapAttributes.pKeyHandle->bufferLen = 4;
#endif
            }
        }
#endif
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Module ID: %d\n", tapAttributes.moduleId);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Primary: %d\n", tapAttributes.primary);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Hierarchy: %d\n", tapAttributes.primary);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Key Usage: %d\n", tapAttributes.keyUsage);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Signature Scheme: %d\n", tapAttributes.sigScheme);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Encryption Scheme: %d\n", tapAttributes.encScheme);
#if defined(__ENABLE_DIGICERT_TEE__)
        if (TRUSTEDGE_KEY_SOURCE_TEE == keySrc)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Provider: %d\n", tapAttributes.provider);
        }
#endif
        if (NULL != tapAttributes.pKeyHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TAP Key Handle: 0x");
            MSG_LOG_printRawBuffer(MSG_LOG_VERBOSE, tapAttributes.pKeyHandle->pBuffer, tapAttributes.pKeyHandle->bufferLen);
            MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "\n");
        }
        if (0 != tapAttributes.keyNonceHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Key Nonce Handle: 0x%08llX\n", tapAttributes.keyNonceHandle);
        }
        if (0 != tapAttributes.certHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Certificate Handle: 0x%08llX\n", tapAttributes.certHandle);
        }

        if (TRUE == tapAttributes.primary)
        {
            if (TAP_KEY_USAGE_ATTESTATION == tapAttributes.keyUsage)
            {
                extFlow = EXT_ENROLL_FLOW_TPM2_IAK;
            }
            else
            {
                extFlow = EXT_ENROLL_FLOW_TPM2_IDEVID;
            }
        }
    }
#endif

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_KEY_GEN;

    if (TRUSTEDGE_KEY_SOURCE_SW_SERVER != keySrc)
    {
        if (NULL == pNewKey)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Generating new key\n");

#if defined(__ENABLE_DIGICERT_TAP__)
            status = TRUSTEDGE_agentCertSpecGenKey(keyGenAlg, keySrc, &pNewKey, &tapAttributes);
#else
            status = TRUSTEDGE_agentCertSpecGenKey(keyGenAlg, keySrc, &pNewKey);
#endif
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_utilsWriteKeyAndCert(pCtx->pConfig, pCtx->curPolicy.pPolicy->pAlias, pNewKey, NULL, 0
#if defined(__ENABLE_DIGICERT_TAP__)
                         , &tapAttributes
#endif
                         );
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
#if defined(__ENABLE_DIGICERT_TAP__)
            if (0 != (pNewKey->type & 0xFF0000) && FALSE == tapAttributes.primary)
            {
                status = TRUSTEDGE_utilsWriteSMPBlob(
                    pCtx->pConfig->pKeystoreKeysDir,
                    pCtx->curPolicy.pPolicy->pAlias, pNewKey,
                    KEY_FORMAT_TAP_PRIVATE_BLOB | KEY_FORMAT_TAP_PUBLIC_BLOB);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
#endif
        }
    }
    else
    {
        MSG_LOG_print(MSG_LOG_INFO, "%s", "Performing server key generation flow\n");
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_CSR_GEN;

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "csrAttributes", &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getToken(pJCtx, ndx, &token);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (CE_FORMAT_CMC == reqFormat)
    {
        if (CE_TRUSTED_SIGNER != reqSpec && CE_TPM2_ATTEST != reqSpec)
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_SPEC;
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCopy, token.len + 1, (void *) token.pStart, token.len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCopy[token.len] = '\0';

        status = TRUSTEDGE_utilsGetSigAlgStr(sigAlg, &pSigAlgStr);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

#if !defined(__DISABLE_TRUSTEDGE_EST__)
        status = EST_createPKCS7RequestFromConfigWithPolicy(
            pCtx->pTrustedStore, pCopy, NULL, EST_CONFIG_JSON, NULL, 0,
            pNewKey, (NULL != pNewKey) ? pNewKey->type : akt_undefined, keyGenAlg, NULL, 0, akt_undefined,
            pSigAlgStr, DIGI_STRLEN(pSigAlgStr), -1, ENROLL, FALSE,
            &pCSR, &csrLen, extFlow, TRUSTEDGE_evalFunction, pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif
    }
    else
    {
        status = CERT_ENROLL_addKeyCertAttributes( &certSpec.keyCtx, pNewKey, NULL, NULL,
                                                keyGenAlg, 0, TRUE,
                                                NULL, 0, NULL);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TAP__)
        status = CERT_ENROLL_setTAPCallback(&certSpec.csrCtx, TRUSTEDGE_TAP_getCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif

        /* token holds the csrAttributes object */
        status = CERT_ENROLL_addCsrAttributes(
            &certSpec.csrCtx, JSON, 0, TRUSTEDGE_evalFunction, pCtx, pNewKey,
            keyGenAlg, FALSE, sigAlg, (ubyte *) token.pStart, token.len, NULL,
            extFlow);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CERT_ENROLL_generateCSRRequest(&certSpec.keyCtx, NULL, &certSpec.csrCtx, 0, &pCSR, &csrLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pCtx->curPolicy.pPolicy->pCertSpecJson, jsonLen,
        pJson, jsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pCtx->curPolicy.pPolicy->certSpecJsonLen = jsonLen;

    pCtx->curPolicy.data.cps.pNewKey = pNewKey; pNewKey = NULL;

exit:

#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != tapAttributes.pKeyHandle)
    {
        DIGI_FREE((void **) &tapAttributes.pKeyHandle->pBuffer);
        DIGI_FREE((void **) &tapAttributes.pKeyHandle);
    }
#endif

    DIGI_FREE((void **) &pCopy);
    DIGI_FREE((void **) &pSpec);
    DIGI_FREE((void **) &pFormat);

    CERT_ENROLL_cleanupCsrCtx(&certSpec.csrCtx);
    CERT_ENROLL_cleanupKeyCtx(&certSpec.keyCtx);

    if (NULL != pKeyAlias)
    {
        DIGI_FREE((void **) &pKeyAlias);
    }

    if (NULL != pKey)
    {
        (void) DIGI_FREE((void **) &pKey);
    }

    if (NULL != pOutFile)
    {
        (void) DIGI_FREE((void **) &pOutFile);
    }

    DIGI_FREE((void **) &pId);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(pNewKey, NULL);
        (void) DIGI_FREE((void **) &pNewKey);
    }

    DIGI_FREE((void **) &pValue);
    JSON_releaseContext(&pJCtx);
    DIGI_FREE((void **) &pCSR);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pDeviceGroupId);

    return status;
}

/*----------------------------------------------------------------------------*/

typedef struct mimeCertificateHandlerData {
    TrustEdgeAgentCtx *pCtx;    /* in */
    sbyte *pPkcs7Data;          /* out */
    sbyte4 pkcs7DataLen;        /* out */
    sbyte *pKeyData;            /* out */
    sbyte4 keyDataLen;          /* out */
    ubyte *pCMCData;            /* out */
    ubyte4 cmcDataLen;          /* out */
} mimeCertificateHandlerData;

static MimePartProcessArg *createCertificateHandlerData (TrustEdgeAgentCtx *pCtx)
{
    mimeCertificateHandlerData *pStruct;

    if (OK != DIGI_MALLOC((void **) &pStruct, sizeof(*pStruct)))
    {
        return NULL;
    }

    if (OK != DIGI_MEMSET ((ubyte *)pStruct, 0x00, sizeof(*pStruct)))
    {
        DIGI_FREE((void **) &pStruct);
        return NULL;
    }

    pStruct->pCtx = pCtx;

    return (MimePartProcessArg *) pStruct;
}

static void freeCertificateHandlerData (MimePartProcessArg **ppStruct)
{
    if (NULL == ppStruct) return;
    mimeCertificateHandlerData *pStruct = *ppStruct;

    DIGI_FREE((void **) &(pStruct->pCMCData));
    DIGI_FREE((void **) &(pStruct->pPkcs7Data));
    DIGI_FREE((void **) &(pStruct->pKeyData));
    DIGI_FREE((void **) ppStruct);
}

#define PKCS7_HEADER        "-----BEGIN PKCS7-----\n"
#define PKCS7_FOOTER        "-----END PKCS7-----\n"

static MSTATUS processCertificateMimePart(
    MimePart *pPart,
    MimePartProcessArg *pInfo)
{
    MSTATUS status;
    mimeCertificateHandlerData *pState;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte *pPkcs7Start, *pPkcs7End;
    sbyte *pId = NULL;
    sbyte *pPkcs7Data = NULL;
    sbyte4 pkcs7DataLen;
    sbyte *pKeyData = NULL;
    sbyte4 keyDataLen;
    if (NULL == pPart || NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pState = (mimeCertificateHandlerData *) pInfo;

    if (MIME_CONTENT_TYPE_JSON == pPart->contentType)
    {
        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            goto exit;
        }

        status = JSON_parse(pJCtx, pPart->pData, pPart->dataLen, &numTokens);
        if (OK != status)
        {
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "certificatePolicyId", &pId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = TRUSTEDGE_validateCurrentPolicy(pState->pCtx, pId, NULL, NULL, NULL,
            NULL, TE_POLICY_TYPE_CERTIFICATE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pState->pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_ISSUED_CERT_RSP_PARSE;
    }
    else if (MIME_CONTENT_TYPE_PKCS7_MIME == pPart->contentType)
    {
        pPkcs7Data = NULL;
        if (pPart->dataLen >= DIGI_STRLEN(PKCS7_HEADER) && 0 == DIGI_STRNCMP(pPart->pData, PKCS7_HEADER, DIGI_STRLEN(PKCS7_HEADER)))
        {
            pPkcs7Start = pPart->pData + DIGI_STRLEN(PKCS7_HEADER);
        }
        else
        {
            pPkcs7Start = pPart->pData;
        }
        if (pPart->dataLen >= DIGI_STRLEN(PKCS7_FOOTER) && 0 == DIGI_STRNCMP(pPart->pData + pPart->dataLen - DIGI_STRLEN(PKCS7_FOOTER), PKCS7_FOOTER, DIGI_STRLEN(PKCS7_FOOTER)))
        {
            pPkcs7End = pPart->pData + pPart->dataLen - DIGI_STRLEN(PKCS7_FOOTER);
        }
        else
        {
            pPkcs7End = pPart->pData + pPart->dataLen;
        }

        pkcs7DataLen = pPkcs7End - pPkcs7Start;
        status = DIGI_MALLOC_MEMCPY ((void **) &pPkcs7Data, pkcs7DataLen, pPkcs7Start, pkcs7DataLen);
        if (OK != status)
            goto exit;

        pState->pPkcs7Data = pPkcs7Data;
        pState->pkcs7DataLen = pkcs7DataLen;
        pPkcs7Data = NULL;
    }
    else if (MIME_CONTENT_TYPE_PKCS8 == pPart->contentType)
    {
        pKeyData = NULL;
        keyDataLen = pPart->dataLen;

        status = DIGI_MALLOC_MEMCPY ((void **) &pKeyData, keyDataLen, pPart->pData, keyDataLen);
        if (OK != status)
            goto exit;

        pState->pKeyData = pKeyData;
        pState->keyDataLen = keyDataLen;
        pKeyData = NULL;
    }
    else if (MIME_CONTENT_TYPE_CMC == pPart->contentType)
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pState->pCMCData, pPart->dataLen,
            pPart->pData, pPart->dataLen);
        if (OK != status)
            goto exit;

        pState->cmcDataLen = pPart->dataLen;
    }
    else
    {
        status = OK;
    }
exit:

    JSON_releaseContext(&pJCtx);

    DIGI_FREE((void **) &pPkcs7Data);
    DIGI_FREE((void **) &pKeyData);
    DIGI_FREE((void **) &pId);
    return status;
}

/*----------------------------------------------------------------------------*/
typedef struct mimeCloudPlatformHandlerData {
    TrustEdgeAgentCtx *pCtx;    /* in */
    sbyte *pProviderCredJson;   /* out */
    sbyte4 providerCredJsonLen; /* out */
} mimeCloudPlatformHandlerData;

static MimePartProcessArg *createCloudPlatformHandlerData (TrustEdgeAgentCtx *pCtx)
{
    mimeCloudPlatformHandlerData *pStruct;

    if (OK != DIGI_MALLOC((void **) &pStruct, sizeof(*pStruct)))
    {
        return NULL;
    }

    if (OK != DIGI_MEMSET ((ubyte *)pStruct, 0x00, sizeof(*pStruct)))
    {
        DIGI_FREE((void **) &pStruct);
        return NULL;
    }

    pStruct->pCtx = pCtx;

    return (MimePartProcessArg *) pStruct;
}

static void freeCloudPlatformHandlerData (MimePartProcessArg **ppStruct)
{
    if (NULL == ppStruct) return;
    mimeCloudPlatformHandlerData *pStruct = *ppStruct;

    DIGI_FREE((void **) &(pStruct->pProviderCredJson));
    DIGI_FREE((void **) ppStruct);
}

typedef struct
{
    sbyte *pType;
    sbyte *pX5c;
    sbyte *pX5t256;
}TrustEdgeAgentProvisioningCreds;

typedef struct
{
    TrustEdgeAgentProvisioningCreds *pCreds;
    ubyte4 credCount;
}TrustEdgeAgentProvisioningCredsList;

static MSTATUS TRUSTEDGE_validateCloudPlatformCreds(TrustEdgeAgentCtx *pCtx, sbyte *pX5c, sbyte *pX5t256In, sbyte *pType, ubyte4 i)
{
    MSTATUS status = OK;
    ubyte pX5t256[SHA256_RESULT_SIZE];
    ubyte *pEncodedFingerprint = NULL;
    ubyte4 encodedFingerprintLen = 0;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen = 0;

    if (0 != DIGI_STRNICMP(pType, "x509", DIGI_STRLEN(pType)))
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRNCMP((sbyte *)pCtx->curPolicy.data.cpps.ppX5t256[i], pX5t256In, DIGI_STRLEN(pX5t256In)))
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    else
    {
        status = BASE64_decodeMessage((ubyte *)pX5c, DIGI_STRLEN(pX5c), &pDecoded, &decodedLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CRYPTO_INTERFACE_SHA256_completeDigest(pDecoded, decodedLen, pX5t256);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = BASE64_urlEncodeMessage(pX5t256, sizeof(pX5t256), &pEncodedFingerprint, &encodedFingerprintLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pEncodedFingerprint[encodedFingerprintLen] = '\0';

        if (0 != DIGI_STRNCMP((sbyte *)pEncodedFingerprint, pX5t256In, encodedFingerprintLen))
        {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
        }
    }

exit:

    if (NULL != pEncodedFingerprint)
    {
        DIGI_FREE((void **) &pEncodedFingerprint);
    }

    if (NULL != pDecoded)
    {
        DIGI_FREE((void **) &pDecoded);
    }

    return status;

}

static MSTATUS processCloudPlatformMimePart(
    MimePart *pPart,
    MimePartProcessArg *pInfo)
{
    MSTATUS status;
    mimeCloudPlatformHandlerData *pState;
    JSON_ContextType *pJCtx = NULL;
    JSON_TokenType arrToken = {0};
    JSON_TokenType x5cToken = {0};
    ubyte4 numTokens;
    ubyte4 index = 0;
    ubyte4 arrIndex = 0;
    ubyte4 x5cIndex = 0;
    sbyte *pPolicyService = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pTimestamp = NULL;
    sbyte *pMode = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pCloudPlatformPolicyId = NULL;
    sbyte *pType = NULL;
    sbyte *pX5c = NULL;
    sbyte *pX5t256 = NULL;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte4 x5cLen = 0;
    sbyte **ppX5c = NULL;

    if (NULL == pPart || NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pState = (mimeCloudPlatformHandlerData*) pInfo;

    if (DIGI_STRNCMP(pPart->pDescription, "Cloud Platform Provider JSON",
        DIGI_STRLEN("Cloud Platform Provider JSON")) == 0)
    {
        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            goto exit;
        }

        status = JSON_parse(pJCtx, pPart->pData, pPart->dataLen, &numTokens);
        if (OK != status)
        {
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "policyService", &pPolicyService, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (0 != DIGI_STRNICMP(pPolicyService, "CloudPlatformPolicy", DIGI_STRLEN(pPolicyService)))
        {
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "deviceId", &pDeviceId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "accountId", &pAccountId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "timestamp", &pTimestamp, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (FALSE == TRUSTEDGE_utilsInValidTimeWindow(pTimestamp, pState->pCtx->timeoutWindow))
        {
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d. Incoming cloud platform message outside timeout window\n",
                __func__, __LINE__);
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "mode", &pMode, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (OK == status)
        {
            if (0 != DIGI_STRNICMP(pMode, "cloudplatform_policy_request", DIGI_STRLEN(pMode)))
            {
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "deviceGroupId", &pDeviceGroupId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "cloudPlatformPolicyId", &pCloudPlatformPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonArrayValue(
            pJCtx, 0, "cloudPlatformCredentials", &arrIndex, &arrToken, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        arrIndex++;
        for (i = 0; i < arrToken.elemCnt; i++)
        {
            status = JSON_getJsonStringValue(
                pJCtx, arrIndex, "type", &pType, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            status = JSON_getJsonArrayValue(
            pJCtx, arrIndex, "x5c", &x5cIndex, &x5cToken, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            x5cIndex++;
            status = DIGI_CALLOC(
                (void **) &ppX5c, x5cToken.elemCnt, sizeof(sbyte *));
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            for (j = 0; j < x5cToken.elemCnt; j++)
            {
                if (NULL != pX5c)
                {
                    DIGI_FREE((void **)&pX5c);
                }
                status = JSON_getJsonString(pJCtx, x5cIndex + j, &pX5c);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                    goto exit;
                }

                x5cLen = DIGI_STRLEN(pX5c);

                status = DIGI_MALLOC_MEMCPY((void **) &ppX5c[j], x5cLen + 1, pX5c, x5cLen + 1);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                ppX5c[j][x5cLen] = '\0';
            }

            status = JSON_getJsonStringValue(
                pJCtx, index, "x5tS256", &pX5t256, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            status = TRUSTEDGE_validateCloudPlatformCreds(pState->pCtx, ppX5c[0], pX5t256, pType, i);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", ">>> PRINTING CLOUD PLATFORM PROVISIONING CREDENTIALS START <<<\n");
            MSG_LOG_print(MSG_LOG_VERBOSE, "Type: %s\n", pType);
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "x5c:\n");
            for (j = 0; j < x5cToken.elemCnt; j++)
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "    \"%s\"\n", ppX5c[j]);
            }
            MSG_LOG_print(MSG_LOG_VERBOSE, "x5tS256: %s\n", pX5t256);
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", ">>> PRINTING CLOUD PLATFORM PROVISIONING CREDENTIALS END <<<\n");

            status = JSON_getLastIndexInObject(
                pJCtx, arrIndex, &arrIndex);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }
        }

        status = TRUSTEDGE_validateCurrentPolicy(pState->pCtx, pCloudPlatformPolicyId, pDeviceId,
            pAccountId, pDeviceGroupId, NULL, TE_POLICY_TYPE_CLOUDPLATFORM);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (DIGI_STRNCMP(pPart->pDescription, "Cloud Platform Provider Provisioned JSON",
        DIGI_STRLEN("Cloud Platform Provider Provisioned JSON")) == 0)
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pState->pProviderCredJson, pPart->dataLen,
            pPart->pData, pPart->dataLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pState->providerCredJsonLen = pPart->dataLen;
    }
    else
    {
        status = OK;
    }

exit:

    JSON_releaseContext(&pJCtx);

    DIGI_FREE((void **) &pPolicyService);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pTimestamp);
    DIGI_FREE((void **) &pMode);
    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pCloudPlatformPolicyId);
    DIGI_FREE((void **) &pType);
    DIGI_FREE((void **) &pX5c);
    DIGI_FREE((void **) &pX5t256);

    for (i = 0; i < x5cToken.elemCnt; i++)
    {
        if (NULL != ppX5c[i])
        {
            DIGI_FREE((void **) &ppX5c[i]);
        }
    }
    if (NULL != ppX5c)
    {
        DIGI_FREE((void **) &ppX5c);
    }

    return status;
}


/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParseIssuedCertificate(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pBody,
    ubyte4 bodyLen)
{
    MSTATUS status;
    certDescriptor *pCertDescArray = NULL;
    ubyte4 certDescArrayLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 i;
    sbyte *pId = NULL;
    AsymmetricKey *pRspKey = NULL;
    mimeCertificateHandlerData *pCertData;
    MimePartProcessArg *pHandlerData = NULL;
    MimePayload payloadData = { 0 };
    byteBoolean isGood = FALSE;
#if defined(__ENABLE_DIGICERT_TAP__)
    TAP_Context *pTapCtx = NULL;
    TAP_EntityCredentialList *pTapEntityCredList = NULL;
#endif
    ubyte *pCSR = NULL;
    ubyte4 csrLen = 0;
    ubyte4 hashId = ht_none;
    ubyte *pPEM = NULL;
    ubyte4 pemLen = 0;

    pHandlerData = createCertificateHandlerData (pCtx);
    if (NULL == pHandlerData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    payloadData.pFile = NULL;
    payloadData.pPayLoad = pBody;
    payloadData.payloadLen = bodyLen;
    status = MIME_process (&payloadData, processCertificateMimePart, pHandlerData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCertData = (mimeCertificateHandlerData*) pHandlerData;
    if (NULL == pCertData->pPkcs7Data && NULL == pCertData->pCMCData)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCertData->pKeyData)
    {
        if (NULL != pCtx->curPolicy.data.cps.pNewKey)
        {
            CRYPTO_uninitAsymmetricKey(pCtx->curPolicy.data.cps.pNewKey, NULL);
            DIGI_FREE((void **) &pCtx->curPolicy.data.cps.pNewKey);
        }

        status = DIGI_CALLOC((void **) &pCtx->curPolicy.data.cps.pNewKey, 1, sizeof(AsymmetricKey));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CRYPTO_deserializeAsymKey(pCertData->pKeyData, pCertData->keyDataLen, NULL, pCtx->curPolicy.data.cps.pNewKey);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pRspKey = pCtx->curPolicy.data.cps.pNewKey;
    }

    if (NULL != pCertData->pKeyData && NULL != pCtx->curPolicy.data.cps.pCertSpec)
    {
        /* Regenerate CSR using server provided key */
        status = TRUSTEDGE_agentGetKeyHashAlgorithm(
            pCtx->curPolicy.data.cps.pCertSpec->keyCtx.keyAlgorithm,
            &hashId);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pCtx->curPolicy.data.cps.pCertSpec->keyCtx.pKey = pCtx->curPolicy.data.cps.pNewKey;
        pCtx->curPolicy.data.cps.pCertSpec->csrCtx.hashId = hashId;

        status = CERT_ENROLL_generateCSRRequest(
            &pCtx->curPolicy.data.cps.pCertSpec->keyCtx, NULL,
            &pCtx->curPolicy.data.cps.pCertSpec->csrCtx, 0,
            &pCSR, &csrLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
    {
        /* Save CSR as is */
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCSR, pCtx->curPolicy.data.cps.csrLen,
            pCtx->curPolicy.data.cps.pCSR, pCtx->curPolicy.data.cps.csrLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        csrLen = pCtx->curPolicy.data.cps.csrLen;
    }

    status = TRUSTEDGE_utilsOneLineCSR(
        pCSR, csrLen, &pPEM, &pemLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCertData->pCMCData)
    {
#if !defined(__DISABLE_TRUSTEDGE_EST__)
        status = TRUSTEDGE_utilsParseCMCResponse(
            pCertData->pCMCData, pCertData->cmcDataLen,
            pCtx->curPolicy.data.cps.pNewKey,
            &pCertDescArray, &certDescArrayLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "Failed to process CMC response %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif
    }
    else if (NULL != pCertData->pPkcs7Data)
    {
        status = CERT_ENROLL_parseResponse(pCertData->pPkcs7Data, pCertData->pkcs7DataLen, pCtx->curPolicy.data.cps.pNewKey, TRUE,
                                        &pCertDescArray, &certDescArrayLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "Failed to process PKCS7 response %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL == pCertDescArray || certDescArrayLen == 0)
    {
        status = ERR_TRUSTEDGE_AGENT_NO_CERTIFICATE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Ensure key and certificate match */
    status = CA_MGMT_verifyCertAndKeyPair(
        pCertDescArray[0].pCertificate, pCertDescArray[0].certLength,
        pCtx->curPolicy.data.cps.pNewKey, &isGood);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE != isGood)
    {
        status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
        MSG_LOG_print(MSG_LOG_ERROR,
            "Issued certificate and key do not match %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_ISSUED_CERT_TRUSTBUNDLE;

    for (i = 1; i < certDescArrayLen; i++)
    {
        status = CERT_STORE_addTrustPoint(
            pCtx->pTrustedStore,
            pCertDescArray[i].pCertificate, pCertDescArray[i].certLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_utilsWriteTrustedCert(
            pCtx->pConfig,
            pCertDescArray[i].pCertificate, pCertDescArray[i].certLength);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_ISSUED_CERT_KEY_AND_CERT_PAIR;

    status = TRUSTEDGE_utilsValidateCert(
        pCtx->pTrustedStore,
        pCertDescArray[0].pCertificate, pCertDescArray[0].certLength, FALSE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to validate issued certificate\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(
        MSG_LOG_INFO,
        "Writing issued certificate to filesystem with basename %s\n",
        pCtx->curPolicy.pPolicy->pAlias);

    if (NULL != pRspKey)
    {
        MSG_LOG_print(MSG_LOG_INFO, "Writing key to filesystem with basename %s\n", pCtx->curPolicy.pPolicy->pAlias);
    }

    /* Write out certificate provided in response and optional key if provided
     * in response */
    status = TRUSTEDGE_utilsWriteKeyAndCert(
        pCtx->pConfig, pCtx->curPolicy.pPolicy->pAlias, pRspKey,
            pCertDescArray[0].pCertificate, pCertDescArray[0].certLength
#if defined(__ENABLE_DIGICERT_TAP__)
        , NULL
#endif
        );
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (0 != pCtx->curPolicy.data.cps.certHandle)
    {
        status = TRUSTEDGE_TAP_getCtx(&pTapCtx, &pTapEntityCredList, NULL, NULL, 0, 1);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = KEYGEN_persistDataAtNVIndex(
            pTapCtx, pTapEntityCredList,
            pCtx->curPolicy.data.cps.certHandle, pCertDescArray[0].pCertificate,
            pCertDescArray[0].certLength, TRUE == pCtx->curPolicy.data.cps.primary ? TAP_AUTH_CONTEXT_PLATFORM : TAP_AUTH_CONTEXT_NONE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to persist certificate\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
#endif

    status = TRUSTEDGE_agentPersistCertSpecAddCert(
        pCtx, pCtx->curPolicy.pPolicy->pId,
        pPEM, pemLen,
        pCtx->curPolicy.pPolicy->pAlias,
        pCertDescArray[0].pCertificate, pCertDescArray[0].certLength);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pCtx->curPolicy.data.cps.pCSR)
    {
        DIGI_FREE((void **) &pCtx->curPolicy.data.cps.pCSR);
    }

    if (NULL != pCtx->curPolicy.data.cps.pCertSpec)
    {
        CERT_ENROLL_cleanupCsrCtx(&(pCtx->curPolicy.data.cps.pCertSpec->csrCtx));
        CERT_ENROLL_cleanupKeyCtx(&(pCtx->curPolicy.data.cps.pCertSpec->keyCtx));
        DIGI_FREE((void **) &pCtx->curPolicy.data.cps.pCertSpec);
    }

    DIGI_FREE((void **) &pPEM);
    DIGI_FREE((void **) &pCSR);
    DIGI_FREE((void ** ) &pId);
    JSON_releaseContext(&pJCtx);

    freeCertificateHandlerData (&pHandlerData);

    if (NULL != pCertDescArray)
    {
        for (i = 0; i < certDescArrayLen; i++)
        {
            (void) CA_MGMT_freeCertificate(&pCertDescArray[i]);
        }

        (void) DIGI_FREE((void **) &pCertDescArray);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParseReleaseArtifactList(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen)
{
    MSTATUS status;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 ndx;
    JSON_TokenType token = { 0 }, tokenList = { 0 };
    ubyte4 i;
    sbyte *pId = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte *pArtifactId = NULL;
    sbyte *pArtifactName = NULL;
    sbyte *pArtifactVersion = NULL;
    sbyte *pArtifactTimestamp = NULL;
    sbyte *pMode = NULL;
    sbyte *pTimestamp = NULL;
    sbyte *pPolicyService = NULL;
    ubyte4 artifactSize = 0;

    /* if we already have an artifact list, we can ignore this message */
    if (NULL != pCtx->curPolicy.data.ups.pArtifactHead)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        goto exit;
    }

    /* Input validation not required */

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "updatePolicyId", &pId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceId", &pDeviceId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "accountId", &pAccountId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceGroupId", &pDeviceGroupId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deploymentId", &pDeploymentId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "policyService", &pPolicyService, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    if (0 != DIGI_STRNICMP(pMode, "UpdatePolicy", DIGI_STRLEN(pMode)))
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "mode", &pMode, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    if (0 != DIGI_STRNICMP(pMode, "release_artifact_list", DIGI_STRLEN(pMode)))
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "timestamp", &pTimestamp, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    if (FALSE == TRUSTEDGE_utilsInValidTimeWindow(pTimestamp, pCtx->timeoutWindow))
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d. Incoming release artifact list message outside timeout window\n",
            __func__, __LINE__);
        goto exit;
    }

    status = TRUSTEDGE_validateCurrentPolicy(pCtx, pId, pDeviceId, pAccountId,
        pDeviceGroupId, pDeploymentId, TE_POLICY_TYPE_UPDATE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(
        pJCtx, 0, "artifacts", &ndx, &tokenList, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < tokenList.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &token);
        if (OK != status)
        {
            goto exit;
        }

        if (JSON_Object != token.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        DIGI_FREE((void **) &pArtifactId);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "artifactId", &pArtifactId, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pArtifactName);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "artifactName", &pArtifactName, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pArtifactVersion);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "artifactVersion", &pArtifactVersion, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pArtifactTimestamp);
        status = JSON_getJsonStringValue(
            pJCtx, ndx, "artifactTimestamp", &pArtifactTimestamp, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, "artifactSize", &artifactSize, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        status = TRUSTEDGE_agentArtifactAddNode(
            &pArtifactId, &pArtifactName, &pArtifactVersion,
            &pArtifactTimestamp, "UNDEFINED", artifactSize,
            FALSE, FALSE, FALSE, 0, 0, 0, 0, &pCtx->curPolicy.data.ups.pArtifactHead);
        if (OK != status)
        {
            goto exit;
        }

        status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
        if (OK != status)
        {
            goto exit;
        }
    }

    TRUSTEDGE_agentArtifactPrintNodes(pCtx->curPolicy.data.ups.pArtifactHead);
    pCtx->curPolicy.data.ups.pArtifact = pCtx->curPolicy.data.ups.pArtifactHead;

    if (NULL == pCtx->curPolicy.data.ups.pArtifactHead)
    {
        /* if no artifacts, policy is complete  */
        pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_SUCCESS;
    }
exit:

    DIGI_FREE((void **) &pId);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pDeviceGroupId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pPolicyService);
    DIGI_FREE((void **) &pMode);

    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pArtifactName);
    DIGI_FREE((void **) &pArtifactVersion);
    DIGI_FREE((void **) &pArtifactTimestamp);
    DIGI_FREE((void **) &pTimestamp);
    JSON_releaseContext(&pJCtx);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParseCloudPlatform(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pBody,
    ubyte4 bodyLen)
{
    MSTATUS status;
    JSON_ContextType *pJCtx = NULL;
    sbyte *pId = NULL;
    mimeCloudPlatformHandlerData *pCloudPlatformData;
    MimePartProcessArg *pHandlerData = NULL;
    MimePayload payloadData = { 0 };
    sbyte *pFileName = NULL;
    sbyte *pOutFile = NULL;

    pHandlerData = createCloudPlatformHandlerData (pCtx);
    if (NULL == pHandlerData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    payloadData.pFile = NULL;
    payloadData.pPayLoad = pBody;
    payloadData.payloadLen = bodyLen;
    status = MIME_process (&payloadData, processCloudPlatformMimePart, pHandlerData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCloudPlatformData = (mimeCloudPlatformHandlerData*) pHandlerData;

    if (NULL == pCloudPlatformData->pProviderCredJson || 0 == pCloudPlatformData->providerCredJsonLen)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(
        pCtx->curPolicy.pPolicy->pId, JSON_EXT, &pFileName);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pProviderCredsDir, pFileName, &pOutFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE,
        "Writing cloud platform provider credentials to %s\n", pOutFile);

    status = DIGICERT_writeFile(
        pOutFile, pCloudPlatformData->pProviderCredJson,
        pCloudPlatformData->providerCredJsonLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void ** ) &pId);
    DIGI_FREE((void **) &pFileName);
    DIGI_FREE((void **) &pOutFile);
    JSON_releaseContext(&pJCtx);
    freeCloudPlatformHandlerData (&pHandlerData);

    return status;
}

static MSTATUS TRUSTEDGE_agentParseErrorResponse(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen,
    ErrorResponseMsg *pErrorMsg)
{
    MSTATUS status;

    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;

    TrustEdgeAgentPolicyType type = TE_POLICY_TYPE_UPDATE;
    sbyte *pPolicyService = NULL;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte *pArtifactId = NULL;
    sbyte *pMode = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pTimestamp = NULL;
    sbyte *pErrorCode = NULL;
    sbyte *pErrorString = NULL;
    intBoolean fatal = FALSE;
    sbyte *pId = NULL;
    TrustEdgeAgentMode mode = TE_MODE_TYPE_UNKNOWN;
    byteBoolean isPending = FALSE;

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "timestamp", &pTimestamp, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == TRUSTEDGE_utilsInValidTimeWindow(pTimestamp, pCtx->timeoutWindow))
    {
        status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d. Incoming device error response message outside timeout window\n",
            __func__, __LINE__);
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "policyService", &pPolicyService, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == DIGI_STRNCMP("UpdatePolicy", pPolicyService, DIGI_STRLEN("UpdatePolicy")))
        type = TE_POLICY_TYPE_UPDATE;
    else if (0 == DIGI_STRNCMP("CertificatePolicy", pPolicyService, DIGI_STRLEN("CertificatePolicy")))
        type = TE_POLICY_TYPE_CERTIFICATE;
    else if (0 == DIGI_STRNCMP("CloudPlatformPolicy", pPolicyService, DIGI_STRLEN("CloudPlatformPolicy")))
        type = TE_POLICY_TYPE_CLOUDPLATFORM;
    DIGI_FREE((void **) &pPolicyService);

    if (TE_POLICY_TYPE_UPDATE == type)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "updatePolicyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "deploymentId", &pDeploymentId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

    }
    else if (TE_POLICY_TYPE_CERTIFICATE == type)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "certificatePolicyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (TE_POLICY_TYPE_CLOUDPLATFORM == type)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "deviceId", &pDeviceId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        status = JSON_getJsonStringValue(
            pJCtx, 0, "accountId", &pAccountId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        status = JSON_getJsonStringValue(
            pJCtx, 0, "policyId", &pPolicyId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Check if error message is for renew certificate message */
    status = TRUSTEDGE_agentCertificateRenewalPending(
        pCtx, pPolicyId, &isPending);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == isPending)
    {
        /* Not for renew certificate message, check against current policy */
        status = TRUSTEDGE_validateCurrentPolicy(
            pCtx, pPolicyId, NULL, NULL, NULL, pDeploymentId, type);
        if (OK != status)
            goto exit;

        MSG_LOG_print(MSG_LOG_ERROR,
            "Error response for current policy - policy ID %s\n", pPolicyId);
    }
    else
    {
        /* Update JSON file notifying that response was recieved */
        status = TRUSTEDGE_agentPersistCertSpecUpdate(
            pCtx, pPolicyId, NULL, 0);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_ERROR,
            "Error response for certificate renew - policy ID %s\n", pPolicyId);
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "mode", &pMode, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "errorCode", &pErrorCode, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "errorString", &pErrorString, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonBooleanValue(
        pJCtx, 0, "fatal", &fatal, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TE_POLICY_TYPE_UPDATE == type)
    {
        status = JSON_getJsonStringValue(
            pJCtx, 0, "artifactId", &pArtifactId, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 == DIGI_STRNCMP(pMode, "update_policy_request", DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_POLICY_REQUEST;
        }
        else if (0 == DIGI_STRNCMP(pMode, "update_artifact_request", DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_UPDATE_ARTIFACT_REQUEST;
        }
        else if (0 == DIGI_STRNCMP(pMode, "update_policy_deployment_progress",  DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_UPDATE_DEPLOY_PROGRESS;
        }
        else if (0 == DIGI_STRNCMP(pMode, "update_policy_deployment_completed",  DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_UPDATE_DEPLOY_COMPLETE;
        }
        else if (0 == DIGI_STRNCMP(pMode, "update_policy_deployment_failed",  DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_UPDATE_DEPLOY_FAILED;
        }
        else if (0 == DIGI_STRNCMP(pMode, "update_artifact_chunk_request",  DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_UPDATE_ARTIFACT_CHUNK_REQUEST;
        }

        switch(mode)
        {
            case TE_MODE_TYPE_UPDATE_ARTIFACT_REQUEST:
            case TE_MODE_TYPE_UPDATE_DEPLOY_PROGRESS:
            case TE_MODE_TYPE_UPDATE_DEPLOY_COMPLETE:
            case TE_MODE_TYPE_UPDATE_DEPLOY_FAILED:
                pId = pCtx->curPolicy.data.ups.pArtifact->pId;
                if (NULL == pArtifactId || 0 != DIGI_STRNCMP(pId, pArtifactId, DIGI_STRLEN(pId)))
                {
                    status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d. Artifact ID %s does not match current artifact ID %s\n", __func__, __LINE__, pArtifactId, pId);
                    goto exit;
                }
                break;
            case TE_MODE_TYPE_UNKNOWN:
            case TE_MODE_TYPE_POLICY_REQUEST:
            default:
                break;
        };
        status = OK;
    }
    else if (TE_POLICY_TYPE_CERTIFICATE == type)
    {
        if (0 == DIGI_STRNCMP(pMode, "certificate_specification", DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_CERTIFICATE_SPECIFICATION;
        }
        else if (0 == DIGI_STRNCMP(pMode, "certificate_request", DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_CERTIFICATE_ISSUE;
        }
        status = OK;
    }
    else if (TE_POLICY_TYPE_CLOUDPLATFORM == type)
    {
        if (0 == DIGI_STRNCMP(pMode, "cloudplatform_policy_request", DIGI_STRLEN(pMode)))
        {
            mode = TE_MODE_TYPE_CLOUDPLATFORM_REQUEST;
        }
        status = OK;
    }
    else
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Policy %s unknown mode %s", pPolicyId, pMode);
        status = OK;
    }

    if (type == TE_POLICY_TYPE_UPDATE)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
        "Policy type: %d\nPolicy ID: %s\nArtifact ID: %s\nMode: %s\nError code: %s\nError string: %s\nFatal: %d\n",
        type,
        pPolicyId,
        pArtifactId,
        pMode,
        pErrorCode,
        pErrorString,
        fatal);
    }
    else if (type == TE_POLICY_TYPE_CERTIFICATE)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
        "Policy type: %d\nPolicy ID: %s\nMode: %s\nError code: %s\nError string: %s\nFatal: %d\n",
        type,
        pPolicyId,
        pMode,
        pErrorCode,
        pErrorString,
        fatal);
    }
    else if (type == TE_POLICY_TYPE_CLOUDPLATFORM)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
        "Policy type: %d\nPolicy ID: %s\nDevice ID: %s\nAccount ID: %s\nMode: %s\nError code: %s\nError string: %s\nFatal: %d\n",
        type,
        pPolicyId,
        pDeviceId,
        pAccountId,
        pMode,
        pErrorCode,
        pErrorString,
        fatal);
    }

    pErrorMsg->pTimestamp = pTimestamp; pTimestamp = NULL;
    pErrorMsg->pPolicyId = pPolicyId; pPolicyId = NULL;
    pErrorMsg->pDeploymentId = pDeploymentId; pDeploymentId = NULL;
    pErrorMsg->pArtifactId = pArtifactId; pArtifactId = NULL;
    pErrorMsg->pDeviceId = pDeviceId; pDeviceId = NULL;
    pErrorMsg->pAccountId = pAccountId; pAccountId = NULL;
    pErrorMsg->pErrorString = pErrorString; pErrorString = NULL;
    pErrorMsg->pErrorCode = pErrorCode; pErrorCode = NULL;
    pErrorMsg->fatal = fatal;
    pErrorMsg->mode = mode;
    pErrorMsg->type = type;
    pErrorMsg->isSet = TRUE;

exit:
    DIGI_FREE((void **) &pPolicyService);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pMode);
    DIGI_FREE((void **) &pTimestamp);
    DIGI_FREE((void **) &pErrorString);
    DIGI_FREE((void **) &pErrorCode);

    JSON_releaseContext(&pJCtx);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_clearErrorResponse(ErrorResponseMsg *pResp)
{
    MSTATUS status = OK;
    if (NULL == pResp)
        goto exit;

    DIGI_FREE((void **) &pResp->pPolicyId);
    DIGI_FREE((void **) &pResp->pDeploymentId);
    DIGI_FREE((void **) &pResp->pArtifactId);
    DIGI_FREE((void **) &pResp->pTimestamp);
    DIGI_FREE((void **) &pResp->pDeviceId);
    DIGI_FREE((void **) &pResp->pAccountId);
    DIGI_FREE((void **) &pResp->pErrorCode);
    DIGI_FREE((void **) &pResp->pErrorString);
    pResp->mode = TE_MODE_TYPE_UNKNOWN;
    pResp->isSet = FALSE;
exit:
    return status;
}

/*----------------------------------------------------------------------------*/
extern MSTATUS TRUSTEDGE_addDesiredAttributes(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pKey,
    ubyte4 keyLen,
    sbyte *pValue,
    ubyte4 valueLen)
{
    MSTATUS status;
    intBoolean isPresent;

    status = TRUSTEDGE_agentIsMetricPresent(pCtx, pKey, keyLen, &isPresent);
    if (OK != status)
        goto exit;

    if (FALSE == isPresent)
    {
        if (0 != valueLen)
        {
            status = TRUSTEDGE_agentAddMetric(
                pCtx, TE_DESIRED_ATTRIBUTES_FILE, pKey, keyLen, pValue, valueLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

exit:
    return status;
}
/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentProcessBody(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType msgType,
    ubyte *pBody,
    ubyte4 bodyLen)
{
    MSTATUS status = ERR_TRUSTEDGE_AGENT;
    ErrorResponseMsg errorMsg = {0};

    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: ENTER - pCtx=%p, msgType=%d, pBody=%p, bodyLen=%u\n",
        __func__, (void*)pCtx, msgType, (void*)pBody, bodyLen);

    switch (msgType)
    {
        case TE_MSG_TYPE_PENDING_POLICIES:
            /* Assume pending policies can be received at any time */
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing pending policies body\n");
            status = TRUSTEDGE_agentParsePendingPolicies(pCtx, pBody, bodyLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            break;

        case TE_MSG_TYPE_CERTIFICATE_SPECIFICATION:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_MSG_TYPE_CERTIFICATE_SPECIFICATION != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_CERTIFICATE_SPECIFICATION, pCtx->curPolicy.pPolicy->lastMsgSentType,
                     __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing certificate specification body\n");
            status = TRUSTEDGE_agentParseCertificateSpecification(
                pCtx, pBody, bodyLen);
            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                pCtx->curPolicy.policyErrorStatus = status;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;

        case TE_MSG_TYPE_ISSUED_CERTIFICATE:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_MSG_TYPE_ISSUED_CERTIFICATE != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_ISSUED_CERTIFICATE, pCtx->curPolicy.pPolicy->lastMsgSentType,
                     __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing issued certificate body\n");
            status = TRUSTEDGE_agentParseIssuedCertificate(
                pCtx, pBody, bodyLen);
            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                pCtx->curPolicy.policyErrorStatus = status;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;

        case TE_MSG_TYPE_CERTIFICATE_RENEW:
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing certificate renew body\n");
            status = TRUSTEDGE_agentParseCertificateRenew(
                pCtx, pBody, bodyLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            }
            /* We do not want to fall-through and change the internal state to
             * certificate renew. Go to exit without changing the state
             * machine */
            goto exit;

        case TE_MSG_TYPE_RELEASE_ARTIFACT_LIST:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_MSG_TYPE_RELEASE_ARTIFACT_LIST != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_RELEASE_ARTIFACT_LIST, pCtx->curPolicy.pPolicy->lastMsgSentType,
                     __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing release artifact list\n");
            status = TRUSTEDGE_agentParseReleaseArtifactList(
                pCtx, pBody, bodyLen);
            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;

        case TE_MSG_TYPE_ARTIFACT_DOWNLOAD:
            MSG_LOG_print(MSG_LOG_DEBUG,
                "%s: TE_MSG_TYPE_ARTIFACT_DOWNLOAD - pBody=%p, bodyLen=%u\n",
                __func__, (void*)pBody, bodyLen);

            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_DEBUG,
                "%s: curPolicy.pPolicy=%p, lastMsgSentType=%d\n",
                __func__, (void*)pCtx->curPolicy.pPolicy, pCtx->curPolicy.pPolicy->lastMsgSentType);

            if (TE_MSG_TYPE_ARTIFACT_DOWNLOAD != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_ARTIFACT_DOWNLOAD, pCtx->curPolicy.pPolicy->lastMsgSentType,
                     __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing artifact download in rollback mode\n");
                status = TRUSTEDGE_agentParseArtifactDownload(
                    pCtx, pBody, bodyLen, TE_ACTION_ROLLBACK);
            }
            else
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing artifact download in install mode\n");
                status = TRUSTEDGE_agentParseArtifactDownload(
                    pCtx, pBody, bodyLen, TE_ACTION_INSTALL);
            }
            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.pPolicy->hasFailed = TRUE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;

        case TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_MSG_TYPE_ARTIFACT_DOWNLOAD != pCtx->curPolicy.pPolicy->lastMsgSentType &&
                TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d or %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_ARTIFACT_DOWNLOAD, TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK,
                    pCtx->curPolicy.pPolicy->lastMsgSentType,
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing artifact download chunk in rollback mode\n");
                status = TRUSTEDGE_agentParseArtifactDownloadChunk(
                    pCtx, pBody, bodyLen, TE_ACTION_ROLLBACK);
            }
            else
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing artifact download chunk in install mode\n");
                status = TRUSTEDGE_agentParseArtifactDownloadChunk(
                    pCtx, pBody, bodyLen, TE_ACTION_INSTALL);
            }

            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.pPolicy->hasFailed = TRUE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;

        case TE_MSG_TYPE_ERROR_RESPONSE:
            status = TRUSTEDGE_agentParseErrorResponse(pCtx, pBody, bodyLen, &errorMsg);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                /* failure to parse error response should be a no-op */
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }

            if (TE_MODE_TYPE_UNKNOWN == errorMsg.mode)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d. Ignoring error response.\n",
                    __func__, __LINE__);
                /* nothing to do for unknown type */
                pCtx->needToProcessResponse = FALSE;
                goto exit; /* skip determin next */
            }
            else if (0 == DIGI_STRCMP(errorMsg.pErrorCode, "AUTHORIZATION_TOKEN_EXPIRED"))
            {
                MSG_LOG_print(MSG_LOG_WARNING, "%s", "Authorization token expired, sending refresh\n");

                status = TRUSTEDGE_agentPolicyUnlinkNode(
                    pCtx->curPolicy.pPolicy, &pCtx->pPendingPolicies);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = TRUSTEDGE_agentPolicyDeleteNodes(&pCtx->pPendingPolicies);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pCtx->pPendingPolicies = pCtx->curPolicy.pPolicy;
                status = TRUSTEDGE_agentSendPolicyRefresh(
                    pCtx,
                    pCtx->configOptions.pDeviceId,
                    pCtx->configOptions.pAccountId,
                    pCtx->curPolicy.pPolicy->pDeviceGroupId);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pCtx->refreshToken          = TRUE;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (TE_MODE_TYPE_UPDATE_ARTIFACT_REQUEST == errorMsg.mode)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount++;
                MSG_LOG_print(MSG_LOG_VERBOSE,
                    "%s line %d. Error response count: %d. Max error responses: %d\n",
                    __func__, __LINE__, pCtx->curPolicy.pPolicy->errorResponseCount, pCtx->maxErrorResponses);
                if (pCtx->curPolicy.pPolicy->errorResponseCount >= pCtx->maxErrorResponses)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE,
                        "%s line %d. Maximum error responses received, treating as fatal.\n",
                        __func__, __LINE__);
                    errorMsg.fatal = TRUE; /* treat as fatal if max attempts reached */
                }

                if (1 == TRUSTEDGE_agentCountPolicies(pCtx->pPendingPolicies) &&
                    FALSE == errorMsg.fatal)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE,
                        "%s line %d. Only one policy, retry download.\n",
                        __func__, __LINE__);
                    break;
                }

                if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                {
                    pCtx->curPolicy.data.ups.pArtifact->ignore = TRUE;
                    pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_INSTALLED;

                    if (TRUE == errorMsg.fatal)
                    {
                        pCtx->curPolicy.pPolicy->hasFailed = TRUE;
                    }

                    if (TRUE == pCtx->curPolicy.pPolicy->hasFailed && FALSE == errorMsg.fatal)
                    {
                        /* clear new error response, done processing. */
                        pCtx->needToProcessResponse = TRUE;
                        goto exit; /* skip determine next */
                    }
                }
                else if (TE_POLICY_STATUS_PENDING == pCtx->curPolicy.pPolicy->status)
                {
                    if (TRUE == TRUSTEDGE_agentHasInstalledArtifact(pCtx->curPolicy.data.ups.pArtifactHead))
                    {
                        MSG_LOG_print(MSG_LOG_VERBOSE,
                            "%s line %d. Installed artifacts, entering rollback mode.\n",
                            __func__, __LINE__);
                        pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_ROLLBACK;
                    }

                    if (TE_ARTIFACT_STATE_DOWNLOADING == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        /* change artifact state back to pending since we will no longer be downloading it */
                        pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_PENDING;
                    }

                    if (TRUE == errorMsg.fatal)
                    {
                        MSG_LOG_print(MSG_LOG_VERBOSE,
                            "%s line %d. Fatal error response.\n",
                            __func__, __LINE__);
                        pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE; /* override */
                        pCtx->curPolicy.pPolicy->hasFailed = TRUE;
                        goto exit; /* skip determine next */
                    }
                }
            }
            else if (TE_MODE_TYPE_UPDATE_DEPLOY_PROGRESS  == errorMsg.mode ||
                     TE_MODE_TYPE_UPDATE_DEPLOY_COMPLETE  == errorMsg.mode ||
                     TE_MODE_TYPE_UPDATE_DEPLOY_FAILED    == errorMsg.mode)
            {
                if (TE_MODE_TYPE_UPDATE_DEPLOY_PROGRESS == errorMsg.mode)
                {
                    sbyte4 sleepTime = 1;
                    sbyte4 maxShifts;

                    pCtx->curPolicy.pPolicy->errorResponseCount++;
                    MSG_LOG_print(MSG_LOG_VERBOSE,
                        "%s line %d. Error response count: %d. Max error responses: %d\n",
                        __func__, __LINE__, pCtx->curPolicy.pPolicy->errorResponseCount, pCtx->maxErrorResponses);
                    if (pCtx->curPolicy.pPolicy->errorResponseCount >= pCtx->maxErrorResponses)
                    {
                        MSG_LOG_print(MSG_LOG_VERBOSE,
                            "%s line %d. Maximum error responses received, skipping.\n",
                            __func__, __LINE__);
                        goto exit;
                    }

                    maxShifts = (pCtx->curPolicy.pPolicy->errorResponseCount < 32)? pCtx->curPolicy.pPolicy->errorResponseCount : 31;
                    for (sbyte4 i = 1; i < maxShifts; i++)
                    {
                        sleepTime <<= 1;
                    }

                    if (TRUE == TRUSTEDGE_sleepCheckStatusMS(sleepTime*1000))
                    {
                        status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                        MSG_LOG_print(MSG_LOG_INFO,
                            "%s line %d status: %d = %s. Sleep interrupted.\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->curPolicy.pPolicy->pDeploymentId,
                        pCtx->curPolicy.data.ups.pArtifact->pId,
                        pCtx->pPatData,
                        pCtx->curPolicy.data.ups.pArtifact->state);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                    }
                }

                /* deployment notification messages should not moving policy */
                goto exit; /* skip determine next */
            }
            else
            {
                pCtx->curPolicy.pPolicy->errorResponseCount++;
                MSG_LOG_print(MSG_LOG_VERBOSE,
                    "%s line %d. Error response count: %d. Max error responses: %d\n",
                    __func__, __LINE__, pCtx->curPolicy.pPolicy->errorResponseCount, pCtx->maxErrorResponses);
                if (pCtx->curPolicy.pPolicy->errorResponseCount >= pCtx->maxErrorResponses)
                {
                    errorMsg.fatal = TRUE; /* treat as fatal if max attempts reached */
                }

                if (TRUE == errorMsg.fatal)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE,
                        "%s line %d. Fatal error response.\n",
                        __func__, __LINE__);
                    pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE; /* override */
                    pCtx->curPolicy.pPolicy->hasFailed = TRUE;
                    goto exit; /* skip determine next */
                }
            }

            break;
        case TE_MSG_TYPE_CLOUDPLATFORM:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "No policy in progress, ignore msg type %d. %s line %d status: %d = %s\n",
                    msgType, __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TE_MSG_TYPE_CLOUDPLATFORM != pCtx->curPolicy.pPolicy->lastMsgSentType)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                MSG_LOG_print(MSG_LOG_WARNING,
                    "MSG type: expecting %d, received %d. %s line %d status: %d = %s\n",
                    TE_MSG_TYPE_CLOUDPLATFORM, pCtx->curPolicy.pPolicy->lastMsgSentType,
                     __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_INFO, "%s", "Processing cloud platform body\n");
            status = TRUSTEDGE_agentParseCloudPlatform(
                pCtx, pBody, bodyLen);
            if (ERR_TRUSTEDGE_UNEXPECTED_MSG == status ||
                ERR_TRUSTEDGE_MSG_PARSING_ERROR == status)
            {
                status = OK;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
            else if (OK != status)
            {
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.lastPolicyMsgType = msgType;
                pCtx->curPolicy.policyErrorStatus = status;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (OK == status)
            {
                pCtx->curPolicy.pPolicy->errorResponseCount = 0;
            }
            break;
        default:
            goto exit;
    }

    status = TRUSTEDGE_agentPolicyDetermineNext(pCtx, msgType);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    if (NULL != pCtx->curPolicy.pPolicy && NULL != errorMsg.pErrorString)
    {
        pCtx->curPolicy.pPolicy->pServerErrorMsg = errorMsg.pErrorString;
        errorMsg.pErrorString = NULL; /* ownership transferred */
    }
    (void) TRUSTEDGE_clearErrorResponse(&errorMsg);

    if (OK == status)
    {
        status = TRUSTEDGE_agentPersistConfiguration(pCtx);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentProcessCommand(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pPayload,
    ubyte4 payloadLen,
    byteBoolean finished)
{
    MSTATUS status;

    /* Debug: Input validation */
    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: ENTER - pCtx=%p, pPayload=%p, payloadLen=%u, finished=%d\n",
        __func__, (void*)pCtx, (void*)pPayload, payloadLen, finished);

    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: pCtx->pPBCtx=%p, pCtx->curTopic=%u\n",
        __func__, (void*)pCtx->pPBCtx, pCtx->curTopic);

    if (pCtx->curTopic < TE_TOPIC_LAST)
    {
        MSG_LOG_print(MSG_LOG_DEBUG,
            "%s: pAllTopics[curTopic].pTopic=%p\n",
            __func__, (void*)pCtx->pAllTopics[pCtx->curTopic].pTopic);
    }

    status = TRUSTEDGE_agentProtobufProcess(
        pCtx, pPayload, payloadLen, finished);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static void TRUSTEDGE_agentLogPayload(
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pMsg,
    ubyte4 msgLen)
{
    MSG_LOG_printRaw(MSG_LOG_VERBOSE, "\n    Outbound Message on Topic: %.*s\n", topicLen, pTopic);
    (void) TRUSTEDGE_agentProtobufPrintMessage(pMsg, msgLen);
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttConsumerHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPublishInfo *pInfo)
{
    MSTATUS status;
    ubyte4 i;
    TrustEdgeAgentCtx *pAgentCtx = NULL;

    status = MQTT_getCookie(connectionInstance, (void **) &pAgentCtx);
    if (OK != status)
    {
        goto exit;
    }

    pAgentCtx->policyReqTimeoutExit = TRUE;

    /* Only process data if consumerStatus is OK */
    if (OK == pAgentCtx->consumerStatus)
    {
        for (i = TE_TOPIC_FIRST; i < TE_TOPIC_LAST; i++)
        {
            if (0 == DIGI_STRNCMP(pAgentCtx->pAllTopics[i].pTopic, pInfo->pTopic, pInfo->topicLen))
            {
                pAgentCtx->curTopic = i;
                switch (i)
                {
                    case TE_TOPIC_NCMD:
                        pAgentCtx->consumerStatus = TRUSTEDGE_agentProcessCommand(
                            pAgentCtx, pInfo->pPayload, pInfo->payloadLen,
                            pMsg->finished);
                        break;

                    case TE_TOPIC_GCMD:
                        pAgentCtx->consumerStatus = TRUSTEDGE_agentProcessCommand(
                            pAgentCtx, pInfo->pPayload, pInfo->payloadLen,
                            pMsg->finished);
                        break;
                }
                break;
            }
        }
    }

    if (TRUE == pMsg->finished)
    {
        /* Last chunk, reset consumer status */
        pAgentCtx->consumerStatus = OK;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttDisconnectHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttDisconnectInfo *pInfo)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pMsg);
    MSG_LOG_print(MSG_LOG_INFO, "%s", "Disconnected from endpoint\n");
    if (NULL != pInfo->pReasonStr)
    {
        MSG_LOG_print(MSG_LOG_INFO, " Disconnect reason: %.*s\n", pInfo->reasonStrLen, pInfo->pReasonStr);
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttConnectEndpoint(
    TrustEdgeAgentCtx *pCtx,
    URI *pURI,
    TCP_SOCKET *pSocket,
    sbyte4 *pSSLConnInst,
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
    TCP_SOCKET *pSocketProxy,
    sbyte4 *pTransportProxy,
#endif
    certStorePtr pStore,
    sbyte4 maxRetryCount)
{
    MSTATUS status;
    sbyte *pScheme = NULL;
    sbyte *pHost = NULL;
    sbyte2 port = 0;
    sbyte pEndpointIp[40];
    byteBoolean closeTCP = FALSE;
    byteBoolean closeSSL = FALSE;
    sbyte4 delay = 1;
    sbyte4 attempts = 0;

    status = URI_GetScheme(pURI, &pScheme);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s line %d status: %d = %s. Failed to get endpoint scheme\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTT) && 0 != DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTTS))
    {
        status = ERR_TRUSTEDGE_AGENT_BAD_ENDPOINT;
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s line %d status: %d = %s. Endpoint scheme %s not allowed\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pScheme);
        goto exit;
    }

    status = URI_GetHost(pURI, &pHost);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s line %d status: %d = %s. Failed to get endpoint host\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = URI_GetPort(pURI, &port);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s line %d status: %d = %s. Failed to get endpoint port\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsGetHostByName(pHost, pEndpointIp);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s line %d status: %d = %s. Failed to resolve MQTT host %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pHost);
        goto exit;
    }

    do {
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
        if (NULL != pCtx->pConfig->pProxyUrl)
        {
            MSG_LOG_print(
                MSG_LOG_INFO,
                "%s", "Connecting to proxy...\n");

            status = TRUSTEDGE_utilsProxyConnect(
                pHost, port, pSocket, pSocketProxy, pTransportProxy,
                pStore);
        }
        else
#endif
        {
            status = TCP_CONNECT(pSocket, pEndpointIp, port);
        }
        if (OK != status)
        {
            if (NULL != pCtx->pTable && NULL != pCtx->pTable->pFuncOnSafeToExit && 1 == pCtx->pTable->pFuncOnSafeToExit(status))
            {
                status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                break;
            }

#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
            if (NULL != pCtx->pConfig->pProxyUrl)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d status: %d = %s. Failed TCP connect to MQTT address %s on port %d through proxy\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pHost, port);
            }
            else
#endif
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d status: %d = %s. Failed TCP connect to MQTT address %s on port %d\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pEndpointIp, port);
            }

            if (TRUE == TRUSTEDGE_sleepCheckStatusMS(delay*1000))
            {
                status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                MSG_LOG_print(MSG_LOG_INFO,
                    "%s line %d status: %d = %s. Sleep interrupted.\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                break;
            }
            delay *= 2;
            attempts++;
        }
    } while (OK != status && attempts < maxRetryCount);
    if (OK != status)
        goto exit;
    closeTCP = TRUE;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (0 == DIGI_STRCMP(pScheme, TRUSTEDGE_AGENT_ENDPOINT_SCHEME_MQTTS))
    {
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
        if (0 <= SSL_isSessionSSL(*pTransportProxy))
        {
            status = SSL_PROXY_connect(
                *pSocketProxy, *pTransportProxy, SSL_PROXY_send, SSL_PROXY_recv,
                *pSocket, 0, NULL, NULL, pHost, pStore);
            if (OK > status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d status: %d = %s. Failed SSL proxy connect to endpoint %s on port %d\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pHost, port);
                goto exit;
            }
        }
        else
#endif
        {
            status = SSL_connect(*pSocket, 0, NULL, NULL, pHost, pStore);
            if (OK > status)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s line %d status: %d = %s. Failed SSL connect to endpoint %s on port %d\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status), pHost, port);
                goto exit;
            }
        }

#if defined(__ENABLE_DIGICERT_PQC__)
        if (TRUE == pCtx->pConfig->requirePQC)
        {
            status = SSL_enforcePQCAlgorithm(*pSSLConnInst);
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

        *pSSLConnInst = (sbyte4) status;
        status = OK;
        closeSSL = TRUE;

        status = SSL_negotiateConnection(*pSSLConnInst);
        if (OK > status)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed SSL negotiation to endpoint %s on port %d\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pHost, port);
            goto exit;
        }
    }
#endif

    MSG_LOG_print(
        MSG_LOG_INFO,
        "Connected to endpoint %s://%s:%d\n", pScheme, pHost, port);

exit:

    if (OK > status)
    {
        if (TRUE == closeSSL)
        {
            SSL_closeConnection(*pSSLConnInst);
        }

        if (TRUE == closeTCP)
        {
            TCP_CLOSE_SOCKET(*pSocket);
        }
    }

    DIGI_FREE((void **) &pHost);
    DIGI_FREE((void **) &pScheme);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentMqttConnect(
    TrustEdgeAgentCtx *pCtx,
    TCP_SOCKET *pSocket,
    sbyte4 *pSSLConnInst,
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
    TCP_SOCKET *pSocketProxy,
    sbyte4 *pTransportProxy,
#endif
    certStorePtr pStore)
{
    MSTATUS status = ERR_TRUSTEDGE_AGENT_NO_ENDPOINTS;
    URI *pEndpoint;
    ubyte4 i;

    /* Input validation not required */
    *pSSLConnInst = -1;

    for (i = 0; i < pCtx->mqttConfig.totalEndpoints; i++)
    {
        pEndpoint = pCtx->mqttConfig.ppEndpoints[i];

        if (NULL == pEndpoint)
        {
            status = ERR_NULL_POINTER;
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. No endpoint with appropriate security strength found at index %d\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), i);
            continue;
        }

        status = TRUSTEDGE_agentMqttConnectEndpoint(
            pCtx, pEndpoint, pSocket, pSSLConnInst,
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
            pSocketProxy, pTransportProxy,
#endif
            pStore, pCtx->maxRetryCount);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed to connect to endpoint %s at index %d\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pEndpoint->uriBuf, i);
            if (ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT == status)
            {
                goto exit;
            }
        }
        else
        {
            pCtx->mqttConfig.connEPIdx = i;
            MSG_LOG_print(MSG_LOG_VERBOSE, "Connected to endpoint %s at index %d\n",
                pEndpoint->uriBuf, i);
            break;
        }
    }

exit:

    if (OK != status)
    {
        /* Intentional status code override */
        status = ERR_TRUSTEDGE_AGENT_NO_ENDPOINTS;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentCreateNBirthMsg(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppNBirthMsg,
    ubyte4 *pNBirthMsgLen);

extern MSTATUS TRUSTEDGE_agentWriteMetrics(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice);

#define MQTT_NCMD_TOPIC         "spBv1.0/%s/NCMD/%s"
#define MQTT_NBIRTH_TOPIC       "spBv1.0/%s/NBIRTH/%s"
#define MQTT_NDATA_TOPIC        "spBv1.0/%s/NDATA/%s"
#define MQTT_GCMD_TOPIC         "spBv1.0/%s/GCMD/%s"
#define MQTT_NDEATH_TOPIC       "spBv1.0/%s/NDEATH/%s"

extern MSTATUS TRUSTEDGE_agentPublishMessage(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentTopic topic,
    ubyte *pMsg,
    ubyte4 msgLen)
{
    MSTATUS status;
    MqttPublishOptions pubOptions = { 0 };
    MqttPublishOptions *pPubOptions = NULL;
    sbyte4 backoffInterval = 1;
    sbyte4 maxRetryCount;
    sbyte4 attempts = 0;

    if (TE_TOPIC_FIRST > topic || TE_TOPIC_LAST <= topic)
    {
        status = ERR_TRUSTEDGE_AGENT_UNKNOWN_TOPIC;
        goto exit;
    }

    if (TE_TOPIC_NDEATH == topic)
    {
        pPubOptions = &pubOptions;
        pubOptions.qos = MQTT_QOS_1;
    }

    TRUSTEDGE_agentLogPayload(
        pCtx->pAllTopics[topic].pTopic, DIGI_STRLEN(pCtx->pAllTopics[topic].pTopic),
        pMsg, msgLen);

    maxRetryCount = pCtx->maxRetryCount;
    do {
        status = MQTT_publish(
            pCtx->connInst, pPubOptions,
            pCtx->pAllTopics[topic].pTopic,
            DIGI_STRLEN(pCtx->pAllTopics[topic].pTopic),
            pMsg, msgLen);
        if (OK != status)
        {
            if (NULL != pCtx->pTable && NULL != pCtx->pTable->pFuncOnSafeToExit && 1 == pCtx->pTable->pFuncOnSafeToExit(status))
            {
                status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                break;
            }

            MSG_LOG_print(MSG_LOG_WARNING,
                "%s line %d status: %d = %s. Failed to publish message\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));

            if (TRUE == TRUSTEDGE_sleepCheckStatusMS(backoffInterval*1000))
            {
                status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                MSG_LOG_print(MSG_LOG_INFO,
                    "%s line %d status: %d = %s. Sleep interrupted.\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                break;
            }

            backoffInterval *= 2;
            attempts++;

            if (attempts >= maxRetryCount)
            {
                status = ERR_TRUSTEDGE_AGENT_MQTT_PUBLISH_ERROR;
                break;
            }
        }
    } while (OK != status);

exit:

    (void) TRUSTEDGE_agentPersistConfiguration(pCtx);
    return status;
}

#define MQTT_NDEATH_MSG \
    "{\n" \
    "    \"divisionId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"deviceGroupId\":\"%s\"\n" \
    "}\n"

static MSTATUS TRUSTEDGE_agentCreateNDeathMsg(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppNDeathTopic,
    ubyte4 *pNDeathTopicLen,
    ubyte **ppNDeathMsg,
    ubyte4 *pNDeathMsgLen)
{
    MSTATUS status;
    sbyte4 ret;
    ubyte *pWill = NULL;
    ubyte4 willLen;
    ubyte *pProtoWill = NULL;
    ubyte4 protoWillLen;
    ubyte *pWillTopic = NULL;
    ubyte4 willTopicLen;

    if (NULL == pCtx || NULL == ppNDeathMsg || NULL == pNDeathMsgLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    willLen = snprintf (NULL, 0, MQTT_NDEATH_MSG,
        pCtx->configOptions.pDivisionId,
        pCtx->configOptions.pAccountId,
        pCtx->configOptions.pDeviceId,
        pCtx->configOptions.pDeviceGroupId);
    if (0 >= willLen)
    {
        status = ERR_TRUSTEDGE;
        goto exit;
    }

    status = DIGI_MALLOC ((void **) &pWill, willLen + 1);
    if (OK != status)
        goto exit;

    ret = snprintf (pWill, willLen + 1, MQTT_NDEATH_MSG,
        pCtx->configOptions.pDivisionId,
        pCtx->configOptions.pAccountId,
        pCtx->configOptions.pDeviceId,
        pCtx->configOptions.pDeviceGroupId);
    if (0 >= ret)
    {
        DIGI_FREE((void **) &pWill);
        status = ERR_TRUSTEDGE;
        goto exit;
    }

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, "DeviceTM_Agent_Disconnected", pWill, willLen, &pProtoWill, &protoWillLen);
    DIGI_FREE((void **) &pWill);
    if (OK != status)
    {
        goto exit;
    }


    if (NULL != ppNDeathTopic && NULL != pNDeathTopicLen)
    {
        willTopicLen = snprintf(NULL, 0, MQTT_NDEATH_TOPIC,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDeviceId);
        if (0 >= willTopicLen)
        {
            status = ERR_TRUSTEDGE;
            goto exit;
        }

        status = DIGI_MALLOC ((void **) &pWillTopic, willTopicLen + 1);
        if (OK != status)
            goto exit;

        ret = snprintf(pWillTopic, willTopicLen + 1, MQTT_NDEATH_TOPIC,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDeviceId);
        if (0 >= ret)
        {
            status = ERR_TRUSTEDGE;
            goto exit;
        }

        *ppNDeathTopic = pWillTopic; pWillTopic = NULL;
        *pNDeathTopicLen = willTopicLen;
    }

    *ppNDeathMsg = pProtoWill; pProtoWill = NULL;
    *pNDeathMsgLen = protoWillLen;

exit:
    DIGI_FREE((void **) &pProtoWill);
    DIGI_FREE((void **) &pWillTopic);

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentTimeoutHandler(
    sbyte4 connInst,
    ubyte4 *pTimeout)
{
    MSTATUS status;
    TrustEdgeAgentCtx *pAgentCtx = NULL;
    ubyte4 elapsedTime;

    if (NULL != gFuncPtrTable.pFuncOnSafeToExit && 1 == gFuncPtrTable.pFuncOnSafeToExit(OK))
    {
        *pTimeout = 0;
        status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
        goto exit;
    }

    status = MQTT_getCookie(connInst, (void **) &pAgentCtx);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == pAgentCtx->policyReqTimeoutExit)
    {
        *pTimeout = 0;
        goto exit;
    }

    elapsedTime = RTOS_deltaMS(&pAgentCtx->policyReqTimer, NULL);
    if (elapsedTime >= pAgentCtx->policyRequestTimeout * 1000)
    {
        pAgentCtx->timeoutExpired = TRUE;
        *pTimeout = 0;
    }
    else
    {
        *pTimeout = (pAgentCtx->policyRequestTimeout * 1000) - elapsedTime;
        if (TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS < *pTimeout)
        {
            *pTimeout = TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS;
        }
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentConnectEndPoint(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    URI *pUri = NULL;
    sbyte *pHost = NULL;
    MqttPacketHandlers mqttHandlers = { 0 };
    MqttConnectOptions mqttConnectOptions = { 0 };
    MqttDisconnectOptions mqttDisconnectOptions = { 0 };
    sbyte *pJWSAuth = NULL;
    int ret;
    sbyte4 connectionStartTime;
    sbyte4 currentTime;
    sbyte *pTopic = NULL;
    ubyte *pNBirthMsg = NULL;
    ubyte4 nBirthMsgLen = 0;
    ubyte4 i;
    MqttSubscribeTopic topic = { 0 };
    sbyte *pSub = NULL;
    byteBoolean closeConnection = FALSE;
    ubyte *pWill = NULL;
    ubyte4 willLen = 0;
    ubyte *pWillTopic = NULL;
    ubyte4 willTopicLen = 0;
    sbyte4 backoffInterval = 1;
    sbyte4 maxRetryCount;
    sbyte4 attempts = 0;
    byteBoolean certRenewPending = FALSE;

    /* Input validation not required */

    MSG_LOG_print(MSG_LOG_INFO, "%s", "Constructing JWS authentication token\n");

    status = TRUSTEDGE_agentCreateJWSAuth(pCtx, &pJWSAuth);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
    TRUSTEDGE_agentKeepMsg(pCtx, "JWSAuth", pJWSAuth, DIGI_STRLEN(pJWSAuth));
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__ */

    MSG_LOG_print(MSG_LOG_INFO, "%s", "Starting connection to MQTT endpoint...\n");

    status = TRUSTEDGE_agentMqttConnect(
        pCtx, &pCtx->mqttConfig.socket,
        &pCtx->mqttConfig.sslConnInst,
#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
        &pCtx->mqttConfig.socketProxy, &pCtx->mqttConfig.transportProxy,
#endif
        pCtx->pTrustedStore);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to connect to all endpoints\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    closeConnection = TRUE;

    pCtx->connInst = MQTT_connect(
        MQTT_V5, pCtx->configOptions.pDeviceId,
        DIGI_STRLEN(pCtx->configOptions.pDeviceId));
    if (0 > pCtx->connInst)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, pCtx->connInst,
            MERROR_lookUpErrorCode(pCtx->connInst));

        status = ERR_TRUSTEDGE_AGENT_MQTT_CONNECT_FAILED;
        goto exit;
    }

    status = MQTT_setCookie(pCtx->connInst, pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = MQTT_setProtocolBufferSize(pCtx->connInst, pCtx->protocolBufferSize);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (-1 < pCtx->mqttConfig.sslConnInst)
    {
        status = MQTT_setTransportSSL(pCtx->connInst, pCtx->mqttConfig.sslConnInst);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else
    {
        status = MQTT_setTransportTCP(pCtx->connInst, pCtx->mqttConfig.socket);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    mqttHandlers.connAckHandler = TRUSTEDGE_agentMqttConnAckHandler;
    mqttHandlers.publishHandler = TRUSTEDGE_agentMqttConsumerHandler;
    mqttHandlers.disconnectHandler = TRUSTEDGE_agentMqttDisconnectHandler;
    mqttHandlers.subAckHandler = TRUSTEDGE_agentMqttSubAckHandler;
    status = MQTT_setControlPacketHandlers(pCtx->connInst, &mqttHandlers);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *) &(mqttConnectOptions.willInfo), 0x00, sizeof (mqttConnectOptions.willInfo));
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_agentCreateNDeathMsg (pCtx, &pWillTopic, &willTopicLen, &pWill, &willLen);
    if (OK != status)
        goto exit;

    mqttConnectOptions.willInfo.pWill = pWill;
    mqttConnectOptions.willInfo.willLen = willLen;
    mqttConnectOptions.willInfo.pWillTopic = pWillTopic;
    mqttConnectOptions.willInfo.willTopicLen = willTopicLen;

    /* these two settings are required for compatibiity with broker */
    mqttConnectOptions.willInfo.retain = FALSE;
    mqttConnectOptions.willInfo.qos = MQTT_QOS_1;

    mqttConnectOptions.keepAliveInterval = pCtx->keepAliveInterval;
    /* Set authentication in MQTT connect message */
    mqttConnectOptions.pPassword = pJWSAuth;
    mqttConnectOptions.passwordLen = DIGI_STRLEN(pJWSAuth);

    mqttConnectOptions.pollingInterval = pCtx->policyRequestTimeout * 1000;

    pCtx->mqttConfig.status = ERR_TRUSTEDGE_AGENT_BAD_ENDPOINT;
    status = MQTT_negotiateConnection(pCtx->connInst, &mqttConnectOptions);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_AGENT_MQTT_CONNECT_FAILED;
        goto exit;
    }

    if (OK != pCtx->mqttConfig.status)
    {
        status = pCtx->mqttConfig.status;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = MQTT_setRecieveTimeoutHandler(
        pCtx->connInst, TRUSTEDGE_agentTimeoutHandler);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Launch thread to handle keep alive */
    status = MQTT_startKeepAliveThread(pCtx->connInst);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = TE_TOPIC_FIRST; i < TE_TOPIC_LAST; i++)
    {
        if (pCtx->pAllTopics[i].attributes & TE_TOPIC_CMD_SUB)
        {
            MSG_LOG_print(MSG_LOG_INFO, "Subscribing to %s\n", pCtx->pAllTopics[i].pTopic);

            topic.pTopic = pCtx->pAllTopics[i].pTopic;
            topic.topicLen = DIGI_STRLEN(pCtx->pAllTopics[i].pTopic);
            if (TE_TOPIC_GCMD == i)
            {
                topic.qos = MQTT_QOS_1;
            }
            else
            {
                topic.qos = MQTT_QOS_0;
            }

            status = MQTT_subscribe(pCtx->connInst, &topic, 1, NULL);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));

                status = ERR_TRUSTEDGE_AGENT_TOPIC_SUBSCRIBE;
                goto exit;
            }
        }
    }

    MSG_LOG_print(MSG_LOG_INFO, "%s", "Constructing NBIRTH Message\n");

    status = TRUSTEDGE_agentCreateNBirthMsg(
        pCtx, &pNBirthMsg, &nBirthMsgLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
    TRUSTEDGE_agentKeepMsg(pCtx, "NBIRTH", pNBirthMsg, nBirthMsgLen);
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__ */

    ret = snprintf(NULL, 0, MQTT_NBIRTH_TOPIC,
                    pCtx->configOptions.pAccountId,
                    pCtx->configOptions.pDeviceId);
    DIGI_MALLOC((void **) &pTopic, ret + 1);
    ret = snprintf(pTopic, ret + 1, MQTT_NBIRTH_TOPIC,
                    pCtx->configOptions.pAccountId,
                    pCtx->configOptions.pDeviceId);

    MSG_LOG_print(
        MSG_LOG_INFO, "Publishing NBIRTH message to topic %s\n", pTopic);

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NBIRTH, pNBirthMsg, nBirthMsgLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Check if any certificates need to be renewed */
    status = TRUSTEDGE_agentCertificateRenewAll(pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* TODO: What is the exit condition?
     *
     * - persist connection in bootstrap configuration file? How long do we
     * listen for?
     * - for platforms which support signals, add signal handling to exit?
     * - what about RTOSes that don't have signal handling?
     */
#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
    connectionStartTime = time(NULL);
#endif
    pCtx->exitClient = FALSE;
    maxRetryCount = pCtx->maxRetryCount;

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
    TRUSTEDGE_setState(CONNECTED);
#endif

    while (FALSE == pCtx->recievedPendingPolicies || NULL != pCtx->pPendingPolicies ||
           MQTT_transactionPending(pCtx->connInst) || TRUE == pCtx->mqttConfig.persistConnection ||
           (OK == (status = TRUSTEDGE_agentCertificateAnyRenewalPending(pCtx, &certRenewPending)) && TRUE == certRenewPending ))
    {
        if (FALSE == pCtx->needToProcessResponse) /* No response to process, wait for data... */
        {
            RTOS_deltaMS(NULL, &pCtx->policyReqTimer);
            pCtx->policyReqTimeoutExit = FALSE;

            status = MQTT_recv(pCtx->connInst);
            if (OK != status)
            {
                if (NULL != pCtx->pTable && NULL != pCtx->pTable->pFuncOnSafeToExit && 1 == pCtx->pTable->pFuncOnSafeToExit(status))
                {
                    /* For general purpose OSes, if signal handler was invoked,
                     * and application was in a system socket call, the system call
                     * is not restarted and will return a TCP error */
                    status = OK;
                    pCtx->exitClient = TRUE;
                    break;
                }

                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. Failed to receive message\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));

                if (TRUE == TRUSTEDGE_sleepCheckStatusMS(backoffInterval*1000))
                {
                    status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                    MSG_LOG_print(MSG_LOG_INFO,
                        "%s line %d status: %d = %s. Sleep interrupted.\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    break;
                }
                backoffInterval *= 2;
                attempts++;

                if (attempts >= maxRetryCount)
                {
                    status = ERR_TRUSTEDGE_AGENT_MQTT_RECEIVE_ERROR;
                    break;
                }
                else
                {
                    status = OK;
                    continue;
                }
            }

            if (TRUE == pCtx->timeoutExpired)
            {
                if (NULL != pCtx->curPolicy.pPolicy)
                {
                    MSG_LOG_print(MSG_LOG_WARNING,
                        "Timeout of %d seconds expired waiting for response\n",
                        pCtx->policyRequestTimeout);
                    pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                }
            }

#ifdef __ENABLE_DIGICERT_TOKEN_MISSING_FALLBACK__
            if(TRUE == pCtx->enforceToken && FALSE == pCtx->isPAT)
            {
                /* Free the current endpoint which has not provided Policy auth token */
                ubyte index = pCtx->mqttConfig.connEPIdx;
                MSG_LOG_print(MSG_LOG_INFO, "No policy auth token found.Freeing the endpoint %s at index %d \n",
                    pCtx->mqttConfig.ppEndpoints[index]->uriBuf, index);
                URI_DELETE(pCtx->mqttConfig.ppEndpoints[index]);
                pCtx->mqttConfig.ppEndpoints[index] = NULL;

                /* Later connect to next available end point */
                status = ERR_TRUSTEDGE_AGENT_NO_POLICY_AUTH_TOKEN;
                goto exit;
            }
#endif

            if (OK != pCtx->mqttConfig.status)
            {
                status = pCtx->mqttConfig.status;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));

                if (TRUE == TRUSTEDGE_sleepCheckStatusMS(backoffInterval*1000))
                {
                    status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                    MSG_LOG_print(MSG_LOG_INFO,
                        "%s line %d status: %d = %s. Sleep interrupted.\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                backoffInterval *= 2;
                attempts++;

                if (attempts >= maxRetryCount)
                {
                    /* use status that was set by mqttConfig.status */
                    break;
                }
                else
                {
                    status = OK;
                    continue;
                }
            }
        }

        status = TRUSTEDGE_agentProcessCurrentPolicyNodes(pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TRUSTEDGE_agentPersistConfiguration(pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (FALSE == pCtx->mqttConfig.persistConnection &&
            TRUE == pCtx->recievedPendingPolicies &&
            NULL == pCtx->pPendingPolicies &&
            ((OK != (status = TRUSTEDGE_agentCertificateAnyRenewalPending(pCtx, &certRenewPending)) || FALSE == certRenewPending )))
        {
            break;
        }

        if (0 < pCtx->connectionUptimeInterval && TRUE == pCtx->timeoutExpired)
        {
#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
            currentTime = time(NULL);
            if (currentTime - connectionStartTime >= pCtx->connectionUptimeInterval)
            {
                break;
            }
#endif
        }

        if (TRUE == pCtx->timeoutExpired)
        {
            pCtx->timeoutExpired = FALSE;
        }

        if (NULL != pCtx->pTable && NULL != pCtx->pTable->pFuncOnSafeToExit && 1 == pCtx->pTable->pFuncOnSafeToExit(status))
        {
            pCtx->exitClient = TRUE;
            break; /* exit */
        }

        /* check to see if any outstanding artifacts have been completed */
        if (NULL != pCtx->curPolicy.pPolicy && TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type &&
            NULL != pCtx->curPolicy.data.ups.pArtifact &&
            TRUE == pCtx->curPolicy.data.ups.pArtifact->isAsync &&
            (TE_ARTIFACT_STATE_INSTALLING  == pCtx->curPolicy.data.ups.pArtifact->state ||
            TE_ARTIFACT_STATE_UNINSTALLING == pCtx->curPolicy.data.ups.pArtifact->state))
        {
            status = TRUSTEDGE_agentCheckStatusFile(pCtx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

exit:
    MSG_LOG_print(MSG_LOG_INFO, "%s", "Terminating connection to MQTT endpoint\n");

    DIGI_FREE((void **) &pWill);
    DIGI_FREE((void **) &pWillTopic);
    DIGI_FREE((void **) &pSub);
    DIGI_FREE((void **) &pNBirthMsg);
    DIGI_FREE((void **) &pHost);
    DIGI_FREE((void **) &pTopic);
    URI_DELETE(pUri);
    DIGI_FREE((void **) &pJWSAuth);
    if (TRUE == closeConnection)
    {
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
        TRUSTEDGE_setState(DISCONNECTED);
#endif
        RTOS_sleepMS(5000);
        if (-1 < pCtx->connInst)
        {
            mqttDisconnectOptions.reasonCode = MQTT_DISCONNECT_SEND_WILL;
            MQTT_disconnect(pCtx->connInst, &mqttDisconnectOptions);
            MQTT_closeConnection(pCtx->connInst);
        }
        if (-1 < pCtx->mqttConfig.sslConnInst)
        {
            SSL_closeConnection(pCtx->mqttConfig.sslConnInst);
        }
        TCP_CLOSE_SOCKET(pCtx->mqttConfig.socket);
        if (-1 < pCtx->mqttConfig.transportProxy)
        {
            SSL_closeConnection(pCtx->mqttConfig.transportProxy);
        }
        TCP_CLOSE_SOCKET(pCtx->mqttConfig.socketProxy);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentInit(
    TrustEdgeAgentCtx *pAgentCtx)
{
    MSTATUS status = OK;
    TrustEdgeAgentTopic topic;
    ubyte4 attributes;
    sbyte *pTopicString;
    int ret;
    sbyte *pSubTopic1 = NULL;
    sbyte *pSubTopic2 = NULL;

    status = COMMON_UTILS_addPathComponent(
        pAgentCtx->pConfig->pKeystoreReqDir, ISSUED_CERT_DIR,
        &pAgentCtx->pIssuedCertDir);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pAgentCtx->pIssuedCertDir, NULL))
    {
        status = FMGMT_mkdir(pAgentCtx->pIssuedCertDir, 0777);
        if (OK != status)
        {
            goto exit;
        }
    }

    for (topic = TE_TOPIC_FIRST; topic < TE_TOPIC_LAST; topic++)
    {
        attributes = 0;
        pTopicString = NULL;

        switch (topic)
        {
            case TE_TOPIC_NCMD:
                attributes = TE_TOPIC_CMD_SUB;
                pTopicString = MQTT_NCMD_TOPIC;
                pSubTopic1 = pAgentCtx->configOptions.pAccountId;
                pSubTopic2 = pAgentCtx->configOptions.pDeviceId;
                break;

            case TE_TOPIC_NBIRTH:
                pTopicString = MQTT_NBIRTH_TOPIC;
                pSubTopic1 = pAgentCtx->configOptions.pAccountId;
                pSubTopic2 = pAgentCtx->configOptions.pDeviceId;
                break;

            case TE_TOPIC_NDATA:
                pTopicString = MQTT_NDATA_TOPIC;
                pSubTopic1 = pAgentCtx->configOptions.pAccountId;
                pSubTopic2 = pAgentCtx->configOptions.pDeviceId;
                break;

            case TE_TOPIC_GCMD:
                attributes = TE_TOPIC_CMD_SUB;
                pTopicString = MQTT_GCMD_TOPIC;
                pSubTopic1 = pAgentCtx->configOptions.pAccountId;
                pSubTopic2 = pAgentCtx->configOptions.pDeviceGroupId;
                break;

            case TE_TOPIC_NDEATH:
                pTopicString = MQTT_NDEATH_TOPIC;
                pSubTopic1 = pAgentCtx->configOptions.pAccountId;
                pSubTopic2 = pAgentCtx->configOptions.pDeviceId;
                break;

            default:
                status = ERR_TRUSTEDGE_AGENT_TOPIC_NOT_SUPPORTED;
                goto exit;
        }

        pAgentCtx->pAllTopics[topic].attributes = attributes;

        ret = snprintf(NULL, 0, pTopicString,
                        pSubTopic1,
                        pSubTopic2);
        DIGI_MALLOC((void **) &pAgentCtx->pAllTopics[topic].pTopic, ret + 1);
        ret = snprintf(pAgentCtx->pAllTopics[topic].pTopic, ret + 1, pTopicString,
                        pSubTopic1,
                        pSubTopic2);
    }

    status = CERT_STORE_createStore(&pAgentCtx->pTrustedStore);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_addTrustPointCertsByDir(
        pAgentCtx->pTrustedStore, NULL, pAgentCtx->pConfig->pKeystoreCADir,
        FALSE);
    if (OK != status)
    {
        goto exit;
    }

    /* Assume agent does not have any pending data */
    pAgentCtx->needToProcessResponse = FALSE;

    /* Can update needToProcessResponse to TRUE depending on what state the
     * policies are in */
    status = TRUSTEDGE_agentPersistLoadConfiguration(pAgentCtx);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pAgentCtx->pPendingPolicies)
    {
        MSG_LOG_print(MSG_LOG_INFO, "%s", "Loaded pending policies from persisted configuration\n");
        TRUSTEDGE_agentPolicyPrintNodes(pAgentCtx->pPendingPolicies);
        /* Technically have recieved pending policies */
        pAgentCtx->recievedPendingPolicies = TRUE;
    }

    if (NULL != pAgentCtx->curPolicy.pPolicy)
    {
        MSG_LOG_print(MSG_LOG_INFO, "Loaded processing policy ID %s from persisted configuration\n", pAgentCtx->curPolicy.pPolicy->pId);
        /* Technically have recieved pending policies */

        if (TE_POLICY_STATUS_SUCCESS != pAgentCtx->curPolicy.pPolicy->status)
            pAgentCtx->recievedPendingPolicies = TRUE;
    }

    if (NULL != pAgentCtx->pAppliedPolicies)
    {
        MSG_LOG_print(MSG_LOG_INFO, "%s", "Loaded applied policies from persisted configuration\n");
        TRUSTEDGE_agentPolicyPrintNodes(pAgentCtx->pAppliedPolicies);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentContextProcess(
    TrustEdgeAgentContext *pCtx,
    TrustEdgeAgentResult **ppResult)
{
    MOC_UNUSED(ppResult);
    MSTATUS status;
    TrustEdgeAgentCtx *pAgentCtx = pCtx;

    if (NULL == pAgentCtx)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Agent context is NULL\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    do {
        status = TRUSTEDGE_agentConnectEndPoint(pAgentCtx);
        if (OK != status)
        {
#ifdef __ENABLE_DIGICERT_TOKEN_MISSING_FALLBACK__
            if (ERR_TRUSTEDGE_AGENT_NO_POLICY_AUTH_TOKEN == status)
            {
                MSG_LOG_print(MSG_LOG_INFO, "%s trying next available end point..\n", __func__);
                pAgentCtx->isPAT = TRUE;
            }
            else
#endif
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    } while (OK != status);

    status = TRUSTEDGE_agentWriteMetrics(pAgentCtx, TE_DESIRED_ATTRIBUTES_FILE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

/**
 * Release TrustEdge agent context
 *
 * @param ppCtx         TrustEdge agent context to release
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
extern MSTATUS TRUSTEDGE_agentContextRelease(
    TrustEdgeAgentContext **ppCtx)
{
    TrustEdgeAgentCtx **ppAgentCtx = (TrustEdgeAgentCtx **) ppCtx;
    MSTATUS status = OK;
    MSTATUS fstatus;
    ubyte4 i;

    if (NULL != ppAgentCtx && NULL != *ppAgentCtx)
    {
        if (NULL != (*ppAgentCtx)->curPolicy.pPolicy)
        {
            status = TRUSTEDGE_agentPolicyClearCurrent(&((*ppAgentCtx)->curPolicy));
        }

        for (i = TE_TOPIC_FIRST; i < TE_TOPIC_LAST; i++)
        {
            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pAllTopics[i].pTopic));
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pDeviceId));
        if (OK == status)
            status = fstatus;

        if (NULL != (*ppAgentCtx)->configOptions.pDeviceName)
        {
            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pDeviceName));
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pAccountId));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pDeviceGroupId));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pDivisionId));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pAuthKey));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->configOptions.pAuthCert));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pBootstrapConfigFile));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pBootstrapSigFile));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pIssuedCertDir));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pWorkspaceDir));
        if (OK == status)
            status = fstatus;

#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
        if (NULL != (*ppAgentCtx)->pDebugDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pDebugDir));
            if (OK == status)
                status = fstatus;
        }
#endif

        if (NULL != (*ppAgentCtx)->pPatData)
        {
            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pPatData));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppAgentCtx)->pPatFile)
        {
            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pPatFile));
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pMetricFile));
        if (OK == status)
            status = fstatus;

        fstatus = HASH_TABLE_removePtrsTable((*ppAgentCtx)->pMetrics, NULL);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->pDesiredAttributeFile));
        if (OK == status)
            status = fstatus;

        fstatus = HASH_TABLE_removePtrsTable((*ppAgentCtx)->pDesiredAttributes, NULL);
        if (OK == status)
            status = fstatus;

        if (NULL != (*ppAgentCtx)->mqttConfig.ppEndpoints)
        {
            for (i = 0; i < (*ppAgentCtx)->mqttConfig.totalEndpoints; i++)
            {
                fstatus = URI_DELETE((*ppAgentCtx)->mqttConfig.ppEndpoints[i]);
                if (OK == status)
                {
                    status = fstatus;
                    (*ppAgentCtx)->mqttConfig.ppEndpoints[i] = NULL;
                }
            }

            fstatus = DIGI_FREE((void **) &((*ppAgentCtx)->mqttConfig.ppEndpoints));
            if (OK == status)
                status = fstatus;
        }

        fstatus = TRUSTEDGE_utilsDeleteConfig(&((*ppAgentCtx)->pConfig));
        if (OK == status)
            status = fstatus;

        fstatus = CERT_STORE_releaseStore(&(*ppAgentCtx)->pTrustedStore);
        if (OK == status)
            status = fstatus;

        if (NULL != (*ppAgentCtx)->pAppliedPolicies)
        {
            fstatus = TRUSTEDGE_agentPolicyDeleteNodes(&(*ppAgentCtx)->pAppliedPolicies);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppAgentCtx)->pErrorPolicies)
        {
            fstatus = TRUSTEDGE_agentPolicyDeleteNodes(&(*ppAgentCtx)->pErrorPolicies);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppAgentCtx)->pPendingPolicies)
        {
            fstatus = TRUSTEDGE_agentPolicyDeleteNodes(&(*ppAgentCtx)->pPendingPolicies);
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) ppAgentCtx);
        if (OK == status)
            status = fstatus;

    }

    return status;
}

/*----------------------------------------------------------------------------*/

static intBoolean TRUSTEDGE_isFatalError(MSTATUS status)
{
    if (OK <= status)
        return FALSE;

    /* errors that are not fatal */
    switch (status)
    {
        case ERR_TRUSTEDGE_AGENT_NO_ENDPOINTS:
        case ERR_TRUSTEDGE_AGENT_MQTT_CONNECT_FAILED:
        case ERR_TRUSTEDGE_AGENT_TOPIC_SUBSCRIBE:
        case ERR_TRUSTEDGE_AGENT_UNKNOWN_TOPIC:
        case ERR_TRUSTEDGE_AGENT_MQTT_RECEIVE_ERROR:
        case ERR_TRUSTEDGE_AGENT_MQTT_PUBLISH_ERROR:
        case ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT:
            return FALSE;
        default:
            return TRUE;
    };
}

/*----------------------------------------------------------------------------*/
static MSTATUS TRUSTEDGE_agentGetCurrentTimeSeconds(ubyte4 *currentTimeSeconds)
{
    MSTATUS status;
    TimeDate currentTime = { 0 };
    TimeDate epochTime = { 0 };
    sbyte4 totalSeconds = 0;

    status = RTOS_timeGMT(&currentTime);
    if (OK != status)
        goto exit;

    epochTime.m_year = 0;
    epochTime.m_month = 1;
    epochTime.m_day = 1;
    epochTime.m_hour = 0;
    epochTime.m_minute = 0;
    epochTime.m_second = 0;

    currentTime.m_day += 1;
    status = DATETIME_diffTime(&currentTime, &epochTime, &totalSeconds);
    if (OK != status)
        goto exit;

    *currentTimeSeconds = (ubyte4)totalSeconds;
exit:
    return status;
}

extern MSTATUS TRUSTEDGE_agentContextService(
    TrustEdgeConfig **ppConfig,
    TrustEdgeAgentResult **ppResult)
{
    MSTATUS status;
    TrustEdgeAgentContext *pCtx = NULL;
    TrustEdgeAgentCtx *pAgentCtx;
    TrustEdgeConfig *pConfig = NULL;
    TrustEdgeConfig *pCopy = NULL;
    sbyte4 sleepInterval;
    sbyte4 refreshHours;
    byteBoolean exitClient;
    ubyte4 currentTimeSeconds;
    ubyte4 lastAttrScanTimeSeconds;
    sbyte4 diffTime;
    sbyte *pValue = NULL;

    if (NULL == ppConfig || NULL == *ppConfig)
    {
        status = ERR_TRUSTEDGE_NO_CONFIG_FILE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. TRUSTEDGE_agentContextService: config missing\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pConfig = *ppConfig;
    *ppConfig = NULL;

    /* check if we have a bootstrap configuration before attempting to start service */
    if (NULL == pConfig->pBootstrapConfig)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s", "No bootstrap configuration file provided\n");
        status = OK;
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pConfig->pBootstrapConfig, NULL))
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s", "Bootstrap configuration not initialized\n");
        status = OK;
        goto exit;
    }

    do {
        DIGI_FREE((void **) &pValue);
        status = FMGMT_getEnvironmentVariableValueAlloc(TRUSTEDGE_AGENT_BOOTSTRAP_SIGNATURE_ENV, &pValue);
        if (OK == status)
        {
            if (0 == DIGI_STRNICMP("ON", pValue, DIGI_STRLEN("ON")))
            {
                pConfig->verifyBootstrapSig = TRUE;
            }
            else if (0 == DIGI_STRNICMP("OFF", pValue, DIGI_STRLEN("OFF")))
            {
                pConfig->verifyBootstrapSig = FALSE;
            }
            else
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "%s %s", TRUSTEDGE_AGENT_BOOTSTRAP_SIGNATURE_ENV, "environment variable must be set to ON or OFF\n");
            }
        }

        status = TRUSTEDGE_utilsCloneConfig (pConfig, &pCopy);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. TRUSTEDGE_utilsCloneConfig failed\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }


        status = TRUSTEDGE_agentContextAcquire(&pCtx, &pCopy);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. TRUSTEDGE_agentContextAcquire failed\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pAgentCtx = pCtx;
        refreshHours = pAgentCtx->refreshHours;

        /* convert current time to seconds */
        status = TRUSTEDGE_agentGetCurrentTimeSeconds(&currentTimeSeconds);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. TRUSTEDGE_agentGetCurrentTimeSeconds failed\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* convert last attribute in milliseconds to seconds */
        lastAttrScanTimeSeconds = pAgentCtx->lastAttrScanTime / 1000;

        diffTime = (sbyte4)(currentTimeSeconds - lastAttrScanTimeSeconds);

        if (diffTime >= (refreshHours * 60 * 60))
        {
            MSG_LOG_print(MSG_LOG_INFO, "%s", "Scanning attributes...\n");
            status = TRUSTEDGE_agentComputeInventoryAttributes(pAgentCtx, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. TRUSTEDGE_agentComputeInventoryAttributes failed\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        /* override persistConnection option in bootstrap when running
         * in service mode */
        pAgentCtx->mqttConfig.persistConnection = TRUE;
        pAgentCtx->service = TRUE;

        status = TRUSTEDGE_agentContextProcess(pCtx, ppResult);
        if (TRUE == TRUSTEDGE_isFatalError(status))
        {
            TRUSTEDGE_agentContextRelease(&pCtx);
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. TRUSTEDGE_agentContextProcess failed\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        exitClient = pAgentCtx->exitClient;
        sleepInterval = pAgentCtx->sleepInterval;

        if (NULL != pCtx)
        {
            TRUSTEDGE_agentContextRelease(&pCtx);
        }

        /* make one last check to see if we got a signal to terminate */
        if (NULL != gFuncPtrTable.pFuncOnSafeToExit && 1 == gFuncPtrTable.pFuncOnSafeToExit(status))
        {
            exitClient = TRUE;
        }

        if (TRUE == pConfig->exitClient)
        {
            exitClient = TRUE;
        }

        if (FALSE == exitClient && TRUE == TRUSTEDGE_sleepCheckStatusMS(sleepInterval*1000))
        {
            exitClient = TRUE; /* sleep was interrupted by a signal handler */
        }
    } while (FALSE == exitClient);

exit:
    if (NULL != pConfig)
        TRUSTEDGE_utilsDeleteConfig (&pConfig);

    DIGI_FREE((void **) &pValue);
    return status;
}

/*----------------------------------------------------------------------------*/

extern void TRUSTEDGE_registerStatusCallback(
    funcPtrSafeToExitCallback cb
)
{
    gFuncPtrTable.pFuncOnSafeToExit = cb;
}

/*----------------------------------------------------------------------------*/

extern void TRUSTEDGE_registerDNSLookupCallback(
    funcPtrDNSLookupCallback cb
)
{
    gFuncPtrTable.pFuncDNSLookup = cb;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)

extern void TRUSTEDGE_registerUpdateActionHandlerCallback(
    funcPtrActionHandlerCallback cb
)
{
    gFuncPtrTable.pFuncActionHandler = cb;
}
#endif

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentWriteMetrics(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice)
{
    MSTATUS status;
    ProtobufPayload metrics;
    TrustEdgeAgentMetric *pMetric;
    void *pBucketCookie = NULL;
    ubyte4 index = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    sbyte* file = NULL;
    hashTableOfPtrs *table = NULL;

    switch (fileChoice)
    {
        case TE_METRICS_FILE:
            file = pCtx->pMetricFile;
            table = pCtx->pMetrics;
            break;
        case TE_DESIRED_ATTRIBUTES_FILE:
            file = pCtx->pDesiredAttributeFile;
            table = pCtx->pDesiredAttributes;
            break;
        default:
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
    }

    PROTOBUF_resetSequenceNumber();

    status = PROTOBUF_preparePayload(&metrics);
    if (OK != status)
    {
        goto exit;
    }

    /* Add metrics */
    while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(table, &pBucketCookie, &index)))
    {
        status = PROTOBUF_addMetricToPayload(&metrics, pMetric->pName, pMetric->pValue, PB_METRIC_DATA_TYPE_STRING, pMetric->valueLen - 1);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = PROTOBUF_encodePayload(&metrics, &pMsg, &msgLen);
    if (OK != status)
    {
        goto exit;
    }

    if (TE_METRICS_FILE == fileChoice)
    {
        pCtx->lastAttrScanTime = metrics.timestamp;
    }

    status = DIGICERT_writeFile(file, pMsg, msgLen);

exit:
    PROTOBUF_freePayload(&metrics);
    DIGI_FREE((void **) &pMsg);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to save metrics\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
    }

    return status;
}

/* TODO: Determine when "deviceState" is Updated or Pending */
#define BIRTH_PAYLOAD   "{\"deviceId\":\"%s\",\"accountId\":\"%s\",\"divisionId\":\"%s\",\"deviceGroupId\":\"%s\",\"deviceState\":\"Updated\"}"

static MSTATUS TRUSTEDGE_agentCreateNBirthMsg(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppNBirthMsg,
    ubyte4 *pNBirthMsgLen)
{
    MSTATUS status;
    ProtobufPayload nbirth_payload;
    TrustEdgeAgentMetric *pMetric;
    void *pBucketCookie = NULL;
    ubyte4 index = 0;
    ubyte *pMsg = NULL, *pBodyMsg = NULL;
    ubyte4 msgLen = 0, bodyMsgLen = 0;
    sbyte *pUuid;
    ubyte4 uuidLen;
    int ret;

    PROTOBUF_resetSequenceNumber();

    status = PROTOBUF_preparePayload(&nbirth_payload);
    if (OK != status)
    {
        goto exit;
    }

    /* UUID value doesn't matter, authentication JWS message will eventually be
     * moved to being a MQTT authentication message. Set it to whatever */
    pUuid = "DeviceTM_BIRTH";
    uuidLen = DIGI_STRLEN(pUuid);
    status = DIGI_MALLOC((void **) &nbirth_payload.pUuid, uuidLen + 1);
    if (OK != status)
    {
        goto exit;
    }
    DIGI_MEMCPY(nbirth_payload.pUuid, pUuid, uuidLen + 1);

    /* Add metrics */
    while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(pCtx->pMetrics, &pBucketCookie, &index)))
    {
        status = PROTOBUF_addMetricToPayload(&nbirth_payload, pMetric->pName, pMetric->pValue, PB_METRIC_DATA_TYPE_STRING, pMetric->valueLen - 1);
        if (OK != status)
        {
            goto exit;
        }
    }

    ret = snprintf(NULL, 0, BIRTH_PAYLOAD,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDivisionId,
                        pCtx->configOptions.pDeviceGroupId);
    bodyMsgLen = ret;

    status = DIGI_MALLOC((void **) &pBodyMsg, bodyMsgLen + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    ret = snprintf(pBodyMsg, bodyMsgLen + 1, BIRTH_PAYLOAD,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->configOptions.pDivisionId,
                        pCtx->configOptions.pDeviceGroupId);

    nbirth_payload.pBody = pBodyMsg;
    nbirth_payload.bodyLen = bodyMsgLen;

    status = PROTOBUF_encodePayload(&nbirth_payload, &pMsg, &msgLen);

    *ppNBirthMsg = pMsg;
    *pNBirthMsgLen = msgLen;

exit:

    PROTOBUF_freePayload(&nbirth_payload);

    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to construct NBirth message\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
    }

    return status;
}


/*----------------------------------------------------------------------------*/
