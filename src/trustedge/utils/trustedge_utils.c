/*
 * trustedge_utils.c
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

#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE /* strptime() */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE /* timegm() */
#endif
#include <stdio.h>
#include <time.h>
#if defined(__ENABLE_DIGICERT_TIMESTAMP_MILLISECONDS__)
#include <sys/time.h>
#endif
#elif defined(__RTOS_WIN32__)
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>
#endif

#if defined(__RTOS_ZEPHYR__)
#include <zephyr/drivers/hwinfo.h>
#endif

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mdefs.h"
#include "../../common/common_utils.h"
#include "../../common/mjson.h"
#include "../../common/mocana.h"
#include "../../common/mfmgmt.h"
#include "../../common/msg_logger.h"
#include "../../common/base64.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/mtcp.h"
#include "../../common/mtcp_async.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_chain.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs10.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/utils/trustedge_tap.h"
#ifdef __ENABLE_DIGICERT_TEE__
#include "../../smp/smp_tee/smp_tap_tee.h"
#endif
#endif
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/crypto_utils.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sha1.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_sig.h"
#endif
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_persist.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
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
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../est/est_client_api.h"
#include "../../trustedge/est/trustedge_est_include.h"

#include "../../../thirdparty/miniz/miniz.h"


#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#define DEFAULT_TRUSTEDGE_CONFIG_PATH       "/etc/digicert/trustedge.json"
#elif defined(__RTOS_WIN32__)
#define DEFAULT_TRUSTEDGE_CONFIG_PATH       "C:\\ProgramData\\DigiCert\\TrustEdge\\trustedge.json"
#else
#error "No default trustedge config filed specified for this platform"
#endif

#ifndef __DISABLE_TRUSTEDGE_REST_API__
#define TRUSTEDGE_HTTP_PORT                     8469
#define TRUSTEDGE_MAX_RESOURCES_PER_PROCESS     10
#define TRUSTEDGE_MAX_PROCESS_LIMIT             10
#endif

#define BUF_SIZE 32

#define TRUSTEDGE_CONFIG_ENV    "TRUSTEDGE_CONFIG"

#define DIRECTORY_PATHS_JSTR        "directory_paths"
#define DEBUG_DIR_JSTR              "debug_dir"
#define BIN_DIR_JSTR                "bin_dir"
#define LIB_DIR_JSTR                "lib_dir"
#define ROOT_DIR_JSTR               "root_dir"
#define CONF_DIR_JSTR               "conf_dir"
#define KEYSTORE_DIR_JSTR           "keystore_dir"
#define CONFIGURATION_JSTR          "configuration"
#define REQUIRE_PQC_JSTR            "require_pqc"
#define CERTIFICATE_JSTR            "certificate"
#define SERVICE_DIR_JSTR            "service_dir"
#define POLLING_INTERVAL_JSTR       "polling_interval"
#define RENEWAL_HOURS_JSTR          "renewal_hours"
#define PROXY_JSTR                  "proxy"
#define URL_JSTR                    "url"
#define LOGLEVEL_JSTR               "loglevel"
#define CONNECTION_UPTIME_JSTR      "connection_uptime_interval"
#define KEEPALIVE_JSTR              "keepalive_interval"
#define RECV_POLLING_JSTR           "recv_polling_interval"
#define POLICY_REQUEST_TIMEOUT_JSTR "policy_request_timeout"
#define SLEEP_JSTR                  "sleep_interval"
#define ACTION_TIMEOUT_JSTR         "action_handler_timeout"
#define REFRESH_HOURS_JSTR          "attributes_refresh_hours"
#define ENFORCE_TOKEN_JSTR          "enforce_token"
#define PROTOCOL_BUFFER_JSTR        "protocol_buffer_size"
#define LOG_PAYLOAD_JSTR            "log_payload"
#define TIMEOUT_WINDOW_JSTR         "policy_timestamp_window"
#define ERROR_RESPONSE_MAX_JSTR     "max_error_responses"
#define BOOTSTRAP_JSTR              "bootstrap"
#define WORKSPACE_DIR               "workspace_dir"
#define PERSIST_ARTIFACT_JSTR       "persist_artifact"
#define AGENT_JSTR                  "agent"
#define PROVIDER_CREDS_DIR_JSTR     "provider_creds_dir"
#define CLOUD_PROVIDER_JSTR         "cloud_provider"
#define LOG_JSTR                    "log"
#define SERVICE_JSTR                "service"
#define MODE_JSTR                   "mode"
#ifndef __DISABLE_TRUSTEDGE_REST_API__
#define REST_API_JSTR               "api"
#define PORT_JSTR                   "port"
#define NUM_PROCESS_JSTR            "num_process"
#define NUM_RESOURCE_JSTR           "num_resource"
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
#define SERVER_KEYCERT_ALIAS_JSTR   "server_keycert_alias"
#define SERVER_FQDN_JSTR            "server_hostname"
#endif
#endif
#define MAX_RETRY_COUNT_JSTR        "max_retry_count"
#define AGENT_RENEWAL_HOURS_JSTR    "renewal_hours"
#define CHUNK_SUPPORTED_JSTR        "chunk_supported"
#define CHUNK_SIZE_JSTR             "chunk_size"
#define CHUNK_WINDOW_SIZE_JSTR      "chunk_window_size"

#define CA_COMPONENT            "ca"
#define REQ_COMPONENT           "req"

#define TRUSTEDGE_KEYS_FOLDER   "keys"
#define TRUSTEDGE_CERTS_FOLDER  "certs"

extern MSTATUS TRUSTEDGE_utilsGetConfigPath(sbyte **ppPath)
{
    MSTATUS status;
    sbyte *pPath = NULL;
    sbyte4 len;

    if (NULL == ppPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Read config file provided by environment variable, otherwise check if
     * default one exists */
    status = FMGMT_getEnvironmentVariableValueAlloc(
        TRUSTEDGE_CONFIG_ENV, &pPath);
    if (OK == status)
    {
        *ppPath = pPath;
    }
    else if (TRUE == FMGMT_pathExists(DEFAULT_TRUSTEDGE_CONFIG_PATH, NULL))
    {
        len = DIGI_STRLEN(DEFAULT_TRUSTEDGE_CONFIG_PATH);
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pPath, len + 1, DEFAULT_TRUSTEDGE_CONFIG_PATH, len);
        if (OK != status)
        {
            goto exit;
        }
        pPath[len] = '\0';
        *ppPath = pPath;
    }
    else
    {
        status = ERR_TRUSTEDGE_NO_CONFIG_FILE;
        goto exit;
    }

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_utilsReadJsonStrAllowNull(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pName,
    sbyte **ppString)
{
    MSTATUS status;
    ubyte4 tokenNdx;
    JSON_TokenType token = { 0 };

    status = JSON_getObjectIndex(
        pJCtx, pName, ndx, &tokenNdx, TRUE);
    if (OK == status)
    {
        status = JSON_getToken(pJCtx, tokenNdx + 1, &token);
        if (OK != status)
        {
            goto exit;
        }

        if (JSON_String == token.type)
        {
            status = DIGI_MALLOC_MEMCPY(
                (void **) ppString, token.len + 1,
                (void *) token.pStart, token.len);
            if (OK != status)
            {
                goto exit;
            }
            (*ppString)[token.len] = '\0';
        }
        else if (JSON_Null != token.type)
        {
            status = ERR_JSON_EXPECTED_ELEMENT_NOT_FOUND;
            goto exit;
        }
    }
    else
    {
        status = OK;
    }

exit:

    return status;
}

extern intBoolean TRUSTEDGE_utilsGetConfigLogLevel(MsgLogLevel *pLogLevel)
{
    MSTATUS status;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pLogLevelStr = NULL;
    MsgLogLevel logLevel;
    intBoolean ret;

    if (NULL == pLogLevel)
        return FALSE;

    status = TRUSTEDGE_utilsReadConfig (&pConfig);
    if (OK != status)
    {
        return FALSE;
    }

    if ((NULL == pConfig->pLogLevel) || ( 0 == DIGI_STRCMP ((const sbyte *)pConfig->pLogLevel, (const sbyte *)"")))
    {
        ret = FALSE;
        goto exit;
    }

    pLogLevelStr = pConfig->pLogLevel;
    if (OK != MSG_LOG_convertStringLevel (pLogLevelStr, &logLevel))
    {
        ret = FALSE;
        goto exit;
    }

    ret = TRUE;
    *pLogLevel = logLevel;

exit:
    TRUSTEDGE_utilsDeleteConfig(&pConfig);
    return ret;
}

extern MSTATUS TRUSTEDGE_utilsReadConfig(
    TrustEdgeConfig **ppConfig)
{
    MSTATUS status;
    TrustEdgeConfig *pConfig = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 tokensFound, ndx;
    sbyte *pPath = NULL;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    sbyte *pJsonVal = NULL;
#endif

    if (NULL == ppConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pConfig, 1, sizeof(*pConfig));
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_utilsGetConfigPath(&pPath);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_readFile(pPath, &pData, &dataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_acquireContext (&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse (pJCtx, pData, dataLen, &tokensFound);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, DIRECTORY_PATHS_JSTR, &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, BIN_DIR_JSTR, &pConfig->pBinDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, BIN_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, LIB_DIR_JSTR, &pConfig->pLibDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, LIB_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, ROOT_DIR_JSTR, &pConfig->pRootDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, ROOT_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, CONF_DIR_JSTR, &pConfig->pConfDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, CONF_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
    pJCtx, ndx, DEBUG_DIR_JSTR, &pConfig->pDebugDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, DEBUG_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }
#endif

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, KEYSTORE_DIR_JSTR, &pConfig->pKeystoreDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, KEYSTORE_DIR_JSTR, DIRECTORY_PATHS_JSTR);
        goto exit;
    }

    if (NULL != pConfig->pKeystoreDir)
    {
        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreDir, CA_COMPONENT, &pConfig->pKeystoreCADir);
        if (OK != status)
        {
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreDir, TRUSTEDGE_CERTS_FOLDER, &pConfig->pKeystoreCertsDir);
        if (OK != status)
        {
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreDir, TRUSTEDGE_KEYS_FOLDER, &pConfig->pKeystoreKeysDir);
        if (OK != status)
        {
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreDir, REQ_COMPONENT, &pConfig->pKeystoreReqDir);
        if (OK != status)
        {
            goto exit;
        }
    }

    pConfig->requirePQC = FALSE;

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, CONFIGURATION_JSTR, &ndx, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, REQUIRE_PQC_JSTR, &pConfig->requirePQC, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, REQUIRE_PQC_JSTR, CONFIGURATION_JSTR);
            goto exit;
        }
    }
    else if (ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, CONFIGURATION_JSTR);
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, CERTIFICATE_JSTR, &ndx, TRUE);
    if (OK == status)
    {
        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, SERVICE_DIR_JSTR, &pConfig->pServiceDir);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, SERVICE_DIR_JSTR, CERTIFICATE_JSTR);
            goto exit;
        }

        if (NULL != pConfig->pServiceDir)
        {
            status = COMMON_UTILS_addPathComponent(
                pConfig->pServiceDir, SERVICE_REQUEST_DIR, &pConfig->pServiceRequestDir);
            if (OK != status)
            {
                goto exit;
            }

            status = COMMON_UTILS_addPathComponent(
                pConfig->pServiceDir, SERVICE_PROCESSING_DIR, &pConfig->pServiceProcessingDir);
            if (OK != status)
            {
                goto exit;
            }

            status = COMMON_UTILS_addPathComponent(
                pConfig->pServiceDir, SERVICE_COMPLETED_DIR, &pConfig->pServiceCompletedDir);
            if (OK != status)
            {
                goto exit;
            }

            status = COMMON_UTILS_addPathComponent(
                pConfig->pServiceDir, SERVICE_FAILED_DIR, &pConfig->pServiceFailedDir);
            if (OK != status)
            {
                goto exit;
            }
        }

        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, MODE_JSTR, &pConfig->pCertificateMode);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, MODE_JSTR, CERTIFICATE_JSTR);
            goto exit;
        }

        pConfig->pollingInterval = SERVICE_POLLING_INTERVAL;
        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, POLLING_INTERVAL_JSTR, &pConfig->pollingInterval, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, POLLING_INTERVAL_JSTR, CERTIFICATE_JSTR);
            goto exit;
        }

        pConfig->renewalHours = SERVICE_RENEWAL_HOURS;
        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, RENEWAL_HOURS_JSTR, &pConfig->renewalHours, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, RENEWAL_HOURS_JSTR, CERTIFICATE_JSTR);
            goto exit;
        }

        pConfig->maxRetryCountCertEnroll = DEFAULT_MAX_RETRY_COUNT_CERT_ENROLL;
        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, MAX_RETRY_COUNT_JSTR, &pConfig->maxRetryCountCertEnroll, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, MAX_RETRY_COUNT_JSTR, CERTIFICATE_JSTR);
            goto exit;
        }
    }
    else
    {
        pConfig->isCertFieldMissing = TRUE;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, PROXY_JSTR, &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, PROXY_JSTR);
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, URL_JSTR, &pConfig->pProxyUrl);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to read '%s' key in '%s'\n",
            __func__, URL_JSTR, PROXY_JSTR);
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, AGENT_JSTR, &ndx, TRUE);
    if (OK != status && ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, AGENT_JSTR);
        goto exit;
    }

    pConfig->connUptimeInterval = SERVICE_UPTIME_INTERVAL;
    pConfig->enforceToken = TRUE;
    pConfig->protocolBufferSize = DEFAULT_PROTOCOL_BUFFER_SIZE;
    pConfig->logPayload = FALSE;
    pConfig->timestampWindow =  DEFAULT_TIMESTAMP_WINDOW;
    pConfig->maxRetryCount = DEFAULT_MAX_RETRY_COUNT;
    pConfig->maxErrorResponses = DEFAULT_MAX_ERROR_RESP;
    pConfig->keepAliveInterval = DEFAULT_KEEP_ALIVE_INTERVAL;
    pConfig->recvPollingInterval = DEFAULT_RECV_POLLING_INTERVAL;
    pConfig->policyRequestTimeout = DEFAULT_POLICY_REQUEST_TIMEOUT;
    pConfig->sleepInterval = SERVICE_SLEEP_INTERVAL;
    pConfig->actionHandlerTimeout = ACTION_HANDLER_TIMEOUT;
    pConfig->refreshHours = DEFAULT_REFRESH_HOURS;
    pConfig->persistArtifact = FALSE;
    pConfig->agentRenewalHours = DEFAULT_AGENT_RENEWAL_HOURS;
    pConfig->chunkSupported = FALSE;
    pConfig->chunkSize = DEFAULT_CHUNK_SIZE;
    pConfig->chunkWindowSize = DEFAULT_CHUNK_WINDOW_SIZE;

    if (OK == status)
    {
        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, CONNECTION_UPTIME_JSTR, &pConfig->connUptimeInterval, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, CONNECTION_UPTIME_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, KEEPALIVE_JSTR, &pConfig->keepAliveInterval, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, KEEPALIVE_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, RECV_POLLING_JSTR, &pConfig->recvPollingInterval, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, RECV_POLLING_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, POLICY_REQUEST_TIMEOUT_JSTR, &pConfig->policyRequestTimeout, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, POLICY_REQUEST_TIMEOUT_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, SLEEP_JSTR, &pConfig->sleepInterval, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, SLEEP_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, ACTION_TIMEOUT_JSTR, &pConfig->actionHandlerTimeout, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, ACTION_TIMEOUT_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, REFRESH_HOURS_JSTR, &pConfig->refreshHours, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, REFRESH_HOURS_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, BOOTSTRAP_JSTR, &pConfig->pBootstrapConfig);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, BOOTSTRAP_JSTR, AGENT_JSTR);
            goto exit;
        }

        /* Whatever the name of bootstrap config is signature file will have the same base name and ends with .sig extension */
        if (NULL != pConfig->pBootstrapConfig)
        {
            if (0 != DIGI_STRNICMP(&pConfig->pBootstrapConfig[DIGI_STRLEN(pConfig->pBootstrapConfig) - DIGI_STRLEN(JSON_EXT)], JSON_EXT, DIGI_STRLEN(JSON_EXT)))
            {
                status = DIGI_CALLOC((void **) &pConfig->pBootstrapSig, 1, DIGI_STRLEN(pConfig->pBootstrapConfig) + DIGI_STRLEN(JSON_EXT) + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(pConfig->pBootstrapSig, pConfig->pBootstrapConfig, DIGI_STRLEN(pConfig->pBootstrapConfig));
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(&pConfig->pBootstrapSig[DIGI_STRLEN(pConfig->pBootstrapConfig)], SIG_EXT, DIGI_STRLEN(SIG_EXT));
                if (OK != status)
                {
                    goto exit;
                }
            }
            else
            {
                status = DIGI_CALLOC((void **) &pConfig->pBootstrapSig, 1, DIGI_STRLEN(pConfig->pBootstrapConfig) + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(pConfig->pBootstrapSig, pConfig->pBootstrapConfig, DIGI_STRLEN(pConfig->pBootstrapConfig) - DIGI_STRLEN(JSON_EXT));
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(&pConfig->pBootstrapSig[DIGI_STRLEN(pConfig->pBootstrapConfig) - DIGI_STRLEN(JSON_EXT)],
                                    SIG_EXT, DIGI_STRLEN(SIG_EXT));
                if (OK != status)
                {
                    goto exit;
                }
            }
        }

        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, WORKSPACE_DIR, &pConfig->pWorkspaceDir);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, WORKSPACE_DIR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, ENFORCE_TOKEN_JSTR, &pConfig->enforceToken, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, ENFORCE_TOKEN_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, PROTOCOL_BUFFER_JSTR, &pConfig->protocolBufferSize, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, PROTOCOL_BUFFER_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, LOG_PAYLOAD_JSTR, &pConfig->logPayload, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, LOG_PAYLOAD_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, TIMEOUT_WINDOW_JSTR, &pConfig->timestampWindow, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, TIMEOUT_WINDOW_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, MAX_RETRY_COUNT_JSTR, &pConfig->maxRetryCount, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, MAX_RETRY_COUNT_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, ERROR_RESPONSE_MAX_JSTR, &pConfig->maxErrorResponses, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, ERROR_RESPONSE_MAX_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, PERSIST_ARTIFACT_JSTR, &pConfig->persistArtifact, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, PERSIST_ARTIFACT_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, AGENT_RENEWAL_HOURS_JSTR, &pConfig->agentRenewalHours, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, AGENT_RENEWAL_HOURS_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonBooleanValue(
            pJCtx, ndx, CHUNK_SUPPORTED_JSTR, &pConfig->chunkSupported, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, CHUNK_SUPPORTED_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, CHUNK_SIZE_JSTR, &pConfig->chunkSize, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, CHUNK_SIZE_JSTR, AGENT_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, CHUNK_WINDOW_SIZE_JSTR, &pConfig->chunkWindowSize, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, CHUNK_WINDOW_SIZE_JSTR, AGENT_JSTR);
            goto exit;
        }
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, CLOUD_PROVIDER_JSTR, &ndx, TRUE);
    if (OK == status)
    {
        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, PROVIDER_CREDS_DIR_JSTR, &pConfig->pProviderCredsDir);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, PROVIDER_CREDS_DIR_JSTR, CLOUD_PROVIDER_JSTR);
            goto exit;
        }
    }
    else if (ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, CLOUD_PROVIDER_JSTR);
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, LOG_JSTR, &ndx, TRUE);
    if (OK != status && ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s: Failed to find '%s' object in config\n",
            __func__, LOG_JSTR);
        goto exit;
    }

    if (OK == status)
    {
        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndx, LOGLEVEL_JSTR, &pConfig->pLogLevel);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, LOGLEVEL_JSTR, LOG_JSTR);
            goto exit;
        }
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, SERVICE_JSTR, &ndx, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndx, MODE_JSTR, &pConfig->pTrustEdgeMode, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, MODE_JSTR, SERVICE_JSTR);
            goto exit;
        }
    }

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    pConfig->numProcess = TRUSTEDGE_MAX_PROCESS_LIMIT;
    pConfig->numResource = TRUSTEDGE_MAX_RESOURCES_PER_PROCESS;
    pConfig->port = TRUSTEDGE_HTTP_PORT;
    status = DIGI_MALLOC_MEMCPY((void **)&pConfig->pRequestType, DIGI_STRLEN(DEFAULT_REQUEST_TYPE) + 1, DEFAULT_REQUEST_TYPE, DIGI_STRLEN(DEFAULT_REQUEST_TYPE));
    if (OK != status)
    {
        goto exit;
    }

    pConfig->pRequestType[DIGI_STRLEN(DEFAULT_REQUEST_TYPE)] = '\0';

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, REST_API_JSTR, &ndx, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndx, MODE_JSTR, &pJsonVal, TRUE);
        if (OK == status)
        {
            (void) DIGI_FREE((void **)&pConfig->pRequestType);
            pConfig->pRequestType = pJsonVal;
            pJsonVal = NULL;
        }
        else if (ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, MODE_JSTR, REST_API_JSTR);
            goto exit;
        }
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
        status = DIGI_MALLOC_MEMCPY((void **)&pConfig->pServerKeyCert, DIGI_STRLEN(DEFAULT_SERVER_KEYCERT_ALIAS) + 1, DEFAULT_SERVER_KEYCERT_ALIAS, DIGI_STRLEN(DEFAULT_SERVER_KEYCERT_ALIAS));
        if (OK != status)
        {
            goto exit;
        }

        pConfig->pServerKeyCert[DIGI_STRLEN(DEFAULT_SERVER_KEYCERT_ALIAS)] = '\0';

        status = DIGI_MALLOC_MEMCPY((void **)&pConfig->pServerFQDN, DIGI_STRLEN(DEFAULT_SERVER_FQDN) + 1, DEFAULT_SERVER_FQDN, DIGI_STRLEN(DEFAULT_SERVER_FQDN));
        if (OK != status)
        {
            goto exit;
        }

        pConfig->pServerFQDN[DIGI_STRLEN(DEFAULT_SERVER_FQDN)] = '\0';

        if (0 == DIGI_STRNICMP("https", pConfig->pRequestType, 5))
        {
            status = JSON_getJsonStringValue(
                pJCtx, ndx, SERVER_KEYCERT_ALIAS_JSTR, &pJsonVal, TRUE);
            if (OK == status)
            {
                (void) DIGI_FREE((void **)&pConfig->pServerKeyCert);
                pConfig->pServerKeyCert = pJsonVal;
                pJsonVal = NULL;
            }
            else if (ERR_NOT_FOUND != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s: Failed to read '%s' key in '%s'\n",
                    __func__, SERVER_KEYCERT_ALIAS_JSTR, REST_API_JSTR);
                goto exit;
            }

            status = JSON_getJsonStringValue(
                pJCtx, ndx, SERVER_FQDN_JSTR, &pJsonVal, TRUE);
            if (OK == status)
            {
                (void) DIGI_FREE((void **)&pConfig->pServerFQDN);
                pConfig->pServerFQDN = pJsonVal;
                pJsonVal = NULL;
            }
            else if (ERR_NOT_FOUND != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s: Failed to read '%s' key in '%s'\n",
                    __func__, SERVER_FQDN_JSTR, REST_API_JSTR);
                goto exit;
            }
        }
#endif
        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, NUM_PROCESS_JSTR, &pConfig->numProcess, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, NUM_PROCESS_JSTR, REST_API_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, NUM_RESOURCE_JSTR, &pConfig->numResource, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, NUM_RESOURCE_JSTR, REST_API_JSTR);
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, ndx, PORT_JSTR, &pConfig->port, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s: Failed to read '%s' key in '%s'\n",
                __func__, PORT_JSTR, REST_API_JSTR);
            goto exit;
        }
    }
#endif

    status = OK; /* clear ERR_NOT_FOUND */
    *ppConfig = pConfig;
    pConfig = NULL;

exit:

    JSON_releaseContext (&pJCtx);
    DIGI_FREE((void **) &pPath);
    DIGI_FREE((void **) &pData);
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (NULL != pJsonVal)
        (void) DIGI_FREE((void**) &pJsonVal);
#endif
    TRUSTEDGE_utilsDeleteConfig(&pConfig);

    return status;
}

extern sbyte* TRUSTEDGE_utilsCloneString(const sbyte *pS)
{
    MSTATUS status;
    sbyte *pN;
    sbyte4 len;

    if (NULL == pS) return NULL;

    len = DIGI_STRLEN(pS);
    status = DIGI_MALLOC_MEMCPY(
        (void **) &pN, len + 1, (sbyte *) pS, len);
    if (OK != status)
    {
        return NULL;
    }
    pN[len] = '\0';

    return pN;
}

extern MSTATUS TRUSTEDGE_utilsCloneConfig (TrustEdgeConfig *pConfig, TrustEdgeConfig **ppConfig)
{
    MSTATUS status;
    TrustEdgeConfig *pCopy = NULL;

    if (NULL == pConfig || NULL == ppConfig)
    {
        status = ERR_TRUSTEDGE_NO_CONFIG_FILE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pCopy, sizeof(*pCopy));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCopy->pBinDir = TRUSTEDGE_utilsCloneString(pConfig->pBinDir);
    pCopy->pLibDir = TRUSTEDGE_utilsCloneString(pConfig->pLibDir);
    pCopy->pRootDir = TRUSTEDGE_utilsCloneString(pConfig->pRootDir);
    pCopy->pConfDir = TRUSTEDGE_utilsCloneString(pConfig->pConfDir);
    pCopy->pDebugDir = TRUSTEDGE_utilsCloneString(pConfig->pDebugDir);
    pCopy->pKeystoreDir = TRUSTEDGE_utilsCloneString(pConfig->pKeystoreDir);
    pCopy->pKeystoreCADir = TRUSTEDGE_utilsCloneString(pConfig->pKeystoreCADir);
    pCopy->pKeystoreCertsDir = TRUSTEDGE_utilsCloneString(pConfig->pKeystoreCertsDir);
    pCopy->pKeystoreKeysDir = TRUSTEDGE_utilsCloneString(pConfig->pKeystoreKeysDir);
    pCopy->pKeystoreReqDir = TRUSTEDGE_utilsCloneString(pConfig->pKeystoreReqDir);
    pCopy->pServiceDir = TRUSTEDGE_utilsCloneString(pConfig->pServiceDir);
    pCopy->pServiceRequestDir = TRUSTEDGE_utilsCloneString (pConfig->pServiceRequestDir);
    pCopy->pServiceProcessingDir = TRUSTEDGE_utilsCloneString(pConfig->pServiceProcessingDir);
    pCopy->pServiceCompletedDir = TRUSTEDGE_utilsCloneString(pConfig->pServiceCompletedDir);
    pCopy->pServiceFailedDir = TRUSTEDGE_utilsCloneString(pConfig->pServiceFailedDir);
    pCopy->pProxyUrl = TRUSTEDGE_utilsCloneString(pConfig->pProxyUrl);
    pCopy->pBootstrapConfig = TRUSTEDGE_utilsCloneString(pConfig->pBootstrapConfig);
    pCopy->pBootstrapSig = TRUSTEDGE_utilsCloneString(pConfig->pBootstrapSig);
    pCopy->pWorkspaceDir = TRUSTEDGE_utilsCloneString(pConfig->pWorkspaceDir);
    pCopy->pLogLevel = TRUSTEDGE_utilsCloneString(pConfig->pLogLevel);
    pCopy->pTrustEdgeMode = TRUSTEDGE_utilsCloneString(pConfig->pTrustEdgeMode);
    pCopy->pCertificateMode = TRUSTEDGE_utilsCloneString(pConfig->pCertificateMode);
    pCopy->pProviderCredsDir = TRUSTEDGE_utilsCloneString(pConfig->pProviderCredsDir);
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    pCopy->pRequestType = TRUSTEDGE_utilsCloneString(pConfig->pRequestType);
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
    pCopy->pServerKeyCert = TRUSTEDGE_utilsCloneString(pConfig->pServerKeyCert);
    pCopy->pServerFQDN = TRUSTEDGE_utilsCloneString(pConfig->pServerFQDN);
#endif
#endif

    pCopy->renewalHours = pConfig->renewalHours;
    pCopy->pollingInterval = pConfig->pollingInterval;
    pCopy->connUptimeInterval = pConfig->connUptimeInterval;
    pCopy->keepAliveInterval = pConfig->keepAliveInterval;
    pCopy->recvPollingInterval = pConfig->recvPollingInterval;
    pCopy->policyRequestTimeout = pConfig->policyRequestTimeout;
    pCopy->sleepInterval = pConfig->sleepInterval;
    pCopy->refreshHours = pConfig->refreshHours;
    pCopy->actionHandlerTimeout = pConfig->actionHandlerTimeout;
    pCopy->maxRetryCount = pConfig->maxRetryCount;
    pCopy->maxRetryCountCertEnroll = pConfig->maxRetryCountCertEnroll;
    pCopy->timestampWindow = pConfig->timestampWindow;
    pCopy->maxErrorResponses = pConfig->maxErrorResponses;
    pCopy->enforceToken = pConfig->enforceToken;
    pCopy->logPayload = pConfig->logPayload;
    pCopy->persistArtifact = pConfig->persistArtifact;
    pCopy->protocolBufferSize = pConfig->protocolBufferSize;
    pCopy->agentRenewalHours = pConfig->agentRenewalHours;
    pCopy->chunkSupported = pConfig->chunkSupported;
    pCopy->chunkSize = pConfig->chunkSize;
    pCopy->chunkWindowSize = pConfig->chunkWindowSize;
    pCopy->verifyBootstrapSig = pConfig->verifyBootstrapSig;
    pCopy->isCertFieldMissing = pConfig->isCertFieldMissing;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    pCopy->numProcess = pConfig->numProcess;
    pCopy->numResource = pConfig->numResource;
    pCopy->port = pConfig->port;
#endif
    pCopy->requirePQC = pConfig->requirePQC;
    pCopy->exitClient = pConfig->exitClient;

    *ppConfig = pCopy;

exit:
    return status;
}


extern MSTATUS TRUSTEDGE_utilsDeleteConfig(
    TrustEdgeConfig **ppConfig)
{
    MSTATUS status = OK, fstatus;

    if (NULL != ppConfig && NULL != *ppConfig)
    {
        fstatus = DIGI_FREE((void **) &(*ppConfig)->pBinDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pLibDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pRootDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pConfDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pKeystoreDir);
        if (OK == status)
            status = fstatus;

#ifdef __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__
        if (NULL != (*ppConfig)->pDebugDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pDebugDir);
            if (OK == status)
                status = fstatus;
        }
#endif

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pKeystoreCADir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pKeystoreCertsDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pKeystoreReqDir);
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &(*ppConfig)->pKeystoreKeysDir);
        if (OK == status)
            status = fstatus;

        if (NULL != (*ppConfig)->pServiceDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServiceDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pServiceRequestDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServiceRequestDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pServiceProcessingDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServiceProcessingDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pServiceCompletedDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServiceCompletedDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pServiceFailedDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServiceFailedDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pTrustEdgeMode)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pTrustEdgeMode);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pCertificateMode)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pCertificateMode);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pProxyUrl)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pProxyUrl);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pBootstrapConfig)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pBootstrapConfig);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pBootstrapSig)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pBootstrapSig);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pWorkspaceDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pWorkspaceDir);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pLogLevel)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pLogLevel);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppConfig)->pProviderCredsDir)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pProviderCredsDir);
            if (OK == status)
                status = fstatus;
        }
#ifndef __DISABLE_TRUSTEDGE_REST_API__
        if (NULL != (*ppConfig)->pRequestType)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pRequestType);
            if (OK == status)
                status = fstatus;
        }
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
        if (NULL != (*ppConfig)->pServerKeyCert)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServerKeyCert);
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pServerFQDN)
        {
            fstatus = DIGI_FREE((void **) &(*ppConfig)->pServerFQDN);
            if (OK == status)
                status = fstatus;
        }
#endif
#endif

        fstatus = DIGI_FREE((void **) ppConfig);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

extern MSTATUS TRUSTEDGE_utilsGetElapsedTime(ubyte4 *pElapsedTime)
{
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
    MSTATUS status;
    sbyte4 currentTime;

    if (NULL == pElapsedTime)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pElapsedTime = 0;
    currentTime = (sbyte4) time(NULL);
    if (-1 == currentTime)
    {
        status = ERR_TRUSTEDGE;
        goto exit;
    }

    *pElapsedTime = (ubyte4) currentTime;
    status = OK;

exit:

    return status;
#else
#error "No time implementation for platform"
#endif
}

extern MSTATUS TRUSTEDGE_utilsValidateCert(
    certStorePtr pCertStore,
    ubyte *pCert,
    ubyte4 certLen,
    byteBoolean validateCert)
{
    MSTATUS status;
    certDescriptor certDesc = {0};
    certChainPtr pCertChain = NULL;
    ValidationConfig vc = { 0 };
    TimeDate td = { 0 };

    certDesc.pCertificate = pCert;
    certDesc.certLength = certLen;

    status = CERTCHAIN_createFromIKE(&pCertChain, &certDesc, 1);
    if (OK != status)
    {
        goto exit;
    }

    vc.keyUsage = 0;
    vc.td = NULL;
    vc.pCertStore = pCertStore;

    if (TRUE == validateCert)
    {
        status = RTOS_timeGMT(&td);
        if (OK != status)
        {
            goto exit;
        }
        vc.td = &td;
    }

    status = CERTCHAIN_validate(MOC_ASYM(hwAccelCtx) pCertChain, &vc);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCertChain)
    {
        CERTCHAIN_delete(&pCertChain);
    }

    return status;
}

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
extern MSTATUS TRUSTEDGE_utilsGetCertInfo(TrustEdgeServiceCtx *pSrvCtx, ubyte *pCert, ubyte4 certLen)
{
    MSTATUS status = OK;
    certDistinguishedName *pCertInfo = NULL;
    TimeDate gmtTimeDate = {0};
    ubyte *pCertSerialNum = NULL;
    ubyte4 certSerialNumLen;
    ubyte *pCertIssuer = NULL;
    ubyte4 issuerLen;
    ubyte4 i, j;

    if ((NULL == pCert) || (NULL == pSrvCtx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certLen)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    status = CRYPTO_UTILS_getIssuerAndSerial(pCert, certLen, &pCertIssuer, &issuerLen, &pCertSerialNum, &certSerialNumLen);
    if (OK != status )
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pSrvCtx->pCertIssuer, 1, issuerLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pSrvCtx->pCertIssuer, pCertIssuer, issuerLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pSrvCtx->pCertSerialNum, 1, certSerialNumLen + certSerialNumLen / 2);
    if (OK != status)
    {
        goto exit;
    }

    j = 0;
    for (i = 0; i < certSerialNumLen; i++)
    {
        if ((i % 2 == 0) && (i != 0))
        {
            pSrvCtx->pCertSerialNum[j++] = ':';
        }
        pSrvCtx->pCertSerialNum[j++] = pCertSerialNum[i];
    }

    /* Get the current time.
     */
    status = RTOS_timeGMT(&gmtTimeDate);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertFromValidityString((const sbyte*)pCertInfo->pEndDate, &pSrvCtx->pCertExpiry);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_utilsComputeAsciiDigest(pCert, certLen, ht_sha256, &pSrvCtx->pCertThumbPrint);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (pCertInfo != NULL)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }
    DIGI_FREE((void **)&pCertSerialNum);
    DIGI_FREE((void **)&pCertIssuer);
    return status;
}
#endif

extern MSTATUS TRUSTEDGE_utilsWriteSMPBlob(
    sbyte *pDirPath,
    sbyte *pBaseName,
    AsymmetricKey *pKey,
    KeyFormat formats)
{
    MSTATUS status = OK;
#if defined(__ENABLE_DIGICERT_TAP__)
    TAP_Key *pTapKey = NULL;
    TAP_Buffer privBlob = { 0 };
    TAP_Buffer pubBlob = { 0 };
    sbyte *pFullPath = NULL;
    ubyte4 keyType = akt_undefined;
    ubyte4 bitLength = 0;
    ubyte2 provider = TAP_PROVIDER_UNDEFINED;
    ubyte4 moduleId = 0;
#endif
    sbyte *pPathWithBaseName = NULL;

#if !defined(__ENABLE_DIGICERT_TAP__)
    MOC_UNUSED(formats);
#endif

    if (NULL == pDirPath || NULL == pBaseName || NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pDirPath, pBaseName, &pPathWithBaseName);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    status = CRYPTO_UTILS_getAsymmetricKeyAttributes(
        pKey, &keyType, &bitLength, &provider, &moduleId);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_PROVIDER_TPM2 == provider)
    {
        if (KEY_FORMAT_TAP_PRIVATE_BLOB & formats)
        {
            status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
            if (OK != status)
                goto exit;

            status = TAP_extractPrivateKeyBlob(
                pTapKey, &privBlob, NULL);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = COMMON_UTILS_addPathExtension(
                pPathWithBaseName, TRUSTEDGE_SUFFIX_PRIV_TAPKEY,
                &pFullPath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_VERBOSE,
                "Writing TAP Private Key Blob File: %s\n", pFullPath);

            status = DIGICERT_writeFile(pFullPath, privBlob.pBuffer, privBlob.bufferLen);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (KEY_FORMAT_TAP_PUBLIC_BLOB & formats)
        {
            if (NULL == pTapKey)
            {
                status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
                if (OK != status)
                    goto exit;
            }

            status = TAP_extractPublicKeyBlob(
                pTapKey, &pubBlob, NULL);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            DIGI_FREE((void **) &pFullPath);
            status = COMMON_UTILS_addPathExtension(
                pPathWithBaseName, TRUSTEDGE_SUFFIX_PUB_TAPKEY,
                &pFullPath);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_VERBOSE,
                "Writing TAP Public Key Blob File: %s\n", pFullPath);

            status = DIGICERT_writeFile(pFullPath, pubBlob.pBuffer, pubBlob.bufferLen);
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
#endif

exit:

#if defined(__ENABLE_DIGICERT_TAP__)
    DIGI_FREE((void **) &(pubBlob.pBuffer));
    DIGI_FREE((void **) &(privBlob.pBuffer));
    DIGI_FREE((void **) &pFullPath);
#endif

    DIGI_FREE((void **) &pPathWithBaseName);

    return status;
}

extern MSTATUS TRUSTEDGE_utilsWriteKeyAndCert(
    TrustEdgeConfig *pConfig,
    sbyte *pBaseName,
    AsymmetricKey *pKey,
    ubyte *pCert,
    ubyte4 certLen
#if defined(__ENABLE_DIGICERT_TAP__)
    , CertEnrollTAPAttributes *pTapAttributes
#endif
    )
{
    MSTATUS status = OK;
    ubyte *pOutCert = NULL, *pOutKey = NULL;
    ubyte4 outCertLen = 0, outKeyLen = 0;
    sbyte *pFileName = NULL, *pOutFile = NULL, *pOldFile = NULL;

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__)
    (void) pTapAttributes;
#endif

    if (NULL != pCert)
    {
        status = BASE64_makePemMessageAlloc(
            MOC_PEM_TYPE_CERT, pCert, certLen, &pOutCert, &outCertLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pKey)
    {
#ifdef __ENABLE_DIGICERT_TEE__
        if (TAP_PROVIDER_TEE == pTapAttributes->provider)
        {
            if (NULL == pTapAttributes || NULL == pTapAttributes->pKeyHandle)
            {
                status = ERR_NULL_POINTER;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            status = CRYPTO_serializeAsymKeyToStorage( pKey,
                privateKeyPem, pTapAttributes->pKeyHandle->pBuffer, pTapAttributes->pKeyHandle->bufferLen, TEE_SECURE_STORAGE,
                &pOutKey, &outKeyLen);
        }
        else
#endif
        {
            status = CRYPTO_serializeAsymKey(
                pKey, privateKeyPem, &pOutKey, &outKeyLen);
        }
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = COMMON_UTILS_addPathExtension(pBaseName, TRUSTEDGE_SUFFIX_PEM, &pFileName);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pCert)
    {
        status = COMMON_UTILS_addPathComponent(pConfig->pKeystoreCertsDir, pFileName, &pOutFile);
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
            status = COMMON_UTILS_addPathExtension(
                pOutFile, TRUSTEDGE_SUFFIX_OLD, &pOldFile);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            MSG_LOG_print(
                MSG_LOG_VERBOSE,
                "Renaming certificate file from %s to %s\n", pOutFile, pOldFile);

            status = FMGMT_rename(pOutFile, pOldFile);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        MSG_LOG_print(
            MSG_LOG_VERBOSE,
            "Writing PEM Certificate File: %s\n", pOutFile);

        status = DIGICERT_writeFile(pOutFile, pOutCert, outCertLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pKey)
    {
        DIGI_FREE((void **) &pOutFile);
        status = COMMON_UTILS_addPathComponent(pConfig->pKeystoreKeysDir, pFileName, &pOutFile);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(
            MSG_LOG_VERBOSE,
            "Writing PKCS#8 Key File: %s\n", pOutFile);

        status = DIGICERT_writeFile(pOutFile, pOutKey, outKeyLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    DIGI_FREE((void **) &pOldFile);
    DIGI_FREE((void **) &pOutCert);
    DIGI_FREE((void **) &pOutKey);
    DIGI_FREE((void **) &pFileName);
    DIGI_FREE((void **) &pOutFile);

    return status;
}

extern MSTATUS TRUSTEDGE_utilsComputeRawDigest (
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashAlgo,
    sbyte **ppDigest,
    sbyte4 *pDigestLen)
{
    MSTATUS status;
    sbyte *pDigest = NULL;
    sbyte4 digestLen;

    /* Input validation not required, function used internally */
    if (ht_sha1 == hashAlgo)
    {
        digestLen = SHA1_RESULT_SIZE;
        status = DIGI_MALLOC(
            (void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;

        status = SHA1_completeDigest(pData, dataLen, pDigest);
        if (OK != status)
            goto exit;
    }
    else if (ht_sha256 == hashAlgo)
    {
        digestLen = SHA256_RESULT_SIZE;
        status = DIGI_MALLOC(
            (void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;

        status = SHA256_completeDigest(pData, dataLen, pDigest);
        if (OK != status)
            goto exit;
    }
    else if (ht_sha384 == hashAlgo)
    {
        digestLen = SHA384_RESULT_SIZE;
        status = DIGI_MALLOC(
            (void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;

        status = SHA384_completeDigest(pData, dataLen, pDigest);
        if (OK != status)
            goto exit;
    }
    else if (ht_sha512 == hashAlgo)
    {
        digestLen = SHA512_RESULT_SIZE;
        status = DIGI_MALLOC(
            (void **) &pDigest, digestLen);
        if (OK != status)
            goto exit;

        status = SHA512_completeDigest(pData, dataLen, pDigest);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

    *pDigestLen = digestLen;
    *ppDigest = pDigest; pDigest = NULL;

exit:
    DIGI_FREE((void **) &pDigest);
    return status;
}

extern MSTATUS TRUSTEDGE_utilsBinToString (
    sbyte *pData,
    sbyte4 dataLen,
    sbyte **ppDataStr)
{
    MSTATUS status;
    sbyte *pDataStr = NULL;
    sbyte4 i;

    status = DIGI_MALLOC(
        (void **) &pDataStr, dataLen * 2 + 1);
    if (OK != status)
        return status;

    for (i = dataLen - 1; i >= 0; i--)
    {
        pDataStr[(2 * i) + 1] = returnHexDigit(pData[i]);
        pDataStr[2 * i] = returnHexDigit(pData[i] >> 4);
    }

    pDataStr[dataLen * 2] = '\0';
    *ppDataStr = pDataStr;

    return OK;
}

extern MSTATUS TRUSTEDGE_utilsComputeAsciiDigest(
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashAlgo,
    sbyte **ppDigestStr)
{
    MSTATUS status;
    sbyte *pDigest = NULL;
    sbyte4 digestLen;

    status = TRUSTEDGE_utilsComputeRawDigest(pData, dataLen, hashAlgo, &pDigest, &digestLen);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_utilsBinToString(pDigest, digestLen, ppDigestStr);
    if (OK != status)
        goto exit;

exit:
    DIGI_FREE((void **) &pDigest);
    return status;
}

extern sbyte* TRUSTEDGE_generateFileDigest (sbyte *pPath, ubyte hashAlgo, sbyte4 *pOutLen)
{
    ubyte *pData = NULL;
    ubyte4 dataLen;

    sbyte *pDigest = NULL;
    ubyte4 digestLen;

    if (NULL == pPath || NULL == pOutLen)
        goto exit;

    *pOutLen = 0;

    if (!FMGMT_pathExists (pPath, NULL))
        goto exit;

    if (OK != DIGICERT_readFile(pPath, &pData, &dataLen))
        goto exit;

    if (OK != TRUSTEDGE_utilsComputeRawDigest (pData, dataLen, hashAlgo, &pDigest, &digestLen))
        goto exit;

    *pOutLen = digestLen;

exit:
    DIGICERT_freeReadFile(&pData);

    return pDigest;
}


extern MSTATUS TRUSTEDGE_utilsWriteTrustedCert(
    TrustEdgeConfig *pConfig,
    ubyte *pCert,
    ubyte4 certLen)
{
    MSTATUS status = OK;
    ubyte *pOutCert = NULL, *pDerCert = NULL;
    ubyte4 outCertLen = 0, derCertLen = 0;
    sbyte *pFileName = NULL;
    intBoolean fileExist = FALSE;

    if (NULL == pCert)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Assume certificate is in DER format on error */
    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &pDerCert, &derCertLen);
    if (OK != status)
    {
        pDerCert = pCert;
        derCertLen = certLen;
    }

    /* Compute digest on DER */
    status = TRUSTEDGE_utilsComputeAsciiDigest(pDerCert, derCertLen, ht_sha1, &pFileName);
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pKeystoreCADir, pFileName, &pFileName);
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathExtension(pFileName, ".pem", &pFileName);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_checkFile((char *) pFileName, NULL, &fileExist);
    if (OK == STATUS_IKE_LIFETIME_SECONDS)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        MSG_LOG_print(
            MSG_LOG_VERBOSE,
            "Certificate already exists: %s\n", pFileName);
    }
    else
    {
        status = BASE64_makePemMessageAlloc(
            MOC_PEM_TYPE_CERT, pDerCert, derCertLen, &pOutCert, &outCertLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(
            MSG_LOG_VERBOSE,
            "Writing PEM Certificate File: %s\n", pFileName);

        status = DIGICERT_writeFile(pFileName, pOutCert, outCertLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    DIGI_FREE((void **) &pOutCert);
    DIGI_FREE((void **) &pFileName);

    if (pDerCert != pCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    return status;
}

#if defined(__ENABLE_DIGICERT_TIMESTAMP_MILLISECONDS__)

#define STRPTIME_FORMAT "%Y-%m-%dT%H:%M:%S"

#define DATE_BUFFER_LENGTH 39
extern MSTATUS TRUSTEDGE_utilsGetTime(sbyte **ppCurrentTime, int whichformat)
{
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#if defined(__RTOS_WIN32__)
    struct _timeb tv;
    struct tm tmInfo;
    struct tm *pTmInfo = &tmInfo;
#else
    struct timeval tv;
    struct tm tmInfo;
#endif
    sbyte *pTime = NULL;
    MSTATUS status;
#if !defined(__RTOS_WIN32__)
    int ret;
#endif

    MOC_UNUSED(whichformat);

    if (NULL == ppCurrentTime)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__RTOS_WIN32__)
    _ftime_s(&tv);
    if (0 != _gmtime64_s(&tmInfo, &tv.time))
    {
        status = ERR_GENERAL;
        goto exit;
    }
#else
    ret = gettimeofday(&tv, NULL);
    if (-1 == ret)
    {
        status = ERR_GENERAL;
        goto exit;
    }
    if (NULL == gmtime_r(&tv.tv_sec, &tmInfo))
    {
        status = ERR_GENERAL;
        goto exit;
    }
#endif

    status = DIGI_CALLOC((void **) &pTime, 1, DATE_BUFFER_LENGTH);
    if (OK != status)
        goto exit;

#if defined(__RTOS_WIN32__)
    strftime(pTime, DATE_BUFFER_LENGTH, "%Y-%m-%dT%H:%M:%S", pTmInfo);
    snprintf(pTime + 19, DATE_BUFFER_LENGTH - 19, ".%03dZ", tv.millitm);
#else
    strftime(pTime, DATE_BUFFER_LENGTH, "%Y-%m-%dT%H:%M:%S", &tmInfo);
    snprintf(pTime + 19, DATE_BUFFER_LENGTH - 19, ".%03ldZ", tv.tv_usec / 1000);
#endif

    *ppCurrentTime = pTime;

exit:

    return status;
#else
#error "No time implementation for platform"
#endif
}

#else

#define STRPTIME_FORMAT "%Y-%m-%dT%H:%M:%SZ"

#define DATE_BUFFER_LENGTH 27
extern MSTATUS TRUSTEDGE_utilsGetTime(sbyte **ppCurrentTime, int whichformat)
{
    MSTATUS status = 0;
    sbyte time_buf[DATE_BUFFER_LENGTH] = {0};
    ubyte4 time_size = 0;
    TimeDate curTime;

    MOC_UNUSED(whichformat);

    if ( NULL == ppCurrentTime)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RTOS_timeGMT(&curTime);
    snprintf( (char *)time_buf, DATE_BUFFER_LENGTH,
                "%4d-%02d-%02dT%02d:%02d:%02dZ",
                curTime.m_year + 1970, curTime.m_month, curTime.m_day,
                curTime.m_hour, curTime.m_minute, curTime.m_second);

    time_size = DIGI_STRLEN((const sbyte *)time_buf);
    status = DIGI_CALLOC( (void**)ppCurrentTime, 1, time_size + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(*ppCurrentTime, time_buf, time_size);
    (*ppCurrentTime)[time_size] = '\0';

exit:

    return status;
}

#endif

static time_t TRUSTEDGE_utilsTimeGM(struct tm *tm)
{
#if defined(__RTOS_LINUX__)
    return timegm(tm);
#elif defined(__RTOS_WIN32__)
    /* Windows uses _mkgmtime instead of timegm */
    return _mkgmtime(tm);
#elif defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
    /* FreeRTOS on ESP32 does not have timegm, so we implement it here */
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "UTC", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();
    return ret;
#else
#error "No timegm implementation for platform"
#endif
}

/* Function takes an ISO 8601 encoded date string and checks that it is within
 * the given time windwow
 * pTimeStr   - ISO 8601 encoded date string
 * timeWindow - window, in seconds,  that pTimeStr needs to be winthin */
intBoolean TRUSTEDGE_utilsInValidTimeWindow(sbyte *pTimeStr, sbyte4 timeWindow)
{
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
    struct tm policyTimeStruct = {0};
    sbyte4 policyTime;
    sbyte4 currentTime;

#if defined(__RTOS_WIN32__)
    /* Windows doesn't have strptime, use sscanf instead */
    int parsed;
    parsed = sscanf(pTimeStr, "%d-%d-%dT%d:%d:%d",
        &policyTimeStruct.tm_year, &policyTimeStruct.tm_mon, &policyTimeStruct.tm_mday,
        &policyTimeStruct.tm_hour, &policyTimeStruct.tm_min, &policyTimeStruct.tm_sec);
    if (parsed < 6)
        return FALSE;
    policyTimeStruct.tm_year -= 1900;  /* tm_year is years since 1900 */
    policyTimeStruct.tm_mon -= 1;      /* tm_mon is 0-11 */
#else
    if (NULL == strptime(pTimeStr, STRPTIME_FORMAT, &policyTimeStruct))
        return FALSE;
#endif

    policyTime = (sbyte4)TRUSTEDGE_utilsTimeGM(&policyTimeStruct);
    currentTime = (sbyte4)time(NULL);

    if (-1 == policyTime || -1 == currentTime)
        return FALSE;

    if ((currentTime > policyTime) && (currentTime - policyTime > timeWindow))
        return FALSE;

    if ((policyTime > currentTime) && (policyTime - currentTime > timeWindow))
        return FALSE;

    return TRUE;
#else
#error "No time implementation for platform"
#endif
}

intBoolean TRUSTEDGE_utilsInValidTimeWindowStr(sbyte *pTimeStr1, sbyte *pTimeStr2)
{
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
    struct tm structTime1 = {0};
    struct tm structTime2 = {0};
    sbyte4 time1;
    sbyte4 time2;

#if defined(__RTOS_WIN32__)
    int parsed;
    parsed = sscanf(pTimeStr1, "%d-%d-%dT%d:%d:%d",
        &structTime1.tm_year, &structTime1.tm_mon, &structTime1.tm_mday,
        &structTime1.tm_hour, &structTime1.tm_min, &structTime1.tm_sec);
    if (parsed < 6)
        return FALSE;
    structTime1.tm_year -= 1900;
    structTime1.tm_mon -= 1;
#else
    if (NULL == strptime(pTimeStr1, STRPTIME_FORMAT, &structTime1))
        return FALSE;
#endif

    time1 = (sbyte4)TRUSTEDGE_utilsTimeGM(&structTime1);

#if defined(__RTOS_WIN32__)
    parsed = sscanf(pTimeStr2, "%d-%d-%dT%d:%d:%d",
        &structTime2.tm_year, &structTime2.tm_mon, &structTime2.tm_mday,
        &structTime2.tm_hour, &structTime2.tm_min, &structTime2.tm_sec);
    if (parsed < 6)
        return FALSE;
    structTime2.tm_year -= 1900;
    structTime2.tm_mon -= 1;
#else
    if (NULL == strptime(pTimeStr2, STRPTIME_FORMAT, &structTime2))
        return FALSE;
#endif

    time2 = (sbyte4)TRUSTEDGE_utilsTimeGM(&structTime2);

    if (-1 == time1 || -1 == time2)
        return FALSE;

    if (time1 > time2)
        return FALSE;

    return TRUE;
#else
#error "No time implementation for platform"
#endif
}

/* Compares pTimeStr in the format YYYYMMDDHHMMSSZ to the timeout specified in
 * seconds. If the current time + timeout >= pTimeStr then this function returns
 * TRUE, otherwise it returns FALSE.
 */
intBoolean TRUSTEDGE_utilsIsExpired(sbyte *pTimeStr, sbyte4 timeWindowSeconds)
{
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
    struct tm timeStruct = {0};
    sbyte4 checkTime;
    sbyte4 endTime;

#if defined(__RTOS_WIN32__)
    /* Windows doesn't have strptime, use sscanf instead */
    /* Format: YYYYMMDDHHMMSSZ */
    int parsed;
    parsed = sscanf(pTimeStr, "%4d%2d%2d%2d%2d%2d",
        &timeStruct.tm_year, &timeStruct.tm_mon, &timeStruct.tm_mday,
        &timeStruct.tm_hour, &timeStruct.tm_min, &timeStruct.tm_sec);
    if (parsed < 6)
    {
        return FALSE;
    }
    timeStruct.tm_year -= 1900;  /* tm_year is years since 1900 */
    timeStruct.tm_mon -= 1;      /* tm_mon is 0-11 */
#else
    if (NULL == strptime(pTimeStr, "%Y%m%d%H%M%SZ", &timeStruct))
    {
        return FALSE;
    }
#endif

    checkTime = (sbyte4)TRUSTEDGE_utilsTimeGM(&timeStruct);
    endTime = (sbyte4)time(NULL);

    if (-1 == checkTime || -1 == endTime)
    {
        return FALSE;
    }

    endTime += timeWindowSeconds;

    if (endTime >= checkTime)
        return TRUE;

    return FALSE;
#else
#error "No time implementation for platform"
#endif
}

extern MSTATUS TRUSTEDGE_utilsClearDir(
    sbyte *pDirPath,
    TrustEdgeFuncPtrFileMatch pMatch,
    void *pArg)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry = { 0 };
    sbyte *pFilePath = NULL;
    byteBoolean match = TRUE;

    if (NULL == pDirPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = FMGMT_getFirstFile (pDirPath, &pDir, &dirEntry);
    if (OK != status)
    {
        goto exit;
    }

    if (FTNone == dirEntry.type)
    {
        goto exit;
    }

    do
    {
        if (FTFile == dirEntry.type)
        {
            if (NULL != pMatch)
            {
                status = pMatch(
                    pArg, dirEntry.pName, dirEntry.nameLength, &match);
                if (OK != status)
                {
                    goto exit;
                }
            }

            if (TRUE == match)
            {
                status = COMMON_UTILS_addPathComponent(
                    pDirPath, dirEntry.pName, &pFilePath);
                if (OK != status)
                {
                    goto exit;
                }

                FMGMT_remove(pFilePath, FALSE);
            }
        }
        else if (FTDirectory == dirEntry.type)
        {
            if (0 == DIGI_STRCMP(dirEntry.pName, ".") ||
                0 == DIGI_STRCMP(dirEntry.pName, ".."))
            {
                /* Do nothing... */
            }
            else
            {
                status = COMMON_UTILS_addPathComponent(
                    pDirPath, dirEntry.pName, &pFilePath);
                if (OK != status)
                {
                    goto exit;
                }

                FMGMT_remove(pFilePath, TRUE);
            }
        }

        status = FMGMT_getNextFile(pDir, &dirEntry);
        if (OK != status)
        {
            goto exit;
        }

    } while (FTNone != dirEntry.type);

exit:

    if (NULL != pDir)
    {
        FMGMT_closeDir (&pDir);
    }

    if (NULL != pFilePath)
    {
        DIGI_FREE ((void **)&pFilePath);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_utilsDeletePersisted(
    TrustEdgeConfig *pConfig)
{
    MSTATUS status;
    sbyte *pFilePath = NULL;

    if (NULL == pConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_METRICS_FILE,
        &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_BOOTSTRAP_FILE,
        &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_BOOTSTRAP_SIG_FILE,
        &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_POLICY_AUTH_FILE,
        &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = COMMON_UTILS_addPathComponent(
        pConfig->pConfDir, TRUSTEDGE_DESIRED_ATTRIBUTE_FILE,
        &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        FMGMT_remove(pFilePath, FALSE);
    }

    status = TRUSTEDGE_agentPersistDelete(pConfig);

exit:

    if (NULL != pFilePath)
    {
        DIGI_FREE ((void **)&pFilePath);
    }

    return status;
}

static MSTATUS
TRUSTEDGE_utilsCreateDirectoryRecursive(sbyte* directory, ubyte4 mode)
{
    MSTATUS  status = OK;
    char *sep;

    if (NULL == directory)
    {
        return ERR_NULL_POINTER;
    }

    if (0 == DIGI_STRLEN ((sbyte*)directory))
    {
        return ERR_INVALID_INPUT;
    }

    /* Does directory exist? */
    if (TRUE == FMGMT_pathExists ((sbyte *)directory, NULL))
    {
        return status;
    }

    /* Find last path separator (handle both / and \) */
    sep = strrchr(directory, '/');
#if defined(__RTOS_WIN32__)
    {
        char *backslash = strrchr(directory, '\\');
        if (backslash != NULL && (sep == NULL || backslash > sep))
            sep = backslash;
    }
#endif
    if (NULL == sep)
    {
        return ERR_NULL_POINTER;
    }

    if(sep != NULL) {
        char origChar = *sep;
        *sep = 0;
        status = TRUSTEDGE_utilsCreateDirectoryRecursive(directory, mode);
        if (OK != status)
            return status;
        *sep = origChar;
    }


    status = FMGMT_mkdir((sbyte *)directory, mode);
    if (OK != status)
    {
        if ((ERR_DIR_EXISTS == status) || (ERR_DIR_INVALID_PATH == status))
        {
            status = OK;
        }
    }
    return status;
}

extern MSTATUS TRUSTEDGE_utilsExtractInlineZip(sbyte *pZ, ubyte4 offset, ubyte4 length, sbyte *pDst)
{
    MSTATUS status;
    sbyte fullPath[MAX_PATH_LENGTH];
#if defined(__RTOS_WIN32__)
    const char *pathSep = "\\";
#else
    const char *pathSep = "/";
#endif
    char *sep;

    FileDescriptorInfo fd = {0};

    mz_zip_archive_file_stat file_stat;
    mz_zip_archive zip_archive = {0};
    mz_bool mzStatus;
    sbyte4 ret;

    if (NULL == pZ || NULL == pDst)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto nocleanup;
    }

    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: pZ=%s, offset=%u, length=%u, pDst=%s\n",
        __func__, pZ, offset, length, pDst);

    if (FALSE == FMGMT_pathExists(pZ, NULL))
    {
        status = ERR_TRUSTEDGE_ZIP_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d: zip file does not exist: %s, status: %d = %s\n",
            __func__, __LINE__, pZ, status,
            MERROR_lookUpErrorCode(status));
        goto nocleanup;
    }

    if (FALSE == FMGMT_pathExists(pDst, &fd) || FTDirectory != fd.type)
    {
        status = ERR_TRUSTEDGE_ZIP_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d: destination dir does not exist or not a directory: %s (exists=%d, type=%d), status: %d = %s\n",
            __func__, __LINE__, pDst, FMGMT_pathExists(pDst, NULL), fd.type, status,
            MERROR_lookUpErrorCode(status));
        goto nocleanup;
    }

    mzStatus = mz_zip_reader_init_file_v2(&zip_archive, pZ, 0, offset, length);
    if (0 == mzStatus)
    {
        status = ERR_TRUSTEDGE_ZIP_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d: mz_zip_reader_init_file_v2 failed for %s (offset=%u, length=%u), mz_error=%s, status: %d = %s\n",
            __func__, __LINE__, pZ, offset, length,
            mz_zip_get_error_string(mz_zip_get_last_error(&zip_archive)),
            status, MERROR_lookUpErrorCode(status));
        goto nocleanup;
    }

    for (unsigned int i = 0; i < (ubyte4)mz_zip_reader_get_num_files (&zip_archive); i++)
    {
        mzStatus = mz_zip_reader_file_stat(&zip_archive, i, &file_stat);
        if (0 == mzStatus)
        {
            status = ERR_TRUSTEDGE_ZIP_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        ret = snprintf(fullPath, MAX_PATH_LENGTH, "%s%s%s", pDst, pathSep, (sbyte *) file_stat.m_filename);
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_ZIP_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if(file_stat.m_is_directory && file_stat.m_is_supported)
        {
            status = FMGMT_mkdir(fullPath, 0777);
            if (OK != status && ERR_DIR_EXISTS != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else if(!file_stat.m_is_directory && file_stat.m_is_supported)
        {
            /* check to see if directory exists - find last separator (handle both / and \) */
            sep = strrchr(fullPath, '/');
#if defined(__RTOS_WIN32__)
            {
                char *backslash = strrchr(fullPath, '\\');
                if (backslash != NULL && (sep == NULL || backslash > sep))
                    sep = backslash;
            }
#endif
            if (NULL == sep)
            {
                status = ERR_TRUSTEDGE_ZIP_ERROR;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            *sep = 0;

            if (FALSE == FMGMT_pathExists(fullPath, NULL))
            {
                status = TRUSTEDGE_utilsCreateDirectoryRecursive(fullPath, 0777);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            ret = snprintf(fullPath, MAX_PATH_LENGTH, "%s%s%s", pDst, pathSep, (sbyte *)file_stat.m_filename);
            if (0 > ret)
            {
                status = ERR_TRUSTEDGE_ZIP_ERROR;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            mzStatus = mz_zip_reader_extract_file_to_file(&zip_archive,
                    file_stat.m_filename, fullPath,
                    MZ_ZIP_FLAG_CASE_SENSITIVE);
            if (0 == mzStatus)
            {
                status = ERR_TRUSTEDGE_ZIP_ERROR;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

    status = OK;
exit:
    mz_zip_reader_end (&zip_archive);
nocleanup:
    return status;
}

extern MSTATUS TRUSTEDGE_utilsExtractZip(sbyte *pZ, sbyte *pDst)
{
    return TRUSTEDGE_utilsExtractInlineZip(pZ, 0, 0, pDst);
}

extern MSTATUS TRUSTEDGE_utilsFindPrivateKey(
    sbyte *pPath,
    ubyte *pDerCert,
    ubyte4 derCertLen,
    ubyte **ppKey,
    ubyte4 *pKeyLen,
    sbyte **ppBootstrapFile)
{
    MSTATUS status;
    CStream cs = { 0 };
    MemFile mf = { 0 };
    ASN1_ITEMPTR pRoot = NULL;
    AsymmetricKey pubKey = { 0 };
    AsymmetricKey privKey = { 0 };
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry = { 0 };
    sbyte *pFilePath = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privKey);

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_setKeyFromSubjectPublicKeyInfo(
        ASN1_FIRST_CHILD(pRoot), cs, &pubKey);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_getFirstFile(pPath, &pDir, &dirEntry);
    if (OK != status)
    {
        goto exit;
    }

    while (FTNone != dirEntry.type)
    {
        if (FTFile == dirEntry.type)
        {
            status = COMMON_UTILS_addPathComponentWithLength(
                pPath, dirEntry.pName, dirEntry.nameLength, &pFilePath);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGICERT_readFile(pFilePath, &pKey, &keyLen);
            if (OK != status)
            {
                goto exit;
            }

            CRYPTO_initAsymmetricKey(&privKey);
            status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, &privKey);
            if (OK == status)
            {
                status = CRYPTO_matchPublicKey(&pubKey, &privKey);
                if (OK == status)
                {
                    *ppBootstrapFile = pFilePath; pFilePath = NULL;
                    *ppKey = pKey;
                    *pKeyLen = keyLen;
                    goto exit;
                }
            }

            DIGI_FREE((void **) &pKey);
            CRYPTO_uninitAsymmetricKey(&privKey, NULL);
        }

        status = FMGMT_getNextFile(pDir, &dirEntry);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = ERR_NOT_FOUND;

exit:

    if (NULL != pDir)
    {
        FMGMT_closeDir(&pDir);
    }

    if (NULL != pFilePath)
    {
        DIGI_FREE((void **)&pFilePath);
    }

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    CRYPTO_uninitAsymmetricKey(&privKey, NULL);

    return status;
}

extern MSTATUS TRUSTEDGE_utilsLoadKey(
    sbyte *pKeyPath,
    AsymmetricKey **ppKey)
{
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey *pAsymKey = NULL;

    status = DIGICERT_readFile(pKeyPath, &pKey, &keyLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pAsymKey, 1, sizeof(AsymmetricKey));
    if (OK != status)
    {
        goto exit;
    }

    CRYPTO_initAsymmetricKey(pAsymKey);

    status = CRYPTO_deserializeAsymKey(pKey, keyLen, NULL, pAsymKey);
    if (OK != status)
    {
        goto exit;
    }

    *ppKey = pAsymKey; pAsymKey = NULL;

exit:

    if (NULL != pAsymKey)
    {
        CRYPTO_uninitAsymmetricKey(pAsymKey, NULL);
        DIGI_FREE((void **) &pAsymKey);
    }

    if (NULL != pKey)
    {
        DIGI_FREE((void **) &pKey);
    }

    return status;
}

extern sbyte4 TRUSTEDGE_utilsRemoveLineBreak(sbyte *pString, sbyte4 stringLen)
{
    if (NULL == pString || 0 == stringLen)
        return 0;

    /* remove any line ending */
    if (stringLen > 1  && '\r' == pString[stringLen-2] && '\n' == pString[stringLen-1])
    {
        pString[stringLen-2] = '\0';
        stringLen-=2;
    }
    else if (stringLen > 0 && '\n' == pString[stringLen-1])
    {
        pString[stringLen-1] = '\0';
        stringLen-=1;
    }

    return stringLen;
}

extern MSTATUS TRUSTEDGE_utilsDetermineKeyParams(
    AsymmetricKey *pKey,
    CertEnrollAlg *pCertEnrollAlg,
    TrustEdgeAgentKeySource *pKeySource)
{
    MSTATUS status = OK;
    ubyte4 keyType;
    ubyte4 keySize;
    ubyte2 provider;
    ubyte4 moduleId;
    CertEnrollAlg alg;
    TrustEdgeAgentKeySource src;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 qsAlg;
#endif

    *pCertEnrollAlg = certEnrollAlgUndefined;
    *pKeySource = TRUSTEDGE_KEY_SOURCE_UNDEFINED;

    status = CRYPTO_UTILS_getAsymmetricKeyAttributes(
        pKey, &keyType, &keySize, &provider, &moduleId);
    if (OK != status)
    {
        goto exit;
    }

    switch (keyType & 0xFF)
    {
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
            status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlg);
            if (OK != status)
            {
                goto exit;
            }

            if (cid_PQC_MLDSA_44 == qsAlg)
            {
                alg = mldsa44;
            }
            else if (cid_PQC_MLDSA_65 == qsAlg)
            {
                alg = mldsa65;
            }
            else if (cid_PQC_MLDSA_87 == qsAlg)
            {
                alg = mldsa87;
            }
            else if (cid_PQC_SLHDSA_SHA2_128F == qsAlg)
            {
                alg = slhdsaSha128f;
            }
            else if (cid_PQC_SLHDSA_SHA2_128S == qsAlg)
            {
                alg = slhdsaSha128s;
            }
            else if (cid_PQC_SLHDSA_SHA2_192F == qsAlg)
            {
                alg = slhdsaSha192f;
            }
            else if (cid_PQC_SLHDSA_SHA2_192S == qsAlg)
            {
                alg = slhdsaSha192s;
            }
            else if (cid_PQC_SLHDSA_SHA2_256F == qsAlg)
            {
                alg = slhdsaSha256f;
            }
            else if (cid_PQC_SLHDSA_SHA2_256S == qsAlg)
            {
                alg = slhdsaSha256s;
            }
            else if (cid_PQC_SLHDSA_SHAKE_128F == qsAlg)
            {
                alg = slhdsaShake128f;
            }
            else if (cid_PQC_SLHDSA_SHAKE_128S == qsAlg)
            {
                alg = slhdsaShake128s;
            }
            else if (cid_PQC_SLHDSA_SHAKE_192F == qsAlg)
            {
                alg = slhdsaShake192f;
            }
            else if (cid_PQC_SLHDSA_SHAKE_192S == qsAlg)
            {
                alg = slhdsaShake192s;
            }
            else if (cid_PQC_SLHDSA_SHAKE_256F == qsAlg)
            {
                alg = slhdsaShake256f;
            }
            else if (cid_PQC_SLHDSA_SHAKE_256S == qsAlg)
            {
                alg = slhdsaShake256s;
            }
            else
            {
                status = ERR_CRYPTO_QS_UNSUPPORTED_CIPHER;
                goto exit;
            }
            break;
#endif
        case akt_rsa:
            if (2048 == keySize)
            {
                alg = rsa2048;
            }
            else if (3072 == keySize)
            {
                alg = rsa3072;
            }
            else if (4096 == keySize)
            {
                alg = rsa4096;
            }
            else
            {
                status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
                goto exit;
            }

            break;

        case akt_ecc:
            if (256 == keySize)
            {
                alg = ecdsaP256;
            }
            else if (384 == keySize)
            {
                alg = ecdsaP384;
            }
            else if (521 == keySize)
            {
                alg = ecdsaP521;
            }
            else
            {
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
            }

            break;

        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

    if (0 == provider)
    {
        src = TRUSTEDGE_KEY_SOURCE_SW;
    }
    else
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        switch (provider)
        {
            case TAP_PROVIDER_TPM2:
                src = TRUSTEDGE_KEY_SOURCE_TPM2;
                break;

            case TAP_PROVIDER_PKCS11:
                src = TRUSTEDGE_KEY_SOURCE_PKCS11;
                break;

            case TAP_PROVIDER_TEE:
                src = TRUSTEDGE_KEY_SOURCE_TEE;
                break;

            default:
                status = ERR_TAP_INVALID_TAP_PROVIDER;
                goto exit;
        }
#else
        status = ERR_TAP_UNSUPPORTED;
        goto exit;
#endif
    }

    *pCertEnrollAlg = alg;
    *pKeySource = src;

exit:

    return status;
}

extern ubyte4 TRUSTEDGE_utilsGetJWTSigAlg(sbyte *pAlgId)
{
    JWSAlg alg;
    if (NULL == pAlgId)
    {
        alg = JWS_ALG_NONE;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_RS256, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_RS256)))
    {
        alg = JWS_ALG_RS256;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_RS384, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_RS384)))
    {
        alg = JWS_ALG_RS384;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_RS512, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_RS512)))
    {
        alg = JWS_ALG_RS512;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_ES256, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_ES256)))
    {
        alg = JWS_ALG_ES256;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_ES384, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_ES384)))
    {
        alg = JWS_ALG_ES384;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_ES512, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_ES512)))
    {
        alg = JWS_ALG_ES512;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_PS256, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_PS256)))
    {
        alg = JWS_ALG_PS256;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_PS384, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_PS384)))
    {
        alg = JWS_ALG_PS384;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_PS512, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_PS512)))
    {
        alg = JWS_ALG_PS512;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_MLDSA44, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_MLDSA44)))
    {
        alg = JWS_ALG_MLDSA44;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_MLDSA65, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_MLDSA65)))
    {
        alg = JWS_ALG_MLDSA65;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_MLDSA87, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_MLDSA87)))
    {
        alg = JWS_ALG_MLDSA87;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128F)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_128F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128S)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_128S;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192F)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_192F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192S)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_192S;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256F)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_256F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256S)))
    {
        alg = JWS_ALG_SLHDSA_SHA2_256S;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128F)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_128F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128S)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_128S;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192F)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_192F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192S)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_192S;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256F, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256F)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_256F;
    }
    else if (0 == DIGI_STRNCMP(pAlgId, JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256S, DIGI_STRLEN(JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256S)))
    {
        alg = JWS_ALG_SLHDSA_SHAKE_256S;
    }
#endif
    else
    {
        alg = JWS_ALG_NONE;
    }

    return (ubyte4) alg;
}

extern MSTATUS TRUSTEDGE_utilsParseJWTHeader(
    sbyte *pHeader,
    sbyte4 headerLen,
    JWSAlg *pAlgId,
    certChainPtr *ppCertChain,
    certStorePtr pCertStore,
    byteBoolean isBootstrapVerifyFlow
)
{
    MOC_UNUSED(pCertStore);
    MSTATUS status = OK;
    JSON_TokenType token = { 0 };
    ubyte4 i, ndx;
    certChainPtr pCertChain = NULL;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen;
    JSON_ContextType *pJCtx = NULL;
    JSON_TokenType certToken = { 0 };
    ubyte4 numTokens;
    sbyte *pType = NULL;
    sbyte *pAlg = NULL;
    sbyte *pUse = NULL;
    sbyte *pEncodedHash = NULL;
    ubyte *pHash = NULL;
    sbyte4 cmpRes = -1;
    sbyte4 hashLen;
    sbyte *pCertHash = NULL;
    sbyte4 certHashLen;
    ubyte *pCert = NULL;
    ubyte4 certLen;
    certDescriptor *pCertDesc = NULL;

    status = BASE64_urlDecodeMessage(pHeader, headerLen, &pDecoded, &decodedLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to decode header\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
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

    status = JSON_parse(pJCtx, pDecoded, decodedLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "typ", &pType, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRNCMP(pType, "JWT", DIGI_STRLEN("JWT")))
    {
        status = ERR_TRUSTEDGE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Type %s not supported\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pType);
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "alg", &pAlg, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Algorithm not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pAlgId = (JWSAlg) TRUSTEDGE_utilsGetJWTSigAlg(pAlg);

    if (TRUE == isBootstrapVerifyFlow)
    {
        status = JSON_getJsonStringValue(pJCtx, 0, "use", &pUse, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 != DIGI_STRNCMP(pUse, "sig", DIGI_STRLEN("sig")))
        {
            status = ERR_TRUSTEDGE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Use field should contain sig, found %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), pUse);
            goto exit;
        }
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "x5t#S256", &pEncodedHash, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Hash of signature not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = BASE64_urlDecodeMessage(pEncodedHash, DIGI_STRLEN(pEncodedHash), &pHash, &hashLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to decode hash\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "x5c", &ndx, &token, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Certificate chain not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == token.elemCnt)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. No certificates in array.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pCertDesc, sizeof(certDescriptor), token.elemCnt);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < token.elemCnt; i++)
    {
        ndx++;
        status = JSON_getToken(pJCtx, ndx, &certToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != certToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Certificate not type string\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CA_MGMT_decodeCertificate((ubyte *) certToken.pStart, certToken.len,
            &pCert, &certLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to decode certificate\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pCertDesc[i].pCertificate = pCert; pCert = NULL;
        pCertDesc[i].certLength   = certLen;
    }

    status = TRUSTEDGE_utilsComputeRawDigest(pCertDesc[0].pCertificate, pCertDesc[0].certLength, ht_sha256, &pCertHash, &certHashLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to compute hash of certificate\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (OK > (status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pCertChain, pCertDesc, token.elemCnt)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (certHashLen != hashLen)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_MEMCMP(pHash, pCertHash, hashLen, &cmpRes);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. hashes do not match\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppCertChain = pCertChain;
    pCertChain = NULL;

exit:

    if (NULL != pCertChain)
        CERTCHAIN_delete(&pCertChain);

    JSON_releaseContext(&pJCtx);
    DIGI_FREE((void **) &pDecoded);
    DIGI_FREE((void **) &pType);
    DIGI_FREE((void **) &pAlg);
    DIGI_FREE((void **) &pUse);
    DIGI_FREE((void **) &pCertHash);
    DIGI_FREE((void **) &pEncodedHash);
    DIGI_FREE((void **) &pHash);

    for (i = 0; i < token.elemCnt; i++)
    {
        (void) CA_MGMT_freeCertificate(&pCertDesc[i]);
    }

    DIGI_FREE((void **) &pCertDesc);
    return status;
}

static MSTATUS rsaVerifySignature(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte hashId,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerify
    )
{
    MSTATUS status;
    ubyte *pDigestInfo = NULL, *pDecrypted = NULL;
    ubyte4 digestInfoLen, decryptedLen, rsaKeyLength;
    sbyte4 result = -1;

    status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, (sbyte4 *) &rsaKeyLength, pAsymKey->type);
    if (OK != status)
    {
        goto exit;
    }

    if (rsaKeyLength != signatureLen)
    {
        status = ERR_RSA_INVALID_CIPHERTEXT_LEN;
        goto exit;
    }

    /* Build the digest info from the digest and digest ID. This will be an
     * ASN.1 formatted algorithm ID and raw digest.
     */
    status = ASN1_buildDigestInfoAlloc(
        pDigest, digestLen, hashId, &pDigestInfo, &digestInfoLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocated memory for the verify result.
     */
    status = DIGI_MALLOC((void **) &pDecrypted, signatureLen);
    if (OK != status)
    {
        goto exit;
    }

    /* The RSA API returns the data and the caller must perform the comparsion
     * themselves.
     */
    status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, pSignature, pDecrypted, &decryptedLen, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Ensure the digest info length matches the decrypted signature.
     */
    if (decryptedLen != digestInfoLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Compare the signatures.
     */
    status = DIGI_MEMCMP(
        pDecrypted, pDigestInfo, decryptedLen, &result);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != result)
    {
        *pVerify = 1;
    }
    else
    {
        *pVerify = 0;
    }

exit:

    DIGI_FREE((void **) &pDigestInfo);
    DIGI_FREE((void **) &pDecrypted);

    return status;
}

static MSTATUS eccVerifySignature(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerify
    )
{
    MOC_UNUSED(signatureLen);
    MSTATUS status;
    ubyte4 elementLen, vfyRes = 1;

    /* Get the ECC element length
     */
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pAsymKey->key.pECC, &elementLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify the signature.
     */
    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux( MOC_ECC(hwAccelCtx)
        pAsymKey->key.pECC, pDigest, digestLen, pSignature, elementLen,
        pSignature + elementLen, elementLen, &vfyRes);
    if (OK != status)
    {
        goto exit;
    }

    *pVerify = vfyRes;

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_utilsVerifyJWTSignature(
    JWSAlg alg,
    sbyte *pPlainText,
    sbyte4 plainTextLen,
    certChainPtr pCertChain,
    sbyte *pSig,
    sbyte4 sigLen,
    byteBoolean isBootstrapVerifyFlow
)
{
    MSTATUS status = OK;
    ubyte pDigest[SHA512_RESULT_SIZE];
    ubyte *pExpectedSig = NULL;
    ubyte4 expectedSigLen;
    JSON_ContextType *pJCtx = NULL;
    ubyte hashAlg;
    AsymmetricKey pubKey = {0};
    ubyte4 vStatus = 1;
    ubyte4 digestLen = 0;

    status = CERTCHAIN_getKey(MOC_ASYM(hwAccelCtx) pCertChain, 0, &pubKey);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Remove newline character from the signature, if present */
    if ('\n' == pSig[sigLen - 1])
    {
        pSig[sigLen - 1] = '\0';
        sigLen--;
    }

    status = BASE64_urlDecodeMessage(pSig, sigLen, &pExpectedSig, &expectedSigLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    switch (alg)
    {
        case JWS_ALG_ES256:
        case JWS_ALG_RS256:
            status = SHA256_completeDigest(pPlainText, plainTextLen, pDigest);
            /* FALLTHROUGH */
        case JWS_ALG_PS256:
            hashAlg = ht_sha256;
            digestLen = SHA256_RESULT_SIZE;
            break;
        case JWS_ALG_RS384:
        case JWS_ALG_ES384:
            status = SHA384_completeDigest(pPlainText, plainTextLen, pDigest);
            /* FALLTHROUGH */
        case JWS_ALG_PS384:
            hashAlg = ht_sha384;
            digestLen = SHA384_RESULT_SIZE;
            break;
        case JWS_ALG_RS512:
        case JWS_ALG_ES512:
            status = SHA512_completeDigest(pPlainText, plainTextLen, pDigest);
            /* FALLTHROUGH */
        case JWS_ALG_PS512:
            hashAlg = ht_sha512;
            digestLen = SHA512_RESULT_SIZE;
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
            hashAlg = ht_none;
            digestLen = 0;
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    switch (alg)
    {
        case JWS_ALG_RS256:
        case JWS_ALG_RS384:
        case JWS_ALG_RS512:
            status = rsaVerifySignature(MOC_RSA(hwAccelCtx) &pubKey, pDigest, digestLen,
                hashAlg, pExpectedSig, expectedSigLen, &vStatus);
            break;
        case JWS_ALG_ES256:
        case JWS_ALG_ES384:
        case JWS_ALG_ES512:
            status = eccVerifySignature(MOC_ECC(hwAccelCtx) &pubKey, pDigest, digestLen,
                pExpectedSig, expectedSigLen, &vStatus);
            break;
        case JWS_ALG_PS256:
        case JWS_ALG_PS384:
        case JWS_ALG_PS512:
            status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify (MOC_RSA(hwAccelCtx)
                pubKey.key.pRSA, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pPlainText, plainTextLen,
                pSig, sigLen, digestLen, &vStatus);
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
            status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(hwAccelCtx) pubKey.pQsCtx, pPlainText, plainTextLen,
                                                    pSig, sigLen, &vStatus);
            break;
#endif
        default:
            status = ERR_TRUSTEDGE_AGENT_JWS_ALG_NOT_SUPPORTED;
    }
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != vStatus)
    {
        status = ERR_TRUSTEDGE_AGENT_SIGNATURE_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (FALSE == isBootstrapVerifyFlow)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s",
            "validated signature of authorization token\n");
    }

exit:

    JSON_releaseContext(&pJCtx);
    DIGI_FREE((void **) &pExpectedSig);
    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    return status;
}

extern intBoolean TRUSTEDGE_utilsValidatePayload(
    sbyte *pPolicyId,
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pDeviceName,
    sbyte *pDeviceGroupId,
    sbyte *pPayload,
    sbyte4 payloadLen,
    byteBoolean isBootstrapVerifyFlow
)
{
    MSTATUS status;
    intBoolean isValid = FALSE;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen;
    sbyte *pAccId = NULL;
    sbyte *pDevId = NULL;
    sbyte *pDivId = NULL;
    sbyte *pDevName = NULL;
    sbyte *pDevGrpId = NULL;
    JSON_TokenType policyToken = { 0 };
    JSON_TokenType token = { 0 };
    ubyte4 ndx;
    sbyte4 cmpRes = -1;
    sbyte *pTokenPolicy = NULL;
    intBoolean policyFound = FALSE;

    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 expTime;
    ubyte4 currentTime;

    if (NULL == pPayload)
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "%s", "no payload found\n");
        return isValid;
    }

    status = BASE64_urlDecodeMessage(pPayload, payloadLen, &pDecoded, &decodedLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to decode payload.\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        return isValid;
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

    status = JSON_parse(pJCtx, pDecoded, decodedLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "account_id", &pAccId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. account_id not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRNCMP(pAccountId, pAccId, DIGI_STRLEN(pAccId)))
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "auth. token accound id %s does not match expected id %s\n",
             pAccId, pAccountId);
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "device_id", &pDevId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. device_id not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRNCMP(pDeviceId, pDevId, DIGI_STRLEN(pDevId)))
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "auth. token device id %s does not match expected id %s\n",
             pDevId, pDeviceId);
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, "division_id", &pDivId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. division_id not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != DIGI_STRNCMP(pDivisionId, pDivId, DIGI_STRLEN(pDivId)))
    {
        MSG_LOG_print(MSG_LOG_WARNING,
            "auth. token division id %s does not match expected id %s\n",
             pDivId, pDivisionId);
        goto exit;
    }

    if (TRUE == isBootstrapVerifyFlow)
    {
        status = JSON_getJsonStringValue(pJCtx, 0, "device_name", &pDevName, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. device_name not found\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 != DIGI_STRNCMP(pDeviceName, pDevName, DIGI_STRLEN(pDevName)))
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "auth. token device name %s does not match expected name %s\n",
                 pDevName, pDeviceName);
            goto exit;
        }

        status = JSON_getJsonStringValue(pJCtx, 0, "device_group_id", &pDevGrpId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. device_group_id not found\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (0 != DIGI_STRNCMP(pDeviceGroupId, pDevGrpId, DIGI_STRLEN(pDevGrpId)))
        {
            MSG_LOG_print(MSG_LOG_WARNING,
                "auth. token device group id %s does not match expected id %s\n",
                 pDevGrpId, pDeviceGroupId);
            goto exit;
        }
    }

     /* If a policy ID was provided check that it is in the list of pending policies */
    if (NULL != pPolicyId)
    {
        status = JSON_getJsonArrayValue(pJCtx, 0, "pending_policies", &ndx, &token, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. pending_policies not found\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "looking for policy ID: %s\n", pPolicyId);
        MSG_LOG_print(MSG_LOG_VERBOSE, "number of policies found: %d\n", token.elemCnt);

        for (unsigned int i = 0; i < token.elemCnt; i++)
        {
            ndx++;
            status = JSON_getToken(pJCtx, ndx, &policyToken);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (JSON_String != policyToken.type)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s. auth. policy ID not type string\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            DIGI_FREE((void **) &pTokenPolicy);
            status = DIGI_MALLOC_MEMCPY((void **) &pTokenPolicy, policyToken.len + 1,
                (void *) policyToken.pStart, policyToken.len);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
            pTokenPolicy[policyToken.len] = '\0';

            MSG_LOG_print(MSG_LOG_INFO, "check policy %s\n", pTokenPolicy);

            if (policyToken.len != DIGI_STRLEN(pPolicyId))
            {
                continue;
            }

            status = DIGI_MEMCMP(pPolicyId, policyToken.pStart, policyToken.len, &cmpRes);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (0 == cmpRes)
            {
                policyFound = TRUE;
                break;
            }
        }

        if (FALSE == policyFound)
        {
            MSG_LOG_print(MSG_LOG_INFO, "%s", "no policy matches\n");
            goto exit;
        }
    }

    status = JSON_getJsonIntegerValue(pJCtx, 0, "exp", &expTime, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. exp not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsGetElapsedTime(&currentTime);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. exp not found\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (currentTime < expTime)
    {
        if (FALSE == isBootstrapVerifyFlow)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                "%s", "authorization token valid\n");
        }
        isValid = TRUE;
    }
    else
    {
        if (FALSE == isBootstrapVerifyFlow)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                "%s", "authorization token expired\n");
        }
        else
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                "%s", "bootstrap config signature token expired\n");
        }
    }

exit:

    JSON_releaseContext(&pJCtx);
    DIGI_FREE((void **) &pDecoded);
    DIGI_FREE((void **) &pAccId);
    DIGI_FREE((void **) &pDevId);
    DIGI_FREE((void **) &pDivId);
    DIGI_FREE((void **) &pDevName);
    DIGI_FREE((void **) &pDevGrpId);
    DIGI_FREE((void **) &pTokenPolicy);

    return isValid;
}

extern MSTATUS TRUSTEDGE_utilsParseJWT(
    sbyte *pToken,
    sbyte4 tokenLen,
    sbyte **ppHeader,
    sbyte4 *pHeaderLen,
    sbyte **ppPayload,
    sbyte4 *pPayloadLen,
    sbyte **ppSignature,
    sbyte4 *pSignatureLen
)
{
    MSTATUS status = OK;
    sbyte4 i = 0;

    if (NULL == pToken || NULL == ppHeader || NULL == pHeaderLen || NULL == ppPayload
        || NULL == pPayloadLen || NULL == ppSignature || NULL == pSignatureLen || 0 == tokenLen)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Input parameters NULL\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppHeader = pToken;
    *pHeaderLen = 0;

    while (i < tokenLen)
    {
        if ('.' == pToken[i])
        {
            if (0 == *pHeaderLen)
            {
                *pHeaderLen = i;
                *ppPayload = pToken + i + 1;
            }
            else
            {
                *pPayloadLen = i - *pHeaderLen - 1;
                *ppSignature = pToken + i + 1;
                break;
            }
        }

        i++;
    }

    *pSignatureLen = tokenLen - i - 1;

    if (0 == *pHeaderLen || 0 == *pPayloadLen || 0 == *pSignatureLen)
    {
        status = ERR_TRUSTEDGE_AGENT_JWT_MALFORMED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Malformed JWT\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
    }

exit:
    return status;
}

extern MSTATUS TRUSTEDGE_utilsProcessJWT(
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pToken,
    sbyte4 tokenLen,
    certStorePtr pCertStore
)
{
    MSTATUS status;
    sbyte *pHeader = NULL;
    sbyte4 headerLen = 0;
    sbyte *pPayload = NULL;
    sbyte4 payloadLen = 0;
    sbyte *pSignature = NULL;
    sbyte4 signatureLen = 0;
    JWSAlg alg = JWS_ALG_NONE;
    certChainPtr pCertChain = NULL;

    status = TRUSTEDGE_utilsParseJWT(pToken, tokenLen, &pHeader, &headerLen, &pPayload, &payloadLen, &pSignature, &signatureLen);
    if (OK != status)
        goto exit;

    MSG_LOG_print(MSG_LOG_VERBOSE,
        "%s", "Processing authentication token header\n");

    status = TRUSTEDGE_utilsParseJWTHeader(
        pHeader, headerLen, &alg, &pCertChain, pCertStore, FALSE);
    if (OK != status)
        goto exit;

    MSG_LOG_print(MSG_LOG_INFO, "%s",
        "processing authorization token payload\n");

    if (FALSE == TRUSTEDGE_utilsValidatePayload(NULL, pAccountId, pDeviceId, pDivisionId,
        NULL, NULL, pPayload, payloadLen, FALSE))
    {
        status = ERR_TRUSTEDGE_AGENT_JWT_MALFORMED;
        goto exit;
    }

    status = TRUSTEDGE_utilsVerifyJWTSignature(alg, pHeader, headerLen + 1 + payloadLen, pCertChain, pSignature, signatureLen, FALSE);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pCertChain)
        CERTCHAIN_delete(&pCertChain);
    return status;
}

extern intBoolean TRUSTEDGE_utilsTokenValid(
    sbyte *pPolicyId,
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pToken)
{
    intBoolean isValid = FALSE;
    sbyte4 start;
    sbyte4 end;
    sbyte4 len;
    sbyte4 i;
    MSTATUS status;
    ubyte *pBase64DecodedAuthToken = NULL;
    ubyte4 base64DecodedAuthTokLen = 0;

    if (NULL == pToken)
        return isValid;

    status = BASE64_decodeMessage(
        pToken, DIGI_STRLEN(pToken),
        &pBase64DecodedAuthToken, &base64DecodedAuthTokLen);
    if (OK != status)
    {
        return isValid;
    }

    len = base64DecodedAuthTokLen;

    i = 0;
    start = 0;
    end = 0;
    while (i < len)
    {
        if ('.' == pBase64DecodedAuthToken[i])
        {
            if (0 == start)
            {
                start = i;
            }
            else
            {
                end = i;
                break;
            }
        }

        i++;
    }

    if (0 == start || 0 == end)
    {
        DIGI_FREE((void **) &pBase64DecodedAuthToken);
        return isValid;
    }

    MSG_LOG_print(MSG_LOG_INFO, "%s",
        "processing authorization token payload\n");

    isValid = TRUSTEDGE_utilsValidatePayload(pPolicyId, pAccountId, pDeviceId, pDivisionId,
                NULL, NULL, pBase64DecodedAuthToken + start + 1, end - start - 1, FALSE);
    DIGI_FREE((void **) &pBase64DecodedAuthToken);
    return isValid;
}

extern MSTATUS TRUSTEDGE_utilsGetSigAlgStr(
    ubyte4 sigAlg,
    sbyte **ppSigAlgStr)
{
    switch (sigAlg)
    {
        case ht_sha1:
            *ppSigAlgStr = "SHA1";
            break;
        case ht_sha224:
            *ppSigAlgStr = "SHA224";
            break;
        case ht_sha256:
            *ppSigAlgStr = "SHA256";
            break;
        case ht_sha384:
            *ppSigAlgStr = "SHA384";
            break;
        case ht_sha512:
            *ppSigAlgStr = "SHA512";
            break;
        default:
            *ppSigAlgStr = "UNKNOWN";
            break;
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_utilsPkcs7AlwaysTrust(
    const void *pArg,
    CStream cs,
    struct ASN1_ITEM *pCertificate,
    sbyte4 chainLength)
{
    MOC_UNUSED(pArg);
    MOC_UNUSED(cs);
    MOC_UNUSED(pCertificate);
    MOC_UNUSED(chainLength);

    /* Always trust the certificate */
    return OK;
}

/*----------------------------------------------------------------------------*/

#if !defined(__DISABLE_TRUSTEDGE_EST__)
extern MSTATUS TRUSTEDGE_utilsParseCMCResponse(
    ubyte *pCMCData,
    ubyte4 cmcDataLen,
    AsymmetricKey *pAsymKey,
    certDescriptor **ppCertDesc,
    ubyte4 *pCertDescArrayLen)
{
    MSTATUS status;
    ubyte *pPkcs7Data = NULL, *pTmp = NULL;
    ubyte4 pkcs7DataLen = 0, tmpLen = 0;
    byteBoolean armorDetected = FALSE;
    MemFile mf;
    CStream cs;
    ubyte4 filteredLen = 0;
    SizedBuffer *pCerts = NULL;
    ubyte4 numCerts = 0, i;
    certDescriptor *pRet = NULL;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen = 0;
    ASN1_ITEMPTR pRoot = NULL;
    ASN1_ITEMPTR pSignerIssuer = NULL;
    ASN1_ITEMPTR pSignerSerial = NULL;
#if defined(__ENABLE_DIGICERT_TAP__)
    TAP_Key *pTapKey = NULL;
    byteBoolean tapAttest = FALSE;
#else
    MOC_UNUSED(pAsymKey);
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
    if (0 != (pAsymKey->type & 0xFF0000))
    {
        status = CRYPTO_INTERFACE_getTapKey(pAsymKey, &pTapKey);
        if (OK != status)
            goto exit;

        if (TAP_KEY_USAGE_ATTESTATION == pTapKey->keyData.keyUsage)
        {
            tapAttest = TRUE;
        }
    }
#endif /* __ENABLE_DIGICERT_TAP__ */

    status = EST_filterPkcs7Banner(
        pCMCData, cmcDataLen, &pTmp, &tmpLen,
        &armorDetected);
    if (OK != status)
        goto exit;

    pPkcs7Data = pTmp;
    pkcs7DataLen = tmpLen;

    if (FALSE == armorDetected && pCMCData == pPkcs7Data)
    {
        pTmp = NULL;
    }

    status = CA_MGMT_decodeCertificate(
        pPkcs7Data, pkcs7DataLen, &pDecoded, &decodedLen);
    if (OK != status)
        goto exit;

    MF_attach(&mf, decodedLen, pDecoded);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_EST_verifyFullcmcResponseWithValidateCb(
        pRoot, cs, NULL, TRUSTEDGE_utilsPkcs7AlwaysTrust,
        &pSignerIssuer, &pSignerSerial);
    if (OK != status)
        goto exit;

    status = EST_filterPkcs7Message(
        pPkcs7Data, pkcs7DataLen, &filteredLen);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_TAP__)
    if (TRUE == tapAttest)
    {
        status = EST_handleFullcmcEnrollResponse(
            pAsymKey, pPkcs7Data, filteredLen,
            "application/pkcs7-mime; smime-type=CMC-response",
            DIGI_STRLEN("application/pkcs7-mime; smime-type=CMC-response"),
            &pCerts, &numCerts);
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        status = EST_receiveResponse(
            "application/pkcs7-mime; smime-type=CMC-response",
            DIGI_STRLEN("application/pkcs7-mime; smime-type=CMC-response"),
            pPkcs7Data, filteredLen, pAsymKey, &pCerts, &numCerts);
        if (OK != status)
            goto exit;
    }

    status = TRUSTEDGE_EST_removeOtherCertificates(&pCerts, &numCerts);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(certDescriptor) * numCerts);
    if (OK != status)
        goto exit;

    for (i = 0; i < numCerts; i++)
    {
        status = CA_MGMT_decodeCertificate(
            pCerts[i].data, pCerts[i].length,
            &pRet[i].pCertificate, &pRet[i].certLength);
        if (OK != status)
            goto exit;
    }

    *ppCertDesc = pRet;
    *pCertDescArrayLen = numCerts;

exit:
    if (NULL != pCerts)
    {
        CRYPTO_UTILS_freeCertificates(&pCerts, numCerts);
    }
    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }
    DIGI_FREE((void **) &pDecoded);
    DIGI_FREE((void **) &pTmp);

    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)

extern MSTATUS TRUSTEDGE_utilsProxyConnect(
    sbyte *pHostname,
    sbyte2 port,
    TCP_SOCKET *pSocket,
    TCP_SOCKET *pSocketProxy,
    sbyte4 *pTransportProxy,
    certStorePtr pStore)
{
    MSTATUS status;
    int ret;
    sbyte *pServerAndPort = NULL;

    ret = snprintf(NULL, 0, "%s:%d", pHostname, port);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pServerAndPort, ret + 1);
    if (OK != status)
        goto exit;

    ret = snprintf(pServerAndPort, ret + 1, "%s:%d", pHostname, port);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = HTTP_PROXY_connect(
        pServerAndPort, pSocket, pSocketProxy, pTransportProxy, pStore);

exit:

    if (NULL != pServerAndPort)
    {
        DIGI_FREE((void **) &pServerAndPort);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_HTTP_PROXY__ */

#define TRUSTEDGE_LF            (0x0a)
#define TRUSTEDGE_CR            (0x0d)
#define PEM_CERT_FILLER         (0xAA)
#define PEM_CERT_LINE_LENGTH    (64)

static MSTATUS determinCeilingValue(float float_value,
    ubyte4* value)
{
    MSTATUS status = OK;

    ubyte4 int_value = (ubyte4)float_value;
    if (int_value == (float)float_value)
    {
        *value = int_value;
    }
    else
    {
        *value = int_value + 1;
    }

    return status;
}

static MSTATUS TRUSTEDGE_utilsOneLine(
    sbyte *pCert,
    ubyte4 certLen,
    ubyte4 headerLen,
    ubyte4 footerLen,
    ubyte **ppOneLineCert,
    ubyte4 *pOneLineCertLen)
{
    MSTATUS status = OK;
    ubyte *pNewBuf = NULL;
    float totalLinesFloat = 0;
    ubyte4 totalLines = 0;
    ubyte4 totalSize = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    totalLinesFloat = (float)(certLen - (headerLen + 1) -
            (float)(footerLen + 1)) / (float)PEM_CERT_LINE_LENGTH;
    determinCeilingValue( totalLinesFloat, &totalLines);

    /* Total size is equal to certificate length plus convert each line from NEWLINE
     * to BACKSLASH and 'n' adding one more character per line.  Otherwise adding
     * total lines to be processed, plus the header badge line and footer badge
     * line. Added a few extra bytes in the formula below for safety.
     */
    totalSize = certLen + (totalLines + 2) + 10;

    status = DIGI_MALLOC ((void **)&pNewBuf, totalSize);
    if (OK != status)
    {
        goto exit;
    }
    DIGI_MEMSET ((void *)pNewBuf, PEM_CERT_FILLER, totalSize);

    for( i = 0; i < certLen; i++)
    {
        if( TRUSTEDGE_LF == pCert[i])
        {
            pNewBuf[j] ='\\';
            j++;
            pNewBuf[j] ='n';
            j++;
        }
        else if ( TRUSTEDGE_CR == pCert[i])
        {
            /* Just remove the carriage return */
        }
        else
        {
            pNewBuf[j] = pCert[i];
            j++;
        }
    }

    *ppOneLineCert = pNewBuf;
    *pOneLineCertLen = j;

exit:
    return status;
}

extern MSTATUS TRUSTEDGE_utilsOneLineCert(
    sbyte *pCert,
    ubyte4 certLen,
    ubyte **ppOneLineCert,
    ubyte4 *pOneLineCertLen)
{
    return TRUSTEDGE_utilsOneLine(
        pCert, certLen, MOC_PEM_CERT_HEADER_LEN, MOC_PEM_CERT_FOOTER_LEN,
        ppOneLineCert, pOneLineCertLen);
}

extern MSTATUS TRUSTEDGE_utilsOneLineCSR(
    sbyte *pCsr,
    ubyte4 csrLen,
    ubyte **ppOneLineCert,
    ubyte4 *pOneLineCertLen)
{
    return TRUSTEDGE_utilsOneLine(
        pCsr, csrLen, MOC_PEM_REQ_HEADER_LEN, MOC_PEM_REQ_FOOTER_LEN,
        ppOneLineCert, pOneLineCertLen);
}

extern MSTATUS TRUSTEDGE_agentGetKeyHashAlgorithm(
    CertEnrollAlg keyAlgorithm,
    ubyte4 *pHashId)
{
    switch (keyAlgorithm)
    {
        case rsa2048:
        /* TPM2 RSA 3k and 4k keys support SHA-256 as digest */
        case rsa3072:
        case rsa4096:
        case ecdsaP256:
            *pHashId = ht_sha256;
            break;

        case ecdsaP384:
            *pHashId = ht_sha384;
            break;

        case ecdsaP521:
            *pHashId = ht_sha512;
            break;

        /* eddsa and pqc have intrinsic hash usage */
        default:
            *pHashId = ht_none;
            break;
    }

    return OK;
}

MSTATUS TRUSTEDGE_utilsGetHostByName(sbyte *pName, sbyte *pIpStr)
{
    MSTATUS status = ERR_NOT_FOUND;
    sbyte4 ret = -1;
    TrustedgeGlobalFuncTable *pTable = TRUSTEDGE_getFunctionTable();

    if (NULL == pName || NULL == pIpStr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pTable && NULL != pTable->pFuncDNSLookup)
    {
        ret = pTable->pFuncDNSLookup(pName, pIpStr);
        if (ret == 0)
        {
            status = OK;
        }
    }

    if (-1 == ret)
    {
        status = TCP_GETHOSTBYNAME(pName, pIpStr);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:
    return status;
}

extern MSTATUS TRUSTEDGE_utilsUpdateBootstrapConfig(
    sbyte *pBootstrapConfig,
    sbyte *pBootstrapKeyFile,
    byteBoolean overwriteExistingKeyFile)
{
    MSTATUS status;
    FileDescriptor pFile = NULL;
    sbyte *pConf = NULL;
    ubyte4 confLen = 0;
    sbyte *pLoc = NULL;
    sbyte *pKeyCertBaseName = NULL;

    if (NULL == pBootstrapConfig || NULL == pBootstrapKeyFile)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Input parameters NULL\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = COMMON_UTILS_splitPath(
        pBootstrapKeyFile, NULL, &pKeyCertBaseName);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to get base name from bootstrap key file %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pBootstrapKeyFile);
        goto exit;
    }

    status = DIGICERT_readFile(
        pBootstrapConfig, (ubyte **) &pConf, &confLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to read existing bootstrap config file %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pBootstrapConfig);
        goto exit;
    }

    status = FMGMT_fopen(pBootstrapConfig, "w", &pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to open bootstrap config file %s for writing\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pBootstrapConfig);
        goto exit;
    }

    if (FALSE == overwriteExistingKeyFile)
    {
        /* Add new key alias */
        pLoc = (sbyte *) strstr((const char *) pConf, BOOTSTRAP_CERTALIAS_JSTR);
        if (NULL == pLoc)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }
        pConf[pLoc - pConf - 1] = '\0';

        FMGMT_fprintf(pFile, (const sbyte *) "%s", pConf);
        FMGMT_fprintf(pFile, (const sbyte *) "\"%s\" : \"%s\",\n      \"", BOOTSTRAP_KEYALIAS_JSTR, pKeyCertBaseName);
        FMGMT_fprintf(pFile, (const sbyte *) "%s", pLoc);
    }
    else
    {
        /* Overwrite existing key alias */
        pLoc = (sbyte *) strstr((const char *) pConf, BOOTSTRAP_KEYALIAS_JSTR);
        if (NULL == pLoc)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }
        pConf[pLoc - pConf - 1] = '\0';

        FMGMT_fprintf(pFile, (const sbyte *) "%s", pConf);
        FMGMT_fprintf(pFile, (const sbyte *) "\"%s\" : \"%s\",\n", BOOTSTRAP_KEYALIAS_JSTR, pKeyCertBaseName);
        while (pLoc < pConf + confLen && *pLoc++ != '\n');
        FMGMT_fprintf(pFile, (const sbyte *) "%s", pLoc);
    }

    status = FMGMT_fflush(pFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to flush bootstrap config file %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status), pBootstrapConfig);
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pConf);
    DIGI_FREE((void **) &pKeyCertBaseName);

    if (NULL != pFile)
        FMGMT_fclose(&pFile);

    return status;
}

/*----------------------------------------------------------------------------*/

#if !defined(__RTOS_ZEPHYR__)
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)

#if defined(_MSC_VER)
#include <intrin.h>
#endif

ubyte4 get_intel_cpuid()
{
    ubyte4 family, model, stepping, extended_model, extended_family, processor_type;
    ubyte4 actual_model;
    ubyte4 actual_family;
    ubyte4 cpuid = 0;

#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    ubyte4 eax = (ubyte4)cpuInfo[0];
#else
    ubyte4 eax, ebx, ecx, edx;
    /* Execute CPUID instruction with EAX = 1 */
    asm volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));
#endif

    stepping = eax & 0xF;
    model = (eax >> 4) & 0xF;
    family = (eax >> 8) & 0xF;
    processor_type = (eax >> 12) & 0x3;
    extended_model = (eax >> 16) & 0xF;
    extended_family = (eax >> 20) & 0xFF;

    if (family == 6 || family == 15)
    {
        actual_model = (extended_model << 4) | model;
    }
    else
    {
        actual_model = model;
    }

    if (family == 15)
    {
        actual_family = extended_family + family;
    }
    else
    {
        actual_family = family;
    }
    /*  Bits   3-0: Stepping ID
        Bits   7-4: Model ID
        Bits  15-8: Family ID
        Bits 13-12: Processor Type
        Bits 19-16: Extended Model ID
        Bits 27-20: Extended Family ID */

    cpuid |= (stepping & 0xF);
    cpuid |= ((actual_model & 0xF) << 4);
    cpuid |= ((actual_family & 0xF) << 8);
    cpuid |= (processor_type << 12);
    cpuid |= ((extended_model & 0xF) << 16);
    cpuid |= ((extended_family & 0xFF) << 20);

    MSG_LOG_print(MSG_LOG_VERBOSE, "Intel: Generated CPUID: 0x%08X\n", cpuid);
    return cpuid;
}
#endif

#if defined(__arm__) || defined(__aarch64__)
/* Function to extract value from a line that starts with a specific field */
static void extract_value(const char *line, const ubyte *field_name, ubyte *value) {
    if (DIGI_STRNCMP(line, field_name, strlen(field_name)) == 0) {
        /* Copy the value after the colon and leading spaces */
        DIGI_STRCBCPY(value, BUF_SIZE, strchr(line, ':') + 2);
        value[strlen(value) - 1] = '\0'; /* Remove the newline character */
    }
}

/* Function to convert a hex string to an integer */
static ubyte4 hex_to_int(const ubyte *hex_str) {
    unsigned int val = 0;
    sscanf(hex_str, "%x", &val);
    return val;
}

/* Function to combine the fields into the CPUID format */
static ubyte4 generate_cpuid(ubyte4 implementer, ubyte4 variant, ubyte4 architecture, ubyte4 part, ubyte4 revision) {
    ubyte4 cpuid = 0;

    cpuid |= (implementer & 0xFF) << 24;      /* bits[31:24] */
    cpuid |= (variant & 0xF) << 20;           /* bits[23:20] */
    if (architecture < 8)
	    cpuid |= (architecture & 0xF) << 16;  /* bits[19:16] */
    else
	    cpuid |= (0xF) << 16;                 /* bits[19:16] */
    cpuid |= (part & 0xFFF) << 4;             /* bits[15:4] */
    cpuid |= (revision & 0xF);                /* bits[3:0] */

    return cpuid;
}

MSTATUS get_armXX_cpuid(ubyte4 *cpuid)
{
    MSTATUS status;
    ubyte buffer[BUF_SIZE];
    ubyte cpu_implementer[BUF_SIZE] = "0";
    ubyte cpu_architecture[BUF_SIZE] = "0";
    ubyte cpu_variant[BUF_SIZE] = "0";
    ubyte cpu_part[BUF_SIZE] = "0";
    ubyte cpu_revision[BUF_SIZE] = "0";
    sbyte *pProcCpuFile = "/proc/cpuinfo";
    FileDescriptor cpuinfo = NULL;
    ubyte4 implementer, architecture, variant, part, revision;

    /* Open the /proc/cpuinfo file */
    status = FMGMT_fopen(pProcCpuFile, "r", &cpuinfo);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Error opening file %s\n", pProcCpuFile);
        return status;
    }

    /* Read the file line by line */
    while (FMGMT_fgets(buffer, sizeof(buffer), cpuinfo)) {
        extract_value(buffer, "CPU implementer", cpu_implementer);
        extract_value(buffer, "CPU architecture", cpu_architecture);
        extract_value(buffer, "CPU variant", cpu_variant);
        extract_value(buffer, "CPU part", cpu_part);
        extract_value(buffer, "CPU revision", cpu_revision);
    }

    /* Close the file */
    FMGMT_fclose(&cpuinfo);

    implementer = hex_to_int(cpu_implementer);
    architecture = DIGI_ATOL(cpu_architecture, NULL);
    variant = hex_to_int(cpu_variant);
    part = hex_to_int(cpu_part);
    revision = DIGI_ATOL(cpu_revision, NULL);

    /* Generate the CPUID in the desired format */
    *cpuid = generate_cpuid(implementer, variant, architecture, part, revision);

    /* Display the values and the generated CPUID */
    MSG_LOG_print(MSG_LOG_VERBOSE, "CPU implementer (bits[31:24]): 0x%X\n", implementer);
    MSG_LOG_print(MSG_LOG_VERBOSE, "CPU variant (bits[23:20]): 0x%X\n", variant);
    MSG_LOG_print(MSG_LOG_VERBOSE, "CPU architecture (bits[19:16]): 0x%X\n", architecture);
    MSG_LOG_print(MSG_LOG_VERBOSE, "CPU part (bits[15:4]): 0x%X\n", part);
    MSG_LOG_print(MSG_LOG_VERBOSE, "CPU revision (bits[3:0]): 0x%X\n", revision);
    MSG_LOG_print(MSG_LOG_VERBOSE, "Generated CPUID: 0x%08X\n", *cpuid);

    return status;
}
#endif
#endif /* __RTOS_ZEPHYR__ */

extern MSTATUS TRUSTEDGE_agentAttributesCPUId(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status;
    sbyte4 length = 0;
#if defined(__RTOS_ZEPHYR__)
    sbyte pId[32];
#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
    length = (sbyte4) hwinfo_get_device_id(pId, sizeof(pId));
#endif
    if (length <= 0)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = BASE64_encodeMessage(pId, length, ppVal, pValLen);
    if (OK != status)
    {
        DIGI_FREE((void **) ppVal);
        goto exit;
    }

    *ppVal[*pValLen] = '\0';

    MSG_LOG_print(MSG_LOG_INFO, "CPU ID: %s\n", *ppVal);
exit:
    return status;
#else
    ubyte4 cpuid = 0;

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
    cpuid = get_intel_cpuid();
#elif defined(__arm__) || defined(__aarch64__)
    status = get_armXX_cpuid(&cpuid);
    if (OK != status)
    {
        return status;
    }
#endif

    length = snprintf(NULL, 0, "%X", cpuid);

    status = DIGI_MALLOC((void **)ppVal, length + 1);
    if (OK != status)
    {
        goto exit;
    }

    snprintf(*ppVal, length + 1, "%X", cpuid);
    *pValLen = DIGI_STRLEN(*ppVal);

    MSG_LOG_print(MSG_LOG_INFO, "CPU ID: %s\n", *ppVal);
exit:

    return status;
#endif /* __RTOS_ZEPHYR__ */
}

MOC_STATIC MSTATUS TRUSTEDGE_utilsGetEnv(
    ubyte *pExpr,
    ubyte4 exprLen,
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status = OK;
    ubyte4 i, j, k;
    ubyte *pMetric = NULL;
    ubyte4 metricLen = 0;
    ubyte4 totalLen = exprLen;
    ubyte *pVal = NULL;
    sbyte *pEnvVar = NULL;

    *ppVal = NULL;
    *pValLen = 0;

    /* Iterate through eval expression */
    for (i = 0; i < exprLen - 1; i++)
    {
        /* Check for starting ## */
        if (pExpr[i] == '#' && pExpr[i + 1] == '#')
        {
            for (j = i + 2; j < exprLen - 1; j++)
            {
                /* Find ending ## */
                if (pExpr[j] == '#' && pExpr[j + 1] == '#')
                {
                    DIGI_FREE((void **) &pEnvVar);
                    status = DIGI_MALLOC_MEMCPY(
                        (void **) &pEnvVar, j - i - 1,
                        pExpr + i + 2, j - i - 2);
                    if (OK != status)
                        goto exit;

                    pEnvVar[j - i - 2] = '\0';

                    DIGI_FREE((void **) &pMetric);
                    (void) FMGMT_getEnvironmentVariableValueAlloc(
                        pEnvVar, (sbyte**) &pMetric);

                    /* Couldn't find metric, just exit */
                    if (NULL == pMetric)
                    {
                        goto exit;
                    }

                    metricLen = DIGI_STRLEN(pMetric);

                    /* Adjust total length */
                    totalLen -= (j - i + 2);
                    totalLen += metricLen;
                    break;
                }
            }

            /* If we didn't find ending ## then keep i the same and continue
             * iterating through the string */
            if (j != exprLen - 1)
                i = j + 1;
        }
    }

    status = DIGI_MALLOC((void **) &pVal, totalLen);
    if (OK != status)
        goto exit;

    /* Same loop as above, but now we need to actually replace the values. k is
     * used as the index into the new evaluated value */
    k = 0;
    for (i = 0; i < exprLen - 1; i++)
    {
        if (pExpr[i] == '#' && pExpr[i + 1] == '#')
        {
            for (j = i + 2; j < exprLen - 1; j++)
            {
                if (pExpr[j] == '#' && pExpr[j + 1] == '#')
                {
                    DIGI_FREE((void **) &pEnvVar);
                    status = DIGI_MALLOC_MEMCPY(
                        (void **) &pEnvVar, j - i - 1,
                        pExpr + i + 2, j - i - 2);
                    if (OK != status)
                        goto exit;

                    pEnvVar[j - i - 2] = '\0';

                    DIGI_FREE((void **) &pMetric);
                    (void) FMGMT_getEnvironmentVariableValueAlloc(
                        pEnvVar, (sbyte **) &pMetric);

                    metricLen = DIGI_STRLEN(pMetric);

                    DIGI_MEMCPY(pVal + k, pMetric, metricLen);
                    k += metricLen;
                    break;
                }
            }

            if (j != exprLen - 1)
                i = j + 1;
            else
                pVal[k++] = pExpr[i]; /* End not found, copy # as is */
        }
        else
        {
            pVal[k++] = pExpr[i]; /* Copy value as is from original eval expression */
        }
    }
    /* Copy over last byte as needed */
    if (i < exprLen)
        pVal[k] = pExpr[i];

    *ppVal = pVal; pVal = NULL;
    *pValLen = totalLen;

exit:

    DIGI_FREE((void **) &pMetric);
    DIGI_FREE((void **) &pEnvVar);

    if (NULL != pVal)
    {
        DIGI_FREE((void **) &pVal);
    }

    return status;
}

extern MSTATUS TRUSTEDGE_utilsEval(
    void *pEvalFunctionArg,
    byteBoolean *pUseDefault,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen)
{
    MSTATUS status = OK;
    ubyte *pVal = NULL;
    ubyte4 valLen = 0;

    MOC_UNUSED(pEvalFunctionArg);

    *pUseDefault = FALSE;

    /* Attempt to replace the eval expression */
    status = TRUSTEDGE_utilsGetEnv(
        pExpression, expressionLen, &pVal, &valLen);
    if (OK != status)
        goto exit;

    if (NULL != pVal)
    {
        /* Found eval expression */
        if (NULL == pOutput)
        {
            /* Caller just wants output size */
            status = ERR_BUFFER_TOO_SMALL;
            *pOutputLen = valLen;
        }
        else
        {
            /* Caller wants evaluated value copied to buffer */
            status = DIGI_MEMCPY(pOutput, pVal, valLen);
        }
    }
    else
    {
        /* Use CPU-ID */
        status = TRUSTEDGE_agentAttributesCPUId(&pVal, &valLen);
        if (OK != status)
            goto exit;

        if (NULL == pOutput)
        {
            /* Caller just wants output size */
            status = ERR_BUFFER_TOO_SMALL;
            *pOutputLen = valLen;
        }
        else
        {
            /* Caller wants evaluated value copied to buffer */
            status = DIGI_MEMCPY(pOutput, pVal, valLen);
        }
    }

exit:

    if (NULL != pVal)
    {
        DIGI_FREE((void **) &pVal);
    }

    return status;
}

extern intBoolean TRUSTEDGE_sleepCheckStatusMS(
    ubyte4 sleepMS)
{
    intBoolean exitRequested = FALSE;
    ubyte4 sleepInterval;
    TrustedgeGlobalFuncTable *pTable = TRUSTEDGE_getFunctionTable();

    /* pTable cannot be NULL, NULL check not requied */

    do
    {
        if (NULL != pTable->pFuncOnSafeToExit && 1 == pTable->pFuncOnSafeToExit(OK))
        {
            exitRequested = TRUE;
            goto exit;
        }

        if (sleepMS > TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS)
        {
            sleepInterval = TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS;
        }
        else
        {
            sleepInterval = sleepMS;
        }

        if (FALSE == RTOS_sleepCheckStatusMS(sleepInterval))
        {
            exitRequested = TRUE;
            goto exit;
        }

        sleepMS -= sleepInterval;

    } while (sleepMS > 0);

exit:

    return exitRequested;
}
