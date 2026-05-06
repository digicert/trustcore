/*
 * trustedge_agent_main.c
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

/* Windows includes must come BEFORE project headers to avoid macro conflicts */
#if defined(__RTOS_WIN32__)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <signal.h>
#include <stdio.h>
#endif

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/arg_parser.h"
#include "../common/mocana.h"
#include "../common/common_utils.h"
#include "../common/build_info.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/base64.h"
#include "../common/uri.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#include "../http/client/http_request.h"
#include "../http/client/http_client_process.h"
#include "../trustedge/utils/trustedge_utils.h"
#include "../trustedge/agent/trustedge_agent.h"
#include "../common/mfmgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/crypto_utils.h"
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
#if !defined(__RTOS_WIN32__) && !defined(_WIN32)
#include <unistd.h>
#endif
#include <signal.h>
#include <time.h>
#include <string.h>
#ifdef __RTOS_LINUX__
#include <pwd.h> /* getpwnam() */
#include <grp.h> /* getgrnam() */
#include <sys/types.h>
#include <fcntl.h>
#endif

/*----------------------------------------------------------------------------*/

#define TRUSTEDGE_AGENT_PROG_NAME       "agent"
#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#define TRUSTEDGE_BOOTSTRAP_TMP_DIR     "/tmp/trustedge_bootstrap"
#elif defined(__RTOS_WIN32__)
#define TRUSTEDGE_BOOTSTRAP_TMP_DIR     "C:\\ProgramData\\DigiCert\\trustedge_bootstrap"
#else
#error "No bootstrap tmp dir specified for this platform"
#endif
#define TRUSTEDGE_BOOTSTRAP_SUBDIR      "bootstrap"
#define TRUSTEDGE_CA_SUBDIR             "ca"
#define TRUSTEDGE_BOOTSTRAP_KEY         "bootstrap_key.pem"
#define TRUSTEDGE_BOOTSTRAP_CERT        "bootstrap_cert.pem"
#define CONFIGURATION_JSTR              "configuration"
#define AUTHENTICATION_JSTR             "authentication"
#define MAX_PATH_LENGTH                 1024
#define TRUSTEDGE_AGENT_BOOTSTRAP_URI   "DEVTM_BOOTSTRAP_URI"
#define TRUSTEDGE_BOOTSTRAP_TMP_FILE    "bootstrap.zip.tmp"

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
void SERIALQS_setOqsCompatibleFormat(byteBoolean format);
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
void MLDSA_setLongFormPrivKeyFormat(byteBoolean format);
#endif
#endif

/*----------------------------------------------------------------------------*/

typedef struct
{
    byteBoolean configureMode;
    byteBoolean resetMode;
    byteBoolean downloadMode;
    sbyte *pBootstrapKey;
    sbyte *pBootstrapCert;
    sbyte *pCredsKey;
    sbyte *pCredsCert;
    sbyte *pBootstrapZipFile;
    sbyte *pUser;
    sbyte *pGroup;
    sbyte *pBootstrapEndpoint;
    byteBoolean exit;
} TrustEdgeAgentMainCtx;

/*----------------------------------------------------------------------------*/

static void TRUSTEDGE_agentDisplayHelp(
    char *pProg)
{
    DB_PRINT("Usage: %s [Options]\n", pProg);
    DB_PRINT("\n");
    DB_PRINT("TrustEdge agent utility\n");
    DB_PRINT("\n");
    DB_PRINT("Options:\n");
    DB_PRINT("  --help                                      Display this help menu\n");
    DB_PRINT("  --configure                                 Run agent in configuration mode\n");
    DB_PRINT("  --download                                  Download bootstrap configuration from endpoint\n");
    DB_PRINT("  --reset                                     Reset agent configuration\n");
    DB_PRINT("  --devtm-bootstrap-uri <url>                 URL for downloading bootstrap configuration\n");
    DB_PRINT("  --bootstrap-zip <file>                      Path to bootstrap zip file\n");
    DB_PRINT("                                              (input for --configure, output for --download)\n");
    DB_PRINT("  --bootstrap-configuration <file>            Path to bootstrap configuration file\n");
    DB_PRINT("  --bootstrap-key <file>                      Path to bootstrap key file\n");
    DB_PRINT("                                              Required in --download mode (client auth)\n");
    DB_PRINT("                                              Optional in --configure mode (updates key alias)\n");
    DB_PRINT("  --bootstrap-cert <file>                     Path to bootstrap certificate file\n");
    DB_PRINT("                                              Required in --download mode (client auth)\n");
    DB_PRINT("  --trustedge-user <user>                     Extract bootstrap zip file contents as specified user\n");
    DB_PRINT("                                              This option is to be only used with --bootstrap-zip\n");
    DB_PRINT("  --trustedge-group <group>                   Extract bootstrap zip file contents as specified group\n");
    DB_PRINT("                                              This option is to be only used with --bootstrap-zip\n");
    DB_PRINT("  --creds-key <file>                          Path to credential key file\n");
    DB_PRINT("  --creds-cert <file>                         Path to credential certificate file\n");
    DB_PRINT("  --workspace-dir <dir>                       Path to workspace directory\n");
    DB_PRINT("  --log-level <level>                         Verbosity level of the message logs. Possible values can be\n");
    DB_PRINT("                                                  NONE\n");
    DB_PRINT("                                                  ERROR\n");
    DB_PRINT("                                                  WARNING\n");
    DB_PRINT("                                                  DEBUG\n");
    DB_PRINT("                                                  INFO\n");
    DB_PRINT("                                                  VERBOSE\n");
#if defined(__ENABLE_DIGICERT_PQC__)
    DB_PRINT("  --require-pqc                               Enforce usage of PQC algorithms\n");
    DB_PRINT("  --qs-format-oqs                             Format keys as per oqs format (non-rfc draft compatible)\n");
#endif
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__) && 0
    DB_PRINT("  --debug-dir <dir>                           Debug directory where messages are stored\n");
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__ */
}

static MSTATUS TRUSTEDGE_agentMainProcessArgs(
    int argc,
    char *ppArgv[],
    TrustEdgeConfig *pConfig,
    TrustEdgeAgentMainCtx *pMainCtx)
{
    MSTATUS status = OK;
    int i;
    sbyte *pConnUptimeInterval = NULL;
    sbyte *pKeepAliveInterval = NULL;
    sbyte *pSleepInterval = NULL;
    sbyte *pRefreshHours = NULL;
    sbyte *pBootstrapConfig = NULL;
    sbyte *pWorkspaceDir = NULL;
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
    sbyte *pDebugDir = NULL;
#endif
    byteBoolean hasNewBootstrapConfig = FALSE;

    pMainCtx->exit = TRUE;

    /* Process user provided arguments */
    for (i = 1; i < argc; i++)
    {
        if (0 == DIGI_STRCMP((const sbyte *) ppArgv[i], (const sbyte *) "--help"))
        {
            TRUSTEDGE_agentDisplayHelp(ppArgv[0]);
            goto exit;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--configure", (const sbyte *) ppArgv[i]))
        {
            pMainCtx->configureMode = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--download", (const sbyte *) ppArgv[i]))
        {
            pMainCtx->downloadMode = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--reset", (const sbyte *) ppArgv[i]))
        {
            pMainCtx->resetMode = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--devtm-bootstrap-uri", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pBootstrapEndpoint);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process bootstrap endpoint argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--bootstrap-configuration", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pBootstrapConfig);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process bootstrap configuration argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (NULL != pConfig->pBootstrapConfig)
                DIGI_FREE((void **) &pConfig->pBootstrapConfig);

            pConfig->pBootstrapConfig = pBootstrapConfig;
            pBootstrapConfig = NULL;
            hasNewBootstrapConfig = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--bootstrap-zip", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pBootstrapZipFile);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process bootstrap zip file argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--bootstrap-key", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pBootstrapKey);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process credential key argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--bootstrap-cert", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pBootstrapCert);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process bootstrap certificate argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--creds-key", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pCredsKey);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process credential key argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--creds-cert", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pCredsCert);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process credential certificate argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--trustedge-user", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pUser);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process user name argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--trustedge-group", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pMainCtx->pGroup);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process group name argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--workspace-dir", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pWorkspaceDir);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process credential certificate argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (NULL != pConfig->pWorkspaceDir)
                DIGI_FREE((void **) &pConfig->pWorkspaceDir);

            pConfig->pWorkspaceDir = pWorkspaceDir;
            pWorkspaceDir = NULL;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--log-level", (const sbyte *) ppArgv[i]))
        {
            i++;
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--uptime-interval", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValueRef(
                ppArgv, argc, &i, &pConnUptimeInterval);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process uptime argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pConfig->connUptimeInterval = DIGI_ATOL(pConnUptimeInterval, NULL);
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--keepalive-interval", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValueRef(
                ppArgv, argc, &i, &pKeepAliveInterval);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process keep alive argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pConfig->keepAliveInterval = DIGI_ATOL(pKeepAliveInterval, NULL);
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--sleep-interval", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValueRef(
                ppArgv, argc, &i, &pSleepInterval);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process sleep argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pConfig->sleepInterval = DIGI_ATOL(pSleepInterval, NULL);
        }
        else if (0 == DIGI_STRCMP((const sbyte *) "--refresh-hours", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValueRef(
                ppArgv, argc, &i, &pRefreshHours);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process refresh hours argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            pConfig->refreshHours = DIGI_ATOL(pRefreshHours, NULL);
        }
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
        else if (0 == DIGI_STRCMP((const sbyte *) "--debug-dir", (const sbyte *) ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                ppArgv, argc, &i, &pDebugDir);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to process debug directory argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (NULL != pConfig->pDebugDir)
                DIGI_FREE((void **) &pConfig->pDebugDir);

            pConfig->pDebugDir = pDebugDir;
            pDebugDir = NULL;
        }
#endif
#if defined(__ENABLE_DIGICERT_PQC__)
        else if (0 == DIGI_STRCMP(ppArgv[i], "--require-pqc"))
        {
            /* Do nothing */
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-qsf") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--qs-format-oqs"))
        {
            SERIALQS_setOqsCompatibleFormat(TRUE);
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
            MLDSA_setLongFormPrivKeyFormat(TRUE);
#endif
        }
#endif /* __ENABLE_DIGICERT_PQC__ */
        else if (0 == DIGI_STRCMP((const sbyte *) ppArgv[1], (const sbyte *) "--verify-bootstrap"))
        {
            pConfig->verifyBootstrapSig = TRUE;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_UNKNOWN_ARG;
            TRUSTEDGE_agentDisplayHelp(ppArgv[0]);
            DB_PRINT(
                "\nERROR: Argument \"%s\" not recognized, status = %s (%d)\n",
                ppArgv[i], MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    if (TRUE == pMainCtx->downloadMode && NULL == pMainCtx->pBootstrapEndpoint)
    {
        status = FMGMT_getEnvironmentVariableValueAlloc(
            TRUSTEDGE_AGENT_BOOTSTRAP_URI, &pMainCtx->pBootstrapEndpoint);
        if (status != OK)
        {
            DB_PRINT(
                "ERROR: Missing bootstrap endpoint in download mode, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    /* validate arguments */
    if (TRUE == pMainCtx->downloadMode)
    {
       if (NULL == pMainCtx->pBootstrapEndpoint ||
           NULL == pMainCtx->pBootstrapZipFile ||
           NULL == pMainCtx->pBootstrapCert ||
           NULL == pMainCtx->pBootstrapKey)
       {
           status = ERR_INVALID_ARG;
           DB_PRINT(
               "ERROR: --devtm-bootstrap-uri, --bootstrap-zip, --bootstrap-key, --bootstrap-cert options are required in download mode, failed with status = %s (%d)\n",
               MERROR_lookUpErrorCode(status), status);
           goto exit;
       }
    }

    if ((FALSE == pMainCtx->configureMode) && (FALSE == pMainCtx->downloadMode) && (NULL != pMainCtx->pBootstrapZipFile))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --configure or --download option is required with --bootstrap-zip, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL != pMainCtx->pBootstrapZipFile) && (NULL != pMainCtx->pCredsKey))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --creds-key cannot be used with --bootstrap-zip option, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL != pMainCtx->pBootstrapZipFile) && (NULL != pMainCtx->pCredsCert))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --creds-cert cannot be used with --bootstrap-zip option, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL != pMainCtx->pBootstrapZipFile) && (TRUE == hasNewBootstrapConfig))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --bootstrap-config cannot be used with --bootstrap-zip option, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL == pMainCtx->pBootstrapZipFile) && (NULL != pMainCtx->pBootstrapKey))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --bootstrap-zip option is required with --bootstrap-key, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL == pMainCtx->pBootstrapZipFile) && (NULL != pMainCtx->pUser))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --bootstrap-zip option is required with --trustedge-user, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if ((NULL == pMainCtx->pBootstrapZipFile) && (NULL != pMainCtx->pGroup))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT(
            "ERROR: --bootstrap-zip option is required with --trustedge-group, failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (NULL != pMainCtx->pBootstrapKey)
    {
        if (FALSE == FMGMT_pathExists(pMainCtx->pBootstrapKey, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            DB_PRINT(
                "ERROR: Bootstrap key file not found, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    if (NULL != pMainCtx->pCredsKey)
    {
        if (FALSE == FMGMT_pathExists(pMainCtx->pCredsKey, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            DB_PRINT(
                "ERROR: Credential key file not found, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    if (NULL != pMainCtx->pCredsCert)
    {
        if (FALSE == FMGMT_pathExists(pMainCtx->pCredsCert, NULL))
        {
            status = ERR_PATH_IS_INVALID;
            DB_PRINT(
                "ERROR: Credential certificate file not found, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    pMainCtx->exit = FALSE;

exit:

    return status;
}

static void TRUSTEDGE_agentMainRelease(
    TrustEdgeAgentMainCtx *pMainCtx)
{
    /* Input argument validation not required */

    DIGI_FREE((void **) &pMainCtx->pUser);
    DIGI_FREE((void **) &pMainCtx->pGroup);
    DIGI_FREE((void **) &pMainCtx->pCredsKey);
    DIGI_FREE((void **) &pMainCtx->pCredsCert);
    DIGI_FREE((void **) &pMainCtx->pBootstrapKey);
    DIGI_FREE((void **) &pMainCtx->pBootstrapZipFile);
    DIGI_FREE((void **) &pMainCtx->pBootstrapCert);
    DIGI_FREE((void **) &pMainCtx->pBootstrapEndpoint);
}

static MSTATUS TRUSTEDGE_agentMainGetClientCertCallback(
    sbyte4 connInst,
    SizedBuffer **ppRetCert,
    ubyte4 *pRetNumCerts,
    ubyte **ppRetKeyBlob,
    ubyte4 *pRetKeyBlobLen,
    ubyte **ppRetCACert,
    ubyte4 *pRetNumCACerts)
{
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte *pTmp = NULL;
    ubyte4 tmpLen = 0;
    AsymmetricKey asymKey = { 0 };
    TrustEdgeAgentMainCtx *pCtx = NULL;

    MOC_UNUSED(ppRetCACert);
    MOC_UNUSED(pRetNumCACerts);

    CRYPTO_initAsymmetricKey(&asymKey);

    status = SSL_getCookie(connInst, (void **)&pCtx);
    if (OK != status)
    {
        DB_PRINT("ERROR: SSL_getCookie failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = DIGICERT_readFile(pCtx->pBootstrapCert, &pData, &dataLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(pData, dataLen, &pTmp, &tmpLen);
    if (OK == status)
    {
        DIGI_FREE((void **) &pData);
        pData = pTmp;
        dataLen = tmpLen;
    }

    (*ppRetCert)->data = pData;
    (*ppRetCert)->length = dataLen;
    *pRetNumCerts = 1;

    status = DIGICERT_readFile(pCtx->pBootstrapKey, &pData, &dataLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(pData, dataLen, NULL, &asymKey);
    if (OK != status)
    {
        DB_PRINT("ERROR: CRYPTO_deserializeAsymKey failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = KEYBLOB_makeKeyBlobEx(&asymKey, ppRetKeyBlob, pRetKeyBlobLen);
    if (OK != status)
    {
        DB_PRINT("ERROR: KEYBLOB_makeKeyBlobEx failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

exit:

    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

static sbyte4 TRUSTEDGE_agentMainHttpSslSend(
    httpContext *pHttpContext,
    TCP_SOCKET socket,
    ubyte *pDataToSend,
    ubyte4 numBytesToSend,
    ubyte4 *pRetNumBytesSent,
    sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);
	sbyte4 result = 0;
	sbyte4 connInst = -1;

	connInst = SSL_getInstanceFromSocket(socket);
	result = SSL_send(connInst, (sbyte  *)pDataToSend, numBytesToSend);
	if (0 > result)
	{
		*pRetNumBytesSent = 0;
		return result;
	}

	*pRetNumBytesSent = (ubyte4) result;
	return OK;
}

static sbyte4 TRUSTEDGE_agentMainHttpResponseHeaderCallback(
    httpContext *pHttpContext,
    sbyte4 isContinueFromBlock)
{
    /* do nothing */
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);
    return OK;
}

static sbyte4 TRUSTEDGE_agentMainBootstrapResponseCallback(
    httpContext *pHttpContext,
    ubyte *pDataReceived,
    ubyte4 dataLength,
    sbyte4 isContinueFromBlock)
{
    MSTATUS status = OK;

    MOC_UNUSED(isContinueFromBlock);

    if ((NULL == pHttpContext) || (NULL == pDataReceived) || (0 == dataLength))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = DIGICERT_appendFile(TRUSTEDGE_BOOTSTRAP_TMP_FILE, pDataReceived, dataLength);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to write to file, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainParseDownloadUri(
    sbyte *pBootstrapEndpoint,
    URI **ppUri,
    sbyte **ppHost,
    sbyte **ppPath)
{
    MSTATUS status = OK;

    if (NULL == pBootstrapEndpoint || NULL == ppUri || NULL == ppHost || NULL == ppPath)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = URI_ParseURI(pBootstrapEndpoint, ppUri);
    if (OK != status || NULL == *ppUri)
    {
        DB_PRINT("ERROR: URI_ParseURI failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = URI_GetHost(*ppUri, ppHost);
    if (OK != status || NULL == *ppHost)
    {
        DB_PRINT("ERROR: URI_GetHost failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = URI_GetFullPath(*ppUri, ppPath);
    if (OK != status || NULL == *ppPath)
    {
        DB_PRINT("ERROR: URI_GetFullPath failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainSetupCertStore(
    TrustEdgeConfig *pConfig,
    certStorePtr *pCertStore)
{
    MSTATUS status = OK;
    byteBoolean validateCerts = TRUE;

    if (NULL == pConfig || NULL == pCertStore || NULL == pConfig->pKeystoreCADir)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CERT_STORE_createStore(pCertStore);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to create certificate store, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CRYPTO_UTILS_addTrustPointCertsByDir(
        *pCertStore, NULL, (sbyte *) pConfig->pKeystoreCADir, validateCerts);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to add trust point certificates from directory %s, status = %s (%d)\n",
                 pConfig->pKeystoreCADir, MERROR_lookUpErrorCode(status), status);
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainSetupSslConnection(
    sbyte *pHost,
    sbyte *pServer,
    certStorePtr certStore,
    TrustEdgeAgentMainCtx *pMainCtx,
    TCP_SOCKET *pSocketServer,
    sbyte4 *pConnInst)
{
    MSTATUS status = OK;
    ubyte4 port = 443;

    if (NULL == pHost || NULL == pServer || NULL == certStore || NULL == pMainCtx ||
        NULL == pSocketServer || NULL == pConnInst)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = TCP_CONNECT(pSocketServer, pServer, port);
    if (OK != status)
    {
        DB_PRINT(
            "ERROR: TCP_CONNECT failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    *pConnInst = SSL_connect(
        *pSocketServer, 0, NULL, NULL, (sbyte *) pHost, certStore);
    if (OK > *pConnInst)
    {
        status = (MSTATUS) *pConnInst;
        DB_PRINT("ERROR: SSL_connect failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SSL_setCookie(*pConnInst, pMainCtx);
    if (OK != status)
    {
        DB_PRINT("ERROR: SSL_setCookie failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SSL_setServerNameIndication(*pConnInst, pHost);
    if (OK != status)
    {
        DB_PRINT("ERROR: Failed to set SNI, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SSL_setClientCertCallback(
            *pConnInst, TRUSTEDGE_agentMainGetClientCertCallback);
    if (OK != status)
    {
        DB_PRINT("ERROR: SSL_setClientCertCallback failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = SSL_negotiateConnection(*pConnInst);
    if (OK > status)
    {
        DB_PRINT("ERROR: SSL_negotiateConnection failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainSetupHttpRequest(
    httpContext *pHttpContext,
    sbyte *pHost,
    sbyte *pPath)
{
    MSTATUS status = OK;
    ubyte4 index = 0;

    if (NULL == pHttpContext || NULL == pHost || NULL == pPath)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[GET])))
    {
        DB_PRINT("ERROR: Failed to set HTTP request method, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    index = Host;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)pHost, DIGI_STRLEN((sbyte*)pHost))))
    {
        DB_PRINT("ERROR: Failed to set HTTP Host header, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    index = Accept;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)"application/zip", 15)))
    {
        DB_PRINT("ERROR: Failed to set HTTP Accept header, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, (sbyte*)pPath)))
    {
        DB_PRINT("ERROR: Failed to set HTTP request URI, status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainExecuteHttpDownload(
    TrustEdgeAgentMainCtx *pMainCtx,
    httpContext *pHttpContext,
    sbyte4 connInst
)
{
    MSTATUS status = OK;
    sbyte4 result = -1;
    sbyte tcpBuffer[1024];
    sbyte4 bytesReceived = -1;
    ubyte4 httpStatusCode = 0;

    if (NULL == pMainCtx || NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    while (!HTTP_CLIENT_PROCESS_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
        {
            goto exit;
        }
    }

    while (!HTTP_isDone(pHttpContext))
    {
        result = SSL_recv(connInst, tcpBuffer, sizeof(tcpBuffer), &bytesReceived, 30000);
        if (result >= OK)
        {
            if (bytesReceived == -1)
            {
                status = ERR_TCP_READ_ERROR;
                goto exit;
            }
            status = OK;
        }
        else
        {
            status = result;
            DB_PRINT("ERROR: SSL_recv failed with status = %s (%d)\n",
                     MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if(OK > (status = HTTP_recv(pHttpContext, (ubyte *)tcpBuffer, bytesReceived)))
        {
            DB_PRINT("ERROR: HTTP_recv failed with status = %s (%d)\n",
                     MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (HTTP_CLIENT_STATE(pHttpContext) == finishedClientHttpState)
        {
            if (OK == (status = HTTP_REQUEST_getStatusCode(pHttpContext, &httpStatusCode)))
            {
                if (httpStatusCode == 200)
                {
                    if (FMGMT_pathExists(pMainCtx->pBootstrapZipFile, NULL))
                        FMGMT_remove(pMainCtx->pBootstrapZipFile, FALSE);

                    status = FMGMT_rename(TRUSTEDGE_BOOTSTRAP_TMP_FILE, pMainCtx->pBootstrapZipFile);
                    if (OK != status)
                    {
                        DB_PRINT("ERROR: Failed to save downloaded bootstrap file to %s, status = %s (%d)\n",
                                 pMainCtx->pBootstrapZipFile,
                                 MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    DB_PRINT("Bootstrap configuration downloaded successfully\n");
                }
                else
                {
                    DB_PRINT("ERROR: HTTP request failed with status code %d\n", httpStatusCode);
                    status = ERR_HTTP;
                }
            }
            break;
        }
    }

exit:
    return status;
}

static MSTATUS TRUSTEDGE_agentMainDownload(
    TrustEdgeConfig *pConfig,
    TrustEdgeAgentMainCtx *pMainCtx)
{
    MSTATUS status = OK;
    URI *pUri = NULL;
    sbyte *pHost = NULL;
    sbyte *pPath = NULL;
    certStorePtr certStore = NULL;
    httpContext *pHttpContext = NULL;
    sbyte *pServer = NULL;
    TCP_SOCKET socketServer = 0;
    sbyte4 connInst = -1;

    if (NULL == pConfig || NULL == pMainCtx || NULL == pMainCtx->pBootstrapEndpoint)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("ERROR: Invalid input argument(s), status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (FMGMT_pathExists(TRUSTEDGE_BOOTSTRAP_TMP_FILE, NULL))
    {
        FMGMT_remove(TRUSTEDGE_BOOTSTRAP_TMP_FILE, FALSE);
    }

    status = TRUSTEDGE_agentMainParseDownloadUri(pMainCtx->pBootstrapEndpoint, &pUri, &pHost, &pPath);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentMainSetupCertStore(pConfig, &certStore);
    if (OK != status)
    {
        goto exit;
    }

    status = HTTP_getHostIpAddr(pHost, &pServer);
    if (OK != status)
    {
        DB_PRINT(
            "ERROR: HTTP_getHostIpAddr failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = TRUSTEDGE_agentMainSetupSslConnection(pHost, pServer, certStore, pMainCtx, &socketServer, &connInst);
    if (OK != status)
    {
        goto exit;
    }

    status = HTTP_connect(&pHttpContext, socketServer);
    if (OK > status)
    {
        DB_PRINT("ERROR: HTTP_connect failed with status = %s (%d)\n",
                 MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    HTTP_httpSettings()->funcPtrHttpTcpSend = TRUSTEDGE_agentMainHttpSslSend;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = TRUSTEDGE_agentMainHttpResponseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = TRUSTEDGE_agentMainBootstrapResponseCallback;

    status = TRUSTEDGE_agentMainSetupHttpRequest(pHttpContext, pHost, pPath);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentMainExecuteHttpDownload(pMainCtx, pHttpContext, connInst);

exit:
    if (NULL != pHost)
    {
        DIGI_FREE((void **) &pHost);
    }
    if (NULL != pPath)
    {
        DIGI_FREE((void **) &pPath);
    }
    if (NULL != pServer)
    {
        DIGI_FREE((void **) &pServer);
    }
    if (NULL != pUri)
    {
        URI_DELETE(pUri);
    }
    if (0 <= connInst)
    {
        SSL_closeConnection(connInst);
    }
    if (0 != socketServer)
    {
        TCP_CLOSE_SOCKET(socketServer);
    }
    if (NULL != pHttpContext)
    {
        HTTP_CONTEXT_releaseContext(&pHttpContext);
    }
    if (NULL != certStore)
    {
        CERT_STORE_releaseStore(&certStore);
    }
    if (FMGMT_pathExists(TRUSTEDGE_BOOTSTRAP_TMP_FILE, NULL))
    {
        FMGMT_remove(TRUSTEDGE_BOOTSTRAP_TMP_FILE, FALSE);
    }
    return status;
}

static MSTATUS TRUSTEDGE_agentMainConfigure(TrustEdgeConfig *pConfig, TrustEdgeAgentMainCtx *pMainCtx)
{
    MSTATUS status = OK, tmpStatus = OK;
    sbyte4 cmpRes = -1;
    ubyte4 confLen;
    sbyte *pConf = NULL;
    sbyte *pPath = NULL;
    sbyte *pTmpPath = NULL;
    sbyte *pCAPath = NULL;
    sbyte *pBootstrapConfig = NULL;
    sbyte *pBootstrapSig = NULL;
    sbyte *pConfigPath = NULL;
    sbyte *pSigPath = NULL;
    sbyte *pKeyCertFile = NULL;
    byteBoolean outerConfigFound = FALSE;
    byteBoolean sigFound = FALSE;
    DirectoryEntry dirEnt;
    DirectoryDescriptor pDirDesc = NULL;
    ubyte4 numTokens;
    ubyte4 ndx, objNdx;
    sbyte *pKeyAlias = NULL;
    sbyte *pCertAlias = NULL;
    JSON_TokenType objToken = { 0 };
    JSON_ContextType *pJCtx = NULL;
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
    struct passwd *pPwdEnt;
    struct group *pGrpEnt;
    uid_t uid;
    gid_t gid;
    int chownFd = -1;
#endif

    DB_PRINT("Running agent in configuration mode...\n");
    if (NULL == pConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
    if (NULL != pMainCtx->pUser)
    {
        pPwdEnt = getpwnam((const char *) pMainCtx->pUser);
        if (NULL == pPwdEnt)
        {
            uid = getuid();
            DB_PRINT("WARNING: Invalid user provided: %s, defaulting to current process user\n", pMainCtx->pUser);
        }
        else
        {
            uid = pPwdEnt->pw_uid;
        }
    }
    else
    {
        uid = getuid();
    }

    if (NULL != pMainCtx->pGroup)
    {
        pGrpEnt = getgrnam((const char *) pMainCtx->pGroup);
        if (NULL == pGrpEnt)
        {
            gid = getgid();
            DB_PRINT("WARNING: Invalid group provided: %s, defaulting to current process group\n", pMainCtx->pGroup);
        }
        else
        {
            gid = pGrpEnt->gr_gid;
        }
    }
    else
    {
        gid = getgid();
    }
#endif /* __RTOS_LINUX__ */

    if (NULL != pMainCtx->pBootstrapZipFile)
    {
        if (TRUE == FMGMT_pathExists((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, NULL))
        {
            FMGMT_remove((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, TRUE);
        }

        status = FMGMT_mkdir((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, 0775);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: FMGMT_mkdir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = TRUSTEDGE_utilsExtractZip(pMainCtx->pBootstrapZipFile, (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: Unable to extract bootstrap zip file, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        DB_PRINT("INFO: %s extracted successfully to %s\n", pMainCtx->pBootstrapZipFile, (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR);

        status = COMMON_UTILS_addPathComponent(
            (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, (sbyte *) TRUSTEDGE_BOOTSTRAP_SUBDIR, &pTmpPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pTmpPath, (sbyte *) TRUSTEDGE_BOOTSTRAP_FILE, &pBootstrapConfig);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (FALSE == FMGMT_pathExists(pBootstrapConfig, NULL))
        {
            status = FMGMT_getFirstFile((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, &pDirDesc, &dirEnt);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: Unable to fetch file, failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            do
            {
                status = DIGI_MEMCMP(dirEnt.pName + dirEnt.nameLength - DIGI_STRLEN(SIG_EXT), (const ubyte *) SIG_EXT, DIGI_STRLEN(SIG_EXT), &cmpRes);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: Null pointer exception, failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if ((0 == cmpRes) && (FTFile == dirEnt.type))
                {
                    /* Free previous allocation if any */
                    DIGI_FREE((void **) &pSigPath);
                    /* Allocate and copy the filename - dirEnt.pName is overwritten on next iteration */
                    if (OK == DIGI_MALLOC((void **) &pSigPath, dirEnt.nameLength + 1))
                    {
                        DIGI_MEMCPY(pSigPath, dirEnt.pName, dirEnt.nameLength);
                        pSigPath[dirEnt.nameLength] = '\0';
                    }
                    sigFound = TRUE;
                }

                status = DIGI_MEMCMP(dirEnt.pName + dirEnt.nameLength - DIGI_STRLEN(JSON_EXT), (const ubyte *) JSON_EXT, DIGI_STRLEN(JSON_EXT), &cmpRes);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: Null pointer exception, failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if ((0 == cmpRes) && (FTFile == dirEnt.type))
                {
                    /* Free previous allocation if any */
                    DIGI_FREE((void **) &pConfigPath);
                    /* Allocate and copy the filename - dirEnt.pName is overwritten on next iteration */
                    if (OK == DIGI_MALLOC((void **) &pConfigPath, dirEnt.nameLength + 1))
                    {
                        DIGI_MEMCPY(pConfigPath, dirEnt.pName, dirEnt.nameLength);
                        pConfigPath[dirEnt.nameLength] = '\0';
                    }
                    outerConfigFound = TRUE;
                }

                status = FMGMT_getNextFile(pDirDesc, &dirEnt);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: Unable to fetch next file, failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            } while (FTNone != dirEnt.type);

            if (FALSE == outerConfigFound)
            {
                status = ERR_TRUSTEDGE_AGENT_NO_BOOTSTRAP_CONFIG;
                DB_PRINT(
                    "ERROR: Bootstrap config file not found, failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            else if (FALSE == sigFound)
            {
                /* Allocate a copy of pConfigPath for pSigPath */
                if (NULL != pConfigPath)
                {
                    ubyte4 len = DIGI_STRLEN(pConfigPath);
                    if (OK == DIGI_MALLOC((void **) &pSigPath, len + 1))
                    {
                        DIGI_MEMCPY(pSigPath, pConfigPath, len);
                        pSigPath[len] = '\0';
                    }
                }
                /* TODO: Uncomment the code when bootstrap signature is mandatory
                status = ERR_TRUSTEDGE_AGENT_NO_BOOTSTRAP_SIG;
                DB_PRINT(
                    "ERROR: Bootstrap signature file not found, failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
                */
            }

            status = COMMON_UTILS_addPathComponent((sbyte *)
                TRUSTEDGE_BOOTSTRAP_TMP_DIR, pConfigPath, &pBootstrapConfig);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            status = COMMON_UTILS_addPathComponent((sbyte *)
                TRUSTEDGE_BOOTSTRAP_TMP_DIR, pSigPath, &pBootstrapSig);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }

        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: JSON_acquireContext failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = DIGICERT_readFile((const char *) pBootstrapConfig, (ubyte **) &pConf, &confLen);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = JSON_parse(pJCtx, (const sbyte *) pConf, confLen, &numTokens);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: JSON_parse failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = JSON_getJsonObjectIndex(
            pJCtx, 0, (sbyte *) CONFIGURATION_JSTR, &ndx, TRUE);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: %s field missing in file %s: failed with status = %s (%d)\n",
                CONFIGURATION_JSTR, pBootstrapConfig, MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = JSON_getObjectIndex(
            pJCtx, (const sbyte *) AUTHENTICATION_JSTR, ndx, &objNdx, TRUE);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: %s field missing in file %s: failed with status = %s (%d)\n",
                AUTHENTICATION_JSTR, pBootstrapConfig, MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        objNdx += 2;
        status = JSON_getToken(pJCtx, objNdx, &objToken);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: JSON_getToken failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (JSON_Object != objToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            DB_PRINT(
                "ERROR: Invalid json object type, failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, objNdx, (sbyte *) BOOTSTRAP_KEYALIAS_JSTR, &pKeyAlias, TRUE);
        tmpStatus = JSON_getJsonStringValue(
            pJCtx, objNdx, (sbyte *) BOOTSTRAP_CERTALIAS_JSTR, &pCertAlias, TRUE);

        if ((OK != status) && (OK != tmpStatus))
        {
            DB_PRINT(
                "ERROR: Neither \"key_alias\" nor \"cert_alias\" fields found in file %s, failed with status = %s (%d)\n",
                pBootstrapConfig, MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL != pMainCtx->pBootstrapKey)
        {
            status = TRUSTEDGE_utilsUpdateBootstrapConfig(
                pBootstrapConfig, pMainCtx->pBootstrapKey, (OK != status) ? FALSE : TRUE);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: TRUSTEDGE_utilsUpdateBootstrapConfig failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            DB_PRINT("INFO: Updated key alias in file %s to %s\n", pBootstrapConfig, pMainCtx->pBootstrapKey);

            pMainCtx->pCredsKey = pMainCtx->pBootstrapKey;
            pMainCtx->pBootstrapKey = NULL;
        }
        else
        {
            if (FALSE == outerConfigFound)
            {
                status = COMMON_UTILS_addPathComponent(
                    pTmpPath, (sbyte *) TRUSTEDGE_BOOTSTRAP_KEY, &pKeyCertFile);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (TRUE == FMGMT_pathExists(pKeyCertFile, NULL))
                {
                    pMainCtx->pCredsKey = pKeyCertFile;
                    pKeyCertFile = NULL;
                }
            }
            else if (NULL != pKeyAlias)
            {
                status = COMMON_UTILS_addPathComponent(
                    (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, pKeyAlias, &pKeyCertFile);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (TRUE == FMGMT_pathExists((const sbyte *) pKeyCertFile, NULL))
                {
                    pMainCtx->pCredsKey = pKeyCertFile;
                    pKeyCertFile = NULL;
                }
            }
            else if (NULL == pKeyAlias)
            {
                if (NULL != pDirDesc)
                {
                    if (OK != FMGMT_closeDir(&pDirDesc))
                    {
                        DB_PRINT(
                            "ERROR: FMGMT_closeDir failed with status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }

                status = FMGMT_getFirstFile((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, &pDirDesc, &dirEnt);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: Unable to fetch file, failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                cmpRes = -1;
                do
                {
                    if (FTFile == dirEnt.type)
                    {
                        DIGI_FREE((void **) &pKeyCertFile);
                        status = COMMON_UTILS_addPathComponent(
                            (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, (sbyte *) dirEnt.pName, &pKeyCertFile);
                        if (OK != status)
                        {
                            DB_PRINT(
                                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        DIGICERT_freeReadFile((ubyte **) &pConf);
                        status = DIGICERT_readFile((const char *) pKeyCertFile, (ubyte **) &pConf, &confLen);
                        if (OK != status)
                        {
                            DB_PRINT(
                                "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        status = DIGI_MEMCMP((const ubyte *) pConf, (const ubyte *) "-----BEGIN PRIVATE KEY-----", 27, &cmpRes);
                        if (OK != status)
                        {
                            DB_PRINT(
                                "ERROR: Null pointer exception, failed with status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }

                        if (0 == cmpRes)
                        {
                            pMainCtx->pCredsKey = pKeyCertFile;
                            pKeyCertFile = NULL;
                            break;
                        }
                    }

                    status = FMGMT_getNextFile(pDirDesc, &dirEnt);
                    if (OK != status)
                    {
                        DB_PRINT(
                            "ERROR: Unable to fetch next file, failed with status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                } while (FTNone != dirEnt.type);
            }
            else
            {
                status = ERR_TRUSTEDGE_AGENT_NO_KEY;
                DB_PRINT(
                    "ERROR: Unable to find bootstrap key file, failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }

        DIGI_FREE((void **) &pKeyCertFile);
        if (FALSE == outerConfigFound)
        {
            status = COMMON_UTILS_addPathComponent(
                pTmpPath, (sbyte *) TRUSTEDGE_BOOTSTRAP_CERT, &pKeyCertFile);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (NULL != pCertAlias)
        {
            status = COMMON_UTILS_addPathComponent(
                (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, pCertAlias, &pKeyCertFile);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }

        if (TRUE == FMGMT_pathExists(pKeyCertFile, NULL))
        {
            pMainCtx->pCredsCert = pKeyCertFile;
            pKeyCertFile = NULL;
        }

        status = COMMON_UTILS_addPathComponent(
            (sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, (sbyte *) TRUSTEDGE_CA_SUBDIR, &pCAPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (TRUE == FMGMT_pathExists(pCAPath, NULL))
        {
            if (NULL != pDirDesc)
            {
                if (OK != FMGMT_closeDir(&pDirDesc))
                {
                    DB_PRINT(
                        "ERROR: FMGMT_closeDir failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }

            status = FMGMT_getFirstFile(pCAPath, &pDirDesc, &dirEnt);
            do
            {
                if (FTFile == dirEnt.type)
                {
                    DIGI_FREE((void **) &pKeyCertFile);
                    status = COMMON_UTILS_addPathComponent(
                        pCAPath, (sbyte *) dirEnt.pName, &pKeyCertFile);
                    if (OK != status)
                    {
                        DB_PRINT(
                            "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    DIGI_FREE((void **) &pTmpPath);
                    status = COMMON_UTILS_addPathComponent(
                        pConfig->pKeystoreCADir, (sbyte *) dirEnt.pName, &pTmpPath);
                    if (OK != status)
                    {
                        DB_PRINT(
                            "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGICERT_copyFile((const char *) pKeyCertFile, (const char *) pTmpPath);
                    if (OK != status)
                    {
                        DB_PRINT(
                            "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
                    if ((NULL != pMainCtx->pUser) || (NULL != pMainCtx->pGroup))
                    {
                        chownFd = open((const char *) pTmpPath, O_RDONLY | O_NOFOLLOW);
                        if (-1 == chownFd) {
                            status = ERR_FILE_WRITE_FAILED;
                            DB_PRINT(
                                "ERROR: fchown open failed\n");
                            goto exit;
                        }
                        if (-1 == fchown(chownFd, uid, gid)) {
                            status = ERR_FILE_WRITE_FAILED;
                            DB_PRINT(
                                "ERROR: fchown failed with status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                        close(chownFd);
                        chownFd = -1;
                    }
#endif /* __RTOS_LINUX__ */
                }

                if (FTNone == dirEnt.type)
                {
                    break;
                }

                status = FMGMT_getNextFile(pDirDesc, &dirEnt);
                if (OK != status)
                {
                    DB_PRINT(
                        "ERROR: Unable to fetch next file, failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            } while (TRUE);
        }

        DIGI_FREE((void **) &(pConfig->pBootstrapConfig));
        pConfig->pBootstrapConfig = pBootstrapConfig;
        pBootstrapConfig = NULL;
    }

    if (NULL != pConfig->pBootstrapConfig)
    {
        status = COMMON_UTILS_addPathComponent(
            pConfig->pConfDir,
            (sbyte *) TRUSTEDGE_BOOTSTRAP_FILE,
            &pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        DB_PRINT("Copying bootstrap configuration file %s to %s\n", pConfig->pBootstrapConfig, pPath);

        status = DIGICERT_copyFile((const char *) pConfig->pBootstrapConfig, (const char *) pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
        if ((NULL != pMainCtx->pUser) || (NULL != pMainCtx->pGroup))
        {
            chownFd = open((const char *) pPath, O_RDONLY | O_NOFOLLOW);
            if (-1 == chownFd) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown open failed\n");
                goto exit;
            }
            if (-1 == fchown(chownFd, uid, gid)) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            close(chownFd);
            chownFd = -1;
        }
#endif /* __RTOS_LINUX__ */
    }

    if (NULL != pBootstrapSig)
    {
        /* TODO: Remove this condition once we deploy this to prod */
        if (0 != DIGI_STRCMP(pConfig->pBootstrapConfig, pBootstrapSig))
        {
            status = COMMON_UTILS_addPathComponent(
                pConfig->pConfDir,
                (sbyte *) TRUSTEDGE_BOOTSTRAP_SIG_FILE,
                &pPath);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            DB_PRINT("Copying bootstrap signature file %s to %s\n", pBootstrapSig, pPath);

            status = DIGICERT_copyFile((const char *) pBootstrapSig, (const char *) pPath);
            if (OK != status)
            {
                DB_PRINT(
                    "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
            if ((NULL != pMainCtx->pUser) || (NULL != pMainCtx->pGroup))
            {
                chownFd = open((const char *) pPath, O_RDONLY | O_NOFOLLOW);
                if (-1 == chownFd) {
                    status = ERR_FILE_WRITE_FAILED;
                    DB_PRINT(
                        "ERROR: fchown open failed\n");
                    goto exit;
                }
                if (-1 == fchown(chownFd, uid, gid)) {
                    status = ERR_FILE_WRITE_FAILED;
                    DB_PRINT(
                        "ERROR: fchown failed with status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                close(chownFd);
                chownFd = -1;
            }
#endif /* __RTOS_LINUX__ */
        }
    }

    if (NULL != pMainCtx->pCredsCert)
    {
        status = COMMON_UTILS_splitPath(
            pMainCtx->pCredsCert, NULL, &pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_splitPath failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreCertsDir, pPath, &pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        DB_PRINT("Copying credential certificate file %s to %s\n", pMainCtx->pCredsCert, pPath);

        status = DIGICERT_copyFile((const char *) pMainCtx->pCredsCert, (const char *) pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
        if ((NULL != pMainCtx->pUser) || (NULL != pMainCtx->pGroup))
        {
            chownFd = open((const char *) pPath, O_RDONLY | O_NOFOLLOW);
            if (-1 == chownFd) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown open failed\n");
                goto exit;
            }
            if (-1 == fchown(chownFd, uid, gid)) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            close(chownFd);
            chownFd = -1;
        }
#endif /* __RTOS_LINUX__ */
    }

    if (NULL != pMainCtx->pCredsKey)
    {
        status = COMMON_UTILS_splitPath(
            pMainCtx->pCredsKey, NULL, &pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_splitPath failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = COMMON_UTILS_addPathComponent(
            pConfig->pKeystoreKeysDir, pPath, &pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: COMMON_UTILS_addPathComponent failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        DB_PRINT("Copying credential key file %s to %s\n", pMainCtx->pCredsKey, pPath);

        status = DIGICERT_copyFile((const char *) pMainCtx->pCredsKey, (const char *) pPath);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: DIGICERT_readFile failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
        if ((NULL != pMainCtx->pUser) || (NULL != pMainCtx->pGroup))
        {
            chownFd = open((const char *) pPath, O_RDONLY | O_NOFOLLOW);
            if (-1 == chownFd) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown open failed\n");
                goto exit;
            }
            if (-1 == fchown(chownFd, uid, gid)) {
                status = ERR_FILE_WRITE_FAILED;
                DB_PRINT(
                    "ERROR: fchown failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            close(chownFd);
            chownFd = -1;
        }
#endif /* __RTOS_LINUX__ */
    }

    DB_PRINT("Configuration completed successfully\n");

exit:
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)
    if (chownFd >= 0)
        close(chownFd);
#endif
    if (NULL != pPath)
    {
        DIGI_FREE((void **) &pPath);
    }
    if (NULL != pBootstrapConfig)
    {
        DIGI_FREE((void **) &pBootstrapConfig);
    }
    if (NULL != pBootstrapSig)
    {
        DIGI_FREE((void **) &pBootstrapSig);
    }
    if (NULL != pTmpPath)
    {
        DIGI_FREE((void **) &pTmpPath);
    }
    if (NULL != pCAPath)
    {
        DIGI_FREE((void **) &pCAPath);
    }
    if (NULL != pKeyAlias)
    {
        DIGI_FREE((void **) &pKeyAlias);
    }
    if (NULL != pCertAlias)
    {
        DIGI_FREE((void **) &pCertAlias);
    }
    if (NULL != pKeyCertFile)
    {
        DIGI_FREE((void **) &pKeyCertFile);
    }
    if (NULL != pConfigPath)
    {
        DIGI_FREE((void **) &pConfigPath);
    }
    if (NULL != pSigPath)
    {
        DIGI_FREE((void **) &pSigPath);
    }
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }
    if (NULL != pDirDesc)
    {
        if (OK != FMGMT_closeDir(&pDirDesc))
        {
            tmpStatus = ERR_DIR_CLOSE_FAILED;
            DB_PRINT(
                "ERROR: FMGMT_closeDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(tmpStatus), tmpStatus);
        }
    }

    DIGICERT_freeReadFile((ubyte **) &pConf);

    if (TRUE == FMGMT_pathExists(TRUSTEDGE_BOOTSTRAP_TMP_DIR, NULL))
    {
        if (OK != FMGMT_remove((const sbyte *) TRUSTEDGE_BOOTSTRAP_TMP_DIR, TRUE))
        {
            DB_PRINT("ERROR: Attempt to remove %s dir failed\n", TRUSTEDGE_BOOTSTRAP_TMP_DIR);
        }
        else
        {
            DB_PRINT("INFO: Cleaning up %s\n", TRUSTEDGE_BOOTSTRAP_TMP_DIR);
        }
    }

    return status;
}

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
int TRUSTEDGE_extractBootStrap(char *pPath)
{
    MSTATUS status;
    TrustEdgeAgentMainCtx ctx = {0};
    TrustEdgeConfig *pConfig = NULL;
    ctx.pBootstrapZipFile = pPath;

    status = TRUSTEDGE_utilsReadConfig(&pConfig);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_agentMainConfigure(pConfig, &ctx);

exit:

    /* pBootstrapZipFile was not allocated, zero the pointer so it won't be freed */
    ctx.pBootstrapZipFile = NULL;
    TRUSTEDGE_agentMainRelease(&ctx);

    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
    }

    return status;
}
#endif


static MSTATUS TRUSTEDGE_agentMainKeysMatch(
    void *pArg,
    sbyte *pFile,
    ubyte4 fileLen,
    byteBoolean *pMatch)
{
    MOC_UNUSED(pArg);
    MOC_UNUSED(pFile);
    MOC_UNUSED(fileLen);

    *pMatch = TRUE;
    return OK;
}

extern MSTATUS TRUSTEDGE_agentMainReset(
    )
{
    MSTATUS status;
    MSTATUS fstatus = OK;
    TrustEdgeConfig *pConfig = NULL;
    sbyte *pPath = NULL;

    DB_PRINT("Running agent in reset mode...\n");

    status = TRUSTEDGE_utilsReadConfig(&pConfig);
    if (OK != status)
    {
        DB_PRINT(
            "WARNING: TRUSTEDGE_utilsReadConfig failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        if (fstatus == OK)
            fstatus = status;
    }

    if (NULL != pConfig->pKeystoreCADir && TRUE == FMGMT_pathExists(pConfig->pKeystoreCADir, NULL))
    {
        DB_PRINT("Clearing %s directory\n", pConfig->pKeystoreCADir);

        status = TRUSTEDGE_utilsClearDir(pConfig->pKeystoreCADir, NULL, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "WARNING: TRUSTEDGE_utilsClearDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            if (fstatus == OK)
                fstatus = status;
        }
    }

    if (NULL != pConfig->pKeystoreCertsDir && TRUE == FMGMT_pathExists(pConfig->pKeystoreCertsDir, NULL))
    {
        DB_PRINT("Clearing %s directory\n", pConfig->pKeystoreCertsDir);

        status = TRUSTEDGE_utilsClearDir(pConfig->pKeystoreCertsDir, NULL, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "WARNING: TRUSTEDGE_utilsClearDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            if (fstatus == OK)
                fstatus = status;
        }
    }

    if (NULL != pConfig->pKeystoreKeysDir && TRUE == FMGMT_pathExists(pConfig->pKeystoreKeysDir, NULL))
    {
        DB_PRINT("Clearing %s directory\n", pConfig->pKeystoreKeysDir);

        status = TRUSTEDGE_utilsClearDir(pConfig->pKeystoreKeysDir, TRUSTEDGE_agentMainKeysMatch, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "WARNING: TRUSTEDGE_utilsClearDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            if (fstatus == OK)
                fstatus = status;
        }
    }

    if (NULL != pConfig->pKeystoreReqDir && TRUE == FMGMT_pathExists(pConfig->pKeystoreReqDir, NULL))
    {
        DB_PRINT("Clearing %s directory\n", pConfig->pKeystoreReqDir);

        status = TRUSTEDGE_utilsClearDir(pConfig->pKeystoreReqDir, NULL, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "WARNING: TRUSTEDGE_utilsClearDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            if (fstatus == OK)
                fstatus = status;
        }
    }

    if (NULL != pConfig->pProviderCredsDir && TRUE == FMGMT_pathExists(pConfig->pProviderCredsDir, NULL))
    {
        DB_PRINT("Clearing %s directory\n", pConfig->pProviderCredsDir);

        status = TRUSTEDGE_utilsClearDir(pConfig->pProviderCredsDir, NULL, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "WARNING: TRUSTEDGE_utilsClearDir failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            if (fstatus == OK)
                fstatus = status;
        }
    }

    DB_PRINT("Clearing configuration\n");

    status = TRUSTEDGE_utilsDeletePersisted(pConfig);
    if (OK != status)
    {
        DB_PRINT(
            "WARNING: TRUSTEDGE_utilsDeletePersisted failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        if (fstatus == OK)
            fstatus = status;
    }

    DB_PRINT("Reset completed\n");

    if (NULL != pPath)
    {
        DIGI_FREE((void **) &pPath);
    }

    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
    }

    return fstatus;
}

extern volatile int gShutdownClient;
static int statusCheckCallback(int status)
{
    MOC_UNUSED(status);
    return gShutdownClient;
}

int TRUSTEDGE_agentMain(int argc, char *ppArgv[], int isService, TrustEdgeConfig **ppConfig)
{
    MSTATUS status;
    TrustEdgeAgentMainCtx mainCtx = { 0 };
    TrustEdgeAgentContext *pCtx = NULL;

    if (NULL == ppConfig || NULL == *ppConfig)
    {
        status = ERR_TRUSTEDGE_NO_CONFIG_FILE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "TRUSTEDGE_agentMain failed, missing trustedge config status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO, "Trustedge version : %s\n", BUILD_INFO_VERSION_VAL);

    status = TRUSTEDGE_agentMainProcessArgs(argc, ppArgv, *ppConfig, &mainCtx);
    if (OK != status)
    {
        DB_PRINT(
            "ERROR: TRUSTEDGE_agentMainProcessArgs failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (TRUE == mainCtx.exit)
    {
        goto exit;
    }

    if (TRUE == mainCtx.downloadMode)
    {
        status = TRUSTEDGE_agentMainDownload(*ppConfig, &mainCtx);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentMainDownload failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (FALSE == mainCtx.configureMode)
        {
            goto exit;
        }
    }

    if (TRUE == mainCtx.configureMode)
    {
        if (NULL != mainCtx.pBootstrapZipFile)
        {
            if (FALSE == FMGMT_pathExists(mainCtx.pBootstrapZipFile, NULL))
            {
                status = ERR_PATH_IS_INVALID;
                DB_PRINT(
                    "ERROR: Bootstrap zip file not found, failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        if(TRUE == TRUSTEDGE_isServiceRunning())
        {
            DB_PRINT("%s %s %s",
                "Warning: The Trustedge service is currently running.",
                "Please stop the Trustedge service first,",
                "then reset the device before proceeding with configuration.\n");
            status = ERR_TRUSTEDGE_AGENT_ALREADY_RUNNING;
            goto exit;
        }
        status = TRUSTEDGE_agentMainConfigure(*ppConfig, &mainCtx);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentMainConfigure failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
        }
        goto exit;
    }
    else if (TRUE == mainCtx.resetMode)
    {
        if(TRUE == TRUSTEDGE_isServiceRunning())
        {
            DB_PRINT("%s",
                "WARNING: The Trustedge service is currently running. Please stop the Trustedge service first.\n");
            status = ERR_TRUSTEDGE_AGENT_ALREADY_RUNNING;
            goto exit;
        }
        status = TRUSTEDGE_agentMainReset();
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentMainReset failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
        }
        goto exit;
    }

    TRUSTEDGE_registerStatusCallback(statusCheckCallback);

    if (isService)
    {
        status = TRUSTEDGE_agentContextService (ppConfig, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentContextService failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
    else
    {
        status = TRUSTEDGE_agentContextAcquire(&pCtx, ppConfig);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentContextAcquire failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        status = TRUSTEDGE_agentContextProcess(pCtx, NULL);
        if (OK != status)
        {
            DB_PRINT(
                "ERROR: TRUSTEDGE_agentContextProcess failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

exit:

    if (NULL != pCtx)
    {
        TRUSTEDGE_agentContextRelease(&pCtx);
    }

    TRUSTEDGE_agentMainRelease(&mainCtx);

    MSG_LOG_print(MSG_LOG_INFO, "Exiting agent: status = %s (%d)\n", MERROR_lookUpErrorCode(status), status);

    return (OK == status) ? 0 : -1;
}
