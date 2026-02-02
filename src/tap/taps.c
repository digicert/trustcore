/*
 * taps.c
 *
 * Trust Anchor Platform Server
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
#include <stdio.h>

#ifdef __RTOS_WIN32__
#include <Windows.h>
#endif

#include "../common/moptions.h"

#if defined(__LINUX_RTOS__)
#include "stdlib.h"
#include "string.h"
#include <signal.h>
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#include <signal.h>
#endif


#if defined (__ENABLE_DIGICERT_TAP__)
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mprintf.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/moc_config.h"
#include "../common/base64.h"
#include "../common/mfmgmt.h"

#include "../crypto/cert_store.h"
#ifdef __ENABLE_DIGICERT_EXTENDED_CRED_VALIDATION__
#include "../common/mjson.h"
#include "../crypto/crypto_utils.h"
#endif
#include "../ssl/ssl.h"


#include "taps.h"
#include "tap_smp.h"
#include "tap_common.h"
#include "tap_remote.h"
#include "tap_conf_common.h"
#include "tap_utils.h"
#include "tools/moctap_credparser.h"

#include "tap_serialize.h"
#include "tap_serialize_smp.h"
#include "tap_serialize_remote.h"
#include "tap_serialize_remote.h"
#include "smp_serialize_interface.h"
#ifdef __ENABLE_DIGICERT_TPM2__
#include "../smp/smp_tpm2/smp_tap_tpm2.h"
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#include "../data_protection/file_protect_external_seed.h"
#endif

#ifdef __RTOS_WIN32__
#include "../common/mcmdline.h"
#endif

#if defined(__RTOS_WIN32__) && defined(__RUN_TAPS_SERVICE__)
#include "..\tap\win\svc_utils.h"
#include "..\tap\win\eventlog_utils.h"
#endif

#define MAX_SSL_SERVER_CONNECTIONS  16

#define MAX_CMD_BUFFER   8192

#ifndef __RTOS_WIN32__
#define TAP_CONF_FILE_DIR "/etc/digicert/"
#else
/* For Windows, this is directory name/path relative to %ProgramData%\Mocana */
#define TAP_CONF_FILE_DIR ""
#endif

typedef struct _TAPS_MODULE_CONFIG_SECTION
{
    int moduleId;
    TAP_Buffer credentialsFile;

    /* credentials file is parsed to generate this list */
    TAP_EntityCredentialList *pServerCredentialsList;

    struct _TAPS_MODULE_CONFIG_SECTION *pNext;
} TAPS_MODULE_CONFIG_SECTION;

typedef struct
{
    TAPS_MODULE_CONFIG_SECTION **ppModuleConfigSection;
    char *name;
} TAPS_PARSE_PARMS;

#define TAP_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TAP_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#ifdef __RTOS_WIN32__
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        sprintf_s(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#else
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        snprintf(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#endif

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

/*------------------------------------------------------------------*/
/*  Internal types and  definitions */
/*------------------------------------------------------------------*/

/* Local provider list, created during startup */
static TAP_ProviderList localProviderList = { 0 };
/* Local config info list, created during startup */
static TAP_ConfigInfoList configInfoList = { 0 };

/* Fix me, Remove when credentials are scanned from module section */
TAP_EntityCredentialList serverCredentialsList = {0};

TAPS_MODULE_CONFIG_SECTION **ppgConfig = NULL;

static TAP_OPERATIONAL_INFO tapServerInfo = {0};
//static TAPS_MODULE_MGR moduleMgr = {0};
static volatile intBoolean quitTime = FALSE;
static TAPS_CONNECTION_MGR connectionMgr = {0};

TCP_SOCKET tapListenSocket = -1;

typedef int (*platformParseCmdLineOpts)(tapsExecutionOptions *pOpts, int argc, char *argv[]);
static tapsExecutionOptions *pExecutionOpts = NULL;
#ifdef __RUN_TAPS_SERVICE__
static tapsServiceOpts *gpServiceOpts = NULL;
#endif

#ifdef __DISABLE_DIGICERT_TAP_CREDS_FILE__
extern MSTATUS TAPS_getModuleCredentials(TAP_ConfigInfoList *pConfigInfoList,
        int moduleId,
        TAP_PROVIDER providerType, TAP_EntityCredentialList **ppServerCredentialsList);
#endif

MSTATUS TAPS_dispatcher(TAPS_CONNECTION *pConnInfo, TAP_PROVIDER providerType, TAP_CmdReq *pCmdReq, TAP_CmdRsp *pCmdRsp, TAP_LocalContext *pLocalContext);

typedef MSTATUS (*TAPS_SMP_DISPATCHER_PTR)(TAP_RequestContext *, SMP_CmdReq *, SMP_CmdRsp *, TAP_ErrorAttributes *, TAP_ErrorAttributes **);


/* Populated in runtime */
static TAPS_SMP_DISPATCHER_PTR TAPS_dispatchCommand[TAP_PROVIDER_MAX+1] = { 0 };
static MSTATUS TAPS_processAcceptRequests();
MSTATUS TAPS_shutdown();

#if defined(__LINUX_RTOS__)
void sigpipeHandler(int sigCode)
{
    DB_PRINT("Got SIGPIPE signal, ignoring ...\n");
    return;
}
#endif

void TAPS_interruptToStop()
{
    if (0 <= tapListenSocket)
        TCP_CLOSE_SOCKET(tapListenSocket);

    quitTime = TRUE;
}

#if defined(__LINUX_RTOS__)
/* Terminate gracefully */
void sigHandler(int sigCode)
{
    printf("Got Signal %d, terminating ...\n", sigCode);
    TAPS_interruptToStop();
}
#endif

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to parse configuration file
 * @details Parses the TAP server configuration file to get
 * 		SSL configuration details as well as location of TAP modules
 *
 * @return OK on success
 *
 */
static MSTATUS
TAPS_parseServerConfiguration(const char *fullPath)
{
    MSTATUS status = OK;
    ubyte *pConfig = NULL;
    ubyte4 configLen;
    ubyte *pUnixServerPath = NULL;
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"serverport", 0, 0},
        {(const sbyte *)"enablemutualauthentication", 0, 0},
        {(const sbyte *)"enableunsecurecomms", 0, 0},
        {(const sbyte *)"sslcertificatefile", 0, 0},
        {(const sbyte *)"sslcertificatekeyfile", 0, 0},
        {(const sbyte *)"sslrootcertificatefile", 0, 0},
        {(const sbyte *)"module", 0, 0},
        {(const sbyte *)"sharedcontext", 0, 0},
        {(const sbyte *)"bindaddress", 0, 0},
#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
        {(const sbyte *)"servername", 0, 0},
#endif
        {NULL, 0, 0}
    };
    TAP_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(CONFIG_ConfigItem)];
    TAP_PARSE_PARMS *pParseParms;

    DB_PRINT("%s: Processing %s...\n", __FUNCTION__, fullPath);
    if (fullPath)
    {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK == (status = DIGICERT_readFileEx(fullPath, &pConfig, &configLen, FALSE)))
#else
        if (OK == (status = DIGICERT_readFile(fullPath, &pConfig, &configLen)))
#endif
        {
            if (tapServerInfo.pRootCerts)
            {
                TAP_CONF_COMMON_freeCertStore(&tapServerInfo);
            }
            tapServerInfo.pRootCerts = NULL;

            if (tapServerInfo.pModuleConfInfo)
            {
                TAP_CONF_COMMON_freeModuleConfigFileInfo(
                        &(tapServerInfo.pModuleConfInfo));
            }
            tapServerInfo.pModuleConfInfo = NULL;

            pParseParms = &parseParms[0];

            configItems[0].callback = TAP_CONF_COMMON_ParseIntValue;
            pParseParms->u.pIntValue = &(tapServerInfo.serverPort);
            pParseParms->name = (char *)configItems[0].key;
            configItems[0].callback_arg = pParseParms;

            pParseParms++;

            configItems[1].callback = TAP_CONF_COMMON_ParseIntValue;
            pParseParms->u.pIntValue = &(tapServerInfo.enableMutualAuth);
            pParseParms->name = (char *)configItems[1].key;
            configItems[1].callback_arg = pParseParms;

            pParseParms++;

            configItems[2].callback = TAP_CONF_COMMON_ParseIntValue;
            pParseParms->u.pIntValue = &(tapServerInfo.enableunsecurecomms);
            pParseParms->name = (char *)configItems[2].key;
            configItems[2].callback_arg = pParseParms;

            pParseParms++;

            configItems[3].callback = TAP_CONF_COMMON_ParseStrValue;
            pParseParms->u.ppStrValue = (ubyte **)&(tapServerInfo.certificateFileName);
            pParseParms->name = (char *)configItems[3].key;
            configItems[3].callback_arg = pParseParms;

            pParseParms++;

            configItems[4].callback = TAP_CONF_COMMON_ParseStrValue;
            pParseParms->u.ppStrValue = (ubyte **)&(tapServerInfo.certificateKeyFileName);
            pParseParms->name = (char *)configItems[4].key;
            configItems[4].callback_arg = pParseParms;

            pParseParms++;

            configItems[5].callback = TAP_CONF_COMMON_ParseRootCertificateFileLine;
            pParseParms->name = (char *)configItems[5].key;
            pParseParms->u.ppRootCerts = &(tapServerInfo.pRootCerts);
            configItems[5].callback_arg = pParseParms;

            pParseParms++;

            configItems[6].callback = TAP_CONF_COMMON_ParseModuleConfigFileLine;
            pParseParms->name = (char *)configItems[6].key;
            pParseParms->u.ppModuleConfigFileList = &(tapServerInfo.pModuleConfInfo);
            configItems[6].callback_arg = pParseParms;

            pParseParms++;

            configItems[7].callback = TAP_CONF_COMMON_ParseIntValue;
            pParseParms->name = (char *)configItems[7].key;
            pParseParms->u.pIntValue = &(tapServerInfo.isSharedContext);
            configItems[7].callback_arg = pParseParms;

            pParseParms++;

            configItems[8].callback = TAP_CONF_COMMON_ParseStrValue;
            pParseParms->name = (char *)configItems[8].key;
            pParseParms->u.ppStrValue = (ubyte **)&(tapServerInfo.pBindAddr);
            configItems[8].callback_arg = pParseParms;

#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
            pParseParms++;

            configItems[9].callback = TAP_CONF_COMMON_ParseStrValue;
            pParseParms->name = (char *)configItems[9].key;
            pParseParms->u.ppStrValue = &pUnixServerPath;
            configItems[9].callback_arg = pParseParms;
#endif

            status = CONFIG_parseData(pConfig, configLen, configItems);

            /* Override configuration file with command line options (if specified) */
            if(pExecutionOpts->serverPort)
                tapServerInfo.serverPort = pExecutionOpts->serverPort;
            else
                pExecutionOpts->serverPort = tapServerInfo.serverPort;

#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
            if (TAP_UNIX_DOMAIN_SOCKET == pExecutionOpts->serverPort)
            {
                /* Force flags for Unix Domain sockets */
                tapServerInfo.enableunsecurecomms = 1;
                tapServerInfo.enableMutualAuth = 0;

                if(!pExecutionOpts->unixServerPath[0])
                {
                    if (pUnixServerPath)
                    {
                        DIGI_STRCBCPY(pExecutionOpts->unixServerPath,
                                    sizeof(pExecutionOpts->unixServerPath), pUnixServerPath);
                    }
                    else
                        DIGI_STRCBCPY(pExecutionOpts->unixServerPath,
                            sizeof(pExecutionOpts->unixServerPath),
                                DEFAULT_UNIX_DOMAIN_PATH);
                }
            }

            if (pUnixServerPath)
                DIGI_FREE((void **)&pUnixServerPath);
#endif
            DIGICERT_freeReadFile(&pConfig);
        }
        else
        {
            /* Debug */
            status = ERR_FILE_OPEN_FAILED;
            LOG_ERROR("Error opening file %s, status %d\n", fullPath, (int)status);
        }
    }
    else
    {
        status = ERR_INVALID_ARG;
    }

    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to terminate the connection and remove this connection from the active connections list
 * @details Function to terminate the connection and remove this connection from the active connections list
 *     <p> This does the following:
 *        - Terminates the connection
 *        - Updates the connection list after removing the specified
 *          connection from the list, using connectionMgr mutex for
 *          serializing access. It does not free the connection memory or
 *          associated resources.
 *
 * @return OK on success
 *
 */
static MSTATUS
TAPS_CONNECTION_terminate(TAPS_CONNECTION *pConnection)
{
    MSTATUS status = OK;
    TAPS_CONNECTION *pPrevConnection = NULL;
    TAPS_CONNECTION *pCurrConnection = NULL;

    if (NULL == pConnection)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
#ifdef __ENABLE_SECURE_COMM__
    /* Clean up the connection */
    if (!tapServerInfo.enableunsecurecomms)
    {
        if (SOCKET_STATE_CONNECTED == pConnection->state)
            SSL_closeConnection(pConnection->sslConnectId);
    }
#endif

    if (SOCKET_STATE_CONNECTED == pConnection->state)
        TCP_CLOSE_SOCKET(pConnection->sockfd);

    /* Clean up the connection */
    pConnection->pTapModule = NULL;
    pConnection->state = SOCKET_STATE_TERMINATED;
    pConnection->localConnection = 0;

    /* Take connection mgr lock */
    if (OK != (status = RTOS_mutexWait(connectionMgr.mutex)))
    {
        goto exit;
    }

    /* Remove this connection from active connections list */
    pCurrConnection = connectionMgr.pFirstActiveConnection;

    while (pCurrConnection)
    {
        if (pConnection == pCurrConnection)
        {
            /* Found it, remove from the Active list */
            if (pPrevConnection)
            {
                pPrevConnection->pNext = pConnection->pNext;
            }
            else
            {
                /* First, update the head */
                connectionMgr.pFirstActiveConnection = pConnection->pNext;
            }

            break;
        }

        pPrevConnection = pCurrConnection;

        pCurrConnection = pCurrConnection->pNext;
    }

    /* Release connection mgr lock */
    if (OK != (status = RTOS_mutexRelease(connectionMgr.mutex)))
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS
TAPS_CONNECTION_localHost(MOC_IP_ADDRESS_S destIp)
{
    return OK;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to add a new connection to the active connections list
 * @details Function to add a new connection to the active connections list
 *     <p> This does the following:
 *        - Updates the Active connection list using the connectionMgr mutex for
 *          serializing access.
 *      <p> Called by the connection thread to add the connection object
 *          to the Active list maintained by the connection manager.
 *
 * @return OK on success
 *
 */
static MSTATUS
TAPS_CONNECTION_addToActiveList(TAPS_CONNECTION *pConnection)
{
    MSTATUS status = OK;
    ubyte2 destPort;
    MOC_IP_ADDRESS_S destIp;

    if (NULL == pConnection)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Take connection mgr lock */
    if (OK != (status = RTOS_mutexWait(connectionMgr.mutex)))
    {
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE_UNIX_DOMAIN__
    pConnection->localConnection = 1;
#else
    if (OK != TCP_getPeerName(pConnection->sockfd, &destPort, &destIp))
    {
        /* Debug */
        pConnection->localConnection = 1;
    }
    else
    {
        if (OK == TAPS_CONNECTION_localHost(destIp))
            pConnection->localConnection = 1;
    }
#endif

    /* Add to Top the of Active list */
    pConnection->pNext = connectionMgr.pFirstActiveConnection;
    connectionMgr.pFirstActiveConnection = pConnection;

    /* Release connection mgr lock */
    if (OK != (status = RTOS_mutexRelease(connectionMgr.mutex)))
    {
        goto exit;
    }

exit:
    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to uninitialize connection thread manager
 * @details Function to uninitialize connection thread manager
 *     <p> This does the following:
 *        -  Frees mutex used to serialize access to connection list
 *        -  resets the connection head
 *
 * @return OK on success
 *
 */
static
MSTATUS TAPS_uninitConnectionManager()
{
    MSTATUS status = OK;
    TAPS_CONNECTION *pConnection = NULL;
    TAPS_CONNECTION *pNextConnection = NULL;
    ubyte4 pendingThreads = 0;

    if (connectionMgr.pFirstActiveConnection)
    {
        if (OK != (status = RTOS_mutexWait(connectionMgr.mutex)))
        {
            goto exit;
        }

        /* Mark connections to be terminated */
        for (pConnection = connectionMgr.pFirstActiveConnection; pConnection;)
        {
            pConnection->quitTime = 1;

            /* Force receive error by closing the client connection */
            TCP_CLOSE_SOCKET(pConnection->sockfd);

            pNextConnection = pConnection->pNext;

            pConnection = pNextConnection;
        }

        if (OK != (status = RTOS_mutexRelease(connectionMgr.mutex)))
        {
            goto exit;
        }

        /* Give the threads chance to clean up */
        RTOS_sleepMS(MOCANA_TAP_THREAD_TIMEOUT);

        if (OK != (status = RTOS_mutexWait(connectionMgr.mutex)))
        {
            goto exit;
        }

        pendingThreads = 0;
        for (pConnection = connectionMgr.pFirstActiveConnection; pConnection;)
        {
            pNextConnection = pConnection->pNext;

            /* Mark pending connections */
            if (SOCKET_STATE_TERMINATED != pConnection->state)
            {
                pendingThreads++;
            }

            pConnection = pNextConnection;
        }

        if (OK != (status = RTOS_mutexRelease(connectionMgr.mutex)))
        {
            goto exit;
        }

        /* Wait for pending threads to terminate */
        /* TODO ... should have a forced termination option */
        while (pendingThreads)
        {
            if (OK != (status = RTOS_mutexWait(connectionMgr.mutex)))
            {
                goto exit;
            }

            pendingThreads = 0;

            for (pConnection = connectionMgr.pFirstActiveConnection; pConnection;)
            {
                pNextConnection = pConnection->pNext;

                if (SOCKET_STATE_TERMINATED != pConnection->state)
                {
                    pendingThreads++;
                }

                pConnection = pNextConnection;
            }

            if (OK != (status = RTOS_mutexRelease(connectionMgr.mutex)))
            {
                goto exit;
            }

            if (pendingThreads)
            {
                /* Give the threads chance to clean up */
                RTOS_sleepMS(MOCANA_TAP_THREAD_TIMEOUT);
            }
        }
    }

    if (connectionMgr.mutex)
    {
        /* Free mutex used to serialize access to the connection list */
        if (OK != (status = RTOS_mutexFree(&connectionMgr.mutex)))
        {
            goto exit;
        }
    }

    DIGI_MEMSET((void *)&connectionMgr, 0, sizeof(connectionMgr));

exit:
    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to initialize connection thread manager
 * @details Function to initialize connection thread manager
 *     <p> This does the following:
 *        -  Initializes mutex used to serialize access to connection list
 *        -  Initializes the connection head
 *
 * @return OK on success
 *
 */
static MSTATUS
TAPS_initConnectionManager()
{
    MSTATUS status = OK;

    TAP_DEBUG_PRINT_1("Initializing Connection...");
    /* Allocate mutex to serialize access to the connection list */
    if (OK != (status = RTOS_mutexCreate(&connectionMgr.mutex, 0, 0)))
    {
        goto exit;
    }

    /* Initialized connection list head */
    connectionMgr.pFirstActiveConnection = NULL;

exit:
    if (OK != status)
        TAPS_uninitConnectionManager();

    return status;
}


MSTATUS
TAPS_ParseIntValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAPS_PARSE_PARMS *pParseParms = (TAPS_PARSE_PARMS *)arg;
    char *valString;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }
    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    status = DIGI_MALLOC((void **)&valString, sLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for integer value\n",__FUNCTION__, __LINE__, sLen);
    }
    else
    {
        DIGI_MEMCPY(valString, line+offset, sLen-1);
        valString[sLen-1] = 0;
        pModuleConfigSection = (TAPS_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        pModuleConfigSection->moduleId = DIGI_ATOL((const sbyte *)valString, NULL);

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
        DIGI_FREE((void **)&valString);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_TPM__
/* For TPM12, credential file path is absolute filepath, not relative to config directory */
MSTATUS
TAPS_ParseTpm12CredentialPath(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAPS_PARSE_PARMS *pParseParms = (TAPS_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;
    byteBoolean isCredPathRelative = FALSE;
    ubyte4 pathLen = 0;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    pModuleConfigSection = (TAPS_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

    /* Check if its a relative path */
    pathLen = DIGI_STRLEN((const sbyte *)pExecutionOpts->confDirPath);
    status = TAP_UTILS_isPathRelative(line+offset, sLen-1, &isCredPathRelative);
    if (OK == status && TRUE == isCredPathRelative && 0 < pathLen)
    {
        status = DIGI_MALLOC((void **)&pValString, sLen + pathLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error allocating %d bytes for string value\n",__FUNCTION__, __LINE__, sLen);
            goto exit;
        }
        DIGI_MEMCPY(pValString, pExecutionOpts->confDirPath, pathLen);
        DIGI_MEMCPY(&pValString[pathLen], line+offset, sLen-1);
        pValString[pathLen + sLen - 1] = 0;
        pModuleConfigSection->credentialsFile.pBuffer = (ubyte *)pValString;
        pModuleConfigSection->credentialsFile.bufferLen = pathLen + sLen - 1;
    }
    else
    {
        status = DIGI_MALLOC((void **)&pValString, sLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d: Error allocating %d bytes for string value\n",__FUNCTION__, __LINE__, sLen);
            goto exit;
        }
        DIGI_MEMCPY(pValString, line+offset, sLen-1);
        pValString[sLen - 1] = 0;
        pModuleConfigSection->credentialsFile.pBuffer = (ubyte *)pValString;
        pModuleConfigSection->credentialsFile.bufferLen = sLen;
    }

    /* Tell the parser we've eaten the rest of the line */
    *bytesUsed = CONFIG_nextLine(line, bytesLeft);

exit:
    return status;
}
#endif /*__ENABLE_DIGICERT_TPM__*/


MSTATUS
TAPS_ParseStrValue(ubyte* line, ubyte4 bytesLeft, void* arg, ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0, i, sLen;
    TAPS_PARSE_PARMS *pParseParms = (TAPS_PARSE_PARMS *)arg;
    ubyte *pValString = NULL;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;
    ubyte4 pathLen = 0;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoValue(line, bytesLeft, (const sbyte *)pParseParms->name, '=', &offset)))
    {
        DB_PRINT("%s.%d: Error %d while parsing value for key - %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }

    /* value is a number */
    for ( i = offset;
            i < bytesLeft && line[i] != '\n' && line[i] != '\r';
            ++i)
    {
    }

    /* go back and look for space */
    for ( --i; i >= offset && DIGI_ISSPACE(line[i]); --i)
    {
    }

    sLen =  i + 2 - offset;
    pathLen = DIGI_STRLEN((const sbyte *)pExecutionOpts->confDirPath);
    status = DIGI_MALLOC((void **)&pValString, sLen + pathLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for string value\n",__FUNCTION__, __LINE__, sLen);
    }
    else
    {
        DIGI_MEMCPY(pValString, pExecutionOpts->confDirPath, pathLen);
        DIGI_MEMCPY(&pValString[pathLen], line+offset, sLen-1);
        pValString[pathLen + sLen - 1] = 0;
        pModuleConfigSection = (TAPS_MODULE_CONFIG_SECTION *)*(pParseParms->ppModuleConfigSection);

        pModuleConfigSection->credentialsFile.pBuffer = (ubyte *)pValString;
        pModuleConfigSection->credentialsFile.bufferLen = sLen;

        /* Tell the parser we've eaten the rest of the line */
        *bytesUsed = CONFIG_nextLine(line, bytesLeft);
    }

    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to parse module section
 * @details Function to populate module section and create moduleCredential structure
 *     <p> This does the following:
 *        -  Parses the [module] section
 *        -  Create a moduleCredential structure and chains it
 *        -  Populates the moduleId and credentialfile fields
 *
 * @return OK on success
 *
 */
MSTATUS
TAPS_ParseModuleConfigSection(ubyte* line, ubyte4 bytesLeft, void* arg,
    ubyte4* bytesUsed)
{
    MSTATUS status;
    ubyte4  offset = 0;
    TAPS_PARSE_PARMS *pParseParms = (TAPS_PARSE_PARMS *)arg;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (NULL == pParseParms)
    {
        DB_PRINT("%s.%d: Invalid argument\n", __FUNCTION__, __LINE__);
        return ERR_INVALID_ARG;
    }

    if (OK != (status = CONFIG_gotoSection(line, bytesLeft,
                    (const sbyte *)pParseParms->name, &offset)))
    {
        DB_PRINT("%s.%d: Error %d while seeking section %s\n", __FUNCTION__, __LINE__, status, pParseParms->name);
        return status;
    }

    /* Allocate Module Config Section */
    if (OK != (status = DIGI_MALLOC((void **)&pModuleConfigSection,
                    sizeof(*pModuleConfigSection))))
    {
        DB_PRINT("%s.%d: Error allocating %d bytes for ModuleconfigSection\n",__FUNCTION__, __LINE__, sizeof(*pModuleConfigSection));
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pModuleConfigSection, 0,
            sizeof(*pModuleConfigSection));

    /* Add new config file name node to top of the list */
    pModuleConfigSection->pNext = *(pParseParms->ppModuleConfigSection);
    *(pParseParms->ppModuleConfigSection) = pModuleConfigSection;

    /* Tell the parser we've eaten the rest of the line */
    *bytesUsed = CONFIG_nextLine(line, bytesLeft);
exit:

    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to populate the module ID and associated credential file list upon startup
 * @details Function to populate moduleCredential structure comprising of module ID and credential file
 *     <p> This does the following:
 *        -  Parses all the [module] sections in the file
 *        -  Create a moduleCredential structure linked list
 *
 * @return OK on success
 *
 */
MSTATUS TAPS_parseModuleConfiguration(TAP_ConfigInfo *pConfigInfo,
        TAPS_MODULE_CONFIG_SECTION **ppgConfig)
{
    MSTATUS status = OK;
    TAP_Buffer *pConfigBuffer = NULL;
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"[module]", 0, 0},
        {(const sbyte *)"credfile", 0, 0},
        {(const sbyte *)"modulenum", 0, 0},
        {(const sbyte *)NULL, 0, 0}
    };
    TAPS_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(CONFIG_ConfigItem)];
    TAPS_PARSE_PARMS *pParseParms;
    ubyte *pConfig = NULL;
    ubyte4 configLen = 0;

    if (NULL == pConfigInfo)
    {
        status = ERR_NULL_POINTER;
        LOG_ERROR("NULL pointer on input, Input pointer = %p,",
                pConfigInfo);
        goto exit;
    }

    pConfigBuffer = &(pConfigInfo->configInfo);
    if ((0 == pConfigBuffer->bufferLen)
       || (NULL == pConfigBuffer->pBuffer))
    {
        status = ERR_NULL_POINTER;
        LOG_ERROR("Invalid input, Buffer Len = %d, Configuration buffer = %p\n",
                pConfigBuffer->bufferLen, pConfigBuffer->pBuffer);
        goto exit;
    }

    pConfig = pConfigBuffer->pBuffer;
    configLen = pConfigBuffer->bufferLen;

    pParseParms = &parseParms[0];

    configItems[0].callback = TAPS_ParseModuleConfigSection;
    pParseParms->name = (char *)configItems[0].key;
    pParseParms->ppModuleConfigSection = ppgConfig;
    configItems[0].callback_arg = pParseParms;

    pParseParms++;

    pParseParms->name = (char *)configItems[1].key;
    pParseParms->ppModuleConfigSection = ppgConfig;
    configItems[1].callback_arg = pParseParms;
    switch(pConfigInfo->provider)
    {
#ifdef __ENABLE_DIGICERT_TPM__
        case TAP_PROVIDER_TPM:
            configItems[1].callback = TAPS_ParseTpm12CredentialPath;
            break;
#endif
        case TAP_PROVIDER_TPM2:
        default:
            configItems[1].callback = TAPS_ParseStrValue;
            break;
    }

    pParseParms++;

    configItems[2].callback = TAPS_ParseIntValue;
    pParseParms->name = (char *)configItems[2].key;
    pParseParms->ppModuleConfigSection = ppgConfig;
    configItems[2].callback_arg = pParseParms;

    status = CONFIG_parseData(pConfig, configLen, configItems);

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_EXTENDED_CRED_VALIDATION__

static MSTATUS TAPS_createCertStoreFromDir(sbyte *pPath, certStorePtr *ppStore)
{
    MSTATUS status;
    DirectoryDescriptor dir = NULL;
    DirectoryEntry ent;
    byteBoolean isCertEntryValid = FALSE;
    byteBoolean isFileEntryTypeDir = FALSE;
    char *dirEntryName = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    char *pFullPath = NULL, *pIndex;
    ubyte valid = 0;
    ubyte4 verify = 0;
    intBoolean foundCert;
    certStorePtr pNewStore = NULL;

    status = FMGMT_getFirstFile (pPath, &dir, &ent);
    if (OK != status)
    {
        LOG_ERROR("Error reading directory %s, status=%d\n",
                                    pPath,
                                    status);
        goto exit;
    }

    status = CERT_STORE_createStore(&pNewStore);
    if (OK != status)
    {
        goto exit;
    }

    while (FTNone != ent.type)
    {
        if (FTFile == ent.type)
        {
            DIGI_FREE((void **) &pFullPath);

            status = DIGI_MALLOC(
                (void **) &pFullPath,
                DIGI_STRLEN(pPath) + 1 + ent.nameLength + 1);
            if (OK != status)
            {
                goto exit;
            }
            pIndex = pFullPath;

            DIGI_MEMCPY(pIndex, pPath, DIGI_STRLEN(pPath));
            pIndex += DIGI_STRLEN(pPath);

            *pIndex = '/';
            pIndex++;

            DIGI_MEMCPY(pIndex, ent.pName, ent.nameLength);
            pIndex += ent.nameLength;

            *pIndex = '\0';

            status = DIGICERT_readFile(pFullPath, &pCert, &certLen);
            if (OK != status)
            {
                LOG_ERROR("Error reading certificate file %s, status=%d\n",
                                    pFullPath,
                                    status);
                goto exit;
            }

            foundCert = FALSE;

            if ( (ent.nameLength > 4) &&
                 (0 == DIGI_STRNICMP (ent.pName + ent.nameLength - 4, ".pem", 4)) )
            {
                ubyte *pDerCert = NULL;
                ubyte4 derCertLen;

                status = CA_MGMT_decodeCertificate(
                    pCert, certLen, &pDerCert, &derCertLen);
                if (OK != status)
                {
                    goto exit;
                }

                DIGI_FREE((void **) &pCert);
                pCert = pDerCert;
                certLen = derCertLen;

                foundCert = TRUE;
            }

            if ( (ent.nameLength > 4) &&
                 (0 == DIGI_STRNICMP (ent.pName + ent.nameLength - 4, ".der", 4)) )
            {
                foundCert = TRUE;
            }

            if (TRUE == foundCert)
            {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                status = DPM_verifyFile(
                    pFullPath, TRUE, DPM_CA_CERTS);
                if (OK != status)
                {
                    LOG_ERROR("Error verifying certificate file %s, status=%d\n",
                                    pFullPath,
                                    status);
                    goto exit;
                }
#endif

                status = CERT_STORE_addTrustPoint(pNewStore, pCert, certLen);
                if (OK != status)
                {
                    goto exit;
                }
            }
        }

        status = FMGMT_getNextFile (dir, &ent);
        if (OK != status)
            goto exit;
    }

    *ppStore = pNewStore;
    pNewStore = NULL;

exit:
    if (NULL != dir)
        FMGMT_closeDir (&dir);

    if (NULL != pNewStore)
    {
        CERT_STORE_releaseStore(&pNewStore);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **)&pFullPath);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }

    return status;
}

static MSTATUS TAPS_verifyFileSig(sbyte *pFile)
{
    MSTATUS status;
    sbyte *pTrustStorePath = NULL;
    certStorePtr pCertStore = NULL;
    ubyte4 vfyStatus = 1;
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    byteBoolean verifyConfig;
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DPM_checkStatus(DPM_CONFIG, &verifyConfig);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == verifyConfig)
    {
        status = CRYPTO_UTILS_readTrustedPathsNoVerify(NULL, NULL, &pTrustStorePath, NULL);
    }
    else
#endif
    {
        status = CRYPTO_UTILS_readTrustedPaths(NULL, NULL, &pTrustStorePath, NULL);
    }
    if (OK != status)
    {
        goto exit;
    }

    status = TAPS_createCertStoreFromDir(pTrustStorePath, &pCertStore);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJsonMultiSigByFileExt(
        pFile, pCertStore, &vfyStatus);
    if (OK != status)
    {
        LOG_ERROR("Error verifying signatures %s, status=%d\n",
                                    pFile,
                                    status);
        goto exit;
    }

    if (0 != vfyStatus)
    {
        status = ERR_CRYPTO_UTIL_JSON_VERIFY_FAILURE;
        LOG_ERROR("Error verifying signatures, status %d = %s",
                (int)status, MERROR_lookUpErrorCode(status));
    }

exit:

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }


    if (NULL != pTrustStorePath)
    {
        DIGI_FREE((void **) &pTrustStorePath);
    }

    return status;
}
#endif

MSTATUS TAPS_loadModuleCredentials()
{
    MSTATUS status = OK;
    ubyte4 providerIndex = 0;
    ubyte *pFileBuffer = NULL;
    ubyte4 fileBufferLen = 0;
    ubyte *pRawBuffer = NULL;
    ubyte4 rawBufferLen = 0;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if (ppgConfig)
    {
        /* Iterate through all the providers */
        while (providerIndex < configInfoList.count)
        {
            if (NULL != (pModuleConfigSection = ppgConfig[providerIndex]))
            {
                /* Collect credentials of all modules of this provider type */
                while (pModuleConfigSection)
                {
                    if (pModuleConfigSection->credentialsFile.bufferLen)
                    {
#ifdef __ENABLE_DIGICERT_EXTENDED_CRED_VALIDATION__
                        status = TAPS_verifyFileSig(
                            pModuleConfigSection->credentialsFile.pBuffer);
                        if (OK != status)
                        {
                            LOG_ERROR("Error verifying credentials file %s, status=%d\n",
                                    pModuleConfigSection->credentialsFile.pBuffer,
                                    status);
                            goto exit;
                        }
#endif

                        /* Read file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                        status = DIGICERT_readFileEx(
                                (const char *)pModuleConfigSection->credentialsFile.pBuffer,
                                &pRawBuffer, &rawBufferLen, FALSE);
#else
                        status = DIGICERT_readFile(
                                (const char *)pModuleConfigSection->credentialsFile.pBuffer,
                                &pRawBuffer, &rawBufferLen);
#endif
                        if (OK != status)
                        {
                            LOG_ERROR("Error reading credentials file %s, status=%d\n",
                                    pModuleConfigSection->credentialsFile.pBuffer,
                                    status);
                            goto exit;
                        }
                        /* Decode */
                        status = BASE64_decodeMessage(pRawBuffer, rawBufferLen,
                                &pFileBuffer, &fileBufferLen);
                        if (OK != status)
                        {
                            LOG_ERROR("Error decoding credentials file %s, status %d = %s\n",
                                    pModuleConfigSection->credentialsFile.pBuffer,
                                    (int)status, MERROR_lookUpErrorCode(status));
                            goto exit;
                        }

                        /* Parse Credentials */
                        status = MocTap_GetCredentialData((sbyte *)pFileBuffer,
                                fileBufferLen,
                                &pModuleConfigSection->pServerCredentialsList);
                        if (OK != status)
                        {
                            LOG_ERROR("Error parsing credentials file %s, status %d = %s\n",
                                    pModuleConfigSection->credentialsFile.pBuffer,
                                    (int)status, MERROR_lookUpErrorCode(status));
                            goto exit;
                        }

                        DB_PRINT("Processed credentials file %s \n",
                                pModuleConfigSection->credentialsFile.pBuffer);
                        if (pRawBuffer)
                            DIGI_FREE((void **)&pRawBuffer);

                        /* Free file buffer */
                        DIGICERT_freeReadFile(&pFileBuffer);

                        pFileBuffer = NULL;
                    }

                    pModuleConfigSection = pModuleConfigSection->pNext;
                }
            }

            providerIndex++;
        }
    }
exit:

    if (pRawBuffer)
        DIGI_FREE((void **)&pRawBuffer);

    if (pFileBuffer)
        DIGICERT_freeReadFile(&pFileBuffer);

    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief  Function to populate the module list upon startup
 * @details Function to perform startup tasks
 *     <p> This does the following:
 *        -  populate the module list from configuration file
 *        -  Create a module context each available module type
 *        -  The Main function listens and spawns a thread for each connection request
 *
 * @return OK on success
 *
 */
MSTATUS TAPS_startup()
{
    MSTATUS status = OK;
    TAP_MODULE_CONFIG_FILE_INFO *pModuleConfInfo = NULL;
    TAP_MODULE_CONFIG_FILE_INFO *pModuleConfInfoNext = NULL;
    /*TAP_ConfigInfo *pCurrConfigInfo = NULL;*/
    ubyte *pConfig = NULL;
    ubyte4 configLen = 0;
    ubyte4 configInfoListIndex = 0;
    static CONFIG_ConfigItem configItems[] = {
        {(const sbyte *)"providerType", 0, 0},
        {(const sbyte *)NULL, 0, 0}
    };
    TAP_PARSE_PARMS parseParms[sizeof(configItems)/sizeof(CONFIG_ConfigItem)] = {0};
    TAP_PARSE_PARMS *pParseParms = NULL;
    ubyte4 providerType = 0;
    ubyte *pFullPath = NULL;
    ubyte4 pathLen = 0;
    char *pTapServerConfigFile = NULL;
    char *pTapServerConfigDir = NULL;

    TAP_DEBUG_PRINT_1("BEGINS");
    /* Parse configuration file for connection mode
     * and available provider types
     */
    if(pExecutionOpts->isConfFileSpecified)
    {
        status = TAPS_parseServerConfiguration(pExecutionOpts->confFilePath) ;
    }
    else
    {
#ifdef __RTOS_WIN32__
        status = TAP_UTILS_getWinConfigFilePath(&pTapServerConfigFile, TAP_SERVER_CONFIG_FILE);
        if (OK != status)
        {
            goto exit;
        }
#else
        pTapServerConfigFile = TAP_SERVER_CONFIG_FILE;
#endif
        status = TAPS_parseServerConfiguration(pTapServerConfigFile) ;
    }
    if (OK != status )
    {
        LOG_ERROR("Error parsing server configuration file, status %d = %s",
                (int)status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == tapServerInfo.pModuleConfInfo)
    {
        status = ERR_INVALID_ARG;
        LOG_ERROR("Error missing \"module\" name value pair in configuration");
        goto exit;
    }

#ifdef __ENABLE_SECURE_COMM__
    if (!tapServerInfo.enableunsecurecomms)
    {
        if (0 != (status = SSL_init(MAX_SSL_SERVER_CONNECTIONS, 0)))
        {
            LOG_ERROR("Error initializing SSL stack, status %d = %s\n",
                    (int)status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
#endif

    pModuleConfInfo = tapServerInfo.pModuleConfInfo;
    while (pModuleConfInfo)
    {
        configInfoListIndex++;
        pModuleConfInfo = pModuleConfInfo->pNext;
    }

    /* Allocate memory for global configuration pointers */
    status = DIGI_CALLOC((void **)&ppgConfig, 1,
            configInfoListIndex * sizeof(*ppgConfig));
    if (OK != status)
    {
        LOG_ERROR("Error allocating memory for provider list, status %d = %s",
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Allocate memory for the configInfoList to support each provider */
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1,
            configInfoListIndex * sizeof(*configInfoList.pConfig));
    if (OK != status)
    {
        LOG_ERROR("Error allocating memory for provider configuration, status %d = %s",
                        status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    configInfoList.count = configInfoListIndex;

    /* Build the TAP_ConfigInfoList */
    TAP_DEBUG_PRINT("Building config file list for %d module(s) ...",
                    configInfoList.count);

    /* Organize module file name lists based on providerType */
    configInfoListIndex = 0;
    pModuleConfInfo = tapServerInfo.pModuleConfInfo;
    while (pModuleConfInfo)
    {
        pModuleConfInfoNext = pModuleConfInfo->pNext;
        if(pExecutionOpts->isConfDirSpecified)
        {
            pathLen = DIGI_STRLEN((const sbyte *)pExecutionOpts->confDirPath);
        }
        else
        {
#ifdef __RTOS_WIN32__
            status = TAP_UTILS_getWinConfigDir(&pTapServerConfigDir, TAP_CONF_FILE_DIR);
            if (OK != status)
            {
                goto exit;
            }
#else
            pTapServerConfigDir = TAP_CONF_FILE_DIR;
#endif
            pathLen = DIGI_STRLEN((const sbyte *)pTapServerConfigDir);
        }

        status = DIGI_CALLOC((void **)&pFullPath, 1, pModuleConfInfo->name.bufferLen + pathLen + 1);
        if (OK != status)
        {
            goto exit;
        }
        DIGI_MEMSET((ubyte *)pFullPath, 0, pModuleConfInfo->name.bufferLen + pathLen + 1);

        if(pExecutionOpts->isConfDirSpecified)
        {
            DIGI_MEMCPY(pFullPath, pExecutionOpts->confDirPath, pathLen);
        }
        else
        {
            DIGI_MEMCPY(pFullPath, pTapServerConfigDir, pathLen);
        }

        /* Save this path in confDirPath */
        if (sizeof(pExecutionOpts->confDirPath) > pathLen)
        {
            DIGI_MEMCPY(pExecutionOpts->confDirPath, pFullPath, pathLen);
            pExecutionOpts->confDirPath[pathLen] = 0;
        }

        DIGI_MEMCPY((pFullPath + pathLen), pModuleConfInfo->name.pBuffer,
                    pModuleConfInfo->name.bufferLen);

        /* Replace the filename with full file path */
        DIGI_FREE((void **)&pModuleConfInfo->name.pBuffer);

        pModuleConfInfo->name.pBuffer = pFullPath;
        pModuleConfInfo->name.bufferLen += pathLen + 1;

        TAP_DEBUG_PRINT("Reading module file %s ...", pFullPath);
        status = DIGICERT_readFile((const char *)pFullPath, &pConfig, &configLen);
        if (OK == status)
        {
       /*     status = DIGI_CALLOC((void **)&(pCurrConfigInfo), 1, sizeof(TAP_ConfigInfo));*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__) && defined(__ENABLE_DIGICERT_EXTENDED_CRED_VALIDATION__)
            status = DPM_verifyFile(pFullPath, TRUE, DPM_CONFIG);
            if (OK != status)
            {
                LOG_ERROR("Error allocating memory for provider configuration, status %d = %s",
                        status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
#endif

            pParseParms = &parseParms[0];
            providerType = 0;
            configItems[0].callback = TAP_CONF_COMMON_ParseIntValue;
            pParseParms->u.pIntValue = &providerType;
            pParseParms->name = (char *)configItems[0].key;
            configItems[0].callback_arg = pParseParms;

            status = CONFIG_parseData(pConfig, configLen, configItems);

            TAP_DEBUG_PRINT("completed processing %s ...", pFullPath);

            /* Ignore invalid provider types */
            if (TAP_PROVIDER_MAX < providerType)
            {
                DIGICERT_freeReadFile(&pConfig);
                continue;
            }

            /* Copy the entire file buffer to the provider's config */
            configInfoList.pConfig[configInfoListIndex].provider = providerType;
            configInfoList.pConfig[configInfoListIndex].configInfo.bufferLen = configLen;
            configInfoList.pConfig[configInfoListIndex].configInfo.pBuffer = pConfig;
            configInfoList.pConfig[configInfoListIndex].useSharedHandle =
                            (0 == tapServerInfo.isSharedContext) ? FALSE : TRUE;

            /* Get the credentials per module */
            TAPS_parseModuleConfiguration(&configInfoList.pConfig[configInfoListIndex],
                    &ppgConfig[configInfoListIndex]);
        }

        pModuleConfInfo = pModuleConfInfoNext;
        configInfoListIndex++;
    }

    /* Load credentials */
    status = TAPS_loadModuleCredentials();
    if (OK != status)
    {
        LOG_ERROR("Failed to load module credentials, status %d = %s",
                        status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    TAP_DEBUG_PRINT_1("Module credentials loaded successfully");
    /* Get the list of providers available on the server */
    status = TAP_COMMON_registerLocalProviders(&configInfoList, &localProviderList);
    if (OK != status)
    {
        LOG_ERROR("Failed to register Local provider, status %d = %s",
                        status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    TAP_DEBUG_PRINT_1("Local providers registered successfully");

    if (!tapServerInfo.enableunsecurecomms)
    {
        TAP_DEBUG_PRINT_1("TAPS initialzing secure communication configurations...");
        /* Setup SSL certificate store and load Root CA certificates */
        if (OK != (status = TAP_CONF_COMMON_setCertStore(&tapServerInfo)))
        {
            LOG_ERROR("Failed to set certificate store, status %d = %s",
                     status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Load server certificate */
        status = TAP_CONF_COMMON_loadCertificateAndKey(tapServerInfo.certificateFileName,
                tapServerInfo.certificateKeyFileName,
                tapServerInfo.pSslCertStore);
        if (OK != status)
        {
            LOG_ERROR("Failed to load server certificate and key, status %d = %s",
                     status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Initialize connection manager */
    if (OK != (status = TAPS_initConnectionManager()))
    {
        LOG_ERROR("Failed to initialize connection, status %d = %s",
                 status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    TAP_DEBUG_PRINT_1("Connection Initialized");
exit:
#ifdef __RTOS_WIN32__
    if ((NULL != pTapServerConfigFile)
        && (FALSE == pExecutionOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTapServerConfigFile);
    }
    if ((FALSE == pExecutionOpts->isConfDirSpecified)
        && (NULL != pTapServerConfigDir)
        )
    {
        DIGI_FREE(&pTapServerConfigDir);
    }
#endif /*__RTOS_WIN32__*/
    TAP_DEBUG_PRINT("ENDS with status = %ld", status);
    return status;
}

/**
 * @private
 * @internal
 *
 * @ingroup taps_functions
 *
 * @brief Function to clean up resources on shutdown.
 * @details Function to clean up resources on shutdown.
 *     <p> This does the following:
 *        -  kill any open SSL and TCP connections (after giving a chance to complete commands first)
 *        -  free any memory allocated for the module list
 *        -  free any global memory
 *
 * @return OK on success
 */
MSTATUS TAPS_shutdown()
{
    MSTATUS status = OK;
    MSTATUS tmpStatus;
    int i = 0;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    /* Terminate connection threads */
    status = TAPS_uninitConnectionManager();

    status = TAP_COMMON_unregisterLocalProviders(&localProviderList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to unregister local providers and free the local provider list, status %d = %s\n",
                 __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    /* Free configInfoList */
    for (i = 0; i < configInfoList.count; i++)
    {
        if (NULL != configInfoList.pConfig[i].configInfo.pBuffer)
            DIGICERT_freeReadFile(&(configInfoList.pConfig[i].configInfo.pBuffer));
        configInfoList.pConfig[i].configInfo.bufferLen = 0;

        if (NULL != (pModuleConfigSection = ppgConfig[i]))
        {
            /* Collect credentials of all modules of this provider type */
            while (pModuleConfigSection)
            {
                if (pModuleConfigSection->credentialsFile.pBuffer)
                    DIGI_FREE((void **)&pModuleConfigSection->credentialsFile.pBuffer);

                if (pModuleConfigSection->pServerCredentialsList)
                {
                    TAP_UTILS_clearEntityCredentialList(
                            pModuleConfigSection->pServerCredentialsList);
                    DIGI_FREE((void **)&pModuleConfigSection->pServerCredentialsList);
                }

                pModuleConfigSection = pModuleConfigSection->pNext;
            }
            DIGI_FREE((void **) &ppgConfig[i]);
        }
    }
    DIGI_FREE((void **)&ppgConfig) ;

    DIGI_FREE((void **)&configInfoList.pConfig);

    /* Cleanup Module File name nodes */
    if(tapServerInfo.pModuleConfInfo)
    {
        if (OK != (tmpStatus = TAP_CONF_COMMON_freeModuleConfigFileInfo(
                        &tapServerInfo.pModuleConfInfo)))
        {
            DB_PRINT("Error %d freeing module config file nodes\n", (int)tmpStatus);
        }
    }
#ifdef __ENABLE_SECURE_COMM__
    if (!tapServerInfo.enableunsecurecomms)
    {
        /* Cleanup SSL certificates */
        if (OK != (tmpStatus = TAP_CONF_COMMON_freeCertStore(&tapServerInfo)))
        {
            DB_PRINT("Error %d freeing certificate store\n", (int)tmpStatus);
        }

        /* Clean up SSL stack */
        SSL_releaseTables();
        SSL_shutdownStack();
    }
#endif
    quitTime = FALSE;
    TAP_CONF_COMMON_freeCertFilenameBuffers(&tapServerInfo);

    return status;
}

static MSTATUS
TAPS_CONNECTION_negotiate(TAPS_CONNECTION *pConnection)
{
    MSTATUS status = OK;
#ifdef __ENABLE_SECURE_COMM__
    ubyte4 sessionFlags = 0;
#endif

    if (NULL == pConnection)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __ENABLE_SECURE_COMM__
    if (!tapServerInfo.enableunsecurecomms)
    {
        /* Negotiate SSL operating parameters */
        if (0 > (pConnection->sslConnectId =
                    SSL_acceptConnection(pConnection->sockfd, tapServerInfo.pSslCertStore)))
        {
            TCP_CLOSE_SOCKET(pConnection->sockfd);
            pConnection->state = SOCKET_STATE_FREE;
            status = ERR_SSL_INIT_CONNECTION;

            goto exit;
        }

        if (!tapServerInfo.enableMutualAuth)
        {
            if (OK == (status = SSL_getSessionFlags(pConnection->sslConnectId, &sessionFlags)))
            {
                sessionFlags &= ~SSL_FLAG_REQUIRE_MUTUAL_AUTH;
                sessionFlags |= SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;

                if (OK != (status = SSL_setSessionFlags(pConnection->sslConnectId, sessionFlags)))
                {
                    LOG_ERROR("Error %d disabling Mutual Authentication on this SSL connection\n", (int)status);
                }
            }
            else
            {
                LOG_ERROR("Error %d getting session flags\n", (int)status);
            }
        }

        if (OK != (status = SSL_negotiateConnection(pConnection->sslConnectId)))
        {
            SSL_closeConnection(pConnection->sslConnectId);
            TCP_CLOSE_SOCKET(pConnection->sockfd);
            pConnection->state = SOCKET_STATE_FREE;
        }
        else
            pConnection->state = SOCKET_STATE_CONNECTED;
    }
    else
#endif
        pConnection->state = SOCKET_STATE_CONNECTED;

exit:
    return status;
}

static MSTATUS
TAPS_CONNECTION_send(TAPS_CONNECTION *pConnection, ubyte *pTxBuf,
        ubyte4 txBufLen, ubyte4 *pByteCount)
{
    MSTATUS status = OK;
    ubyte4 bytesXmitted = 0;

    if ((NULL == pConnection) || (NULL == pTxBuf) ||
            (0 == txBufLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __ENABLE_SECURE_COMM__
    /* Transmit buffer to remote client */
    if (!tapServerInfo.enableunsecurecomms)
    {
        if (txBufLen != (bytesXmitted = SSL_send(pConnection->sslConnectId, (sbyte *)pTxBuf,
                        txBufLen)))
        {
            DB_PRINT("SSL_send error, status %d, sent %d, expected %d", (int)status,
                    bytesXmitted, txBufLen);
            goto exit;
        }
    }
    else
#endif
    {
        if (OK != (status = TCP_WRITE_ALL(pConnection->sockfd,
                        (sbyte *)pTxBuf,
                        txBufLen,
                        &bytesXmitted)))
        {
            DB_PRINT("socket write error, sending %d bytes, sent %d",
                    (int)txBufLen, bytesXmitted);
        }

        if (NULL != pByteCount)
            *pByteCount = bytesXmitted;
    }

exit:
    return status;
}

static MSTATUS
TAPS_CONNECTION_recv(TAPS_CONNECTION *pConnection, ubyte *pRxBuf,
        ubyte4 rxBufLen, ubyte4 *pBytesReceived, ubyte4 timeout)
{
    MSTATUS status = OK;
    ubyte4 byteCount = 0;

    if ((NULL == pConnection) || (NULL == pRxBuf) ||
            (0 == rxBufLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#ifdef __ENABLE_SECURE_COMM__
    if (!tapServerInfo.enableunsecurecomms)
    {
        if (OK != (status = SSL_recv(pConnection->sslConnectId,
                        (sbyte *)pRxBuf,
                        rxBufLen,
                        (sbyte4 *)&byteCount,
                        timeout)))
        {
            if (ERR_TCP_SOCKET_CLOSED != status)
                DB_PRINT("SSL_recv returned status %d", (int)status);
        }

        if (NULL != pBytesReceived)
            *pBytesReceived = byteCount;
    }
    else
#endif
    {
        if (OK != (status = TCP_READ_ALL(pConnection->sockfd, (sbyte *)pRxBuf, rxBufLen, &byteCount,
                        timeout)))
        {
            if (ERR_TCP_SOCKET_CLOSED == status)
            {
                DB_PRINT("[INFO] Connection closed\n");
            }
            else
            {
                DB_PRINT("[DEBUG] Error reading TAP header, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
            }

            goto exit;
        }
        if (NULL != pBytesReceived)
            *pBytesReceived = byteCount;
    }

exit:
    return status;
}


MSTATUS TAPS_dispatcher(TAPS_CONNECTION *pConnInfo, TAP_PROVIDER providerType, TAP_CmdReq *pCmdReq, TAP_CmdRsp *pCmdRsp, TAP_LocalContext *pLocalContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 byteCount = 0;
    ubyte *pRspBuffer = NULL;
    ubyte4 rspBufferLen = 0;
    ubyte4 returnListLen = 0;
    ubyte4 offset = 0;
    TAP_CmdRspHdr tapRspHdr = {0};
    ubyte tapRspHdrBuffer[sizeof(TAP_CmdRspHdr)];

    if ((NULL == pConnInfo) || (NULL == pCmdReq) || NULL == pCmdRsp)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ERR_INVALID_ARG;

    /* set rsp fields we know at this point */
    pCmdRsp->cmdCode = pCmdReq->cmdCode;
    /* The status will get set appropriately later. */
    pCmdRsp->cmdStatus = ERR_TAP;
    /* Module should set the moduleRspInfo in the pCmdRsp->rspParams.<cmd> structure. */

    /* First check if TAP_PROVIDER is supported to avoid switching for each command */
    switch (providerType)
    {
        case TAP_PROVIDER_UNDEFINED:
        case TAP_PROVIDER_TPM2:
#ifdef __ENABLE_DIGICERT_TPM2__
            status = OK;
#else
            /* TODO: Do we want a new error to indicate the TAP_PROVIDER is supported but not enabled in the build? */
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_PKCS11:
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_TEE:
#ifdef __ENABLE_DIGICERT_TEE__
            status = OK;
#else
            status = ERR_TAP_UNSUPPORTED;
#endif
            break;
        case TAP_PROVIDER_TPM:
        case TAP_PROVIDER_SGX:
        case TAP_PROVIDER_STSAFE:
        case TAP_PROVIDER_GEMSIM:
        case TAP_PROVIDER_RENS5:
        case TAP_PROVIDER_TRUSTX:
        case TAP_PROVIDER_ARMM23:
        case TAP_PROVIDER_ARMM33:
        case TAP_PROVIDER_EPID:
        case TAP_PROVIDER_SW:
        default:
            status = ERR_TAP_INVALID_TAP_PROVIDER;
            break;
    }

    if (OK != status)
    {
        pCmdRsp->cmdStatus = status;
        goto exit;
    }

    switch (pCmdReq->cmdCode)
    {
        case TAP_CMD_GET_PROVIDER_LIST:
        {
            status = TAP_COMMON_copyProviderList(&localProviderList,
                                                 &(pCmdRsp->rspParams.getProviderList.providerList));
            if (OK != status)
            {
                LOG_ERROR("Failed to copy local provider list, status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
                if (NULL != pCmdRsp->rspParams.getProviderList.providerList.pProviderCmdList)
                {
                    exitStatus = TAP_UTILS_freeProviderList(&(pCmdRsp->rspParams.getProviderList.providerList));
                    if (OK != exitStatus)
                    {
                        LOG_ERROR("Failed to free memory, status %d = %s\n",
                                exitStatus, MERROR_lookUpErrorCode(exitStatus));
                    }
                }
            }

            status = TAP_UTILS_getProviderListLen(&pCmdRsp->rspParams.getProviderList.providerList, &returnListLen);
            rspBufferLen = sizeof(tapRspHdr);
            rspBufferLen += sizeof(pCmdRsp->cmdCode);
            rspBufferLen += sizeof(pCmdRsp->cmdStatus);
            rspBufferLen += returnListLen;

            pCmdRsp->cmdStatus = status;
            tapRspHdr.cmdStatus = status;

            break;
        } /* case TAP_CMD_GET_PROVIDER_LIST */

        case TAP_CMD_IS_PROVIDER_PRESENT:
        {
            /* Check if we have a TAP_CmdCodeList for the provider. */
            rspBufferLen = sizeof(tapRspHdr);
            rspBufferLen += sizeof(*pCmdRsp);

            pCmdRsp->rspParams.isProviderPresent.isPresent = 0;
            status = TAP_COMMON_checkTapProvider(providerType);
            if (OK == status)
            {
                if (0 < localProviderList.pProviderCmdList[providerType].cmdList.listLen)
                    pCmdRsp->rspParams.isProviderPresent.isPresent = 1;
            }

            pCmdRsp->cmdStatus = status;
            tapRspHdr.cmdStatus = status;

            break;
        } /* case TAP_CMD_IS_PROVIDER_PRESENT */

        default:
            LOG_ERROR("Error, unsupported server command %d\n", pCmdReq->cmdCode);
            /* Build TAP response header */
            tapRspHdr.cmdStatus = ERR_INVALID_ARG;
            tapRspHdr.totalBytes = sizeof(tapRspHdr);
            rspBufferLen = tapRspHdr.totalBytes;

            break;
    }   /* switch (pCmdReq->cmdCode) */

    if (OK != (status = DIGI_MALLOC((void **)&pRspBuffer, rspBufferLen)))
    {
        goto exit;
    }

    /* Build the response payload */
    offset = sizeof(tapRspHdr);
    if (sizeof(tapRspHdr) < rspBufferLen)
    {
        status = TAP_SERIALIZE_serialize(
                    &TAP_REMOTE_SHADOW_TAP_CmdRsp,
                    TAP_SD_IN,
                    (void *)pCmdRsp,
                    sizeof(*pCmdRsp),
                    pRspBuffer,
                    rspBufferLen,
                    &offset);
        if (OK != status)
        {
            LOG_ERROR("Failed to serialize TAP_CmdRsp, status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Build TAP response header */
    tapRspHdr.totalBytes = offset;

    offset = 0;
    /* Serialize TAP response header */
    status = TAP_SERIALIZE_serialize(
                    &TAP_REMOTE_SHADOW_TAP_CmdRspHdr,
                    TAP_SD_IN,
                    (ubyte *)&tapRspHdr,
                    sizeof(tapRspHdr),
                    pRspBuffer,
                    sizeof(tapRspHdrBuffer),
                    &offset);
    if (OK != status)
    {
        LOG_ERROR("[DEBUG] Error serializing TAP_RSP_HDR, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Transmit to client */
    byteCount = 0;
    if (OK != (status = TAPS_CONNECTION_send(pConnInfo, pRspBuffer,
                    tapRspHdr.totalBytes, &byteCount)))
    {
        LOG_ERROR("[DEBUG] Error sending response, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != pRspBuffer)
        DIGI_FREE((void **)&pRspBuffer);

    return status;
}

/*
   Not all commands have a response, this is not of consequence in a local
   secure element, but when the secure element is remote the response has to
   be serialized and the serialized buffer length needs to be set to 0. This
   function helps the caller make that decision.
   */
static int TAP_cmdRspAvailable(SMP_CmdRsp *pSmpCmdRsp)
{
    int rc = 1;

    switch (pSmpCmdRsp->cmdCode)
    {
        case SMP_CC_UNINIT_MODULE:
        case SMP_CC_UNINIT_TOKEN:
        case SMP_CC_UNINIT_OBJECT:
        case SMP_CC_DELETE_OBJECT:
        case SMP_CC_FREE_PUBLIC_KEY:
        case SMP_CC_FREE_MODULE_LIST:
        case SMP_CC_RESET_MODULE:
        case SMP_CC_FREE_SIGNATURE_BUFFER:
        case SMP_CC_STIR_RANDOM:
        case SMP_CC_PROVISION_MODULE:
        case SMP_CC_RESET_TOKEN:
        case SMP_CC_DELETE_TOKEN:
        case SMP_CC_ASSOCIATE_MODULE_CREDENTIALS:
        case SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS:
        case SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS:
        case SMP_CC_VERIFY_UPDATE:
        case SMP_CC_SIGN_UPDATE:
        case SMP_CC_DIGEST_UPDATE:
        case SMP_CC_EVICT_OBJECT:
        case SMP_CC_PERSIST_OBJECT:
            rc = 0;
            break;

        default:
            break;
    }

    return rc;
}

#ifndef __DISABLE_DIGICERT_TAP_CREDS_FILE__
MSTATUS TAPS_getModuleCredentials(TAP_ConfigInfoList *pConfigInfoList,
        int moduleId,
        TAP_PROVIDER providerType, TAP_EntityCredentialList **ppServerCredentialsList)
{
    MSTATUS status = OK;
    int i = 0;
    TAPS_MODULE_CONFIG_SECTION *pModuleConfigSection = NULL;

    if ((NULL == pConfigInfoList) || (NULL == ppServerCredentialsList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 > pConfigInfoList->count)
    {
        status = ERR_INVALID_INPUT;
        LOG_ERROR("Empty configInfoList provided, status %d = %s\n",
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pConfigInfoList->pConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < pConfigInfoList->count; i++)
    {
        if (pConfigInfoList->pConfig[i].provider == providerType)
        {
            switch (providerType)
            {
                case TAP_PROVIDER_TPM2:
                case TAP_PROVIDER_TPM:
                case TAP_PROVIDER_PKCS11:
                case TAP_PROVIDER_TEE:
                    /* Get to the correct moduleId */
                    pModuleConfigSection = ppgConfig[i];

                    while (pModuleConfigSection)
                    {
                        if (pModuleConfigSection->moduleId == moduleId)
                        {
                            *ppServerCredentialsList = pModuleConfigSection->pServerCredentialsList;
                            break;
                        }

                        pModuleConfigSection = pModuleConfigSection->pNext;
                    }

                    break;

                default:
                    break;
            }

            break;
        }
    }

exit:
    return status;
}
#endif /* !__DISABLE_DIGICERT_TAP_CREDS_FILE__ */

/* Add this token to a tracked list.
   Duplicate tokenHandle is treated as error */
static void
TAPS_trackToken(TAPS_CONNECTION *pConnInfo,
        TAP_HANDLE tokenHandle)
{
    MSTATUS status = OK;
    TAPS_TRACKING_NODE *pTrackingNode = NULL;

    if (NULL == pConnInfo)
        goto exit;

    /* Check for duplicate tokens */
    pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        if (pTrackingNode->tokenHandle == tokenHandle)
        {
            DB_PRINT("%s.%d Error duplicate tokenHandle 0x%08x being tracked\n",
                    __FUNCTION__, __LINE__, (unsigned int)tokenHandle);
            goto exit;
        }

        pTrackingNode = pTrackingNode->pNext;
    }

    pTrackingNode = pConnInfo->pFirstTrackingNode;

    status = DIGI_CALLOC((void **)&pConnInfo->pFirstTrackingNode, 1,
            sizeof(*pConnInfo->pFirstTrackingNode));
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating memory for token tracking node, status = %d:%s\n",
                __FUNCTION__, __LINE__, (int)status, MERROR_lookUpErrorCode(status));

        goto exit;
    }

    pConnInfo->pFirstTrackingNode->tokenHandle = tokenHandle;
    pConnInfo->pFirstTrackingNode->pNext = pTrackingNode;

exit:
    return;
}

/* Add this object to a tracked list.
   Duplicate tokenHandle and objectHandle is treated as error */
static void
TAPS_trackObject(TAPS_CONNECTION *pConnInfo,
        TAP_HANDLE tokenHandle, TAP_HANDLE objectHandle)
{
    TAPS_TRACKING_NODE *pTrackingNode = NULL;
    TAPS_TRACKING_NODE *pInsertNode = NULL;

    if (NULL == pConnInfo)
        goto exit;

    /* Every object is created under a token and since the token is
       created first tracking object should have already been created
     */
    /* Check for duplicate entries and locate the entry at which this
     object should be tracked
     */
    pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        if (pTrackingNode->tokenHandle == tokenHandle)
        {
            if (pTrackingNode->objectHandle == objectHandle)
            {
                DB_PRINT("%s.%d Error duplicate tokenHandle %d or objectHandle %d being tracked\n",
                    __FUNCTION__, __LINE__, (int)tokenHandle, (int)objectHandle);
                goto exit;
            }

            pInsertNode = pTrackingNode;
        }

        pTrackingNode = pTrackingNode->pNext;
    }

    if (pInsertNode)
    {
        pInsertNode->objectHandle = objectHandle;
    }
    else
    {
        DB_PRINT("%s.%d Error token handle 0x%08x not found\n",
                __FUNCTION__, __LINE__, (unsigned int)tokenHandle);

        goto exit;
    }

exit:

    return;
}

/* Remove this object from the tracked list */
static void
TAPS_untrackObject(TAPS_CONNECTION *pConnInfo,
        TAP_HANDLE tokenHandle, TAP_HANDLE objectHandle)
{
    TAPS_TRACKING_NODE *pTrackingNode = NULL;

    if ((NULL == pConnInfo) || (NULL == pConnInfo->pFirstTrackingNode))
        goto exit;

    pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        if ((pTrackingNode->tokenHandle == tokenHandle) &&
            ((pTrackingNode->objectHandle == objectHandle) ||
             (0 == pTrackingNode->objectHandle)))
        {
            /* Clear the object handle */
            pTrackingNode->objectHandle = 0;

            /* Node will be freed when uninitToken is invoked */

            goto exit;
        }

        pTrackingNode = pTrackingNode->pNext;
    }

    DB_PRINT("%s.%d Error token 0x%08x, object 0x%08x not found\n",
                __FUNCTION__, __LINE__, (unsigned int)tokenHandle,
                (unsigned int)objectHandle);

exit:

    return;
}

/* Remove this token from the tracked list */
static void
TAPS_untrackToken(TAPS_CONNECTION *pConnInfo,
        TAP_HANDLE tokenHandle)
{
    TAPS_TRACKING_NODE *pTrackingNode = NULL;
    TAPS_TRACKING_NODE *pPrevNode = NULL;

    if ((NULL == pConnInfo) || (NULL == pConnInfo->pFirstTrackingNode))
        goto exit;

    pPrevNode = pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        if (pTrackingNode->tokenHandle == tokenHandle)
        {
            if (pTrackingNode == pConnInfo->pFirstTrackingNode)
                pConnInfo->pFirstTrackingNode = pTrackingNode->pNext;
            else
                pPrevNode->pNext = pTrackingNode->pNext;

            pTrackingNode->tokenHandle = 0;

            /* Free node */
            DIGI_FREE((void **)&pTrackingNode);

            goto exit;
        }

        pPrevNode = pTrackingNode;
        pTrackingNode = pTrackingNode->pNext;
    }

    DB_PRINT("%s.%d Error token 0x%08x not found\n",
                __FUNCTION__, __LINE__, (unsigned int)tokenHandle);

exit:

    return;
}

static void
TAPS_freeTrackedObjects(TAPS_CONNECTION *pConnInfo, TAP_LocalContext localContext,
        ubyte4 savedProviderType, TAP_HANDLE savedModuleHandle)
{
    TAPS_TRACKING_NODE *pTrackingNode = NULL;
    TAPS_TRACKING_NODE *pNextNode = NULL;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    if ((NULL == pConnInfo) || (NULL == pConnInfo->pFirstTrackingNode))
        goto exit;

    pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        /* Delete the Object */
        smpCmdReq.cmdCode = SMP_CC_DELETE_OBJECT;
        smpCmdReq.reqParams.deleteObject.moduleHandle = savedModuleHandle;
        smpCmdReq.reqParams.deleteObject.tokenHandle = pTrackingNode->tokenHandle;
        smpCmdReq.reqParams.deleteObject.objectHandle = pTrackingNode->objectHandle;

        if (NULL != TAPS_dispatchCommand[savedProviderType])
        {
            TAPS_dispatchCommand[savedProviderType]((TAP_RequestContext)localContext.pModuleContext, &smpCmdReq,
                    &smpCmdRsp, NULL, NULL);
        }

        /* Uninit the Token */
        smpCmdReq.cmdCode = SMP_CC_UNINIT_TOKEN;
        smpCmdReq.reqParams.uninitToken.moduleHandle = savedModuleHandle;
        smpCmdReq.reqParams.uninitToken.tokenHandle = pTrackingNode->tokenHandle;

        if (NULL != TAPS_dispatchCommand[savedProviderType])
        {
            TAPS_dispatchCommand[savedProviderType]((TAP_RequestContext)localContext.pModuleContext, &smpCmdReq,
                    &smpCmdRsp, NULL, NULL);
        }

        pTrackingNode = pTrackingNode->pNext;
    }

    pTrackingNode = pConnInfo->pFirstTrackingNode;
    while (pTrackingNode)
    {
        pNextNode = pTrackingNode->pNext;

        /* Free node memory */
        DIGI_FREE((void **)&pTrackingNode);

        pTrackingNode = pNextNode;
    }

exit:

    return;
}

static void
TAPS_connectionThread(void *arg)
{
    MSTATUS status = OK;
    MSTATUS cmdStatus = OK;
    TAPS_CONNECTION *pConnInfo = (TAPS_CONNECTION *)arg;
    ubyte4 timeout = 0;
    ubyte4 byteCount = 0, offset = 0;
    TAP_CmdReqHdr tapCmdHdr = {0};
    TAP_CmdRspHdr tapRspHdr = {0};
    TAP_CmdReq tapCmdReq = { 0, };
    TAP_CmdRsp tapCmdRsp = { 0, };
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    ubyte tapCmdHdrBuffer[sizeof(TAP_CmdReqHdr)];
    ubyte tapRspHdrBuffer[sizeof(TAP_CmdRspHdr)];
    ubyte *pReqBuffer = NULL;
    ubyte *pRspBuffer = NULL;
    TAP_LocalContext localContext = {0};
    ubyte4 rspBufferLen = 0;
    TAP_EntityCredentialList *pOldCredentialList = NULL;
    TAP_EntityCredentialList *pServerCredentialsList = NULL;
    TAP_AttributeList *pOldModuleAttributes = NULL;
    TAP_AttributeList serverModuleAttributes = {0};
    int i;
    TAP_HANDLE savedModuleHandle = 0;
    ubyte4 savedProviderType = 0;
    ubyte4 j;

	if (NULL == pConnInfo)
		goto exit;

    status = DIGI_MALLOC((void **)&pReqBuffer, MAX_CMD_BUFFER);
    if (OK != status)
    {
        LOG_ERROR("Unable to allocate %d bytes for request buffer\n",
                MAX_CMD_BUFFER);
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pRspBuffer, MAX_CMD_BUFFER);
    if (OK != status)
    {
        LOG_ERROR("Unable to allocate %d bytes for response buffer\n",
                MAX_CMD_BUFFER);
        goto exit;
    }

    DB_PRINT("TAP connection thread started...\n");

    /* Add this connection to active list */
    if (OK != (status = TAPS_CONNECTION_addToActiveList(pConnInfo)))
    {
        LOG_ERROR("Unable to add connection to activelist, status = %d\n", status);
        goto exit;
    }

	/* Negotiate Connection
       Handles SSL negotiation if enabled
     */
	if (OK != (status = TAPS_CONNECTION_negotiate(pConnInfo)))
	{
        LOG_ERROR("Unable to negotiate new client connection, status = %d\n", status);
		goto exit;
	}

    /* Now ready to accept commands */
	while (!pConnInfo->quitTime)
	{
        byteCount = 0;

        /* Read TAP header */
        if (OK != (status = TAPS_CONNECTION_recv(pConnInfo, tapCmdHdrBuffer,
                        sizeof(tapCmdHdrBuffer), &byteCount, timeout)))
        {
            goto exit;
        }

        if (tapServerInfo.enableunsecurecomms)
        {
            if (sizeof(tapCmdHdrBuffer) == byteCount)
            {
                for (j = 0; j < byteCount; j++)
                {
                    if (tapCmdHdrBuffer[j] != 0)
                    {
                        break;
                    }
                }
                /* If j == byteCount then all bytes are 0. Valid close
                 * connection invoked by the client */
                if (j == byteCount)
                {
                    goto exit;
                }
            }
        }

        /* Deserialize header */
        DIGI_MEMSET((ubyte *)&tapCmdHdr, 0, sizeof(tapCmdHdr));
        offset = 0;
        if (OK != (status = TAP_SERIALIZE_serialize(
                        &TAP_REMOTE_SHADOW_TAP_CmdReqHdr,
                        TAP_SD_OUT,
                        tapCmdHdrBuffer,
                        sizeof(tapCmdHdrBuffer),
                        (ubyte *)&tapCmdHdr,
                        sizeof(tapCmdHdr),
                        &offset)))
        {
            LOG_ERROR("[DEBUG] Error deserializing TAP cmd header, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Validate command destination Input */
        switch (tapCmdHdr.cmdDest)
        {
            case TAP_CMD_DEST_MODULE:
            case TAP_CMD_DEST_SERVER:
                break;
            default:
                LOG_ERROR("[DEBUG] Unsupported TAP destination %d, dropping connection ...\n", (int)tapCmdHdr.cmdDest);
                goto exit;
                break;
        }

        /* If this command is for the server, execute and terminate */
        if (TAP_CMD_DEST_SERVER == tapCmdHdr.cmdDest)
        {
            /* Get Server command */
            byteCount = 0;

            /* Read Command */
            if (OK != (status = TAPS_CONNECTION_recv(pConnInfo, pReqBuffer,
                            tapCmdHdr.totalBytes - sizeof(tapCmdHdr), &byteCount, timeout)))
            {
                if (!pConnInfo->quitTime)
                    LOG_ERROR("Error %d receiving server command\n", status);
                goto exit;
            }

            /* Deserialize */
            offset = 0;
            if (TAP_CMD_TYPE_TAP != tapCmdHdr.cmdType)
            {
                LOG_ERROR("[DEBUG] Unsupported TAP_CMD_TYPE %d for TAP server, dropping connection ...\n", (int)tapCmdHdr.cmdType);
                goto exit;
            }
            status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdReq, TAP_SD_OUT,
                    pReqBuffer, byteCount, (ubyte *)&tapCmdReq,
                    sizeof(tapCmdReq), &offset);
            if (OK != status)
            {
                LOG_ERROR("[DEBUG] Error deserializing command request, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            DB_PRINT("[DEBUG] Dispatching server command %d\n", tapCmdReq.cmdCode);
            /* Handle TAP Server directed commands */
            if (OK != (status = TAPS_dispatcher(pConnInfo, tapCmdHdr.providerType, &tapCmdReq, &tapCmdRsp,
                            &localContext)))
            {
                LOG_ERROR("[DEBUG] Error dispatching server command, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            continue;
        }

        /* Identify TAP provider and create a module context if this is the first command */
        else if ((TAP_CMD_DEST_MODULE == tapCmdHdr.cmdDest) &&
                (TAP_PROVIDER_UNDEFINED != tapCmdHdr.providerType))
        {
            if (sizeof (pConnInfo->cmdBuffer) >= tapCmdHdr.totalBytes)
            {
                /* Read the TAP specific command */
                if (OK != (status = TAPS_CONNECTION_recv(pConnInfo, pConnInfo->cmdBuffer,
                                tapCmdHdr.totalBytes - sizeof(tapCmdHdr), &byteCount, timeout)))
                {
                    LOG_ERROR("[DEBUG] Error receiving TAP command, dropping connection ..., status = %d\n", status);
                    goto exit;
                }
            }
            else
            {
                LOG_ERROR("[DEBUG] Command request too large, dropping connection ..., Bytes received = %d\n",
                        (int)tapCmdHdr.totalBytes);
                goto exit;
            }

            /* Deserialize */
            if (TAP_CMD_TYPE_SMP != tapCmdHdr.cmdType)
            {
                LOG_ERROR("[DEBUG] Unsupported TAP_CMD_TYPE %d for SMP module, dropping connection ...\n", (int)tapCmdHdr.cmdType);
                goto exit;
            }
            offset = 0;
            status = TAP_SERIALIZE_serialize(&SMP_INTERFACE_SHADOW_SMP_CmdReq, TAP_SD_OUT,
                    pConnInfo->cmdBuffer, byteCount, (ubyte *)&smpCmdReq,
                    sizeof(smpCmdReq), &offset);
            if (OK != status)
            {
                LOG_ERROR("[DEBUG] Error deserializing command request, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if ((TAP_PROVIDER_MAX > tapCmdHdr.providerType) && (NULL != TAPS_dispatchCommand[tapCmdHdr.providerType]))
        {
            status = DIGI_MEMSET((ubyte *)&smpCmdRsp, 0, sizeof(smpCmdRsp));
            if (OK != status)
            {
                LOG_ERROR("[DEBUG] Error clearing command response structure, dropping connection ...\n");
                goto exit;
            }

            /* Inject TPM2 credentials when initToken is invoked */
            switch (tapCmdHdr.providerType)
            {
                case TAP_PROVIDER_TPM2:
                case TAP_PROVIDER_TPM:
                case TAP_PROVIDER_PKCS11:
                case TAP_PROVIDER_TEE:
                    switch (smpCmdReq.cmdCode)
                    {
                        case SMP_CC_INIT_MODULE:
                            /* This will be the first command, from this point on
                               pServerCredentialsList will be valid */
                            TAPS_getModuleCredentials(&configInfoList,
                                (int)smpCmdReq.reqParams.initModule.moduleId,
                                tapCmdHdr.providerType, &pServerCredentialsList);

                            pOldModuleAttributes = smpCmdReq.reqParams.initModule.pModuleAttributes;

                            if (!serverModuleAttributes.listLen && pOldModuleAttributes)
                            {
                                serverModuleAttributes.listLen = pOldModuleAttributes->listLen + 1;

                                /* Allocate 1 more than the max list */
                                status = DIGI_CALLOC((void **)&serverModuleAttributes.pAttributeList,
                                        1, serverModuleAttributes.listLen *
                                        sizeof (*serverModuleAttributes.pAttributeList));
                                if (OK != status)
                                {
                                    LOG_ERROR("Error allocating memory for servermodule attribute list, "
                                            "status %d = %s\n",
                                            (int)status, MERROR_lookUpErrorCode(status));
                                    break;
                                }

                                i = 0;
                                if (pOldModuleAttributes && pOldModuleAttributes->listLen)
                                {
                                    for (i = 0; i < pOldModuleAttributes->listLen; i++)
                                    {
                                        serverModuleAttributes.pAttributeList[i].type = TAP_ATTR_NONE;

                                        switch (pOldModuleAttributes->pAttributeList[i].type)
                                        {
                                            case TAP_ATTR_CREDENTIAL_SET:
                                            case TAP_ATTR_CREDENTIAL_USAGE:
                                                /* Skip credentials */
                                                break;

                                            default:
                                                serverModuleAttributes.pAttributeList[i] = pOldModuleAttributes->pAttributeList[i];
                                                break;
                                        }
                                    }
                                }

                                if (pServerCredentialsList)
                                {
                                    serverModuleAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
                                    serverModuleAttributes.pAttributeList[i].length = sizeof(*pServerCredentialsList);
                                    serverModuleAttributes.pAttributeList[i].pStructOfType = pServerCredentialsList;
                                }
                                else
                                {
                                    serverModuleAttributes.pAttributeList[i].type = TAP_ATTR_NONE;
                                    serverModuleAttributes.pAttributeList[i].length = 0;
                                    serverModuleAttributes.pAttributeList[i].pStructOfType = NULL;
                                }
                            }
                            smpCmdReq.reqParams.initModule.pModuleAttributes = &serverModuleAttributes;
                            break;

                        case SMP_CC_INIT_TOKEN:
                            pOldCredentialList = smpCmdReq.reqParams.initToken.pCredentialList;
                            /* Check moduleHandle */
                            if (savedModuleHandle == smpCmdReq.reqParams.initToken.moduleHandle)
                            {
                                /* Replace the pCredentials with one from credentials file */
                                smpCmdReq.reqParams.initToken.pCredentialList = pServerCredentialsList;
                            }
                            else
                                LOG_ERROR("Mismatched moduleHandle in initToken, skipping credential insertion (savedModuleHandle) %d != (ReqHandle) %d\n",
                                        (int)savedModuleHandle, (int)smpCmdReq.reqParams.initToken.moduleHandle);
                            break;

                        default:
                            break;
                    }
                    break;

                default:
                    break;
            }

            switch (smpCmdReq.cmdCode)
            {
                case SMP_CC_ASSOCIATE_MODULE_CREDENTIALS:
                case SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS:
                    /* Skip credentials association, we have already injected them */
                    cmdStatus = OK;
                    break;

                default:
                    /* Invoke dispatcher */
                    cmdStatus = TAPS_dispatchCommand[tapCmdHdr.providerType]((TAP_RequestContext)localContext.pModuleContext, &smpCmdReq,
                        &smpCmdRsp, NULL, NULL);
                    break;
            }

            /* Clean up TPM2 credentials when initToken is invoked */
            switch (tapCmdHdr.providerType)
            {
                case TAP_PROVIDER_TPM2:
                case TAP_PROVIDER_TPM:
                case TAP_PROVIDER_PKCS11:
                case TAP_PROVIDER_TEE:
                    switch (smpCmdReq.cmdCode)
                    {
                        case SMP_CC_INIT_MODULE:
                            /* Restore ATTR_ENTITY_CREDENTIALS attribute in Module attributes */
                            smpCmdReq.reqParams.initModule.pModuleAttributes = pOldModuleAttributes;
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                savedModuleHandle = smpCmdRsp.rspParams.initModule.moduleHandle;
                                savedProviderType = tapCmdHdr.providerType;
                            }
                            break;

                        case SMP_CC_INIT_TOKEN:
                            /* Restore Credentials */
                            smpCmdReq.reqParams.initToken.pCredentialList = pOldCredentialList;

                            /* Allocate node to track token allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_trackToken(pConnInfo, smpCmdRsp.rspParams.initToken.tokenHandle);
                            }
                            break;

                        case SMP_CC_CREATE_SYMMETRIC_KEY:
                            /* Update node to track object allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_trackObject(pConnInfo, smpCmdReq.reqParams.createSymmetricKey.tokenHandle,
                                        smpCmdRsp.rspParams.createSymmetricKey.keyHandle);
                            }
                            break;

                        case SMP_CC_IMPORT_OBJECT:
                            /* Update node to track object allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_trackObject(pConnInfo, smpCmdReq.reqParams.importObject.tokenHandle,
                                        smpCmdRsp.rspParams.importObject.objectHandle);
                            }
                            break;

                        case SMP_CC_CREATE_OBJECT:
                            /* Update node to track object allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_trackObject(pConnInfo, smpCmdReq.reqParams.createObject.tokenHandle,
                                        smpCmdRsp.rspParams.createObject.handle);
                            }
                            break;

                        case SMP_CC_CREATE_ASYMMETRIC_KEY:
                            /* Update node to track object allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_trackObject(pConnInfo, smpCmdReq.reqParams.createAsymmetricKey.tokenHandle,
                                        smpCmdRsp.rspParams.createAsymmetricKey.keyHandle);
                            }
                            break;

                        case SMP_CC_DELETE_OBJECT:
                            /* Update node to track object allocations */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_untrackObject(pConnInfo, smpCmdReq.reqParams.deleteObject.tokenHandle,
                                        smpCmdReq.reqParams.deleteObject.objectHandle);
                            }
                            break;

                        case SMP_CC_UNINIT_TOKEN:
                            /* Release tracked token */
                            if ((OK == cmdStatus) && (OK == smpCmdRsp.returnCode))
                            {
                                TAPS_untrackToken(pConnInfo, smpCmdReq.reqParams.uninitToken.tokenHandle);
                            }
                            break;

                        case SMP_CC_UNINIT_MODULE:
                            savedModuleHandle = 0;
                            savedProviderType = 0;
                            break;

                        default:
                            break;
                    }
                    break;

                default:
                    break;
            }

            offset = 0;
            /* Not all commands have a SMP response */
            if (TAP_cmdRspAvailable(&smpCmdRsp) && (OK == cmdStatus))
            {
                /* Serialize TAP response  */
                if (OK != (status = TAP_SERIALIZE_serialize(
                                &SMP_INTERFACE_SHADOW_SMP_CmdRsp,
                                TAP_SD_IN,
                                (ubyte *)&smpCmdRsp,
                                sizeof(smpCmdRsp),
                                pRspBuffer,
                                MAX_CMD_BUFFER,
                                &offset)))
                {
                    LOG_ERROR("[DEBUG] Error serializing command response, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            /* Build TAP response header */
            tapRspHdr.cmdStatus = cmdStatus;
            tapRspHdr.cmdType = TAP_CMD_TYPE_SMP;
            rspBufferLen = offset;
            tapRspHdr.totalBytes = offset + sizeof(tapRspHdr);

            offset = 0;
            DIGI_MEMSET(tapRspHdrBuffer, 0, sizeof(tapRspHdrBuffer));
            /* Serialize TAP response header */
            if (OK != (status = TAP_SERIALIZE_serialize(
                            &TAP_REMOTE_SHADOW_TAP_CmdRspHdr,
                            TAP_SD_IN,
                            (ubyte *)&tapRspHdr,
                            sizeof(tapRspHdr),
                            tapRspHdrBuffer,
                            sizeof(tapRspHdrBuffer),
                            &offset)))
            {
                LOG_ERROR("[DEBUG] Error serializing TAP cmd-resp header, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            /* Transmit TAP response header */
            byteCount = 0;
            if (OK != (status = TAPS_CONNECTION_send(pConnInfo, tapRspHdrBuffer,
                            sizeof(tapRspHdrBuffer), &byteCount)))
            {
                LOG_ERROR("[DEBUG] Error sending TAP resp header, status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            /* Transmit TAP response if there is one */
            if (0 < rspBufferLen)
            {
                /* Response is already serialized, transmit */
                byteCount = 0;
                if (OK != (status = TAPS_CONNECTION_send(pConnInfo, (ubyte *)&(pRspBuffer[0]),
                                rspBufferLen, &byteCount)))
                {
                    LOG_ERROR("[DEBUG] Error sending TAP resp , status %d = %s\n", status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                /* Free Response */
                TAP_SERIALIZE_freeDeserializedStructure(
                        &SMP_INTERFACE_SHADOW_SMP_CmdRsp,
                        (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));
            }

            /* Free request */
            TAP_SERIALIZE_freeDeserializedStructure(&SMP_INTERFACE_SHADOW_SMP_CmdReq,
                    (ubyte *)&smpCmdReq, sizeof(smpCmdReq));
        }
        else
        {
            goto exit;
        }

        /* Go back to accepting new commands */
	}

exit:
    /* If this was an abnormal termination, clean up on behalf of the client */
    if (savedModuleHandle && savedProviderType)
    {
        TAPS_freeTrackedObjects(pConnInfo, localContext,
                savedProviderType, savedModuleHandle);

        smpCmdReq.cmdCode = SMP_CC_UNINIT_MODULE;
        smpCmdReq.reqParams.uninitModule.moduleHandle = savedModuleHandle;

        if (NULL != TAPS_dispatchCommand[savedProviderType])
        {
            TAPS_dispatchCommand[savedProviderType]((TAP_RequestContext)localContext.pModuleContext, &smpCmdReq,
                    &smpCmdRsp, NULL, NULL);
        }
        savedModuleHandle = 0;
    }

#ifdef __DISABLE_DIGICERT_TAP_CREDS_FILE__
    if (pServerCredentialsList)
    {
        TAP_UTILS_clearEntityCredentialList(pServerCredentialsList);
        DIGI_FREE((void **)&pServerCredentialsList);
    }
#else
    /* Do not free pServerCredentialsList, it is a reference pointer */
#endif
    if (serverModuleAttributes.pAttributeList)
        DIGI_FREE((void **)&serverModuleAttributes.pAttributeList);

    /* Clean up in error exit paths */
    if (NULL != pRspBuffer)
        DIGI_FREE((void **)&pRspBuffer);

    if (NULL != pReqBuffer)
        DIGI_FREE((void **)&pReqBuffer);

    if (pConnInfo)
    {
        /* Remove from active list */
        TAPS_CONNECTION_terminate(pConnInfo);
        RTOS_destroyThread(pConnInfo->threadId) ;
        /* Free connection context */
		shredMemory((ubyte **)&pConnInfo, sizeof(*pConnInfo), 1);
    }

	return;
}

#if defined(__RTOS_WIN32__)
#define MOC_PLIB_TYPE ".dll"
#else
#define MOC_PLIB_TYPE ".so"
#endif

/* Port validation constants */
#define MIN_PORT_NUMBER 1
#define MAX_PORT_NUMBER 65535

/*
 * Platform specific command line parsing.
 */
void printHelp()
{
    LOG_MESSAGE("taps: Help Menu\n");
    LOG_MESSAGE("This command starts tap server.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [display command line options]");
    LOG_MESSAGE("                   Help menu\n");
    LOG_MESSAGE("           --p=[TPM server port]");
    LOG_MESSAGE("                   Port at which the TAP server is listening.\n");
    LOG_MESSAGE("           --conf=[TAPS configuration file]");
    LOG_MESSAGE("                   Path to taps module configuration file.\n");
    LOG_MESSAGE("           --modconfdir=[module config directory]");
    LOG_MESSAGE("                   Path to module configuration folder.\n");
#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
    LOG_MESSAGE("           --unix=[unix domain socket path]");
    LOG_MESSAGE("                   Path to unix domain socket.\n");
#endif
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    LOG_MESSAGE("           --protect-lib=[shared object plugin path]");
    LOG_MESSAGE("                   Path to a shared object plugin (" MOC_PLIB_TYPE ") for device specific callback methods.\n");
#endif
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(tapsExecutionOptions *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {"conf", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
            {"modconfdir", required_argument, NULL, 4},
#ifdef __ENABLE_TAP_REMOTE_UNIX_DOMAIN__
            {"unix", required_argument, NULL, 5},
#endif
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            {"protect-lib", required_argument, NULL, 6},
#endif
            {NULL, 0, NULL, 0}
    };
    ubyte4 optValLen = 0;

    if (!pOpts || !argv || (0 == argc))
    {
        TAP_DEBUG_PRINT_1("Invalid parameters.");
        goto exit;
    }

    while (TRUE)
    {
        c = getopt_long(argc, argv, optstring, options, &options_index);
        if ((-1 == c))
            break;

        switch (c)
        {
        case 1:
            printHelp();
            pOpts->exitAfterParse = TRUE;
            break;
        case 2:
            pOpts->isConfFileSpecified = TRUE;
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            if (optValLen >= (sizeof(pOpts->confFilePath) - 1))
            {
                LOG_ERROR("File path too long. Max size: %d bytes",
                        (int)(sizeof(pOpts->confFilePath) - 1));
                goto exit;
            }
            if ((0 >= optValLen) || ('-' == optarg[0]))
            {
                LOG_ERROR("Configuration file path not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
            {
                TAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->confFilePath[optValLen] = '\0' ;
            TAP_DEBUG_PRINT("Configuration file path: %s",
                                 pOpts->confFilePath);

            break;

        case 3:
            if (('\0' == optarg[0]) || ('-' == optarg[0]))
            {
                LOG_ERROR("Invalid or no port number specified");
                goto exit;
            }
            pOpts->serverPort = strtoul(optarg, NULL, 0);
            if ((pOpts->serverPort < MIN_PORT_NUMBER) || (pOpts->serverPort > MAX_PORT_NUMBER))
            {
                LOG_ERROR("Invalid port number specified. Valid range: %d-%d",
                        MIN_PORT_NUMBER, MAX_PORT_NUMBER);
                goto exit;
            }
            tapServerInfo.serverPort = pOpts->serverPort;
            TAP_DEBUG_PRINT("Server Port: %u", pOpts->serverPort);
            break;
        case 4:
            pOpts->isConfDirSpecified = TRUE;
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            if (optValLen >= sizeof(pOpts->confDirPath))
            {
                LOG_ERROR("File path too long. Max size: %d bytes",
                        (int)(sizeof(pOpts->confDirPath) - 1));
                goto exit;
            }
            if ((0 >= optValLen) || ('-' == optarg[0]))
            {
                LOG_ERROR("provider module Configuration dir path not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->confDirPath, optarg, optValLen))
            {
                TAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->confDirPath[optValLen] = '\0' ;
            TAP_DEBUG_PRINT(" provider module Configuration dir path: %s",
                                 pOpts->confDirPath);

            break;
#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
        case 5:
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            if (optValLen >= sizeof(pOpts->unixServerPath))
            {
                LOG_ERROR("File path too long. Max size: %d bytes",
                        (int)(sizeof(pOpts->unixServerPath) - 1));
                goto exit;
            }
            if ((0 >= optValLen) || ('-' == optarg[0]))
            {
                LOG_ERROR("unix socket path is not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->unixServerPath, optarg, optValLen))
            {
                TAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->unixServerPath[optValLen] = '\0' ;
            TAP_DEBUG_PRINT(" server unix socket path: %s",
                                 pOpts->unixServerPath);

            break;
#endif
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        case 6:
            pOpts->isProtectLibSpecified = TRUE;
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            if (optValLen >= sizeof(pOpts->protectLibPath))
            {
                LOG_ERROR("Protect Library file path too long. Max size: %d bytes",
                      (int)(sizeof(pOpts->protectLibPath) - 1));
                goto exit;
            }
            if ((0 >= optValLen) || ('-' == optarg[0]))
            {
                LOG_ERROR("Protect Library path is not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->protectLibPath, optarg, optValLen))
            {
                TAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->protectLibPath[optValLen] = '\0';
            TAP_DEBUG_PRINT("Protect Library path: %s",
                            pOpts->protectLibPath);

            break;
#endif
        default:
            goto exit;
            break;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

static MSTATUS TAPS_processAcceptRequests()
{
    MSTATUS status = OK;
    TAPS_CONNECTION *pConnection = NULL;
    TCP_SOCKET tapClientSocket;

    TAP_DEBUG_PRINT_1("Executing TAPS_startup ...");
    if (OK != (status = TAPS_startup()))
    {
        LOG_ERROR("TAPS_startup failed, status = %d", status);
        goto exit;
    }

#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
    if(TAP_UNIX_DOMAIN_SOCKET == pExecutionOpts->serverPort)
    {
        if(OK > (status = UNIXDOMAIN_LISTEN(&tapListenSocket, pExecutionOpts->unixServerPath)))
        {
            LOG_ERROR("Failed to listen unix domain socket at  %s, status = %d", pExecutionOpts->unixServerPath, status);
            goto exit;
        }
        TAP_DEBUG_PRINT("Listening on port = %d", pExecutionOpts->serverPort);
        tapServerInfo.enableunsecurecomms = 1;
    }
    else
#endif
    {
        TAP_DEBUG_PRINT("Listening on port %d", tapServerInfo.serverPort);

        if (NULL != tapServerInfo.pBindAddr)
        {
#if defined(__RTOS_LINUX__)
            TAP_DEBUG_PRINT("Listening on address %s", tapServerInfo.pBindAddr);
            status = TCP_LISTEN_SOCKET_ADDR(
                &tapListenSocket, tapServerInfo.pBindAddr,
                tapServerInfo.serverPort);
#else
            TAP_DEBUG_PRINT_1("Bind address not supported");
            status = ERR_INVALID_INPUT;
            goto exit;
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_TAPS_LOOPBACK__
            TAP_DEBUG_PRINT("Listening on loopback");
            /* Bind and listen on socket on loopback ip address */
            status = TCP_LISTEN_SOCKET_LOCAL(
                &tapListenSocket, tapServerInfo.serverPort);
#else
            TAP_DEBUG_PRINT("Listening on all addresses", tapServerInfo.pBindAddr);
            /* Bind and listen on socket */
            status = TCP_LISTEN_SOCKET(
                &tapListenSocket, tapServerInfo.serverPort);
#endif
        }
        if (OK != status)
        {
            LOG_ERROR(
                "Failed to listen socket on port = %d, status = %d",
                tapServerInfo.serverPort, status);
            goto exit;
        }
    }

#ifdef __RUN_TAPS_SERVICE__
    if (NULL != gpServiceOpts->pTapsStartCallback)
    {
        gpServiceOpts->pTapsStartCallback(status);
    }
#endif /*__RUN_TAPS_SERVICE__*/

    while (!quitTime)
    {
        TAP_DEBUG_PRINT_1("Waiting for client connections ...\n");
        /* Wait for a connection */
#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
        if(TAP_UNIX_DOMAIN_SOCKET == pExecutionOpts->serverPort)
        {
            status = UNIXDOMAIN_ACCEPT(&tapClientSocket, tapListenSocket,
            (intBoolean *)&quitTime);
        }
        else
#endif
        {
            status = TCP_ACCEPT_SOCKET(&tapClientSocket, tapListenSocket,
            (intBoolean *)&quitTime);
        }

        if (OK != status)
        {
            if (!quitTime)
            {
                LOG_ERROR("TAPS failed to accept socket connection on "
                    "port=%d, status = %d",
                    tapServerInfo.serverPort, status);
            }

            goto exit;
        }

        if (quitTime)
            break;

        /* Allocate a connection object to maintain thread context information */
        if (OK != (status = DIGI_CALLOC((void **)&pConnection, 1, sizeof(*pConnection))))
        {
            LOG_ERROR("Error allocation memory for new connection, status = %d\n", status);
            goto exit;
        }

        pConnection->sockfd = tapClientSocket;

        /* Spawn thread to handle this connection */
        if (OK != (status = RTOS_createThread(&TAPS_connectionThread,
            pConnection, 0, &pConnection->threadId)))
        {
            LOG_ERROR("Failed creating thread for client-socket = %d",
                pConnection->sockfd);
            goto exit;
        }

        pConnection = NULL;
    }

exit:
    return status;
}

#if defined(__RTOS_WIN32__) && defined(__RUN_TAPS_SERVICE__)
void tapsMain(void *arg)
#else
int main(int argc, char **argv)
#endif
{
    MSTATUS status = OK, fstatus;

#ifndef __RUN_TAPS_SERVICE__
    platformParseCmdLineOpts platCmdLineParser = NULL;

    status = DIGI_CALLOC((void **)&pExecutionOpts, 1, sizeof(*pExecutionOpts));
    if (OK != status)
    {
        LOG_ERROR("Error allocating memory for tapsExecutionOptions"
            "status = %d", status);
        goto exit;
    }

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif
#else
    if (NULL == arg)
    {
        status = ERR_NULL_POINTER;
        LOG_ERROR("Invalid execution options for TAPS, status=%d",
                        status);
        goto exit;
    }
#endif /* ! __RUN_TAPS_SERVICE__ */

    gMocanaAppsRunning++;

    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        LOG_ERROR("Library initialization failed, DIGICERT_initDigicert status=%d",
                        status);
        goto exit;
    }

    tapServerInfo.serverPort = TAP_DEFAULT_SERVER_PORT_NO;

#ifndef __RUN_TAPS_SERVICE__
    if (NULL == platCmdLineParser)
    {
        LOG_ERROR("No command line parser available for this platform.");
        goto exit;
    }

    if (0 != platCmdLineParser(pExecutionOpts, argc, argv))
    {
        LOG_ERROR("Failed to parse command line options.");
        goto exit;
    }
    if (pExecutionOpts->exitAfterParse)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    /* DIGICERT_initDigicert() above registered default callbacks. If we have a different
       library with callbacks specified, register that instead, */
    if (pExecutionOpts->isProtectLibSpecified)
    {
        status = FP_registerSeedCallbacksFromExternal((const char *) pExecutionOpts->protectLibPath);
        if (OK != status)
        {
            LOG_ERROR("TAPS Failed to load protect-lib, status = %d\n", status);
            goto exit;
        }
    }
#endif

#else
    gpServiceOpts = (tapsServiceOpts*)arg;
    if ((NULL == gpServiceOpts->pExecuteOpts)
        || (NULL == gpServiceOpts->pTapsStopCallback)
        || (NULL == gpServiceOpts->pTapsStartCallback)
        )
    {
        status = ERR_INVALID_INPUT;
        LOG_ERROR("Invalid execution options, status=%d", status);
        goto exit;
    }
    pExecutionOpts = gpServiceOpts->pExecuteOpts;
#endif /*! __RUN_TAPS_SERVICE__ */

#if defined(__LINUX_RTOS__)
    DB_PRINT("Installing signal handlers ...\n");
    /* Ignore SIGPIPE errors, occur when a socket is closed ungracefully */
    if (SIG_ERR == signal(SIGPIPE, sigpipeHandler))
    {
        LOG_ERROR("Unable to install SIGPIPE signal handler, error code %d\n", errno);
        goto exit;
    }

    /* Install signal handler */
    if ((SIG_ERR == signal(SIGHUP, sigHandler))
            || (SIG_ERR == signal(SIGINT, sigHandler)))
    {
        LOG_ERROR("Unable to install signal handler(s), error code %d\n", errno);
        goto exit;
    }
#endif
    /* Populate entry points, needs to be done at runtime */
#ifdef __ENABLE_DIGICERT_TPM2__
    TAPS_dispatchCommand[TAP_PROVIDER_TPM2] = SMP_TPM2_dispatcher;
#endif

#ifdef __ENABLE_DIGICERT_TPM__
    TAPS_dispatchCommand[TAP_PROVIDER_TPM] = SMP_TPM12_dispatcher;
#endif

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
    TAPS_dispatchCommand[TAP_PROVIDER_PKCS11] = SMP_PKCS11_dispatcher;
#endif

#ifdef __ENABLE_DIGICERT_TEE__
    TAPS_dispatchCommand[TAP_PROVIDER_TEE] = SMP_TEE_dispatcher;
#endif

    status = TAPS_processAcceptRequests();
    if (OK != status)
    {
        if (!quitTime)
            LOG_ERROR("TAPS Failed to startup and accept requests, status = %d", status);
        goto exit;
    }

exit:
    LOG_MESSAGE("TAPS exiting...");

#if defined(__RTOS_LINUX__) && defined(__ENABLE_TAP_REMOTE_UNIX_DOMAIN__)
    if(TAP_UNIX_DOMAIN_SOCKET == pExecutionOpts->serverPort)
    {
        UNIXDOMAIN_CLOSE(tapListenSocket);
        FMGMT_remove (pExecutionOpts->unixServerPath, FALSE);
    }
    else
        TCP_CLOSE_SOCKET(tapListenSocket);
#else
    TCP_CLOSE_SOCKET(tapListenSocket);
#endif
    /* Shut down cleanly */
    fstatus = TAPS_shutdown();
    if (OK == status)
        status = fstatus;

#ifndef __RUN_TAPS_SERVICE__
    DIGI_FREE((void **)&pExecutionOpts) ;
#endif
    DIGICERT_freeDigicert();

    gMocanaAppsRunning--;

#ifndef __RUN_TAPS_SERVICE__
    return status;
#else
    if  (   (NULL != gpServiceOpts)
        &&  (NULL != gpServiceOpts->pTapsStopCallback)
        )
    {
        gpServiceOpts->pTapsStopCallback(status);
    }
    return;
#endif
}

#endif

