/**
 @file moctpm2_evictobject.c

 @page digicert_tpm2_evictobject

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_evictobject -
 @endhtmlonly
 Deletes previously created persistent asymmetric key from file system and TPM2 device.

 # SYNOPSIS
 `digicert_tpm2_evictobject [options]`

 # DESCRIPTION
 <B>digicert_tpm2_evictobject</B> This tool deletes previously created persistent key. 
                                   TAP_Key **ppTapKey,
            The persistent key is removed from the TPM2 device and file system.

@verbatim
    --h [help])
        Display command usage info.
    --conf=[TPM 2.0 configuration file]
        Path to TPM 2.0 module configuration file.   
    --s=[server name]
        Host on which TPM chip is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TPM server is listening.
    --pid=[Persistent Key ID]
        (Mandatory) Persistent Key ID where object will be removed from. Must be hex value between 0x81000000 - 0x81ffffff
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO

 # Reporting Bugs
  Report bugs to <Support@digicert.com>

 # Copyright

 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../../data_protection/file_protect.h"
#endif
#include "../../tap_api.h"
#include "../../tap_smp.h"
#include "../../tap_utils.h"
#include "../../tap_serialize.h"
#include "../../tap_serialize_smp.h"
#include "../moctap_tools_utils.h"
#include "../../../smp/smp_tpm2/smp_tap_tpm2.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../common/mcmdline.h"
#endif

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096

#define TPM2_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define PRINT_STATUS(x,y)   \
    DB_PRINT("%s %s status %d = %s\n", x, (y==OK ? "SUCCESS":"FAILED"),\
                y, MERROR_lookUpErrorCode(y))


typedef struct {
    byteBoolean exitAfterParse;

    TAP_AUTH_CONTEXT_PROPERTY authContext;
    byteBoolean authContextSpecified;

#ifdef __ENABLE_TAP_REMOTE__
    ubyte4 serverNameLen;
    ubyte4 serverPort;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

#endif
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];

    TAP_ModuleId moduleNum;

    ubyte objectIdSpecified;
    ubyte4 objectId;

    ubyte idBuf[8];
    TAP_Buffer id;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_evictobject: Help Menu\n");
    LOG_MESSAGE("This tool removes object at a persistent index.\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [display command line options]");
    LOG_MESSAGE("                   Help menu\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[server name]");
    LOG_MESSAGE("                   Mandatory. Host on which TPM chip is located.  This can be 'localhost' or a\n"
                "                   remote host running a TAP server.\n");
    LOG_MESSAGE("           --p=[server port]");
    LOG_MESSAGE("                   Port on which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[TPM 2.0 configuration file]");
    LOG_MESSAGE("                   Path to TPM 2.0 module configuration file.\n");
#endif
    LOG_MESSAGE("           --modulenum=[module num]");
    LOG_MESSAGE("                   Specify the module num to use. If not provided, the first module found is used.\n");
    LOG_MESSAGE("           --pid=[Persistent Key ID]");
    LOG_MESSAGE("                   Mandatory. Persistent Key ID where object will be removed.\n"
                "                   Must be hex value between 0x81000000 - 0x8101ffff\n");
    LOG_MESSAGE("           --authcontext=[S | P]");
    LOG_MESSAGE("                Auth-context to use when evicting the key object. (S | P). Default is S (Storage authentitcation), P is for platform\n");
    return;
}

ubyte4 parseObjectId(char *objectStr, int len)
{
    ubyte4 rc = 0xffffffff;
    ubyte4 val = 0;
    int i, base = 1;

    if (len > 2)
    {
        if ((objectStr[0] == '0') && 
                ((objectStr[1] == 'x') || (objectStr[1] == 'X')))
        {
            objectStr += 2;
            len -= 2;
            if (len != sizeof(ubyte4) * 2)
                goto exit;

            for(i = --len; i >= 0; i--)
            {
                if(objectStr[i] >= '0' && objectStr[i] <= '9')
                {
                    val += (objectStr[i] - '0') * base;
                    base *= 16;
                }
                else if(objectStr[i] >= 'A' && objectStr[i] <= 'F')
                {
                    val += (objectStr[i] - 'A') * base;
                    base *= 16;
                }
                else if(objectStr[i] >= 'a' && objectStr[i] <= 'f')
                {
                    val += (objectStr[i] - 'a') * base;
                    base *= 16;
                }
                else
                    goto exit;
            }

            rc = val;
        }
    }

exit:
    return rc;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
            {"authcontext", required_argument, NULL, 11},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 15},
#endif
            {"modulenum", required_argument, NULL, 17},
            {"pid", required_argument, NULL, 18},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 1;
    MSTATUS status;
    ubyte4 optValLen = 0;

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_1("Invalid parameters.");
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
#ifdef __ENABLE_TAP_REMOTE__
                pOpts->serverNameSpecified = TRUE;
                if (DIGI_STRLEN((const sbyte *)optarg) > SERVER_NAME_LEN)
                {
                    LOG_ERROR("Server name too long. Max size: %d bytes",
                            SERVER_NAME_LEN);
                    goto exit;
                }
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg) + 1;
                if ((pOpts->serverNameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            DIGI_STRLEN((const sbyte *)optarg)))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
#else
                LOG_ERROR("Server name not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 3:
#ifdef __ENABLE_TAP_REMOTE__
                pOpts->serverPort = strtol(optarg, NULL, 0);
                if (pOpts->serverPort == 0)
                {
                    LOG_ERROR("Invalid or no port number specified");
                    goto exit;
                }
                if (pOpts->serverPort < 1 || pOpts->serverPort > 65535)
                {
                    LOG_ERROR("Port number must be in the range 1-65535");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 11:
            {
                    /* --authcontext auth-context identifier */
                    OPT_VAL_INFO optionValues[] = {
                        {"S", TAP_AUTH_CONTEXT_STORAGE},
                        {"P", TAP_AUTH_CONTEXT_PLATFORM},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                     ('-' == optarg[0]))
                    {
                        LOG_ERROR("--authcontext auth-context identifier not specified, specify S or P");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        cmpResult = 1;
                        if (DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName) ==
                                DIGI_STRLEN((const sbyte *)optarg))
                        {
                           if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                        DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                            {
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->authContext = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting auth-context identifier to %s",
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--authcontext not S or P");
                        goto exit;
                    }

                    pOpts->authContextSpecified = TRUE;
                }
                break;

            case 15:
                /* tpm2 config file path */
                pOpts->isConfFileSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen > FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max size: %d bytes",
                            FILE_PATH_LEN);
                    goto exit;
                }
                if ((0 >= optValLen) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Configuration file path not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("TPM2 Configuration file path: %s", 
                                 pOpts->confFilePath);

                break;

            case 17:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
                break;

            case 18:
                /* We get the id as a ubyte4 to validate it, and then get it as a TAP_Buffer */
                pOpts->objectIdSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                pOpts->objectId = parseObjectId(optarg, optValLen);

                if (pOpts->objectId < 0x81000000 || pOpts->objectId > 0x81ffffff)
                {
                    LOG_ERROR("Invalid --pid, must be value between 0x81000000 - 0x81ffffff");
                    goto exit;
                }

                if (EK_OBJECT_ID == pOpts->objectId)
                {
                    LOG_ERROR("Invalid --pid, cannot delete the EK Object");
                    goto exit;
                }

                if (SRK_OBJECT_ID_START == pOpts->objectId)
                {
                    LOG_ERROR("Invalid --pid, cannot delete the SRK Object");
                    goto exit;
                }

                status = DIGI_ATOH((ubyte *) &optarg[2], optValLen - 2, (ubyte *)pOpts->idBuf);
                if (OK != status)
                {
                    LOG_ERROR("--pid invalid hex value\n");
                    goto exit;
                }

                TPM2_DEBUG_PRINT("TPM2 Object ID: 0x%08x", pOpts->objectId);
                
                pOpts->id.pBuffer = (ubyte *) pOpts->idBuf;
                pOpts->id.bufferLen = (optValLen - 2)/2;

                break;

            default:
                pOpts->exitAfterParse = TRUE;
                goto exit;
                break;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

static TAP_Module *getTapModule(TAP_ModuleList *pModuleList, TAP_ModuleId moduleNum)
{
    ubyte4 i;
    TAP_Module *pModule = NULL;

    if (NULL != pModuleList)
    {
        if (0 == moduleNum)
        {
            if (0 < pModuleList->numModules)
                pModule = &(pModuleList->pModuleList[0]);
        }
        else
        {
            for (i = 0; i < pModuleList->numModules; i++)
            {
                if (pModuleList->pModuleList[i].moduleId == moduleNum)
                {
                    pModule = &(pModuleList->pModuleList[i]);
                    break;
                }
            }
        }
    }
    return pModule;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = ERR_GENERAL;
    TAP_KeyInfo keyInfo = {0};
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_Key *pLoadedTapKey = NULL;
    TAP_Buffer keyBlob = {0};
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_STORAGE;
    TAP_Attribute keyAttribute[] = {
                { TAP_ATTR_AUTH_CONTEXT,
                sizeof(TAP_AUTH_CONTEXT_PROPERTY), &authContext }
            };
    TAP_AttributeList setAttributes = { 1, keyAttribute}  ;
    /*int numCredentials = 0;
    int i = 0;*/

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (TRUE == pOpts->authContextSpecified)
    {
        authContext = pOpts->authContext;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                &pOpts->serverPort);

    }

    if (!pOpts->serverNameSpecified || !pOpts->objectIdSpecified)
    {
        LOG_ERROR("One of mandatory option --s, --pid not specified."); 
        goto exit;
    }
#else
    if (!pOpts->objectIdSpecified)
    {
        LOG_ERROR("One of mandatory option --pid "
                "not specified.");
        printHelp();
        retval = 0;
        goto exit;
    }
#endif

#ifdef __ENABLE_TAP_REMOTE__
    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) && 
            DIGI_STRNICMP((const sbyte *)pOpts->serverName, 
                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;   
    }
#endif

#ifndef __ENABLE_TAP_REMOTE__
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }
    if (TRUE == pOpts->isConfFileSpecified)
    {
        pTpm2ConfigFile = pOpts->confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pTpm2ConfigFile, TPM2_CONFIGURATION_FILE);
        if (OK != status)
        {
            goto exit;
        }
#else
        pTpm2ConfigFile = TPM2_CONFIGURATION_FILE;
#endif
    }

    status = TAP_readConfigFile(pTpm2ConfigFile,
            &configInfoList.pConfig[0].configInfo,
            pOpts->isConfFileSpecified);
    if (OK != status)
    {
        LOG_ERROR("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_init", status);
        goto exit;
    }
    tapInit = TRUE;

#ifdef __ENABLE_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
    connInfo.serverName.bufferLen = pOpts->serverNameLen;
    connInfo.serverPort = pOpts->serverPort;
#endif


#ifdef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, pErrContext);

#endif
    if (OK != status)
    {
        PRINT_STATUS("TAP_getModuleList", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        LOG_ERROR("No TPM2 modules found\n");
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(getTapModule(&moduleList, pOpts->moduleNum), 
            pTpm2ConfigFile, pOpts->isConfFileSpecified,
            &pEntityCredentials,
            pErrContext);

    if (OK != status)
    {    
        PRINT_STATUS("Failed to get credentials from Credential configuration file", status);
        goto exit;
    } 
#endif

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), pEntityCredentials,
                                NULL, &pTapContext, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_initContext", status);
        goto exit;
    }
    contextInit = TRUE;

    /* Invoke TAP API */
    status = TAP_evictObject(
        pTapContext, &pOpts->id, &setAttributes, pErrContext);
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to evict key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    LOG_MESSAGE("Successfully deleted key\n");
    retval = 0;

exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if ((NULL != pTpm2ConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif

    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&keyBlob.pBuffer);

    if (NULL != pEntityCredentials)
    {
        TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
    
        DIGI_FREE((void **)&pEntityCredentials);
    }

    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);   
    }
    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        status = TAP_uninitContext(&pTapContext, &errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
    }
    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(&errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
    }
    /* Free module list */
    if ((TRUE == gotModuleList) && (moduleList.pModuleList))
    {
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
    }
    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeConfigInfoList", status);
    }

    return retval;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts *pOpts = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    DIGICERT_initDigicert();

    if (NULL == platCmdLineParser)
    {
        TPM2_DEBUG_PRINT_1("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        TPM2_DEBUG_PRINT_1("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        TPM2_DEBUG_PRINT_1("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_1("Failed to create key.");
        goto exit;
    }

    retval = 0;

exit:
    if (pOpts)
    {
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);
    }

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_evictobject failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

