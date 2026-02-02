/**
 @file moctpm2_setpolicystorage.c

 @page digicert_tpm2_setpolicystorage

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_setpolicystorage -
 @endhtmlonly
 This tool writes data to the specified index of the NVRAM.

 # SYNOPSIS
 `digicert_tpm2_setpolicystorage [options]`

 # DESCRIPTION
 <B>digicert_tpm2_setpolicystorage</B> This tool writes data to the specified index of the NVRAM.

@verbatim

    --h [display command line options]
        Help menu
    --conf=[TPM 2.0 configuration file]
        Path to TPM 2.0 module configuration file. 
    --s=[server name]
        Host on which TPM chip is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TPM server is listening.
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
    --pspwd=[policy storage password]
        NVRAM write password.
        If not specified , the well-known password is used.
    --psidx=[policy storage index]    
        (Mandatory) Index of the NVRAM to write. Hex values must be prefixed with a "0x"
    --idf=[input data file]
         (Mandatory) Input file containing data to write.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim

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
#include "../../../common/mprintf.h"
#include "../../../common/debug_console.h"
#include "../../../common/vlong.h"
#include "../../../crypto/sha1.h"
#include "../../../crypto/sha256.h"
#include "../../../crypto/sha512.h"
#include "../../tap_api.h"
#include "../../tap_common.h"
#include "../../tap_utils.h"
#include "../../tap_serialize.h"
#include "../../tap_serialize_smp.h"
#include "../moctap_tools_utils.h"
#include "../../../smp/smp_tpm2/smp_tap_tpm2.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
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

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

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

    byteBoolean authSpecified;
    TAP_Buffer authValue;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean nvIndexSpecified;
    ubyte4 nvIndex;

    byteBoolean inNVFileSpecified;
    TAP_Buffer inNVFile;

    ubyte4 serverNameLen;
    ubyte4 serverPort;

    TAP_AUTH_CONTEXT_PROPERTY authContext;
    byteBoolean authContextSpecified;

#ifndef __ENABLE_TAP_REMOTE__ 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* !__ENABLE_TAP_REMOTE__ */

    TAP_ModuleId moduleNum;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_setpolicystorage: Help Menu\n");
    LOG_MESSAGE("This tool writes data to the specified index of the NVRAM in the TPM.");

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
    LOG_MESSAGE("           --pspwd=[policy storage password]");
    LOG_MESSAGE("                   NVRAM write password.\n"
                "                   If not specified , the well-known password is used.\n");
    LOG_MESSAGE("           --psidx=[policy storage index]");
    LOG_MESSAGE("                   (Mandatory) Index of the NVRAM to write. Hex values must be prefixed with a \"0x\"\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file containing data to write.\n");
    LOG_MESSAGE("           --authcontext=[S | P]");
    LOG_MESSAGE("                Auth-context to use for NVRAM. (S | P). Default is S (Storage authentitcation), P is for platform\n");

    return;
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
#ifdef __ENABLE_TAP_REMOTE__
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
#endif
            {"pspwd", required_argument, NULL, 4},
            {"psidx", required_argument, NULL, 5},
            {"idf", required_argument, NULL, 6},
            {"hpass", required_argument, NULL, 8},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 9},
#endif
            {"modulenum", required_argument, NULL, 10},
            {"authcontext", required_argument, NULL, 11},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult = 1;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif

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
#ifdef __ENABLE_TAP_REMOTE__
            case 2:
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
                    LOG_ERROR("--s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            DIGI_STRLEN((const sbyte *)optarg)))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
                break;

            case 3:
                pOpts->serverPort = strtol(optarg, NULL, 0);
                if (pOpts->serverPort == 0)
                {
                    LOG_ERROR("Invalid or no port number specified");
                    goto exit;
                }

                if (pOpts->serverPort < 1 || pOpts->serverPort > 65535)
                {
                    LOG_ERROR("Invalid server port: %d. Port must be between 1 and 65535.", pOpts->serverPort);
                    goto exit;
                }

                TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                break;
#endif
            case 4:
                /* --pspwd policy storage password */
                pOpts->authSpecified = TRUE;
                pOpts->authValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->authValue.pBuffer, 
                                pOpts->authValue.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for password",
                            (int)pOpts->authValue.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->authValue.pBuffer, optarg, 
                            pOpts->authValue.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Policy storage write password: %s", optarg); 

                break;

            case 5:
                /* --psidx policy storage index value */
                pOpts->nvIndexSpecified = TRUE;

                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--psidx Policy storage index not specified");
                    goto exit;
                }

                if (('0' == optarg[0]) && ('x' == optarg[1]))
                {
                    if (OK != DIGI_convertHexString((const char *)&optarg[2], 
                            (ubyte *)&pOpts->nvIndex, sizeof(pOpts->nvIndex)))
                    {
                        TPM2_DEBUG_PRINT_1("Failed to convert hex string");
                        goto exit;
                    }
                    pOpts->nvIndex = DIGI_NTOHL((ubyte *)&pOpts->nvIndex);
                }
                else
                {
                    pOpts->nvIndex = DIGI_ATOL((const sbyte *)optarg, NULL);
                }

                TPM2_DEBUG_PRINT("NVRAM Index: %d", pOpts->nvIndex);

                break;

            case 6:
                /* --idf input data file */
                pOpts->inNVFileSpecified = TRUE;
                pOpts->inNVFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->inNVFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--idf NV input file not specified");
                    goto exit;
                }

                if (pOpts->inNVFile.bufferLen > FILE_PATH_LEN)
                {
                    LOG_ERROR("NVRAM input file path too long. Max size: %d bytes", FILE_PATH_LEN);
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->inNVFile.pBuffer, 
                                pOpts->inNVFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for signature filename",
                            (int)pOpts->inNVFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->inNVFile.pBuffer, optarg, 
                            pOpts->inNVFile.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("NVRAM input filename: %s", pOpts->inNVFile.pBuffer);

                break;
                
                case 9:
                    /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
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
#else
                    LOG_ERROR("TPM2 configuration file path not a "
                              "valid option in a local-only build\n");
                    goto exit;
#endif
                break;
            case 10:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
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
    MSTATUS status;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ConfigInfoList configInfoList = {0,};
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Buffer nvIn = { 0 };
    TAP_CredentialList keyCredentials = { 0 }; 
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_STORAGE;
    TAP_Attribute keyAttribute[] = {
                { TAP_ATTR_AUTH_CONTEXT,
                sizeof(TAP_AUTH_CONTEXT_PROPERTY), &authContext },
                { TAP_ATTR_CREDENTIAL_SET,
                sizeof(TAP_CredentialList), &keyCredentials }
            };
    TAP_AttributeList setAttributes = { 2, keyAttribute}  ;
    ubyte4 numAttrs = 1;
    /*TAP_EntityCredentialList entityCredentials = { 0 };*/
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_ObjectInfo              *pObjectInfo = NULL;
    TAP_ObjectInfoList          objectInfoList = {0};
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
/*    int numCredentials = 0;*/
    int i = 0;

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    if ( !pOpts->nvIndex || 
            !pOpts->inNVFileSpecified) 
    {
        LOG_ERROR("One or more mandatory options --psidx, --idf not specified.");
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

    if (!pOpts->serverNameSpecified)
    {
        LOG_ERROR("Mandatory option --s, not specified.");
        goto exit;
    }
    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) && 
            DIGI_STRNICMP((const sbyte *)pOpts->serverName, 
                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;   
    }
#endif

#ifndef __ENABLE_TAP_REMOTE__
    /* We only get the config information for a local-only build.  For a remote build, the server has the info. */

    status = DIGI_CALLOC((void **) &(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
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
        TPM2_DEBUG_PRINT("TAP_init",status);
        goto exit;
    }
    tapInit = TRUE;


    /* Discover modules */
#ifdef __ENABLE_TAP_REMOTE__
    connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
    connInfo.serverName.bufferLen = pOpts->serverNameLen;
    connInfo.serverPort = pOpts->serverPort;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
            &moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
            &moduleList, pErrContext);
#endif

    if (OK != status)
    {
        LOG_ERROR("TAP_getModuleList failed with error %d", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
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

    if ((0 != pOpts->authValue.bufferLen) && (NULL != pOpts->authValue.pBuffer))
    {
        status = DIGI_CALLOC((void **) &(keyCredentials.pCredentialList), 1, sizeof(TAP_Credential));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }

        keyCredentials.numCredentials = 1;

        keyCredentials.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        keyCredentials.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        keyCredentials.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        keyCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->authValue.bufferLen;
        keyCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->authValue.pBuffer;
    }


    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), pEntityCredentials,
            NULL, &pTapContext, pErrContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_initContext failed with error %d", status);
        goto exit;
    }
    contextInit = TRUE;

    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->inNVFile.pBuffer,
            &nvIn.pBuffer, &nvIn.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error reading NVRAM contents from file, status = %d\n", status);
        goto exit;
    }

    status = TAP_getPolicyStorageList(pTapContext, pEntityCredentials, NULL,
            &objectInfoList, pErrContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_getPolicyStorageList failed with error %d", status);
        goto exit;
    }

    for(i= 0 ; i < objectInfoList.count ; i++)
    {
        if(objectInfoList.pInfo[i].objectId == pOpts->nvIndex) 
            break ;
    }
    if(i == objectInfoList.count)
    {
        LOG_ERROR("Invalid storage index %d\n", pOpts->nvIndex);
        goto exit;

    }
    pObjectInfo = &objectInfoList.pInfo[i];

    if (TRUE == pOpts->authContextSpecified)
    {
        authContext = pOpts->authContext;
    }

    /* Write, must be done before getPolicy */
    status = TAP_setPolicyStorage(pTapContext, pEntityCredentials, pObjectInfo, &setAttributes, 
            &nvIn, pErrContext);

    if (OK != status)
    {
        LOG_ERROR("Error writing NVRAM, status = %d\n", status);
        goto exit;
    }
    else
    {
        retval = 0;
    }


exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if ((NULL != pTpm2ConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif

    if ((TRUE == gotModuleList) && (NULL != moduleList.pModuleList))
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
    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        status = TAP_uninitContext(&pTapContext, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
    }
    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials);
    }

    if (NULL != keyCredentials.pCredentialList)
    {
        status = DIGI_FREE((void**)&keyCredentials.pCredentialList);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }

    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
    }

    if (NULL != nvIn.pBuffer)
        DIGI_FREE((void **)&nvIn.pBuffer);

    if(NULL != objectInfoList.pInfo)
        DIGI_FREE((void**)&objectInfoList.pInfo);

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->inNVFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inNVFile.pBuffer);
        if (pOpts->authValue.pBuffer)
            shredMemory((ubyte **)&(pOpts->authValue.pBuffer), pOpts->authValue.bufferLen, TRUE);
    }

    return;
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
        TPM2_DEBUG_PRINT_1("Failed to write at specified NVRAM index");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
    {
        freeOptions(pOpts);

        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);
    }

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_setpolicystorage failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

