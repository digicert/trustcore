/**
 @file moctap_setpolicystorage.c

 @page moctap_setpolicystorage

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_setpolicystorage -
 @endhtmlonly
 This tool writes data to the specified index of the NVRAM.

 # SYNOPSIS
 `moctap_setpolicystorage [options]`

 # DESCRIPTION
 <B>moctap_setpolicystorage</B> This tool writes data to the specified index of the policy store.

@verbatim

    --h [option(s)]
        Display help for the specified option(s).
    --conf=[Security Module configuration file]
        Path to Security Module configuration file.
    --s=[server name]
        Host on which TPM chip is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TPM server is listening.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use. 
    --pspwd=[policy storage password]
        Policy store write password. If not specified, the well-known password is used.
    --psidx=[policy storage index]    
        (Mandatory) (Mandatory) Index of the policy store to write. Hex values must be prefixed with 0x.
    --pstype=[type of policy storage index]
        (Mandatory) Type of NVRAM index (ordinary, counter, bits, extend) to write.
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
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mprintf.h"
#include "../../common/vlong.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../tap_api.h"
#include "../tap_common.h"
#include "../tap_utils.h"
#include "../tap_serialize.h"
#include "../tap_serialize_smp.h"
#include "../../smp/smp_tpm2/smp_tap_tpm2.h"
#include "moctap_tools_utils.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif
#if defined (__RTOS_WIN32__)
#include "../../common/mcmdline.h"
#include "errno.h"
#endif

#define IS_VALID_PORT(p) ((p) > 0 && (p) <= 65535)
#define MAX_PASSWORD_LEN 256
#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096
#define TAPTOOL_CREDFILE_NAME_LEN  256

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean authSpecified;
    TAP_Buffer authValue;

    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];
    
    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean nvIndexSpecified;
    ubyte4 nvIndex;

    byteBoolean nvTypeSpecified;
    ubyte4 nvType;

    byteBoolean inNVFileSpecified;
    TAP_Buffer inNVFile;

    ubyte4 serverNameLen;
    ubyte4 serverPort;

#ifndef __ENABLE_TAP_REMOTE__ 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* !__ENABLE_TAP_REMOTE__ */

} cmdLineOpts;

extern MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen, 
      TAP_EntityCredentialList **pUsageCredentials) ;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("moctap_nvwrite: Help Menu\n");
    LOG_MESSAGE("This tool writes data to the specified index of the policy store.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [option(s)]");
    LOG_MESSAGE("                   Display help for the specified option(s).\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[TAP server name or module path]");
    LOG_MESSAGE("                   Mandatory option. Specify the server name such as localhost or\n"
            "                       module path such as /dev/tpm0.\n");
    LOG_MESSAGE("           --p=[TAP server port]");
    LOG_MESSAGE("                   Port at which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[Security Module configuration file]");
    LOG_MESSAGE("                   Path to Security Module configuration file.\n");
#endif
    LOG_MESSAGE("           --pn=[provider name]");
    LOG_MESSAGE("                   Provider label for the Security Module..\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use.\n");
    LOG_MESSAGE("           --pspwd=[policy store password]");
    LOG_MESSAGE("                   Policy store write password. If not specified, the well-known password is used.\n");
    LOG_MESSAGE("           --psidx=[policy store password]");
    LOG_MESSAGE("                   (Mandatory) Index of the policy store to write. Hex values must be prefixed with\"0x\"\n");
    LOG_MESSAGE("           --pstype=[type of policy store index]");
    LOG_MESSAGE("                   (Mandatory) Type of policy store index (ordinary, counter, bits, extend) to write.\n");
    LOG_MESSAGE("           --idf=[input file]");
    LOG_MESSAGE("                   (Mandatory) Input file containing data to write.\n");
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
            {"pstype", required_argument, NULL, 7},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 8},
#endif
            {"pn", required_argument, NULL, 9},
            {"mid", required_argument, NULL, 10},
            {"cred", required_argument, NULL, 11},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult = 1;
    sbyte4 filenameLen ;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif

    if (!pOpts || !argv || (0 == argc))
    {
        MOCTAP_DEBUG_PRINT_1("Invalid parameters.");
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
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->serverNameLen >= SERVER_NAME_LEN)
                {
                    LOG_ERROR("Server name too long. Max length: %d characters",
                            SERVER_NAME_LEN - 1);
                    goto exit;
                }
                if ((pOpts->serverNameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverName[pOpts->serverNameLen] = '\0';
                MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
                pOpts->serverNameSpecified = TRUE;
                break;

            case 3:
                {
                    char *endptr;
                    long port;
                    errno = 0;
                    port = strtol(optarg, &endptr, 0);
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                        !IS_VALID_PORT(port))
                    {
                        LOG_ERROR("Invalid port number. Port must be between 1 and 65535");
                        goto exit;
                    }
                    pOpts->serverPort = (ubyte4)port;
                    MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
                break;
#endif
            case 4:
                /* --pspwd password */
                {
                    ubyte4 passwordLen = DIGI_STRLEN((const sbyte *)optarg);
                    
                    if ((passwordLen == 0) || ('-' == optarg[0]))
                    {
                        LOG_ERROR("--pspwd password not specified");
                        goto exit;
                    }
                    
                    if (passwordLen > MAX_PASSWORD_LEN)
                    {
                        LOG_ERROR("Password too long. Max length: %d characters", MAX_PASSWORD_LEN);
                        goto exit;
                    }
                    
                    pOpts->authValue.bufferLen = passwordLen;
                    
                    if (OK != (status = DIGI_MALLOC((void **)&pOpts->authValue.pBuffer, 
                                    passwordLen + 1)))
                    {
                        LOG_ERROR("Unable to allocate %d bytes for password",
                                (int)(passwordLen + 1));
                        goto exit;
                    }
                    if (OK != DIGI_MEMCPY(pOpts->authValue.pBuffer, optarg, passwordLen))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->authValue.pBuffer);
                        pOpts->authValue.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->authValue.pBuffer[passwordLen] = '\0';
                    pOpts->authSpecified = TRUE;
                }
                break;

            case 5:
                /* --psidx NVRAM index value */
                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-psidx NV index not specified");
                    goto exit;
                }

                if (('0' == optarg[0]) && ('x' == optarg[1]))
                {
                    if (optarg[2] == '\0')
                    {
                        LOG_ERROR("-psidx Invalid hex value: no digits after 0x");
                        goto exit;
                    }
                    if (OK != DIGI_convertHexString((const char *)&optarg[2], 
                            (ubyte *)&pOpts->nvIndex, sizeof(pOpts->nvIndex)))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to convert hex string");
                        goto exit;
                    }
                    pOpts->nvIndex = DIGI_NTOHL((ubyte *)&pOpts->nvIndex);
                }
                else
                {
                    char *endptr;
                    long nvIdx;
                    errno = 0;
                    nvIdx = strtol(optarg, &endptr, 10);
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (nvIdx < 0))
                    {
                        LOG_ERROR("-psidx Invalid NV index value");
                        goto exit;
                    }
                    pOpts->nvIndex = (ubyte4)nvIdx;
                }

                MOCTAP_DEBUG_PRINT("NVRAM Index: %d", pOpts->nvIndex);
                pOpts->nvIndexSpecified = TRUE;

                break;

            case 6:
                /* --idf input nvram content file */
                {
                    ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                    pOpts->inNVFile.bufferLen = optValLen + 1;

                    if ((optValLen == 0) || ('-' == optarg[0]))
                    {
                        LOG_ERROR("-idf NV input file not specified");
                        goto exit;
                    }

                    if (OK != (status = DIGI_MALLOC((void **)&pOpts->inNVFile.pBuffer, 
                                    pOpts->inNVFile.bufferLen)))
                    {
                        LOG_ERROR("Unable to allocate %d bytes for signature filename",
                                (int)pOpts->inNVFile.bufferLen);
                        goto exit;
                    }
                    if (OK != DIGI_MEMCPY(pOpts->inNVFile.pBuffer, optarg, optValLen))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->inNVFile.pBuffer);
                        pOpts->inNVFile.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->inNVFile.pBuffer[optValLen] = '\0';
                    MOCTAP_DEBUG_PRINT("NVRAM input filename: %s", pOpts->inNVFile.pBuffer);
                    pOpts->inNVFileSpecified = TRUE;
                }
                break;

            case 7:
                {
                    /* --pstype NVRAM index type */
                    OPT_VAL_INFO optionValues[] = {
                        {"ordinary", TAP_WRITE_OP_DIRECT},
                        {"counter", TAP_WRITE_OP_FILL},
                        {"bits", TAP_WRITE_OP_BIT_SET},
                        {"extend", TAP_WRITE_OP_EXTEND},
                        {NULL, 0},
                    };
                    ubyte oIndex;
                    ubyte4 optValLen;
                    ubyte4 optionNameLen;

                    optValLen = DIGI_STRLEN((const sbyte *)optarg);
                    if ((optValLen == 0) || ('-' == optarg[0]))
                    {
                        LOG_ERROR("-pstype NV index type not specified");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        cmpResult = 1;
                        optionNameLen = DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName);
                        if (optionNameLen == optValLen)
                        {
                            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                        optionNameLen, &cmpResult))
                            {
                                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->nvType = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting NVRAM Type to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--pstype not ordinary or counter or bits or extend");
                        goto exit;
                    }
                    pOpts->nvTypeSpecified = TRUE;
                }
                break;
                

                case 8:
                    /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                    optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                    if (optValLen >= FILE_PATH_LEN)
                    {
                        LOG_ERROR("File path too long. Max length: %d characters",
                                FILE_PATH_LEN - 1);
                        goto exit;
                    }
                    if ((0 >= optValLen) || ('-' == optarg[0]))
                    {
                        LOG_ERROR("Configuration file path not specified");
                        goto exit;
                    }

                    if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                        goto exit;
                    }
                    pOpts->confFilePath[optValLen] = '\0';
                    MOCTAP_DEBUG_PRINT("Provider Configuration file path: %s", 
                                     pOpts->confFilePath);
                    pOpts->isConfFileSpecified = TRUE;
#else
                    LOG_ERROR("Provider configuration file path not a "
                              "valid option in a local-only build\n");
                    goto exit;
#endif
                break;

            case 9:
                /* --provider name */
                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--pn provider name not specified");
                    goto exit;
                }
                status = getProviderFromName((const ubyte*)optarg,
                                                &(pOpts->pTapProviderEntry));
                if(OK != status)
                {
                    LOG_ERROR("--pn not a known provider %s", optarg);
                    goto exit;
                }
                pOpts->prNameSpecified = TRUE;
                break;

            case 10:
                /* --mid module id */
                {
                    char *endptr;
                    long moduleId;
                    errno = 0;
                    moduleId = strtol(optarg, &endptr, 0);
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (moduleId < 0))
                    {
                        LOG_ERROR("Invalid or no module id specified");
                        goto exit;
                    }
                    pOpts->moduleId = (TAP_ModuleId)moduleId;
                    MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
                    pOpts->modIdSpecified = TRUE;
                }
                break;

            case 11:
                /* --cred credential file */
                filenameLen = DIGI_STRLEN((const sbyte *)optarg);
                if (filenameLen >= TAPTOOL_CREDFILE_NAME_LEN)
                {
                    LOG_ERROR("credential file name too long. Max length: %d characters",
                            TAPTOOL_CREDFILE_NAME_LEN - 1);
                    goto exit;
                }
                if ((filenameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--cred credential file name not specified");
                    goto exit;
                }
            
                if (OK != DIGI_MEMCPY(pOpts->credFileName, optarg, filenameLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->credFileName[filenameLen] = '\0';
                MOCTAP_DEBUG_PRINT("cred file name name: %s", pOpts->credFileName);
                pOpts->credFileSpecified = TRUE;
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

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status;
    TAP_ConfigInfoList configInfoList = {0,};
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 }; 
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Buffer nvIn = { 0 };
    TAP_CredentialList keyCredentials = { 0 }; 
    /* TAP_Buffer userCredBuf = {0} ;*/
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_ObjectInfo              *pObjectInfo = NULL;
    TAP_ObjectInfoList          objectInfoList = {0};
    ubyte tapInit = FALSE;
    ubyte contextInit = FALSE;
    ubyte gotModuleList = FALSE;
    TAP_Attribute keyAttribute = { TAP_ATTR_CREDENTIAL_SET,
                sizeof(TAP_CredentialList), &keyCredentials };
    TAP_AttributeList setAttributes = { 1, &keyAttribute} ; 
    int i = 0;

    if (!pOpts)
    {
        MOCTAP_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    if ( !pOpts->nvIndex || 
            !pOpts->inNVFileSpecified || (FALSE == pOpts->nvTypeSpecified)
            || (pOpts->prNameSpecified == FALSE) || (pOpts->modIdSpecified == FALSE)) 
    {
        LOG_ERROR("One or more mandatory options --pstype, --psidx, --idf, --pn, --mid not specified.");
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE__
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
        pSmpConfigFile = pOpts->confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pSmpConfigFile, pOpts->pTapProviderEntry->configFilePath);
        if (OK != status)
        {
            goto exit;
        }
#else
        pSmpConfigFile = pOpts->pTapProviderEntry->configFilePath;
#endif
    }

    status = TAP_readConfigFile(pSmpConfigFile,
            &configInfoList.pConfig[0].configInfo,
            pOpts->isConfFileSpecified);
    if (OK != status)
    {
        LOG_ERROR("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = pOpts->pTapProviderEntry->providerType;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        MOCTAP_DEBUG_PRINT("TAP_init",status);
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
    status = TAP_getModuleList(&connInfo, pOpts->pTapProviderEntry->providerType, NULL,
                               &moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, pOpts->pTapProviderEntry->providerType, NULL,
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
        LOG_ERROR("No Provider modules found\n");
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(&(moduleList.pModuleList[0]),
            pSmpConfigFile, pOpts->isConfFileSpecified,
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
        pOpts->authValue.pBuffer = NULL;
        pOpts->authValue.bufferLen = 0;
    }

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(&(moduleList.pModuleList[0]), pEntityCredentials,
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

    /* Write, must be done before getPolicy */
    /*status = TAP_setPolicyStorage(pTapContext, pEntityCredentials, pObjectInfo, &pObjectInfo->objectAttributes, 
            &nvIn, pErrContext);*/
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
    if ((NULL != pSmpConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pSmpConfigFile);
    }
#endif /* defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__) */

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
        DIGI_FREE((void **)&pEntityCredentials) ;
    }

    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }
    /*if (NULL != userCredBuf.pBuffer)
        DIGICERT_freeReadFile(&userCredBuf.pBuffer);*/

    /* Free module list */
    if ((TRUE == gotModuleList) && (moduleList.pModuleList))
    {
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
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

        if (NULL != pOpts->pTapProviderEntry)
            freeTapProviderEntry(&pOpts->pTapProviderEntry);
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
        MOCTAP_DEBUG_PRINT_1("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to write at specified NVRAM index");
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
        LOG_ERROR("*****moctap_setpolicystorage failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

