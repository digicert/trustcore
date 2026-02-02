/**
 @file moctap_createpolicystorage.c

 @page moctap_createpolicystorage

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_createpolicystorage-
 @endhtmlonly
 configures the NVRAM format at the specified index in the TPM.

 # SYNOPSIS
 `moctap_createpolicystorage [options]`

 # DESCRIPTION
 <B>moctap_createpolicystorage</B> This tool configures the policy store format at the specified index in the Security Module.

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
        Policy store access authorization password. If none is specified, the well-known password is used.
    --psidx=[policy storage index]
        (Mandatory) Index of the NVRAM to be configured. Hex values must be prefixed with a "0x"
    --pssize=[size of the policy storage index]
        (Mandatory) Size of data in bytes at NVRAM index
    --pstype=[policy storage index type]
        (Mandatory) Type of the NVRAM index (ordinary, counter, bits, extend) to configure.

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
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096
#define TAPTOOL_CREDFILE_NAME_LEN  256
#define MAX_PASSWORD_LEN 256
#define MIN_PORT_NUMBER 1
#define MAX_PORT_NUMBER 65535

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

    byteBoolean nvSizeSpecified;
    ubyte4 nvSize;

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
    LOG_MESSAGE("moctap_createpolicystorage: Help Menu\n");
    LOG_MESSAGE("This tool configures the NVRAM format at the specified index in the TPM.");

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
    LOG_MESSAGE("               Provider label for the Security Module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("               Specify the module ID to use..\n");
    LOG_MESSAGE("           --pspwd=[policy store password]");
    LOG_MESSAGE("                   Policy store access authorization password.\n"
                "                   If none is specified, the well-known password is used.\n");
    LOG_MESSAGE("           --psidx=[policy store index]");
    LOG_MESSAGE("                   (Mandatory) Index of the policy store to be configured. Hex values must be prefixed with \"0x\". \n");
    LOG_MESSAGE("           --pssize=[size of the policy store index]");
    LOG_MESSAGE("                   (Mandatory) Type of the policy store index (ordinary, counter, bits, extend) to configure.\n");
    LOG_MESSAGE("           --pstype=[policy store index type]");
    LOG_MESSAGE("                   (Mandatory) Type of the policy store index (ordinary, counter, bits, extend) to configure.\n");
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
            {"pssize", required_argument, NULL, 6},
            {"pstype", required_argument, NULL, 7},
            {"conf", required_argument, NULL, 8},
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
                pOpts->serverNameSpecified = TRUE;
                if (DIGI_STRLEN((const sbyte *)optarg) >= SERVER_NAME_LEN)
                {
                    LOG_ERROR("Server name too long. Max size: %d bytes",
                            SERVER_NAME_LEN - 1);
                    goto exit;
                }
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);
                if ((pOpts->serverNameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            DIGI_STRLEN((const sbyte *)optarg)))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverName[DIGI_STRLEN((const sbyte *)optarg)] = '\0';
                MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
                break;

            case 3:
                {
                    char *endptr = NULL;
                    long portNum;
                    
                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("Port number not specified");
                        goto exit;
                    }
                    
                    errno = 0;
                    portNum = strtol(optarg, &endptr, 0);
                    
                    /* Check for conversion errors */
                    if (errno == ERANGE || endptr == optarg || *endptr != '\0')
                    {
                        LOG_ERROR("Invalid port number format");
                        goto exit;
                    }
                    
                    /* Check for valid port range */
                    if (portNum < MIN_PORT_NUMBER || portNum > MAX_PORT_NUMBER)
                    {
                        LOG_ERROR("Port number must be between %d and %d",
                                MIN_PORT_NUMBER, MAX_PORT_NUMBER);
                        goto exit;
                    }
                    
                    pOpts->serverPort = (ubyte4)portNum;
                    MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
                break;
#endif
            case 4:
                /* --pspwd password */
                pOpts->authSpecified = TRUE;
                pOpts->authValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (pOpts->authValue.bufferLen == 0)
                {
                    LOG_ERROR("Password not specified");
                    goto exit;
                }
                
                if (pOpts->authValue.bufferLen > MAX_PASSWORD_LEN)
                {
                    LOG_ERROR("Password too long. Max size: %d bytes",
                            MAX_PASSWORD_LEN);
                    goto exit;
                }

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
                    DIGI_FREE(&pOpts->authValue.pBuffer);
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                MOCTAP_DEBUG_PRINT("NVRAM password: %s", optarg); 

                break;

            case 5:
                /* --psidx NVRAM index value */
                pOpts->nvIndexSpecified = TRUE;

                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-psidx NV index not specified");
                    goto exit;
                }

                if ((DIGI_STRLEN((const sbyte *)optarg) > 2) &&
                    ('0' == optarg[0]) && ('x' == optarg[1]))
                {
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
                    const sbyte *endPtr = NULL;
                    pOpts->nvIndex = DIGI_ATOL((const sbyte *)optarg, &endPtr);
                    if ((NULL != endPtr) && (*endPtr != '\0'))
                    {
                        LOG_ERROR("Invalid NV index value");
                        goto exit;
                    }
                }

                MOCTAP_DEBUG_PRINT("NVRAM Index: %d", pOpts->nvIndex);

                break;

            case 6:
                /* --pssize NVRAM index size */
                {
                    const sbyte *endPtr = NULL;
                    
                    pOpts->nvSizeSpecified = TRUE;
                    
                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("NV size not specified");
                        goto exit;
                    }
                    
                    pOpts->nvSize = DIGI_ATOL((const sbyte *)optarg, &endPtr);
                    
                    if ((NULL != endPtr) && (*endPtr != '\0'))
                    {
                        LOG_ERROR("Invalid NV size value");
                        goto exit;
                    }
                    
                    if (pOpts->nvSize == 0)
                    {
                        LOG_ERROR("NV size cannot be zero");
                        goto exit;
                    }

                    MOCTAP_DEBUG_PRINT("NVRAM index size: %d", pOpts->nvSize);
                }
                break;

            case 7:
                {
                    /* --pstype NVRAM index type */
                    pOpts->nvTypeSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"ordinary", TAP_WRITE_OP_DIRECT},
                        {"counter", TAP_WRITE_OP_FILL},
                        {"bits", TAP_WRITE_OP_BIT_SET},
                        {"extend", TAP_WRITE_OP_EXTEND},
                        {NULL, 0},
                    };
                    ubyte oIndex;
                
                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-pstype NV index type not specified");
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
                }
                break;
            case 8:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                pOpts->isConfFileSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max size: %d bytes",
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
#else
                LOG_ERROR("Provider configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
                break;
            case 9:
                /* --provider name */
                pOpts->prNameSpecified = TRUE;
            
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
                break;

            case 10:
                /* --mid module id */
                {
                    char *endptr = NULL;
                    long moduleIdVal;
                    
                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("Module id not specified");
                        goto exit;
                    }
                    
                    errno = 0;
                    moduleIdVal = strtol(optarg, &endptr, 0);
                    
                    /* Check for conversion errors */
                    if (errno == ERANGE || endptr == optarg || *endptr != '\0')
                    {
                        LOG_ERROR("Invalid module id format");
                        goto exit;
                    }
                    
                    if (moduleIdVal < 0)
                    {
                        LOG_ERROR("Module id cannot be negative");
                        goto exit;
                    }
                    
                    pOpts->moduleId = (TAP_ModuleId)moduleIdVal;
                    MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
                    pOpts->modIdSpecified = TRUE;
                }
                break;
            
            case 11:
                /* --cred credential file */
                pOpts->credFileSpecified = TRUE;
                if (DIGI_STRLEN((const sbyte *)optarg) >= TAPTOOL_CREDFILE_NAME_LEN)
                {
                    LOG_ERROR("credential file name too long. Max size: %d bytes",
                            TAPTOOL_CREDFILE_NAME_LEN - 1);
                    goto exit;
                }
                filenameLen = DIGI_STRLEN((const sbyte *)optarg);
                if ((filenameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--cred credential file name not specified");
                    goto exit;
                }
            
                if (OK != DIGI_MEMCPY(pOpts->credFileName, optarg,
                        DIGI_STRLEN((const sbyte *)optarg)))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->credFileName[DIGI_STRLEN((const sbyte *)optarg)] = '\0';
                MOCTAP_DEBUG_PRINT("cred file name name: %s", pOpts->credFileName);
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
    TAP_ErrorContext errContext = NULL;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Context *pTapContext = NULL;
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_CredentialList   storageCredentials = {0} ;
    TAP_StorageInfo storageInfo = {0} ;
    ubyte tapInit = FALSE;
    ubyte contextInit = FALSE;
    ubyte gotModuleList = FALSE;

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
            (pOpts->nvTypeSpecified == FALSE) || (pOpts->nvSizeSpecified == FALSE)
            || (pOpts->prNameSpecified == FALSE) || (pOpts->modIdSpecified == FALSE))
             
    {
        LOG_ERROR("One or more mandatory options --pssize, --psidx, --pstype, --pn, --mid not specified.");
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
    configInfoList.pConfig[0].provider =  pOpts->pTapProviderEntry->providerType;
#endif
    
    status = TAP_init(&configInfoList, &errContext);
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
    
        status = DIGI_CALLOC((void **) &(storageCredentials.pCredentialList), 1,
                        sizeof(TAP_Credential));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }
    
    
        storageCredentials.numCredentials = 1;
    
        storageCredentials.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        storageCredentials.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        storageCredentials.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        storageCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->authValue.bufferLen;
        storageCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->authValue.pBuffer;
        pOpts->authValue.pBuffer = NULL;
        pOpts->authValue.bufferLen = 0;
    }

    /* Initialize context on first module*/
    pTapContext = NULL;
    status = TAP_initContext(&(moduleList.pModuleList[0]), pEntityCredentials,
                                NULL, &pTapContext, &errContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_initContext failed with error %d", status);
        goto exit;
    }
    contextInit = TRUE;

    storageInfo.index = pOpts->nvIndex ;
    storageInfo.size = pOpts->nvSize ;
    storageInfo.storageType = pOpts->nvType ;
    storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE) ;
    storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE) ;
    storageInfo.pAttributes = NULL ;
    /* Allocate policy */
    status = TAP_allocatePolicyStorage(pTapContext, pEntityCredentials, &storageInfo,
                                         NULL, &storageCredentials, 
                                         &errContext);


    if (OK != status)
    {
        LOG_ERROR("Error allocating policy storage, status = %d\n", status);
        goto exit;
    }
    else
    {
        retval = 0;
        PRINT_STATUS("Storage object created successfully ", status);
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
        status = TAP_uninitContext(&pTapContext, &errContext);
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
    if (NULL != storageCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&storageCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);   
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

 /*   if (NULL != userCredBuf.pBuffer)
        DIGICERT_freeReadFile(&userCredBuf.pBuffer);*/

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
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
        MOCTAP_DEBUG_PRINT_1("Failed to configure NVRAM index");
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
        LOG_ERROR("*****moctap_createpolicystorage failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

