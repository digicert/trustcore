/**
 @file moctap_delpolicystorage.c

 @page moctap_delpolicystorage

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_delpolicystorage -
 @endhtmlonly
 This tool deletes the NVRAM format at the specified index.

 # SYNOPSIS
 `moctap_delpolicystorage [options]`

 # DESCRIPTION
 <B>moctap_delpolicystorage</B> This tool deletes the policy store format at the specified index in the Security Module.

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
        NVRAM access authorization password.
        If none is specified , the well-known password is used.
    --psidx=[policy storage index]
        (Mandatory) Index of the NVRAM to be deleted. Hex values must be prefixed with "0x" 
    --pssize=[policy storage size]
        (Mandatory:) Size in bytes of the NVRAM index
    --pstype=[NVRAM index type]
        (Mandatory) Type of the NVRAM index (ordinary, counter, bits, extend) to configure.
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
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096
#define TAPTOOL_CREDFILE_NAME_LEN  256
#define MAX_PASSWORD_LEN 256
#define IS_VALID_PORT(p) ((p) > 0 && (p) <= 65535)

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
    LOG_MESSAGE("moctap_delpolicystorage: Help Menu\n");
    LOG_MESSAGE("This tool deletes the policy store format at the specified index in the Security Module.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [option(s)]");
    LOG_MESSAGE("                   Help menu\n");
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
    LOG_MESSAGE("                   Provider label for the Security Module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use\n");
    LOG_MESSAGE("           --pspwd=[policy store password]");
    LOG_MESSAGE("                   Policy store access authorization password. \n"
                "                   If none is specified, the well-known password is used.\n");
    LOG_MESSAGE("           --psidx=[policy store index]");
    LOG_MESSAGE("                   (Mandatory) Index of the policy store to be configured. Hex values must be prefixed with  \"0x\" \n");
    LOG_MESSAGE("           --pssize=[size of the policy store index]");
    LOG_MESSAGE("                   (Mandatory) Size in bytes of the policy store index.\n");
    LOG_MESSAGE("           --pstype=[policy store index type]");
    LOG_MESSAGE("                   (Mandatory) Type of the policy store index (ordinary, counter, bits, extend) to configure. \n");
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

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            pOpts->serverNameLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverNameSpecified = TRUE;
                MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
                break;

            case 3:
                {
                    char *endptr = NULL;
                    long port;

                    errno = 0;
                    port = strtol(optarg, &endptr, 0);

                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                        !IS_VALID_PORT(port))
                    {
                        LOG_ERROR("Invalid or no port number specified");
                        goto exit;
                    }
                    pOpts->serverPort = (ubyte4)port;
                    MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
                break;
#endif
            case 4:
                /* --pspwd password */
                pOpts->authValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if ((pOpts->authValue.bufferLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--pspwd password not specified");
                    goto exit;
                }
                
                if (pOpts->authValue.bufferLen > MAX_PASSWORD_LEN)
                {
                    LOG_ERROR("Password too long. Max length: %d characters",
                            MAX_PASSWORD_LEN);
                    goto exit;
                }

                /* Allocate buffer with space for null terminator */
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->authValue.pBuffer, 
                                pOpts->authValue.bufferLen + 1)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for password",
                            (int)(pOpts->authValue.bufferLen + 1));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->authValue.pBuffer, optarg, 
                            pOpts->authValue.bufferLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->authValue.pBuffer);
                    pOpts->authValue.bufferLen = 0;
                    goto exit;
                }
                /* Add null terminator */
                pOpts->authValue.pBuffer[pOpts->authValue.bufferLen] = '\0';
                pOpts->authSpecified = TRUE;

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
                    /* Validate hex string has content after "0x" */
                    if ('\0' == optarg[2])
                    {
                        LOG_ERROR("Invalid NV index: hex string has no digits after '0x'");
                        goto exit;
                    }
                    
                    if (OK != DIGI_convertHexString((const char *)&optarg[2], 
                                (ubyte *)&pOpts->nvIndex, sizeof(pOpts->nvIndex)))
                    {
                        LOG_ERROR("Invalid NV index: failed to convert hex string");
                        goto exit;
                    }
                    pOpts->nvIndex = DIGI_NTOHL((ubyte *)&pOpts->nvIndex);
                }
                else
                {
                    char *endptr = NULL;
                    long index;
                    
                    errno = 0;
                    index = strtol(optarg, &endptr, 10);
                    
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                        (index < 0))
                    {
                        LOG_ERROR("Invalid NV index value");
                        goto exit;
                    }
                    pOpts->nvIndex = (ubyte4)index;
                }
                pOpts->nvIndexSpecified = TRUE;

                MOCTAP_DEBUG_PRINT("NVRAM Index: %d", pOpts->nvIndex);

                break;

            case 6:
                /* --pssize NVRAM index size */
                {
                    char *endptr = NULL;
                    long size;
                    
                    errno = 0;
                    size = strtol(optarg, &endptr, 10);
                    
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                        (size <= 0))
                    {
                        LOG_ERROR("Invalid or no NV size specified");
                        goto exit;
                    }
                    pOpts->nvSize = (ubyte4)size;
                    pOpts->nvSizeSpecified = TRUE;

                    MOCTAP_DEBUG_PRINT("NVRAM index size: %d", pOpts->nvSize);
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
                    ubyte4 optargLen;
                
                    optargLen = DIGI_STRLEN((const sbyte *)optarg);
                    if ((optargLen == 0) || ('-' == optarg[0]))
                    {
                        LOG_ERROR("-pstype NV index type not specified");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        ubyte4 optionNameLen = DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName);
                        
                        cmpResult = 1;
                        if (optionNameLen == optargLen)
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
                pOpts->isConfFileSpecified = TRUE;
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
                    char *endptr = NULL;
                    long moduleId;
                    
                    errno = 0;
                    moduleId = strtol(optarg, &endptr, 0);
                    
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                        (moduleId < 0))
                    {
                        LOG_ERROR("Invalid or no module id specified");
                        goto exit;
                    }
                    pOpts->moduleId = (TAP_ModuleId)moduleId;
                    pOpts->modIdSpecified = TRUE;
                    
                    MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
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
                pOpts->credFileSpecified = TRUE;
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
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_ErrorContext errContext = NULL;
    /*TAP_ErrorContext *pErrContext = &errContext;*/
    TAP_Context *pTapContext = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_EntityCredentialList *pEntityCredentials = NULL;
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
         (pOpts->prNameSpecified == FALSE) || (pOpts->modIdSpecified == FALSE))             
    {
        LOG_ERROR("One or more mandatory options --psidx, --pn, --mid not specified.");
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
    
    status = TAP_init(&configInfoList, &errContext);
    if (OK != status)
    {
        MOCTAP_DEBUG_PRINT("TAP_init",status);
        goto exit;
    }
    tapInit = TRUE;

/* Discover modules */
#ifdef __ENABLE_TAP_REMOTE__
        connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
        connInfo.serverName.bufferLen = pOpts->serverNameLen;
        connInfo.serverPort = pOpts->serverPort;

            status = TAP_getModuleList(&connInfo, pOpts->pTapProviderEntry->providerType, NULL,
                                       &moduleList, &errContext);
#else
            status = TAP_getModuleList(NULL, pOpts->pTapProviderEntry->providerType, NULL,
                                       &moduleList, &errContext);
#endif
    if (OK != status)
    {
        LOG_ERROR("TAP_getModuleList failed with error %d", status);
        goto exit;
    }

    gotModuleList = TRUE;

    if (0 == moduleList.numModules)
    {
        printf("No Provider modules found\n");
    }

#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(&(moduleList.pModuleList[0]),
            pSmpConfigFile, pOpts->isConfFileSpecified,
            &pEntityCredentials,
            &errContext);

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
    status = TAP_freePolicyStorage(pTapContext, pEntityCredentials, &storageInfo,
                                         &errContext);


    if (OK != status)
    {
        LOG_ERROR("Error deleting policy storage, status = %d\n", status);
        goto exit;
    }
    else
    {
        retval = 0;
        PRINT_STATUS("Storage object deleted successfully ", status);
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

    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }

    if ((TRUE == gotModuleList) && (NULL != moduleList.pModuleList))
    {
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
    }

    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(&errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
    }


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
        LOG_ERROR("*****moctap_delpolicystorage failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

