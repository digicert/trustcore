/**
 @file moctap_unsealdata.c

 @page moctap_unsealdata

 @ingroup moctap_tools_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_unsealdata -
 @endhtmlonly
 This tool unseals the sealed input data, previously sealed with moctap_sealdata.

 # SYNOPSIS
 `moctap_unsealdata [options]`

 # DESCRIPTION
 <B>moctap_unsealdata</B> This tool unseals the sealed input data, previously sealed with moctap_sealdata.<B>moctap_sealdata</B>.

@verbatim
    --h [option(s)]
         Display help for the specified option(s).
    --conf=[Security Module configuration file]
         Display command version info.
    --s=[server name or module path]
         Mandatory option. Specify the server name such as localhost or
         module path such as /dev/tpm0.
    --p=[server port]
         Port at which the TPM server is listening. If not specified, the default is used.
    --pn=[provider name]
         Provider label for the Security Module.
    --mid=[module id]
         Specify the module ID to use.
    --auth=[auth value]
         Authorization value to use to seal data. 
         If no authorization value is specified, the well-known password is used.
    --tdidx=[PCR index]
         PCR value to unseal data. 
         Multiple PCRs may be specified with a --tdidx=option for each PCR index.
    --idf=[input data file]
         (Mandatory) Input file that contains the previously sealed data to unseal.
    --odf=[output data file]
         (Mandatory) Output file that contains the unsealed data.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    --u [unicode]
         Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_seal

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
#include "../tap_utils.h"
#include "../tap_serialize.h"
#include "../tap_serialize_smp.h"
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
#define MAX_PCR_REGISTERS 24
#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096
#define TAPTOOL_CREDFILE_NAME_LEN  256

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean dataAuthSpecified;
    TAP_Buffer dataAuthValue;

    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;

    byteBoolean serverPortSpecified;
    ubyte4 serverPort;

    byteBoolean inFileSpecified;
    TAP_Buffer inFile;

    byteBoolean outFileSpecified;
    TAP_Buffer outFile;

    byteBoolean pcrSpecified;
    ubyte4 numPcrs;
    ubyte pcrList[24];

#ifndef __ENABLE_TAP_REMOTE__ 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* __ENABLE_TAP_REMOTE__ */

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
    LOG_MESSAGE("moctap_unsealdata: Help Menu\n");
    LOG_MESSAGE("This tool unseals the sealed input data, previously sealed with moctap_sealdata.");
    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [option(s)]");
    LOG_MESSAGE("                Display help for the specified option(s).\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[TAP server name or module path]");
    LOG_MESSAGE("                Mandatory option. Specify the server name such as localhost or\n"
            "                    module path such as /dev/tpm0.\n");
    LOG_MESSAGE("           --p=[TAP server port]");
    LOG_MESSAGE("                Port at which the TAP server is listening. If not specified, the default is used.\n");
#else
    LOG_MESSAGE("           --conf=[Security Module configuration file]");
    LOG_MESSAGE("                   Path to Security Module configuration file.\n");
#endif
    LOG_MESSAGE("           --pn=[provider name]");
    LOG_MESSAGE("                   Provider label for the Security Module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use.\n");
    LOG_MESSAGE("           --auth=[auth value]\n");
    LOG_MESSAGE("                   Authorization value to use to seal data.\n");
    LOG_MESSAGE("                   If no auth value is specified, the well-known password is used.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                 (Mandatory) Input file that contains the previously sealed data to unseal.\n");
    LOG_MESSAGE("           --odf=[output data file]");
    LOG_MESSAGE("                 (Mandatory) Output file that contains the unsealed data.\n");
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
            {"v", no_argument, NULL, 2},
#ifdef __ENABLE_TAP_REMOTE__
            {"s", required_argument, NULL, 3},
            {"p", required_argument, NULL, 4},
#endif
            {"auth", required_argument, NULL, 5},
            {"idf", required_argument, NULL, 6},
            {"odf", required_argument, NULL, 7},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 9},
#endif
            {"tdidx", required_argument, NULL, 10},
            {"pn", required_argument, NULL, 13},
            {"mid", required_argument, NULL, 14},
            {"cred", required_argument, NULL, 15},
            {NULL, 0, NULL, 0},
    };
    ubyte currPcr = 0 ;
    MSTATUS status;
    sbyte4 cmpResult;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4  optValLen = 0;
#endif
    sbyte4 filenameLen ;

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
        case 2:
            LOG_MESSAGE("TAP library version: %d.%d\n", TAP_VERSION_MAJOR, TAP_VERSION_MINOR);
            pOpts->exitAfterParse = TRUE;
            break;
#ifdef __ENABLE_TAP_REMOTE__
        case 3:
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
            pOpts->serverName[pOpts->serverNameLen] = '\0';
            MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
            pOpts->serverNameSpecified = TRUE;
            break;

        case 4:
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
                pOpts->serverPortSpecified = TRUE;
            }
            break;
#endif
        case 5:
            /* --auth password */
            {
                ubyte4 passwordLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if ((passwordLen == 0) || ('-' == optarg[0]))
                {
                    LOG_ERROR("--auth password not specified");
                    goto exit;
                }
                
                if (passwordLen > MAX_PASSWORD_LEN)
                {
                    LOG_ERROR("Password too long. Max length: %d characters", MAX_PASSWORD_LEN);
                    goto exit;
                }
                
                pOpts->dataAuthValue.bufferLen = passwordLen;
                if (OK != (status = DIGI_CALLOC((void **)&pOpts->dataAuthValue.pBuffer, 1,
                                passwordLen + 1)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for password",
                            (int)(passwordLen + 1));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->dataAuthValue.pBuffer, optarg, passwordLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->dataAuthValue.pBuffer);
                    pOpts->dataAuthValue.bufferLen = 0;
                    goto exit;
                }
                pOpts->dataAuthValue.pBuffer[passwordLen] = '\0';
                pOpts->dataAuthSpecified = TRUE;
            }
            break;

        case 6:
            /* --idf input data file */
            {
                ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("Input file path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((optValLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-idf Input data file not specified");
                    goto exit;
                }

                pOpts->inFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_CALLOC((void **)&pOpts->inFile.pBuffer, 1,
                                pOpts->inFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for input data filename",
                            (int)pOpts->inFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->inFile.pBuffer, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->inFile.pBuffer);
                    pOpts->inFile.bufferLen = 0;
                    goto exit;
                }
                pOpts->inFile.pBuffer[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Input data filename: %s", pOpts->inFile.pBuffer);
                pOpts->inFileSpecified = TRUE;
            }
            break;

        case 7:
            /* --odf output file */
            {
                ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("Output file path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((optValLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-odf Output file not specified");
                    goto exit;
                }

                pOpts->outFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_CALLOC((void **)&pOpts->outFile.pBuffer, 1,
                                pOpts->outFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for output filename",
                            (int)pOpts->outFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->outFile.pBuffer, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->outFile.pBuffer);
                    pOpts->outFile.bufferLen = 0;
                    goto exit;
                }
                pOpts->outFile.pBuffer[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Sealed data filename: %s", pOpts->outFile.pBuffer);
                pOpts->outFileSpecified = TRUE;
            }
            break;

        case 9:
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

        case 10:
            {
                char *endptr;
                long pcrNum;
                errno = 0;
                pcrNum = strtol(optarg, &endptr, 0);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || 
                    (pcrNum < 0) || (pcrNum >= MAX_PCR_REGISTERS))
                {
                    LOG_ERROR("Invalid PCR number. Must be between 0 and %d", MAX_PCR_REGISTERS - 1);
                    goto exit;
                }
                if (pOpts->numPcrs >= MAX_PCR_REGISTERS)
                {
                    LOG_ERROR("Too many PCR values specified. Maximum is %d", MAX_PCR_REGISTERS);
                    goto exit;
                }
                pOpts->pcrList[pOpts->numPcrs] = (ubyte)pcrNum;
                MOCTAP_DEBUG_PRINT("PCR: %d", pOpts->pcrList[pOpts->numPcrs]);
                pOpts->numPcrs++;
                pOpts->pcrSpecified = TRUE;
            }
            break;

        case 13:
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

        case 14:
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

        case 15:
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
            LOG_MESSAGE("Invalid option!\n\n");
            printHelp();
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

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = ERR_GENERAL;
    TAP_ConfigInfoList configInfoList = { 0, };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_CredentialList dataCredentials = { 0 };
    TAP_EntityCredentialList *pEntityCredentials = NULL;
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte contextInit = FALSE;
    TAP_Buffer inData = { 0 };
    TAP_Buffer outData = { 0 };
    TAP_SealAttributes *pSealAttributes = NULL;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 }; 
#endif
    ubyte gotModuleList = FALSE;
    TAP_ModuleList moduleList = { 0 };
    TAP_SealAttributes sealAttributes = { 0 };
    ubyte sealAttributesCnt = 0 ;
    int i = 0;
    TAP_Buffer pcrData = { 0 };
    TAP_TRUSTED_DATA_TYPE dataType ;
    TAP_OBJECT_TYPE objectType = TAP_OBJECT_TYPE_UNDEFINED;
    void *pObject = NULL;

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
#ifdef __ENABLE_TAP_REMOTE
    if (!pOpts->serverNameSpecified || !pOpts->dataAuthSpecified || 
        !pOpts->inFileSpecified || !pOpts->outFileSpecified ||
	!pOpts->prNameSpecified || !pOpts->modIdSpecified) 
    {
        LOG_ERROR("One or more mandatory options --s, --auth, --idf, --odf, --pn, --mid not specified.");
        goto exit;
    }
    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) && DIGI_STRNICMP((const sbyte *)pOpts->serverName, 
                                                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;   
    }
#else
    if (!pOpts->inFileSpecified || !pOpts->outFileSpecified ||
	!pOpts->prNameSpecified || !pOpts->modIdSpecified) 
    {
        LOG_ERROR("One or more mandatory options --idf, --odf, --pn, --mid not specified.");
        goto exit;
    }    
#endif

#ifndef __ENABLE_TAP_REMOTE__
    /* We only get the config information for a local-only build.  For a remote build, the server has the info. */

    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
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
    if ((0 != pOpts->dataAuthValue.bufferLen) && (NULL != pOpts->dataAuthValue.pBuffer))
    {
        sealAttributesCnt++ ;
    }
    if(pOpts->pcrSpecified == TRUE)
    {
        sealAttributesCnt += 2 ;  /* one for type followed by key */
    }
    if (0 < sealAttributesCnt)
    {
        status = DIGI_CALLOC((void **) &(sealAttributes.pAttributeList), sealAttributesCnt, sizeof(TAP_Attribute));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }

        if ((0 != pOpts->dataAuthValue.bufferLen) && (NULL != pOpts->dataAuthValue.pBuffer))
        {
            status = DIGI_CALLOC((void **) &(dataCredentials.pCredentialList), 1, sizeof(TAP_Credential));
            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory; status %d", status);
                goto exit;
            }
            i = 0;
            dataCredentials.numCredentials = 1;
            dataCredentials.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
            dataCredentials.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
            dataCredentials.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
            dataCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->dataAuthValue.bufferLen;
            dataCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->dataAuthValue.pBuffer;
            sealAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL;
            sealAttributes.pAttributeList[i].length = sizeof(TAP_Credential);
            sealAttributes.pAttributeList[i].pStructOfType = &(dataCredentials.pCredentialList[0]);
            pOpts->dataAuthValue.pBuffer = NULL;
            pOpts->dataAuthValue.bufferLen = 0;
            i++;
        }
        if(pOpts->pcrSpecified == TRUE)
        {
            pcrData.bufferLen = pOpts->numPcrs ;
            pcrData.pBuffer = pOpts->pcrList ;
            sealAttributes.pAttributeList[i].type = TAP_ATTR_TRUSTED_DATA_TYPE ;
            dataType = TAP_TRUSTED_DATA_TYPE_MEASUREMENT ;
            sealAttributes.pAttributeList[i].length = sizeof(TAP_TRUSTED_DATA_TYPE);
            sealAttributes.pAttributeList[i].pStructOfType = &dataType ;
            i++ ;
            sealAttributes.pAttributeList[i].type = TAP_ATTR_TRUSTED_DATA_KEY ;
            sealAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            sealAttributes.pAttributeList[i].pStructOfType = &pcrData;
            i++ ;
        }
    }
    sealAttributes.listLen = i;
    pSealAttributes = &sealAttributes;

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(&(moduleList.pModuleList[0]), pEntityCredentials,
                             NULL, &pTapContext, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_initContext", status);
        goto exit;
    }
    contextInit = TRUE;

    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->inFile.pBuffer, &(inData.pBuffer), &(inData.bufferLen));
    if (OK != status)
    {
        LOG_ERROR("DIGICERT_readFile failed to read input file with error %d", status);
        goto exit;
    }

    /* TODO: check input size */
    /* Unseal */
    status = TAP_unsealWithTrustedData(pTapContext, pEntityCredentials, objectType, pObject, pSealAttributes,
                                        &inData, &outData, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_unsealWithTrustedData", status);
        goto exit;
    }

    /* Save unsealed data to output file */
    status = DIGICERT_writeFile((const char *)pOpts->outFile.pBuffer,
                                outData.pBuffer, outData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing unsealed data to file, status = %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("Succcessfully unsealed data\n");
    retval = 0;

exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if ((NULL != pSmpConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pSmpConfigFile);
    }
#endif /* defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__) */

    if (inData.pBuffer)
        shredMemory((ubyte **)&(inData.pBuffer), inData.bufferLen, TRUE);

    if (outData.pBuffer)
        shredMemory((ubyte **)&(outData.pBuffer), outData.bufferLen, TRUE);
        
    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials);
    }
    if (NULL != dataCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&dataCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }
    if (NULL != sealAttributes.pAttributeList)
    {
        DIGI_FREE((void **)&sealAttributes.pAttributeList);
    }

    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        status = TAP_uninitContext(&pTapContext, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
    }
    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(pErrContext);
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

    if(sealAttributesCnt)
    {
        DIGI_FREE((void **) &(sealAttributes.pAttributeList)) ;
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

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->outFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outFile.pBuffer);

        if (pOpts->inFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inFile.pBuffer);

        if (pOpts->dataAuthValue.pBuffer)
            shredMemory((ubyte **)&(pOpts->dataAuthValue.pBuffer), pOpts->dataAuthValue.bufferLen, TRUE);

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
        MOCTAP_DEBUG_PRINT_1("Failed to unseal data.");
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
        LOG_ERROR("*****moctap_unseal failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

