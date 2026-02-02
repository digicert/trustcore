/**
 @file moctap_gettrusteddata.c

 @page moctap_gettrusteddata

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_gettrusteddata -
 @endhtmlonly
 This tool reads the Security Module’s trusted data source.

 # SYNOPSIS
 `moctap_gettrusteddata [options]`

 # DESCRIPTION
 <B>moctap_gettrusteddata</B> This tool reads the Security Module’s trusted data source.

@verbatim
    --h [option(s)]
        Display help for the specified option(s).
    --s=[server name]
        Host on which TPM chip is located.  This can be 'localhost' or a remote host running a TAP server.
    --p=[server port]
        Port on which the TAP server is listening.
    --conf [Security Module configuration file]
        Path to Security Module configuration file.
    --pn=[provider name]
        Provider label for the Security Module
    --mid=[module id]
        Specify the module ID to use.
    --tdtype=[data type]
        Type of trusted data (measurement, identifier, time or report).
    --tdsubtype=[subtype]
        Specify the source ID in the case of multiple data type sources
    --halg=[hash algorithm]
        (Optional) Hash algorithm (sha1, sha256 or sha512) to hash the data in the input file. Defaults to sha256.
    --tdidx=[trusted data index]
        (Optional) Indices to the trusted data source 
    --odf=[output data file]
        (Mandatory) Output file that contains the trusted data.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_createasymkey,  moctap_createsymkey, moctap_decrypt

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

typedef struct
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096
#define DEFAULT_SUB_TYPE 1
#define TAPTOOL_CREDFILE_NAME_LEN  256
#define MAX_TRUSTEDDATA_KEYS   64

typedef struct {
    byteBoolean exitAfterParse;


    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];

    byteBoolean outTrustedDataFileSpecified;
    TAP_Buffer outTrustedDataFile;

    byteBoolean dataTypeSpecified;
    TAP_TRUSTED_DATA_TYPE dataType;

    byteBoolean trustedDataKeySpecified;
    ubyte4 numTrustedDataKeys;
    ubyte trustedDataKeyList[MAX_TRUSTEDDATA_KEYS];
    
    byteBoolean subTypeSpecified;
    ubyte4 subType;

    byteBoolean hashAlgSpecified;
    TAP_HASH_ALG hashAlg;

#ifdef __ENABLE_TAP_REMOTE__
    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    ubyte4 serverNameLen;
    ubyte4 serverPort;

#else
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
    LOG_MESSAGE("moctap_gettrusteddata: Help Menu\n");
    LOG_MESSAGE("This tool reads the Security Module’s trusted data source.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [option(s)]");
    LOG_MESSAGE("                   Display help for the specified option(s).\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[TAP server name or module path]");
    LOG_MESSAGE("                   Mandatory. Specify the server name such as localhost or a remote host.\n");
    LOG_MESSAGE("           --p=[TAP server port]");
    LOG_MESSAGE("                   Port at which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[Security Module configuration file]");
    LOG_MESSAGE("                   Path to Security Module configuration file.\n");
#endif
    LOG_MESSAGE("           --pn=[provider name]");
    LOG_MESSAGE("                   Provider label for the Security Module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use.\n");
    LOG_MESSAGE("           --tdtype=[data type]");
    LOG_MESSAGE("                   Type of trusted data (measurement, identifier, report).\n");
    LOG_MESSAGE("           --tdsubtype=[subtype]");
    LOG_MESSAGE("                   Specify the source ID in the case of multiple data type sources\n");
    LOG_MESSAGE("           --tdidx=[trusted data index]");
    LOG_MESSAGE("                   Multiple indices can be specified by repeating this option.\n"); 
    LOG_MESSAGE("           --halg=[hash algorithm]");
    LOG_MESSAGE("                   (Optional) Hash algorithm (sha1, sha256 or sha512) to \n"
                "                    hash the data in the input file. Defaults to sha256.\n");
    LOG_MESSAGE("           --odf=[output data file]");
    LOG_MESSAGE("                   (Mandatory) Output file that contains the trusted data.\n");
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
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
            {"halg", required_argument, NULL, 4},
            {"tdtype", required_argument, NULL, 5},
            {"tdsubtype", required_argument, NULL, 6},
            {"odf", required_argument, NULL, 7},
            {"tdidx", required_argument, NULL, 9},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 10},
#endif
	        {"pn", required_argument, NULL, 13},
            {"mid", required_argument, NULL, 14},
            {"cred", required_argument, NULL, 15},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
    ubyte oIndex;
    ubyte4 optValLen = 0;
    sbyte4 filenameLen ;
    ubyte currTrustedDataKey = 0;

    if (!pOpts || !argv || (0 == argc))
    {
        MOCTAP_DEBUG_PRINT_1("Invalid parameters.");
        goto exit;
    }

    pOpts->numTrustedDataKeys = 0;
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
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            if (optValLen >= SERVER_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max length: %d characters", SERVER_NAME_LEN - 1);
                goto exit;
            }
            pOpts->serverNameLen = optValLen;

            if ((pOpts->serverNameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-s Server name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, optValLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->serverName[optValLen] = '\0';
            MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
            pOpts->serverNameSpecified = TRUE;
#else
                LOG_ERROR("Server name not a valid option in a local-only build\n");
                goto exit;
#endif
            break;

        case 3:
#ifdef __ENABLE_TAP_REMOTE__
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
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
            break;

        case 4:
            /* --halg digest hash algorithm */
            {
                OPT_VAL_INFO optionValues[] = {
                    {"sha1", TAP_HASH_ALG_SHA1},
                    {"sha256", TAP_HASH_ALG_SHA256},
                    {"sha512", TAP_HASH_ALG_SHA512},
                    {NULL, 0},
                };
                ubyte4 optionLengths[] = {4, 6, 6, 0};

                optValLen = DIGI_STRLEN((const sbyte *)optarg);
                if ((optValLen == 0) || ('-' == optarg[0]))
                {
                    LOG_ERROR("-halg Digest hash algorithm not specified");
                    goto exit;
                }

                for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                {
                    cmpResult = 1;
                    if (optionLengths[oIndex] == optValLen)
                    {
                        if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                    optionLengths[oIndex], &cmpResult))
                        {
                            MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                            goto exit;
                        }

                        if (!cmpResult)
                        {
                            pOpts->hashAlg = optionValues[oIndex].val;
                            MOCTAP_DEBUG_PRINT("Setting digest algorithm to %s",
                                    optionValues[oIndex].pName);
                            break;
                        }
                    }
                }

                if (NULL == optionValues[oIndex].pName)
                {
                    LOG_ERROR("--halg not sha1 or sha256 or sha512");
                    goto exit;
                }
                pOpts->hashAlgSpecified = TRUE;
            }
            break;

        case 5:
            /* --tdtype - data type */
            {
                OPT_VAL_INFO dataTypeOptionValues[] = {
                            {"measure", TAP_TRUSTED_DATA_TYPE_MEASUREMENT},
                            {"id", TAP_TRUSTED_DATA_TYPE_IDENTIFIER},
                            {"report", TAP_TRUSTED_DATA_TYPE_REPORT},
                            {NULL, 0},
                };
                ubyte4 dataTypeLengths[] = {7, 2, 6, 0};

                optValLen = DIGI_STRLEN((const sbyte *)optarg);
                if ((optValLen == 0) || ('-' == optarg[0]))
                {
                    LOG_ERROR("-tdtype not specified");
                    goto exit;
                }

                for (oIndex = 0; dataTypeOptionValues[oIndex].pName; oIndex++)
                {
                    cmpResult = 1;
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)dataTypeOptionValues[oIndex].pName,
                                    dataTypeLengths[oIndex], &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->dataType = dataTypeOptionValues[oIndex].val;
                        if (pOpts->dataType != TAP_TRUSTED_DATA_TYPE_MEASUREMENT)
                        {
                            LOG_ERROR("Currently only support measurement trusted data type\n");
                            goto exit;   
                        }

                        MOCTAP_DEBUG_PRINT("Setting data type to %s", dataTypeOptionValues[oIndex].pName);
                        break;
                    }
                }

                if (!dataTypeOptionValues[oIndex].pName)
                {
                     LOG_ERROR("--tdtype not measure, id, or report");
                    goto exit;
                }
                pOpts->dataTypeSpecified = TRUE;
            }
            break;

        case 6:
            /* --stype subtype of trusted data */
            {
                char *endptr;
                long subtype;
                errno = 0;
                subtype = strtol(optarg, &endptr, 0);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (subtype < 0))
                {
                    LOG_ERROR("-tdsubtype Invalid or no subtype specified");
                    goto exit;
                }
                pOpts->subType = (ubyte4)subtype;
                if (pOpts->subType != DEFAULT_SUB_TYPE)
                {
                    LOG_ERROR("-tdsubtype Current supported sub type is %d", DEFAULT_SUB_TYPE);
                    goto exit;
                }

                MOCTAP_DEBUG_PRINT("Sub type: %d", pOpts->subType);
                pOpts->subTypeSpecified = TRUE;
            }
            break;

        case 7:
            /* --odf output signature file */
            optValLen = DIGI_STRLEN((const sbyte *)optarg);
            pOpts->outTrustedDataFile.bufferLen = optValLen + 1;

            if ((optValLen == 0) || ('-' == optarg[0]))
            {
                LOG_ERROR("-odf Output trusted data file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outTrustedDataFile.pBuffer, 
                            pOpts->outTrustedDataFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for trusted data filename",
                        (int)pOpts->outTrustedDataFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outTrustedDataFile.pBuffer, optarg, optValLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE((void **)&pOpts->outTrustedDataFile.pBuffer);
                pOpts->outTrustedDataFile.bufferLen = 0;
                goto exit;
            }
            pOpts->outTrustedDataFile.pBuffer[optValLen] = '\0';
            MOCTAP_DEBUG_PRINT("Trusted data filename: %s", pOpts->outTrustedDataFile.pBuffer);
            pOpts->outTrustedDataFileSpecified = TRUE;

            break;
        
        case 9:
            /* -- tdidx data key */
            {
                char *endptr;
                long tdIndex;
                
                optValLen = DIGI_STRLEN((const sbyte *)optarg);
                if ((optValLen == 0) || ('-' == optarg[0]))
                {
                    LOG_ERROR("--tdidx No value(s) specified");
                    goto exit;
                }
                
                errno = 0;
                tdIndex = strtol(optarg, &endptr, 0);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') ||
                    (tdIndex < 0) || (tdIndex >= MAX_TRUSTEDDATA_KEYS))
                {
                    LOG_ERROR("--tdidx Invalid Trusted-Data Index specified");
                    goto exit;
                }
                currTrustedDataKey = (ubyte)tdIndex;
                pOpts->trustedDataKeyList[pOpts->numTrustedDataKeys] = currTrustedDataKey;
                MOCTAP_DEBUG_PRINT("Trusted data key: %d",
                        pOpts->trustedDataKeyList[pOpts->numTrustedDataKeys]);
                pOpts->numTrustedDataKeys++;
                pOpts->trustedDataKeySpecified = TRUE;
            }
            break;

        case 10:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max length: 255 characters");
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
                MOCTAP_DEBUG_PRINT("Configuration file path: %s", 
                                 pOpts->confFilePath);
                pOpts->isConfFileSpecified = TRUE;
#else
                LOG_ERROR("Configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
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
                LOG_ERROR("credential file name too long. Max length: 255 characters");
                goto exit;
            }
            if ((filenameLen == 0) || ('-' == optarg[0]))
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
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ModuleList moduleList = { 0 };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 }; 
#endif
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
    byteBoolean tapInit = FALSE;
    byteBoolean contextInit = FALSE;
    ubyte gotModuleList = FALSE;

    TAP_Buffer trustedData = { 0 };
    static TAP_Buffer tapTrustKeyAttr = {0};
    static TAP_HASH_ALG tapTrustKeyHashAlg = TAP_HASH_ALG_SHA256;

    TAP_Attribute tapTrustKeyAttrList[] = {
        {TAP_ATTR_TRUSTED_DATA_KEY, sizeof(tapTrustKeyAttr), &tapTrustKeyAttr},
        {TAP_ATTR_HASH_ALG, sizeof(tapTrustKeyHashAlg), &tapTrustKeyHashAlg}
    };

    TAP_TrustedDataInfo dataInfo =
    {
        .subType = DEFAULT_SUB_TYPE,
        .attributes = {sizeof(tapTrustKeyAttrList)/sizeof(TAP_Attribute), tapTrustKeyAttrList}
    };

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

    /* Set trustedDataKey */
    if (pOpts->trustedDataKeySpecified)
    {
        tapTrustKeyAttr.pBuffer = pOpts->trustedDataKeyList;
        tapTrustKeyAttr.bufferLen = pOpts->numTrustedDataKeys;
    }

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified || !pOpts->dataTypeSpecified ||
        !pOpts->subTypeSpecified || !pOpts->outTrustedDataFileSpecified ||
        !pOpts->trustedDataKeySpecified || !pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory options --s, --tddtype, --tdsubtype, --tdidx, --pn, --mid or --odf not specified.");
        goto exit;
    }
#else
    if (!pOpts->dataTypeSpecified || !pOpts->subTypeSpecified || 
        !pOpts->trustedDataKeySpecified || !pOpts->outTrustedDataFileSpecified ||
	!pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory options --tdtype, --tdsubtype, --tdidx, --pn, --mid or --odf not specified.");
        goto exit;
    }
#endif

    tapTrustKeyHashAlg = (TRUE == pOpts->hashAlgSpecified) ?
                            pOpts->hashAlg : TAP_HASH_ALG_SHA256;

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
        PRINT_STATUS("TAP_init",status);
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

    dataInfo.subType = pOpts->subType;

    /* Read PCR values */
    status = TAP_getTrustedData(pTapContext, pEntityCredentials, pOpts->dataType, &dataInfo,
                                &trustedData, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_getTrustedData", status);
        goto exit;
    }

    /* Save trusted data to output file */
    status = DIGICERT_writeFile((const char *)pOpts->outTrustedDataFile.pBuffer, trustedData.pBuffer, trustedData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing trusted data to file, status = %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("Successfully wrote trusted data to file\n");
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

    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        /* Deinitialize context */
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

    if (NULL != trustedData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&trustedData);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
    }

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
        if(pOpts->outTrustedDataFile.pBuffer)
            shredMemory((ubyte **)&pOpts->outTrustedDataFile.pBuffer,pOpts->outTrustedDataFile.bufferLen, TRUE);

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
        MOCTAP_DEBUG_PRINT_1("Failed to get trusted data.");
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
        LOG_ERROR("*****moctap_gettrusteddata failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

