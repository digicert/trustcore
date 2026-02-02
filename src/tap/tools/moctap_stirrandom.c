/**
 @file moctap_stirrandom.c

 @page moctap_stirrandom

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_stirrandom -
 @endhtmlonly
 This tool adds entropy to the random bit generator.

 # SYNOPSIS
 `moctap_stirrandom [options]`

 # DESCRIPTION
 <B>moctap_stirrandom</B> encrypts data using the key provided.

@verbatim
    --h [option(s)]
        Display help for the specified option(s).
    --s [server name]
        Host on which TPM chip is located.  This can be 'localhost' or a remote host running a TAP server.
    --p [server port]
        Port on which the TAP server is listening.
    --conf=[Security Module configuration file]
        Path to Security Module configuration file.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use.
    --size=[number of bytes to stir]
        Number of bytes to be use to stir the RNG.
    --idf=[input data file]
        (Mandatory) Input file that contains the entropy.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_stirrandom

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
#define MAX_STIR_SIZE 32
#define TAPTOOL_CREDFILE_NAME_LEN  256

typedef struct {
    byteBoolean exitAfterParse;


    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];

    byteBoolean entropyDataFileSpecified;
    TAP_Buffer entropyDataFile;
    
    byteBoolean stirSizeSpecified;
    ubyte4 stirSize;

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
    LOG_MESSAGE("moctap_stirrandom: Help Menu\n");
    LOG_MESSAGE("This tool encrypts the input file using TPM.");

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
    LOG_MESSAGE("           --size=[number of bytes to stir]");
    LOG_MESSAGE("                   Number of bytes to be used to stir the RNG.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the entropy.\n");
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
            {"size", required_argument, NULL, 5},
            {"idf", required_argument, NULL, 6},
            {"conf", required_argument, NULL, 8},
            {"pn", required_argument, NULL, 13},
            {"mid", required_argument, NULL, 14},
            {"cred", required_argument, NULL, 15},
            {NULL, 0, NULL, 0},
    };
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
#ifdef __ENABLE_TAP_REMOTE__
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

        case 5:
            /* --size number of bytes to stir */
            {
                char *endptr;
                long size;
                errno = 0;
                size = strtol(optarg, &endptr, 0);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (size <= 0))
                {
                    LOG_ERROR("-size Invalid or no size of number of bytes is specified");
                    goto exit;
                }
                if (size > MAX_STIR_SIZE)
                {
                    LOG_ERROR("-size Current supported max size is %d", MAX_STIR_SIZE);
                    goto exit;
                }
                pOpts->stirSize = (ubyte4)size;
                MOCTAP_DEBUG_PRINT("Number of bytes to be stirred: %d", pOpts->stirSize);
                pOpts->stirSizeSpecified = TRUE;
            }
            break;

        case 6:
            /* --idf input entropy data file */
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
                    LOG_ERROR("-idf Input entropy data file not specified");
                    goto exit;
                }

                pOpts->entropyDataFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->entropyDataFile.pBuffer, 
                                pOpts->entropyDataFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for entropy data filename",
                            (int)pOpts->entropyDataFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->entropyDataFile.pBuffer, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->entropyDataFile.pBuffer);
                    pOpts->entropyDataFile.bufferLen = 0;
                    goto exit;
                }
                pOpts->entropyDataFile.pBuffer[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Entropy data filename: %s", pOpts->entropyDataFile.pBuffer);
                pOpts->entropyDataFileSpecified = TRUE;
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
    byteBoolean gotModuleList = FALSE;
    TAP_RngAttributes *pRandAttributes = NULL;
    TAP_Buffer entropyData = {0};
    TAP_ModuleList moduleList = { 0 };

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

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified || !pOpts->stirSizeSpecified ||
        !pOpts->entropyDataFileSpecified || !pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory options --s, --size, --pn, --mid or --idf not specified.");
        goto exit;
    }
#else
    if (!pOpts->stirSizeSpecified || !pOpts->entropyDataFileSpecified ||
	!pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory options --size, --pn, --mid or --idf not specified.");
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
        printf("No Provider modules found\n");
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

    /* Read input entropy data file */
    status = DIGICERT_readFile((const char *)pOpts->entropyDataFile.pBuffer, &(entropyData.pBuffer), &(entropyData.bufferLen));
    if (OK != status)
    {
        LOG_ERROR("DIGICERT_readFile failed to read input file with error %d", status);
        goto exit;
    }

    status = TAP_stirRandom(pTapContext, pOpts->stirSize, pRandAttributes, &entropyData, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_stirRandom", status);
        goto exit;
    }

    LOG_MESSAGE("Sucessfully stirred random number.\n");
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

    if ((TRUE == gotModuleList) && (NULL != moduleList.pModuleList))
    {   
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
    }
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
        DIGI_FREE((void **)&pEntityCredentials);
    }

    if (NULL != entropyData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&entropyData);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
    }

    if (TRUE == tapInit)
    {
        status = TAP_uninit(pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
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

        if (pOpts->entropyDataFile.pBuffer)
            shredMemory((ubyte **)&(pOpts->entropyDataFile.pBuffer), pOpts->entropyDataFile.bufferLen, TRUE);

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
        MOCTAP_DEBUG_PRINT_1("Failed to get random data.");
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
        LOG_ERROR("*****moctap_stirrandom failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

