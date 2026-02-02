/**
 @file moctpm2_getrandom.c

 @page digicert_tpm2_getrandom

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_getrandom -
 @endhtmlonly
 Encrypt data using a TPM 2.0 key.

 # SYNOPSIS
 `digicert_tpm2_getrandom [options]`

 # DESCRIPTION
 <B>digicert_tpm2_getrandom</B> This tool generates random data using the TPM’s RNG

@verbatim
    --h [help]
        Display command usage info.
    --conf=[TPM 2.0 configuration file]
        Path to TPM 2.0 module configuration file. 
    --s=[server name]
        Host on which TPM chip is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TPM server is listening.
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
    --rndsize=[random number size]
        (Mandatory) Size of random number to generate.
    --odf=[output data file]
        (Mandatory) Output file name that contains random number
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 digicert_tpm2_stirrandom

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
#include "../../tap_smp.h"
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

typedef struct
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096
#define MAX_RANDOM_SIZE 48

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

    byteBoolean randomDataFileSpecified;
    TAP_Buffer randomDataFile;
    
    byteBoolean randomSizeSpecified;
    ubyte4 randomSize;

#ifdef __ENABLE_TAP_REMOTE__
    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    ubyte4 serverNameLen;
    ubyte4 serverPort;

#else
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* __ENABLE_TAP_REMOTE__ */

    TAP_ModuleId moduleNum;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_getrandom: Help Menu\n");
    LOG_MESSAGE("This tool generates random data using the TPM’s RNG");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [display command line options]");
    LOG_MESSAGE("                   Help menu\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[server name]");
    LOG_MESSAGE("                   (Mandatory) Host on which TPM chip is located.  This can be 'localhost' or a\n"
                "                   remote host running a TAP server.\n");
    LOG_MESSAGE("           --p=[server port]");
    LOG_MESSAGE("                   Port on which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[TPM 2.0 configuration file]");
    LOG_MESSAGE("                   Path to TPM 2.0 module configuration file.\n");
#endif
    LOG_MESSAGE("           --modulenum=[module num]");
    LOG_MESSAGE("                   Specify the module num to use. If not provided, the first module found is used.\n");
    LOG_MESSAGE("           --rndsize=[random number size]");
    LOG_MESSAGE("                   (Mandatory) Size of random number to generate.\n");
    LOG_MESSAGE("           --odf=[output data file]");
    LOG_MESSAGE("                   (Mandatory) Output file that contains the random number.\n");
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
            {"rndsize", required_argument, NULL, 4},
            {"odf", required_argument, NULL, 5},
            {"conf", required_argument, NULL, 6},
            {"modulenum", required_argument, NULL, 7},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
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
                LOG_ERROR("Invalid server port: %d. Port must be between 1 and 65535.", pOpts->serverPort);
                goto exit;
            }

            TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
            break;

        case 4:
            /* --rndsize size of random data */
                pOpts->randomSizeSpecified = TRUE;
                pOpts->randomSize = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (pOpts->randomSize == 0)
                {
                    LOG_ERROR("--rndsize Invalid or no size of random data is specified");
                    goto exit;
                }
                if (pOpts->randomSize > MAX_RANDOM_SIZE)
                {
                    LOG_ERROR("-rndsize Current supported max size is %d", MAX_RANDOM_SIZE);
                    goto exit;
                }

                TPM2_DEBUG_PRINT("Random data size: %d", pOpts->randomSize);
             break;

        case 5:
            /* --odf output random data file */
            pOpts->randomDataFileSpecified = TRUE;
            pOpts->randomDataFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->randomDataFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--odf Output data file not specified");
                goto exit;
            }

            /* Validate output data file path length */
            if (pOpts->randomDataFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Output data file path too long. Max size: %d bytes", FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->randomDataFile.pBuffer, 
                            pOpts->randomDataFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for random data filename",
                        (int)pOpts->randomDataFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->randomDataFile.pBuffer, optarg, 
                        pOpts->randomDataFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("random data filename: %s", pOpts->randomDataFile.pBuffer);

            break;

        case 6:
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
             case 7:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
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
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_EntityCredentialList entityCredentials = { 0 };
    TAP_EntityCredentialList *pEntityCredentials = NULL;
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    byteBoolean tapInit = FALSE;
    byteBoolean gotModuleList = FALSE;
    byteBoolean contextInit = FALSE;
/*    int numCredentials = 0;
    int i = 0;*/
    TAP_AttributeList   *pRandAttributes = NULL;
    TAP_Buffer randomData = {0};

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

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                &pOpts->serverPort);
    }

    if (!pOpts->serverNameSpecified || !pOpts->randomSizeSpecified ||
        !pOpts->randomDataFileSpecified )
    {
        LOG_ERROR("One of mandatory options --s, --rndsize or --odf not specified.");
        goto exit;
    }
#else
    if (!pOpts->randomSizeSpecified || !pOpts->randomDataFileSpecified)
    {
        LOG_ERROR("One of mandatory options --rndsize or --odf not specified.");
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

    /* We only get the config information for a local-only build.  For a remote build, the server has the info. */

    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
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
#endif

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;

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

    status = TAP_getRandom(pTapContext, pOpts->randomSize, pRandAttributes,
                            &randomData, &errContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_getRandom", status);
        goto exit;
    }

    /* Save random data to output file */
    status = DIGICERT_writeFile((const char *)pOpts->randomDataFile.pBuffer, 
                                randomData.pBuffer, randomData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing random data to file, status = %d\n", status);
        goto exit;
    }

    DIGI_FREE((void **)&randomData.pBuffer);
    LOG_MESSAGE("Successfully wrote random data to file\n");
    retval = 0;

exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if (    (NULL != pTpm2ConfigFile)
       &&   (FALSE == pOpts->isConfFileSpecified)
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

    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        /* Deinitialize context */
        status = TAP_uninitContext(&pTapContext, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
    }

    if (NULL != pEntityCredentials)
    {
        TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
    
        DIGI_FREE((void **)&pEntityCredentials);
    }

    if (NULL != entityCredentials.pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(&entityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
    }

    if (NULL != randomData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&randomData);
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
        if (pOpts->randomDataFile.pBuffer)
            shredMemory((ubyte **)&(pOpts->randomDataFile.pBuffer), pOpts->randomDataFile.bufferLen, TRUE);
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
        TPM2_DEBUG_PRINT_1("Failed to get random data.");
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
        LOG_ERROR("*****digicert_tpm2_getrandom failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

