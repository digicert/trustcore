/**
 @file moctpm2_selftest.c

 @page digicert_tpm2_selftest

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_selftest -
 @endhtmlonly
 Request that the TPM perform and/or report a selftest.

 # SYNOPSIS
 `digicert_tpm2_selftest [options]`

 # DESCRIPTION
 <B>digicert_tpm2_selftest</B> requests that the TPM perform a self test and report the results.
 If the -r option is specified, the TPM only reports the outcome of the last self test operation without performing another self test.
 If the TPM fails the self test, it enters failure mode where no commands are accepted.
 The results are reported in a manufacturer specific format.
 The TPM's self test is always executed automatically at every boot.

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
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
    --i [run incremental self-test]
        Run an incremental self-test.
    --r [return results only]
        Return last self-test results (does not rerun self-test)

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
#include "../../../common/debug_console.h"
#include "../../tap_api.h"
#include "../../tap_smp.h"
#include "../../tap_utils.h"
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

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256

#define TPM2_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean incrementalTestSpecified;

    byteBoolean resultsOnlySpecified;

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
    LOG_MESSAGE("digicert_tpm2_selftest: Help Menu\n");
    LOG_MESSAGE("This tool performs a full or incremental self-test.");

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
    LOG_MESSAGE("           --i [Run incremental self-test]");
    LOG_MESSAGE("                   Run an incremental self-test.\n");
    LOG_MESSAGE("           --r [Return results only]");
    LOG_MESSAGE("                   Return the last self-test results (does not rerun self-test)\n");
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
            {"i", no_argument, NULL, 4},
            {"r", no_argument, NULL, 5},
            {"conf", required_argument, NULL, 6},
            {"modulenum", required_argument, NULL, 7},
            {NULL, 0, NULL, 0},
    };
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
            printf("-s is an invalid option in a local-only build\n");
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
            printf("-p is an invalid option in a local-only build\n");
            goto exit;
#endif
            break;

        case 4:
            /* --i, incremental self test specified */
            pOpts->incrementalTestSpecified = TRUE;
            break;

        case 5:
            /* --r, results only */
            pOpts->resultsOnlySpecified = TRUE;
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
    if ((pOpts->incrementalTestSpecified) && (pOpts->resultsOnlySpecified))
    {
        printf("Cannot specify both --i and --r options\n");
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
    TAP_ModuleList moduleList = {0};
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_TEST_MODE testMode = TAP_TEST_MODE_FULL;
    TAP_Attribute reqAttribute = {TAP_ATTR_TEST_MODE, sizeof(TAP_TEST_MODE), &testMode};
    TAP_TestRequestAttributes requestAttributes = { 1, &reqAttribute};
    TAP_TestResponseAttributes responseAttributes = {0};
    TAP_TEST_STATUS testStatus = 0;
    ubyte tapInit = FALSE;
    //ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
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

    if ((pOpts->incrementalTestSpecified) && (pOpts->resultsOnlySpecified))
    {
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

    if (!pOpts->serverPort)
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
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        goto exit;
    }
    tapInit = TRUE;

    /* Discover modules */
#ifdef __ENABLE_TAP_REMOTE__
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
        LOG_ERROR("TAP_getModuleList failed with error %d", status);
        goto exit;
    }
    //gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
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

    if (pOpts->incrementalTestSpecified)
        testMode = TAP_TEST_MODE_PARTIAL;
    else if (pOpts->resultsOnlySpecified)
        testMode = TAP_TEST_MODE_LAST_RESULTS;
    else
        testMode = TAP_TEST_MODE_FULL;

    /* Build request attributes */

    /* Invoke TAP API */
    status = TAP_selfTest(pTapContext, &requestAttributes,
                          &responseAttributes, pErrContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_selfTest call failed with error %d\n", status);
    }
    else
        retval = 0;

    if (0 == responseAttributes.listLen)
    {
        printf("TAP_selfTest returned no data\n");
        goto exit;
    }
    for (i = 0; i < responseAttributes.listLen; i++)
    {
        if (NULL == responseAttributes.pAttributeList[i].pStructOfType)
            break;
        switch(responseAttributes.pAttributeList[i].type)
        {
            case TAP_ATTR_TEST_STATUS:
                testStatus = *(TAP_TEST_STATUS *)(responseAttributes.pAttributeList[i].pStructOfType);
                printf("Test Status: ");
                switch(testStatus)
                {
                    case TAP_TEST_STATUS_SUCCESS:
                        printf("Success\n");
                        break;
                    case TAP_TEST_STATUS_FAILURE:
                        printf("Failure\n");
                        break;
                    case TAP_TEST_STATUS_PENDING:
                        printf("Pending\n");
                        break;
                    default:
                        LOG_ERROR("TAP_selfTest returned invalid attribute of type %d\n",
                                  responseAttributes.pAttributeList[i].type);
                        break;
                }
                break;
            case TAP_ATTR_TEST_REPORT:
                printf("Test Report: %s", ((TAP_Buffer *)(responseAttributes.pAttributeList[i].pStructOfType))->pBuffer);
                break;
            default:
                break;
        }
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

    TAP_UTILS_freeAttributeList(&responseAttributes);

    if (NULL != moduleList.pModuleList)
    {
        TAP_freeModuleList(&moduleList);
    }

    /* Free config info */
    if (NULL != configInfoList.pConfig)
        TAP_UTILS_freeConfigInfoList(&configInfoList);

    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
        TAP_uninitContext(&pTapContext, pErrContext);

    /* Uninitialize TAP */
    if (TRUE == tapInit)
        TAP_uninit(pErrContext);

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
        TPM2_DEBUG_PRINT_1("Failed to start selftest");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_selftest failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

