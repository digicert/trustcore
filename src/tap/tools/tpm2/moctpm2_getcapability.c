/**
 @file moctpm2_getcapability.c

 @page digicert_tpm2_getcapability

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_getcapability -
 @endhtmlonly
 Get the capabilities for a TPM 2.0 chip. 

 # SYNOPSIS
 `digicert_tpm2_getcapability [options]`

 # DESCRIPTION
 <B>digicert_tpm2_getcapability</B> This tool returns the TPM 2.0 secure element capabilities information.

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
    --cap=[capability]
        Category of data to return (defaults to 6 'TPM_CAP_TPM_PROPERTIES')
    --pr=[property]
        First property of the selected capability to return (defaults to first available property).
        Hex values must be prefixed with a "0x"
    --pc=[property count]
        Number of properties to return (default returns all)
    --modulenum=[module num]
        Module number to use. If not provided first module is used by default
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

#if defined (__RTOS_WIN32__)
#include "../../../common/mcmdline.h"
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

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

/* Defines for default values*/
#define MOCTPM2_GETCAP_DEFAULT_CAP          TAP_TPM2_CAP_TPM_PROPERTIES
#define MOCTPM2_GETCAP_DEFAULT_PROPERTY     ((ubyte4)0x00000000)

typedef struct {
    byteBoolean exitAfterParse;

#ifdef __ENABLE_TAP_REMOTE__
    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    ubyte4 serverNameLen;
    ubyte4 serverPort;
#else
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif

    ubyte4 capability;
    byteBoolean isCapabilitySpecified;
    
    ubyte4 property;
    byteBoolean isPropertySpecified;

    ubyte4 propertyCount;
    byteBoolean isPropertyCountSpecified;

    TAP_ModuleId moduleNum;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printValidPropertyValues(ubyte4 capability)
{
    switch (capability)
    {
        case TAP_TPM2_CAP_TPM_PROPERTIES:
        {
            LOG_MESSAGE("Property values for capability '%d':", capability);
            LOG_MESSAGE("           0x%08x - PT_FIXED [For values in the fixed group]", TAP_TPM2_PT_FIXED);
            LOG_MESSAGE("           0x%08x - PT_VAR [For values in the variable group]", TAP_TPM2_PT_VAR);
        }
        break;

        case TAP_TPM2_CAP_ALGS:
        case TAP_TPM2_CAP_HANDLES:
        case TAP_TPM2_CAP_COMMANDS:
        case TAP_TPM2_CAP_PP_COMMANDS:
        case TAP_TPM2_CAP_AUDIT_COMMANDS:
        case TAP_TPM2_CAP_PCRS:
        case TAP_TPM2_CAP_PCR_PROPERTIES:
        case TAP_TPM2_CAP_ECC_CURVES:
        default:
        {
            LOG_MESSAGE("Property value is not used for capability '%d'.", capability);
        }
        break;
    }
}

byteBoolean validatePropertyValue(ubyte4 capability, ubyte4 property)
{
    byteBoolean isValid = TRUE;

    switch (capability)
    {
        case TAP_TPM2_CAP_TPM_PROPERTIES:
        {
            if (TAP_TPM2_PT_FIXED > property || (TAP_TPM2_PT_VAR + TAP_TPM2_PT_GROUP) <= property)
            {
                isValid = FALSE;
                LOG_ERROR("Invalid property value '0x%08x' for capability '%d'",
                    property, capability);
                printValidPropertyValues(capability);
            }
        }
        break;

        case TAP_TPM2_CAP_PP_COMMANDS:
        case TAP_TPM2_CAP_AUDIT_COMMANDS:
        case TAP_TPM2_CAP_PCRS:
        case TAP_TPM2_CAP_PCR_PROPERTIES:
        {
            printValidPropertyValues(capability);
            break;
        }

        case TAP_TPM2_CAP_ALGS:
        case TAP_TPM2_CAP_HANDLES:
        case TAP_TPM2_CAP_COMMANDS:
        case TAP_TPM2_CAP_ECC_CURVES:
        default:
            break;
    }

    return isValid;
}

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_getcapability: Help Menu\n");
    LOG_MESSAGE("This tool returns the TPM 2.0 secure element capabilities information.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [Display command line options]");
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
    LOG_MESSAGE("           --cap=[capability]");
    LOG_MESSAGE("                   Category of data to return (defaults to 6 'TPM_CAP_TPM_PROPERTIES').");
    LOG_MESSAGE("                       0 - TPM_CAP_ALGS");
    LOG_MESSAGE("                       1 - TPM_CAP_HANDLES");
    LOG_MESSAGE("                       2 - UNSUPPORTED"); /* TPM_CAP_COMMANDS */
    LOG_MESSAGE("                       3 - UNSUPPORTED"); /* TPM_CAP_PP_COMMANDS */
    LOG_MESSAGE("                       4 - UNSUPPORTED"); /* TPM_CAP_AUDIT_COMMANDS */
    LOG_MESSAGE("                       5 - TPM_CAP_PCRS");
    LOG_MESSAGE("                       6 - TPM_CAP_TPM_PROPERTIES");
    LOG_MESSAGE("                       7 - UNSUPPORTED"); /* TPM_CAP_PCR_PROPERTIES */
    LOG_MESSAGE("                       8 - TPM_CAP_ECC_CURVE\n");

    LOG_MESSAGE("           --pr=[property]");
    LOG_MESSAGE("                   First property of the selected capability to return (defaults to first available property).");
    LOG_MESSAGE("                   Hex values must be prefixed with a '0x'.\n");
    LOG_MESSAGE("           --pc=[property count]");
    LOG_MESSAGE("                   Number of properties to return (default returns all).\n");

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
#else
            {"conf", required_argument, NULL, 4},
#endif
            {"cap", required_argument, NULL, 5},
            {"pr", required_argument, NULL, 6},
            {"pc", required_argument, NULL, 7},
            {"modulenum", required_argument, NULL, 8},
            {NULL, 0, NULL, 0},
    };
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4  optConfFileValLen = 0;
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
                LOG_ERROR("Port number must be in the range 1-65535");
                goto exit;
            }

            TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
            break;
#else

        case 4:
            /* tpm2 config file path */
            pOpts->isConfFileSpecified = TRUE;
            optConfFileValLen = DIGI_STRLEN((const sbyte *)optarg); 
            if (optConfFileValLen > FILE_PATH_LEN)
            {
                LOG_ERROR("File path too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }
            if ((0 >= optConfFileValLen) || ('-' == optarg[0]))
            {
                LOG_ERROR("Configuration file path not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optConfFileValLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("TPM2 Configuration file path: %s", 
                             pOpts->confFilePath);
            break;
#endif
        case 5:
            /* capability */
            pOpts->isCapabilitySpecified = TRUE;
            pOpts->capability = strtol(optarg, NULL, 0);
            if (TAP_TPM2_CAP_FIRST > pOpts->capability || TAP_TPM2_CAP_LAST < pOpts->capability)
            {
                LOG_ERROR("Invalid capability value specified.\n"
                         "\tValid values = %d to %d\n",
                        TAP_TPM2_CAP_FIRST, TAP_TPM2_CAP_LAST);
                printHelp();
                goto exit;
            }
            TPM2_DEBUG_PRINT("Selected capability: %d", pOpts->capability);
            break;

        case 6:
            /*property start index*/
            pOpts->isPropertySpecified = TRUE;
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--pr property not specified");
                goto exit;
            }

            if (('0' == optarg[0]) && ('x' == optarg[1]))
            {
                if (OK != DIGI_convertHexString((const char *)&optarg[2],
                    (ubyte *)&pOpts->property, sizeof(pOpts->property)))
                {
                    TPM2_DEBUG_PRINT_1("Failed to convert hex string");
                    goto exit;
                }
                pOpts->property = DIGI_NTOHL((ubyte *)&pOpts->property);
            }
            else
            {
                pOpts->property = DIGI_ATOL((const sbyte *)optarg, NULL);
            }
            TPM2_DEBUG_PRINT("First property: 0x%08x", pOpts->property);
            break;

        case 7:
            /*number of properties to get*/
            pOpts->isPropertyCountSpecified = TRUE;
            pOpts->propertyCount = strtol(optarg, NULL, 0);
            if(0 == pOpts->propertyCount)
            {
                LOG_ERROR("Invalid property count specified.");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Number of properties: %d", pOpts->propertyCount);
            break;
        case 8:
            pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
            TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
            break;

        default:
            printHelp();
            pOpts->exitAfterParse = TRUE;
            break;
        }
    }
    if (pOpts->isPropertySpecified &&
        !validatePropertyValue(pOpts->capability, pOpts->property)
        )
    {
            goto exit;
    }

    if (!pOpts->isCapabilitySpecified)
    {
        pOpts->capability = MOCTPM2_GETCAP_DEFAULT_CAP;
    }
    if (!pOpts->isPropertySpecified)
    {
        pOpts->property = MOCTPM2_GETCAP_DEFAULT_PROPERTY;
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

void printProperty(TAP_ModuleCapProperty *property, ubyte4 cap)
{
    ubyte4 propertyVal = 0;
    MSTATUS status = OK;
    if (NULL == property)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    switch (cap)
    {
    case TAP_TPM2_CAP_TPM_PROPERTIES:
        if (sizeof(propertyVal) != property->propertyValue.bufferLen)
        {
            status = ERR_TAP_INVALID_SIZE;
            goto exit;
        }
        propertyVal = DIGI_NTOHL(property->propertyValue.pBuffer);
        break;
    default:
        if (0 != property->propertyValue.bufferLen &&
            NULL != property->propertyValue.pBuffer)
        {
            status = DIGI_MEMCPY(&propertyVal, property->propertyValue.pBuffer, sizeof(propertyVal));
            if (OK != status)
                goto exit;
        }
        break;
    }

    printf("Property 0x%08x", property->propertyId);
    if (0 != property->propertyValue.bufferLen)
    {
        printf("\tValue %08x", propertyVal);
    }
    if (0 != property->propertyDescription.bufferLen)
    {
        printf("\t%s", property->propertyDescription.pBuffer);
    }
    printf("\n");

exit:
    if (OK != status)
    {
        LOG_MESSAGE("Invalid property");
    }
    return;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = OK;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ConfigInfoList configInfoList = { 0, };
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Context *pTapContext = NULL;
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    ubyte4 i = 0;
    /*TAP_EntityCredentialList *pEntityCredentials = NULL;*/
    TAP_ModuleCapPropertyList propertyList = { 0 };
    /* Property Selection input struct */
    TAP_MODULE_CAP_CAP_T capability = 0;
    TAP_MODULE_CAP_PROPERTY_TAG property = 0;
    ubyte4 propertyCount = 0;

    TAP_Attribute getCapAttributes[] =
    {
        {   TAP_ATTR_GET_CAP_CAPABILITY,
            sizeof(TAP_MODULE_CAP_CAP_T), 
            &capability
        },
        {   TAP_ATTR_GET_CAP_PROPERTY,
            sizeof(TAP_MODULE_CAP_PROPERTY_TAG), 
            &property 
        },
        {   TAP_ATTR_GET_CAP_PROPERTY_COUNT,
            sizeof(pOpts->propertyCount),
            &propertyCount
        }
    };
    TAP_ModuleCapPropertyAttributes propertySelection = 
                        {
                            sizeof(getCapAttributes) / sizeof(*getCapAttributes),
                            getCapAttributes 
                        };

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

    capability = pOpts->capability;
    property = pOpts->property;
    propertyCount = pOpts->propertyCount;

#ifdef __ENABLE_TAP_REMOTE__
    /* If options are not specified in command line, check environment variables */
    TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                    &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                    &pOpts->serverPort);

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
        LOG_ERROR("Failed to open configuration file %s, status = %d", 
                pTpm2ConfigFile, status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_init",status);
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
        PRINT_STATUS("TAP_getModuleList", status);        
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
    }

    /* Initialize context on first module*/
    pTapContext = NULL;
    /*status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), pEntityCredentials,
                             NULL, &pTapContext, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_initContext", status);
        goto exit;
    }*/

    if(OK == status)
        contextInit = TRUE;

    /* Invoke TAP API */
    status = TAP_getModuleCapability(getTapModule(&moduleList, pOpts->moduleNum), 
                                     &propertySelection,
                                     &propertyList,
                                     pErrContext);

    if (ERR_TAP_UNSUPPORTED == status)
    {
        LOG_MESSAGE("Unsupported feature");
    }

    if (OK != status)
    {
        PRINT_STATUS("TAP_getModuleCapability failed with error ",
                    status);
        goto exit;
    }

    LOG_MESSAGE("%d properties fetched under capability %d",
                propertyList.numProperties, pOpts->capability);
    for (i = 0; i < propertyList.numProperties; i++)
    {
        printProperty(&(propertyList.pPropertyList[i]), pOpts->capability);
    } 

    status = TAP_UTILS_freeModuleCapPropertyList(&propertyList);
    if (OK != status)
    {
        PRINT_STATUS("Failed to free property-list", status);
        goto exit;
    }

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

    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
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
        TPM2_DEBUG_PRINT_1("Failed to get capabilities");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_getcapability failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

