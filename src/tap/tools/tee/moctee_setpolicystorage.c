/**
 @file moctee_setpolicystorage.c

 @page moctee_setpolicystorage

 @ingroup tap_tools_tee_commands

 @htmlonly
 <h1>NAME</h1>
 moctee_setpolicystorage -
 @endhtmlonly
 This tool writes data for secure storage.

 # SYNOPSIS
 `moctee_setpolicystorage [options]`

 # DESCRIPTION
 <B>moctee_setpolicystorage</B> This tool writes data for secure storage.

@verbatim

    --help [display command line options]
        Help menu
    --id=[String id]
         (Mandatory) Data identifier.
    --data=[data in hex form with leading 0x and even number of chars]
         Input data to write.
    --idf=[input data file]
         Input file containing data to write.
    --conf=[TEE configuration file]
        Path to TEE module configuration file. Default is /etc/mocana/tee_smp.conf
    --s=[server name]
        Host on which TEE is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TEE server is listening.
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used.

@endverbatim

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
#include "../../../common/utils.h"
#include "../../tap_api.h"
#include "../../tap_common.h"
#include "../../tap_utils.h"
#include "../../tap_serialize.h"
#include "../../tap_serialize_smp.h"
#include "../moctap_tools_utils.h"
#include "../../../smp/smp_tee/smp_tap_tee.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../common/mcmdline.h"
#include "errno.h"
#endif

#ifndef TEE_CONFIG_PATH
#if defined(__RTOS_WIN32__)
#define TEE_CONFIG_PATH "tee_smp.conf"
#else
#define TEE_CONFIG_PATH "/etc/mocana/tee_smp.conf"
#endif
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define IS_VALID_PORT(p) ((p) > 0 && (p) <= 65535)

#define TEE_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TEE_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define PRINT_STATUS(x,y)   \
            DB_PRINT("%s %s status %d = %s\n", x, (y==OK ? "SUCCESS":"FAILED"),\
                        y, MERROR_lookUpErrorCode(y))

typedef struct 
{
    byteBoolean exitAfterParse;
    
    byteBoolean idSpecified;
    TAP_Buffer id;

    byteBoolean dataSpecified;
    TAP_Buffer data;

    byteBoolean dataFileSpecified;
    TAP_Buffer dataFile;

#ifdef __ENABLE_TAP_REMOTE__
    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN + 1];

    ubyte4 serverNameLen;
    ubyte4 serverPort;
#else
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* __ENABLE_TAP_REMOTE__ */

    TAP_ModuleId moduleNum;

} cmdLineOpts;

static MSTATUS utilReadId(sbyte *pStr, TAP_Buffer *pOutId)
{
    MSTATUS status = ERR_INVALID_ARG;
    ubyte *pId = NULL;
    ubyte4 idLen = 0;
    byteBoolean isHex = FALSE;

    idLen = (ubyte4) DIGI_STRLEN(pStr);
    if ( (idLen >= 3) && pStr[0] == '0' && (pStr[1] == 'x' || pStr[1] == 'X') )
        isHex = TRUE;

    /* internal method, NULL checks not necc */
    if (isHex)
    {
       /* use idLen as a temp for string form lem */
        if (idLen < 4 || idLen & 0x01)
        {
            goto exit;
        }
        
        /* now get the real id Len */
        idLen = (idLen - 2) / 2;

        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
            goto exit;

        status = DIGI_ATOH(pStr + 2, idLen*2, pId);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **) &pId, idLen + 1); /* we'll add a zero byte for string form printing */
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pId, (ubyte *) pStr, idLen);
        if (OK != status)
            goto exit;

        pId[idLen] = 0x0;
    }

    pOutId->pBuffer = pId; pId = NULL;
    pOutId->bufferLen = idLen; idLen = 0;

exit:

    if (NULL != pId)
    {
        (void) DIGI_MEMSET_FREE(&pId, idLen);
    }
    
    return status;
}

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("moctee_setpolicystorage: Help Menu\n");
    LOG_MESSAGE("This tool writes data to secure storage.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --help [display command line options]\n");
    LOG_MESSAGE("                Help menu\n");
    LOG_MESSAGE("           --id=[Hex id or String id]\n");
    LOG_MESSAGE("                (Mandatory) Data identifier. If beginning with 0x or 0X this\n");
    LOG_MESSAGE("                will be treated as a hex array (must be even number of chars).\n");
    LOG_MESSAGE("                Otherwise this will be treated as an ascii string.\n");
    LOG_MESSAGE("           --data=[data in hex form with leading 0x and even number of chars]\n");
    LOG_MESSAGE("                Input data to write.\n");
    LOG_MESSAGE("           --idf=[input data file]\n");
    LOG_MESSAGE("                Input file containing data to write.\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[server name]");
    LOG_MESSAGE("                   Mandatory. Host on which TEE is located. This can be 'localhost' or a\n"
                "                   remote host running a TAP server.\n");
    LOG_MESSAGE("           --p=[server port]");
    LOG_MESSAGE("                   Port on which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[TEE configuration file]");
    LOG_MESSAGE("                   Path to the TEE module configuration file. Default is /etc/mocana/tee_smp.conf\n");
#endif
    LOG_MESSAGE("           --modulenum=[module num]");
    LOG_MESSAGE("                   Specify the module num to use. If not provided, the first module found is used.\n");

    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] =
    {
        {"help", no_argument, NULL, 1},
        {"id", required_argument, NULL, 2},
        {"data", required_argument, NULL, 3},
        {"idf", required_argument, NULL, 4},
#ifdef __ENABLE_TAP_REMOTE__
        {"s", required_argument, NULL, 5},
        {"p", required_argument, NULL, 6},
#else
        {"conf", required_argument, NULL, 7},
#endif
        {"modulenum", required_argument, NULL, 8},
        {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    ubyte4 optValLen = 0;

    if (!pOpts || !argv || (0 == argc))
    {
        TEE_DEBUG_PRINT_1("Invalid parameters.");
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
                /* --id value */
                optValLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (0 == optValLen|| '-' == optarg[0])
                {
                    LOG_ERROR("--id not specified");
                    goto exit;
                }

                status = utilReadId((sbyte *) optarg, &pOpts->id);
                if (OK != status)
                {
                    LOG_ERROR("Unable to read the id\n");
                    goto exit;
                }                
                pOpts->idSpecified = TRUE;
                break;

            case 3:
                /* --data value */
                optValLen = DIGI_STRLEN((const sbyte *)optarg);

                if (optValLen < 4 || optValLen & 0x1 || '0' != optarg[0] || 'x' != optarg[1])
                {
                    TEE_DEBUG_PRINT_1("Failed to convert --data hex string, must have leading 0x and even number of chars");
                    goto exit;
                }

                pOpts->data.bufferLen = (optValLen - 2)/2;

                status = DIGI_MALLOC((void **) &pOpts->data.pBuffer, pOpts->data.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Unable to allocate %d bytes for the data buffer",
                            (int)pOpts->data.bufferLen);
                    goto exit;
                }

                status = DIGI_convertHexString((const char *)&optarg[2], pOpts->data.pBuffer, pOpts->data.bufferLen);
                if (OK != status)
                {
                        TEE_DEBUG_PRINT_1("Failed to convert hex string");
                        DIGI_FREE((void **)&pOpts->data.pBuffer);
                        pOpts->data.bufferLen = 0;
                        goto exit;                    
                }
                       
                pOpts->dataSpecified = TRUE;
                break;

            case 4:

                /* --idf value */
                pOpts->dataFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (pOpts->dataFile.bufferLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("Input file path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if (0 == pOpts->dataFile.bufferLen || '-' == optarg[0])
                {
                    LOG_ERROR("--idf not specified");
                    goto exit;
                }

                /* we'll allocate extra space so it stays a C string */
                status = DIGI_MALLOC((void **) &pOpts->dataFile.pBuffer, pOpts->dataFile.bufferLen + 1);
                if (OK != status)
                {
                    LOG_ERROR("Unable to allocate %d bytes for the dataFile",
                            (int)(pOpts->dataFile.bufferLen + 1));
                    goto exit;
                }
                
                status = DIGI_MEMCPY(pOpts->dataFile.pBuffer, optarg, pOpts->dataFile.bufferLen);
                if (OK != status)
                {
                    TEE_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->dataFile.pBuffer);
                    pOpts->dataFile.bufferLen = 0;
                    goto exit;
                }
 
                pOpts->dataFile.pBuffer[pOpts->dataFile.bufferLen] = 0x00;
                pOpts->dataFileSpecified = TRUE;
                break;

#ifdef __ENABLE_TAP_REMOTE__
            case 5:
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);

                if (pOpts->serverNameLen >= SERVER_NAME_LEN)
                {
                    LOG_ERROR("Server name too long. Max length: %d characters",
                            SERVER_NAME_LEN - 1);
                    goto exit;
                }
                if (pOpts->serverNameLen == 0 || '-' == optarg[0])
                {
                    LOG_ERROR("--s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))
                {
                    TEE_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverName[pOpts->serverNameLen] = '\0';
                TEE_DEBUG_PRINT("TEE Server/Module name: %s", pOpts->serverName);
                pOpts->serverNameSpecified = TRUE;
                break;

            case 6:
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
                    TEE_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
                break;
#else
            case 7:
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((0 == optValLen) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Configuration file path not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
                {
                    TEE_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->confFilePath[optValLen] = '\0';
                TEE_DEBUG_PRINT("TEE Configuration file path: %s", 
                                    pOpts->confFilePath);
                pOpts->isConfFileSpecified = TRUE;
                break;
#endif /* __ENABLE_TAP_REMOTE__ */
            case 8:
                {
                    char *endptr;
                    long moduleNum;
                    errno = 0;
                    moduleNum = strtol(optarg, &endptr, 0);
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (moduleNum < 0))
                    {
                        TEE_DEBUG_PRINT_1("Invalid module num. Must be greater than or equal to 0");
                        goto exit;
                    }
                    pOpts->moduleNum = (TAP_ModuleId)moduleNum;
                    TEE_DEBUG_PRINT("module num: %d", (int) pOpts->moduleNum);
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
    int retval = 0;
    MSTATUS status = OK;
  
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ConfigInfo config = {0};
    TAP_ConfigInfoList configInfoList = {0,};
    TAP_ErrorContext errContext = {0};
    TAP_ObjectInfo objInfo = {0};

    ubyte4 tokenId = TEE_SECURE_STORAGE;
    
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#else
    char *pConfigFile = NULL;
#endif

    config.provider = TAP_PROVIDER_TEE;
    configInfoList.count = 1;
    configInfoList.pConfig = &config;

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        (void) TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                                       &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                                       &pOpts->serverPort);
        /* next if will goto exit anyway, no status check ok */
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

#else
    if (TRUE == pOpts->isConfFileSpecified)
    {
        pConfigFile = pOpts->confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pConfigFile, TEE_CONFIG_PATH);
        if (OK != status)
        {
            goto exit;
        }
#else
        pConfigFile = TEE_CONFIG_PATH;
#endif
    }

    status = TAP_readConfigFile((char *) pConfigFile, &configInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
    {
        LOG_ERROR("TAP_readConfigFile failed with error %d", status);
        goto exit;
    }

#endif /* __ENABLE_TAP_REMOTE__ */

    status = TAP_init(&configInfoList, &errContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_init failed with error %d", status);
        goto exit;
    }

    /* Discover modules */
#ifdef __ENABLE_TAP_REMOTE__
    connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
    connInfo.serverName.bufferLen = pOpts->serverNameLen;
    connInfo.serverPort = pOpts->serverPort;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TEE, NULL,
            &moduleList, &errContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TEE, NULL,
            &moduleList, &errContext);
#endif
    if (OK != status)
    {
        LOG_ERROR("TAP_getModuleList failed with error %d", status);
        goto exit;
    }
  
    if (0 == moduleList.numModules)
    {
        LOG_ERROR("No TEE modules found\n");
        goto exit;
    }

    status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), NULL, NULL, &pTapContext, &errContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_initContext failed with error %d", status);
        goto exit;
    }

    /* We set the object Id as an attribute */
    status = DIGI_MALLOC((void **) &objInfo.objectAttributes.pAttributeList, 1 * sizeof(TAP_Attribute));
    if (OK != status)
    {
        LOG_ERROR("Unable to allocate the attribute list");
        goto exit;
    }

    objInfo.objectAttributes.pAttributeList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    objInfo.objectAttributes.pAttributeList[0].length = sizeof(pOpts->id);
    objInfo.objectAttributes.pAttributeList[0].pStructOfType = (void *)&pOpts->id;

    objInfo.objectAttributes.listLen = 1;
    objInfo.tokenId = tokenId;
    objInfo.providerType = TAP_PROVIDER_TEE; /* ok to set this but not needed */

    if (pOpts->dataFileSpecified)
    {
        /* Read input data file */
        status = UTILS_readFile((const char *)pOpts->dataFile.pBuffer, &pOpts->data.pBuffer, &pOpts->data.bufferLen);
        if (OK != status)
        {
            LOG_ERROR("Error reading input data file contents from file, status = %d\n", status);
            goto exit;
        }
    }

    status = TAP_setPolicyStorage(pTapContext, NULL, &objInfo, NULL, &pOpts->data, &errContext);
    if (OK != status)
    {
        LOG_ERROR("TAP_setPolicyStorage failed with error %d", status);
    }

exit:

    (void) TAP_UTILS_freeBuffer(&(configInfoList.pConfig[0].configInfo)); /* ok if empty configInfo */

    if (NULL != moduleList.pModuleList)
    {
        (void) TAP_freeModuleList(&moduleList);
    }

    if (NULL != objInfo.objectAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &objInfo.objectAttributes.pAttributeList);
    }

    /* if pOpts->data.pBuffer was allocated it'll be freed later */
    (void) TAP_uninitContext(&pTapContext, &errContext);
    (void) TAP_uninit(&errContext);

    return retval;
}

static void freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts->id.pBuffer)
        shredMemory((ubyte **)&(pOpts->id.pBuffer), pOpts->id.bufferLen, TRUE);
    if (pOpts->data.pBuffer)
        shredMemory((ubyte **)&(pOpts->data.pBuffer), pOpts->data.bufferLen, TRUE);
    if (pOpts->dataFile.pBuffer)
        shredMemory((ubyte **)&(pOpts->dataFile.pBuffer), pOpts->dataFile.bufferLen, TRUE);

    return;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts opts = {0};
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    if (NULL == platCmdLineParser)
    {
        TEE_DEBUG_PRINT_1("No command line parser available for this platform.");
        goto exit;
    }

    if (0 != platCmdLineParser(&opts, argc, argv))
    {
        TEE_DEBUG_PRINT_1("Failed to parse command line options.");
        printHelp();
        goto exit;
    }

    if (opts.exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    if (!opts.idSpecified)
    {
        TEE_DEBUG_PRINT_1("Must specify --id.");
        goto exit;        
    }

    if (!opts.dataSpecified && !opts.dataFileSpecified)
    {
        TEE_DEBUG_PRINT_1("Must specify one of --data or --idf.");
        goto exit;
    }

    if (opts.dataSpecified && opts.dataFileSpecified)
    {
        TEE_DEBUG_PRINT_1("May only specify one of --data or --idf.");
        goto exit;
    }

    if (0 != executeOptions(&opts))
    {
        TEE_DEBUG_PRINT_1("Failed to write at specified NVRAM index");
        goto exit;
    }

    retval = 0;

exit:

    freeOptions(&opts);
    (void) DIGI_MEMSET((void *) &opts, 0x00, sizeof(opts));

    if (0 != retval)
        LOG_ERROR("*****moctee_setpolicystorage failed to complete successfully.*****");

    return retval;
}
