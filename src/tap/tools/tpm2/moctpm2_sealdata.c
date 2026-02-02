/**
 @file moctpm2_sealdata.c

 @page digicert_tpm2_sealdata

 @ingroup digicert_tpm2_tools_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_sealdata -
 @endhtmlonly
 Get sealed data using a TPM 2.0 chip.

 # SYNOPSIS
 `digicert_tpm2_sealdata [options]`

 # DESCRIPTION
 <B>digicert_tpm2_sealdata</B> seals the input data to the TPM's SRK. The result can be unsealed via <B>digicert_tpm2_unsealdata</B>.

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
    --auth=[password]
        Authorization password to seal data. If no auth value is specified, the well-known password is used.
    --tdidx=[PCR index]
        PCR value to seal data. 
        Multiple PCRs may be specified with a --tdidx=option for each PCR index.
    --idf=[input data file]
        (Mandatory) Input file name that contains the data to be sealed.
    --odf=[output sealed data file]
        (Mandatory) Output file name that will contain the sealed data.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    --u [unicode]
         Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 digicert_tpm2_unseal

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

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096

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

    byteBoolean dataAuthSpecified;
    TAP_Buffer dataAuthValue;

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
#endif /* !__ENABLE_TAP_REMOTE__ */

    TAP_ModuleId moduleNum;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_sealdata: Help Menu\n");
    LOG_MESSAGE("This tool seals the input data to the TPM's SRK, and an optionally with the PCR configuration. The result can be unsealed with digicert_tpm2_unsealdata");

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
    LOG_MESSAGE("           --auth=[password]");
    LOG_MESSAGE("                   Authorization password to seal data.\n"
                "                   If no auth value is specified , the well-known password is used.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file name that contains the data to be sealed\n");
    LOG_MESSAGE("           --odf=[output sealed data file]");
    LOG_MESSAGE("                   (Mandatory) Output file name that will contain the sealed data\n");
    LOG_MESSAGE("           --tdidx=[PCR index]");
    LOG_MESSAGE("                   Optional: PCR value to seal the data.");
    LOG_MESSAGE("                   Multiple PCRs may be specified with a --tdidx=option for each PCR index\n");
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
            {"spass", required_argument, NULL, 8},
            {"tdidx", required_argument, NULL, 9},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 10},
#endif
            {"modulenum", required_argument, NULL, 11},
            {NULL, 0, NULL, 0},
    };
    ubyte currPcr = 0;
    MSTATUS status;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4  optValLen = 0;
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
            //LOG_MESSAGE("%s version: %d.%d\n", argv[0], TAP_TPM2_VERSION_MAJOR, TAP_TPM2_VERSION_MINOR);
            LOG_MESSAGE("TAP library version: %d.%d\n", TAP_VERSION_MAJOR, TAP_VERSION_MINOR);
            pOpts->exitAfterParse = TRUE;
            break;
#ifdef __ENABLE_TAP_REMOTE__
        case 3:
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

        case 4:
            pOpts->serverPortSpecified = TRUE;
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
            break;
#endif
        case 5:
            /* --auth password */
            pOpts->dataAuthSpecified = TRUE;
            pOpts->dataAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if (OK != (status = DIGI_CALLOC((void **)&pOpts->dataAuthValue.pBuffer, 1,
                            pOpts->dataAuthValue.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for password",
                        (int)pOpts->dataAuthValue.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->dataAuthValue.pBuffer, optarg, 
                        pOpts->dataAuthValue.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Auth value: %s", optarg); 

            break;

        case 6:
            /* --idf input data file */
            pOpts->inFileSpecified = TRUE;
            pOpts->inFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->inFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--idf Input data file not specified");
                goto exit;
            }

            if (pOpts->inFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Input data file path too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_CALLOC((void **)&pOpts->inFile.pBuffer, 1,
                            pOpts->inFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for input data filename",
                        (int)pOpts->inFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->inFile.pBuffer, optarg, 
                        pOpts->inFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Input data filename: %s", pOpts->inFile.pBuffer);

            break;

        case 7:
            /* --odf output sealed data file */
            pOpts->outFileSpecified = TRUE;
            pOpts->outFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->outFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--odf Output sealed data filename not specified");
                goto exit;
            }

            if (pOpts->outFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Sealed data file path too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_CALLOC((void **)&pOpts->outFile.pBuffer, 1,
                            pOpts->outFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for output filename",
                        (int)pOpts->outFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outFile.pBuffer, optarg, 
                        pOpts->outFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Sealed data filename: %s", pOpts->outFile.pBuffer);

            break;

        case 9:
            currPcr = strtol(optarg, NULL, 0);
            if (currPcr > 23)
            {
                LOG_ERROR("Invalid PCR number specified");
                goto exit;
            }
            pOpts->pcrList[pOpts->numPcrs] = (ubyte)currPcr;
            TPM2_DEBUG_PRINT("PCR: %d", pOpts->pcrList[pOpts->numPcrs]);
            pOpts->numPcrs++;
            pOpts->pcrSpecified = TRUE ;

            break;
        case 10:
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
             case 11:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
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
    MSTATUS status = ERR_GENERAL;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_CredentialList dataCredentials = { 0 };
    TAP_CredentialList *pDataCredentials = NULL;
    TAP_EntityCredentialList entityCredentials = { 0 }; 
    TAP_EntityCredentialList *pEntityCredentials = NULL;
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
/*    int numCredentials = 0;*/
    int i = 0;
    TAP_Buffer inData = { 0 };
    TAP_Buffer outData = { 0 };
    TAP_SealAttributes sealAttributes = { 0 };
    TAP_SealAttributes *pSealAttributes = NULL;
    /*TAP_TokenId srkTokenId = 0;*/
    TAP_Buffer pcrData = { 0 };
    ubyte sealAttributesCnt = 0 ;
    TAP_TRUSTED_DATA_TYPE dataType ;
 
    TAP_OBJECT_TYPE objectType = TAP_OBJECT_TYPE_UNDEFINED; // For TPM2 for now.
    void *pObject = NULL;

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

    if (!pOpts->dataAuthSpecified && !pOpts->pcrSpecified)
    {
        LOG_ERROR("One or more mandatory options --tdidx or --auth not specified.");
        goto exit;
    }

    if (!pOpts->serverNameSpecified ||
             !pOpts->inFileSpecified || !pOpts->outFileSpecified) 
    {
        LOG_ERROR("One or more mandatory options --s, --idf, --osf not specified.");
        goto exit;
    }
    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) && DIGI_STRNICMP((const sbyte *)pOpts->serverName, 
                                                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;   
    }
#else
    if (!pOpts->inFileSpecified || !pOpts->outFileSpecified) 
    {
        LOG_ERROR("One or more mandatory options --idf, --osf not specified.");
        goto exit;
    }    
#endif
    

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

    status = TAP_init(&configInfoList, &errContext);
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
    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, &errContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, &errContext);
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
            &errContext);

    if (OK != status)
    {
        PRINT_STATUS("Failed to get credentials from Credential configuration file", status);
        goto exit;
    }
#endif

    if ((0 != pOpts->dataAuthValue.bufferLen) && (NULL != pOpts->dataAuthValue.pBuffer))
    {
        status = DIGI_CALLOC((void **) &(dataCredentials.pCredentialList), 1, sizeof(TAP_Credential));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }
        dataCredentials.numCredentials = 1;
        dataCredentials.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        dataCredentials.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        dataCredentials.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        dataCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->dataAuthValue.bufferLen;
        dataCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->dataAuthValue.pBuffer;
        pDataCredentials = &dataCredentials;
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
        i = 0;
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
        sealAttributes.listLen = i ;
        pSealAttributes = &sealAttributes ;

    }
    
    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), pEntityCredentials,
                             NULL, &pTapContext, &errContext);
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
    /* Seal */
    status = TAP_sealWithTrustedData(pTapContext, pEntityCredentials, objectType, pObject, pDataCredentials, pSealAttributes,
                                        &inData, &outData, &errContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_sealWithTrustedData", status);
        goto exit;
    }

    /* Save sealed data to output file */
    status = DIGICERT_writeFile((const char *)pOpts->outFile.pBuffer,
                                outData.pBuffer, outData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing sealed data to file, status = %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("Successfully sealed data\n");
    retval = 0;

exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if ((NULL != pTpm2ConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif

    if (NULL != inData.pBuffer)
        DIGICERT_freeReadFile(&inData.pBuffer);
    
    if (NULL != outData.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&outData);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
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
        status = TAP_uninitContext(&pTapContext, &errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
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

        /* Don't free dataAuthValue TAP_Buffer as they are freed by TAP_UTILS_clearCredentialList */
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
        TPM2_DEBUG_PRINT_1("Failed to seal data.");
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
        LOG_ERROR("*****digicert_tpm2_sealdata failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

