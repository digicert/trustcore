/**
 @file moctpm2_duplicatekey.c

 @page digicert_tpm2_duplicatekey

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_duplicatekey -
 @endhtmlonly
 This tool generates duplicate key for export into another TPM.

 # SYNOPSIS
 `digicert_tpm2_duplicatekey [options]`

 # DESCRIPTION
 <B>digicert_tpm2_duplicatekey</B> This tool generates duplicate key for export into another TPM.

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
    --kpwd=[key password]
        (Optional) Password of the key to be loaded.
    --pri=[input private key file]
        (Mandatory) Input file that contains the private key.
    --pub=[pubkey blob file]
        (Mandatory) Input file that contains the public key blob of the new parent.
    --odf=[output signature file]
        (Mandatory) Output file that contains the duplicated key.
    --modulenum=[module num]
        Module number to use. If not provided first module is used by default
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
@endverbatim

 # SEE ALSO
 digicert_tpm2_importduplicatekey

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
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../../data_protection/file_protect.h"
#endif
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

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

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

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean inPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

    byteBoolean inPubKeyFileSpecified;
    TAP_Buffer pubKeyFile;


    byteBoolean outDupFileSpecified;
    TAP_Buffer outDupFile;

    ubyte4 serverNameLen;
    ubyte4 serverPort;

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
    LOG_MESSAGE("digicert_tpm2_duplicatekey: Help Menu\n");
    LOG_MESSAGE("This tool generates duplicate key for export into another TPM.");

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
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   (Optional) password of the key to be loaded.\n");
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the private key.\n");
    LOG_MESSAGE("           --pub=[pubkey blob file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the public key blob of the new parent.\n");
    LOG_MESSAGE("           --odf=[output duplicate key file]");
    LOG_MESSAGE("                   (Mandatory) Output file that contains the duplicated key.\n");
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
int posixParseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
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
            {"pri", required_argument, NULL, 4},
            {"kpwd", required_argument, NULL, 5},
            {"pub", required_argument, NULL, 6},
            {"odf", required_argument, NULL, 8},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 11},
#endif
            {"modulenum", required_argument, NULL, 12},
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
#endif
            case 4:
                /* --pri input private key file */
                pOpts->inPrivKeyFileSpecified = TRUE;
                pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->privKeyFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--pri Private key output file not specified");
                    goto exit;
                }

                if(DIGI_STRLEN((const sbyte *)optarg) > FILE_PATH_LEN)
                {
                    LOG_ERROR("--pri Private key input file path too long");
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, 
                                pOpts->privKeyFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for private key filename",
                            (int)pOpts->privKeyFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, 
                            pOpts->privKeyFile.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

                break;

            case 5:
                /* --kpwd password */
                pOpts->keyAuthSpecified = TRUE;
                pOpts->keyAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer,
                                pOpts->keyAuthValue.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for key password",
                            (int)pOpts->keyAuthValue.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg,
                            pOpts->keyAuthValue.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Key password: %s", optarg); 

                break;

            case 6:
                /* --pub input new parent public key file */
                pOpts->inPubKeyFileSpecified = TRUE;
                pOpts->pubKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->pubKeyFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--pub New parent public key file not specified");
                    goto exit;
                }

                if(DIGI_STRLEN((const sbyte *)optarg) > FILE_PATH_LEN)
                {
                    LOG_ERROR("--pub New parent public key input file path too long");
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->pubKeyFile.pBuffer, 
                                pOpts->pubKeyFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for new public key filename",
                            (int)pOpts->pubKeyFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->pubKeyFile.pBuffer, optarg, 
                            pOpts->pubKeyFile.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("New parent public key filename: %s", pOpts->pubKeyFile.pBuffer);

                break;


            case 8:
                /* --odf output signature file */
                pOpts->outDupFileSpecified = TRUE;
                pOpts->outDupFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->outDupFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--odf Output signature file not specified");
                    goto exit;
                }

                if(DIGI_STRLEN((const sbyte *)optarg) > FILE_PATH_LEN)
                {
                    LOG_ERROR("--odf Output duplicate key file path too long");
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->outDupFile.pBuffer, 
                                pOpts->outDupFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for duplicate filename",
                            (int)pOpts->outDupFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->outDupFile.pBuffer, optarg, 
                            pOpts->outDupFile.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Duplicate filename: %s", pOpts->outDupFile.pBuffer);

                break;

            case 11:
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
            case 12:
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
    MSTATUS status = ERR_GENERAL;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_ConfigInfoList configInfoList = { 0, };
#ifndef __ENABLE_TAP_REMOTE__
    const char *pTpm2ConfigFile = (const char *)TPM2_CONFIGURATION_FILE;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    TAP_Buffer keyBlob = {0};
    TAP_Buffer pubKey = {0};
    TAP_Buffer duplicateKey = {0};
    TAP_Key *pLoadedTapKey = NULL;


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

    if (!pOpts->serverNameSpecified || !pOpts->inPrivKeyFileSpecified || 
            !pOpts->inPubKeyFileSpecified ||
            !pOpts->outDupFileSpecified) 
    {
        LOG_ERROR("One or more mandatory options --s, --p, --pub or --odf not specified.");
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
    if (!pOpts->inPubKeyFileSpecified || !pOpts->inPrivKeyFileSpecified ||
        !pOpts->outDupFileSpecified)
    {
        LOG_ERROR("One or more mandatory options --pub, --odf not specified.");
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

    if ((0 != pOpts->keyAuthValue.bufferLen) && (NULL != pOpts->keyAuthValue.pBuffer))
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
        keyCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->keyAuthValue.bufferLen;
        keyCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->keyAuthValue.pBuffer;
        pKeyCredentials = &keyCredentials;
    }

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

    /* TODO: Format input parameters */
    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->pubKeyFile.pBuffer, 
                                    &pubKey.pBuffer, &pubKey.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error reading the pub key file of the parent, status = %d\n", status);
        goto exit;
    }
        /* Invoke TAP API */
        /* Load Key object from file */
        /* Read input data file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        status = DIGICERT_readFileEx((const char *)pOpts->privKeyFile.pBuffer, 
                                    &keyBlob.pBuffer, &keyBlob.bufferLen, TRUE);
#else
        status = DIGICERT_readFile((const char *)pOpts->privKeyFile.pBuffer, 
                                    &keyBlob.pBuffer, &keyBlob.bufferLen);
#endif

        if (OK == status)
        {
            /* Deserialize into TAPKey */
            status = TAP_deserializeKey(&keyBlob, &pLoadedTapKey, pErrContext);
            if (OK != status)
            {
                PRINT_STATUS("TAP_deserializeKey", status);
                goto exit;
            }

            status = TAP_loadKey(pTapContext, pEntityCredentials, pLoadedTapKey, pKeyCredentials, NULL, pErrContext);
            if (OK != status)
            {
                PRINT_STATUS("TAP_loadKey", status);
                goto exit;
            }

            status = TAP_exportDuplicateKey(pLoadedTapKey, pEntityCredentials, NULL,
                                            &pubKey, &duplicateKey, pErrContext);

            if (OK != status)
            {
                PRINT_STATUS("Dupliacte failed", status);
                goto exit;
            }
            else
            {

                /* Save Signature to output file */
                status = DIGICERT_writeFile((const char *)pOpts->outDupFile.pBuffer,
                                            duplicateKey.pBuffer, duplicateKey.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Error writing duplicate to file, status = %d\n", status);
                    goto exit;
                }

                LOG_MESSAGE("key is duplicated successfully!\n");

                retval = 0;
            }
        }
        else
        {
            LOG_ERROR("Error reading the private key file, status = %d\n", status);
        }

exit:
    if (NULL != pLoadedTapKey)
    {
        /* Unload key object */
        status = TAP_unloadKey(pLoadedTapKey, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);
        
        /* Free Key */
        status = TAP_freeKey(&pLoadedTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
    }

    if (NULL != duplicateKey.pBuffer)
        DIGICERT_freeReadFile(&duplicateKey.pBuffer);
    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&keyBlob.pBuffer);
    if (NULL != pubKey.pBuffer)
        DIGICERT_freeReadFile(&pubKey.pBuffer);


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

    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials);
    }

    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->outDupFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outDupFile.pBuffer);

        if (pOpts->pubKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->pubKeyFile.pBuffer);

        if (pOpts->privKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);

        /* Don't free keyAuthValue TAP_Buffers as they are freed by TAP_UTILS_clearCredentialList */
    }

    return;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts *pOpts = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
    platCmdLineParser = posixParseCmdLineOpts;
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
        TPM2_DEBUG_PRINT_1("Failed to generate signature.");
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
        LOG_ERROR("*****digicert_tpm2_duplicatekey failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

