/**
 @file moctpm2_verifyquote.c

 @page digicert_tpm2_verifyquote

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_verify -
 @endhtmlonly
 Verify a signature on quote using a TPM 2.0 key.

 # SYNOPSIS
 `digicert_tpm2_verifyquote [options]`

 # DESCRIPTION
 <B>digicert_tpm2_verifyquote</B> This tool verifies the signature of TPM quote.

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
    --kpwd=[key password]
        (Optional) Password of the key to load.
    --halg=[hash algorithm]
        (Mandatory) Hash algorithm (sha1 or sha256 or sha384 or sha512) for the hash of the TPM quote.
    --pri=[input private key file]
        (Mandatory) Input file that contains the private key.
    --idf=[input data file]
        (Mandatory) Input file that contains the data to verify.
    --isf=[Input signature file]
        (Mandatory) Input file that contains the signature.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 digicert_tpm2_createasymkey,  digicert_tpm2_createsymkey, digicert_tpm2_getquote

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
#include "../../../crypto/hw_accel.h"
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

    byteBoolean hashAlgSpecified;
    TAP_HASH_ALG hashAlg;

    byteBoolean inPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

    byteBoolean inFileSpecified;
    TAP_Buffer inFile;

    byteBoolean inSignatureFileSpecified;
    TAP_Buffer inSignatureFile;

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
    LOG_MESSAGE("digicert_tpm2_verifyquote: Help Menu\n");
    LOG_MESSAGE("This tool verifies the signature of TPM quote.");

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
    LOG_MESSAGE("                   (Optional) Password of the key to load.\n");
    LOG_MESSAGE("           --halg=[hash algorithm]");
    LOG_MESSAGE("                   (Mandatory) Hash algorithm (sha1 or sha256 or sha384 or sha512) for the hash of the TPM quote.\n");
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the private key\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the data to verify.\n");
    LOG_MESSAGE("           --isf=[input signature file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the signature.\n");
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
            {"halg", required_argument, NULL, 4},
            {"kpwd", required_argument, NULL, 5},
            {"pri", required_argument, NULL, 6},
            {"idf", required_argument, NULL, 7},
            {"isf", required_argument, NULL, 8},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 11},
#endif
            {"modulenum", required_argument, NULL, 13},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
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
                LOG_ERROR("Invalid server port: %d. Port must be between 1 and 65535.", pOpts->serverPort);
                goto exit;
            }
            TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
            break;
#endif
        case 4:
            /* --halg digest hash algorithm */
            pOpts->hashAlgSpecified = TRUE;

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--halg Digest hash algorithm not specified");
                goto exit;
            }

            /* Validate hash algorithm string length */
            if (DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"sha512"))
            {
                LOG_ERROR("--halg Invalid hash algorithm. Must be sha1, sha256, sha384, or sha512");
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha1",
                    DIGI_STRLEN((const sbyte *)"sha1"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA1;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA1");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha256",
                    DIGI_STRLEN((const sbyte *)"sha256"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA256;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA256");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha384",
                    DIGI_STRLEN((const sbyte *)"sha384"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA384;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA384");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha512",
                    DIGI_STRLEN((const sbyte *)"sha512"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA512;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA512");
                break;
            }
            LOG_ERROR("--kh not sha1 or sha256 or sha512");
            goto exit;
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
            /* --pri input private key file */
            pOpts->inPrivKeyFileSpecified = TRUE;
            pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->privKeyFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--pri Input private key file not specified");
                goto exit;
            }

            /* Validate private key file path length */
            if (pOpts->privKeyFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Private key file path too long");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, 
                            pOpts->privKeyFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for Private key filename",
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

        case 7:
            /* --idf input data file */
            pOpts->inFileSpecified = TRUE;
            pOpts->inFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->inFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--idf Input data file not specified");
                goto exit;
            }

            /* Validate input data file path length */
            if (pOpts->inFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Input data file path too long.");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->inFile.pBuffer, 
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

        case 8:
            /* --isf input signature file */
            pOpts->inSignatureFileSpecified = TRUE;
            pOpts->inSignatureFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->inSignatureFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--isf Input signature file not specified");
                goto exit;
            }

            /* Validate input signature file path length */
            if (pOpts->inSignatureFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Input signature file path too long. Max size: %d bytes", FILE_PATH_LEN);
                goto exit;
            }
            
            if (OK != (status = DIGI_MALLOC((void **)&pOpts->inSignatureFile.pBuffer, 
                            pOpts->inSignatureFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for signature filename",
                        (int)pOpts->inSignatureFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->inSignatureFile.pBuffer, optarg, 
                        pOpts->inSignatureFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Signature filename: %s", pOpts->inSignatureFile.pBuffer);

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

            case 13:
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
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    ubyte4 bufferLen = 0;
    ubyte *pBuffer = NULL;
    ubyte digestBuf[SHA512_RESULT_SIZE];
    TAP_Buffer keyBlob = {0};
    TAP_Signature signature = {0};
    TAP_Key *pLoadedTapKey = NULL;
    ubyte *pSignatureBuffer = NULL;
    ubyte4 signatureBufferLen;
    ubyte4 offset = 0;
    /*int numCredentials = 0;*/
    byteBoolean isSigValid = 0;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    /*int i = 0;*/
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    hwAccelDescr hwAccelCtx = 0;

    TAP_Buffer digest = 
    {
        .pBuffer    = digestBuf,
        .bufferLen  = 0    
    };

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto help_exit;
    }
#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                &pOpts->serverPort);
    }

    if (!pOpts->serverNameSpecified ||  
            !pOpts->inPrivKeyFileSpecified || !pOpts->inFileSpecified ||
            !pOpts->inSignatureFileSpecified || !pOpts->hashAlgSpecified )
    {
        LOG_ERROR("One or more mandatory options --s, --pri, --halg, --idf, --isf not specified.");
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
    if (!pOpts->inPrivKeyFileSpecified || !pOpts->inFileSpecified ||
        !pOpts->inSignatureFileSpecified || !pOpts->hashAlgSpecified)
    {
        LOG_ERROR("One or more mandatory options --pri, --halg, --idf, --isf not specified.");
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
        status = TAP_UTILS_getWinConfigFilePath(&pTpm2ConfigFile,
            TPM2_CONFIGURATION_FILE);
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
        LOG_ERROR("No TPM2 modules found\n");
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

    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->inFile.pBuffer, &pBuffer, &bufferLen);
    if (OK == status)
    {
        status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
        if (OK != status)
            goto exit;
        
        /* Generate digest using specified hash algorithm */
        switch (pOpts->hashAlg)
        {
            case TAP_HASH_ALG_SHA1:
                SHA1_completeDigest(MOC_HASH(hwAccelCtx) pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA1_RESULT_SIZE;
                break;

            case TAP_HASH_ALG_SHA512:
                SHA512_completeDigest(MOC_HASH(hwAccelCtx) pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA512_RESULT_SIZE;
                break;

            case TAP_HASH_ALG_SHA384:
                SHA384_completeDigest(MOC_HASH(hwAccelCtx) pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA384_RESULT_SIZE;
                break;

            case TAP_HASH_ALG_SHA256:
            default:
                SHA256_completeDigest(MOC_HASH(hwAccelCtx) pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA256_RESULT_SIZE;
                break;
        }

        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

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

            /* Load TAPKey from the serialized key blob */
            status = TAP_loadKey(pTapContext, pEntityCredentials, pLoadedTapKey, pKeyCredentials, NULL, pErrContext);
            if (OK != status)
            {
                PRINT_STATUS("TAP_loadKey", status);
                goto exit;
            }

            {
                /* Load Signature file */
                status = DIGICERT_readFile((const char *)pOpts->inSignatureFile.pBuffer,
                        &pSignatureBuffer, &signatureBufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Error reading signature to file, status = %d\n", status);
                    goto exit;
                }

                /* Serialize signature */
                offset = 0;
                status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Signature,
                                                TAP_SD_OUT, 
                                                pSignatureBuffer, signatureBufferLen,
                                                (void *)&signature, sizeof(signature), &offset);
                if (OK != status)
                {
                    PRINT_STATUS("TAP_SERIALIZE_serialize", status);
                    goto exit;
                }

                /* Verify Signature using the appropriate API */
                if (TAP_KEY_ALGORITHM_HMAC == pLoadedTapKey->keyData.keyAlgorithm)
                {
                    status = TAP_symVerifySignature(pLoadedTapKey, pEntityCredentials, NULL, &digest,
                                                    &signature, &isSigValid, pErrContext);
                }
                else
                {
                    if (pLoadedTapKey->keyData.keyAlgorithm == TAP_KEY_ALGORITHM_RSA)
                        sigScheme = pLoadedTapKey->keyData.algKeyInfo.rsaInfo.sigScheme;
                    else
                        sigScheme = pLoadedTapKey->keyData.algKeyInfo.eccInfo.sigScheme;

                    status = TAP_asymVerifySignature(pLoadedTapKey, pEntityCredentials, NULL, opExecFlag,
                                                    sigScheme, &digest, &signature, &isSigValid, pErrContext);
                }

                if (OK != status)
                {
                    PRINT_STATUS("Verify signature", status);
                    goto exit;
                }
                
                if (isSigValid)
                    LOG_MESSAGE("Signature verified successfully!\n");
                else
                    LOG_MESSAGE("Signature verification failed!\n");

                retval = 0;
            }
        }
        else
        {
            LOG_ERROR("Error reading private key file, status = %d\n", status);            
        }
    }
    else
    {
        LOG_ERROR("Error reading data file, status = %d\n", status);
        goto exit;
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
    status = TAP_freeSignature(&signature);
    if (OK != status)
        PRINT_STATUS("TAP_freeSignature", status);
    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&keyBlob.pBuffer);

    if (NULL != pBuffer)
        DIGICERT_freeReadFile(&pBuffer);
    
    if (NULL != pSignatureBuffer)
        DIGICERT_freeReadFile(&pSignatureBuffer);

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

help_exit:
    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->inSignatureFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inSignatureFile.pBuffer);

        if (pOpts->inFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inFile.pBuffer);

        if (pOpts->privKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);

        /* Don't free keyAuthValue TAP_Buffer as it is freed by TAP_UTILS_clearCredentialList */
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
        LOG_ERROR("Failed to verify signature.");
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
        LOG_ERROR("*****digicert_tpm2_verifyquote failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

