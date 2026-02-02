/**
 @file moctap_verifyquote.c

 @page moctap_verifyquote

 @ingroup tap_tools_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_verifyquote -
 @endhtmlonly
 Verify a signature on quote using an SE key.

 # SYNOPSIS
 `moctap_verifyquote [options]`

 # DESCRIPTION
 <B>moctap_verifyquote</B> This tool verifies the signature of the Security Module quote.

@verbatim
    --h [option(s)]
        Display help for the specified option(s).
    --s=[server name]
        Host on which TPM chip is located.  This can be 'localhost' or a remote host running a TAP server.
    --p=[server port]
        Port on which the TAP server is listening.
    --conf=[Security Module configuration file]
        Path to Security Module configuration file.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use.
    --kpwd=[key password]
        (Optional) Password of the key to load.
    --halg=[hash algorithm]
        Hash algorithm (sha1, sha256, or sha512) for the hash of the TPM quote.
    --pri=[private key file]
        (Mandatory) Input file that contains the private key.
    --idf=[input data file]
        (Mandatory) Input file that contains the data to verify
    --isf=[input signature file]
        (Mandatory) Input file that contains the signature.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_createasymkey,  moctap_createsymkey, moctap_getquote

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
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../data_protection/file_protect.h"
#endif
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
#define MAX_PASSWORD_LEN 256
#define SERVER_NAME_LEN 256
#define TAPTOOL_CREDFILE_NAME_LEN  256
#define FILE_PATH_LEN   256

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];

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
    LOG_MESSAGE("moctap_verifyquote: Help Menu\n");
    LOG_MESSAGE("This tool verifies the signature of the Security Module quote.");

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
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   (Optional) Password of the key to load.\n");
    LOG_MESSAGE("           --halg=[hash algorithm]");
    LOG_MESSAGE("                   Hash algorithm (sha1, sha256, or sha512) for the hash of the TPM quote.\n");
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the private key.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the data to verify..\n");
    LOG_MESSAGE("           --isf=[input signature file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the signature.\n");
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    sbyte4 filenameLen ;
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
            {"pn", required_argument, NULL, 9},
            {"mid", required_argument, NULL, 10},
            {"cred", required_argument, NULL, 11},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 12},
#endif
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif

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
#ifdef __ENABLE_TAP_REMOTE__
        case 2:
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

        case 3:
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
            break;
#endif
        case 4:
            /* --halg digest hash algorithm */
            {
                typedef struct {
                    char *pName;
                    TAP_HASH_ALG val;
                } HASH_OPT_VAL_INFO;
                
                HASH_OPT_VAL_INFO optionValues[] = {
                    {"sha1", TAP_HASH_ALG_SHA1},
                    {"sha256", TAP_HASH_ALG_SHA256},
                    {"sha512", TAP_HASH_ALG_SHA512},
                    {NULL, 0},
                };
                ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                ubyte4 optionNameLen;
                ubyte oIndex;

                if ((optValLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--halg Digest hash algorithm not specified");
                    goto exit;
                }

                for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                {
                    cmpResult = 1;
                    optionNameLen = DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName);
                    if (optionNameLen == optValLen)
                    {
                        if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                    optionNameLen, &cmpResult))
                        {
                            MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                            goto exit;
                        }

                        if (!cmpResult)
                        {
                            pOpts->hashAlg = optionValues[oIndex].val;
                            MOCTAP_DEBUG_PRINT("Setting Hash algorithm to %s", optionValues[oIndex].pName);
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
            /* --kpwd password */
            {
                ubyte4 passwordLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if ((passwordLen == 0) || ('-' == optarg[0]))
                {
                    LOG_ERROR("--kpwd password not specified");
                    goto exit;
                }
                
                if (passwordLen > MAX_PASSWORD_LEN)
                {
                    LOG_ERROR("Password too long. Max length: %d characters", MAX_PASSWORD_LEN);
                    goto exit;
                }
                
                pOpts->keyAuthValue.bufferLen = passwordLen;
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer,
                                                passwordLen + 1)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for key password",
                                (int)(passwordLen + 1));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg, passwordLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->keyAuthValue.pBuffer);
                    pOpts->keyAuthValue.bufferLen = 0;
                    goto exit;
                }
                pOpts->keyAuthValue.pBuffer[passwordLen] = '\0';
                pOpts->keyAuthSpecified = TRUE;
            }
            break;

        case 6:
            /* --pri input private key file */
            {
                ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("Private key file path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((optValLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--pri Input private key file not specified");
                    goto exit;
                }

                pOpts->privKeyFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, 
                                pOpts->privKeyFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for Private key filename",
                            (int)pOpts->privKeyFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);
                    pOpts->privKeyFile.bufferLen = 0;
                    goto exit;
                }
                pOpts->privKeyFile.pBuffer[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);
                pOpts->inPrivKeyFileSpecified = TRUE;
            }
            break;

        case 7:
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
                    LOG_ERROR("--idf Input data file not specified");
                    goto exit;
                }

                pOpts->inFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->inFile.pBuffer, 
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

        case 8:
            /* --isf input signature file */
            {
                ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("Signature file path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((optValLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--isf Input signature file not specified");
                    goto exit;
                }

                pOpts->inSignatureFile.bufferLen = optValLen + 1;
                if (OK != (status = DIGI_MALLOC((void **)&pOpts->inSignatureFile.pBuffer, 
                                pOpts->inSignatureFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for signature filename",
                            (int)pOpts->inSignatureFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->inSignatureFile.pBuffer, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE((void **)&pOpts->inSignatureFile.pBuffer);
                    pOpts->inSignatureFile.bufferLen = 0;
                    goto exit;
                }
                pOpts->inSignatureFile.pBuffer[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Signature filename: %s", pOpts->inSignatureFile.pBuffer);
                pOpts->inSignatureFileSpecified = TRUE;
            }
            break;
        
        case 9:
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

            case 10:
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
                
                case 11:
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

        case 12:
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
    MSTATUS status = ERR_GENERAL;
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList keyCredentials = { 0 };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_ConfigInfoList configInfoList = { 0, };
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    ubyte tapInit = FALSE;
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
    byteBoolean isSigValid = 0;
    TAP_ModuleList moduleList = { 0 };
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    ubyte gotModuleList = FALSE;
    TAP_Buffer digest = 
    {
        .pBuffer    = digestBuf,
        .bufferLen  = 0    
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
#ifdef __ENABLE_TAP_REMOTE
    if (!pOpts->serverNameSpecified ||  
            !pOpts->inPrivKeyFileSpecified || !pOpts->inFileSpecified ||
            !pOpts->inSignatureFileSpecified || !pOpts->prNameSpecified || 
            !pOpts->modIdSpecified) 
    {
        LOG_ERROR("One or more mandatory options --s, --pri, --idf, --pn, --mid is not specified.");
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
        !pOpts->inSignatureFileSpecified || !pOpts->prNameSpecified || 
        !pOpts->modIdSpecified)
    {
        LOG_ERROR("One or more mandatory options --pri, --idf,--pn, --mid is not specified.");
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
            &errContext);

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
        pOpts->keyAuthValue.pBuffer = NULL;
        pOpts->keyAuthValue.bufferLen = 0;
        pKeyCredentials = &keyCredentials;
    }

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

    /* TODO: Format input parameters */
    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->inFile.pBuffer, &pBuffer, &bufferLen);
    if (OK == status)
    {
        /* Generate digest using specified hash algorithm */
        switch (pOpts->hashAlg)
        {
            case TAP_HASH_ALG_SHA1:
                SHA1_completeDigest(pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA1_RESULT_SIZE;
                break;

            case TAP_HASH_ALG_SHA512:
                SHA512_completeDigest(pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA512_RESULT_SIZE;
                break;

            case TAP_HASH_ALG_SHA256:
            default:
                SHA256_completeDigest(pBuffer, bufferLen, digest.pBuffer);
                digest.bufferLen = SHA256_RESULT_SIZE;
                break;
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
    if ((NULL != pSmpConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pSmpConfigFile);
    }
#endif /* defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__) */

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

    /* Free module list */
    if ((TRUE == gotModuleList) && (moduleList.pModuleList))
    {
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
    }

    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(&errContext);
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

    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials) ;
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
        if (pOpts->inSignatureFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inSignatureFile.pBuffer);

        if (pOpts->inFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inFile.pBuffer);

        if (pOpts->privKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);

        if (pOpts->keyAuthValue.pBuffer)
            shredMemory((ubyte **)&(pOpts->keyAuthValue.pBuffer), pOpts->keyAuthValue.bufferLen, TRUE);

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
        LOG_ERROR("*****moctap_verifyquote failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

