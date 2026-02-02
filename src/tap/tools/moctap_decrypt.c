/**
 @file moctap_decrypt.c

 @page moctap_decrypt

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_decrypt -
 @endhtmlonly
 This tool decrypts a previously encrypted buffer using an input asymmetric key.

 # SYNOPSIS
 `moctap_decrypt [options]`

 # DESCRIPTION
 <B>moctap_decrypt</B> decrypts data using the key provided.

@verbatim
    --h [option(s)]
        Display help for the specified option(s).
    --conf=[Security Module configuration file]
        Path to Security Module configuration file.
    --s=[server name]
        Host on which TPM chip is located.  This can be 'localhost' or a remote host running a TAP server.
    --p=[server port]
        Port on which the TAP server is listening.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use.
    --kpwd=[key password]
        (Optional) Symmetric cipher mode for symmetric key encryption.
    --kmode=[key mode]
        (Optional) Symmetric cipher mode for symmetric key encryption.
    --es=[encryption scheme]
        (Optional) Encryption scheme (PCKS1, OAEPSHA1 or OAEPSHA256) for asymmetric key encryption.
    --pri=[private key file]
        (Mandatory) Input file that contains the private key.
    --idf=[input data file]
        (Mandatory) Input file that contains the encrypted data.
    --odf=[output data file]
        (Mandatory) Output file that contains the decrypted data.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_createasymkey,  moctap_createsymkey, moctap_encrypt

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
#endif

typedef struct
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096
#define TAPTOOL_CREDFILE_NAME_LEN  256

/* Password and port validation constants */
#define MAX_PASSWORD_LEN 256
#define MIN_PORT_NUMBER 1
#define MAX_PORT_NUMBER 65535

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

    byteBoolean inPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

    byteBoolean inFileSpecified;
    TAP_Buffer inFile;

    byteBoolean outDecryptedFileSpecified;
    TAP_Buffer outDecryptedFile;

    byteBoolean modeSpecified;
    TAP_SYM_KEY_MODE symMode;

    byteBoolean encSchemeSpecified;
    TAP_ENC_SCHEME encScheme;

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
    LOG_MESSAGE("moctap_decrypt: Help Menu\n");
    LOG_MESSAGE("This tool decrypts the input encrypted file using TPM.");

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
    LOG_MESSAGE("                   Specify the module ID to use\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to be loaded.\n");
    LOG_MESSAGE("           --kmode=[key mode]");
    LOG_MESSAGE("                   (Optional) Symmetric cipher mode for symmetric key encryption.\n");
    LOG_MESSAGE("           --es=[encryption scheme]");
    LOG_MESSAGE("                   (Optional) Encryption scheme (PCKS1, OAEPSHA1 or OAEPSHA256) for asymmetric key encryption.\n");
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                    (Mandatory) Input file that contains the private key.\n");
    LOG_MESSAGE("           --idf=[input encrypted file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the encrypted data.\n");
    LOG_MESSAGE("           --odf=[output decrypted file]");
    LOG_MESSAGE("                    (Mandatory) Output file that contains the decrypted data.\n");
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
            {"kpwd", required_argument, NULL, 5},
            {"kmode", required_argument, NULL, 6},
            {"es", required_argument, NULL, 7},
            {"pri", required_argument, NULL, 8},
            {"idf", required_argument, NULL, 9},
            {"odf", required_argument, NULL, 10},
            {"conf", required_argument, NULL, 12},
            {"pn", required_argument, NULL, 13},
            {"mid", required_argument, NULL, 14},
            {"cred", required_argument, NULL, 15},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif
    ubyte oIndex;
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
            pOpts->serverNameSpecified = TRUE;
            pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);
            
            if (pOpts->serverNameLen >= SERVER_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max size: %d bytes",
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
#else
            LOG_ERROR("Server name not a valid option in a local-only build\n");
            goto exit;
#endif
            break;

        case 3:
#ifdef __ENABLE_TAP_REMOTE__
            {
                char *endptr = NULL;
                long portNum;
                
                errno = 0;
                portNum = strtol(optarg, &endptr, 0);
                
                if ((errno != 0) || (endptr == optarg) || (*endptr != '\0'))
                {
                    LOG_ERROR("Invalid port number format");
                    goto exit;
                }
                
                if (portNum < MIN_PORT_NUMBER || portNum > MAX_PORT_NUMBER)
                {
                    LOG_ERROR("Port number out of valid range (1-65535)");
                    goto exit;
                }
                
                pOpts->serverPort = (ubyte4)portNum;
                MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
            }
#else
            LOG_ERROR("Server port not a valid option in a local-only build\n");
            goto exit;
#endif
            break;

        case 5:
            /* --kpwd password */
            pOpts->keyAuthSpecified = TRUE;
            pOpts->keyAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if (pOpts->keyAuthValue.bufferLen == 0)
            {
                LOG_ERROR("Empty password not allowed");
                goto exit;
            }

            if (pOpts->keyAuthValue.bufferLen > MAX_PASSWORD_LEN)
            {
                LOG_ERROR("Password too long. Max size: %d bytes", MAX_PASSWORD_LEN);
                goto exit;
            }

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
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->keyAuthValue.pBuffer);
                goto exit;
            }
            MOCTAP_DEBUG_PRINT("Key password specified"); 

            break;

        case 6:
            /* --kmode - symmetric cipher mode */
            OPT_VAL_INFO modeOptionValues[] = {
                        {"ctr", TAP_SYM_KEY_MODE_CTR},
                        {"cfb", TAP_SYM_KEY_MODE_CFB},
                        {"ofb", TAP_SYM_KEY_MODE_OFB},
                        {"cbc", TAP_SYM_KEY_MODE_CBC},
                        {"ecb", TAP_SYM_KEY_MODE_ECB},
                        {NULL, 0},
            };

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) || ('-' == optarg[0]))
            {
                LOG_ERROR("-kmode Symmetric cipher mode not specified");
                goto exit;
            }

            for (oIndex = 0; modeOptionValues[oIndex].pName; oIndex++)
            {
                cmpResult = 1;
                if (DIGI_STRLEN((const sbyte *)modeOptionValues[oIndex].pName) ==
                           DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)modeOptionValues[oIndex].pName,
                                    DIGI_STRLEN((const sbyte *)modeOptionValues[oIndex].pName), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->symMode = modeOptionValues[oIndex].val;
                        pOpts->modeSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT("Setting cipher mode to %s", modeOptionValues[oIndex].pName);
                        break;
                    }
                }
            }

            if (!modeOptionValues[oIndex].pName)
            {
                 LOG_ERROR("--kmode not cfb, ctr, ofb, cbc or ecb");
                goto exit;
            }
            break;

        case 7:
            /* --es Encryption scheme */
             pOpts->encSchemeSpecified = TRUE;
             OPT_VAL_INFO esOptionValues[] = {
                    {"pkcs1", TAP_ENC_SCHEME_PKCS1_5},
                    {"oaepsha1", TAP_ENC_SCHEME_OAEP_SHA1},
                    {"oaepsha256", TAP_ENC_SCHEME_OAEP_SHA256},
                    {NULL, 0},
             };

             if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
             {
                  LOG_ERROR("-es Encryption scheme not specified");
                  goto exit;
             }

             for (oIndex = 0; esOptionValues[oIndex].pName; oIndex++)
             {
                 cmpResult = 1;
                 if (DIGI_STRLEN((const sbyte *)esOptionValues[oIndex].pName) ==
                            DIGI_STRLEN((const sbyte *)optarg))
                 {
                     if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)esOptionValues[oIndex].pName,
                                    DIGI_STRLEN((const sbyte *)esOptionValues[oIndex].pName), &cmpResult))
                     {
                          MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                          goto exit;
                     }

                     if (!cmpResult)
                     {
                          pOpts->encScheme = esOptionValues[oIndex].val;
                          MOCTAP_DEBUG_PRINT("Setting encryption scheme to %s",
                                        esOptionValues[oIndex].pName);
                          break;
                     }
                 }
             }

             if (!esOptionValues[oIndex].pName)
             {
                  LOG_ERROR("--es not pkcs1, oaepsha1 or oaepsha256");
                  goto exit;
             }
             pOpts->encSchemeSpecified = TRUE;            break;

        case 8:
            /* --pri input private key file */
            pOpts->inPrivKeyFileSpecified = TRUE;
            pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->privKeyFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-pri Private key input file not specified");
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
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            MOCTAP_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

            break;

        case 9:
            /* --idf input data file */
            pOpts->inFileSpecified = TRUE;
            pOpts->inFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->inFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-idf Input data file not specified");
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
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            MOCTAP_DEBUG_PRINT("Input data filename: %s", pOpts->inFile.pBuffer);

            break;

        case 10:
            /* --odf output signature file */
            pOpts->outDecryptedFileSpecified = TRUE;
            pOpts->outDecryptedFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->outDecryptedFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-odf Output signature file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outDecryptedFile.pBuffer, 
                            pOpts->outDecryptedFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for signature filename",
                        (int)pOpts->outDecryptedFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outDecryptedFile.pBuffer, optarg, 
                        pOpts->outDecryptedFile.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            MOCTAP_DEBUG_PRINT("Decrypted filename: %s", pOpts->outDecryptedFile.pBuffer);

            break;

        case 12:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                pOpts->isConfFileSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max size: %d bytes",
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
                MOCTAP_DEBUG_PRINT("Configuration file path: %s", 
                                 pOpts->confFilePath);
#else
                LOG_ERROR("Configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
                break;

        case 13:
            /* --provider name */
            pOpts->prNameSpecified = TRUE;

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
            break;

        case 14:
            /* --mid module id */
            {
                char *endptr = NULL;
                long moduleId;
                
                errno = 0;
                moduleId = strtol(optarg, &endptr, 0);
                
                if ((errno != 0) || (endptr == optarg) || (*endptr != '\0'))
                {
                    LOG_ERROR("Invalid module id format");
                    goto exit;
                }
                
                if (moduleId < 0)
                {
                    LOG_ERROR("Module id cannot be negative");
                    goto exit;
                }
                
                pOpts->moduleId = (TAP_ModuleId)moduleId;
                MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
                pOpts->modIdSpecified = TRUE;
            }
            break;

        case 15:
            /* --cred credential file */
            pOpts->credFileSpecified = TRUE;
            if (DIGI_STRLEN((const sbyte *)optarg) >= TAPTOOL_CREDFILE_NAME_LEN)
            {
                LOG_ERROR("credential file name too long. Max size: %d bytes",
                        TAPTOOL_CREDFILE_NAME_LEN - 1);
                goto exit;
            }
            filenameLen = DIGI_STRLEN((const sbyte *)optarg);
            if ((filenameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--cred credential file name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->credFileName, optarg,
                    filenameLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->credFileName[filenameLen] = '\0';
            MOCTAP_DEBUG_PRINT("cred file name name: %s", pOpts->credFileName);
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
    TAP_ConfigInfoList configInfoList = { 0, };
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ModuleList moduleList = { 0 };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    //TAP_EntityCredentialList entityCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Buffer inData = { 0 };
    TAP_Buffer keyBlob = { 0 };
    TAP_Buffer decryptedData = { 0 };
    TAP_Key *pLoadedTapKey = {0};
    TAP_Buffer iv = {0};
    TAP_SYM_KEY_MODE keySymMode = TAP_SYM_KEY_MODE_UNDEFINED;
    TAP_ENC_SCHEME keyEncScheme = TAP_ENC_SCHEME_NONE;
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
    byteBoolean tapInit = FALSE;
    byteBoolean contextInit = FALSE;
    ubyte gotModuleList = FALSE;

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
    if (!pOpts->serverNameSpecified || 
        !pOpts->inFileSpecified || !pOpts->outDecryptedFileSpecified ||
        !pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory options --s, --pri, --idf, --pn, --mid or --odf not specified.");
        goto exit;
    }
#else
    if (!pOpts->inPrivKeyFileSpecified
        || !pOpts->inFileSpecified || !pOpts->outDecryptedFileSpecified)
    {
        LOG_ERROR("One of mandatory options --pri, --idf , --pn, --mid or --odf not specified.");
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

    /* Read encrypted data file */
    status = DIGICERT_readFile((const char *)pOpts->inFile.pBuffer, &(inData.pBuffer), &(inData.bufferLen));
    if (OK != status)
    {
        LOG_ERROR("Error reading input file. status %d", status);
        DB_PRINT("Errno=%d",errno);
        goto exit;
    }

    /* Read key file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGICERT_readFileEx((const char *)pOpts->privKeyFile.pBuffer,
                             &(keyBlob.pBuffer), &(keyBlob.bufferLen), TRUE);
#else
    status = DIGICERT_readFile((const char *)pOpts->privKeyFile.pBuffer,
                             &(keyBlob.pBuffer), &(keyBlob.bufferLen));
#endif
    if (OK != status)
    {
        LOG_ERROR("Error reading private key file, status = %d\n", status);
        DB_PRINT("Errno=%d",errno);
        goto exit;
    }

    /* Deserialize into TAP_Key */
    status = TAP_deserializeKey(&keyBlob, &pLoadedTapKey, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_deserializeKey", status);
        goto exit;
    }

    status = TAP_loadKey(pTapContext, pEntityCredentials, pLoadedTapKey,pKeyCredentials, NULL, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_loadKey", status);
        goto exit;
    }

    /* Decrypt using the correct API */
    switch(pLoadedTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
            keySymMode = pLoadedTapKey->keyData.algKeyInfo.aesInfo.symMode;
            if (TRUE == pOpts->modeSpecified)
                status = TAP_symDecrypt(pLoadedTapKey, pEntityCredentials, NULL, pOpts->symMode, &iv,
                                        &inData, &decryptedData, pErrContext);
            else
                status = TAP_symDecrypt(pLoadedTapKey, pEntityCredentials, NULL, keySymMode, &iv,
                                        &inData, &decryptedData, pErrContext);
            break;

        case TAP_KEY_ALGORITHM_RSA:
            keyEncScheme = pLoadedTapKey->keyData.algKeyInfo.rsaInfo.encScheme;
        case TAP_KEY_ALGORITHM_ECC:
            if (TRUE == pOpts->encSchemeSpecified)
                status = TAP_asymDecrypt(pLoadedTapKey, pEntityCredentials, NULL, pOpts->encScheme,
                                         &inData, &decryptedData, pErrContext);
            else
                status = TAP_asymDecrypt(pLoadedTapKey, pEntityCredentials, NULL, keyEncScheme,
                                         &inData, &decryptedData, pErrContext);
            break;

        default:
            LOG_ERROR("Invalid key algorithm %d\n", pLoadedTapKey->keyData.keyAlgorithm);
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    PRINT_STATUS("Decrypt input file", status);
    if (OK != status)
        goto exit;
    
    /* Save decrypted data to output file */
    status = DIGICERT_writeFile((const char *)pOpts->outDecryptedFile.pBuffer,
                              decryptedData.pBuffer, decryptedData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing decrypted data to file, status = %d\n", status);
        goto exit;
    }

    LOG_MESSAGE("Successfully wrote decrypted data to file\n");
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

    if (NULL != pLoadedTapKey)
    {
        /* Unload key object */
        status = TAP_unloadKey(pLoadedTapKey, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);

        status = TAP_freeKey(&pLoadedTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
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

    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }

    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&(keyBlob.pBuffer));

    if (NULL != inData.pBuffer)
        DIGICERT_freeReadFile(&(inData.pBuffer));

    if (NULL != decryptedData.pBuffer)
        shredMemory(&(decryptedData.pBuffer), decryptedData.bufferLen, TRUE);

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
        if (pOpts->outDecryptedFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outDecryptedFile.pBuffer);

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
        MOCTAP_DEBUG_PRINT_1("Failed to decrypt input file.");
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
        LOG_ERROR("*****moctap_decrypt failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

