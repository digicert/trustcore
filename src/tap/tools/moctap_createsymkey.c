/**
 @file moctap_createsymkey.c

 @page moctap_createsymkey

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_createsymkey -
 @endhtmlonly
 This tool creates a symmetric key for Encrypt/Decrypt or Sign/Verify operations.

 # SYNOPSIS
 `moctap_createsymkey [options]`

 # DESCRIPTION
 <B>moctap_createsymkey</B> generates a symmetric key.

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
    --ktype=[key type]
        (Mandatory) Type of key (decrypt or sign) to create.
    --ksize=[key size]
        (Mandatory) Key size (128, 192, or 256) in bits.
    --kpwd=[key password]
        Password of the key to create. If no key password is specified, the key is created without a password.
    --kalg=[key hash algorithm]
        Hash algorithm (sha1 or sha256) for key creation.
    --kmode=[key mode]
        Key mode (CFB, CTR, OFB, CBC) for key creation.
    --pri=[output private key file]
        Output file that contains the created key.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctpms_createasymkey

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
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../data_protection/file_protect.h"
#endif
#include "../tap_api.h"
#include "../tap_utils.h"
#include "../tap_serialize.h"
#include "../tap_serialize_smp.h"
#include "../../smp/smp_tpm2/smp_tap_tpm2.h"
#include "moctap_tools_utils.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
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

/* Port and password validation constants */
#define MIN_PORT_NUMBER 1
#define MAX_PORT_NUMBER 65535
#define MAX_PASSWORD_LEN 256

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

    byteBoolean keyUsageSpecified;
    TAP_KEY_USAGE keyUsage;

    byteBoolean keyWidthSpecified;
    TAP_KEY_SIZE keyWidth;

    byteBoolean algSpecified;
    TAP_KEY_ALGORITHM keyAlg;

    byteBoolean keyModeSpecified;
    TAP_SYM_KEY_MODE keyMode;

    byteBoolean hashAlgSpecified;
    TAP_HASH_ALG keyHashAlg;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean outPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

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
    LOG_MESSAGE("moctap_createsymkey: Help Menu\n");
    LOG_MESSAGE("This tool creates a symmetric key for Encrypt/Decrypt or Sign/Verify operations.\n");

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
    LOG_MESSAGE("           --ktype=[key type]");
    LOG_MESSAGE("                   (Mandatory) Type of key (decrypt or sign) to create.\n");
    LOG_MESSAGE("           --ksize=[key size]");
    LOG_MESSAGE("                   (Mandatory) Key size (128, 192, or 256) in bits.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to create.\n"
                "                   If no key password is specified , the the key is created without a password.\n");
    LOG_MESSAGE("           --halg=[key hash algorithm]");
    LOG_MESSAGE("                   Hash algorithm (sha1 or sha256) for key creation.\n");
    LOG_MESSAGE("           --kmode=[key mode]");
    LOG_MESSAGE("                   Key mode (CFB, CTR, OFB, CBC) for key creation.\n");
    LOG_MESSAGE("           --pri=[output key file]");
    LOG_MESSAGE("                   Output file that contains the created key.\n");
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
            {"ktype", required_argument, NULL, 4},
            {"kpwd", required_argument, NULL, 5},
            {"ksize", required_argument, NULL, 6},
            {"halg", required_argument, NULL, 7},
            {"kmode", required_argument, NULL, 8},
            {"pri", required_argument, NULL, 9},
            {"conf", required_argument, NULL, 12},
            {"pn", required_argument, NULL, 16},
            {"mid", required_argument, NULL, 17},
            {"cred", required_argument, NULL, 18},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 0;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif
    MSTATUS status;
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
#ifdef __ENABLE_TAP_REMOTE__
            case 2:
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
                pOpts->serverNameSpecified = TRUE;
                MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
                break;

            case 3:
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
                        LOG_ERROR("Port number out of valid range (%d-%d)",
                                MIN_PORT_NUMBER, MAX_PORT_NUMBER);
                        goto exit;
                    }
                    
                    pOpts->serverPort = (ubyte4)portNum;
                    MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
                break;
#endif
            case 4:
                /* --ktype, Key type, decrypt or sign */
                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--ktype Key type not specified");
                    goto exit;
                }

                cmpResult = 1;
                /* TODO: Is only decrypt currently supported?  Why not the same as in asym? */
                if (DIGI_STRLEN((const sbyte *)"decrypt") == DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"decrypt",
                                DIGI_STRLEN((const sbyte *)"decrypt"), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->keyUsage = TAP_KEY_USAGE_DECRYPT;
                        pOpts->keyUsageSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT_1("Setting Key type to decryption");
                        break;
                    }
                }

                cmpResult = 1;
                if (DIGI_STRLEN((const sbyte *)"sign") == DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sign",
                                DIGI_STRLEN((const sbyte *)"sign"), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->keyUsage = TAP_KEY_USAGE_SIGNING;
                        pOpts->keyUsageSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT_1("Setting Key type to signing");
                        break;
                    }
                }

                LOG_ERROR("--ktype not decrypt or sign");
                goto exit;
                break;

            case 5:
                /* --kpwd password */
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

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer, pOpts->keyAuthValue.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for key password",
                            (int)pOpts->keyAuthValue.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg, pOpts->keyAuthValue.bufferLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    DIGI_FREE(&pOpts->keyAuthValue.pBuffer);
                    goto exit;
                }
                pOpts->keyAuthSpecified = TRUE;
                MOCTAP_DEBUG_PRINT("Key password specified");

                break;

            case 6:
                /* --ksize, Key size 128 or 192 or 256 */
                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-ksize Key size not specified");
                    goto exit;
                }

                cmpResult = 1;
                if (DIGI_STRLEN((const sbyte *)"128") == DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"128",
                                DIGI_STRLEN((const sbyte *)"128"), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->keyWidth = TAP_KEY_SIZE_128;
                        pOpts->keyWidthSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT_1("Setting Key width to 128");
                        break;
                    }
                }

                cmpResult = 1;
                if (DIGI_STRLEN((const sbyte *)"192") == DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"192",
                                DIGI_STRLEN((const sbyte *)"192"), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->keyWidth = TAP_KEY_SIZE_192;
                        pOpts->keyWidthSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT_1("Setting Key width to 192");
                        break;
                    }
                }

                cmpResult = 1;
                if (DIGI_STRLEN((const sbyte *)"256") == DIGI_STRLEN((const sbyte *)optarg))
                {
                    if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"256",
                                DIGI_STRLEN((const sbyte *)"256"), &cmpResult))
                    {
                        MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                        goto exit;
                    }

                    if (!cmpResult)
                    {
                        pOpts->keyWidth = TAP_KEY_SIZE_256;
                        pOpts->keyWidthSpecified = TRUE;
                        MOCTAP_DEBUG_PRINT_1("Setting Key width to 256");
                        break;
                    }
                }

                LOG_ERROR("--ksize not 128 or 192 or 256");
                goto exit;
                break;

            case 7:
                {
                    OPT_VAL_INFO optionValues[] = {
                        {"sha1", TAP_HASH_ALG_SHA1},
                        {"sha256", TAP_HASH_ALG_SHA256},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("--halg Hash algorithm not specified");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        /* --halg hash algorithm */
                        cmpResult = 1;
                        if (DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName) ==
                                   DIGI_STRLEN((const sbyte *)optarg))
                        {
                            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                        DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                            {
                                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keyHashAlg = optionValues[oIndex].val;
                                pOpts->hashAlgSpecified = TRUE;
                                MOCTAP_DEBUG_PRINT("Setting Hash algorithm to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--halg not sha1 or sha256");
                        goto exit;
                    }
                }
                break;

            case 8:
                {
                    /* --kmode encryption mode */
                    OPT_VAL_INFO optionValues[] = {
                        {"ctr", TAP_SYM_KEY_MODE_CTR},
                        {"cfb", TAP_SYM_KEY_MODE_CFB},
                        {"ofb", TAP_SYM_KEY_MODE_OFB},
                        {"cbc", TAP_SYM_KEY_MODE_CBC},
                        {"ecb", TAP_SYM_KEY_MODE_ECB},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("--kmode Encryption mode not specified");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        cmpResult = 1;
                        if (DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName) ==
                                   DIGI_STRLEN((const sbyte *)optarg))
                        {
                            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                        DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                            {
                                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keyMode = optionValues[oIndex].val;
                                pOpts->keyModeSpecified = TRUE;
                                MOCTAP_DEBUG_PRINT("Setting key mode to %s", optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--kmode not cfb, ctr, ofb, cbc or ecb");
                        goto exit;
                    }
                }
                break;

            case 9:
                /* --pri output private key file */
                pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->privKeyFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-pri Private key output file not specified");
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, pOpts->privKeyFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for Public key filename",
                            (int)pOpts->privKeyFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, pOpts->privKeyFile.bufferLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->outPrivKeyFileSpecified = TRUE;
                MOCTAP_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

                break;

            case 12:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
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
                pOpts->isConfFileSpecified = TRUE;
                MOCTAP_DEBUG_PRINT("Provider Configuration file path: %s", 
                                 pOpts->confFilePath);
#else
                LOG_ERROR("Provider configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 16:
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

        case 17:
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

        case 18:
            /* --cred credential file */
            filenameLen = DIGI_STRLEN((const sbyte *)optarg);
            if (filenameLen >= TAPTOOL_CREDFILE_NAME_LEN)
            {
                LOG_ERROR("credential file name too long. Max size: %d bytes",
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
            pOpts->credFileSpecified = TRUE;
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
    TAP_KeyInfo keyInfo = {0};
    TAP_Context *pTapContext = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer privateKeyBuffer = {0};
    TAP_ErrorContext *pErrContext = NULL;
    TAP_ConfigInfoList configInfoList = { 0, };
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_ModuleList moduleList = { 0 };
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 }; 
#endif
    ubyte tapInit = FALSE;
    ubyte contextInit = FALSE;
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
    if (!pOpts->serverNameSpecified || !pOpts->outPrivKeyFileSpecified ||
	!pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory option --s, --pr, --pn --mid not specified.");
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
    if (!pOpts->outPrivKeyFileSpecified || !pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory option --pr, --pn --mid not specified.");
        goto exit;
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
        pOpts->keyAuthValue.bufferLen = 0;
        pOpts->keyAuthValue.pBuffer = NULL;
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

    /* Format input parameters */
    if (TAP_KEY_USAGE_DECRYPT == pOpts->keyUsage)
        keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    else
        keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;

    keyInfo.keyUsage = pOpts->keyUsage;
    keyInfo.tokenId = 0;
    keyInfo.objectId = 0;

    if (TAP_KEY_USAGE_DECRYPT == pOpts->keyUsage)
    {
        keyInfo.algKeyInfo.aesInfo.keySize = pOpts->keyWidth;
        keyInfo.algKeyInfo.aesInfo.symMode = pOpts->keyMode;
    }
    else
    {
        keyInfo.algKeyInfo.hmacInfo.hashAlg = pOpts->keyHashAlg;
    }

    /* Invoke TAP API */
    status = TAP_symGenerateKey(pTapContext, pEntityCredentials, &keyInfo, NULL, pKeyCredentials,
                                &pTapKey, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_symGenerateKey", status);
        goto exit;
    }

    /* TAPKey is the Private key, it should contain everything about the key,
       will need that when it is loaded in future for crypto operations */

    status = TAP_serializeKey(pTapKey, blobFormat, blobEncoding, &privateKeyBuffer,
            pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("Private key serialization", status);
        goto exit;
    }

    if (NULL == pOpts->privKeyFile.pBuffer)
    {
        MOCTAP_DEBUG_PRINT_1("NULL pOpts->privKeyFile.pBuffer\n");
    }
    
    /* Write private key to file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGICERT_writeFileEx((const char *)pOpts->privKeyFile.pBuffer,
                              privateKeyBuffer.pBuffer, privateKeyBuffer.bufferLen, TRUE);
#else
    status = DIGICERT_writeFile((const char *)pOpts->privKeyFile.pBuffer,
                              privateKeyBuffer.pBuffer, privateKeyBuffer.bufferLen);
#endif
    if (OK != status)
    {
        LOG_ERROR("Failed to write Private Key to file, error %d\n", status);
    }

    LOG_MESSAGE("Successfully wrote Private Key to file\n");
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

    /* Unload key */
    if (NULL != pTapKey)
    {
        status = TAP_unloadKey(pTapKey, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);

        status = TAP_freeKey(&pTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
    }

    if (NULL != privateKeyBuffer.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&privateKeyBuffer);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
    }

    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
    }
    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }
    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        status = TAP_uninitContext(&pTapContext, pErrContext);
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
        MOCTAP_DEBUG_PRINT_1("Failed to create key.");
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
        LOG_ERROR("*****moctap_createsymkey failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

