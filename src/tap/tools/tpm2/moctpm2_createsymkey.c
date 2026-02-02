/**
 @file moctpm2_createsymkey.c

 @page digicert_tpm2_createsymkey

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_createsymkey -
 @endhtmlonly
 Generate a symmetric key using a TPM 2.0 chip.

 # SYNOPSIS
 `digicert_tpm2_createsymkey [options]`

 # DESCRIPTION
 <B>digicert_tpm2_createsymkey</B> generates a symmetric key.

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
    --ktype=[decrypt or sign]
        (Mandatory) Type of key (decrypt or sign) to create.
    --ksize=[key size]
        (Mandatory) Key size (128 or 192 or 256) in bits.
    --kpwd=[key password]
        Password of the key to be created. If no key password is specified, the key is created without a password.
    --kmode=[key mode]
        Key mode (cfb or ctr or ofb or cbc) for key creation.
    --pri=[output private key file]
        Output file that contains the created key.
    --enablecmk
        Enables duplication of the key to another TPM
    --modulenum=[module num]
        Module number to use. If not provided first module is used by default
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
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/debug_console.h"
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

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER  4096

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
    TAP_KEY_CMK key_cmk;

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

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

    TAP_ModuleId moduleNum;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_createsymkey: Help Menu\n");
    LOG_MESSAGE("This tool creates a symmetric key for Encrypt/Decrypt or Sign/Verify operations.\n");

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
    LOG_MESSAGE("           --ktype=[key type]");
    LOG_MESSAGE("                   (Mandatory) Type of key (decrypt or sign) to create.\n");
    LOG_MESSAGE("           --ksize=[key size]");
    LOG_MESSAGE("                   (Mandatory) Key size (128 or 192 or 256) in bits.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to be created.\n"
                "                   If no key password is specified with this option, the is created without a password.\n");
    LOG_MESSAGE("           --halg=[key hash algorithm]");
    LOG_MESSAGE("                   Hash algorithm (sha1 or sha256) for key creation.\n");
    LOG_MESSAGE("           --kmode=[key mode]");
    LOG_MESSAGE("                   Key mode (cfb or ctr or ofb or cbc) for key creation.\n");
    LOG_MESSAGE("           --enablecmk");
    LOG_MESSAGE("                   enables duplication of the key to another TPM.\n"
                "                   By default, the key is created with CMK disabled.\n");
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
            {"conf", required_argument, NULL, 10},
            {"enablecmk", no_argument, NULL, 11},
            {"modulenum", required_argument, NULL, 12},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 0;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif
    MSTATUS status;

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
                /* type, Key type, decrypt or sign */
                pOpts->keyUsageSpecified = TRUE;

                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--ktype Key type not specified");
                    goto exit;
                }

                /* Check length of keyusage string is within allowed limit */
                if (DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"decrypt"))
                {
                    LOG_ERROR("--ktype Key type string too long. Max size: %d bytes",
                            (int)DIGI_STRLEN((const sbyte *)"decrypt"));
                    goto exit;
                }

                cmpResult = 1;
                /* TODO: Is only decrypt currently supported?  Why not the same as in asym? */
                if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"decrypt",
                            DIGI_STRLEN((const sbyte *)"decrypt"), &cmpResult))
                {
                    TPM2_DEBUG_PRINT_1("Failed to compare memory");
                    goto exit;
                }

                if (!cmpResult)
                {
                    pOpts->keyUsage = TAP_KEY_USAGE_DECRYPT;
                    TPM2_DEBUG_PRINT_1("Setting Key type to decryption");
                    break;
                }

                cmpResult = 1;
                if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sign",
                            DIGI_STRLEN((const sbyte *)"sign"), &cmpResult))
                {
                    TPM2_DEBUG_PRINT_1("Failed to compare memory");
                    goto exit;
                }

                if (!cmpResult)
                {
                    pOpts->keyUsage = TAP_KEY_USAGE_SIGNING;
                    TPM2_DEBUG_PRINT_1("Setting Key type to signing");
                    break;
                }

                LOG_ERROR("--ktype not decrypt or sign");
                goto exit;
                break;

            case 5:
                /* --kpwd password */
                pOpts->keyAuthSpecified = TRUE;
                pOpts->keyAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer, pOpts->keyAuthValue.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for key password",
                            (int)pOpts->keyAuthValue.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg, pOpts->keyAuthValue.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Key password: %s", optarg); 

                break;

            case 6:
                /* --ksize, Key size 128 or 192 or 256 */
                pOpts->keyWidthSpecified = TRUE;
                cmpResult = 1;

                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--ksize Key size not specified");
                    goto exit;
                }

                /* Check length of key size string is within allowed limit */
                if (DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"256"))
                {
                    LOG_ERROR("--ksize Key size string too long. Max size: %d bytes",
                            (int)DIGI_STRLEN((const sbyte *)"256"));
                    goto exit;
                }

                if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"128",
                            DIGI_STRLEN((const sbyte *)"128"), &cmpResult))
                {
                    TPM2_DEBUG_PRINT_1("Failed to compare memory");
                    goto exit;
                }

                if (!cmpResult)
                {
                    pOpts->keyWidth = TAP_KEY_SIZE_128;
                    TPM2_DEBUG_PRINT_1("Setting Key width to 128");
                    break;
                }

                cmpResult = 1;
                pOpts->keyWidthSpecified = TRUE;
                if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"192",
                            DIGI_STRLEN((const sbyte *)"192"), &cmpResult))
                {
                    TPM2_DEBUG_PRINT_1("Failed to compare memory");
                    goto exit;
                }

                if (!cmpResult)
                {
                    pOpts->keyWidth = TAP_KEY_SIZE_192;
                    TPM2_DEBUG_PRINT_1("Setting Key width to 192");
                    break;
                }

                cmpResult = 1;
                pOpts->keyWidthSpecified = TRUE;
                if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"256",
                            DIGI_STRLEN((const sbyte *)"256"), &cmpResult))
                {
                    TPM2_DEBUG_PRINT_1("Failed to compare memory");
                    goto exit;
                }

                if (!cmpResult)
                {
                    pOpts->keyWidth = TAP_KEY_SIZE_256;
                    TPM2_DEBUG_PRINT_1("Setting Key width to 256");
                    break;
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

                    /* Check length of hash algorithm string is within allowed limit */
                    if (DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"sha256"))
                    {
                        LOG_ERROR("--halg Hash algorithm string too long. Max size: %d bytes",
                                (int)DIGI_STRLEN((const sbyte *)"sha256"));
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        /* --halg hash algorithm */
                        pOpts->hashAlgSpecified = TRUE;
                        cmpResult = 1;
                        if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                    DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                        {
                            TPM2_DEBUG_PRINT_1("Failed to compare memory");
                            goto exit;
                        }

                        if (!cmpResult)
                        {
                            pOpts->keyHashAlg = optionValues[oIndex].val;
                            TPM2_DEBUG_PRINT("Setting Hash algorithm to %s", 
                                    optionValues[oIndex].pName);
                            break;
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
                    /* --mode encryption mode */
                    pOpts->keyModeSpecified = TRUE;
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
                        LOG_ERROR("--mode Encryption mode not specified");
                        goto exit;
                    }

                    /* Check length of symmetric cipher mode string is within allowed limit */
                    if (DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"ctr"))
                    {
                        LOG_ERROR("--kmode Invalid symmetric cipher mode. Must be cfb, ctr, ofb, cbc or ecb");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        cmpResult = 1;
                        if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                    DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                        {
                            TPM2_DEBUG_PRINT_1("Failed to compare memory");
                            goto exit;
                        }

                        if (!cmpResult)
                        {
                            pOpts->keyMode = optionValues[oIndex].val;
                            TPM2_DEBUG_PRINT("Setting key mode to %s", optionValues[oIndex].pName);
                            break;
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--kmode not cfb or ctr or ofb or cbc");
                        goto exit;
                    }
                }
                break;

            case 9:
                /* --pri output private key file */
                pOpts->outPrivKeyFileSpecified = TRUE;
                pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->privKeyFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-pri Private key output file not specified");
                    goto exit;
                }

                /* Check length of private key file string is within allowed limit */
                if (DIGI_STRLEN((const sbyte *)optarg) > FILE_PATH_LEN)
                {
                    LOG_ERROR("--pri Private key input file name too long");
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
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

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
                pOpts->key_cmk = TAP_KEY_CMK_ENABLE;
                TPM2_DEBUG_PRINT_1("cmk enabled");
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
    TAP_KeyInfo keyInfo = {0};
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList entityCredentials = { 0 };
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_KEY_CMK enable_cmk = TAP_KEY_CMK_DISABLE;
    TAP_Attribute cmkAttribute = {TAP_ATTR_KEY_CMK, sizeof(TAP_KEY_CMK), &enable_cmk};
    TAP_AttributeList keyAttributes = { 1, &cmkAttribute}  ;     
    TAP_Key *pTapKey = NULL;
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer privateKeyBuffer = {0};
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_ConfigInfoList configInfoList = { 0, };
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    /*int numCredentials = 0;
    int i = 0;*/

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

    enable_cmk = pOpts->key_cmk;

#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                &pOpts->serverPort);
    }

    if (!pOpts->serverNameSpecified || !pOpts->outPrivKeyFileSpecified)
    {
        LOG_ERROR("One of mandatory option --s, --pri not specified.");
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
    if (!pOpts->outPrivKeyFileSpecified)
    {
        LOG_ERROR("One of mandatory option --pri not specified.");
        goto exit;
    }
#endif
    if (FALSE == pOpts->keyUsageSpecified)
    {
        LOG_ERROR("One of mandatory option --ktype is not specified.");
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__

    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
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
        LOG_ERROR("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
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
    status = TAP_symGenerateKey(pTapContext, pEntityCredentials, &keyInfo, &keyAttributes, pKeyCredentials,
                                &pTapKey, &errContext);
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
        TPM2_DEBUG_PRINT_1("NULL pOpts->privKeyFile.pBuffer\n");
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
    if ((NULL != pTpm2ConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif

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

    if (NULL != entityCredentials.pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(&entityCredentials);
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
    /* Free pEntityCredentials */
    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials);
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
        TPM2_DEBUG_PRINT_1("Failed to create key.");
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
        LOG_ERROR("*****digicert_tpm2_createsymkey failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

