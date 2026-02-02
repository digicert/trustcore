/**
 @file moctap_createasymkey.c

 @page moctap_createasymkey

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_createasymkey -
 @endhtmlonly
 This tool creates an RSA or ECC key pair. The key pair is created with the ownership key as the parent.

 # SYNOPSIS
 `moctap_createasymkey [options]`

 # DESCRIPTION
 <B>moctap_createasymkey</B> generates an asymmetric key.

@verbatim
    --h [option(s)]]
        Display help for the specified option(s).
    --conf=[Security Module configuration file]
        Path to Security Module configuration file.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use.
    --kalg [ecc or rsa]
        (Mandatory) Specify the algorithm (RSA or ECC) to create the key
    --ktype [sign, storage, general, or attest]
        (Mandatory) Type of key (sign, storage, general, or attest) to create.
    --ksize [key size]
        (Mandatory) Key size (2048, 3072, or 4096) in bits.
    --kpwd [key password]
        Password of the key to create. If no key password is specified, 
        the key is created without a password.
    --ss [signing scheme]
        (Mandatory) Signing scheme (pkcs1, ecdsa1, ecdsa256, pss256, pkcs1_sha1 or pkcs1_der) to create the signing key.
    --es [encryption scheme]
        Encryption scheme (PKCS1, OAESPSHA1, or OAEPSHA256) to use to create the storage key.
    --c [ECC curve identifier]
        Curve identifier (n192, n224, n256, or n384 or n521) for ECC key.
    --pub [output public key file]
        Output file that contains the public key.
    --pri [output private key file]
        Output file that contains the private key.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 moctap_createsymkey

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

/* Port validation constants */
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

    byteBoolean keyUsageSpecified;
    TAP_KEY_USAGE keyUsage;

    byteBoolean keyWidthSpecified;
    TAP_KEY_SIZE keyWidth;

    byteBoolean algSpecified;
    TAP_KEY_ALGORITHM keyAlg;

    byteBoolean encSchSpecified;
    TAP_ENC_SCHEME encScheme;

    byteBoolean signSchSpecified;
    TAP_ENC_SCHEME keySignScheme;

    byteBoolean curveIdSpecified;
    TAP_ECC_CURVE curveId;

    byteBoolean outPubKeyFileSpecified;
    TAP_Buffer pubKeyFile;

    byteBoolean outPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

#ifdef __ENABLE_TAP_REMOTE__
    ubyte4 serverNameLen;
    ubyte4 serverPort;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

#else 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif

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
    LOG_MESSAGE("moctap_createasymkey: Help Menu\n");
    LOG_MESSAGE("This tool creates an RSA or ECC key pair."
            " The key pair is created with built in SRK as the parent.\n");

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
    LOG_MESSAGE("                   provider name of the SMP module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use.\n");
    LOG_MESSAGE("           --kalg=[key algorithm]");
    LOG_MESSAGE("                   (Mandatory) Specify the algorithm (RSA or ECC) to create the key\n");
    LOG_MESSAGE("           --ktype=[key type");
    LOG_MESSAGE("                   (Mandatory) Type of key (sign, storage, general, or attest) to create.\n");
    LOG_MESSAGE("           --ksize=[key size]");
    LOG_MESSAGE("                   (Mandatory) Key size (2048, 3072, or 4096) in bits.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to create.\n"
                "                   If no key password is specified, the key is created without a password.\n");
    LOG_MESSAGE("           --ss=[key signing scheme]");
    LOG_MESSAGE("                   (Mandatory) Signing scheme (pkcs1, ecdsa1, ecdsa256, pss256, pkcs1_sha1 or pkcs1_der) to create the signing key.\n");
    LOG_MESSAGE("           --es=[key encryption scheme]");
    LOG_MESSAGE("                   Encryption scheme (PKCS1, OAESPSHA1, or OAEPSHA256) to use to create the storage key.\n");
    LOG_MESSAGE("           --c=[ECC curve identifier]");
    LOG_MESSAGE("                   Curve identifier (n192, n224, n256, or n384 or n521) for ECC key.\n");
    LOG_MESSAGE("           --pub=[output public key file]");
    LOG_MESSAGE("                   Output file that contains the public key.\n");
    LOG_MESSAGE("           --pri=[output private key file]");
    LOG_MESSAGE("                   Output file that contains the private key.\n");
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
            {"kalg", required_argument, NULL, 4},
            {"ktype", required_argument, NULL, 5},
            {"kpwd", required_argument, NULL, 6},
            {"ss", required_argument, NULL, 8},
            {"es", required_argument, NULL, 9},
            {"pub", required_argument, NULL, 10},
            {"pri", required_argument, NULL, 11},
            {"ksize", required_argument, NULL, 12},
            {"c", required_argument, NULL, 13},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 15},
#endif
            {"pn", required_argument, NULL, 16},
            {"mid", required_argument, NULL, 17},
            {"cred", required_argument, NULL, 18},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 1;
    MSTATUS status;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif
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

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))
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
                if (('\0' == optarg[0]) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Invalid or no port number specified");
                    goto exit;
                }
                pOpts->serverPort = strtoul(optarg, NULL, 0);
                if ((pOpts->serverPort < MIN_PORT_NUMBER) || (pOpts->serverPort > MAX_PORT_NUMBER))
                {
                    LOG_ERROR("Invalid port number specified. Valid range: %d-%d",
                            MIN_PORT_NUMBER, MAX_PORT_NUMBER);
                    goto exit;
                }
                MOCTAP_DEBUG_PRINT("Server Port: %u", pOpts->serverPort);
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 4:
                {
                    /* kalg, Key algorithm RSA or ECC */
                    pOpts->algSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"rsa", TAP_KEY_ALGORITHM_RSA},
                        {"ecc", TAP_KEY_ALGORITHM_ECC},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-kalg Key algorithm not specified");
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
                                pOpts->keyAlg = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Creating %s key",
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--kalg not RSA or ECC");
                        goto exit;
                    }
                }
                break;

            case 5:
                {
                    /* --ktype, Key type sign, storage, attest, general */
                    pOpts->keyUsageSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"sign", TAP_KEY_USAGE_SIGNING},
                        {"storage", TAP_KEY_USAGE_DECRYPT},
                        {"attest", TAP_KEY_USAGE_ATTESTATION},
                        {"general", TAP_KEY_USAGE_GENERAL},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-ktype Key type not specified");
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
                                pOpts->keyUsage = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting key usage to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--ktype not sign or storage or general or attest");
                        goto exit;
                    }
                }
                break;

            case 6:
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
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                MOCTAP_DEBUG_PRINT("Key password: %s", optarg); 

                break;

            case 8:
                {
                    /* --ss signing scheme */
                    pOpts->signSchSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"pkcs1", TAP_SIG_SCHEME_PKCS1_5},
                        {"ecdsa1", TAP_SIG_SCHEME_ECDSA_SHA1},
                        {"ecdsa256", TAP_SIG_SCHEME_ECDSA_SHA256},
                        {"pss256", TAP_SIG_SCHEME_PSS_SHA256},
                        {"pkcs1_sha1", TAP_SIG_SCHEME_PKCS1_5_SHA1},
                        {"pkcs1_der", TAP_SIG_SCHEME_PKCS1_5_DER},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-ss Signing scheme not specified");
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
                                pOpts->keySignScheme = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting key signing scheme to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }
                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--ss not pkcs1 or ecdsa1 or ecdsa256 or pss256 or pkcs1_sha1 or pkcs1_der");
                        goto exit;
                    }
                }
                break;

            case 9:
                {
                    /* --es Encryption scheme */
                    OPT_VAL_INFO optionValues[] = {
                        {"pkcs1", TAP_ENC_SCHEME_PKCS1_5},
                        {"oaepsha1", TAP_ENC_SCHEME_OAEP_SHA1},
                        {"oaepsha256", TAP_ENC_SCHEME_OAEP_SHA256},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-es Encryption scheme not specified");
                        goto exit;
                    }

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {
                        /* --es Encryption scheme */
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
                                pOpts->encScheme = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting encryption scheme to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--es not pkcs1 or oaepsha1 or oaepsha256");
                        goto exit;
                    }
                    pOpts->encSchSpecified = TRUE;
                }
                break;

            case 10:
                /* --pub output public key file */
                pOpts->outPubKeyFileSpecified = TRUE;
                pOpts->pubKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->pubKeyFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-pub Public key output file not specified");
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->pubKeyFile.pBuffer, pOpts->pubKeyFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for Public key filename",
                            (int)pOpts->pubKeyFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->pubKeyFile.pBuffer, optarg, pOpts->pubKeyFile.bufferLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                MOCTAP_DEBUG_PRINT("Public key filename: %s", pOpts->pubKeyFile.pBuffer);

                break;

            case 11:
                /* --pri output private key file */
                pOpts->outPrivKeyFileSpecified = TRUE;
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
                MOCTAP_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

                break;

            case 12:
                {
                    /* --ksize, Key size 2048, 3072, or 4096 */
                    pOpts->keyWidthSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"2048", TAP_KEY_SIZE_2048},
                        {"3072", TAP_KEY_SIZE_3072},
                        {"4096", TAP_KEY_SIZE_4096},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-ksize Key size not specified");
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
                                pOpts->keyWidth = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting key size to %s bits", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--ksize not 2048, 3072, or 4096");
                        goto exit;
                    }
                }
                break;

            case 13:
                {
                    /* --c ECC curve identifier */
                    OPT_VAL_INFO optionValues[] = {
                        {"n192", TAP_ECC_CURVE_NIST_P192},
                        {"n224", TAP_ECC_CURVE_NIST_P224},
                        {"n256", TAP_ECC_CURVE_NIST_P256},
                        {"n384", TAP_ECC_CURVE_NIST_P384},
                        {"n521", TAP_ECC_CURVE_NIST_P521},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-c ECC curve identifier not specified");
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
                                pOpts->curveId = optionValues[oIndex].val;
                                MOCTAP_DEBUG_PRINT("Setting curve identifier to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--c not n192 or n224 or n256 or n384 or n521");
                        goto exit;
                    }

                    pOpts->curveIdSpecified = TRUE;
                }
                break;

            case 15:
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
                          "valid option in a remote build\n");
                goto exit;
#endif
                break;

        case 16:
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

        case 17:
            /* --mid module id */
            if (('\0' == optarg[0]) || ('-' == optarg[0]))
            {
                LOG_ERROR("Invalid or no module id specified");
                goto exit;
            }
            pOpts->moduleId = strtol(optarg, NULL, 0);
            if (pOpts->moduleId == 0)
            {
                LOG_ERROR("Invalid or no module id specified");
                goto exit;
            }
            MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
            pOpts->modIdSpecified = TRUE ;
            break;

        case 18:
            /* --cred credential file */
            pOpts->credFileSpecified = TRUE;
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
            MOCTAP_DEBUG_PRINT("cred file name name: %s", pOpts->credFileName);
            break;

            default:
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


int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = ERR_GENERAL;
    TAP_KeyInfo keyInfo = {0};
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_Buffer publicKeyBuffer = {0};
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer privateKeyBuffer = {0};
    TAP_ModuleList moduleList = { 0 };
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
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
    if (!pOpts->serverNameSpecified || !pOpts->outPubKeyFileSpecified ||
        !pOpts->outPrivKeyFileSpecified)
    {
        LOG_ERROR("One of mandatory option --s, --pub, --pri not specified.");
        goto exit;
    }
    if (!pOpts->keyWidthSpecified || !pOpts->keyUsageSpecified ||
        !pOpts->algSpecified || !pOpts->prNameSpecified || 
        !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory option --kalg, --ktype --ksize --pn --mid not specified.");
        printHelp();
        retval = 0;
        goto exit;
    }
    if (TAP_KEY_ALGORITHM_ECC == pOpts->keyAlg)
    {
        /* Key curve must be specified */
        if (!pOpts->curveIdSpecified)
        {
            LOG_ERROR("Mandatory option for this algorithm --c not specified.");
            printHelp();
            retval = 0;
            goto exit;
        }
    }

    if (TAP_KEY_USAGE_SIGNING == pOpts->keyUsage)
    {
        /* Signing Scheme must be specified for signing key */
        if (!pOpts->signSchSpecified)
        {
            LOG_ERROR("Mandatory option for this key usage --ss not specified.");
            printHelp();
            retval = 0;
            goto exit;
        }
    }
#else
    if (!pOpts->outPubKeyFileSpecified || !pOpts->outPrivKeyFileSpecified ||
             !pOpts->keyUsageSpecified || !pOpts->algSpecified ||
             !pOpts->prNameSpecified || !pOpts->modIdSpecified)
    {
        LOG_ERROR("One of mandatory option --pub, --pri, --kalg, --ktype "
                  "--pn, --mid not specified.");
        printHelp();
        retval = 0;
        goto exit;
    }
    if (TAP_KEY_ALGORITHM_ECC == pOpts->keyAlg)
    {
        /* Key curve must be specified */
        if (!pOpts->curveIdSpecified)
        {
            LOG_ERROR("Mandatory option for this algorithm --c not specified.");
            printHelp();
            retval = 0;
            goto exit;
        }
    }
    else
    {
        if (!pOpts->keyWidthSpecified)
        {
            LOG_ERROR("Mandatory option for this algorithm --ksize not specified.");
            printHelp();
            retval = 0;
            goto exit;
        }
    }

    if (TAP_KEY_USAGE_SIGNING == pOpts->keyUsage)
    {
        /* Signing Scheme must be specified for signing key */
        if (!pOpts->signSchSpecified)
        {
            LOG_ERROR("Mandatory option for this key usage --ss not specified.");
            printHelp();
            retval = 0;
            goto exit;
        }
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

    /*! The algorithm-specific key information.  This structure is selected by keyAlgorithm, and is either TAP_KeyInfo_RSA or TAP_KeyInfo_ECC. */

    /* Format input parameters */
    keyInfo.keyAlgorithm = pOpts->keyAlg;
    keyInfo.keyUsage = pOpts->keyUsage;
    keyInfo.tokenId = 0;
    keyInfo.objectId = 0;

    if (TAP_KEY_ALGORITHM_RSA == pOpts->keyAlg)
    {
        keyInfo.algKeyInfo.rsaInfo.sigScheme = pOpts->keySignScheme;
        keyInfo.algKeyInfo.rsaInfo.encScheme = pOpts->encScheme;
        keyInfo.algKeyInfo.rsaInfo.exponent = 0;
        keyInfo.algKeyInfo.rsaInfo.keySize = pOpts->keyWidth;
    }
    else 
    {
        keyInfo.algKeyInfo.eccInfo.sigScheme = pOpts->keySignScheme;
        keyInfo.algKeyInfo.eccInfo.curveId = pOpts->curveId;
    }

    /* Invoke TAP API */
    status = TAP_asymGenerateKey(pTapContext, pEntityCredentials, &keyInfo, NULL, pKeyCredentials,
                                &pTapKey, pErrContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_asymGenerateKey", status);
        goto exit;
    }

    /* Write public key to file */
    /* Serialize Public key */
    status = TAP_UTILS_serializePubKeyToPEM(&pTapKey->keyData,
                            &publicKeyBuffer);
    if (OK != status)
    {
        PRINT_STATUS("Serialize public key in PEM", status);
        /* Serialize in binary form if PEM serialization fails */
        MOCTAP_DEBUG_PRINT_1("Serializing public key in binary form\n");
        status = DIGI_CALLOC((void **)&(publicKeyBuffer.pBuffer),
                            MAX_CMD_BUFFER,
                            sizeof(*(publicKeyBuffer.pBuffer)));
        if (OK != status)
        {
            PRINT_STATUS("publicKeyBuffer memory allocation", status);
            goto exit;
        }
        status = TAP_SERIALIZE_serialize(TAP_SERALIZE_SMP_getPublicKeyShadowStruct(),
                            TAP_SD_IN,
                            (void *)&pTapKey->keyData.publicKey,
                            sizeof(pTapKey->keyData.publicKey),
                            publicKeyBuffer.pBuffer, MAX_CMD_BUFFER,
                            &publicKeyBuffer.bufferLen);
        if (OK != status)
        {
            PRINT_STATUS("Serialize public key in binary", status);
        }
    }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGICERT_writeFileEx((const char *)pOpts->pubKeyFile.pBuffer,
                                publicKeyBuffer.pBuffer,
                                publicKeyBuffer.bufferLen, TRUE);
#else
    status = DIGICERT_writeFile((const char *)pOpts->pubKeyFile.pBuffer,
                                publicKeyBuffer.pBuffer,
                                publicKeyBuffer.bufferLen);
#endif

    if (OK != status)
    {
        LOG_ERROR("Failed to write public key to file, error %d\n", status);
    }
    else
    {
        LOG_MESSAGE("Successfully wrote Public Key to file\n");
    }
    /* TAP_Key is the Private key, it should contain everything about the key,
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
        goto exit;
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

    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        status = TAP_unloadKey(pTapKey, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);

        status = TAP_freeKey(&pTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
    }

    status = TAP_UTILS_freeBuffer(&publicKeyBuffer);
    if (OK != status)
        PRINT_STATUS("TAP_UTILS_freeBuffer", status);

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
        DIGI_FREE((void **)&pEntityCredentials);
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

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->pubKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->pubKeyFile.pBuffer);

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
        LOG_ERROR("*****moctap_createasymkey failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

