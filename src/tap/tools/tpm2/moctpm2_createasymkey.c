/**
 @file moctpm2_createasymkey.c

 @page digicert_tpm2_createasymkey

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_createasymkey -
 @endhtmlonly
 Generate an asymmetric key using a TPM 2.0 chip.

 # SYNOPSIS
 `digicert_tpm2_createasymkey [options]`

 # DESCRIPTION
 <B>digicert_tpm2_createasymkey</B> This tool creates an RSA or ECC key pair.
            The key pair is created with the built-in SRK as the parent.

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
    --kalg=[key algorithm]
        (Mandatory) Specify the algorithm (rsa or ecc) to create the key.
    --ktype=[key type]
        (Mandatory) Type of key (sign, storage, general, or attest) to create.
    --ksize=[key size]
        (Mandatory for RSA keys) Key size (2048, 3072, or 4096) in bits.
    --kpwd=[key password]
        Password of the key to create. If no key password is specified, the key is created without a password.
    --ss=[key signing scheme]
        (Mandatory) Signing scheme (pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, pss256, pss384 or pss512) to create the signing key.
    --es=[key encryption scheme]
        Encryption scheme (pkcs1, oaepsha1, oaepsha256, oaepsha384 or oaepsha512) to use to create the storage key.
    --c=[ECC curve identifier]
        Curve identifier (n192 or n224 or n256 or n384 or n521) for ECC key.
    --pub=[output public key file]
        Output file that contains the public key.
    --pri=[output private key file]
        Output file that contains the private key.
    --enablecmk
        Enables duplication of the key to another TPM
    --modulenum=[module num]
        Module number to use. If not provided first module is used by default
    --hierarchy=Optional: Specify the hierarchy under which the key will be created (SH | EH | PH)
        Hierarchy under which key is created. Default is Storage Hierarchy (SH)
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 digicert_tpm2_createsymkey

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
#define MAX_PASSWORD_LEN 256
#define IS_VALID_PORT(p) ((p) > 0 && (p) <= 65535)

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
    TAP_KEY_CMK key_cmk ;

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

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
#endif

    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];

    TAP_ModuleId moduleNum;

    TAP_HIERARCHY_PROPERTY hierarchy;
    byteBoolean hierarchySpecified;

    TAP_CREATE_KEY_TYPE keyType;

    byteBoolean inUniqueFileSpecified;
    TAP_Buffer inUniqueFile;

    byteBoolean handleSpecified;
    ubyte4      keyHandle;
    ubyte       handleBuf[8];
    TAP_Buffer  handle;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_createasymkey: Help Menu\n");
    LOG_MESSAGE("This tool creates an RSA or ECC key pair."
            " The key pair is created with built-in SRK as the parent.\n");

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
    LOG_MESSAGE("           --kalg=[ecc or rsa]");
    LOG_MESSAGE("                   (Mandatory) Specify the algorithm (rsa or ecc) to create the key.\n");
    LOG_MESSAGE("           --ktype=[key type]");
    LOG_MESSAGE("                   (Mandatory) Type of key (sign, storage, general, or attest) to create.\n");
    LOG_MESSAGE("           --ksize=[key size]");
    LOG_MESSAGE("                   (Mandatory for RSA keys) Key size (2048, 3072, or 4096) in bits.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to create. If no key password is specified, the key is created without\n"
                "                   password.\n");
    LOG_MESSAGE("           --ss=[key signing scheme]");
    LOG_MESSAGE("                   (Mandatory) Signing scheme (pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, \n"
                "                   pss256, pss384 or pss512) to create the signing key.\n");
    LOG_MESSAGE("           --es=[key encryption scheme]");
    LOG_MESSAGE("                   Encryption scheme (pkcs1, oaepsha1, oaepsha256, \n"
                "                   oaepsha384, oaepsha512) to use to create the storage key.\n");
    LOG_MESSAGE("           --c=[ECC curve identifier]");
    LOG_MESSAGE("                   Curve identifier (n192 or n224 or n256 or n384 or n521) for ECC key.\n");
    LOG_MESSAGE("           --enablecmk");
    LOG_MESSAGE("                   enables duplication of the key to another TPM.\n"
                "                   By default, the key is created with CMK disabled.\n");
    LOG_MESSAGE("           --hr=[SH | EH | PH]");
    LOG_MESSAGE("                   Hierarchy under which this new key is created. (SH | EH | PH). Default is SH (Storage Hierarchy)\n");
    LOG_MESSAGE("           --primary");
    LOG_MESSAGE("                   Create a primary key\n");
    LOG_MESSAGE("           --pub=[output public key file]");
    LOG_MESSAGE("                   Output file that contains the public key\n");
    LOG_MESSAGE("           --pri=[output private key file]");
    LOG_MESSAGE("                   Output file that contains the private key.\n");
    LOG_MESSAGE("           --uniquedata=[unique data file]");
    LOG_MESSAGE("                   (Optional) Input file containing data to write (less than 256 bytes).\n");
    LOG_MESSAGE("           --pid=[key persistence id]");
    LOG_MESSAGE("                   (Optional) ID where the primary key should be persisted.\n");
    return;
}

ubyte4 parseObjectId(char *objectStr, int len)
{
    ubyte4 rc = 0xffffffff;
    ubyte4 val = 0;
    int i, base = 1;

    if (len > 2)
    {
        if ((objectStr[0] == '0') &&
                ((objectStr[1] == 'x') || (objectStr[1] == 'X')))
        {
            objectStr += 2;
            len -= 2;
            if (len != sizeof(ubyte4) * 2)
                goto exit;

            for(i = --len; i >= 0; i--)
            {
                if(objectStr[i] >= '0' && objectStr[i] <= '9')
                {
                    val += (objectStr[i] - '0') * base;
                    base *= 16;
                }
                else if(objectStr[i] >= 'A' && objectStr[i] <= 'F')
                {
                    val += (objectStr[i] - 'A') * base;
                    base *= 16;
                }
                else if(objectStr[i] >= 'a' && objectStr[i] <= 'f')
                {
                    val += (objectStr[i] - 'a') * base;
                    base *= 16;
                }
                else
                    goto exit;
            }

            rc = val;
        }
    }

exit:
    return rc;
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
            {"ss", required_argument, NULL, 7},
            {"es", required_argument, NULL, 8},
            {"pub", required_argument, NULL, 9},
            {"pri", required_argument, NULL, 10},
            {"ksize", required_argument, NULL, 11},
            {"c", required_argument, NULL, 12},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 13},
#endif
            {"enablecmk", no_argument, NULL, 14},
            {"hr", required_argument, NULL, 16},
            {"modulenum", required_argument, NULL, 15},
            {"primary", no_argument, NULL, 17},
            {"uniquedata", required_argument, NULL, 18},
            {"pid", required_argument, NULL, 19},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 1;
    MSTATUS status;
    ubyte4 optValLen = 0;

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_1("Invalid parameters.");
        goto exit;
    }

    /* Set any default values */
    pOpts->keyType = TAP_CREATE_KEY_TYPE_NON_PRIMARY;

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

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverName[pOpts->serverNameLen] = '\0';
                TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
                pOpts->serverNameSpecified = TRUE;
#else
                LOG_ERROR("Server name not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 3:
#ifdef __ENABLE_TAP_REMOTE__
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
                    TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
                }
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 4:
                {
                    /* alg, Key algorithm RSA or ECC */
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keyAlg = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Creating %s key",
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
                    pOpts->algSpecified = TRUE;
                }
                break;

            case 5:
                {
                    /* --type, Key type sign, storage, attest, general */
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keyUsage = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting key usage to %s", 
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
                    pOpts->keyUsageSpecified = TRUE;
                }
                break;

            case 6:
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
                        TPM2_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->keyAuthValue.pBuffer);
                        pOpts->keyAuthValue.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->keyAuthValue.pBuffer[passwordLen] = '\0';
                    pOpts->keyAuthSpecified = TRUE;
                }
                break;

            case 7:
                {
                    /* --ss signing scheme */
                    OPT_VAL_INFO optionValues[] = {
                        {"pkcs1", TAP_SIG_SCHEME_PKCS1_5},
                        {"pkcs1_sha384", TAP_SIG_SCHEME_PKCS1_5_SHA384},
                        {"pkcs1_sha256", TAP_SIG_SCHEME_PKCS1_5_SHA256},
                        {"pkcs1_sha512", TAP_SIG_SCHEME_PKCS1_5_SHA512},
                        {"ecdsa1", TAP_SIG_SCHEME_ECDSA_SHA1},
                        {"ecdsa256", TAP_SIG_SCHEME_ECDSA_SHA256},
                        {"ecdsa384", TAP_SIG_SCHEME_ECDSA_SHA384},
                        {"ecdsa512", TAP_SIG_SCHEME_ECDSA_SHA512},
                        {"pss256", TAP_SIG_SCHEME_PSS_SHA256},
                        {"pss384", TAP_SIG_SCHEME_PSS_SHA384},
                        {"pss512", TAP_SIG_SCHEME_PSS_SHA512},
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keySignScheme = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting key signing scheme to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }
                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--ss not pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, pss256, pss384 or pss512");
                        goto exit;
                    }
                    pOpts->signSchSpecified = TRUE;
                }
                break;

            case 8:
                {
                    /* --es Encryption scheme */
                    OPT_VAL_INFO optionValues[] = {
                        {"pkcs1", TAP_ENC_SCHEME_PKCS1_5},
                        {"oaepsha1", TAP_ENC_SCHEME_OAEP_SHA1},
                        {"oaepsha256", TAP_ENC_SCHEME_OAEP_SHA256},
                        {"oaepsha384", TAP_ENC_SCHEME_OAEP_SHA384},
                        {"oaepsha512", TAP_ENC_SCHEME_OAEP_SHA512},
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->encScheme = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting encryption scheme to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--es not pkcs1, oaepsha1, oaepsha256, oaepsha384 or oaepsha512");
                        goto exit;
                    }
                    pOpts->encSchSpecified = TRUE;
                }
                break;

            case 9:
                /* --pub output public key file */
                {
                    ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                    
                    if (optValLen >= FILE_PATH_LEN)
                    {
                        LOG_ERROR("Public key file path too long. Max length: %d characters",
                                FILE_PATH_LEN - 1);
                        goto exit;
                    }
                    if ((optValLen == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-pub Public key output file not specified");
                        goto exit;
                    }

                    pOpts->pubKeyFile.bufferLen = optValLen + 1;
                    if (OK != (status = DIGI_MALLOC((void **)&pOpts->pubKeyFile.pBuffer, pOpts->pubKeyFile.bufferLen)))
                    {
                        LOG_ERROR("Unable to allocate %d bytes for Public key filename",
                                (int)pOpts->pubKeyFile.bufferLen);
                        goto exit;
                    }
                    if (OK != DIGI_MEMCPY(pOpts->pubKeyFile.pBuffer, optarg, optValLen))
                    {
                        TPM2_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->pubKeyFile.pBuffer);
                        pOpts->pubKeyFile.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->pubKeyFile.pBuffer[optValLen] = '\0';
                    TPM2_DEBUG_PRINT("Public key filename: %s", pOpts->pubKeyFile.pBuffer);
                    pOpts->outPubKeyFileSpecified = TRUE;
                }
                break;

            case 10:
                /* --pri output private key file */
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
                        LOG_ERROR("-pri Private key output file not specified");
                        goto exit;
                    }

                    pOpts->privKeyFile.bufferLen = optValLen + 1;
                    if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, pOpts->privKeyFile.bufferLen)))
                    {
                        LOG_ERROR("Unable to allocate %d bytes for Private key filename",
                                (int)pOpts->privKeyFile.bufferLen);
                        goto exit;
                    }
                    if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, optValLen))
                    {
                        TPM2_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);
                        pOpts->privKeyFile.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->privKeyFile.pBuffer[optValLen] = '\0';
                    TPM2_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);
                    pOpts->outPrivKeyFileSpecified = TRUE;
                }
                break;

            case 11:
                {
                    /* --ksize, Key size 2048, 3072 or 4096 */
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
                        LOG_ERROR("--ksize Key size not specified");
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->keyWidth = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting key size to %s bits", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--kh not 2048, 3072, or 4096");
                        goto exit;
                    }
                    pOpts->keyWidthSpecified = TRUE;
                }
                break;

            case 12:
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->curveId = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting curve identifier to %s", 
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

            case 13:
                /* tpm2 config file path */
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
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->confFilePath[optValLen] = '\0';
                TPM2_DEBUG_PRINT("TPM2 Configuration file path: %s", 
                                 pOpts->confFilePath);
                pOpts->isConfFileSpecified = TRUE;
                break;

            case 14:
                pOpts->key_cmk = TAP_KEY_CMK_ENABLE;
                TPM2_DEBUG_PRINT_1("cmk enabled");
                break;

            case 15:
                {
                    char *endptr;
                    long moduleNum;
                    errno = 0;
                    moduleNum = strtol(optarg, &endptr, 0);
                    if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (moduleNum <= 0))
                    {
                        TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater than 0");
                        goto exit;
                    }
                    pOpts->moduleNum = (ubyte4)moduleNum;
                    TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
                }
                break;

            case 16:
                {
                    /* --hr Hierarchy identifier */
                    OPT_VAL_INFO optionValues[] = {
                        {"SH", TAP_HIERARCHY_STORAGE},
                        {"EH", TAP_HIERARCHY_ENDORSEMENT},
                        {"PH", TAP_HIERARCHY_PLATFORM},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("--hr Hierarchy identifier not specified, specify SH or EH or PH");
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
                                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->hierarchy = optionValues[oIndex].val;
                                TPM2_DEBUG_PRINT("Setting Hierarchy identifier to %s", 
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (!optionValues[oIndex].pName)
                    {
                        LOG_ERROR("--hr not SH or EH or PH");
                        goto exit;
                    }
                    pOpts->hierarchySpecified = TRUE;
                }
                break;

            case 17:
                pOpts->keyType = TAP_CREATE_KEY_TYPE_PRIMARY;
                TPM2_DEBUG_PRINT_1("primary key creation enabled");
                break;

            case 18:
                /* --uniquedata unique data file */
                {
                    ubyte4 optValLen = DIGI_STRLEN((const sbyte *)optarg);
                    
                    if (optValLen >= FILE_PATH_LEN)
                    {
                        LOG_ERROR("Unique data file path too long. Max length: %d characters",
                                FILE_PATH_LEN - 1);
                        goto exit;
                    }
                    if ((optValLen == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("--uniquedata unique-data input file not specified");
                        goto exit;
                    }

                    pOpts->inUniqueFile.bufferLen = optValLen + 1;
                    if (OK != (status = DIGI_MALLOC((void **)&pOpts->inUniqueFile.pBuffer, 
                                    pOpts->inUniqueFile.bufferLen)))
                    {
                        LOG_ERROR("Unable to allocate %d bytes for unique-data filename",
                                (int)pOpts->inUniqueFile.bufferLen);
                        goto exit;
                    }
                    if (OK != DIGI_MEMCPY(pOpts->inUniqueFile.pBuffer, optarg, optValLen))
                    {
                        TPM2_DEBUG_PRINT_1("Failed to copy memory");
                        DIGI_FREE((void **)&pOpts->inUniqueFile.pBuffer);
                        pOpts->inUniqueFile.bufferLen = 0;
                        goto exit;
                    }
                    pOpts->inUniqueFile.pBuffer[optValLen] = '\0';
                    TPM2_DEBUG_PRINT("unique data input filename: %s", pOpts->inUniqueFile.pBuffer);
                    pOpts->inUniqueFileSpecified = TRUE;
                }
                break;
 
            case 19:
                /* --pid key handle for persistence */
                pOpts->handleSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg);
                pOpts->keyHandle = parseObjectId(optarg, optValLen);

                status = DIGI_ATOH((ubyte *) &optarg[2], optValLen - 2, (ubyte *)pOpts->handleBuf);
                if (OK != status)
                {
                    LOG_ERROR("--pid invalid hex value\n");
                    goto exit;
                }

                TPM2_DEBUG_PRINT("TPM2 Key Handle: 0x%08x", pOpts->keyHandle);

                pOpts->handle.pBuffer = (ubyte *) pOpts->handleBuf;
                pOpts->handle.bufferLen = (optValLen - 2)/2;

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
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_KEY_CMK enable_cmk;
    TAP_HIERARCHY_PROPERTY hierarchy = TAP_HIERARCHY_STORAGE;
    TAP_CREATE_KEY_TYPE keyType = TAP_CREATE_KEY_TYPE_NON_PRIMARY;
    TAP_Attribute cmkAttribute = {TAP_ATTR_KEY_CMK, sizeof(TAP_KEY_CMK), &enable_cmk};
    ubyte4 numKeyAttrs = 1;
    TAP_AttributeList keyAttributes = {0};
    TAP_Key *pTapKey = NULL;
    TAP_Buffer publicKeyBuffer = {0};
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer privateKeyBuffer = {0};
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    /*int numCredentials = 0;*/
    int i = 0;
    TAP_Buffer uniqueDataBuf = {0};

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    enable_cmk = pOpts->key_cmk;

    if (pOpts->hierarchySpecified)
        hierarchy = pOpts->hierarchy;

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

    if (!pOpts->serverNameSpecified || !pOpts->outPubKeyFileSpecified ||
        !pOpts->outPrivKeyFileSpecified)
    {
        LOG_ERROR("One of mandatory option --s, --pub, --pri not specified."); 
        goto exit;
    }
    if (!pOpts->keyUsageSpecified || !pOpts->algSpecified)
    {
        LOG_ERROR("One of mandatory option --kalg, --ktype not specified.");
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
#else
    if (!pOpts->outPubKeyFileSpecified || !pOpts->outPrivKeyFileSpecified ||
             !pOpts->keyUsageSpecified || !pOpts->algSpecified)
    {
        LOG_ERROR("One of mandatory option --pub, --pri, --kalg, --ktype "
                "not specified.");
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

    if ( (TAP_CREATE_KEY_TYPE_PRIMARY == pOpts->keyType) && !(pOpts->handleSpecified) )
    {
            LOG_ERROR("--pid is mandatory for primary key.");
            printHelp();
            retval = 0;
            goto exit;
    }

    if (TAP_CREATE_KEY_TYPE_PRIMARY != pOpts->keyType)
    {
        if (pOpts->inUniqueFileSpecified || pOpts->handleSpecified)
        {
            LOG_ERROR("--uniquedata, --pid are supported only for primary key.");
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
        pKeyCredentials = & keyCredentials;
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

    /*! The algorithm-specific key information.  This structure is selected by keyAlgorithm, and is either TAP_KeyInfo_RSA or TAP_KeyInfo_ECC. */

    /* Format input parameters */
    keyInfo.keyAlgorithm = pOpts->keyAlg;
    keyInfo.keyUsage = pOpts->keyUsage;
    keyInfo.tokenId = hierarchy;
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

    /* Set Key Attributes */
    if (TAP_CREATE_KEY_TYPE_PRIMARY == pOpts->keyType)
    {
        numKeyAttrs++;
    }
    if (TRUE == pOpts->inUniqueFileSpecified)
    {
        numKeyAttrs++;
    }
    if (pOpts->handleSpecified)
    {
        numKeyAttrs++;
    }

    status = DIGI_CALLOC((void**)&(keyAttributes.pAttributeList), numKeyAttrs,
                        sizeof(TAP_Attribute));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory; status %d", status);
        goto exit;
    }
    keyAttributes.listLen = numKeyAttrs;

    i=0;
    keyAttributes.pAttributeList[i]= cmkAttribute;

    if (TAP_CREATE_KEY_TYPE_PRIMARY == pOpts->keyType)
    {
        i++;
        keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_TYPE;
        keyAttributes.pAttributeList[i].length = sizeof(TAP_CREATE_KEY_TYPE);
        keyAttributes.pAttributeList[i].pStructOfType = &(pOpts->keyType);
    }
    if (TRUE == pOpts->inUniqueFileSpecified)
    {
        /* Read input data file */
        status = DIGICERT_readFile((const char *)pOpts->inUniqueFile.pBuffer,
                &uniqueDataBuf.pBuffer, &uniqueDataBuf.bufferLen);
        if (OK != status)
        {
            LOG_ERROR("Error reading unique-data from file, status = %d\n", status);
            goto exit;
        }

        if ( (0>= uniqueDataBuf.bufferLen) || (256 < uniqueDataBuf.bufferLen) )
        {
            LOG_ERROR("Invalid unique data length, maximum allowed 256, length=%d, status = %d\n",
                   uniqueDataBuf.bufferLen, status);
            goto exit;
        }
        
        i++;
        keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_ENTROPY;
        keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
        keyAttributes.pAttributeList[i].pStructOfType = &(uniqueDataBuf);
    }
    if (pOpts->handleSpecified)
    {
        i++;
        keyAttributes.pAttributeList[i].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
        keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
        keyAttributes.pAttributeList[i].pStructOfType = (void *) &(pOpts->handle);
    }

    /* Invoke TAP API */
    status = TAP_asymGenerateKey(pTapContext, pEntityCredentials, &keyInfo, &keyAttributes, pKeyCredentials,
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
        PRINT_STATUS("Serialize public key", status);
        /* Serialize in binary form if PEM serialization fails */
        TPM2_DEBUG_PRINT_1("Serializing public key in binary form\n");
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
        goto exit;
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
        TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
    
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
    
    /* Free attributes */
    if (NULL != keyAttributes.pAttributeList)
    {
        status = DIGI_FREE((void **)&(keyAttributes.pAttributeList));
        if (OK != status)
            PRINT_STATUS("DIGI_FREE() for pAttributes", status);
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
        LOG_ERROR("*****digicert_tpm2_createasymkey failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

