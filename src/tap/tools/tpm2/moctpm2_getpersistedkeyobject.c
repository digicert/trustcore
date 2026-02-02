/**
 @file moctpm2_getpersistedobject.c

 @page digicert_tpm2_getpersistedobject

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_getpersistedobject -
 @endhtmlonly
 retrieves a persisted object and serializes
 as a TAP blob.

 # SYNOPSIS
 `digicert_tpm2_getpersistedobject [options]` retrieves a persisted object and serializes
 as a TAP blob.

 # DESCRIPTION
 <B>digicert_tpm2_getpersistedobject</B> 

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
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
    --pid=[Persistent object ID]
        (Mandatory) Persistent object ID where object is stored. Must be hex value between 0x81000000 - 0x8100ffff.
    --kalg=[key algorithm]
        (Mandatory) Specify the algorithm (rsa, ecc, aes, hmac) of the key object.
    --ktype=[key type]
        (Mandatory) Type of key object (sign, storage, general, or attest).
    --halg=[key hash algorithm]
        (If applicable) Hash algorithm (sha1 or sha256) for hmac keys.\n");
    --kmode=[key mode]
        (If applicable) Key mode (cfb or ctr or ofb or cbc) for aes keys.\n");
    --ksize=[key size]
        (If applicable) Key size in bits, 128, 192, 256 for AES or 2048, 3072, 4096 for RSA.\n");
    --kpwd=[key password]
        (If applicable) Password of the key.
    --ss=[key signing scheme]
        (If applicable) Signing scheme (pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, pss256, pss384 or pss512).
    --es=[key encryption scheme]
        (If applicable) Encryption scheme (pkcs1, oaepsha1, oaepsha256, oaepsha384 or oaepsha512).
    --c=[ECC curve identifier]
        (If applicable) Curve identifier (n192 or n224 or n256 or n384 or n521) for an ECC key.
    --pri=[output private key file]
        (Mandatory) Output file that will contain the private key.
    --pub=[output public key file]
        (If applicable) Output file that will contain the public key.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim


 # SEE ALSO
 digicert_tpm2_createasymkey, digicert_tpm2_createsymkey, digicert_tpm2_persistkeyobject

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

    byteBoolean keyUsageSpecified;
    TAP_KEY_USAGE keyUsage;

    byteBoolean keyModeSpecified;
    TAP_SYM_KEY_MODE keyMode;

    byteBoolean hashAlgSpecified;
    TAP_HASH_ALG keyHashAlg;

    byteBoolean keyWidthSpecified;
    TAP_KEY_SIZE keyWidth;

    byteBoolean algSpecified;
    TAP_KEY_ALGORITHM keyAlg;

    byteBoolean encSchSpecified;
    TAP_ENC_SCHEME encScheme;

    byteBoolean signSchSpecified;
    TAP_SIG_SCHEME keySignScheme;

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

    TAP_ModuleId moduleNum;

    ubyte objectIdSpecified;
    ubyte4 objectId;

    TAP_KeyInfo tapKeyInfo;
    
    ubyte idBuf[8];
    TAP_Buffer id;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_getpersistedobject: Help Menu\n");
    LOG_MESSAGE("retrieves a persisted object and serializes it as a TAP blob.\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [display command line options]");
    LOG_MESSAGE("                   Help menu\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[server name]");
    LOG_MESSAGE("                   Mandatory. Host on which TPM chip is located.  This can be 'localhost' or a\n"
                "                   remote host running a TAP server.\n");
    LOG_MESSAGE("           --p=server port]");
    LOG_MESSAGE("                   Port on which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[TPM 2.0 configuration file]");
    LOG_MESSAGE("                   Path to TPM 2.0 module configuration file.\n");
#endif
    LOG_MESSAGE("           --modulenum=[module num]");
    LOG_MESSAGE("                   Specify the module num to use. If not provided, the first module found is used.\n");

    LOG_MESSAGE("           --pid=[Persistent object ID]");
    LOG_MESSAGE("                   (Mandatory) Persistent Key ID where object is stored.\n");
    LOG_MESSAGE("                   Must be hex value between 0x81000000 - 0x8101ffff\n");
    LOG_MESSAGE("           --kalg=[key algorithm]");
    LOG_MESSAGE("                   (Mandatory) Specify the algorithm (rsa, ecc, aes, hmac) of the key object.\n");
    LOG_MESSAGE("           --ktype=[key type]");
    LOG_MESSAGE("                   (Mandatory) Type of key object (sign, storage, general, or attest).\n");
    LOG_MESSAGE("           --halg=[key hash algorithm]");
    LOG_MESSAGE("                   (If applicable) Hash algorithm (sha1 or sha256) for hmac keys.\n");
    LOG_MESSAGE("           --kmode=[key mode]");
    LOG_MESSAGE("                   (If applicable) Key mode (cfb or ctr or ofb or cbc) for aes keys.\n");
    LOG_MESSAGE("           --ksize=[key size]");
    LOG_MESSAGE("                   (If applicable) Key size in bits, 128, 192, 256 for AES or 2048, 3072, 4096 for RSA.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   (If applicable) Password of the key.\n");
    LOG_MESSAGE("           --ss=[key signing scheme]");
    LOG_MESSAGE("                   (If applicable) Signing scheme (pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, pss256, pss384 or pss512).\n");
    LOG_MESSAGE("           --es=[key encryption scheme]");
    LOG_MESSAGE("                   (If applicable) Encryption scheme (pkcs1, oaepsha1, oaepsha256, oaepsha384 or oaepsha512).\n");
    LOG_MESSAGE("           --c=[ECC curve identifier]");
    LOG_MESSAGE("                   (If applicable) Curve identifier (n192 or n224 or n256 or n384 or n521) for an ECC key.\n");
    LOG_MESSAGE("           --pri=[output private key file]");
    LOG_MESSAGE("                   (Mandatory) Output file that will contain the private key.\n");
    LOG_MESSAGE("           --pub=[output public key file]");
    LOG_MESSAGE("                   (If applicable) Output file that will contain the public key.\n");

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

static void createTAPKeyInfo(cmdLineOpts *pOpts)
{
    pOpts->tapKeyInfo.keyUsage = pOpts->keyUsage;
    pOpts->tapKeyInfo.keyAlgorithm = pOpts->keyAlg;
    pOpts->tapKeyInfo.keyUsage = pOpts->keyUsage;

    if (TAP_KEY_ALGORITHM_RSA == pOpts->keyAlg)
    {   
        pOpts->tapKeyInfo.algKeyInfo.rsaInfo.keySize = pOpts->keyWidth;
        
        if (TAP_KEY_USAGE_SIGNING == pOpts->keyUsage || TAP_KEY_USAGE_ATTESTATION == pOpts->keyUsage)
        {
            pOpts->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = pOpts->keySignScheme;
        }
        else if (TAP_KEY_USAGE_DECRYPT == pOpts->keyUsage || TAP_KEY_USAGE_STORAGE == pOpts->keyUsage)
        {
            pOpts->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = pOpts->encScheme;
        }
        else if (TAP_SIG_SCHEME_NONE != pOpts->keySignScheme)  /* we'll set sig scheme or enc scheme if not empty */
        {
            pOpts->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = pOpts->keySignScheme; 
        }
        else if (TAP_ENC_SCHEME_NONE != pOpts->encScheme)
        {
            pOpts->tapKeyInfo.algKeyInfo.rsaInfo.encScheme = pOpts->encScheme; 
        }
        /* else leave rsaInfo.sig/encscheme as 0 */
    } 
#ifdef __ENABLE_DIGICERT_ECC__
    else if (TAP_KEY_ALGORITHM_ECC == pOpts->keyAlg)
    {
        pOpts->tapKeyInfo.algKeyInfo.eccInfo.curveId = pOpts->curveId;

        if (TAP_KEY_USAGE_SIGNING == pOpts->keyUsage || TAP_KEY_USAGE_ATTESTATION == pOpts->keyUsage)
        {
            pOpts->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = pOpts->keySignScheme;
        }
        else if (TAP_SIG_SCHEME_NONE != pOpts->keySignScheme)  /* we'll set sig scheme or enc scheme if not empty */
        {
            pOpts->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = pOpts->keySignScheme; 
        }

        /* else leave eccInfo.sigscheme as 0 */
    }
#endif
    else if (TAP_KEY_ALGORITHM_AES == pOpts->keyAlg)
    {   
        pOpts->tapKeyInfo.algKeyInfo.aesInfo.keySize = pOpts->keyWidth;
        pOpts->tapKeyInfo.algKeyInfo.aesInfo.symMode = pOpts->keyMode;
    }
    else if (TAP_KEY_ALGORITHM_HMAC == pOpts->keyAlg)
    {
        pOpts->tapKeyInfo.algKeyInfo.hmacInfo.hashAlg = pOpts->keyHashAlg;
    }
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
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
#endif
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
            {"modulenum", required_argument, NULL, 17},
            {"pid", required_argument, NULL, 18},
            {"halg", required_argument, NULL, 19},
            {"kmode", required_argument, NULL, 20},
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
                    LOG_ERROR("-s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            DIGI_STRLEN((const sbyte *)optarg)))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
#else
                LOG_ERROR("Server name not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 3:
#ifdef __ENABLE_TAP_REMOTE__
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
#else
                LOG_ERROR("Server port not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case 4:
                {
                    /* alg, Key algorithm RSA, ECC, AES, or HMAC */
                    pOpts->algSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"rsa", TAP_KEY_ALGORITHM_RSA},
                        {"ecc", TAP_KEY_ALGORITHM_ECC},
                        {"aes", TAP_KEY_ALGORITHM_AES},
                        {"hmac", TAP_KEY_ALGORITHM_HMAC},
                        {NULL, 0},
                    };
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        LOG_ERROR("-kalg Key algorithm not specified");
                        goto exit;
                    }

                    /* Check Key algorithm string length */
                    if(DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"hmac"))
                    {
                        LOG_ERROR("--kalg Invalid key algorithm. Must be rsa, ecc, aes, or hmac");
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
                }
                break;

            case 5:
                {
                    /* --type, Key type sign, storage, attest, general */
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

                    /* Check if Key type string length exceeds maximum allowed */
                    if(DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"storage"))
                    {
                        LOG_ERROR("--ktype Invalid key type. Must be sign, storage, general, or attest");
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
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Key password: %s", optarg); 

                break;
            
            case 8:
                {
                    /* --ss signing scheme */
                    pOpts->signSchSpecified = TRUE;
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

                    /* Check if Signing scheme string length exceeds maximum allowed */
                    if(DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"pkcs1_sha512"))
                    {
                        LOG_ERROR("--ss Invalid signing scheme. Must be pkcs1, pkcs1_sha256, pkcs1_sha384, pkcs1_sha512, ecdsa1, ecdsa256, ecdsa384, ecdsa512, pss256, pss384 or pss512");
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
                }
                break;

            case 9:
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
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Public key filename: %s", pOpts->pubKeyFile.pBuffer);

                break;

            case 11:
                /* --pri output private key file */
                pOpts->outPrivKeyFileSpecified = TRUE;
                pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->pubKeyFile.bufferLen == 1) ||
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
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

                break;

            case 12:
                {
                    /* --ksize, Key size 2048, 3072, or 4096 */
                    pOpts->keyWidthSpecified = TRUE;
                    OPT_VAL_INFO optionValues[] = {
                        {"128", TAP_KEY_SIZE_128},
                        {"192", TAP_KEY_SIZE_192},
                        {"256", TAP_KEY_SIZE_256},
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

#ifndef __ENABLE_TAP_REMOTE__
            case 15:
                /* tpm2 config file path */
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

                break;
#else
                LOG_ERROR("--conf not a valid option in a remote-only build\n");
                goto exit;
#endif

            case 17:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
                break;

            case 18:
                /* We get the id as a ubyte4 to validate it, and then get it as a TAP_Buffer */
                pOpts->objectIdSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                pOpts->objectId = parseObjectId(optarg, optValLen);

                if (pOpts->objectId < 0x81000000 || pOpts->objectId > 0x8101ffff)
                {
                    LOG_ERROR("Invalid --pid, must be value between 0x81000000 - 0x8101ffff");
                    goto exit;
                }

                status = DIGI_ATOH((ubyte *) &optarg[2], optValLen - 2, (ubyte *)pOpts->idBuf);
                if (OK != status)
                {
                    LOG_ERROR("--pid invalid hex value\n");
                    goto exit;
                }

                TPM2_DEBUG_PRINT("TPM2 Object ID: 0x%08x", pOpts->objectId);
                
                pOpts->id.pBuffer = (ubyte *) pOpts->idBuf;
                pOpts->id.bufferLen = (optValLen - 2)/2;

                break;
                
            case 19:
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

            case 20:
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

            default:
                pOpts->exitAfterParse = TRUE;
                goto exit;
                break;
        }
    }

    createTAPKeyInfo(pOpts);
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
    TAP_ErrorContext errContext = { 0 };
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
    TAP_BLOB_FORMAT blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer privateKeyBuffer = {0};
    TAP_Buffer publicKeyBuffer = {0};

    TAP_Key *pTapKey = NULL;

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

    if(!pOpts->outPrivKeyFileSpecified || !pOpts->objectIdSpecified) 
    {
        LOG_ERROR("One or more mandatory options --pid, --pri not specified.");
        goto exit;
    }
    
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
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

    if (!pOpts->serverNameSpecified)
    {
        LOG_ERROR("Mandatory option --s not specified.");
        goto exit;        
    }

    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) &&
            DIGI_STRNICMP((const sbyte *)pOpts->serverName,
                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;
    }

    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
    connInfo.serverName.bufferLen = pOpts->serverNameLen;
    connInfo.serverPort = pOpts->serverPort;

#else

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

#endif /* __ENABLE_TAP_REMOTE__ */

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

    status = TAP_importKeyFromID(pTapContext, pEntityCredentials, &pOpts->tapKeyInfo, &pOpts->id, NULL,
            pKeyCredentials, &pTapKey, &errContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_importKeyFromID", status);
        goto exit;
    }

    if ((TAP_KEY_ALGORITHM_ECC == pOpts->keyAlg || TAP_KEY_ALGORITHM_RSA == pOpts->keyAlg) && pOpts->outPubKeyFileSpecified)
    {
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

    if (NULL != privateKeyBuffer.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&privateKeyBuffer);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
    }

    if (NULL != publicKeyBuffer.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&publicKeyBuffer);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeBuffer", status);
    }

    if (NULL != pTapKey)
    {
        /* Unload key object */
        status = TAP_unloadKey(pTapKey, pErrContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);

        /* Free Key */
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
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

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    /* null check already done */
    if (pOpts->pubKeyFile.pBuffer)
        DIGI_FREE((void **)&pOpts->pubKeyFile.pBuffer);

    if (pOpts->privKeyFile.pBuffer)
        DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);

    /* Don't free keyAuthValue TAP_Buffers as they are freed by TAP_UTILS_clearCredentialList */

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
        TPM2_DEBUG_PRINT_1("Failed to get persisted object.");
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
        LOG_ERROR("*****digicert_tpm2_getpersistedobject failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
