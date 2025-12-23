/*
 * tap_nanoroot_example.c
 *
 * Sample code demonstrating the usage of NanoROOT.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#if (defined(__ENABLE_MOCANA_TAP__) && defined(__ENABLE_MOCANA_EXAMPLES__))

/*------------------------------------------------------------------*/
/* Includes for this example
 */

#include <stdio.h>
#include <string.h>

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#include "common/initmocana.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "tap/tap_smp.h"
#include "tap/tap_api.h"
#include "tap/tap_utils.h"
#include "common/debug_console.h"
#include "tap/tap_conf_common.h"
#include "crypto_interface/crypto_interface_sha256.h"
#include "crypto_interface/crypto_interface_sha512.h"
#include "crypto_interface/crypto_interface_rsa.h"
#include "crypto_interface/crypto_interface_ecc.h"
#include "crypto_interface/crypto_interface_qs_sig.h"
#include "asn1/parseasn1.h"
#include "crypto/asn1cert.h"
#include "crypto/pubcrypto_data.h"

/* Message can be at most 511 characters (512 bytes including null terminator) */
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char pMsg[512] = {0}; \
        snprintf(pMsg, sizeof(pMsg), fmt, ##__VA_ARGS__); \
        printf("%s\n", pMsg); \
    } while (0)

/* Message can be at most 511 characters (512 bytes including null terminator) */
#define LOG_ERROR(fmt, ...) \
    do {\
        char pMsg[512] = {0}; \
        snprintf(pMsg, sizeof(pMsg), fmt, ##__VA_ARGS__); \
        printf("ERROR: %s\n", pMsg); \
    } while (0)


#define PRINT_ERR(STATUS, MESSAGE) \
                printf("%s.%d: ERROR! %s, status=%d\n", \
                        __FUNCTION__, __LINE__, MESSAGE, STATUS)

#define PRINT_SUCCESS(MESSAGE)\
                printf("%s.%d: SUCCESS! %s\n", \
                        __FUNCTION__, __LINE__, MESSAGE)

#define PRINT_TEST_HEADER(MESSAGE)\
                DB_PRINT("\n---------- %s ----------\n", MESSAGE)

#define PRINT_TEST_FOOTER(MESSAGE)\
                DB_PRINT("---------- %s ----------\n\n", MESSAGE)


#define NanoROOT_MAX_SEED_LEN 64
#define FILE_NAME_LEN 256
#define MIN_KEY_ID_LEN 9
#define MAX_KEY_ID_LEN 18
#define NanoROOT_CONFIGURATION_FILE "./config/nanoroot_smp.conf"
#define APP_STATE_TAP_INIT      0x00000001
#define R_MAX_LEN  66 /* P-521 max size */
#define BUF_SIZE 256

extern void SERIALQS_setOqsCompatibleFormat(byteBoolean format);

TAP_ErrorContext gErrContext;
ubyte4 gApplicationState = 0x00;

typedef enum {
    NanoROOT_SEAL = 1,
    NanoROOT_UNSEAL,
    NanoROOT_SIGN,
    NanoROOT_VERIFY,
} NanoROOT_operation;

typedef struct {
    byteBoolean exitAfterParse;
    byteBoolean configFileSpecified;
    char configFile[FILE_NAME_LEN];
    ubyte4 configFileLen;
    byteBoolean inputFileSpecified;
    char inputFile[FILE_NAME_LEN];
    ubyte4 inputFileLen;
    byteBoolean outputFileSpecified;
    char outputFile[FILE_NAME_LEN];
    ubyte4 outputFileLen;
    byteBoolean sealOp;
    byteBoolean unsealOp;
    byteBoolean signBufferOp;
    byteBoolean signDigestOp;
    byteBoolean verifyOp;
    NanoROOT_operation opType;
    byteBoolean credentialSpecified;
    char credential[NanoROOT_MAX_SEED_LEN];
    ubyte4 credentialLen;
    char pubKeyFile[FILE_NAME_LEN];
    ubyte4 pubKeyFileLen;
    byteBoolean pubKeyFileSpecified;
    char keyId[MAX_KEY_ID_LEN];
    ubyte4 keyIdLen;
    byteBoolean keyIdSpecified;
    ubyte4 hashType;
    byteBoolean hashTypeSpecified;
} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

MOC_STATIC void printHelp()
{
    LOG_MESSAGE("tap_nanoroot_example: Help Menu");
    LOG_MESSAGE("This utility demonstrates the usage of the TAP APIs to test the NanoROOT SMP Provider.");

    LOG_MESSAGE("\nUsage:");
    LOG_MESSAGE("  --help                  Display this help message");

    LOG_MESSAGE("\nMandatory Options:");
    LOG_MESSAGE("  --config                Full path to the configuration file");
    LOG_MESSAGE("  --infile                Full path to the input file");
    LOG_MESSAGE("                          - Seal:        Reads plaintext data");
    LOG_MESSAGE("                          - Unseal:      Reads encrypted data");
    LOG_MESSAGE("                          - Sign/Verify: Reads data to be signed or verified");

    LOG_MESSAGE("  --outfile               Full path to the output or signature file");
    LOG_MESSAGE("                          - Seal:        Saves encrypted data");
    LOG_MESSAGE("                          - Unseal:      Saves decrypted data");
    LOG_MESSAGE("                          - Sign:        Saves generated signature");
    LOG_MESSAGE("                          - Verify:      Reads signature for verification");

    LOG_MESSAGE("  --keyId                 Hexadecimal key identifier (required for sign/verify operations)");
    LOG_MESSAGE("                          Supported values:");
    LOG_MESSAGE("                            RSA 2K   → 0x100000002");
    LOG_MESSAGE("                            RSA 3K   → 0x100000003");
    LOG_MESSAGE("                            RSA 4K   → 0x100000004");
    LOG_MESSAGE("                            RSA 8K   → 0x100000005");
    LOG_MESSAGE("                            MLDSA44  → 0x200000001");
    LOG_MESSAGE("                            MLDSA65  → 0x200000002");
    LOG_MESSAGE("                            MLDSA87  → 0x200000003");
    LOG_MESSAGE("                            P-256    → 0x300000001");
    LOG_MESSAGE("                            P-384    → 0x300000002");
    LOG_MESSAGE("                            P-521    → 0x300000003");

    LOG_MESSAGE("  --hashType              Hash type required for sign/verify operations");
    LOG_MESSAGE("                          Supported values:");
    LOG_MESSAGE("                            None     → 0 (Use for MLDSA algorithms)");
    LOG_MESSAGE("                            SHA-256  → 1 (Use for RSA 2K, RSA 3K, ECC P-256, ECC P-384)");
    LOG_MESSAGE("                            SHA-512  → 2 (Use for RSA 4K, RSA 8K, ECC P-521)");

    LOG_MESSAGE("  --pubKey                Required for sign/verify operations");
    LOG_MESSAGE("                          - Sign:    Saves public key to the specified file");
    LOG_MESSAGE("                          - Verify:  Reads public key from the specified file");
    LOG_MESSAGE("                          Note: Verification is performed in software and does not require NanoROOT SMP.");

    LOG_MESSAGE("\nOptional:");
    LOG_MESSAGE("  --passphrase            Password used for seal/unseal operations");

    LOG_MESSAGE("\nOperations (exactly one must be specified):");
    LOG_MESSAGE("  --seal                  Encrypt input data using NanoROOT");
    LOG_MESSAGE("  --unseal                Decrypt data using NanoROOT");
    LOG_MESSAGE("  --signBuffer            Sign operation where NanoROOT performs digest and signing");
    LOG_MESSAGE("  --signDigest            Sign operation where digest is computed in software and signed by NanoROOT");
    LOG_MESSAGE("                          Note: signDigest is NOT supported for MLDSA algorithms.");
    LOG_MESSAGE("  --verify                Verify a signature (performed in software)");

    return;
}

MOC_STATIC int validateCmdLineOpts(cmdLineOpts *pOpts)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (!pOpts)
    {
        PRINT_ERR(status, "Invalid input: null command-line options structure.");
        goto exit;
    }

    if (pOpts->configFileSpecified == FALSE)
    {
        PRINT_ERR(status, "Missing required option: specify the NanoROOT configuration file using \"--config\".");
        goto exit;
    }

    if (pOpts->inputFileSpecified == FALSE)
    {
        PRINT_ERR(status, "Missing required option: specify the input file using \"--infile\".");
        goto exit;
    }

    if (pOpts->outputFileSpecified == FALSE)
    {
        PRINT_ERR(status, "Missing required option: specify the output file using \"--outfile\".");
        goto exit;
    }

    if ((pOpts->sealOp + pOpts->unsealOp + pOpts->signBufferOp +
         pOpts->signDigestOp + pOpts->verifyOp) != 1)
    {
        PRINT_ERR(status, "Invalid operation: specify exactly one operation among --seal, --unseal, --signBuffer, --signDigest, or --verify.");
        goto exit;
    }

    if (pOpts->signBufferOp || pOpts->signDigestOp || pOpts->verifyOp)
    {
        if (pOpts->keyIdSpecified == FALSE)
        {
            PRINT_ERR(status, "Missing required option: specify key ID using \"--keyId\" for sign or verify operations.");
            goto exit;
        }
        if (pOpts->pubKeyFileSpecified == FALSE)
        {
            PRINT_ERR(status, "Missing required option: specify the public key file using \"--pubKey\" for sign or verify operations.");
            goto exit;
        }
        if (pOpts->hashTypeSpecified == FALSE)
        {
            PRINT_ERR(status, "Missing required option: specify hash type using \"--hashType\" for sign or verify operations.");
            goto exit;
        }
        if ( !(pOpts->hashType == 0 ||pOpts->hashType == 1 || pOpts->hashType == 2))
        {
            PRINT_ERR(status, "Invalid hashType.");
            goto exit;
        }
    }

    if (pOpts->keyIdSpecified == TRUE && (pOpts->sealOp || pOpts->unsealOp))
    {
        PRINT_ERR(status, "Invalid usage: \"--keyId\" is applicable only for sign or verify operations.");
        goto exit;
    }

    if (pOpts->pubKeyFileSpecified == TRUE && (pOpts->sealOp || pOpts->unsealOp))
    {
        PRINT_ERR(status, "Invalid usage: \"--pubKey\" is applicable only for sign or verify operations.");
        goto exit;
    }

    if (pOpts->credentialSpecified == TRUE &&
        (pOpts->signBufferOp || pOpts->signDigestOp || pOpts->verifyOp))
    {
        PRINT_ERR(status, "Invalid usage: \"--passphrase\" is applicable only for seal or unseal operations.");
        goto exit;
    }

    if (pOpts->hashTypeSpecified == TRUE && (pOpts->sealOp || pOpts->unsealOp))
    {
        PRINT_ERR(status, "Invalid usage: \"--hashType\" is applicable only for sign or verify operations.");
        goto exit;
    }

    status = OK;

exit:
    return status;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
MOC_STATIC MSTATUS parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    MSTATUS status = ERR_INVALID_INPUT;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    size_t len = 0;
    const struct option options[] = {
            {"help", no_argument, NULL, 1},
            {"config", required_argument, NULL, 2},
            {"infile", required_argument, NULL, 3},
            {"outfile", required_argument, NULL, 4},
            {"seal", no_argument, NULL, 5},
            {"unseal", no_argument, NULL, 6},
            {"signBuffer", no_argument, NULL, 7},
            {"signDigest", no_argument, NULL, 8},
            {"verify", no_argument, NULL, 9},
            {"pubKey", required_argument, NULL, 10},
            {"keyId", required_argument, NULL, 11},
            {"passphrase", required_argument, NULL, 12},
            {"hashType", required_argument, NULL, 13},
            {NULL, 0, NULL, 0},
    };

    if (!pOpts || !argv || (0 == argc))
    {
        LOG_ERROR("Invalid parameters.");
        goto exit;
    }

    while (TRUE)
    {
        c = getopt_long(argc, argv, optstring, options, &options_index);
        if ((-1 == c))
            break;

        /* Add validation for optarg before using it */
        if ((c >= 2 && c <= 4) || (c >= 10 && c <= 13))
        {
            if (!optarg)
            {
                LOG_ERROR("Missing argument for option");
                goto exit;
            }
            /* Use strnlen for safety - different limits for different option types */
            if (c == 12)  /* passphrase */
            {
                len = strnlen(optarg, NanoROOT_MAX_SEED_LEN);
            }
            else if (c == 11)  /* keyId */
            {
                len = strnlen(optarg, MAX_KEY_ID_LEN);
            }
            else if (c == 13)  /* hashType - numeric argument */
            {
                len = strnlen(optarg, 16);  /* Reasonable limit for numeric string */
            }
            else  /* config, infile, outfile, pubKey - file paths */
            {
                len = strnlen(optarg, FILE_NAME_LEN);
            }
            
            if (len == 0)
            {
                LOG_ERROR("Empty argument for option");
                goto exit;
            }
        }

        switch (c)
        {
        case 1:
            {
                printHelp();
                pOpts->exitAfterParse = TRUE;
            }
            break;

        case 2:
            {
                len = strnlen(optarg, FILE_NAME_LEN);
                if (len >= FILE_NAME_LEN)
                {
                    LOG_ERROR("Config file name too long. Max size: %d bytes", FILE_NAME_LEN - 1);
                    goto exit;
                }
                if (len == 0 || optarg[0] == '-')
                {
                    LOG_ERROR("--config Config file name not specified");
                    goto exit;
                }
                pOpts->configFileSpecified = TRUE;
                strncpy(pOpts->configFile, optarg, FILE_NAME_LEN - 1);
                pOpts->configFile[FILE_NAME_LEN - 1] = '\0';
                pOpts->configFileLen = len;
                LOG_MESSAGE("NanoROOT config file name: %s", pOpts->configFile);
            }
            break;

        case 3:
            {
                len = strnlen(optarg, FILE_NAME_LEN);
                if (len >= FILE_NAME_LEN)
                {
                    LOG_ERROR("Input file name too long. Max size: %d bytes", FILE_NAME_LEN - 1);
                    goto exit;
                }
                if (len == 0 || optarg[0] == '-')
                {
                    LOG_ERROR("--infile input file name not specified");
                    goto exit;
                }
                pOpts->inputFileSpecified = TRUE;
                strncpy(pOpts->inputFile, optarg, FILE_NAME_LEN - 1);
                pOpts->inputFile[FILE_NAME_LEN - 1] = '\0';
                pOpts->inputFileLen = len;
                LOG_MESSAGE("Input file name: %s", pOpts->inputFile);
            }
            break;

        case 4:
            {
                len = strnlen(optarg, FILE_NAME_LEN);
                if (len >= FILE_NAME_LEN)
                {
                    LOG_ERROR("Output file name too long. Max size: %d bytes", FILE_NAME_LEN - 1);
                    goto exit;
                }
                if (len == 0 || optarg[0] == '-')
                {
                    LOG_ERROR("--outfile output file name not specified");
                    goto exit;
                }
                pOpts->outputFileSpecified = TRUE;
                strncpy(pOpts->outputFile, optarg, FILE_NAME_LEN - 1);
                pOpts->outputFile[FILE_NAME_LEN - 1] = '\0';
                pOpts->outputFileLen = len;
                LOG_MESSAGE("Output file name: %s", pOpts->outputFile);
            }
            break;

        case 5:
            {
                pOpts->sealOp = TRUE;
                pOpts->opType = NanoROOT_SEAL;
            }
            break;

        case 6:
            {
                pOpts->unsealOp = TRUE;
                pOpts->opType = NanoROOT_UNSEAL;
            }
            break;

        case 7:
            {
                pOpts->signBufferOp = TRUE;
                pOpts->opType = NanoROOT_SIGN;
            }
            break;

        case 8:
            {
                pOpts->signDigestOp = TRUE;
                pOpts->opType = NanoROOT_SIGN;
            }
            break;

        case 9:
            {
                pOpts->verifyOp = TRUE;
                pOpts->opType = NanoROOT_VERIFY;
            }
            break;

        case 10:
            {
                len = strnlen(optarg, FILE_NAME_LEN);
                if (len >= FILE_NAME_LEN)
                {
                    LOG_ERROR("Public key file name too long. Max size: %d bytes", FILE_NAME_LEN - 1);
                    goto exit;
                }
                if (len == 0 || optarg[0] == '-')
                {
                    LOG_ERROR("--pubKey Public Key file name not specified");
                    goto exit;
                }
                pOpts->pubKeyFileSpecified = TRUE;
                strncpy(pOpts->pubKeyFile, optarg, FILE_NAME_LEN - 1);
                pOpts->pubKeyFile[FILE_NAME_LEN - 1] = '\0';
                pOpts->pubKeyFileLen = len;
                LOG_MESSAGE("Public key file name: %s", pOpts->pubKeyFile);
            }
            break;

        case 11:
            {
                len = strnlen(optarg, MAX_KEY_ID_LEN);
                if (len >= MAX_KEY_ID_LEN || len < MIN_KEY_ID_LEN)
                {
                    LOG_ERROR("keyId not valid. Min size: %d bytes. Max size: %d bytes",
                            MIN_KEY_ID_LEN, MAX_KEY_ID_LEN - 1);
                    goto exit;
                }
                if (optarg[0] == '-')
                {
                    LOG_ERROR("--keyId Key Id not specified");
                    goto exit;
                }
                pOpts->keyIdSpecified = TRUE;
                strncpy(pOpts->keyId, optarg, MAX_KEY_ID_LEN - 1);
                pOpts->keyId[MAX_KEY_ID_LEN - 1] = '\0';
                pOpts->keyIdLen = len;
                LOG_MESSAGE("key Id: %s", pOpts->keyId);
            }
            break;

        case 12:
            {
                len = strnlen(optarg, NanoROOT_MAX_SEED_LEN);
                if (len >= NanoROOT_MAX_SEED_LEN)
                {
                    LOG_ERROR("Credential too long. Max length: %d bytes", NanoROOT_MAX_SEED_LEN - 1);
                    goto exit;
                }
                if (len == 0 || optarg[0] == '-')
                {
                    LOG_ERROR("--passphrase credential not specified");
                    goto exit;
                }
                pOpts->credentialSpecified = TRUE;
                strncpy(pOpts->credential, optarg, NanoROOT_MAX_SEED_LEN - 1);
                pOpts->credential[NanoROOT_MAX_SEED_LEN - 1] = '\0';
                pOpts->credentialLen = len;
            }
            break;

        case 13:
            {
                pOpts->hashTypeSpecified = TRUE;
                pOpts->hashType = (ubyte4)strtoul(optarg, NULL, 10);
                LOG_MESSAGE("hashType : %d", pOpts->hashType);
            }
            break;

        default:
            printHelp();
            pOpts->exitAfterParse = TRUE;
        }
    }
    status = OK;

exit:
    if(OK != status)
    {
        printHelp();
        pOpts->exitAfterParse = TRUE;
    }
    return status;
}
#endif

/* initTapModuleCtx
 * Function to initialize a SE/SMP 
 *
 * Demonstrates usage of - 
 *  TAP_initContext
 */
MSTATUS initTapModuleCtx(TAP_Module *pModule, TAP_Context **ppTapContext)
{
    MSTATUS status = OK;

    if (NULL == pModule || NULL == ppTapContext)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "NULL input arguments received");
        goto exit;
    }
   
    status = TAP_initContext(pModule, NULL, NULL, ppTapContext, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed initializing context for TAP Module");
        goto exit;
    }

    if (NULL == *ppTapContext)
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Error initializing tap context");
        goto exit;
    }
    PRINT_SUCCESS("TAP Module initialized");

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* uninitTapModuleCtx
 * Function to uninitialize a SE/SMP 
 *
 * Demonstrates usage of - 
 *  TAP_uninitContext
 */
MSTATUS uninitTapModuleCtx(TAP_Context **ppTapContext)
{
    MSTATUS status = OK;

    /* uninitialize context */
    status = TAP_uninitContext(ppTapContext, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_uninitContext call failed");
    }
    else
    {
        PRINT_SUCCESS("TAP_Context uninitialized");
    }
    if (*ppTapContext)
    {
        status = MOC_FREE((void **)ppTapContext);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed releasing memory for ppTAPContext");
        }
        else
        {
            PRINT_SUCCESS("Released memory from ppTAPContext");
        }
    }

    return status;
}

/* Configuration initialization */
MSTATUS initTapConfigInfo(TAP_ConfigInfo* pConfigInfo, cmdLineOpts *pOpts)
{
    MSTATUS status = OK;
    char *pConfigFile = NULL;

    if (NULL == pConfigInfo || NULL == pOpts)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "NULL parameter pConfigInfo");
        goto exit;
    }

    if (TRUE == pOpts->configFileSpecified)
    {
       pConfigFile = pOpts->configFile;
    }
    else
    {
        pConfigFile = NanoROOT_CONFIGURATION_FILE;
    }

    status = TAP_readConfigFile(pConfigFile, &pConfigInfo->configInfo,
                            pOpts->configFileSpecified);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to read config file");
        goto exit;
    }
    pConfigInfo->provider = TAP_PROVIDER_NANOROOT;

exit:
    return status;
}

/* EXAMPLE_init
 * Function to perform initialization for this example.
 * Initializes top MOCANA and TAP layer.
 */
MSTATUS 
EXAMPLE_init(cmdLineOpts *pOpts)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = {0, NULL};

    if (NULL == pOpts)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "NULL parameter pOpts");
        goto exit;
    }

    /* Initialize using default setup by passing in NULL */
    status = MOCANA_initialize(NULL, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Mocana Init failed");
        goto exit;
    }
    PRINT_SUCCESS("MOCANA Initialized successfully!");

    status = MOC_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        PRINT_ERR(status, "Failed allocating memory for config list");
        goto exit;
    }
    configInfoList.count = 1;

    status = initTapConfigInfo(configInfoList.pConfig, pOpts);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to retrieved a module configuration");
        goto exit;
    }
    PRINT_SUCCESS("Module configured");

    DB_PRINT("Calling TAP_init ...\n");
    status = TAP_init(&configInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_init failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP Init completed successfully");

exit:
    if (NULL != configInfoList.pConfig)
    {
        if (NULL != configInfoList.pConfig[0].configInfo.pBuffer)
            TAP_UTILS_freeBuffer(&(configInfoList.pConfig[0].configInfo));
        MOC_FREE((void **) &(configInfoList.pConfig));
    }

    return status;
}

/* EXAMPLE_uninit
 * Uninitialize the top MOCANA and TAP layer,
 * that was initialized in EXAMPLE_init()
 * Demonstrates usage of - 
 *  TAP_uninit
 *  MOCANA_free
 */
MSTATUS EXAMPLE_uninit(byteBoolean isTapInit)
{
    MSTATUS status = OK;
    
    if (isTapInit)
    {
        status = TAP_uninit(&gErrContext);
    }

    MOCANA_free(NULL);

    return status;
}

MSTATUS getHashAlgo(ubyte4 hashType, ubyte4 *pHashAlgo)
{
    if(pHashAlgo == NULL)
    {
        return ERR_NULL_POINTER;
    }

    switch(hashType)
    {
        case 0:
            *pHashAlgo = ht_none;
            DB_PRINT("Hash Algo : ht_none\n");
            break;

        case 1:
            *pHashAlgo = ht_sha256;
            DB_PRINT("Hash Algo : ht_sha256\n");
            break;

        case 2:
            *pHashAlgo = ht_sha512;
            DB_PRINT("Hash Algo : ht_sha512\n");
            break;

        default:
            return ERR_INVALID_ARG;
    }

    return OK;
}

MSTATUS getSigScheme(TAP_KEY_ALGORITHM keyAlgorithm, ubyte4 hashType, TAP_SIG_SCHEME *pSigScheme)
{
    if(pSigScheme == NULL)
    {
        return ERR_NULL_POINTER;
    }

    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            {
                switch(hashType)
                {
                    case 1:
                        *pSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                        break;

                    case 2:
                        *pSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                        break;

                    default:
                        return ERR_TAP_INVALID_SCHEME;

                }
            }
            break;

        case TAP_KEY_ALGORITHM_ECC:
            {
                switch(hashType)
                {
                    case 1:
                        *pSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                        break;

                    case 2:
                        *pSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                        break;

                    default:
                        return ERR_TAP_INVALID_SCHEME;

                }
            }
            break;

        case TAP_KEY_ALGORITHM_MLDSA:
            {
                if(hashType == 0)
                {
                    *pSigScheme = TAP_SIG_SCHEME_NONE;
                }
                else
                {
                    return ERR_TAP_INVALID_SCHEME;
                }
            }
            break;

        default:
            return ERR_TAP_INVALID_ALGORITHM;
    }
    return OK;
}

/* sealData
 * Demonstrates usage of 
 *  TAP_sealWithTrustedData
 */
MSTATUS sealData(   TAP_Context*        pTapContext,
                    TAP_Buffer*         pSealedData,
                    TAP_Buffer*         pDataToSeal,
                    TAP_SealAttributes* pSealAttributes,
                    TAP_OBJECT_TYPE     objectType
                )
{
    MSTATUS status = OK;
#ifdef DUMP_DATA
    ubyte4 iter = 0;
#endif

    status = TAP_sealWithTrustedData(pTapContext, NULL, 
                                     objectType, NULL,
                                     NULL, pSealAttributes,
                                     pDataToSeal, pSealedData, 
                                     &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Seal operation using "
                          "TAP_sealWithTrustedData failed");
        goto exit;
    }

    if( NULL == pSealedData->pBuffer || 0 >= pSealedData->bufferLen )
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Sealed data is empty");
        goto exit;
    }

    PRINT_SUCCESS("Seal With Trusted Data completed");

#ifdef DUMP_DATA
    DB_PRINT("Sealed Data size = %d\nSealed data buffer:-\n\t",
             pSealedData->bufferLen, pSealedData->pBuffer);
    for (iter = 0; iter < pSealedData->bufferLen; iter++) 
    {
        if (0 == iter%32)
            DB_PRINT("\n\t");
        DB_PRINT("%02x ",pSealedData->pBuffer[iter]);
    }
    DB_PRINT("\n");
#endif


exit:
    return status;
}


/*------------------------------------------------------------------*/

/* unsealData
 * Demonstrates usage of 
 *  TAP_unsealWithTrustedData
 */
MSTATUS unsealData( TAP_Context*        pTapContext,
                    TAP_Buffer*         pSealedData,
                    TAP_Buffer*         pUnsealedData,
                    TAP_SealAttributes* pSealAttributes,
                    TAP_OBJECT_TYPE     objectType
                  )
{
    MSTATUS status = OK;
#ifdef DUMP_DATA
    ubyte4 iter = 0;
#endif

    status = TAP_unsealWithTrustedData(pTapContext, NULL, 
                                       objectType , NULL,
                                       pSealAttributes, pSealedData, 
                                       pUnsealedData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_unsealWithTrustedData failed");
        goto exit;
    }

    if( NULL == pUnsealedData->pBuffer || 0 >= pUnsealedData->bufferLen )
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Unsealed data is empty");
        goto exit;
    }

    DB_PRINT("UnSeal With Trusted Data OK.\n");

#ifdef DUMP_DATA
    DB_PRINT("Unsealed Data size = %d\nUnsealed data buffer:-\n\t",
             pUnsealedData->bufferLen, pUnsealedData->pBuffer);
    for (iter = 0; iter < pUnsealedData->bufferLen; iter++) 
    {
        if (0 == iter%32)
            DB_PRINT("\n\t");
        DB_PRINT("%02x ", pUnsealedData->pBuffer[iter]);
    }
    DB_PRINT("\n");
#endif

exit:
    return status;
}

MOC_STATIC MSTATUS genCredAttrList(ubyte *pCredentials, int credentialLen, TAP_AttributeList **ppAttributeList)
{
    MSTATUS status = OK;
    TAP_AttributeList *pAttributeList = NULL;
    TAP_Attribute *pAttribute = NULL;
    TAP_Credential *pCredential = NULL;

    if(NULL == pCredentials || NULL == ppAttributeList)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "genCredAttrList() failed");
        return status;
    }

    if(0 > credentialLen)
    {
        status = ERR_INVALID_INPUT;
        PRINT_ERR(status, "genCredAttrList() failed");
        return status;
    }
    /* Allocate Attribute list */
    status = MOC_CALLOC((void **)&pAttributeList, 1, sizeof(*pAttributeList));
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate single element of TAP_BUFFER */
    status = MOC_CALLOC((void **)&pAttribute, 1, sizeof(*pAttribute));
    if (OK != status)
    {
        goto exit;
    }

    pAttributeList->listLen = 1; 
    pAttributeList->pAttributeList = pAttribute;

    pAttribute->type = TAP_ATTR_CREDENTIAL;
    pAttribute->length = sizeof(TAP_Credential);

    status = MOC_CALLOC((void **)&pCredential, 1, sizeof(*pCredential));
    if (OK != status)
    {
        goto exit;
    }

    status = MOC_CALLOC((void **)&pCredential->credentialData.pBuffer, 1, credentialLen+1);
    if (OK != status)
    {
        goto exit;
    }

    pAttribute->pStructOfType = pCredential;
    pCredential->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
    pCredential->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
    pCredential->credentialContext = TAP_CREDENTIAL_CONTEXT_USER;
    pCredential->credentialData.bufferLen = credentialLen;
    status = MOC_MEMCPY(pCredential->credentialData.pBuffer, pCredentials, credentialLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to copy pCredentials");
        goto exit;
    }

    *ppAttributeList = pAttributeList;

exit:
    if (OK != status)
    {
        if (pCredential)
        {
            if (pCredential->credentialData.pBuffer)
            {
                MOC_MEMSET_FREE(&pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);
            }
        }

        if (pAttribute)
            MOC_FREE((void **)&pAttribute);

        if (pAttributeList)
            MOC_FREE((void **)&pAttributeList);
    }

    return status;
}

MOC_STATIC void freeAttrList(TAP_AttributeList *pAttributeList)
{
    ubyte4 count = 0;
    TAP_Attribute *pAttr = NULL;
    TAP_Credential *pCredential = NULL;

    if(NULL == pAttributeList)
        return;

    for(count = 0; count < pAttributeList->listLen; count++)
    {
        pAttr = &pAttributeList->pAttributeList[count];
        if(pAttr)
        {
            if (TAP_ATTR_CREDENTIAL == pAttr->type)
            {
                pCredential = pAttr->pStructOfType;
                if (pCredential->credentialData.pBuffer)
                {
                    MOC_MEMSET_FREE(&pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);
                }
                MOC_FREE((void **)&pCredential);
            }

            MOC_FREE((void **)&pAttr);
        }
    }
    MOC_FREE((void **)&pAttributeList);
    return;
}

MSTATUS publishRSAPublicKey(TAP_Key *pTapKey, char * pubKeyFile, AsymmetricKey *pPubKey)
{
    MSTATUS status = OK;
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;

    if(NULL == pTapKey || NULL == pubKeyFile || NULL == pPubKey)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "publishRSAPublicKey() failed");
        return status;
    }

    /* We will need a new Asymmetric key containing a public RSA key */
    status = CRYPTO_createRSAKey(pPubKey, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_createRSAKey() failed");
        goto exit;
    }
    /* set it in the new public key */
    status = CRYPTO_INTERFACE_RSA_setPublicKeyData(pPubKey->key.pRSA,
                    pTapKey->keyData.publicKey.publicKey.rsaKey.pExponent,
                    pTapKey->keyData.publicKey.publicKey.rsaKey.exponentLen,
                    pTapKey->keyData.publicKey.publicKey.rsaKey.pModulus,
                    pTapKey->keyData.publicKey.publicKey.rsaKey.modulusLen, NULL);

    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_INTERFACE_RSA_setPublicKeyData() failed");
        goto exit;
    }

    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey(pPubKey, publicKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_serializeAsymKey() failed");
        goto exit;
    }

    /* And write it to a file */
    status = MOCANA_writeFile(pubKeyFile, pKeyBuff, keyBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "MOCANA_writeFile()  public key failed");
        goto exit;
    }

exit:
    if (NULL != pKeyBuff)
    {
        (void) MOC_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }
    return status;
}

MSTATUS verifyRSASignature(AsymmetricKey *pPubKey,
                           TAP_Buffer *pDataToVerify,
                           TAP_Buffer *pSignature,
                           ubyte4 hashAlgo,
                           intBoolean *pIsSigValid
                           )
{
    MSTATUS status = OK;
    *pIsSigValid = FALSE;

    if(NULL == pPubKey || NULL == pDataToVerify || NULL == pSignature || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyRSASignature() failed");
        return status;
    }

    if( !(hashAlgo == ht_sha256 || hashAlgo == ht_sha512))
    {
        status = ERR_INVALID_INPUT;
        PRINT_ERR(status, "verifyRSASignature() failed");
        return status;
    }

    DB_PRINT("Verifying the created signature...\n");
    status = CRYPTO_INTERFACE_RSA_verifyData(pPubKey->key.pRSA, pDataToVerify->pBuffer, pDataToVerify->bufferLen, hashAlgo,
                                                 pSignature->pBuffer, pSignature->bufferLen, pIsSigValid, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_RSA_verifyData() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_RSA_verifyData()");

    if(TRUE == *pIsSigValid)
    {
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else
    {
        status = ERR_RSA_BAD_SIGNATURE;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }

exit:

    return status;
}

MSTATUS publishECCPublicKey(TAP_Key *pTapKey, char * pubKeyFile, AsymmetricKey *pPubKey)
{
    MSTATUS status = OK;
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;
    ubyte *pEccKeyBuff = NULL;
    ubyte4 eccKeyBuffLen = 0;

    if(NULL == pTapKey || NULL == pubKeyFile || NULL == pPubKey)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "publishECCPublicKey() failed");
        return status;
    }

    status = CRYPTO_createECCKeyEx(pPubKey, pTapKey->keyData.publicKey.publicKey.eccKey.curveId);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_createECCKeyEx() failed");
        goto exit;
    }

    /* Prepare raw ECC public into ASN1 format */
    /* ECC Public key length = 1 byte for "0x04" + pubX len + pubY len */
    eccKeyBuffLen = 1 + pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen + pTapKey->keyData.publicKey.publicKey.eccKey.pubYLen;

    status = MOC_CALLOC((void **)&pEccKeyBuff, 1, eccKeyBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to allocate memory for pEccKeyBuff.");
        goto exit;
    }
    if (OK != MOC_MEMSET(pEccKeyBuff, 0x04, 1))
    {
        PRINT_ERR(status, "Failed to memset 0x04");
        goto exit;
    }

    status = MOC_MEMCPY(pEccKeyBuff + 1 , pTapKey->keyData.publicKey.publicKey.eccKey.pPubX,
                pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to copy pPubX");
        goto exit;
    }
    status = MOC_MEMCPY(pEccKeyBuff + 1 +  pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen,
                pTapKey->keyData.publicKey.publicKey.eccKey.pPubY,
                pTapKey->keyData.publicKey.publicKey.eccKey.pubYLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to copy pPubY");
        goto exit;
    }

    /* set it in the new public key */
    CRYPTO_INTERFACE_EC_setKeyParametersAux (pPubKey->key.pECC, pEccKeyBuff , eccKeyBuffLen , NULL, 0);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_INTERFACE_EC_setKeyParametersAux() failed");
        goto exit;
    }

    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey(pPubKey, publicKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_serializeAsymKey() failed");
        goto exit;
    }

    /* And write it to a file */
    status = MOCANA_writeFile(pubKeyFile, pKeyBuff, keyBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "MOCANA_writeFile()  public key failed");
        goto exit;
    }

exit:
    if (NULL != pEccKeyBuff)
    {
        (void) MOC_MEMSET_FREE(&pEccKeyBuff, eccKeyBuffLen);
    }
    if (NULL != pKeyBuff)
    {
        (void) MOC_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }
    return status;
}

MSTATUS verifyECCSignature(AsymmetricKey *pPubKey,
                           TAP_Buffer *pDataToSign,
                           TAP_ECCSignature *pSignature,
                           TAP_Buffer *pSigOut,
                           ubyte4 hashAlgo,
                           intBoolean *pIsSigValid
                           )
{
    MSTATUS status = OK;
    *pIsSigValid = FALSE;
    ubyte *pEccSigBuff = NULL;
    ubyte4 eccSigBuffLen = 0;
    ubyte4 vfy = -1;

    if(NULL == pPubKey || NULL == pDataToSign || NULL == pSignature || NULL == pSigOut || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyECCSignature() failed");
        return status;
    }

    /* Prepare signature to write to output file */
    eccSigBuffLen = pSignature->rDataLen + pSignature->sDataLen;
    status = MOC_CALLOC((void **)&pEccSigBuff, 1, eccSigBuffLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to allocate memory for pEccSigBuff.");
        goto exit;
    }
    status = MOC_MEMCPY(pEccSigBuff, pSignature->pRData, pSignature->rDataLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to copy pRData");
        goto exit;
    }
    status = MOC_MEMCPY(pEccSigBuff + pSignature->rDataLen, pSignature->pSData, pSignature->sDataLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to copy pSData");
        goto exit;
    }
    /* save raw ecc signature */
    pSigOut->pBuffer = pEccSigBuff;
    pSigOut->bufferLen = eccSigBuffLen;

    /* Verify the signature with the public key */
    DB_PRINT("Verifying the generated signature...\n");
    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (pPubKey->key.pECC, hashAlgo, pDataToSign->pBuffer,
                    pDataToSign->bufferLen, pEccSigBuff, eccSigBuffLen, &vfy, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_ECDSA_verifyMessageExt() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_ECDSA_verifyMessageExt()");
    if (0 == vfy)
    {
        *pIsSigValid = TRUE;
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else 
    {
        status = ERR_ECDSA_VERIFICATION_FAILED;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }
    MOC_FREE((void **)&pSigOut->pBuffer);
    pSigOut->pBuffer = NULL;
    pSigOut->bufferLen = 0;

    status = ASN1CERT_encodeRS( pSignature->pRData, pSignature->rDataLen,
                                pSignature->pSData, pSignature->sDataLen,
                                &pSigOut->pBuffer, &pSigOut->bufferLen);
    if (OK != status)
    {
        PRINT_ERR(status, "ASN1CERT_encodeRS() failed");
    }

exit:

    MOC_FREE((void **)&pSignature->pRData);
    MOC_FREE((void **)&pSignature->pSData);
    if(OK != status)
    {
        MOC_FREE((void **)&pSigOut->pBuffer);
    }
    return status;
}

MSTATUS publishMLDSAPublicKey(TAP_Key *pTapKey,
                              char * pubKeyFile,
                              QS_CTX **ppCtx
                             )
{
    MSTATUS status = OK;
    QS_CTX *pCtx = NULL;
    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = 0;
    AsymmetricKey pubKey = {0};

    if(NULL == pTapKey || NULL == pubKeyFile || NULL == ppCtx)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "publishMLDSAPublicKey() failed");
        return status;
    }

    status = CRYPTO_INTERFACE_QS_newCtx(&pCtx, pTapKey->keyData.publicKey.publicKey.mldsaKey.qsAlg);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_INTERFACE_QS_newCtx() failed");
        goto exit;
    }
    status = CRYPTO_INTERFACE_QS_setPublicKey(pCtx,
                                pTapKey->keyData.publicKey.publicKey.mldsaKey.pPublicKey,
                                pTapKey->keyData.publicKey.publicKey.mldsaKey.publicKeyLen);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_INTERFACE_QS_setPublicKey() failed");
        goto exit;
    }

    pubKey.type = akt_qs;
    pubKey.pQsCtx = pCtx;

    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey(&pubKey, publicKeyPem, &pKeyBuffer, &keyBufferLen);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_serializeAsymKey() failed");
        goto exit;
    }

    /* And write it to a file */
    status = MOCANA_writeFile(pubKeyFile, pKeyBuffer, keyBufferLen);
    if (OK != status)
    {
        PRINT_ERR(status, "MOCANA_writeFile()  public key failed");
        goto exit;
    }
    *ppCtx = pCtx;

exit:
    if (NULL != pKeyBuffer)
    {
        (void) MOC_MEMSET_FREE(&pKeyBuffer, keyBufferLen);
    }
    return status;
}

MSTATUS verifyMLDSASignature(QS_CTX *pCtx,
                           TAP_Buffer *pDataToSign,
                           TAP_Buffer *pSignature,
                           intBoolean *pIsSigValid
                           )
{
    MSTATUS status = OK;
    ubyte4 verifyStatus = 0;
    *pIsSigValid = FALSE;

    if(NULL == pCtx || NULL == pDataToSign || NULL == pSignature || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyMLDSASignature() failed");
        return status;
    }

    DB_PRINT("Verifying the created signature...\n");
    status = CRYPTO_INTERFACE_QS_SIG_verify(pCtx, pDataToSign->pBuffer, pDataToSign->bufferLen,
                            pSignature->pBuffer, pSignature->bufferLen, &verifyStatus);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_QS_SIG_verify() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_QS_SIG_verify()");
    if(0 == verifyStatus)
    {
        *pIsSigValid = TRUE;
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else 
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }

exit:
    return status;
}
/*------------------------------------------------------------------*/
/* testAsymSignVerify
 * Flow - 
 *  Create a digest from plain text
 *  Create signature using incoming key and digest created above
 *  Verify the signature against the digest
 * Demonstrates usage of  
 *  TAP_asymSign
 */
MSTATUS testAsymSignVerify( TAP_Key *pTapKey,
                            ubyte4 hashType,
                            TAP_KEY_ALGORITHM keyAlgo,
                            byteBoolean isDigest,
                            TAP_Buffer *pDataToSign,
                            TAP_Buffer *pSignature,
                            char * pubKeyFile
                          )
{
    MSTATUS status = OK;
    TAP_Signature tapSignature = {0};
    byteBoolean isDataNotDigest = FALSE;
    TAP_Attribute attributes = {
        TAP_ATTR_IS_DATA_NOT_DIGEST, sizeof(isDataNotDigest), &isDataNotDigest
    };
    TAP_AttributeList operAttributes = {1, &attributes};
    intBoolean isSigValid = FALSE;
    ubyte digestBuf[SHA512_RESULT_SIZE] = {0};
    TAP_Buffer digestBuffer =
                            {
                                .pBuffer    = digestBuf,
                                .bufferLen  = SHA512_RESULT_SIZE,
                            };

    hwAccelDescr hwAccelCtx = 0;
    TAP_EntityCredentialList*   pEntityCredentials = NULL;
    AsymmetricKey pubKey = {0};
    QS_CTX *pCtx = NULL;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    ubyte4 hashAlgo = 0;

    if(NULL == pTapKey || NULL == pDataToSign || NULL == pSignature || NULL == pubKeyFile)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "testAsymSignVerify() failed");
        return status;
    }
    if( 0 == keyAlgo)
    {
        status = ERR_INVALID_INPUT;
        PRINT_ERR(status, "testAsymSignVerify() failed");
        return status;
    }

    status = getHashAlgo(hashType, &hashAlgo);
    if (OK != status)
    {
        DB_PRINT("Invalid hashType %d provided, status %d\n", hashType, status);
        goto exit;
    }

    status = getSigScheme(keyAlgo, hashType, &sigScheme);
    if (OK != status)
    {
        DB_PRINT("Invalid keyAlgo %d hashType %d provided, status %d\n", keyAlgo, hashType, status);
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    if(TRUE == isDigest)
    {
        /* Digest the input data */
        if(sigScheme == TAP_SIG_SCHEME_PKCS1_5_SHA256 || sigScheme == TAP_SIG_SCHEME_ECDSA_SHA256)
        {
            status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) pDataToSign->pBuffer,
                                pDataToSign->bufferLen, digestBuffer.pBuffer);
            if (OK != status)
            {
                DB_PRINT("SHA256_completeDigest failed with status %d\n", status);
                goto exit;
            }
            digestBuffer.bufferLen = SHA256_RESULT_SIZE;
        }
        else if(sigScheme == TAP_SIG_SCHEME_PKCS1_5_SHA512 || sigScheme ==  TAP_SIG_SCHEME_ECDSA_SHA512)
        {
            status = CRYPTO_INTERFACE_SHA512_completeDigest(MOC_HASH(hwAccelCtx) pDataToSign->pBuffer,
                                pDataToSign->bufferLen, digestBuffer.pBuffer);
            if (OK != status)
            {
                DB_PRINT("SHA512_completeDigest failed with status %d\n", status);
                goto exit;
            }
            digestBuffer.bufferLen = SHA512_RESULT_SIZE;
        }

        DB_PRINT("Signing digest using generated asymmetric key...\n");
        /* Sign the digest */
        isDataNotDigest = FALSE;
        status = TAP_asymSign(pTapKey, pEntityCredentials, &operAttributes,
                              sigScheme, isDataNotDigest, &digestBuffer,
                              &tapSignature, &gErrContext);
    }
    else
    {
        /* Sign the data buffer */
        isDataNotDigest = TRUE;
        DB_PRINT("Signing data buffer using generated asymmetric key...\n");
        status = TAP_asymSign(pTapKey, pEntityCredentials, &operAttributes,
                              sigScheme, isDataNotDigest, pDataToSign,
                              &tapSignature, &gErrContext);
    }
    if (OK != status)
    {
        PRINT_ERR(status, "Asymmetric Sign operation using TAP_asymSign failed");
        goto exit;
    }
    PRINT_SUCCESS("Asymmetric Sign operation using TAP_asymSign done");


    /*********** Publish public key and verify signature ***********/
    switch(keyAlgo)
    {
        case TAP_KEY_ALGORITHM_RSA:
            {
                status = publishRSAPublicKey(pTapKey, pubKeyFile, &pubKey);
                if (OK != status)
                {
                    PRINT_ERR(status,"publishRSAPublicKey() failed");
                    goto exit;
                }

                pSignature->pBuffer = tapSignature.signature.rsaSignature.pSignature;
                pSignature->bufferLen = tapSignature.signature.rsaSignature.signatureLen;
                tapSignature.signature.rsaSignature.pSignature = NULL;
                tapSignature.signature.rsaSignature.signatureLen = 0;
                
                status = verifyRSASignature(&pubKey, pDataToSign, pSignature, hashAlgo, &isSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status,"verifyRSASignature() failed");
                    goto exit;
                }
            }
            break;

        case TAP_KEY_ALGORITHM_ECC:
            {
                status = publishECCPublicKey(pTapKey, pubKeyFile, &pubKey);
                if (OK != status)
                {
                    PRINT_ERR(status,"publishECCPublicKey() failed");
                    goto exit;
                }

                status = verifyECCSignature(&pubKey, pDataToSign, &tapSignature.signature.eccSignature,  pSignature, hashAlgo, &isSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status,"verifyECCSignature() failed");
                    goto exit;
                }
            }
            break;

        case TAP_KEY_ALGORITHM_MLDSA:
            {
                status = publishMLDSAPublicKey(pTapKey, pubKeyFile, &pCtx);
                if (OK != status)
                {
                    PRINT_ERR(status,"publishMLDSAPublicKey() failed");
                    goto exit;
                }

                pSignature->pBuffer = tapSignature.signature.mldsaSignature.pSignature;
                pSignature->bufferLen = tapSignature.signature.mldsaSignature.signatureLen;
                tapSignature.signature.mldsaSignature.pSignature = NULL;
                tapSignature.signature.mldsaSignature.signatureLen = 0;

                status = verifyMLDSASignature(pCtx, pDataToSign, pSignature, &isSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status,"verifyMLDSASignature() failed");
                    goto exit;
                }
            }
            break;

        default:
                status = ERR_TAP_INVALID_ALGORITHM;
                PRINT_ERR(status, "Invalid TAP Algo");
                goto exit;
    }
    /* Check the verification result */
    if (TRUE != isSigValid)
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }
    PRINT_SUCCESS("Signature verification completed successfully");

exit:
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    return status;
}

/* createKeyFromId
 * Demonstrates usage of
 *  TAP_importKeyFromID
 */
static MSTATUS createKeyFromId(TAP_Context *pTapContext,
                               TAP_KEY_ALGORITHM keyAlgo,
                               TAP_Buffer *pKey,
                               TAP_Key **ppTapKey
                               )
{
    MSTATUS status = ERR_INVALID_INPUT;
    TAP_KeyInfo keyInfo = {0};
    keyInfo.keyAlgorithm = keyAlgo;

    status = TAP_importKeyFromID(pTapContext, NULL, &keyInfo,
                       pKey, NULL, NULL, ppTapKey, &gErrContext);

    return status;
}

MSTATUS getKeyId(char *pKeyId, TAP_Buffer *pKeyIdBuf)
{
    MSTATUS status = OK;
    ubyte* idBuf = pKeyIdBuf->pBuffer;
    char *endptr;

    if(NULL == pKeyId || NULL == pKeyIdBuf)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getKeyId() failed");
        return status;
    }

    ubyte8 hexValue = strtoull((const char*)pKeyId, &endptr, 16);
    if (*endptr != '\0') {
        PRINT_ERR(status, "Error: Invalid hex string.");
        return ERR_INVALID_INPUT;
    }
    DB_PRINT("Hex String: %s\n", pKeyId);
    DB_PRINT("Parsed Value (decimal): %llu\n", (unsigned long long)hexValue);
    DB_PRINT("Parsed Value (hex): 0x%llX\n", (unsigned long long)hexValue);

   for (int i = 0; i < sizeof(ubyte8); i++) {
        idBuf[i] = (hexValue >> (8 * i)) & 0xFF;
    }

    return OK;
}
/*------------------------------------------------------------------*/
/* signData
 * Executes a series of key related TAP methods,
 * for Asymmetric key of usage type GENERAL
 */
MSTATUS signData(   TAP_Context *pTapContext,
                    TAP_Buffer *pDataToSign,
                    TAP_Buffer *pSignature,
                    char *pubKeyFile,
                    byteBoolean isDigest,
                    ubyte4 hashType,
                    TAP_Buffer *pKeyId
                )
{
    MSTATUS status = OK;
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_UNDEFINED;
    TAP_KEY_SIZE keySize = 0;
    ubyte4 subKeyType = 0;
    TAP_Key *pTapKey = NULL;

    if(NULL == pTapContext || NULL == pDataToSign || NULL == pSignature || NULL == pubKeyFile || NULL ==pKeyId)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "signData() failed");
        return status;
    }

    status = TAP_NanoROOT_parse_algorithm_info(*(ubyte8*)pKeyId->pBuffer, &keyAlgorithm, &keySize, &subKeyType);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unsupported Alogrithm status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    DB_PRINT("%s.%d Creating key....\n", __FUNCTION__, __LINE__);
    status = createKeyFromId(pTapContext, keyAlgorithm, pKeyId, &pTapKey);
    if (OK != status)
    {
        PRINT_ERR(status, "Key generation failed");
        goto exit;
    }
    PRINT_SUCCESS("Asymmetric Key Generated using TAP_importKeyFromID");

    DB_PRINT("%s.%d Executing sign+verify using the above generated key...\n",
            __FUNCTION__, __LINE__);
    status = testAsymSignVerify(pTapKey, hashType, keyAlgorithm,
                isDigest, pDataToSign, pSignature, pubKeyFile);
    if (OK != status)
    {
        PRINT_ERR(status, "testAsymSignVerify() failed ");
        goto exit;
    }

exit:

    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        if (OK != TAP_unloadKey(pTapKey, &gErrContext))
        {
            LOG_ERROR("TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        if (OK != TAP_freeKey(&pTapKey))
        {
            LOG_ERROR("TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}

/*------------------------------------------------------------------*/
/* verifyRSASignFromFile
 * Flow -
 *  Create a digest from plain text
 *  Verify the signature against the digest
 */
MSTATUS verifyRSASignFromFile( TAP_Buffer *pDataToVerify,
                        TAP_Buffer *pSignature,
                        TAP_Buffer *pPubKeyData,
                        ubyte4 hashAlgo,
                        intBoolean *pIsSigValid
                      )
{
    MSTATUS status = OK;
    AsymmetricKey asymPubKey = {0};
    hwAccelDescr hwAccelCtx = 0;
    *pIsSigValid = FALSE;

    if(NULL == pDataToVerify || NULL == pSignature || NULL == pPubKeyData || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyRSASignFromFile() failed");
        return status;
    }

    if( !(hashAlgo == ht_sha256 || hashAlgo == ht_sha512))
    {
        status = ERR_INVALID_INPUT;
        PRINT_ERR(status, "verifyRSASignature() failed");
        return status;
    }

    status = CRYPTO_deserializeAsymKey(pPubKeyData->pBuffer, pPubKeyData->bufferLen, NULL, &asymPubKey);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_deserializeAsymKey() failed");
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_RSA_verifyData(MOC_HASH(hwAccelCtx) asymPubKey.key.pRSA, pDataToVerify->pBuffer,
                pDataToVerify->bufferLen, hashAlgo, pSignature->pBuffer, pSignature->bufferLen, pIsSigValid, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_RSA_verifyData() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_RSA_verifyData()");

    /* Check the verification result */
    if (TRUE == *pIsSigValid)
    {
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else
    {
        status = ERR_RSA_BAD_SIGNATURE;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&asymPubKey, NULL);
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*------------------------------------------------------------------*/
/* verifyECCSignFromFile
 * Flow -
 *  Create a digest from plain text
 *  Verify the signature against the digest
 */
MSTATUS verifyECCSignFromFile( TAP_Buffer *pDataToVerify,
                        TAP_Buffer *pSignature,
                        TAP_Buffer *pPubKeyData,
                        ubyte4 hashAlgo,
                        intBoolean *pIsSigValid
                      )
{
    MSTATUS status = OK;
    AsymmetricKey asymPubKey = {0};
    hwAccelDescr hwAccelCtx = 0;
    ubyte *pSig = NULL;
    ubyte4 elementLen;
    ubyte4 vfy = -1;

    if(NULL == pDataToVerify || NULL == pSignature || NULL == pPubKeyData || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyECCSignFromFile() failed");
        return status;
    }

    *pIsSigValid = FALSE;

    status = CRYPTO_deserializeAsymKey(pPubKeyData->pBuffer, pPubKeyData->bufferLen, NULL, &asymPubKey);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_deserializeAsymKey() failed");
        goto exit;
    }

    /* signature for ECDSA is a SEQUENCE consisting of two INTEGERs,
     * extract R and S values to byte strings */
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(asymPubKey.key.pECC, &elementLen);
    if (OK != status)
        goto exit;

    /* Allocate signature buffer, space for r and s
     */
    status = MOC_MALLOC((void **) &pSig, 2 * elementLen);
    if (OK != status)
        goto exit;

    /* decode asn1 format signature into the signature buffer */
    status = X509_decodeRS(pSignature->pBuffer, pSignature->bufferLen, pSig, pSig + elementLen, elementLen);
    if (OK != status)
        goto exit;

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    /* Verify the digestInfo.*/
    DB_PRINT("Verifying the signature...\n");
    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (asymPubKey.key.pECC, hashAlgo, pDataToVerify->pBuffer,
                    pDataToVerify->bufferLen, pSig, 2 * elementLen, &vfy, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_ECDSA_verifyMessageExt() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_ECDSA_verifyMessageExt()");
    if (0 == vfy)
    {
        *pIsSigValid = TRUE;
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else 
    {
        status = ERR_ECDSA_VERIFICATION_FAILED;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }

exit:

    if (NULL != pSig)
    {
        MOC_FREE((void **) &pSig);
    }
    (void) CRYPTO_uninitAsymmetricKey(&asymPubKey, NULL);
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    return status;
}

/*------------------------------------------------------------------*/
/* verifyMLDSASignFromFile
 * Flow -
 *  Create a digest from plain text
 *  Verify the signature against the digest
 */
MSTATUS verifyMLDSASignFromFile( TAP_Buffer *pDataToVerify,
                        TAP_Buffer *pSignature,
                        TAP_Buffer *pPubKeyData,
                        ubyte4 subKeyType,
                        ubyte4 hashType,
                        intBoolean *pIsSigValid
                      )
{
    MSTATUS status = ERR_BAD_KEY_BLOB;
    AsymmetricKey asymPubKey = {0};
    ubyte4 verifyStatus = 0;
    *pIsSigValid = FALSE;

    if(NULL == pDataToVerify || NULL == pSignature || NULL == pPubKeyData || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyMLDSASignFromFile() failed");
        return status;
    }

    if(0 != hashType)
    {
        status = ERR_TAP_INVALID_SCHEME;
        DB_PRINT("For MLDSA hashType should be 0\n");
        goto exit;
    }

    SERIALQS_setOqsCompatibleFormat(FALSE);

    status = CRYPTO_deserializeAsymKey(pPubKeyData->pBuffer, pPubKeyData->bufferLen, NULL, &asymPubKey);
    if (OK != status)
    {
        PRINT_ERR(status, "CRYPTO_deserializeAsymKey() failed");
        goto exit;
    }

    /* Verify the signature .*/
    DB_PRINT("Verifying the signature...\n");
    status = CRYPTO_INTERFACE_QS_SIG_verify(asymPubKey.pQsCtx, pDataToVerify->pBuffer, pDataToVerify->bufferLen,
                            pSignature->pBuffer, pSignature->bufferLen, &verifyStatus);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using CRYPTO_INTERFACE_QS_SIG_verify() failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using CRYPTO_INTERFACE_QS_SIG_verify()");
    if(0 == verifyStatus)
    {
        *pIsSigValid = TRUE;
        PRINT_SUCCESS("Signature verification PASS.");
    }
    else 
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&asymPubKey, NULL);
    return status;
}
/*------------------------------------------------------------------*/
/* verifyData
 * Executes a series of key related TAP methods,
 * for Asymmetric key of usage type GENERAL
 */
MSTATUS verifyData( TAP_Buffer *pDataToVerify,
                    char *signFile,
                    char *pubKeyFile,
                    ubyte4 hashType,
                    TAP_Buffer *pKeyId,
                    intBoolean *pIsSigValid
                )
{
    MSTATUS status = OK;
    TAP_Buffer signBuf = {0};
    TAP_Buffer pubKeyData = {0};
    TAP_KEY_ALGORITHM keyAlgo = TAP_KEY_ALGORITHM_UNDEFINED;
    TAP_KEY_SIZE keySize = 0;
    ubyte4 subKeyType = 0;
    *pIsSigValid = FALSE;
    ubyte4 hashAlgo = 0;

    if(NULL == pDataToVerify || NULL == signFile || NULL == pubKeyFile || NULL == pKeyId || NULL == pIsSigValid)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "verifyData() failed");
        return status;
    }

    status = MOCANA_readFile(signFile, &signBuf.pBuffer, &signBuf.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to read signature file : %s, status : %d", signFile, status);
        goto exit;
    }

    status = MOCANA_readFile(pubKeyFile, &pubKeyData.pBuffer, &pubKeyData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to read public key file : %s, status : %d", pubKeyFile, status);
        goto exit;
    }

    status = TAP_NanoROOT_parse_algorithm_info(*(ubyte8*)pKeyId->pBuffer, &keyAlgo, &keySize, &subKeyType);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unsupported Alogrithm status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = getHashAlgo(hashType, &hashAlgo);
    if (OK != status)
    {
        DB_PRINT("Invalid hashType %d provided, status %d\n", hashType, status);
        goto exit;
    }

    DB_PRINT("%s.%d Executing sign verification operation using the provided key...\n",
            __FUNCTION__, __LINE__);

    switch(keyAlgo)
    {
        case TAP_KEY_ALGORITHM_RSA:
            {
                status = verifyRSASignFromFile(pDataToVerify, &signBuf, &pubKeyData, hashAlgo, pIsSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status, "verifyRSASignFromFile() failed ");
                    goto exit;
                }
            }
            break;

        case TAP_KEY_ALGORITHM_ECC:
            {
                status = verifyECCSignFromFile(pDataToVerify, &signBuf, &pubKeyData, hashAlgo, pIsSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status, "verifyECCSignFromFile() failed ");
                    goto exit;
                }
            }
            break;

        case TAP_KEY_ALGORITHM_MLDSA:
            {
                status = verifyMLDSASignFromFile(pDataToVerify, &signBuf, &pubKeyData, subKeyType, hashType, pIsSigValid);
                if (OK != status)
                {
                    PRINT_ERR(status, "verifyMLDSASignFromFile() failed ");
                    goto exit;
                }
            }
            break;

        default:
                status = ERR_TAP_INVALID_ALGORITHM;
                PRINT_ERR(status, "Invalid TAP Algo");
                goto exit;
    }

exit:

    MOC_FREE((void **)&signBuf.pBuffer);
    MOC_FREE((void **)&pubKeyData.pBuffer);
    return status;
}

MSTATUS executeOptions(TAP_Context *pTapContext, cmdLineOpts *pOpts)
{
    MSTATUS status = OK;
    TAP_Buffer inputData = {0};
    TAP_Buffer outputData = {0};
    TAP_ConfigInfo tapConfig = {0};
    TAP_AttributeList *pAttributeList = NULL;
    TAP_OBJECT_TYPE objectType = TAP_OBJECT_TYPE_UNDEFINED;
    TAP_Buffer keyId = {0};
    ubyte idBuf[sizeof(ubyte8)] = {0};
    intBoolean isValidSign;

    if (NULL == pTapContext || NULL == pOpts)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "Invalid parameters.");
        return status;
    }

    status = MOCANA_readFile(pOpts->configFile, &tapConfig.configInfo.pBuffer,
                             &tapConfig.configInfo.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to read NanoROOT config file : %s, status : %d", pOpts->configFile, status);
        goto exit;
    }
    tapConfig.provider = TAP_PROVIDER_NANOROOT;

    status = MOCANA_readFile(pOpts->inputFile, &inputData.pBuffer, &inputData.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to read input file : %s, status : %d", pOpts->inputFile, status);
        goto exit;
    }

    if(pOpts->credentialSpecified)
    {
        status = genCredAttrList((ubyte *)pOpts->credential, pOpts->credentialLen, &pAttributeList);
        if (OK != status)
        {
            PRINT_ERR(status, "Attribute List generation failed");
            goto exit;
        }
    }

    if(pOpts->keyIdSpecified)
    {
        keyId.pBuffer = idBuf;
        keyId.bufferLen = sizeof(idBuf);
        status = getKeyId(pOpts->keyId, &keyId);
        if (OK != status)
        {
            goto exit;
        }
    }

    switch(pOpts->opType)
    {
        case NanoROOT_SEAL:
            {
                status = sealData(pTapContext, &outputData, &inputData, pAttributeList, objectType);
                if (OK != status)
                {
                    PRINT_ERR(status, "sealData failed");
                    goto exit;
                }
            }
            break;


        case NanoROOT_UNSEAL:
            {
                status = unsealData(pTapContext, &inputData, &outputData, pAttributeList, objectType);
                if (OK != status)
                {
                    PRINT_ERR(status, "unsealData failed");
                    goto exit;
                }
            }
            break;

        case NanoROOT_SIGN:
            {
                status = signData(pTapContext, &inputData, &outputData, pOpts->pubKeyFile, pOpts->signDigestOp, pOpts->hashType, &keyId);
                if (OK != status)
                {
                    PRINT_ERR(status, "signData failed");
                    goto exit;
                }
            }
            break;

        case NanoROOT_VERIFY:
            {
                status = verifyData(&inputData, pOpts->outputFile, pOpts->pubKeyFile, pOpts->hashType, &keyId, &isValidSign);
                if (OK != status)
                {
                    PRINT_ERR(status, "verifyData failed");
                    goto exit;
                }
                if(isValidSign == TRUE)
                {
                    PRINT_SUCCESS("Signature verification pass.");
                }
                else
                {
                    LOG_ERROR("Signature verification failed\n");
                }
            }
            break;

        default:
            LOG_ERROR("Operation not supported\n");
            goto exit;
    }

    if(pOpts->opType == NanoROOT_SEAL || pOpts->opType == NanoROOT_UNSEAL || pOpts->opType == NanoROOT_SIGN)
    {
        status = MOCANA_writeFile(pOpts->outputFile, outputData.pBuffer, outputData.bufferLen);
        if (OK != status)
        {
            LOG_ERROR("Failed to write output file : %s, status : %d", pOpts->outputFile, status);
            goto exit;
        }
    }

exit:

    freeAttrList(pAttributeList);
    MOC_FREE((void **)&outputData.pBuffer);
    MOC_FREE((void **)&inputData.pBuffer);
    MOC_FREE((void **)&tapConfig.configInfo.pBuffer);
    return status;
}

int main(int argc, char **argv)
{
    MSTATUS status = OK;
    cmdLineOpts *pOpts = NULL;
    TAP_Module *pModule = NULL;
    TAP_ModuleList *pModuleList = NULL;
    TAP_Context *pTapContext = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    if (NULL == platCmdLineParser)
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "No command line parser available for this platform");
        goto exit;
    }

    status = MOC_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts));
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    status = platCmdLineParser(pOpts, argc, argv);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to parse command line options.");
        goto exit;
    }
    
    if (pOpts->exitAfterParse)
    {
        status = OK;
        goto exit;
    }
    status = validateCmdLineOpts(pOpts);
    if (OK != status)
    {
        PRINT_ERR(status, "Cmd line options validation failed");
        printHelp();
        goto exit;
    }

    PRINT_TEST_HEADER("Mocana TAP initialization");
    status = EXAMPLE_init(pOpts);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to initialize TAP");
        goto exit;
    }
    PRINT_TEST_FOOTER("Mocana TAP initialization");
    gApplicationState |= APP_STATE_TAP_INIT;

    /* Get Modules list */
    PRINT_TEST_HEADER("Get list of Providers and Modules");

    status = MOC_CALLOC((void **)&pModuleList, 1, sizeof(TAP_ModuleList));
    if (OK != status)
    {
        PRINT_ERR(status, "Error allocating memory for TAP_ModuleList");    
        goto exit;
    }
    status = TAP_getModuleList(NULL, TAP_PROVIDER_NANOROOT, NULL,
                               pModuleList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to fetch list of SMPs");
        goto exit;
    }
    PRINT_TEST_FOOTER("Get list of Providers and Modules");

    pModule = (TAP_Module *)&(pModuleList->pModuleList[0]);

    status = initTapModuleCtx(pModule, &pTapContext);
    if ( (OK != status) || (NULL==pTapContext) )
    {
        PRINT_ERR(status, "Failed initializing module");
        goto exit;
    }
    PRINT_SUCCESS("Module Initialized ...");

    status = executeOptions(pTapContext, pOpts);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed execution for module");
        goto exit;
    }

exit:
    MOC_FREE((void **)&pOpts);
    uninitTapModuleCtx(&pTapContext);
    EXAMPLE_uninit((gApplicationState & APP_STATE_TAP_INIT) ? TRUE : FALSE);
    gApplicationState &= ~APP_STATE_TAP_INIT;

    if (NULL != pModuleList)
    {
        TAP_freeModuleList(pModuleList);  
        MOC_FREE((void**)&pModuleList);
    }

    return status;
}

#endif  /* defined(__ENABLE_MOCANA_TAP__)) && defined(__ENABLE_MOCANA_EXAMPLES__) */
