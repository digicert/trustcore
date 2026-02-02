/*
 * fapi2_ekdumper.c
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
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../../common/moptions.h"
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/mfmgmt.h"
#include "../fapi2/fapi2.h"
#include "../tap_serialize_tpm2.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../../common/mcmdline.h"
#endif

#define SERVER_NAME_LEN 256
#define DEFAULT_SERVER_NAME "/dev/tpm0"
#define DEFAULT_EK_CERT_FILE "ek_cert.der"
#define DEFAULT_EK_PUBKEY_FILE "ek_pub_key.txt"

#define TPM2_DEBUG_PRINT_NO_ARGS(fmt) \
    do {\
        DB_PRINT("\n%s() - %d: "fmt"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("\n%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#ifdef __RTOS_WIN32__
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        sprintf_s(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#else
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        snprintf(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#endif

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

#define PRINT_TO_FILE(pFile, fmt, ...)\
    do {\
        LOG_MESSAGE(fmt, ##__VA_ARGS__);\
        if (OK != FMGMT_fprintf (pFile, fmt, ##__VA_ARGS__))\
        {\
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to write to text file");\
            goto exit;\
        }\
    }while (0)

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean pcrIndexesSpecified;
    ubyte4 pcrIndex;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("fapi2_quote: Help Menu\n");
    LOG_MESSAGE("This tool uses the TPM2 FAPI directly to create a quote."
            " Use digicert_tpm2_quote if available. For use only for Demo purposes."
            " Signature Scheme and Hash algorithm used will be the same ones used during key creation.\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu");
    LOG_MESSAGE("           --s=[TPM server name or module path]");
    LOG_MESSAGE("                   Specify the server name such as localhost or\n"
            "                       module path such as /dev/tpm0. If not specified, /dev/tpm0 will be used.");
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
static int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {"s", required_argument, NULL, 2},
            {NULL, 0, NULL, 0},
    };

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameters.");
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
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->serverName[pOpts->serverNameLen] = '\0';
            TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
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
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    ContextIsTpmProvisionedOut isTpmProvisioned = { 0 };
    ContextGetPrimaryObjectNameIn ekGetHandleIn = { 0 };
    ContextGetPrimaryObjectNameOut ekHandle = { 0 };
    AsymGetPublicKeyIn ekGetPublicKeyIn = { 0 };
    AsymGetPublicKeyOut ekGetPublicKeyOut = { 0 };
    FileDescriptor pPublicKeyFile = NULL;
    int i = 0;
    NVReadOpIn nvReadIn = { 0 };
    NVReadOpOut nvReadOut = { 0 };
    MSTATUS status = ERR_GENERAL;
    ContextSetHierarchyAuthIn setHierarchyAuth = { 0 };

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    if (!pOpts->serverNameSpecified)
    {
        pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)DEFAULT_SERVER_NAME);
        DIGI_MEMCPY((void *)pOpts->serverName, DEFAULT_SERVER_NAME, pOpts->serverNameLen);
    }

    status = FMGMT_fopen (DEFAULT_EK_PUBKEY_FILE, "wb", &pPublicKeyFile);
    if (OK != status)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to open file for public key");
        goto exit;
    }

    rc = FAPI2_CONTEXT_init(&pCtx, pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, 0, 10, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to create FAPI2 context.");
        goto exit;
    }

    rc = FAPI2_CONTEXT_isTpmProvisioned(pCtx, &isTpmProvisioned);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed isTpmProvisioned.");
        goto exit;
    }

    if (!isTpmProvisioned.provisioned)
    {
        LOG_ERROR("TPM is not provisioned. Please Clear TPM and re-run this tool.");
        goto exit;
    }

    setHierarchyAuth.forceUseOwnerAuth = TRUE;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &setHierarchyAuth);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed set hierarchy auth.");
        goto exit;
    }
    ekGetHandleIn.persistentHandle = FAPI2_RH_EK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &ekGetHandleIn, &ekHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to get EK handle from context.");
        goto exit;
    }

    ekGetPublicKeyIn.keyName = ekHandle.objName;
    rc = FAPI2_ASYM_getPublicKey(pCtx, &ekGetPublicKeyIn, &ekGetPublicKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to get EK public key.");
        goto exit;
    }

    switch (ekGetPublicKeyOut.keyAlg)
    {
    case TPM2_ALG_RSA:
        LOG_MESSAGE("EK is an RSA Key.");
        PRINT_TO_FILE(pPublicKeyFile, "\n*****RSA PUBLIC KEY *******\n");
        for (i = 0; i < ekGetPublicKeyOut.publicKey.rsaPublic.size; i++)
            PRINT_TO_FILE(pPublicKeyFile, "0x%x ", ekGetPublicKeyOut.publicKey.rsaPublic.buffer[i]);

        nvReadIn.nvIndex = 0x01C00002;
        rc = FAPI2_NV_readOp(pCtx, &nvReadIn, &nvReadOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to read NV index for RSA key.");
            goto exit;
        }

        status = DIGICERT_writeFile(DEFAULT_EK_CERT_FILE,
                nvReadOut.readData.buffer, nvReadOut.readData.size);
        if (OK != status)
        {
            LOG_ERROR("Error writing RSA certificate to file, status = %d\n", status);
            goto exit;
        }
        LOG_MESSAGE("\nDone writing RSA Public Key and Cert\n");
        break;
    case TPM2_ALG_ECC:
        LOG_MESSAGE("EK is an ECC Key.");
        PRINT_TO_FILE(pPublicKeyFile, "\n*****ECC PUBLIC KEY *******\n");
        PRINT_TO_FILE(pPublicKeyFile, "Point X: ");
        for (i = 0; i < ekGetPublicKeyOut.publicKey.eccPublic.x.size; i++)
            PRINT_TO_FILE(pPublicKeyFile, "0x%x ", ekGetPublicKeyOut.publicKey.eccPublic.x.buffer[i]);

        PRINT_TO_FILE(pPublicKeyFile, "\nPoint Y: ");
        for (i = 0; i < ekGetPublicKeyOut.publicKey.eccPublic.y.size; i++)
            PRINT_TO_FILE(pPublicKeyFile, "0x%x ", ekGetPublicKeyOut.publicKey.eccPublic.y.buffer[i]);

        nvReadIn.nvIndex = 0x01C0000A;
        rc = FAPI2_NV_readOp(pCtx, &nvReadIn, &nvReadOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to read NV index for ECC key.");
            goto exit;
        }

        status = DIGICERT_writeFile(DEFAULT_EK_CERT_FILE,
                nvReadOut.readData.buffer, nvReadOut.readData.size);
        if (OK != status)
        {
            LOG_ERROR("Error writing ECC certificate to file, status = %d\n", status);
            goto exit;
        }
        LOG_MESSAGE("\nDone writing ECC Public Key and Cert\n");

        break;
    default:
        LOG_ERROR("Unknown EK type.");
        goto exit;
        break;
    }

    rc = TSS2_RC_SUCCESS;
    retval = 0;
exit:
    if (pCtx)
    {
        rc = FAPI2_CONTEXT_uninit(&pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to free FAPI2 context");
        }
    }
    if(NULL != pPublicKeyFile)
    {
        FMGMT_fclose (&pPublicKeyFile);
    }

    return retval;
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
        TPM2_DEBUG_PRINT_NO_ARGS("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to get quote.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****fapi2 quote tool failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
