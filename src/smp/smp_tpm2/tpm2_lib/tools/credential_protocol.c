/*
 * credential_protocol.c
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
#include "../fapi2/fapi2.h"
#include "tpm2_server_helpers.h"

#ifdef __RTOS_WIN32__
#include "../../../../common/mcmdline.h"
#endif

/*
 * Default to linux build
 */
#if  !defined(__RTOS_LINUX__) && !defined (__RTOS_OSX__) && !defined(__RTOS_WIN32__)
#define __RTOS_LINUX__
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#define TPM2_DEBUG_PRINT_NO_ARGS(fmt) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
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

#define SERVER_NAME_LEN 256
#define DEFAULT_SERVER_NAME "/dev/tpm0"

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
    ubyte4 serverPort;
} cmdLineOpts;

typedef struct {
    cmdLineOpts options;

    struct {
        FAPI2_CONTEXT *pCtx;
        AsymmetricKey akPublicKey;
        AsymmetricKey rotPublicKey;
        CredentialGetCsrAttrIn csrAttrIn;
        CredentialGetCsrAttrOut csrAttrOut;
        CredentialUnwrapSecretOut recoveredCredential;
    } ClientReturn;

    struct {
        TPM2B_DATA keyCredential;
        ubyte *pBase64Credential;
        ubyte4 credentialLen;
    } ServerReturn;

} application_context_t;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("Credential protection example: Help Menu\n");
    LOG_MESSAGE("This is an example to show the working of the TPM2.0 privacy CA"
            " credential protection protocol in action. A client TPM provides "
            "the required information for the server to provide a credential. The server"
            "creates and wraps the credential to a client TPM. The client TPM then unwraps"
            " the credential. The credential in this example is an AES key.\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu");
    LOG_MESSAGE("           --s=[TPM server name or module path]");
    LOG_MESSAGE("                   Optional. Specify the server name such as localhost or\n"
            "                       module path such as /dev/tpm0. If not specified, /dev/tpm0 or localhost will be used.");
    LOG_MESSAGE("           --p=[TPM server port]");
    LOG_MESSAGE("                   Optional. Port at which the TPM server is listening.");
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
            {"p", required_argument, NULL, 3},
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
            if ((pOpts->serverNameLen == 0) || ('-' == optarg[0]))
            {
                LOG_ERROR("Invalid server name specified");
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
        case 3:
            if (('\0' == optarg[0]) || ('-' == optarg[0]))
            {
                LOG_ERROR("Invalid port number specified");
                goto exit;
            }
            pOpts->serverPort = strtoul(optarg, NULL, 0);
            if ((pOpts->serverPort < 1) || (pOpts->serverPort > 65535))
            {
                LOG_ERROR("Invalid port number specified. Port must be between 1 and 65535");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Server Port: %u", pOpts->serverPort);
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

/*
 * Convert TPM public RSA key into AsymmetricKey
 */
static MSTATUS tpm2RsaPublicToAsymmetricKey(AsymmetricKey *pKey,
        ubyte4 exponent,
        TPM2B_PUBLIC_KEY_RSA *pRsa)
{
    MSTATUS status = ERR_GENERAL;

    if (OK != CRYPTO_initAsymmetricKey(pKey))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to init asym key");
        goto exit;
    }

    pKey->type = akt_rsa;

    if (OK != RSA_createKey(&(pKey->key.pRSA)))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to create RSA public key");
        goto exit;
    }

    if (OK != RSA_setPublicKeyParameters(pKey->key.pRSA, exponent,
            pRsa->buffer,
            pRsa->size,
            NULL))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to set rsa key public parameters");
        goto exit;
    }

    status = OK;
exit:
    return status;
}
#ifdef __ENABLE_DIGICERT_ECC__
/*
 * Convert TPM2 ECC public Key to Asymmetric Keys
 */
static MSTATUS tpm2EccPublicToAsymmetricKey(AsymmetricKey *pKey,
        PEllipticCurvePtr pECcurve,
        TPMS_ECC_POINT *pEcc)
{

    MSTATUS status = ERR_GENERAL;

    if (OK != CRYPTO_initAsymmetricKey(pKey))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to init asym key");
        goto exit;
    }

    pKey->type = akt_ecc;

    if (OK != EC_newKey(pECcurve, &pKey->key.pECC))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("\nFailed to create ECC key in software\n");
        goto exit;
    }

    PRIMEFIELD_setToByteString(pECcurve->pPF, pKey->key.pECC->Qx,
            pEcc->x.buffer,
            pEcc->x.size);
    PRIMEFIELD_setToByteString(pECcurve->pPF, pKey->key.pECC->Qy,
            pEcc->y.buffer,
            pEcc->y.size);

    status = OK;
exit:
    return status;
}
#endif

static MSTATUS handleToAsymmetricKey(FAPI2_CONTEXT *pCtx,
        TPM2B_NAME *pHandle,
        AsymmetricKey *pKey,
#ifdef __ENABLE_DIGICERT_ECC__
        PEllipticCurvePtr pECcurve,
#endif
        ubyte4 exponent
)
{
    MSTATUS status = ERR_INTERNAL_ERROR;
    AsymGetPublicKeyIn getPubKeyIn = { 0 };
    AsymGetPublicKeyOut pubKey = { 0 };

    getPubKeyIn.keyName = *pHandle;
    if (TSS2_RC_SUCCESS != FAPI2_ASYM_getPublicKey(pCtx,
            &getPubKeyIn, &pubKey))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("\nFailed to get public Key\n");
        goto exit;
    }

    switch (pubKey.keyAlg)
    {
    case TPM2_ALG_RSA:
        if (OK != (status = tpm2RsaPublicToAsymmetricKey(pKey, exponent,
                &pubKey.publicKey.rsaPublic)))
        {
            goto exit;
        }
        break;
#ifdef __ENABLE_DIGICERT_ECC__
    case TPM2_ALG_ECC:
        if (OK != (status = tpm2EccPublicToAsymmetricKey(pKey, pECcurve,
                &pubKey.publicKey.eccPublic)))
        {
            goto exit;
        }
        break;
#endif
    default:
        TPM2_DEBUG_PRINT_NO_ARGS("\nInvalid key type!\n");
        goto exit;
    }
    status = OK;
exit:
    return status;
}

static MSTATUS clientTpmGetCsrInfo(application_context_t *pAppCtx)
{
    MSTATUS status = ERR_GENERAL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    ContextIsTpmProvisionedOut isTpmProvisioned = { 0 };
    ContextSetHierarchyAuthIn setHierarchyAuth = { 0 };

    cmdLineOpts *pOpts = NULL;
    typedef struct {
        ContextGetPrimaryObjectNameIn getHandleIn;
        ContextGetPrimaryObjectNameOut ekHandle;
        ContextGetPrimaryObjectNameOut akHandle;
        AsymCreateKeyIn createAkIn;
        AsymCreateKeyOut akInfo;
        AsymGetPublicKeyIn getPublicKeyIn;
        AsymGetPublicKeyOut ekPublicKey;
        AsymGetPublicKeyOut akPublicKey;
    } local_context_t;

    local_context_t *pLocals = NULL;

    if (!pAppCtx || !pAppCtx->options.serverNameSpecified)
    {
        status = ERR_INTERNAL_ERROR;
        TPM2_DEBUG_PRINT_NO_ARGS("Dev Error. Invalid app context, or server name not present");
        goto exit;
    }

    pOpts = &(pAppCtx->options);

    rc = FAPI2_CONTEXT_init(&pCtx, pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, pOpts->serverPort, 3, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to initialize context with TPM. Is server/device name correct?");
        goto exit;
    }

    setHierarchyAuth.forceUseEndorsementAuth = TRUE;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &setHierarchyAuth);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to set endorsement hierarchy password.");
        goto exit;
    }

    pAppCtx->ClientReturn.pCtx = pCtx;

    rc = FAPI2_CONTEXT_isTpmProvisioned(pCtx, &isTpmProvisioned);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to verify if TPM is provisioned. TPM must be provisioned"
                " and operational.");
        goto exit;
    }

    if (!isTpmProvisioned.provisioned)
    {
        LOG_ERROR("TPM is not provisioned.");
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pLocals, 1, sizeof(*pLocals));
    if (OK != status)
    {
        LOG_ERROR("Memory allocation failure, %d", status);
        goto exit;
    }

    /*
     * Get Primary EK handle
     */
    pLocals->getHandleIn.persistentHandle = FAPI2_RH_EK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &pLocals->getHandleIn,
            &pLocals->ekHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to get EK handle, 0x%x", (unsigned int)rc);
        goto exit;
    }

    /*
     * Get AK handle at FAPI2_RH_EK + 1. If one does not exist, create a temp AK.
     */
    pLocals->getHandleIn.persistentHandle = FAPI2_RH_EK + 1;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &pLocals->getHandleIn,
            &pLocals->akHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
#ifdef __ENABLE_DIGICERT_ECC__
        LOG_MESSAGE("No AK at 0x%x, Creating Temp AK", (unsigned int)(pLocals->getHandleIn.persistentHandle));
        pLocals->createAkIn.keyAlg = TPM2_ALG_ECC;
        pLocals->createAkIn.keyInfo.eccInfo.curveID = TPM2_ECC_NIST_P256;
        pLocals->createAkIn.keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
        pLocals->createAkIn.keyInfo.eccInfo.scheme = TPM2_ALG_ECDSA;
#else
        /* FIXME */
        LOG_MESSAGE("No AK at 0x%x, ECC not supported, Fix this!!!", (unsigned int)(pLocals->getHandleIn.persistentHandle));
        rc = TSS2_BASE_RC_NOT_IMPLEMENTED;
        goto exit;
#endif
        rc = FAPI2_ASYM_createAsymKey(pCtx, &pLocals->createAkIn, &pLocals->akInfo);
        if (TSS2_RC_SUCCESS != rc)
        {
            LOG_ERROR("Failed to create AK. rc = 0x%x", (unsigned int)rc);
            goto exit;
        }

        pLocals->akHandle.objName = pLocals->akInfo.keyName;
    }

    pAppCtx->ClientReturn.csrAttrIn.decryptKey = pLocals->ekHandle.objName;
    pAppCtx->ClientReturn.csrAttrIn.activateKey = pLocals->akHandle.objName;

    rc = FAPI2_CREDENTIAL_getCSRAttr(pCtx, &pAppCtx->ClientReturn.csrAttrIn,
            &pAppCtx->ClientReturn.csrAttrOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to get CSR attributes, 0x%x", (unsigned int)rc);
        goto exit;
    }

    /*
     * From here on, this is extra work specific to this example. A server may perform
     * the equivalent operation using different methods.
     */
    status = handleToAsymmetricKey(pCtx, &pLocals->ekHandle.objName,
            &pAppCtx->ClientReturn.rotPublicKey,
#ifdef __ENABLE_DIGICERT_ECC__
            /* TODO: FIX ME, hardcoded to EC 256 keys. */
            EC_P256,
#endif
            0x10001);
    if (OK != status)
    {
        LOG_ERROR("Failed to create AsymmetricKey for EK, %d", status);
        goto exit;
    }

    status = handleToAsymmetricKey(pCtx, &pLocals->akHandle.objName,
            &pAppCtx->ClientReturn.akPublicKey,
#ifdef __ENABLE_DIGICERT_ECC__
            /* TODO: FIX ME, hardcoded to EC 256 keys. */
            EC_P256,
#endif
            0x10001);
    if (OK != status)
    {
        LOG_ERROR("Failed to create AsymmetricKey for AK, %d", status);
        goto exit;
    }

    status = OK;
exit:
    if (pLocals)
        shredMemory((ubyte **)&pLocals, sizeof(*pLocals), TRUE);

    return status;
}

static MSTATUS serverGetWrappedCredential(application_context_t *pAppCtx)
{
    MSTATUS status = ERR_GENERAL;

    if (!pAppCtx)
    {
        status = ERR_INTERNAL_ERROR;
        TPM2_DEBUG_PRINT_NO_ARGS("Dev Error. Invalid app context.");
        goto exit;
    }

    /*
     * Generate 41 byte random number as credential to be wrapped. This size
     * is arbitrary. It will typically be the size of an AES key(16 bytes).
     */
    pAppCtx->ServerReturn.keyCredential.size = 32;
    status = RANDOM_numberGenerator(g_pRandomContext,
            (ubyte *)pAppCtx->ServerReturn.keyCredential.buffer,
            pAppCtx->ServerReturn.keyCredential.size);
    if (OK != status)
    {
        LOG_ERROR("Failed to generate random number. error=%d", status);
        goto exit;
    }

    status = SMP_TPM2_wrapCredentialSecret(&(pAppCtx->ClientReturn.akPublicKey),
            &(pAppCtx->ClientReturn.rotPublicKey),
            pAppCtx->ClientReturn.csrAttrOut.pBase64Blob,
            pAppCtx->ClientReturn.csrAttrOut.blobLen,
            pAppCtx->ServerReturn.keyCredential.buffer,
            pAppCtx->ServerReturn.keyCredential.size,
            &pAppCtx->ServerReturn.pBase64Credential,
            &pAppCtx->ServerReturn.credentialLen);
    if (OK != status)
    {
        LOG_ERROR("Failed to wrap credential into base64 blob. error=%d\n", status);
        goto exit;
    }

    status = OK;
exit:
    return status;
}

static MSTATUS clientTpmActivateCredential(application_context_t *pAppCtx)
{
    MSTATUS status = ERR_GENERAL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    CredentialUnwrapSecretIn unwrapIn = { 0 };
    ContextSetObjectAuthIn setAuthIn = { 0 };

    if (!pAppCtx)
    {
        status = ERR_INTERNAL_ERROR;
        TPM2_DEBUG_PRINT_NO_ARGS("Dev Error. Invalid app context.");
        goto exit;
    }

    setAuthIn.forceUseAuthValue = TRUE;

    /*
     * Set authValue for decrypt key. For now use empty Auth.
     */
    setAuthIn.objName = pAppCtx->ClientReturn.csrAttrIn.decryptKey;
    rc = FAPI2_CONTEXT_setObjectAuth(pAppCtx->ClientReturn.pCtx, &setAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to set object auth for decrypt key. error=%d\n", (int)rc);
        goto exit;
    }

    setAuthIn.objName = pAppCtx->ClientReturn.csrAttrIn.activateKey;
    rc = FAPI2_CONTEXT_setObjectAuth(pAppCtx->ClientReturn.pCtx, &setAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to set object auth for AK. error=%d\n", (int)rc);
        goto exit;
    }
    /*
     * Set authValue for activate key. For now use empty Auth.
     */
    unwrapIn.activateKey = pAppCtx->ClientReturn.csrAttrIn.activateKey;
    unwrapIn.decryptKey = pAppCtx->ClientReturn.csrAttrIn.decryptKey;
    unwrapIn.pBase64Blob = pAppCtx->ServerReturn.pBase64Credential;
    unwrapIn.blobLen = pAppCtx->ServerReturn.credentialLen;
    rc = FAPI2_CREDENTIAL_unwrapSecret(pAppCtx->ClientReturn.pCtx,
            &unwrapIn, &pAppCtx->ClientReturn.recoveredCredential);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to unwrap credential. error=%d\n", (int)rc);
        goto exit;
    }

    status = OK;
exit:
    return status;
}

static void cleanupContext(application_context_t *pAppCtx)
{
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (pAppCtx)
    {
        if (pAppCtx->ClientReturn.pCtx)
        {
            if (pAppCtx->ClientReturn.csrAttrIn.activateKey.size != 0)
            {
                flushObjectIn.objName = pAppCtx->ClientReturn.csrAttrIn.activateKey;
                FAPI2_CONTEXT_flushObject(pAppCtx->ClientReturn.pCtx, &flushObjectIn);
            }

            if (pAppCtx->ClientReturn.csrAttrIn.decryptKey.size != 0)
            {
                flushObjectIn.objName = pAppCtx->ClientReturn.csrAttrIn.decryptKey;
                FAPI2_CONTEXT_flushObject(pAppCtx->ClientReturn.pCtx, &flushObjectIn);
            }

            FAPI2_CONTEXT_uninit(&pAppCtx->ClientReturn.pCtx);
        }

        if (pAppCtx->ServerReturn.pBase64Credential)
            DIGI_FREE((void **)&(pAppCtx->ServerReturn.pBase64Credential));
    }
}

static MSTATUS executeOptions(application_context_t *pAppCtx)
{
    MSTATUS status = ERR_GENERAL;
    sbyte4 cmpResult = 0;

    if (!pAppCtx)
    {
        status = ERR_INTERNAL_ERROR;
        TPM2_DEBUG_PRINT_NO_ARGS("Dev Error. Invalid app context");
        goto exit;
    }

    /*
     * Default to device /dev/tpm0
     */
    if (!pAppCtx->options.serverNameSpecified)
    {
        pAppCtx->options.serverNameLen = DIGI_STRLEN((const sbyte *)DEFAULT_SERVER_NAME);
        DIGI_MEMCPY((void *)pAppCtx->options.serverName, DEFAULT_SERVER_NAME,
                pAppCtx->options.serverNameLen);
        pAppCtx->options.serverNameSpecified = TRUE;
    }

    /*
     * This portion is run on the client side. Here, we talk to the
     * client side TPM to obtain the required public information.
     */
    status = clientTpmGetCsrInfo(pAppCtx);
    if (OK != status)
    {
        LOG_ERROR("Falied to get information from client TPM, status = %d", status);
        goto exit;
    }

    /*
     * Imagine there is some network here.
     */

    /*
     * On the server side, we use the information provided by the client
     * to create a wrapped credential.
     * Ideally this function will be called after the server has validated
     * the EK's certificate chain to a genuine TPM and possibly to a known
     * TPM within a network.
     */
    status = serverGetWrappedCredential(pAppCtx);
    if (OK != status)
    {
        LOG_ERROR("Falied to get wrapped credential from server, status = %d", status);
        goto exit;
    }
    /*
     * Imagaine there is some network here.
     */

    /*
     * The wrapped credential is fed into the client side TPM and the
     * credential is recovered.
     */
    status = clientTpmActivateCredential(pAppCtx);
    if (OK != status)
    {
        LOG_ERROR("Falied to get wrapped credential from server, status = %d", status);
        goto exit;
    }

    /*
     * Verify credential created by server is same as the one returned by TPM.
     */
    if (pAppCtx->ServerReturn.keyCredential.size !=
            pAppCtx->ClientReturn.recoveredCredential.secret.size)
    {
        LOG_ERROR("Recovered credential size not same as server created credential.");
        goto exit;
    }

    status = DIGI_MEMCMP(pAppCtx->ClientReturn.recoveredCredential.secret.buffer,
            pAppCtx->ServerReturn.keyCredential.buffer,
            pAppCtx->ServerReturn.keyCredential.size, &cmpResult);
    if (cmpResult)
    {
        LOG_ERROR("Recovered credential not same as server created credential.");
        goto exit;
    }

    status = OK;
exit:

    /*
     * Clean up any resources used.
     */
    cleanupContext(pAppCtx);

    if (OK != status)
        LOG_ERROR("Failed credential protection example. status = %d", status);

    return status;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    application_context_t *pAppCtx = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    DIGICERT_initDigicert();

    if (NULL == platCmdLineParser)
    {
        LOG_ERROR("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pAppCtx, 1, sizeof(*pAppCtx)))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to allocate memory for application_context_t.");
        goto exit;
    }

    if (0 != platCmdLineParser(&(pAppCtx->options), argc, argv))
    {
        LOG_ERROR("Failed to parse command line options.");
        goto exit;
    }

    if (OK != executeOptions(pAppCtx))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to complete credential protection example.");
        goto exit;
    }

    retval = 0;
    LOG_MESSAGE("Successfully completed Credential Activation Protocol.");
exit:

    if (pAppCtx)
        shredMemory((ubyte **)&pAppCtx, sizeof(*pAppCtx), TRUE);

    if (0 != retval)
        LOG_ERROR("*****Credential protection example failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
