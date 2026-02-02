/*
 * mocpkcs11_keygen.c
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
 * @file       mocpkcs11_keygen.c
 * @brief      Utility to generate RSA/ECC key pairs using PKCS11
 * @details    This utility generates RSA or ECC key pairs in a PKCS11 token
               and exports them to PEM or DER format files. The output consists
               of two files: <alias>_priv.pem/der and <alias>_pub.pem/der
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
#include "../../../common/initmocana.h"
#include "../../../crypto/rsa.h"
#include "../../../crypto/primeec.h"
#include "../../../crypto/ca_mgmt.h"
#include "../../../crypto_interface/cryptointerface.h"
#include "../../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../../tap/tap.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_utils.h"
#include "../moctap_tools_utils.h"
#include "../../smp.h"
#include "../../smp_interface.h"
#include "../smp_pkcs11_api.h"
#include "../smp_pkcs11_interface.h"
#include "../smp_pkcs11.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#define PKCS11_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define PKCS11_DEBUG_PRINT_NO_ARGS(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#ifndef TAP_TEST_CONFIG_PATH
#define TAP_TEST_CONFIG_PATH "/etc/mocana/pkcs11_smp.conf"
#endif

#ifndef TAP_TEST_PROVIDER
#define TAP_TEST_PROVIDER TAP_PROVIDER_PKCS11
#endif

#ifndef TAP_TEST_DEFAULT_MODNUM
#define TAP_TEST_DEFAULT_MODNUM 1
#endif

static TAP_Context *gpTapCtx = NULL;
static TAP_EntityCredentialList *gpTapEntityCredList = NULL;
static TAP_CredentialList *gpTapCredList = NULL;
static TAP_ErrorContext gErrContext;
static TAP_ErrorContext *gpErrContext = &gErrContext;
static TAP_ConfigInfoList gConfigInfoList = {0,};

static void TAP_TEST_UTIL_clean(void);
static MSTATUS TAP_TEST_UTIL_init(ubyte4 modNum);

MSTATUS TAP_SMP_getTokenList(TAP_Context *pTapContext, TAP_TOKEN_TYPE tokenType,
                         TAP_TokenCapabilityAttributes *pCapabilityAttributes,
                         TAP_EntityList *pTokenList, TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_initToken(TAP_Context *pTapContext, TAP_TokenId *pTokenId,
                          TAP_TokenCapabilityAttributes *pTokenAttributes,
                          TAP_EntityCredentialList *pCredentials,
                          TAP_TokenHandle *pTokenHandle,
                          TAP_ErrorContext *pErrContext);

typedef struct
{
    ubyte4 keyType;
    ubyte4 size;
    sbyte *pAlias;
    byteBoolean isPem;
    ubyte4 modNum;

} KeyGenInfo;

static MSTATUS setStrParam(sbyte **ppParam, sbyte *pValue)
{
    MSTATUS status;
    ubyte4 valueLen = 0;
    if ( (NULL == ppParam) || (NULL == pValue) )
    {
        return ERR_NULL_POINTER;
    }

    valueLen = DIGI_STRLEN((const sbyte *)pValue);
    status = DIGI_MALLOC_MEMCPY (
        (void **)ppParam, valueLen + 1,
        (void *)pValue, valueLen);
    if (OK != status)
        goto exit;

    (*ppParam)[valueLen] = '\0';

exit:
    return status;
}

extern TAP_Context * TAP_TEST_UTIL_getTapContext(void)
{
    return gpTapCtx;
}

extern TAP_EntityCredentialList * TAP_TEST_UTIL_getEntityCredentialList(void)
{
    return gpTapEntityCredList;
}

extern TAP_CredentialList * TAP_TEST_UTIL_getCredentialList(void)
{
    return gpTapCredList;
}

static MSTATUS TAP_TEST_UTIL_getCtx(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    if (1 == getContext)
    {
        *ppTapCtx = gpTapCtx;
        *ppTapEntityCred = gpTapEntityCredList;
        *ppTapKeyCred = gpTapCredList;
    }
    else
    {
        *ppTapCtx = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

    return OK;
}

static MSTATUS TAP_TEST_UTIL_init(ubyte4 modNum)
{
    MSTATUS status = 0;
    TAP_Module module = {0};

    status = DIGI_CALLOC((void **)&(gConfigInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
        goto exit;

    status = TAP_readConfigFile((char *) TAP_TEST_CONFIG_PATH, &gConfigInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
        goto exit;

    gConfigInfoList.count = 1;
    gConfigInfoList.pConfig[0].provider = TAP_TEST_PROVIDER;

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    module.providerType = TAP_TEST_PROVIDER;
    module.moduleId = modNum;

#if !defined(__ENABLE_DIGICERT_TAP_REMOTE__)
    status = TAP_getModuleCredentials(&module, (char *) TAP_TEST_CONFIG_PATH, TRUE, &gpTapEntityCredList, gpErrContext);
    if (OK != status)
        goto exit;
#endif

    status = TAP_initContext(&module, gpTapEntityCredList, NULL, &gpTapCtx, gpErrContext);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_TEST_UTIL_getCtx);

exit:

    if (OK != status)
    {
        TAP_TEST_UTIL_clean();
    }

    return status;
}

static void TAP_TEST_UTIL_clean(void)
{
    sbyte4 i = 0;

    if (NULL != gConfigInfoList.pConfig)
    {
        (void) TAP_UTILS_freeConfigInfoList(&gConfigInfoList);
    }

    if (NULL != gpTapEntityCredList)
    {
        (void) TAP_UTILS_clearEntityCredentialList(gpTapEntityCredList);
        (void) DIGI_FREE((void**) &gpTapEntityCredList);
    }

    if (NULL != gpTapCredList)
    {
        if (NULL != gpTapCredList->pCredentialList)
        {
            for (i = 0; i < gpTapCredList->numCredentials; i++)
            {
                if (gpTapCredList->pCredentialList[i].credentialData.pBuffer != NULL)
                    (void) DIGI_FREE((void**)&(gpTapCredList->pCredentialList[i].credentialData.pBuffer));
            }
            (void) DIGI_FREE((void**) &(gpTapCredList->pCredentialList));
        }

        (void) DIGI_FREE((void**) &gpTapCredList);
    }

    if (NULL != gpTapCtx)
    {
        (void) TAP_uninitContext(&gpTapCtx, gpErrContext);
    }

    (void) TAP_uninit(gpErrContext);

    return;
}

/* Suffix must always be 3 bytes at most (ie pem or der) */
static MSTATUS aliasToFilenames(sbyte *pAlias, sbyte **ppPrivFile, sbyte **ppPubFile, sbyte *pSuffix)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pPubFile = NULL;
    sbyte *pPrivFile = NULL;
    ubyte4 aliasLen = 0;

    if ( (NULL == pAlias) || (NULL == ppPrivFile) || (NULL == ppPubFile) )
    {
        goto exit;
    }

    aliasLen = DIGI_STRLEN(pAlias);

    /* We need room for alias + _pub.pem + \0 */
    status = DIGI_CALLOC((void **)&pPubFile, 1, aliasLen + 9);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pPubFile, (void *)pAlias, aliasLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPubFile + aliasLen), "_pub.", 5);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPubFile + aliasLen + 5), (void *) pSuffix, 3);
    if (OK != status)
        goto exit;

    /* We need room for alias + _priv.pem + \0 */
    status = DIGI_CALLOC((void **)&pPrivFile, 1, aliasLen + 10);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pPrivFile, (void *)pAlias, aliasLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPrivFile + aliasLen), "_priv.", 6);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPrivFile + aliasLen + 6), (void *) pSuffix, 3);
    if (OK != status)
        goto exit;

    *ppPrivFile = pPrivFile;
    *ppPubFile = pPubFile;
    pPrivFile = NULL;
    pPubFile = NULL;

exit:

    if (NULL != pPrivFile)
    {
        DIGI_FREE((void **)&pPrivFile);
    }
    if (NULL != pPubFile)
    {
        DIGI_FREE((void **)&pPubFile);
    }

    return status;
}

static MSTATUS writeKeyToFile(AsymmetricKey *pPrivKey, AsymmetricKey *pPubKey, sbyte *pAlias, byteBoolean isPem)
{
    MSTATUS status;
    ubyte *pPrivKeyData = NULL;
    ubyte4 privKeyDataLen = 0;
    ubyte *pPubKeyData = NULL;
    ubyte4 pubKeyDataLen = 0;
    sbyte *pPrivFile = NULL;
    sbyte *pPubFile = NULL;

    status = aliasToFilenames(pAlias, &pPrivFile, &pPubFile, isPem ? "pem" : "der");
    if (OK != status)
    {
        printf("ERROR aliasToFilenames, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_serializeAsymKey (
        pPrivKey, isPem ? privateKeyPem : privateKeyInfoDer, &pPrivKeyData, &privKeyDataLen);
    if (OK != status)
    {
        printf("ERROR serializing private key, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_serializeAsymKey (
        pPubKey, isPem ? publicKeyPem : publicKeyInfoDer, &pPubKeyData, &pubKeyDataLen);
    if (OK != status)
    {
        printf("ERROR serializing public key, status: %d\n", status);
        goto exit;
    }

    status = DIGICERT_writeFile((const char *)pPrivFile, pPrivKeyData, privKeyDataLen);
    if (OK != status)
        goto exit;

    status = DIGICERT_writeFile((const char *)pPubFile, pPubKeyData, pubKeyDataLen);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pPrivFile)
    {
        DIGI_FREE((void **)&pPrivFile);
    }
    if (NULL != pPubFile)
    {
        DIGI_FREE((void **)&pPubFile);
    }
    if (NULL != pPrivKeyData)
    {
        DIGI_FREE((void **)&pPrivKeyData);
    }
    if (NULL != pPubKeyData)
    {
        DIGI_FREE((void **)&pPubKeyData);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__
static ubyte4 sizeToCurve(ubyte4 size)
{
#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (192 == size)
    {
        return cid_EC_P192;
    }
    else
#endif
    if (224 == size)   /* ok to assume the rest are enabled */
    {
        return cid_EC_P224;
    }
    else if (256 == size)
    {
        return cid_EC_P256;
    }
    else if (384 == size)
    {
        return cid_EC_P384;
    }
    else if (521 == size)
    {
        return cid_EC_P521;
    }

    return 0;
}

static MSTATUS generateEccKey(KeyGenInfo *pKeyInfo)
{
    MSTATUS status;
    AsymmetricKey key = {0};
    AsymmetricKey pubKey = {0};
    MEccTapKeyGenArgs eccTapArgs = {0};
    ECCKey *pNewKey = NULL, *pPubKey = NULL;
    sbyte *pPrivFile = NULL;
    sbyte *pPubFile = NULL;

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
    {
        printf("ERROR CRYPTO_initAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&pubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_initAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_NONE;
    eccTapArgs.keyUsage = TAP_KEY_USAGE_GENERAL;
    eccTapArgs.pTapCtx = TAP_TEST_UTIL_getTapContext();
    eccTapArgs.pEntityCredentials = TAP_TEST_UTIL_getEntityCredentialList();
    eccTapArgs.pKeyCredentials = TAP_TEST_UTIL_getCredentialList();

    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc( sizeToCurve(pKeyInfo->size), (void **) &pNewKey, NULL, NULL, akt_tap_ecc, &eccTapArgs);
    if (OK != status)
    {
        printf("Failed to generate ECC key, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_loadAsymmetricKey(&key, akt_tap_ecc, (void **) &pNewKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_loadAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_getECCPublicKey(&key, &pPubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_INTERFACE_getECCPublicKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_loadAsymmetricKey(&pubKey, akt_ecc, (void **) &pPubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_loadAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = writeKeyToFile(&key, &pubKey, pKeyInfo->pAlias, pKeyInfo->isPem);
    if (OK != status)
    {
        printf("ERROR writeKeyToFile, status: %d\n", status);
        goto exit;
    }

exit:
    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
    }

    return status;
}
#endif

static MSTATUS generateRsaKey(KeyGenInfo *pKeyInfo)
{
    MSTATUS status;
    AsymmetricKey key = {0};
    AsymmetricKey pubKey = {0};
    MRsaTapKeyGenArgs rsaTapArgs = {0};
    RSAKey *pNewKey = NULL, *pPubKey = NULL;
    sbyte *pPrivFile = NULL;
    sbyte *pPubFile = NULL;

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
    {
        printf("ERROR CRYPTO_initAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&pubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_initAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE;
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_GENERAL;
    rsaTapArgs.pTapCtx = TAP_TEST_UTIL_getTapContext();
    rsaTapArgs.pEntityCredentials = TAP_TEST_UTIL_getEntityCredentialList();
    rsaTapArgs.pKeyCredentials = TAP_TEST_UTIL_getCredentialList();

    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pNewKey, pKeyInfo->size, NULL, akt_tap_rsa, &rsaTapArgs);
    if (OK != status)
    {
        printf("Failed to generate RSA key, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_loadAsymmetricKey(&key, akt_tap_rsa, (void **) &pNewKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_loadAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_getRSAPublicKey(&key, &pPubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_INTERFACE_getRSAPublicKey, status: %d\n", status);
        goto exit;
    }

    status = CRYPTO_loadAsymmetricKey(&pubKey, akt_rsa, (void **) &pPubKey);
    if (OK != status)
    {
        printf("ERROR CRYPTO_loadAsymmetricKey, status: %d\n", status);
        goto exit;
    }

    status = writeKeyToFile(&key, &pubKey, pKeyInfo->pAlias, pKeyInfo->isPem);
    if (OK != status)
    {
        printf("ERROR writeKeyToFile, status: %d\n", status);
        goto exit;
    }

exit:
    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pNewKey, NULL);
    }

    return status;
}

static MSTATUS generateKey(KeyGenInfo *pKeyInfo)
{
    MSTATUS status = ERR_INVALID_ARG;

    if (NULL == pKeyInfo)
        goto exit;

    switch(pKeyInfo->keyType)
    {
        case MOC_LOCAL_TYPE_RSA:
            status = generateRsaKey(pKeyInfo);
            break;
#ifdef __ENABLE_DIGICERT_ECC__
        case MOC_LOCAL_TYPE_ECC:
            status = generateEccKey(pKeyInfo);
            break;
#endif
        default:
            goto exit;
    }

exit:
    return status;
}

static void displayHelp(char *prog)
{
    printf(" Usage: %s <options>\n", prog);
    printf("  options:\n");
#ifdef __ENABLE_DIGICERT_ECC__
    printf("    -type <key_type>     The key type, one of {rsa, ecc}.\n");
#else
    printf("    -type <key_type>     The key type, must be rsa.\n");
#endif
    printf("    -size <key_size>     The key size in bits.\n");
    printf("    -alias <alias_name>  Alias for the output files. The output is two files, alias_pub.pem and alias_priv.pem\n");
    printf("    -outform <format>    Optional, one of {pem, der}, default is pem.\n");
    printf("    -modulenum <value>   Optional. Module number of the module configuration to be used. Default is 1.\n");
    printf("\n");
    return;
}

static MSTATUS readArgs(int argc, char **ppArgv, KeyGenInfo *pKeyInfo)
{
    MSTATUS status = ERR_INVALID_INPUT;
    sbyte4 i;

    if (argc < 2)
    {
        displayHelp(ppArgv[0]);
        return -1;
    }

    /* set to pem for default case */
    pKeyInfo->isPem = TRUE;
    pKeyInfo->modNum = TAP_TEST_DEFAULT_MODNUM;

    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-help") == 0)
        {
            displayHelp(ppArgv[0]);
            return -2;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-alias") == 0)
        {
            if (++i < argc)
            {
                status = setStrParam(&(pKeyInfo->pAlias), (sbyte *)ppArgv[i]);
                if (OK != status)
                    goto exit;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-type") == 0)
        {
            if (++i < argc)
            {
                if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"rsa") == 0)
                {
                    pKeyInfo->keyType = MOC_LOCAL_TYPE_RSA;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"ecc") == 0)
                {
                    pKeyInfo->keyType = MOC_LOCAL_TYPE_ECC;
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-size") == 0)
        {
            if (++i < argc)
            {
                pKeyInfo->size = (ubyte4)atoi((const char *)ppArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-outform") == 0)
        {
            if (++i < argc)
            {
                if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"der") == 0)
                {
                    pKeyInfo->isPem = FALSE;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"pem") != 0)
                {
                    printf("Warning, unrecognized -outform: %s, using pem by default.\n", ppArgv[i]);
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-modulenum") == 0)
        {
            if (++i < argc)
            {
                pKeyInfo->modNum = (ubyte4)atoi((const char *)ppArgv[i]);
            }
            continue;
        }
    }

    status = OK;

exit:
    return status;

}

int main(int argc, char *argv[])
{
    MSTATUS status;
    KeyGenInfo keyInfo = {0};

    status = readArgs(argc, argv, &keyInfo);
    if (-2 == status)
    {
        return 0;
    }
    else if (OK != status)
    {
        printf("ERROR readArgs, status: %d\n", status);
        goto exit;
    }

    DIGICERT_initDigicert();

    status = TAP_TEST_UTIL_init(keyInfo.modNum);
    if (OK != status)
    {
        printf("ERROR TAP_TEST_UTIL_init, status: %d\n", status);
        goto exit;
    }

    status = generateKey(&keyInfo);
    if (OK != status)
    {
        printf("ERROR generateKey, status: %d\n", status);
        goto exit;
    }

exit:

    if (NULL != keyInfo.pAlias)
    {
        (void) DIGI_FREE((void **) &keyInfo.pAlias);
    }

    if (0 != status)
        LOG_ERROR("***** Failed to generate key *****");

    TAP_TEST_UTIL_clean();
    DIGICERT_freeDigicert();
    return status;
}
