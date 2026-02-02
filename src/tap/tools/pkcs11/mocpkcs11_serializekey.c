/*
 * mocpkcs11_serializekey.c
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
 * @file       mocpkcs11_serializekey.c
 * @brief      Utility to serialize a given key by ID into PEM/DER or Mocana Blob format.
 * @details    Utility to serialize a given key by ID into PEM/DER or Mocana Blob format.
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
#include "../../../common/initmocana.h"
#include "../../../common/base64.h"
#include "../../../common/debug_console.h"
#include "../../../crypto/rsa.h"
#include "../../../crypto/primeec.h"
#include "../../../crypto/ca_mgmt.h"
#include "../../../cap/capasym.h"
#include "../../../crypto_interface/cryptointerface.h"
#include "../../../crypto_interface/crypto_interface_tap.h"
#include "../../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../../tap/tap.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_utils.h"
#include "../../smp.h"
#include "../../smp_interface.h"
#include "../smp_pkcs11_api.h"
#include "../smp_pkcs11_interface.h"
#include "../smp_pkcs11.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifndef TAP_TEST_CONFIG_PATH
#define TAP_TEST_CONFIG_PATH "/etc/mocana/pkcs11_smp.conf"
#endif

#ifndef TAP_TEST_PROVIDER
#define TAP_TEST_PROVIDER TAP_PROVIDER_PKCS11
#endif

#ifndef TAP_TEST_DEFAULT_MODNUM
#define TAP_TEST_DEFAULT_MODNUM 1
#endif

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

/* structure should match that in tap.c. Needed so can obtain the module Handle */
typedef struct
{
    /*! context signature */
    ubyte4                           signature;
    /*! security module type; must be value #TAP_PROVIDER value */
    TAP_PROVIDER                     providerType;
    /*! Information to uniquely identify a module.  This contains #TAP_ConnectionInfo. */
    TAP_Module                       module;
    /*! SSL session information for a connection. */
    TAP_SessionInfo                  sessionInfo;
    /*! Policy/Security descriptor */
    TAP_PolicyInfo                  *pPolicyAuthInfo;
    /*! Module handle returned by SMP */
    TAP_ModuleHandle moduleHandle;
} _TAP_Context;

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

MSTATUS PKCS11_getCertData(
    Pkcs11_Module* pGemModule,
    Pkcs11_Token* pGemToken,
    ubyte *pCertId,
    ubyte4 certIdLen,
    ubyte **ppCertData,
    usize *pCertDataLen);

#define ID_FORM_HEX 0
#define ID_FORM_STRING 1
#define ID_FORM_BASE64 2

typedef struct
{
    /* input params */
    ubyte4 keyType;
    ubyte4 sigScheme;
    sbyte *pIdIn;
    ubyte4 idform;
    sbyte *pAlias;
    sbyte *pAlias_pri;
    sbyte *pAlias_pub;
    sbyte *pAlias_crt;
    serializedKeyFormat outform;
    ubyte4 modNum;

    /* calculated params for CI API use */
    TAP_KeyInfo tapKeyInfo;
    ubyte *pId;
    ubyte4 idLen;
    serializedKeyFormat puboutform;

} KeySerInfo;

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

static MSTATUS getTokenHandle (
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_TokenHandle *pTokenHandle,
    TAP_ErrorContext *pErrContext
)
{
    MSTATUS status;
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttributes = {0};
    volatile TAP_EntityCredentialList nullUsageCredentials = {0};
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };

    if (NULL == pTokenHandle)
        return ERR_NULL_POINTER;

    if (NULL != pUsageCredentials)
    {
        status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                    NULL, pErrContext);
        if (OK != status)
        {
            LOG_ERROR("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                    &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        LOG_ERROR("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        LOG_ERROR("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit;
    }

    tokenId = tokenList.entityIdList.pEntityIdList[0];

    DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId,
                (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttributes,
                pUsageCredentials ? pUsageCredentials :
                (TAP_EntityCredentialList *)&nullUsageCredentials,
                &tokenHandle, pErrContext);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pTokenHandle = tokenHandle;

exit:
    return status;
}

/* Suffix must always be 3 bytes at most (ie pem or der) */
static MSTATUS aliasToFilenames(sbyte *pAlias, sbyte **ppPrivFile, sbyte **ppPubFile, sbyte **ppCertFile, sbyte *pSuffix)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pPubFile = NULL;
    sbyte *pPrivFile = NULL;
    sbyte *pCertFile = NULL;
    ubyte4 aliasLen = 0;

    MOC_UNUSED(pSuffix); /* for now */

    /* internal method, null checks not needed */
    aliasLen = DIGI_STRLEN(pAlias);

    /* We need room for alias + .pub + \0 */
    status = DIGI_CALLOC((void **)&pPubFile, 1, aliasLen + 5);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pPubFile, (void *)pAlias, aliasLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPubFile + aliasLen), ".pub", 4);
    if (OK != status)
        goto exit;

/*
    status = DIGI_MEMCPY((void *)(pPubFile + aliasLen + 4), (void *) pSuffix, 4);
    if (OK != status)
        goto exit;
*/
    /* We need room for alias + .pri + \0 */
    status = DIGI_CALLOC((void **)&pPrivFile, 1, aliasLen + 5);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pPrivFile, (void *)pAlias, aliasLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pPrivFile + aliasLen), ".pri", 4);
    if (OK != status)
        goto exit;
/*
    status = DIGI_MEMCPY((void *)(pPrivFile + aliasLen) + 4, (void *) pSuffix, 4);
    if (OK != status)
        goto exit;
*/

    status = DIGI_CALLOC((void **)&pCertFile, 1, aliasLen + 5);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pCertFile, (void *)pAlias, aliasLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pCertFile + aliasLen), ".crt", 4);
    if (OK != status)
        goto exit;
/*
    status = DIGI_MEMCPY((void *)(pCertFile + aliasLen) + 4, (void *) pSuffix, 4);
    if (OK != status)
        goto exit;
*/
    *ppPrivFile = pPrivFile;
    *ppPubFile = pPubFile;
    *ppCertFile = pCertFile;
    pPrivFile = NULL;
    pPubFile = NULL;
    pCertFile = NULL;

exit:

    if (NULL != pPrivFile)
    {
        DIGI_FREE((void **)&pPrivFile);
    }
    if (NULL != pPubFile)
    {
        DIGI_FREE((void **)&pPubFile);
    }
    if (NULL != pCertFile)
    {
        DIGI_FREE((void **)&pCertFile);
    }

    return status;
}

static MSTATUS writeFiles(ubyte *pSerKey, ubyte4 serKeyLen, ubyte *pSerPub, ubyte4 serPubLen, ubyte *pCert, ubyte4 certLen, KeySerInfo *pKeyInfo)
{
    MSTATUS status = OK;
    sbyte *pPrivFile = NULL;
    sbyte *pPubFile = NULL;
    sbyte *pCertFile = NULL;

    if (NULL != pKeyInfo->pAlias)
    {
        /* for now we just output pem */
        status = aliasToFilenames(pKeyInfo->pAlias, &pPrivFile, &pPubFile, &pCertFile, ".pem");
        if (OK != status)
        {
            printf("ERROR aliasToFilenames, status: %d\n", status);
            goto exit;
        }
    }

    /* The _pri/_pub/_crt Alias's override the above */
    if (NULL != pKeyInfo->pAlias_pri)
    {
        status = DIGICERT_writeFile((const char *)pKeyInfo->pAlias_pri, pSerKey, serKeyLen);
    }
    else
    {
        status = DIGICERT_writeFile((const char *)pPrivFile, pSerKey, serKeyLen);
    }
    if (OK != status)
        goto exit;

    if (NULL != pSerPub)
    {
        if (NULL != pKeyInfo->pAlias_pub)
        {
            status = DIGICERT_writeFile((const char *)pKeyInfo->pAlias_pub, pSerPub, serPubLen);
        }
        else if (NULL != pKeyInfo->pAlias)
        {
            status = DIGICERT_writeFile((const char *)pPubFile, pSerPub, serPubLen);
        }
        if (OK != status)
            goto exit;
    }

    if (NULL != pCert)
    {
        if (NULL != pKeyInfo->pAlias_crt)
        {
            status = DIGICERT_writeFile((const char *)pKeyInfo->pAlias_crt, pCert, certLen);
        }
        else if (NULL != pKeyInfo->pAlias)
        {
            status = DIGICERT_writeFile((const char *)pCertFile, pCert, certLen);
        }
    }

exit:

    if (NULL != pPrivFile)
    {
        DIGI_FREE((void **)&pPrivFile);
    }
    if (NULL != pPubFile)
    {
        DIGI_FREE((void **)&pPubFile);
    }
    if (NULL != pCertFile)
    {
        DIGI_FREE((void **)&pCertFile);
    }

    return status;
}

static void createTAPKeyInfo(KeySerInfo *pKeyInfo)
{
    if (MOC_LOCAL_TYPE_RSA == pKeyInfo->keyType)
    {
        pKeyInfo->tapKeyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
        switch (pKeyInfo->sigScheme)
        {
            case ht_sha1:
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                break;

            case ht_sha224:
                /* TO DO validate somewhere */
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE;
                break;

            case ht_sha256:
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                break;

            case ht_sha384:
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                break;

            case ht_sha512:
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                break;

            default:
                pKeyInfo->tapKeyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE;
                break;            
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (MOC_LOCAL_TYPE_ECC == pKeyInfo->keyType)
    {
        pKeyInfo->tapKeyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
        switch (pKeyInfo->sigScheme)
        {
            case ht_sha1:
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                break;

            case ht_sha224:
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                break;

            case ht_sha256:
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                break;

            case ht_sha384:
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                break;

            case ht_sha512:
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                break;

            default:
                /* TO DO, might not work */
                pKeyInfo->tapKeyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_NONE;
                break;            
        }
    }
#endif
}

static MSTATUS convertId(KeySerInfo *pKeyInfo)
{
    MSTATUS status = ERR_INVALID_ARG;
    ubyte *pId = NULL;
    ubyte4 idLen = 0;

    if (ID_FORM_HEX == pKeyInfo->idform)
    {
        /* use idLen as a temp for string form lem */
        idLen = (ubyte4) DIGI_STRLEN(pKeyInfo->pIdIn);
        if (idLen < 4 || idLen & 0x01)
        {
            printf("ERROR: Hex form ID must begin with 0x prefix and be even in number of characters, status: %d\n", status);
            goto exit;
        }

        if ('0' != pKeyInfo->pIdIn[0] || ('x' != pKeyInfo->pIdIn[1] && 'X' != pKeyInfo->pIdIn[1] )) 
        {
            printf("ERROR: Hex form ID must begin with 0x prefix, status: %d\n", status);
            goto exit;
        }
        
        /* now get the real id Len */
        idLen = (idLen - 2) / 2;

        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
        {
            printf("ERROR: Unable to allocate memory, status: %d\n", status);
            goto exit;
        }

        status = DIGI_ATOH(pKeyInfo->pIdIn + 2, idLen*2, pId);
        if (OK != status)
        {
            printf("ERROR: Invalid Hex string ID, status: %d\n", status);
            goto exit;
        }
    }
    else if (ID_FORM_STRING == pKeyInfo->idform)
    {
        idLen = (ubyte4) DIGI_STRLEN(pKeyInfo->pIdIn);
        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
        {
            printf("ERROR: Unable to allocate memory, status: %d\n", status);
            goto exit;
        }

        status = DIGI_MEMCPY(pId, (ubyte *) pKeyInfo->pIdIn, idLen);
        if (OK != status)
        {
            printf("ERROR: Unable to copy string form ID, status: %d\n", status);
            goto exit;
        }
    }
    else if (ID_FORM_BASE64 == pKeyInfo->idform)
    {
        status = BASE64_decodeMessage(pKeyInfo->pIdIn, (ubyte4) DIGI_STRLEN(pKeyInfo->pIdIn), &pId, &idLen);
        if (OK != status)
        {
            printf("ERROR: Invalid Base64 form ID, status: %d\n", status);
            goto exit;
        }
    }

    status = OK;
    pKeyInfo->pId = pId; pId = NULL;
    pKeyInfo->idLen = idLen;

exit:

    if (NULL != pId)
    {
        (void) DIGI_MEMSET_FREE(&pId, idLen);
    }

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
    printf("    -sig_scheme <scheme> One of {sha1, sha224, sha256, sha384, sha512}\n");
    printf("    -id <key_id>         The id of the key. Default format is hex.\n");
    printf("    -idform <format>     Optional. The format of the input id, one of {hex, string, base64}.\n");
    printf("    -alias_ori <name>    Output file name for the private key.\n");
    printf("    -alias_pub <name>    Output file name for the public key.\n");
    printf("    -alias_crt <name>    Output file name for the certificate (if found).\n");
    printf("    -alias <name>        Optional. Can be used in place of the above 3 commands. File name\n");
    printf("                         stub for the output files. Suffix will be .pri, .pub, .crt respectively.\n");
    printf("    -modulenum <value>   Optional. Module number of the module configuration to be used. Default is 1.\n");
/*    printf("    -outform <format>    Optional, one of {pem, der, blob}, default is pem.\n"); */
    printf("\n");
    return;
}

static MSTATUS readArgs(int argc, char **ppArgv, KeySerInfo *pKeyInfo)
{
    MSTATUS status = ERR_INVALID_INPUT;
    sbyte4 i;

    if (argc < 2)
    {
        displayHelp(ppArgv[0]);
        return -1;
    }

    /* set defaults */
    pKeyInfo->idform = ID_FORM_HEX;
    pKeyInfo->outform = privateKeyPem;
    pKeyInfo->puboutform = publicKeyPem;
    pKeyInfo->modNum = TAP_TEST_DEFAULT_MODNUM;
    /* default sigScheme is 0, ok for RSA but ECDSA may need non-zero */

    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-help") == 0)
        {
            displayHelp(ppArgv[0]);
            return -2;
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
#ifdef __ENABLE_DIGICERT_ECC__
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"ecc") == 0)
                {
                    pKeyInfo->keyType = MOC_LOCAL_TYPE_ECC;
                }
#endif
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-sig_scheme") == 0)
        {
            if (++i < argc)
            {
                if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"sha1") == 0)
                {
                    pKeyInfo->sigScheme = ht_sha1;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"sha224") == 0)
                {
                    pKeyInfo->sigScheme = ht_sha224;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"sha256") == 0)
                {
                    pKeyInfo->sigScheme = ht_sha256;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"sha384") == 0)
                {
                    pKeyInfo->sigScheme = ht_sha384;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"sha512") == 0)
                {
                    pKeyInfo->sigScheme = ht_sha512;
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-id") == 0)
        {
            if (++i < argc)
            {
                pKeyInfo->pIdIn = (sbyte *)ppArgv[i];
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-idform") == 0)
        {
            if (++i < argc)
            {
                if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"hex") == 0)
                {
                    pKeyInfo->idform = ID_FORM_HEX;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"string") == 0)
                {
                    pKeyInfo->idform = ID_FORM_STRING;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"base64") == 0)
                {
                    pKeyInfo->idform = ID_FORM_BASE64;
                }
            }
            continue;
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
            (const sbyte *)"-alias_pri") == 0)
        {
            if (++i < argc)
            {
                status = setStrParam(&(pKeyInfo->pAlias_pri), (sbyte *)ppArgv[i]);
                if (OK != status)
                    goto exit;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-alias_pub") == 0)
        {
            if (++i < argc)
            {
                status = setStrParam(&(pKeyInfo->pAlias_pub), (sbyte *)ppArgv[i]);
                if (OK != status)
                    goto exit;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-alias_crt") == 0)
        {
            if (++i < argc)
            {
                status = setStrParam(&(pKeyInfo->pAlias_crt), (sbyte *)ppArgv[i]);
                if (OK != status)
                    goto exit;
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
        /*
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-outform") == 0)
        {
            if (++i < argc)
            {
                if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"der") == 0)
                {
                    pKeyInfo->outform = privateKeyInfoDer;
                    pKeyInfo->puboutform = publicKeyInfoDer;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"pem") == 0)
                {
                    pKeyInfo->outform = privateKeyPem;
                    pKeyInfo->puboutform = publicKeyPem;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"blob") == 0)
                {
                    pKeyInfo->outform = mocanaBlobVersion2;
                    pKeyInfo->puboutform = mocanaBlobVersion2;
                }
            }
            continue;
        }
        */
    }

    if (NULL == pKeyInfo->pAlias && NULL == pKeyInfo->pAlias_pri)
    {
        status = ERR_INVALID_INPUT;
        printf("ERROR: Must include at least one of -alias or -alias_pri\n");
        goto exit;
    }

    createTAPKeyInfo(pKeyInfo);
    status = convertId(pKeyInfo);
    /* error for convertId already printed */

exit:
    return status;

}

int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    KeySerInfo keyInfo = {0};
    AsymmetricKey privKey = {0};
    AsymmetricKey pubKey = {0};
    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;
    ubyte *pSerializedPub = NULL;
    ubyte4 serializedPubLen = 0;
    ubyte *pSerCert = NULL;
    usize serCertLen = 0;
    RSAKey *pRSAKey = NULL;
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pECCKey = NULL;
#endif
    TAP_TokenHandle tokenHandle = 0;
    TAP_ErrorContext errContext = {0};

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

    status = CRYPTO_initAsymmetricKey(&privKey);
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


    status = CRYPTO_INTERFACE_TAP_serializeKeyById(TAP_TEST_UTIL_getTapContext(), TAP_TEST_UTIL_getEntityCredentialList(), TAP_TEST_UTIL_getCredentialList(),
                                                   &keyInfo.tapKeyInfo, keyInfo.pId, keyInfo.idLen, keyInfo.outform, &pSerializedKey, &serializedKeyLen);

    if (OK != status)
    {
        printf("ERROR: Please make sure your ID is correct and the correct format, status: %d\n", status);
        goto exit;
    }

    /* we have to deserialize in order to get the public key too */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerializedKey, serializedKeyLen, NULL, &privKey);
    if (OK != status)
    {
        printf("ERROR: Unable to deserialize key in order to retrieve the public key, status: %d\n", status);
        goto exit;
    }

    if(MOC_LOCAL_TYPE_RSA == keyInfo.keyType)
    {
        status = CRYPTO_INTERFACE_getRSAPublicKey(&privKey, &pRSAKey);
        if (OK != status)
        {
            printf("ERROR: Unable to retrieve public key, status: %d\n", status);
            goto exit;
        }

        status = CRYPTO_loadAsymmetricKey(&pubKey, akt_rsa, (void **)&pRSAKey);
        if (OK != status)
        {
            printf("ERROR: Unable to load public key, status: %d\n", status);
            goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if(MOC_LOCAL_TYPE_ECC == keyInfo.keyType)
    {
        status = CRYPTO_INTERFACE_getECCPublicKey(&privKey, &pECCKey);
        if (OK != status)
        {
            printf("ERROR: Unable to retrieve public key, status: %d\n", status);
            goto exit;
        }

        status = CRYPTO_loadAsymmetricKey(&pubKey, akt_ecc, (void **)&pECCKey);
        if (OK != status)
        {
            printf("ERROR: Unable to load public key, status: %d\n", status);
            goto exit;
        }
    }
#endif

    status = CRYPTO_serializeAsymKey (&pubKey, keyInfo.puboutform, &pSerializedPub, &serializedPubLen);
    if (OK != status)
    {
        printf("ERROR: Unable to serialize public key, status: %d\n", status);
        goto exit;
    }

    /* Also check if there is a certificate */
    status = getTokenHandle(TAP_TEST_UTIL_getTapContext(), TAP_TEST_UTIL_getEntityCredentialList(), &tokenHandle, &errContext);
    if (OK != status)
    {
        printf("ERROR: Unable to get a handle on the token, status: %d\n", status);
        goto exit;
    }

    status = PKCS11_getCertData((Pkcs11_Module *)(uintptr)((_TAP_Context *) gpTapCtx)->moduleHandle, (Pkcs11_Token *) (uintptr) tokenHandle, keyInfo.pId, keyInfo.idLen, &pSerCert, &serCertLen);
    if (OK != status && ERR_NOT_FOUND != status)
    {
        printf("ERROR: Unable to search for a certificate, status: %d\n", status);
        goto exit;
    }

    if (NULL != pSerCert && privateKeyInfoDer != keyInfo.outform)
    {
        ubyte *pTemp = NULL;
        ubyte4 tempLen = 0;

        status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_CERT, pSerCert, serCertLen, &pTemp, &tempLen);
        if (OK != status)
        {
            printf("ERROR: Unable to convert cert to PEM form: %d\n", status);
            goto exit;
        }

        (void) DIGI_MEMSET_FREE(&pSerCert, serCertLen);
        pSerCert = pTemp;
        serCertLen = tempLen;
    }

    /* write files, cert is written only if it was found */
    status = writeFiles(pSerializedKey, serializedKeyLen, pSerializedPub, serializedPubLen, pSerCert, (ubyte4) serCertLen, &keyInfo);
    if (OK != status)
    {
        printf("ERROR writeFiles, status: %d\n", status);
    }

exit:

    if (0 != status)
        printf("***** Failed to serialize key *****\n");

    (void) CRYPTO_uninitAsymmetricKey(&privKey, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    
    if (NULL != keyInfo.pId)
    {
        (void) DIGI_MEMSET_FREE(&keyInfo.pId, keyInfo.idLen);
    }

    if (NULL != keyInfo.pAlias)
    {
        (void) DIGI_FREE((void **) &keyInfo.pAlias);
    }

    if (NULL != pSerializedKey)
    {
        (void) DIGI_MEMSET_FREE(&pSerializedKey, serializedKeyLen);
    }

    if (NULL != pSerializedPub)
    {
        (void) DIGI_MEMSET_FREE(&pSerializedPub, serializedPubLen);
    }

    if (NULL != pSerCert)
    {
        (void) DIGI_MEMSET_FREE(&pSerCert, (ubyte4) serCertLen);
    }

    (void) TAP_TEST_UTIL_clean();
    (void) DIGICERT_freeDigicert();
    return status;
}
