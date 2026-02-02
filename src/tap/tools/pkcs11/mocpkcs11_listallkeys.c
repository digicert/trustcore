/*
 * mocpkcs11_listallkeys.c
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
 * @file       mocpkcs11_listallkeys.c
 * @brief      Utility to list all PKCS11 objects with a CKA_ID attribute
 * @details    This utility returns the module id in string format that can be
               copied to the configuration file for unique identification of this
               module.
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
#include "../../../crypto_interface/cryptointerface.h"
#include "../../../tap/tap.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_utils.h"
#include "../moctap_tools_utils.h"
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

MSTATUS PKCS11_listAllKeys(Pkcs11_Module *pGemModule, Pkcs11_Token* pGemToken);
MSTATUS PKCS11_deleteAllKeys(Pkcs11_Module *pGemModule, Pkcs11_Token* pGemToken);

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


MSTATUS listAllKeys()
{
    MSTATUS status;
    TAP_TokenHandle tokenHandle = 0;

    status = getTokenHandle (
        gpTapCtx, gpTapEntityCredList, &tokenHandle, NULL);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = PKCS11_listAllKeys((Pkcs11_Module *) (uintptr) ((_TAP_Context *) gpTapCtx)->moduleHandle, (Pkcs11_Token *) (uintptr) tokenHandle);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to delete all keys status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    return status;
}

static void displayHelp(char *prog)
{
    printf(" Usage: %s <options>\n", prog);
    printf("  options:\n");
    printf("    -modulenum <value>    Optional. Module number of the module configuration to be used. Default is 1.\n");
    printf("\n");
    return;
}

static MSTATUS readArgs(int argc, char **ppArgv, ubyte4 *pModNum)
{
    sbyte4 i = 0;

    /* set the default case */
    *pModNum = TAP_TEST_DEFAULT_MODNUM;

    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-help") == 0)
        {
            displayHelp(ppArgv[0]);
            return -2;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-modulenum") == 0)
        {
            if (++i < argc)
            {
                *pModNum = (ubyte4)atoi((const char *)ppArgv[i]);
            }
            continue;
        }
    }

    return OK;
}

int main(int argc, char *argv[])
{
    MSTATUS status;
    ubyte4 modNum;

    status = readArgs(argc, argv, &modNum);
    if (-2 == status)
    {
        return 0;
    }

    DIGICERT_initDigicert();

    status = TAP_TEST_UTIL_init(modNum);
    if (OK != status)
        goto exit;

    status = listAllKeys();

exit:

    if (0 != status)
        LOG_ERROR("***** Failed to list keys *****");

    TAP_TEST_UTIL_clean();
    DIGICERT_freeDigicert();
    return status;
}
