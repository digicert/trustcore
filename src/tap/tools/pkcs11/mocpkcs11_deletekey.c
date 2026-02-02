/*
 * mocpkcs11_deletekey.c
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
 * @file       mocpkcs11_deletekey.c
 * @brief      Utility to delete PKCS11 objects by CKA_ID attribute
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
#include "../../../common/base64.h"
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

#define ID_FORM_HEX 0
#define ID_FORM_STRING 1
#define ID_FORM_BASE64 2

typedef struct
{
    byteBoolean isAll;
    sbyte *pIdIn;
    ubyte4 idform;

    ubyte *pId;
    ubyte4 idLen;
    ubyte4 modNum;

} DeleteInfo;

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
MSTATUS PKCS11_deleteById(Pkcs11_Module *pGemModule, Pkcs11_Token* pGemToken, ubyte *pId, ubyte4 idLen);

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


MSTATUS deleteAllKeys(Pkcs11_Module *pModuleHandle, Pkcs11_Token *pTokenHandle)
{
    MSTATUS status;

    status = PKCS11_listAllKeys(pModuleHandle, pTokenHandle);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to list all keys status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = PKCS11_deleteAllKeys(pModuleHandle, pTokenHandle);
    if (OK != status)
    {
        LOG_ERROR("%s.%d Failed to delete all keys status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    return status;
}

static MSTATUS convertId(DeleteInfo *pDeleteInfo)
{
    MSTATUS status = ERR_INVALID_ARG;
    ubyte *pId = NULL;
    ubyte4 idLen = 0;

    if (ID_FORM_HEX == pDeleteInfo->idform)
    {
        /* use idLen as a temp for string form lem */
        idLen = (ubyte4) DIGI_STRLEN(pDeleteInfo->pIdIn);
        if (idLen < 4 || idLen & 0x01)
        {
            printf("ERROR: Hex form ID must begin with 0x prefix and be even in number of characters, status: %d\n", status);
            goto exit;
        }

        if ('0' != pDeleteInfo->pIdIn[0] || ('x' != pDeleteInfo->pIdIn[1] && 'X' != pDeleteInfo->pIdIn[1] )) 
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

        status = DIGI_ATOH(pDeleteInfo->pIdIn + 2, idLen*2, pId);
        if (OK != status)
        {
            printf("ERROR: Invalid Hex string ID, status: %d\n", status);
            goto exit;
        }
    }
    else if (ID_FORM_STRING == pDeleteInfo->idform)
    {
        idLen = (ubyte4) DIGI_STRLEN(pDeleteInfo->pIdIn);
        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
        {
            printf("ERROR: Unable to allocate memory, status: %d\n", status);
            goto exit;
        }

        status = DIGI_MEMCPY(pId, (ubyte *) pDeleteInfo->pIdIn, idLen);
        if (OK != status)
        {
            printf("ERROR: Unable to copy string form ID, status: %d\n", status);
            goto exit;
        }
    }
    else if (ID_FORM_BASE64 == pDeleteInfo->idform)
    {
        status = BASE64_decodeMessage(pDeleteInfo->pIdIn, (ubyte4) DIGI_STRLEN(pDeleteInfo->pIdIn), &pId, &idLen);
        if (OK != status)
        {
            printf("ERROR: Invalid Base64 form ID, status: %d\n", status);
            goto exit;
        }
    }

    status = OK;
    pDeleteInfo->pId = pId; pId = NULL;
    pDeleteInfo->idLen = idLen;

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
    printf("    -all                 Optional. Delete All keys.\n");
    printf("    -id <key_id>         The id of the key (or keypair/cert) to be deleted. Default format is hex.\n");
    printf("    -idform <format>     Optional. The format of the input id, one of {hex, string, base64}.\n");
    printf("    -modulenum <value>   Optional. Module number of the module configuration to be used. Default is 1.\n");
    printf("\n");
    return;
}

static MSTATUS readArgs(int argc, char **ppArgv, DeleteInfo *pDeleteInfo)
{
    MSTATUS status = ERR_INVALID_INPUT;
    sbyte4 i;

    if (argc < 2)
    {
        displayHelp(ppArgv[0]);
        return -1;
    }

    /* set defaults */
    pDeleteInfo->idform = ID_FORM_HEX;
    pDeleteInfo->modNum = TAP_TEST_DEFAULT_MODNUM;

    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-help") == 0)
        {
            displayHelp(ppArgv[0]);
            return -2;
        }        
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-all") == 0)
        {
            pDeleteInfo->isAll = TRUE;
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-id") == 0)
        {
            if (++i < argc)
            {
                pDeleteInfo->pIdIn = (sbyte *)ppArgv[i];
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
                    pDeleteInfo->idform = ID_FORM_HEX;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"string") == 0)
                {
                    pDeleteInfo->idform = ID_FORM_STRING;
                }
                else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
                    (const sbyte *)"base64") == 0)
                {
                    pDeleteInfo->idform = ID_FORM_BASE64;
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-modulenum") == 0)
        {
            if (++i < argc)
            {
                pDeleteInfo->modNum = (ubyte4)atoi((const char *)ppArgv[i]);
            }
            continue;
        }
    }

    status = OK;

    if (NULL != pDeleteInfo->pIdIn)
    {
        status = convertId(pDeleteInfo);
        /* error for convertId already printed */
    }

exit:

    return status;
}

int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    DeleteInfo delInfo = {0};
    TAP_TokenHandle tokenHandle = 0;

    status = readArgs(argc, argv, &delInfo);
    if (-2 == status)
    {
        return 0;
    }
    else if (OK != status)
    {
        printf("ERROR: readArgs, status: %d\n", status);
        goto exit;
    }

    DIGICERT_initDigicert();

    status = TAP_TEST_UTIL_init(delInfo.modNum);
    if (OK != status)
        goto exit;

    status = getTokenHandle (gpTapCtx, gpTapEntityCredList, &tokenHandle, NULL);
    if (OK != status)
    {
        printf("ERROR: getTokenHandl, status = %d\n", status);
        goto exit;
    }

    if (delInfo.isAll)
    {
        status = deleteAllKeys( (Pkcs11_Module *) (uintptr) ((_TAP_Context *) gpTapCtx)->moduleHandle, (Pkcs11_Token *) (uintptr) tokenHandle);
        /* error already printed */
    }
    else
    {
        status = PKCS11_deleteById((Pkcs11_Module *) (uintptr) ((_TAP_Context *) gpTapCtx)->moduleHandle, (Pkcs11_Token *) (uintptr) tokenHandle, delInfo.pId, delInfo.idLen);
        if (ERR_NOT_FOUND == status)
        {
            status = OK;
            printf("No key or object with that ID. Nothing deleted.\n");
        }
        else if (OK != status)
        {
            printf("ERROR: Unable to delete key or object with that ID, status = %d.\n", status);
        }
    }
    
exit:

    if (0 != status)
        LOG_ERROR("***** Execution failed *****");

    if (NULL != delInfo.pId)
    {
        (void) DIGI_MEMSET_FREE(&delInfo.pId, delInfo.idLen);
    }

    TAP_TEST_UTIL_clean();
    DIGICERT_freeDigicert();
    return status;
}
