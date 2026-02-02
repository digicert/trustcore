/*
 * crypto_interface_tap_example.c
 *
 * Crypto Interface TAP Example Code
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
 
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"

#include "../../crypto/mocasym.h"
#include "../../crypto/rsa.h"
#include "../cryptointerface.h"

#ifdef __ENABLE_DIGICERT_TAP__

#include "crypto_interface_tap_example.h"

#ifndef __ENABLE_DIGICERT_TAP_EXTERN__

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
#include "../../tap/tap_conf_common.h"

#ifndef TAP_SERVER_NAME
#define TAP_SERVER_NAME "127.0.0.1"
#endif

#ifndef TAP_SERVER_PORT
#define TAP_SERVER_PORT 8277
#endif

#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */

#ifndef TAP_EXAMPLE_CONFIG_PATH
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define TAP_EXAMPLE_CONFIG_PATH "/etc/mocana/pkcs11_smp.conf"
#elif defined(__ENABLE_DIGICERT_TPM2__)
#include "../../common/tpm2_path.h"
#define TAP_EXAMPLE_CONFIG_PATH TPM2_CONFIGURATION_FILE
#else
#error "SMP flag not specified. Cannot set default path to TAP config file."
#endif
#endif

#ifndef TAP_EXAMPLE_PROVIDER
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define TAP_EXAMPLE_PROVIDER TAP_PROVIDER_PKCS11
#elif defined(__ENABLE_DIGICERT_TPM2__)
#define TAP_EXAMPLE_PROVIDER TAP_PROVIDER_TPM2
#else
#error "SMP flag not specified. Cannot set TAP provider."
#endif
#endif

/* modulenum 0 is reserved, this example will use 1 and 2 */
#ifndef TAP_EXAMPLE_MAX_MODULES
#define TAP_EXAMPLE_MAX_MODULES 3
#endif

static TAP_Context *gpTapCtx[TAP_EXAMPLE_MAX_MODULES] = {0};
static TAP_EntityCredentialList *gpTapEntityCredList[TAP_EXAMPLE_MAX_MODULES] = {0};
static TAP_CredentialList *gpTapCredList[TAP_EXAMPLE_MAX_MODULES] = {0};
static TAP_ErrorContext gErrContext;
static TAP_ErrorContext *gpErrContext = &gErrContext;
static TAP_ConfigInfoList gConfigInfoList = {0,};

extern TAP_Context * TAP_EXAMPLE_getTapContext(ubyte4 moduleNum)
{
    return gpTapCtx[moduleNum];
}

extern TAP_EntityCredentialList * TAP_EXAMPLE_getEntityCredentialList(ubyte4 moduleNum)
{
    return gpTapEntityCredList[moduleNum];
}

extern TAP_CredentialList * TAP_EXAMPLE_getCredentialList(ubyte4 moduleNum)
{
    return gpTapCredList[moduleNum];
}

/* Callback for context with modulenum 1 */
extern MSTATUS TAP_EXAMPLE_getCtx1(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    if (1 == getContext)
    {
        *ppTapCtx = gpTapCtx[1];
        *ppTapEntityCred = gpTapEntityCredList[1];
        *ppTapKeyCred = gpTapCredList[1];
    }
    else
    {
        *ppTapCtx = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

    return OK;
}

/* Callback for context with modulenum 2 */
extern MSTATUS TAP_EXAMPLE_getCtx2(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    if (1 == getContext)
    {
        *ppTapCtx = gpTapCtx[2];
        *ppTapEntityCred = gpTapEntityCredList[2];
        *ppTapKeyCred = gpTapCredList[2];
    }
    else
    {
        *ppTapCtx = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

    return OK;
}

/* Takes a list of the module numbers to be initialized */
extern MSTATUS TAP_EXAMPLE_init(ubyte4 *pModNums, ubyte4 numMods)
{
    MSTATUS status = 0;
    TAP_Module module = {0};
    ubyte4 i = 0;

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };

    /* Discover modules */
    connInfo.serverName.bufferLen = DIGI_STRLEN(TAP_SERVER_NAME)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)TAP_SERVER_NAME, DIGI_STRLEN(TAP_SERVER_NAME));
    if (OK != status)
        goto exit;

    connInfo.serverPort = TAP_SERVER_PORT;
    module.hostInfo = connInfo;

#else

    status = DIGI_CALLOC((void **)&(gConfigInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
        goto exit;

    status = TAP_readConfigFile((char *) TAP_EXAMPLE_CONFIG_PATH, &gConfigInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
        goto exit;

    gConfigInfoList.count = 1;
    gConfigInfoList.pConfig[0].provider = TAP_EXAMPLE_PROVIDER;

#endif

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    for (i = 0; i < numMods; i++)
    {
        if (pModNums[i] >= TAP_EXAMPLE_MAX_MODULES)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        
        module.providerType = TAP_EXAMPLE_PROVIDER;
        module.moduleId = pModNums[i];

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
        status = TAP_getModuleCredentials(&module, (char *) TAP_EXAMPLE_CONFIG_PATH, TRUE, &gpTapEntityCredList[pModNums[i]], gpErrContext);
        if (OK != status)
            goto exit;
#endif

        status = TAP_initContext(&module, gpTapEntityCredList[pModNums[i]], NULL, &gpTapCtx[pModNums[i]], gpErrContext);
        if (OK != status)
            goto exit;
    }

    /* we'll register getCtx1 as the default. App will need to register when they want to use a different modulenum */
    status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_EXAMPLE_getCtx1);

exit:

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif

    if (OK != status)
    {
        TAP_EXAMPLE_clean();
    }

    return status;
}

extern TAP_PROVIDER TAP_EXAMPLE_getProvider(void)
{
    return TAP_EXAMPLE_PROVIDER;
}

extern void TAP_EXAMPLE_clean(void)
{
    sbyte4 i = 0, j = 0;

    if (NULL != gConfigInfoList.pConfig)
    {
        (void) TAP_UTILS_freeConfigInfoList(&gConfigInfoList);
    }

    for (j = 0; j < TAP_EXAMPLE_MAX_MODULES; j++)
    {
        if (NULL != gpTapEntityCredList[j])
        {
            (void) TAP_UTILS_clearEntityCredentialList(gpTapEntityCredList[j]);
            (void) DIGI_FREE((void**) &gpTapEntityCredList[j]);
        }

        if (NULL != gpTapCredList[j])
        {
            if (NULL != gpTapCredList[j]->pCredentialList)
            {
                for (i = 0; i < gpTapCredList[j]->numCredentials; i++)
                {
                    if (gpTapCredList[j]->pCredentialList[i].credentialData.pBuffer != NULL)
                        (void) DIGI_FREE((void**)&(gpTapCredList[j]->pCredentialList[i].credentialData.pBuffer));
                }
                (void) DIGI_FREE((void**) &(gpTapCredList[j]->pCredentialList));
            }

            (void) DIGI_FREE((void**) &gpTapCredList[j]);
        }

        if (NULL != gpTapCtx[j])
        {
            (void) TAP_uninitContext(&gpTapCtx[j], gpErrContext);
        }
    }

    (void) TAP_uninit(gpErrContext);

    return;
}

#else /* __ENABLE_DIGICERT_TAP_EXTERN__ */

#include "../../tap/tap_api.h"

extern TAP_PROVIDER TAP_EXAMPLE_getProvider(void)
{
    MSTATUS status = OK;
    TAP_ProviderList providerList = {0, NULL};
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;

    status = TAP_getProviderList(NULL, &providerList, pErrContext);
    if (OK != status)
       return 0;

    return providerList.pProviderCmdList[0].provider;
}

extern TAP_Context * TAP_EXAMPLE_getTapContext(ubyte4 moduleNum)
{
    return NULL;
}

extern TAP_EntityCredentialList * TAP_EXAMPLE_getEntityCredentialList(ubyte4 moduleNum)
{
    return NULL;
}

extern TAP_CredentialList * TAP_EXAMPLE_getCredentialList(ubyte4 moduleNum)
{
    return NULL;
}

/* Initialization for tap extern is handled in the ci core */
extern MSTATUS TAP_EXAMPLE_init(ubyte4 *pModNums, ubyte4 numMods)
{
   return OK;
}

extern void TAP_EXAMPLE_clean(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_TAP_EXTERN__ */
#endif /* __ENABLE_DIGICERT_TAP__ */
