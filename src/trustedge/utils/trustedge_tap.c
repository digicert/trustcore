/**
 * @file  trustedge_tap.c
 *
 * @brief TAP init/clean methods
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_TAP__

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/mrtos.h"
#include "../../common/vlong.h"
#include "../../common/mfmgmt.h"
#include "../../common/common_utils.h"
#include "../../crypto/rsa.h"
#include "../../crypto_interface/cryptointerface.h"

#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"

#include "../../trustedge/utils/trustedge_tap.h"

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__

#ifndef TRUSTEDGE_TAP_CONFIG_PATH
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define TRUSTEDGE_TAP_CONFIG_PATH "/etc/digicert/pkcs11_smp.conf"
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#define TRUSTEDGE_TAP_CONFIG_PATH "/etc/digicert/nanoroot_smp.conf"
#elif defined(__ENABLE_DIGICERT_TPM2__)
#include "../../common/tpm2_path.h"
#define TRUSTEDGE_TAP_CONFIG_PATH TPM2_CONFIGURATION_FILE
#elif defined(__ENABLE_DIGICERT_TEE__)
#include "../../smp/smp_tee/smp_tap_tee.h"
#define TRUSTEDGE_TAP_CONFIG_PATH "/etc/digicert/tee_smp.conf"
#else
#error "SMP flag not specified. Cannot set default path to TAP config file."
#endif
#endif

#ifndef TRUSTEDGE_TAP_PROVIDER
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define TRUSTEDGE_TAP_PROVIDER TAP_PROVIDER_PKCS11
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#define TRUSTEDGE_TAP_PROVIDER TAP_PROVIDER_NANOROOT
#elif defined(__ENABLE_DIGICERT_TPM2__)
#define TRUSTEDGE_TAP_PROVIDER TAP_PROVIDER_TPM2
#elif defined(__ENABLE_DIGICERT_TEE__)
#define TRUSTEDGE_TAP_PROVIDER TAP_PROVIDER_TEE
#else
#error "SMP flag not specified. Cannot set TAP provider."
#endif
#endif

#endif /* !__ENABLE_DIGICERT_TAP_REMOTE__ */

static TAP_Context *gpTapCtx = NULL;
static TAP_EntityCredentialList *gpTapEntityCredList = NULL;
static TAP_CredentialList *gpTapCredList = NULL;

static TAP_ErrorContext gErrContext = {0};
static TAP_ErrorContext *gpErrContext = &gErrContext;
static TAP_ConfigInfoList gConfigInfoList = {0, };

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_TAP_getCtx(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext)
{
    MOC_UNUSED(pKey);
    MOC_UNUSED(op);
    if (1 == getContext)
    {
        if (NULL != ppTapCtx) *ppTapCtx = gpTapCtx;
        if (NULL != ppTapEntityCred) *ppTapEntityCred = gpTapEntityCredList;
        if (NULL != ppTapKeyCred) *ppTapKeyCred = gpTapCredList;
    }
    else
    {
        if (NULL != ppTapCtx) *ppTapCtx = NULL;
        if (NULL != ppTapEntityCred) *ppTapEntityCred = NULL;
        if (NULL != ppTapKeyCred) *ppTapKeyCred = NULL;
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void TRUSTEDGE_TAP_clean(void)
{
    ubyte4 i = 0;

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

/*---------------------------------------------------------------------------*/

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

/*---------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
MOC_EXTERN MSTATUS TRUSTEDGE_TAP_init(TAP_PROVIDER provider, sbyte *pServer, ubyte4 port, ubyte4 modNum)
#else
MOC_EXTERN MSTATUS TRUSTEDGE_TAP_init(ubyte4 modNum, TrustEdgeConfig *pConfig)
#endif
{
    MSTATUS status = 0;
    TAP_Module module = {0};
    TAP_Module *pModule = NULL;

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
    TAP_ModuleList moduleList = { 0 };

    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *) pServer;
    connInfo.serverName.bufferLen = DIGI_STRLEN(pServer) + 1; /* treat as a string */
    connInfo.serverPort = port;

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    status = TAP_getModuleList(&connInfo, provider, NULL, &moduleList, gpErrContext);
    if (OK != status)
        goto exit;

    pModule = getTapModule(&moduleList, (TAP_ModuleId) modNum);

#else
    sbyte *pTapConfigPath = NULL;
    sbyte4 len;

    status = DIGI_CALLOC((void **)&(gConfigInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
        goto exit;

    if (TRUE == FMGMT_pathExists(TRUSTEDGE_TAP_CONFIG_PATH, NULL))
    {
        len = DIGI_STRLEN(TRUSTEDGE_TAP_CONFIG_PATH) + 1;
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pTapConfigPath, len, TRUSTEDGE_TAP_CONFIG_PATH, len);
        if (OK != status)
            goto exit;
    }
    else if (NULL != pConfig)
    {
        /* Attempt to use TAP configuration in root directory */
        status = COMMON_UTILS_splitPath(
            TRUSTEDGE_TAP_CONFIG_PATH, NULL, &pTapConfigPath);
        if (OK != status)
            goto exit;

        status = COMMON_UTILS_addPathComponent(
            pConfig->pRootDir, pTapConfigPath, &pTapConfigPath);
        if (OK != status)
            goto exit;
    }

    status = TAP_readConfigFile((char *) pTapConfigPath, &gConfigInfoList.pConfig[0].configInfo, FALSE);
    if (OK != status)
        goto exit;

    gConfigInfoList.count = 1;
    gConfigInfoList.pConfig[0].provider = TRUSTEDGE_TAP_PROVIDER;

    status = TAP_init(&gConfigInfoList, gpErrContext);
    if (OK != status)
        goto exit;

    module.providerType = TRUSTEDGE_TAP_PROVIDER;
    module.moduleId = modNum;
    pModule = &module;

#ifndef __ENABLE_DIGICERT_TEE__
    status = TAP_getModuleCredentials(pModule, (char *) pTapConfigPath, TRUE, &gpTapEntityCredList, gpErrContext);
    if (OK != status)
        goto exit;
#endif
#endif /* __ENABLE_DIGICERT_TAP_REMOTE__ */

    status = TAP_initContext(pModule, gpTapEntityCredList, NULL, &gpTapCtx, gpErrContext);
    if (OK != status)
        goto exit;

#ifndef __ENABLE_DIGICERT_TEE__
    /* also allocate an empty credList */
    status = DIGI_CALLOC((void **) &gpTapCredList, 1, sizeof(TAP_CredentialList));
    if (OK != status)
        goto exit;
#endif

    status = CRYPTO_INTERFACE_registerTapCtxCallback(TRUSTEDGE_TAP_getCtx);

exit:

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (NULL != moduleList.pModuleList)
    {
        (void) TAP_freeModuleList(&moduleList);
    }
#else
    if (NULL != pTapConfigPath)
    {
        DIGI_FREE((void **) &pTapConfigPath);
    }
#endif

    if (OK != status)
    {
        TRUSTEDGE_TAP_clean();
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN void TRUSTEDGE_TAP_unloadKey(AsymmetricKey *pKey)
{
    TAP_Key *pTapKey = NULL;
    (void) CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
    (void) TAP_unloadKey(pTapKey, gpErrContext);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_TAP_isProviderModuleLoaded(
    TAP_PROVIDER provider,
    TAP_ModuleId moduleId,
    byteBoolean *pLoaded)
{
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    return ERR_NOT_IMPLEMENTED;
#else
    MSTATUS status;
    TAP_ModuleList moduleList = { 0 };
    TAP_Module *pFound = NULL;

    *pLoaded = FALSE;

    status = TAP_getModuleList(
        NULL, provider, NULL, &moduleList, gpErrContext);
    if (OK != status)
    {
        goto exit;
    }

    pFound = getTapModule(&moduleList, moduleId);
    if (NULL != pFound)
    {
        *pLoaded = TRUE;
    }

exit:

    if (NULL != moduleList.pModuleList)
    {
        (void) TAP_freeModuleList(&moduleList);
    }

    return status;
#endif
}

#endif /* __ENABLE_DIGICERT_TAP__ */
